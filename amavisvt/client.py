# -*- coding: utf-8 -*-
import base64
import email
import os
import zipfile

import magic
import re
import requests
import logging
import hashlib
import memcache
import tempfile

import shutil

logger = logging.getLogger(__name__)

from amavisvt import VERSION
from amavisvt.db import Database
from amavisvt.db.base import NoopDatabase

try:
	from ConfigParser import SafeConfigParser as ConfigParser
except ImportError:
	from configparser import ConfigParser


BUFFER_SIZE = 4096

def clean_silent(paths):
	for p in paths if isinstance(paths, list) else [paths]:
		try:
			logger.debug("Cleaning up: %s", p)
			if os.path.isdir(p):
				shutil.rmtree(p)
			else:
				os.remove(p)
		except:
			logger.exception("Could not remove %s", p)


class Configuration(ConfigParser):
	def __init__(self, cliargs=None, **kwargs):
		defaults = cliargs or {}
		for k in [k for k in defaults.keys() if not defaults[k]]:
			del defaults[k]

		defaults.setdefault('positive-expire', str(21 * 86400))
		defaults.setdefault('negative-expire', str(12 * 3600))
		defaults.setdefault('unknown-expire', str(12 * 3600))
		defaults.setdefault('timeout', '10')
		defaults.setdefault('hits-required', "5")
		defaults.setdefault('pretend', 'false')
		defaults.setdefault('api-url', "https://www.virustotal.com/vtapi/v2/file/report")
		defaults.setdefault('report-url', "https://www.virustotal.com/vtapi/v2/file/scan")
		defaults.setdefault('database-path', '/var/lib/amavisvt/amavisvt.sqlite3')

		defaults.setdefault('filename-pattern-detection', 'false')
		defaults.setdefault('min-filename-patterns', '20')
		defaults.setdefault('infected-percent', '0.7')
		defaults.setdefault('auto-report', 'false')

		ConfigParser.__init__(self, defaults=defaults)
		paths = kwargs.get('path', None)
		if paths:
			paths = [paths]
		else:
			paths = [
				'/etc/amavisvt.cfg',
				os.path.expanduser('~/.amavisvt.cfg'),
				'amavisvt.cfg'
			]
		files_read = self.read(paths)
		logger.info("Read configuration files: %s", files_read)

	@property
	def apikey(self):
		return self.get('DEFAULT', 'api-key')

	@property
	def positive_expire(self):
		return int(self.get('DEFAULT', 'positive-expire'))

	@property
	def negative_expire(self):
		return int(self.get('DEFAULT', 'negative-expire'))

	@property
	def unknown_expire(self):
		return int(self.get('DEFAULT', 'unknown-expire'))

	@property
	def hits_required(self):
		return int(self.get('DEFAULT', 'hits-required'))

	@property
	def api_url(self):
		return self.get('DEFAULT', 'api-url')

	@property
	def report_url(self):
		return self.get('DEFAULT', 'report-url')

	@property
	def timeout(self):
		return int(self.get('DEFAULT', 'timeout'))

	@property
	def pretend(self):
		return (self.get('DEFAULT', 'pretend') or "false").lower() == "true"

	@property
	def database_path(self):
		return self.get('DEFAULT', 'database-path')

	@property
	def filename_pattern_detection(self):
		return self.get('DEFAULT', 'filename-pattern-detection').lower() == "true"

	@property
	def min_filename_patterns(self):
		return int(self.get('DEFAULT', 'min-filename-patterns'))

	@property
	def min_infected_percent(self):
		return float(self.get('DEFAULT', 'infected-percent'))

	@property
	def auto_report(self):
		return self.get('DEFAULT', 'auto-report').lower() == "true"


class VTResponse(object):
	def __init__(self, virustotal_response):
		self._data = virustotal_response
		self.infected = False

	resource = property(lambda self: self._data['resource'])
	response_code = property(lambda self: self._data['response_code'])
	verbose_message = property(lambda self: self._data.get('verbose_msg', ''))
	md5 = property(lambda self: self._data.get('md5'))
	permalink = property(lambda self: self._data.get('permalink'))
	positives = property(lambda self: int(self._data.get('positives', 0)))
	scan_date = property(lambda self: self._data.get('scan_date'))
	scan_id = property(lambda self: self._data.get('scan_id'))
	scans = property(lambda self: self._data.get('scans'))
	sha1 = property(lambda self: self._data.get('sha1'))
	sha256 = property(lambda self: self._data.get('sha256'))
	total = property(lambda self: self._data.get('total'))

	def __str__(self):
		return "%s: %s" % (self.resource, self.verbose_message or '<no message>')


class FilenameResponse(VTResponse):

	def __init__(self):
		super(FilenameResponse, self).__init__(virustotal_response={
			'resource': '<filename>',
			'scans': {
				'filename pattern': {
					'detected': True,
					'result': 'filename pattern matches infected files'
				}
			},
			'positives': 1,
			'total': 1,
			'sha256': '',
		})
		self.infected = True


class Resource(object):

	def __init__(self, path, **kwargs):
		self.path = path
		self._filename = kwargs.get('filename', None)
		self._no_unpack = kwargs.get('no_unpack', False)
		self.cleanup = kwargs.get('cleanup', True)
		self._md5 = None
		self._sha1 = None
		self._sha256 = None
		self._mime_type = None
		self._size = None

	@property
	def md5(self):
		if self._md5 is None:
			self.examine()
		return self._md5

	@property
	def sha1(self):
		if self._sha1 is None:
			self.examine()
		return self._sha1

	@property
	def sha256(self):
		if self._sha256 is None:
			self.examine()
		return self._sha256

	@property
	def mime_type(self):
		if self._mime_type is None:
			self.examine()
		return self._mime_type

	@property
	def size(self):
		if self._size is None:
			self._size = os.path.getsize(self.path)
		return self._size

	@property
	def can_unpack(self):
		return self.mime_type in ('application/zip', 'message/rfc822', ) and not self._no_unpack

	@property
	def filename(self):
		return self._filename or os.path.basename(self.path)

	def __iter__(self):
		for x in self._iter_unpacked(self, 10): # todo: make depth configurable
			yield x

	def _iter_unpacked(self, resource, depth):
		if depth <= 0:
			logger.warning("Reached maximum unpack depth - further sub resources will not be checked!")
			return

		if resource.can_unpack:
			for subresource in resource.unpack():
				yield subresource
				for subsubresource in self._iter_unpacked(subresource, depth-1):
					yield subsubresource

	def examine(self):
		logger.debug("Examine %s", self.path)
		md5hasher = hashlib.md5()
		sha1hasher = hashlib.sha1()
		sha256hasher = hashlib.sha256()

		id_buffer = b""

		with open(self.path, 'rb') as f:
			tmp = f.read(BUFFER_SIZE)
			while tmp:
				if len(id_buffer) < BUFFER_SIZE * 4:
					id_buffer += tmp

				md5hasher.update(tmp)
				sha1hasher.update(tmp)
				sha256hasher.update(tmp)
				tmp = f.read(BUFFER_SIZE)

		self._md5 = md5hasher.hexdigest()
		self._sha1 = sha1hasher.hexdigest()
		self._sha256 = sha256hasher.hexdigest()

		with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
			self._mime_type = m.id_buffer(id_buffer)
			logger.debug("libmagic identified %s as: %s", self, self._mime_type)

			# This is a hacky way to detect mail messages. Sometimes, when the amount of other text data exceeds the
			# amount of "mail-like" data in a file (like a mail message with lots of HTML), libmagic fails to detect
			# the file as a mail message.
			if self._mime_type in ('text/plain', 'text/html'):
				try:
					msg = email.message_from_string(id_buffer.decode('utf-8'))
					if len(msg.keys()) and 'From' in msg and 'To' in msg:
						logger.debug("Identified mail in %s when libmagic could not (said it was %s)", self.filename, self.mime_type)
						self._mime_type = 'message/rfc822'
				except:
					pass

	def unpack(self):
		unpack_func = None

		if self.mime_type == 'application/zip':
			unpack_func = self.unpack_zip
		elif self.mime_type == 'message/rfc822':
			unpack_func = self.unpack_mail

		try:
			for res in unpack_func():
				yield res
		except:
			logger.exception("Error unpacking %s" % self)

	def unpack_zip(self):
		logger.debug("Unpacking %s as ZIP", self.path)

		try:
			with zipfile.ZipFile(self.path) as zf:
				for i, zi in enumerate(zf.infolist()):
					if i > 1000:
						logger.warning("Stopping examining zip entry at %s", i)
						break

					_, t = tempfile.mkstemp('-zipentry', prefix='amavisvt-')
					logger.debug("Extracting entry %s to %s", zi.filename, t)
					try:
						with zf.open(zi, 'r') as fi, open(t, 'wb') as fo:
							tmp = fi.read(BUFFER_SIZE)
							while tmp:
								fo.write(tmp)
								tmp = fi.read(BUFFER_SIZE)

						yield Resource(t, filename=zi.filename)
					except NotImplementedError as nie:
						logger.info("Skipping %s: %s", zi, nie)

		except zipfile.error as e:
			logger.error("Error unpacking zip file %s: %s", self.path, e)

	def unpack_mail(self):
		try:
			with open(self.path) as f:
				msg = email.message_from_file(f)

			sender = msg.get('From', '<not set>')
			recipient = msg.get('To', '<not set>')
			logger.info("Mail from %s to %s", sender, recipient)

			payload = msg.get_payload()

			if isinstance(payload, list):
				for i, part in enumerate(payload):
					if not isinstance(part, email.message.Message):
						logging.debug("Skipping non-message payload")
						continue

					logger.debug("Mailpart %s", i)
					for k, v in part.items():
						logger.debug(" %s: %s", k, v)

					filename = part.get_filename()
					partname = "part%s" % i

					if not filename:
						continue

					try:
						partpayload = part.get_payload()
						if len(partpayload) > 27892121:  # roughly 20 MiB as base64
							logger.warning("Skipping part (larger than 20MiB")
						else:
							_, outpath = tempfile.mkstemp('-mailpart', prefix='amavisvt-')

							with open(outpath, 'wb') as o:
								o.write(base64.b64decode(partpayload))

							logger.debug("Mail part %s (%s): orig filename: %s, mime type: %s", i, outpath, filename, Resource(outpath).mime_type)

							yield Resource(outpath, filename=filename)
					except Exception as ex:
						logger.exception("Could not extract attachment %s: %s", partname, ex)
			else:
				logger.debug("Skipping single payload message")

		except:
			logger.exception("Failed to parse mail file %s", self.path)

	def __str__(self):
		return self.filename


class AmavisVT(object):
	buffer_size = 4096

	def __init__(self, config, memcached_servers=None):
		self.config = config
		self.memcached = memcache.Client(memcached_servers or ['127.0.0.1:11211'])
		try:
			self.database = Database(config)
		except:
			logger.exception("Error opening database")
			self.database = NoopDatabase(config)

		self.clean_paths = []

	def run(self, file_or_directory):
		resources = []

		if os.path.isfile(file_or_directory):
			resources.append(Resource(file_or_directory, cleanup=False))
		elif os.path.isdir(file_or_directory):
			for root, dirs, files in os.walk(file_or_directory):
				for f in files:
					p = os.path.join(root, f)
					resources.append(Resource(p, cleanup=False))

		return self.process(resources)

	def process(self, resources):
		hashes_for_vt = []
		results = []

		try:
			def _iter_resources():
				for r in resources:
					yield r
					for x in r:
						yield x

			all_resources = list(_iter_resources())
			logger.info("Processing %s resources: %s", len(all_resources), ', '.join([r.path for r in all_resources]))

			for resource in all_resources:
				if resource.cleanup:
					self.clean_paths.append(resource.path)

				if self.is_included(resource):
					cached_value = self.get_from_cache(resource.sha256)

					if cached_value:
						logger.info("Using cached result for file %s (%s): %s", resource, resource.sha256, cached_value)
						results.append((resource, cached_value))
					else:
						hashes_for_vt.append((resource, resource.sha256))
				else:
					logger.debug("Skipping resource: %s", resource)
					continue

			logger.info("Sending %s hashes to Virustotal", len(hashes_for_vt))
			vt_results = list(self.check_vt(hashes_for_vt))

			if self.config.filename_pattern_detection:
				logger.debug("Filename pattern detection enabled")

				for resource, sha256 in hashes_for_vt:
					vtresult = [r for _, r in vt_results if r and r.sha256 == sha256]
					vtresult = vtresult[0] if vtresult else None

					if vtresult and vtresult.infected:
						continue

					# add the resource to the database
					self.database.add_resource(resource, vtresult)

					if self.database.filename_pattern_match(resource.filename):
						logger.info("Flagging attachment %s as INFECTED (identified via filename pattern)", resource.filename)

						results.append((resource, FilenameResponse()))

						if self.config.auto_report:
							self.report_to_vt(resource)

			results.extend(vt_results)

			# update patterns for entries which have no pattern set yet
			self.database.update_patterns()

			return results
		finally:
			clean_silent(self.clean_paths)
			self.database.clean()

	def is_included(self, resource):
		return any((f(resource) for f in [
					lambda r: r.mime_type.startswith('application/'),
					lambda r: r.mime_type in ('text/x-shellscript', 'text/x-perl', 'text/x-ruby', 'text/x-python'),
					lambda r: re.search(r"\.(exe|com|zip|tar\.[\w\d]+|doc\w?|xls\w?|ppt\w?|pdf|js|bat|cmd|rtf|ttf|html?)$", r.filename, re.IGNORECASE)
		]))

	def check_vt(self, checksums):
		if self.config.pretend:
			logger.info("NOT sending requests to virustotal")
			return

		if not checksums:
			return

		try:
			response = requests.post(self.config.api_url, {
				'apikey': self.config.apikey,
				'resource': ', '.join([x[1] for x in checksums])
			}, timeout=float(self.config.timeout), headers={
				'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
			})
			response.raise_for_status()
			if response.status_code == 204:
				raise Exception("API-Limit exceeded!")

			responses = response.json()
			if not isinstance(responses, list):
				responses = [responses]

			for filename, checksum in checksums:
				try:
					d = [d for d in responses
							if checksum in (
								d.get('resource', None),
								d.get('md5', None),
								d.get('sha1', None),
								d.get('sha256', None),
							)][0]
					vtr = VTResponse(d)
					vtr.infected = vtr.positives >= self.config.hits_required

					if vtr.response_code:
						logger.info("Saving in cache: %s", vtr.sha256)
						expires = self.config.positive_expire if vtr.positives >= self.config.hits_required else self.config.negative_expire
						self.set_in_cache(vtr.resource, d, expires)
						logger.debug("Result for %s: %s" % (filename, vtr))
						yield filename, vtr
					else:
						self.set_in_cache(vtr.resource, d, self.config.unknown_expire)
						logger.debug("Skipping result (no scan report): %s", vtr.resource)
						yield filename, None

				except IndexError:
					logger.warn("Got no response for %s (%s)", filename, checksum)
		except:
			logger.exception("Error asking virustotal about files")

	def report_to_vt(self, resource):
		if self.config.pretend:
			logger.info("NOT sending resource to virustotal")
			return

		try:
			logger.info("Reporting resource %s to virustotal", resource)

			files = {
				'file': open(resource.path, 'rb'),
			}
			response = requests.post(self.config.report_url, data={
										'apikey': self.config.apikey,
									},
									files=files,
									timeout=float(self.config.timeout),
									headers={
										'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
									})
			response.raise_for_status()
			if response.status_code == 204:
				raise Exception("API-Limit exceeded!")

			vtr = VTResponse(response.json())
			logger.info("Report result: %s", vtr)
		except:
			logger.exception("Error reporting %s to virustotal", resource)

	def get_from_cache(self, sha256hash):
		from_cache = self.memcached.get(sha256hash)
		if from_cache:
			vtr = VTResponse(from_cache)
			vtr.infected = vtr.positives >= self.config.hits_required
			return vtr

	def set_in_cache(self, sha256hash, d, expire=0):
		logger.debug("Saving key %s in cache. Expires in %s seconds", sha256hash, expire)
		self.memcached.set(sha256hash, d, time=expire)
