# -*- coding: utf-8 -*-
import base64
import email
import os
import uuid
import zipfile

import magic
import re
import requests
import logging
import hashlib
import memcache
import tempfile

import shutil

from amavisvt import VERSION

logger = logging.getLogger(__name__)

try:
	from ConfigParser import SafeConfigParser as ConfigParser
except ImportError:
	from configparser import ConfigParser

BUFFER_SIZE = 4096


class Configuration(ConfigParser):
	def __init__(self, cliargs=None):
		defaults = cliargs or {}
		for k in defaults.keys():
			if not defaults[k]:
				del defaults[k]

		defaults.setdefault('positive-expire', str(21 * 86400))
		defaults.setdefault('negative-expire', str(12 * 3600))
		defaults.setdefault('unknown-expire', str(12 * 3600))
		defaults.setdefault('api-url', "https://www.virustotal.com/vtapi/v2/file/report")
		defaults.setdefault('gather-samples', 'false')
		defaults.setdefault('samples-dir', 'None')

		ConfigParser.__init__(self, defaults=defaults)
		files_read = self.read([
			'/etc/amavisvt.cfg',
			os.path.expanduser('~/.amavisvt.cfg'),
			'amavisvt.cfg'
		])
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
	def gather_samples(self):
		return (self.get('DEFAULT', 'gather-samples') or "").lower() == "true"

	@property
	def samples_dir(self):
		return self.get('DEFAULT', 'samples-dir')


class VTResponse(object):
	def __init__(self, virustotal_response):
		self._data = virustotal_response

	resource = property(lambda self: self._data['resource'])
	response_code = property(lambda self: self._data['response_code'])
	verbose_message = property(lambda self:  self._data['verbose_msg'])
	md5 = property(lambda self: self._data.get('md5'))
	permalink = property(lambda self: self._data.get('permalink'))
	positives = property(lambda self: int(self._data.get('positives', 0)))
	scan_date = property(lambda self:  self._data.get('scan_date'))
	scan_id = property(lambda self: self._data.get('scan_id'))
	scans = property(lambda self: self._data.get('scans'))
	sha1 = property(lambda self: self._data.get('sha1'))
	sha256 = property(lambda self: self._data.get('sha256'))
	total = property(lambda self: self._data.get('total'))

	def __str__(self):
		return "%s: %s (Positives: %s of %s)" % (self.resource, self.verbose_message, self.positives, self.total)


class Resource(object):

	def __init__(self, path):
		self.path = path
		self._md5 = None
		self._sha1 = None
		self._sha256 = None
		self._mime_type = None
		self._size = None
		self._mail_indicator = None

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
	def mail_hint(self):
		if self._mail_indicator is None:
			self.examine()
		return self._mail_indicator

	@property
	def size(self):
		if self._size is None:
			self._size = os.path.getsize(self.path)
		return self._size

	@property
	def can_unpack(self):
		return self.mime_type in ('application/zip', 'message/rfc822', ) or self.mail_hint

	@property
	def basename(self):
		return os.path.basename(self.path)

	def examine(self):
		logger.debug("Examine %s", self.path)
		md5hasher = hashlib.md5()
		sha1hasher = hashlib.sha1()
		sha256hasher = hashlib.sha256()

		id_buffer = ""

		with open(self.path, 'r') as f:
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

			if self._mime_type != 'message/rfc822':
				if '\n\n' in id_buffer:
					try:
						msg = email.message_from_string(id_buffer)
						self._mail_indicator = len(msg.keys()) and 'From' in msg and 'To' in msg
						if self._mail_indicator:
							logger.debug("Identified mail in %s when libmagic could not (said it was %s)", self.basename, self.mime_type)
					except:
						self._mail_indicator = False
				else:
					self._mail_indicator = False

	def unpack(self):
		if self.mime_type == 'application/zip':
			logger.debug("Unpacking %s as ZIP", self.path)
			tempdir = tempfile.mkdtemp()

			try:
				with zipfile.ZipFile(self.path) as zf:
					for i, zi in enumerate(zf.infolist()):
						if i > 1000:
							logger.warning("Stopping examining zip entry at %s", i)
							break

						t = os.path.join(tempdir, "zipentry-%s" % i)
						logger.debug("Extracting zipinfo %s to %s", zi, t)
						with zf.open(zi, 'r') as fi:
							with open(t, 'w') as fo:
								tmp = fi.read(BUFFER_SIZE)
								while tmp:
									fo.write(tmp)
									tmp = fi.read(BUFFER_SIZE)

				return tempdir, self
			except zipfile.error as e:
				logger.error("Error unpacking zip file %s: %s", self.path, e)

		elif self.mime_type == 'message/rfc822' or self.mail_hint:
			tempdir = tempfile.mkdtemp()

			try:
				with open(self.path) as f:
					msg = email.message_from_file(f)

				sender = msg.get('From', '<not set>')
				recipient = msg.get('To', '<not set>')
				logger.info("Mail from %s to %s", sender, recipient)

				payload = msg.get_payload()

				if not isinstance(payload, list):
					logger.debug("Skipping single payload message")
					return None, None

				for i, part in enumerate(payload):
					if not isinstance(part, email.message.Message):
						logging.debug("Skipping non-message payload")
						continue

					filename = part.get_filename()
					partname = "part%s" % i

					if not filename:
						continue

					basename, ext = os.path.splitext(filename)

					try:
						partpayload = part.get_payload()
						if len(partpayload) > 27892121:  # roughly 20 MiB as base64
							logger.warning("Skipping part (larger than 20MiB")
						else:
							outpath = os.path.join(tempdir, "%s%s" % (partname, ext))
							with open(outpath, 'w') as o:
								o.write(base64.b64decode(partpayload))

							logger.debug("Mail part %s: orig filename: %s, mime type: %s", outpath, filename, Resource(outpath).mime_type)
					except Exception as ex:
						logger.error("Could not extract attchment %s: %s", partname, ex)

				return tempdir, None
			except:
				logger.exception("Failed to parse mail file %s", self.path)

		return None, None

	def __str__(self):
		return self.basename


class AmavisVT(object):
	buffer_size = 4096

	def __init__(self, config, memcached_servers=None):
		self.config = config
		self.memcached = memcache.Client(memcached_servers or ['127.0.0.1:11211'])

		self.clean_paths = []

	def run(self, paths, recursively=True):
		results = []
		hashes_for_vt = []

		try:
			for resource in self.find_files(paths, recursively):
				logger.debug("----> %s, %s, %s, %s: %s", resource, resource.md5, resource.sha1, resource.sha256, resource.mime_type)

				if not self.is_included(resource):
					logger.debug("Skipping: %s", resource)
					continue

				cached_value = self.get_from_cache(resource.sha256)

				if cached_value:
					logger.info("Using cached result for file %s (%s): %s", resource, resource.sha256, cached_value)
					results.append((resource, cached_value))
				else:
					hashes_for_vt.append((resource, resource.sha256))

			logger.info("Sending %s hashes to Virustotal", len(hashes_for_vt))
			results.extend(list(self.check_vt(hashes_for_vt)))

			if self.config.gather_samples:
				temp_dir = os.path.join(self.config.samples_dir, str(uuid.uuid4()))

				try:
					for resource, result in results:
						if result is None or result.total is None and self.is_included(resource):
							if result:
								logger.debug("Sample gathering: result.total: %s, result.positives: %s", result.total, result.positives)
							if not os.path.exists(temp_dir):
								os.makedirs(temp_dir, 0o700)

							dest = os.path.join(temp_dir, os.path.basename(resource.path))
							logger.info("Saving sample of %s as %s", resource, dest)
							shutil.copy(resource.path, dest)
				except:
					logger.exception("Sample gathering failed")

			return results

		finally:
			for p in self.clean_paths:
				try:
					logger.debug("Cleaning up: %s", p)
					shutil.rmtree(p)
				except:
					logger.exception("Could not remove %s", p)

	def is_included(self, resource):
		return any((f(resource) for f in [
					lambda r: r.mime_type.startswith('application/'),
					lambda r: r.mime_type in ('text/x-shellscript', 'text/x-perl', 'text/x-ruby', 'text/x-python'),
					lambda r: re.search(r"\.(exe|com|zip|tar\.[\w\d]+|doc\w?|xls\w?|ppt\w?|pdf|js|bat|cmd|rtf|ttf|html?)$", r.basename, re.IGNORECASE)
		]))

	def find_files(self, paths, recursively, auto_unpack=True):

		def _inner():
			examine_paths = paths if isinstance(paths, list) else [paths]

			for path in examine_paths:
				path = os.path.abspath(os.path.expanduser(path))

				if os.path.isfile(path):
					yield Resource(path)
				elif os.path.isdir(path):
					for root, dirs, files in os.walk(path):
						for f in files:
							yield Resource(os.path.join(root, f))

						if not recursively:
							break

		for resource in _inner():
			if resource.size == 0:
				continue

			if resource.can_unpack and auto_unpack:
				try:
					tempdir, res = resource.unpack()

					if tempdir is not None:
						self.clean_paths.append(tempdir)

						for subresource in self.find_files(tempdir, False):
							yield subresource

					if res:
						yield res
				except:
					logger.exception("Unpacking %s failed", resource)
			else:
				yield resource

	def check_vt(self, checksums):
		if not checksums:
			return

		try:
			response = requests.post(self.config.api_url, {
				'apikey': self.config.apikey,
				'resource': ', '.join([x[1] for x in checksums])
			}, timeout=10.0, headers={
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

	def get_from_cache(self, sha256hash):
		from_cache = self.memcached.get(sha256hash)
		if from_cache:
			return VTResponse(from_cache)

	def set_in_cache(self, sha256hash, d, expire=0):
		logger.debug("Saving key %s in cache. Expires in %s seconds", sha256hash, expire)
		self.memcached.set(sha256hash, d, time=expire)
