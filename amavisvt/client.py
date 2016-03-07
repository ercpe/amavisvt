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

from amavisvt import VERSION

logger = logging.getLogger(__name__)

try:
	from ConfigParser import SafeConfigParser as ConfigParser
except ImportError:
	from configparser import ConfigParser


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
		defaults.setdefault('scan-zips', "false")
		defaults.setdefault('scan-whole-mail', "false")
		defaults.setdefault('scan-parts-filename', r'.*')

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
	def scan_zips(self):
		return (self.get('DEFAULT', 'scan-zips') or "").lower() == "true"

	@property
	def scan_whole_mail(self):
		return (self.get('DEFAULT', 'scan-whole-mail') or "").lower() == "true"

	@property
	def scan_parts_filename_re(self):
		return re.compile(self.get('DEFAULT', 'scan-parts-filename') or "", flags=re.IGNORECASE)


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


class AmavisVT(object):
	buffer_size = 4096

	def __init__(self, config, memcached_servers=None):
		self.config = config
		self.memcached = memcache.Client(memcached_servers or ['127.0.0.1:11211'])

		self.clean_paths = []

	def run(self, paths, recursively=True):
		result = []
		hashes_for_vt = []

		try:
			for path, friendly_name, checksum in self.get_checksums(self.find_files(paths, recursively)):
				logger.debug("%s = %s (SHA256)", friendly_name, checksum)

				cached_value = self.get_from_cache(checksum)

				if cached_value:
					logger.info("Using cached result for file %s (%s)", path, checksum)
					result.append((path, cached_value))
				else:
					hashes_for_vt.append((path, checksum))

			logger.info("Sending %s hashes to Virustotal", len(hashes_for_vt))
			result.extend(list(self.check_vt(hashes_for_vt)))

			return result

		finally:
			for p in self.clean_paths:
				try:
					logger.debug("Cleaning up: %s", p)
					shutil.rmtree(p)
				except:
					logger.exception("Could not remove %s", p)

	def find_files(self, paths, recursively, auto_unpack=True):
		for path in paths:
			path = os.path.abspath(os.path.expanduser(path))

			def _iter_file(filename):
				if os.path.getsize(filename) == 0:
					return

				tmp_dir = None
				if auto_unpack:
					tmp_dir = self.extract_file(filename)

				if tmp_dir:
					for x in self.find_files([tmp_dir], True, False):
						yield x
				else:
					yield filename, filename[len(path)+1:]

			if os.path.isfile(path):
				for x in _iter_file(path):
					yield x
			elif os.path.isdir(path):
				for root, dirs, files in os.walk(path):
					for f in files:
						for x in _iter_file(os.path.join(root, f)):
							yield x

					if not recursively:
						break

	def get_checksums(self, paths):
		for path, friendly_name in paths:
			try:
				# todo: identify file
				hasher = hashlib.sha256()

				with open(path, 'r') as f:
					tmp = f.read(self.buffer_size)
					while tmp:
						hasher.update(tmp)
						tmp = f.read(self.buffer_size)

				yield path, friendly_name, hasher.hexdigest()
			except IOError as ioe:
				logger.warning("Skipping %s: %s", path, ioe)

	def extract_file(self, path):
		basename, ext = os.path.splitext(path.lower())

		if ext == '.zip':
			tempdir = tempfile.mkdtemp()
			self.clean_paths.append(tempdir)

			try:
				shutil.copy(path, os.path.join(tempdir, os.path.basename(path)))
				with zipfile.ZipFile(path) as zf:
					for i, zi in enumerate(zf.infolist()):
						if i > 1000:
							logger.warning("Stopping examining zip entry at %s", i)
							break

						t = os.path.join(tempdir, "zipentry-%s" % i)
						logger.debug("Extracting zipinfo %s to %s", zi, t)
						with zf.open(zi, 'r') as fi:
							with open(t, 'w') as fo:
								tmp = fi.read(self.buffer_size)
								while tmp:
									fo.write(tmp)
									tmp = fi.read(self.buffer_size)
				return tempdir
			except zipfile.error as e:
				logger.error("Error unpacking zip file %s: %s", path, e)
		else:
			with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
				with open(path) as f:
					is_mail = m.id_buffer(f.read(min(5 * 1024 * 1024, os.path.getsize(path)))) == "message/rfc822"

			if is_mail:
				logger.debug("Identified mail file: %s", path)

				tempdir = tempfile.mkdtemp()
				self.clean_paths.append(tempdir)

				try:
					shutil.copy(path, os.path.join(tempdir, os.path.basename(path)))

					msg = email.message_from_file(open(path))

					payload = msg.get_payload()

					if not isinstance(payload, list):
						logger.debug("Skipping single payload message")
						return None

					for i, part in enumerate(payload):
						if not isinstance(part, email.message.Message):
							logging.debug("Skipping non-message payload")
							continue

						filename = part.get_filename()
						partname = "part%s" % i

						if not filename:
							continue

						logger.debug("Testing filename against re %s", self.config.scan_parts_filename_re.pattern)
						if self.config.scan_parts_filename_re.search(filename):
							logger.debug("Considering part: %s (matches re)", partname)

							partpayload = part.get_payload()
							if len(partpayload) > 27892121:  # roughly 20 MiB as base64
								logger.warning("Skipping part (larger than 20MiB")
							else:
								outpath = os.path.join(tempdir, partname)
								with open(outpath, 'w') as o:
									o.write(base64.b64decode(partpayload))
						else:
							logger.debug("Ignoring part: %s", partname)

					return tempdir
				except:
					logger.exception("Failed to parse mail file %s", path)

		return None

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
