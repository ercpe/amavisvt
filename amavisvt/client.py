# -*- coding: utf-8 -*-
import os
import zipfile

import magic
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

	def run(self, path):
		files_checksums = []

		if os.path.isdir(path):
			dir_items = [os.path.join(path, x) for x in os.listdir(path)]
		else:
			dir_items = [path]

		result = []
		hashes_for_vt = []

		files_checksums = self.get_dir_items(dir_items)

		for file_path, checksum in files_checksums:
			cached_value = self.get_from_cache(checksum)

			if cached_value:
				logger.info("Using cached result for file %s (%s)", file_path, checksum)
				result.append((file_path, cached_value))
			else:
				hashes_for_vt.append((file_path, checksum))

		logger.info("Sending %s hashes to Virustotal", len(hashes_for_vt))
		result.extend(list(self.check_vt(hashes_for_vt)))

		return result

	def get_dir_items(self, dir_items):
		files_checksums = []

		for full_path in dir_items:
			if not os.path.isfile(full_path):
				logging.info("Not a file: %s. Skipping", full_path)
				continue

			try:
				checksum, filetype = self.identify_file(full_path)
				if filetype.startswith('application/') or \
					filetype.startswith('image/') or \
					filetype in ('text/x-shellscript', 'text/x-perl', 'text/x-ruby', 'text/x-python') or not filetype:

					files_checksums.append((full_path, checksum))

					if filetype == 'application/zip' and self.config.scan_zips:
						files_checksums.extend(self.unpack_and_hash(full_path))
				else:
					logger.info("Skipping file %s (wrong filetype %s)", full_path, filetype)
			except IOError:
				logger.info("Ignoring %s (IOError)", full_path)

		return files_checksums

	def unpack_and_hash(self, filename):
		tempdir = tempfile.mkdtemp()

		files_checksums = []

		try:
			with zipfile.ZipFile(filename) as zf:
				for i, zi in enumerate(zf.infolist()):
					if i > 1000:
						logger.warning("Stopping examining zip entry at %s", i)
						break

					t = os.path.join(tempdir, "zipentry-%s" % i)
					logger.debug("Extracting zipinfo %s to %s", zi, t)
					with zf.open(zi, 'r') as fi:
						with open(t, 'w') as fo:
							fo.write(fi.read(1024))

					if os.path.isfile(t):
						chksum, content_type = self.identify_file(t)
						files_checksums.append((os.path.basename(t), chksum))
					os.remove(t)
		except:
			logger.exception("Error unpacking zip file %s", filename)
		finally:
			shutil.rmtree(tempdir)

		return files_checksums

	def identify_file(self, path):
		hasher = hashlib.sha256()

		head = None

		with open(path, 'r') as f:
			tmp = f.read(self.buffer_size)
			while tmp:
				if not head:
					head = tmp
				hasher.update(tmp)
				tmp = f.read(self.buffer_size)

		with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
			return hasher.hexdigest(), m.id_buffer(head or "")

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

			l = response.json()
			if not isinstance(l, list):
				l = [l]

			for i, d in enumerate(l):
				vtr = VTResponse(d)


				if vtr.response_code:
					logger.info("Saving in cache: %s", vtr.sha256)
					expires = self.config.positive_expire if vtr.positives >= self.config.hits_required else self.config.negative_expire
					self.set_in_cache(vtr.resource, d, expires)
					logger.debug("Result for %s: %s" % (checksums[i][0], vtr))
					yield checksums[i][0], vtr
				else:
					self.set_in_cache(vtr.resource, d, self.config.unknown_expire)
					logger.debug("Skipping result (no scan report): %s", vtr.resource)
					yield checksums[i][0], None
		except:
			logger.exception("Error asking virustotal about files")

	def get_from_cache(self, sha256hash):
		from_cache = self.memcached.get(sha256hash)
		if from_cache:
			return VTResponse(from_cache)

	def set_in_cache(self, sha256hash, d, expire=0):
		logger.debug("Saving key %s in cache. Expires in %s seconds", sha256hash, expire)
		self.memcached.set(sha256hash, d, time=expire)
