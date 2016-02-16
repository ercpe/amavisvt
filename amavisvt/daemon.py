# -*- coding: utf-8 -*-
import os

import magic
import requests
import logging
import hashlib
import memcache

logger = logging.getLogger(__name__)


class VTResponse(object):
	def __init__(self, virustotal_response):
		self._data = virustotal_response

	@property
	def resource(self):
		return self._data['resource']

	@property
	def response_code(self):
		return self._data['response_code']

	@property
	def verbose_message(self):
		return self._data['verbose_msg']

	@property
	def md5(self):
		return self._data.get('md5')

	@property
	def permalink(self):
		return self._data.get('permalink')

	@property
	def positives(self):
		return int(self._data.get('positives', 0))

	@property
	def scan_date(self):
		return self._data.get('scan_date')

	@property
	def scan_id(self):
		return self._data.get('scan_id')

	@property
	def scans(self):
		return self._data.get('scans')

	@property
	def sha1(self):
		return self._data.get('sha1')

	@property
	def sha256(self):
		return self._data.get('sha256')

	@property
	def total(self):
		return self._data.get('total')

	@property
	def detected(self):
		return self.positives >= 5


class AmavisVT(object):
	buffer_size = 4096

	positive_expire = 21 * 86400
	negative_expire = 12 * 3600
	unknown_expire = negative_expire

	def __init__(self, api_key, memcached_servers=None):
		self.api_key = api_key
		self.memcached = memcache.Client(memcached_servers or ['127.0.0.1:11211'])

	def run(self, path):
		files_checksums = []

		for p in os.listdir(path):
			full_path = os.path.join(path, p)

			if not os.path.isfile(full_path):
				logging.info("Not a file: %s. Skipping", full_path)
				continue

			try:
				checksum, filetype = self.identify_file(full_path)
				if filetype.startswith('application/') or not filetype:
					files_checksums.append((full_path, checksum))
				else:
					logger.info("Skipping file %s (wrong filetype %s)", full_path, filetype)
			except IOError:
				logger.info("Ignoring %s (IOError)", full_path)

		result = []
		hashes_for_vt = []

		for file_path, checksum in files_checksums:
			cached_value = self.get_from_cache(checksum)

			if cached_value:
				logger.info("Using cached result for file %s (%s)", file_path, checksum)
				result.append(cached_value)
			else:
				hashes_for_vt.append(checksum)

		logger.info("Sending %s hashes to Virustotal", len(hashes_for_vt))
		result.extend(list(self.check_vt(hashes_for_vt)))

		return result

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
			response = requests.post("https://www.virustotal.com/vtapi/v2/file/report", {
				'apikey': self.api_key,
				'resource': ', '.join(checksums)
			})
			response.raise_for_status()
			if response.status_code == 204:
				logger.info("API-Limit exceeded!")
				return

			l = response.json()
			if not isinstance(l, list):
				l = [l]

			for d in l:
				vtr = VTResponse(d)

				if vtr.response_code:
					logger.info("Saving in cache: %s", vtr.sha256)
					self.set_in_cache(vtr.resource, d, self.positive_expire if vtr.detected else self.negative_expire)
					yield vtr
				else:
					self.set_in_cache(vtr.resource, d, self.unknown_expire)
					logger.debug("Skipping result (no scan report): %s", vtr.resource)
		except:
			logger.exception("Got exception")

	def get_from_cache(self, sha256hash):
		from_cache = self.memcached.get(sha256hash)
		if from_cache:
			return VTResponse(from_cache)

	def set_in_cache(self, sha256hash, d, expire=0):
		self.memcached.set(sha256hash, d, time=expire)
