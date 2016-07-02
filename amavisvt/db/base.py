# -*- coding: utf-8 -*-

class BaseDatabase(object):

	def __init__(self, config):
		self.config = config
		self.conn = None
		self.connect()

	def connect(self):
		raise NotImplementedError

	def close(self):
		raise NotImplementedError

	def add_resource(self, resource, vtresult):
		raise NotImplementedError

	def get_filenames(self):
		raise NotImplementedError

	def update_patterns(self):
		raise NotImplementedError

	def clean(self):
		raise NotImplementedError

	def filename_pattern_match(self, filename):
		raise NotImplementedError


class NoopDatabase(BaseDatabase):
	def connect(self):
		pass

	def close(self):
		pass

	def add_resource(self, resource, vtresult):
		pass

	def get_filenames(self):
		pass

	def update_patterns(self):
		pass

	def clean(self):
		pass

	def filename_pattern_match(self, filename):
		pass