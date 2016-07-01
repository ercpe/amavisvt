# -*- coding: utf-8 -*-

class BaseDatabase(object):

	def __init__(self, path):
		self.db_path = path
		self.conn = None
		self.connect()

	def connect(self):
		raise NotImplementedError

	def close(self):
		raise NotImplementedError

	def add_resource(self, resource):
		raise NotImplementedError

	def get_filenames(self):
		raise NotImplementedError

	def update_patterns(self):
		raise NotImplementedError

	def clean(self):
		raise NotImplementedError

class NoopDatabase(BaseDatabase):
	def connect(self):
		pass

	def close(self):
		pass

	def add_resource(self, resource):
		pass

	def get_filenames(self):
		pass

	def update_patterns(self):
		pass

	def clean(self):
		pass