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


class NoopDatabase(BaseDatabase):
	def connect(self):
		pass

	def close(self):
		pass
