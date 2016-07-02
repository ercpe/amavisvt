# -*- coding: utf-8 -*-
import os

from amavisvt.client import Resource

class DummyResource(Resource):
	def __init__(self):
		super(DummyResource, self).__init__('/dev/null')
		self._examined = False

	def examine(self):
		self._examined = True


class TestResourceExamine(object):
	def test_examine_triggered(self):
		r = DummyResource()
		x = r.md5
		assert r._examined

		r = DummyResource()
		x = r.sha1
		assert r._examined

		r = DummyResource()
		x = r.sha256
		assert r._examined

		r = DummyResource()
		x = r.mime_type
		assert r._examined

	def test_property_size(self):
		r = Resource('/etc')
		assert r.size == os.path.getsize(r.path)
