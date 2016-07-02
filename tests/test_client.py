# -*- coding: utf-8 -*-
from amavisvt.client import AmavisVT, Configuration, Resource
from amavisvt.db.base import NoopDatabase


class DummyResource(Resource):
	
	def __init__(self, filename=None, mime_type=None):
		f = filename or "dummy"
		super(DummyResource, self).__init__(path=f, filename=f)
		self._mime_type = mime_type or 'text/unknown'
		self._md5 = "md5"
		self._sha1 = "sha1"
		self._sha256 = "sha256"

	def examine(self):
		pass


class TestClient(object):

	def test_is_included_by_extension(self):
		avt = AmavisVT(Configuration())

		assert avt.is_included(DummyResource('/tmp/foo.exe'))
		assert avt.is_included(DummyResource('/tmp/foo.com'))
		assert avt.is_included(DummyResource('/tmp/foo.bat'))
		assert avt.is_included(DummyResource('/tmp/foo.cmd'))
		assert avt.is_included(DummyResource('/tmp/foo.tar.gz'))
		assert avt.is_included(DummyResource('/tmp/foo.zip'))
		assert avt.is_included(DummyResource('/tmp/foo.tar.bz2'))
		assert avt.is_included(DummyResource('/tmp/foo.tar.7z'))
		assert avt.is_included(DummyResource('/tmp/foo.doc'))
		assert avt.is_included(DummyResource('/tmp/foo.docx'))
		assert avt.is_included(DummyResource('/tmp/foo.docm'))
		assert avt.is_included(DummyResource('/tmp/foo.xls'))
		assert avt.is_included(DummyResource('/tmp/foo.xlsa'))
		assert avt.is_included(DummyResource('/tmp/foo.xlsx'))
		assert avt.is_included(DummyResource('/tmp/foo.xlsm'))
		assert avt.is_included(DummyResource('/tmp/foo.ppt'))
		assert avt.is_included(DummyResource('/tmp/foo.ppta'))
		assert avt.is_included(DummyResource('/tmp/foo.pptx'))
		assert avt.is_included(DummyResource('/tmp/foo.pptm'))
		assert avt.is_included(DummyResource('/tmp/foo.pdf'))
		assert avt.is_included(DummyResource('/tmp/foo.js'))
		assert avt.is_included(DummyResource('/tmp/foo.rtf'))
		assert avt.is_included(DummyResource('/tmp/foo.ttf'))
		assert avt.is_included(DummyResource('/tmp/foo.htm'))
		assert avt.is_included(DummyResource('/tmp/foo.html'))

	def test_is_included_by_mime_type(self):
		avt = AmavisVT(Configuration())

		assert avt.is_included(DummyResource(mime_type='application/octect-stream'))
		assert avt.is_included(DummyResource(mime_type='application/foobar'))
		assert avt.is_included(DummyResource(mime_type='text/x-shellscript'))
		assert avt.is_included(DummyResource(mime_type='text/x-perl'))
		assert avt.is_included(DummyResource(mime_type='text/x-ruby'))
		assert avt.is_included(DummyResource(mime_type='text/x-python'))

		assert not avt.is_included(DummyResource(mime_type='text/plain'))
		assert not avt.is_included(DummyResource(mime_type='message/rfc822'))
		assert not avt.is_included(DummyResource(mime_type='image/png'))

	def test_database_fallback(self):
		c = Configuration({
			'database-path': '/dev/null',
		}, path='/dev/null')
		avt = AmavisVT(c)

		assert isinstance(avt.database, NoopDatabase)