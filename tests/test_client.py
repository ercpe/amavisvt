# -*- coding: utf-8 -*-
import sys

from amavisvt import VERSION
from amavisvt.client import AmavisVT, Configuration, Resource, VTResponse
from amavisvt.db.base import NoopDatabase
import mock
import pytest

OPEN_PATCH = '__builtin__.open' if sys.version_info < (3,0,0) else 'builtins.open'

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


RAW_DUMMY_RESPONSE = {
	"response_code": 1,
	"verbose_msg": "Scan finished, scan information embedded in this object",
	"resource": "99017f6eebbac24f351415dd410d522d",
	"scan_id": "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724",
	"md5": "99017f6eebbac24f351415dd410d522d",
	"sha1": "4d1740485713a2ab3a4f5822a01f645fe8387f92",
	"sha256": "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c",
	"scan_date": "2010-05-15 03:38:44",
	"positives": 40,
	"total": 40,
	"scans": {
		"nProtect": {"detected": True, "version": "2010-05-14.01", "result": "Trojan.Generic.3611249", "update": "20100514"},
		"CAT-QuickHeal": {"detected": True, "version": "10.00", "result": "Trojan.VB.acgy", "update": "20100514"},
		"McAfee": {"detected": True, "version": "5.400.0.1158", "result": "Generic.dx!rkx", "update": "20100515"},
		"TheHacker": {"detected": True, "version": "6.5.2.0.280", "result": "Trojan/VB.gen", "update": "20100514"},
		"VirusBuster": {"detected": True, "version": "5.0.27.0", "result": "Trojan.VB.JFDE", "update": "20100514"},
		"NOD32": {"detected": True, "version": "5115", "result": "a variant of Win32/Qhost.NTY", "update": "20100514"},
		"F-Prot": {"detected": False, "version": "4.5.1.85", "result": None, "update": "20100514"},
		"Symantec": {"detected": True, "version": "20101.1.0.89", "result": "Trojan.KillAV", "update": "20100515"},
	},
	"permalink": "https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/"
}


@pytest.fixture
def avt():
	return AmavisVT(Configuration({
		'database-path': ':memory:',
		'api-key': 'my-api-key'
	}, path='/dev/null'))


class DummyFile():
	def __eq__(self, other):
		return other is not None and isinstance(other, DummyFile)


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

	@mock.patch('amavisvt.client.memcache.Client.set')
	def test_cache_set(self, memcached_client_set, avt):
		avt.set_in_cache('sha256', {}, 100)
		memcached_client_set.assert_called_with('sha256', {}, time=100)

	@mock.patch('amavisvt.client.memcache.Client.get')
	def test_cache_get_does_not_exist(self, memcached_client_get, avt):
		memcached_client_get.return_value = None
		result = avt.get_from_cache('does-not-exist')
		memcached_client_get.assert_called_with('does-not-exist')
		assert result is None

	@mock.patch('amavisvt.client.memcache.Client.get')
	def test_cache_get_convert_to_not_infected(self, memcached_client_get, avt):
		memcached_client_get.return_value = RAW_DUMMY_RESPONSE
		result = avt.get_from_cache('sha256')
		memcached_client_get.assert_called_with('sha256')
		assert result is not None
		assert isinstance(result, VTResponse)
		assert result.infected

	@mock.patch('amavisvt.client.requests.post')
	def test_report_to_vt_pretend(self, requests_post):
		avt = AmavisVT(Configuration({
			'database-path': ':memory:',
			'api-key': 'my-api-key',
			'pretend': 'true'
		}, path='/dev/null'))
		avt.report_to_vt(DummyResource('file1', 'application/zip'))
		assert not requests_post.called

	@mock.patch(OPEN_PATCH)
	@mock.patch('amavisvt.client.requests.post')
	def test_report_to_vt(self, requests_post, open_patch, avt):
		open_patch.return_value = DummyFile()

		avt.report_to_vt(DummyResource(__file__, 'application/zip'))
		requests_post.assert_called_with(
			'https://www.virustotal.com/vtapi/v2/file/scan',
			data = {
				'apikey': 'my-api-key'
			},
			files={
				'file': DummyFile()
			},
			timeout=10.0,
			headers={
				'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
			},
		)

	@mock.patch(OPEN_PATCH)
	@mock.patch('amavisvt.client.requests.post')
	@pytest.mark.skipif(sys.version_info >= (3,4,0) and sys.version_info < (3,5,0), reason="Test broken on python 3.4 (???)")
	def test_report_to_vt_fail_silently(self, requests_post, open_patch, avt):
		open_patch.return_value = DummyFile()

		response = mock.MagicMock()
		requests_post.return_value = response
		requests_post.side_effect = Exception

		avt.report_to_vt(DummyResource(__file__, 'application/zip'))
		requests_post.assert_called_with(
			'https://www.virustotal.com/vtapi/v2/file/scan',
			data={
				'apikey': 'my-api-key'
			},
			files={
				'file': DummyFile()
			},
			timeout=10.0,
			headers={
				'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
			},
		)

	@mock.patch(OPEN_PATCH)
	@mock.patch('amavisvt.client.requests.post')
	def test_report_to_vt_fail_silently_apilimit_reached(self, requests_post, open_patch, avt):
		open_patch.return_value = DummyFile()

		response = mock.MagicMock()
		response.status_code = 204

		requests_post.return_value = response

		avt.report_to_vt(DummyResource(__file__, 'application/zip'))
		requests_post.assert_called_with(
			'https://www.virustotal.com/vtapi/v2/file/scan',
			data={
				'apikey': 'my-api-key'
			},
			files={
				'file': DummyFile()
			},
			timeout=10.0,
			headers={
				'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
			},
		)
