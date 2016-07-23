# -*- coding: utf-8 -*-
import os
import sys

import requests
import shutil

from amavisvt import VERSION
from amavisvt.client import AmavisVT, Resource, VTResponse
from amavisvt.config import AmavisVTConfigurationParser
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
	"resource": u"99017f6eebbac24f351415dd410d522d",
	"scan_id": "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724",
	"md5": u"99017f6eebbac24f351415dd410d522d",
	"sha1": u"4d1740485713a2ab3a4f5822a01f645fe8387f92",
	"sha256": u"52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c",
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
	return AmavisVT(AmavisVTConfigurationParser({
		'database-path': ':memory:',
		'api-key': 'my-api-key'
	}, path='/dev/null'))


class DummyFile():
	def __eq__(self, other):
		return other is not None and isinstance(other, DummyFile)


class TestClientBasic(object):

	def test_is_included_by_extension(self):
		avt = AmavisVT(AmavisVTConfigurationParser())

		for ext in [
			'.exe', '.com', '.bat', '.cmd', '.tar.gz', '.zip', '.tar.bz2', '.tar.7z', '.doc', '.docx', '.docm', '.xls',
			'.xlsa', '.xlsx', '.xlsm', '.ppt', '.ppta', '.pptx', '.pptm', '.pdf', '.js', '.rtf', '.ttf', '.htm', '.html',
			'.vbs', '.wsf'
		]:
			assert avt.is_included(DummyResource('/tmp/foo%s' % ext))

	def test_is_included_by_mime_type(self):
		avt = AmavisVT(AmavisVTConfigurationParser())

		assert avt.is_included(DummyResource(mime_type='application/octect-stream'))
		assert avt.is_included(DummyResource(mime_type='application/foobar'))
		assert avt.is_included(DummyResource(mime_type='text/x-shellscript'))
		assert avt.is_included(DummyResource(mime_type='text/x-perl'))
		assert avt.is_included(DummyResource(mime_type='text/x-ruby'))
		assert avt.is_included(DummyResource(mime_type='text/x-python'))

		assert not avt.is_included(DummyResource(mime_type='text/plain'))
		assert not avt.is_included(DummyResource(mime_type='message/rfc822'))
		assert not avt.is_included(DummyResource(mime_type='image/png'))

	def test_is_infected(self, avt):
		assert not avt.is_infected(0)
		assert not avt.is_infected(1)
		assert avt.is_infected(5)
		assert avt.is_infected(50)

		assert avt.is_infected(VTResponse(RAW_DUMMY_RESPONSE))


class TestClientDatabase(object):

	def test_database_fallback(self):
		c = AmavisVTConfigurationParser({
			'database-path': '/dev/null',
		}, path='/dev/null')
		avt = AmavisVT(c)

		assert isinstance(avt.database, NoopDatabase)


class TestClientCache(object):
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


class TestClientReportToVT(object):
	@mock.patch('amavisvt.client.requests.post')
	def test_report_to_vt_pretend(self, requests_post):
		avt = AmavisVT(AmavisVTConfigurationParser({
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
				'file': (__file__, DummyFile())
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
				'file': (__file__, DummyFile())
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
				'file': (__file__, DummyFile())
			},
			timeout=10.0,
			headers={
				'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
			},
		)


class TestClientCheckVT(object):

	@mock.patch('amavisvt.client.requests.post')
	def test_check_vt_pretend(self, requests_post):
		avt = AmavisVT(AmavisVTConfigurationParser({
			'database-path': ':memory:',
			'api-key': 'my-api-key',
			'pretend': 'true'
		}, path='/dev/null'))

		result = list(avt.check_vt(None))
		assert not requests_post.called
		assert not result

	@mock.patch('amavisvt.client.requests.post')
	def test_check_vt_no_checksums(self, requests_post):
		avt = AmavisVT(AmavisVTConfigurationParser({
			'database-path': ':memory:',
			'api-key': 'my-api-key',
		}, path='/dev/null'))

		result = list(avt.check_vt(None))
		assert not requests_post.called
		assert not result

		result = list(avt.check_vt([]))
		assert not requests_post.called
		assert not result

	@mock.patch('amavisvt.client.requests.post')
	def test_check_vt_request(self, requests_post, avt):
		result = list(avt.check_vt([
			('foo.zip', 'foo'),
			('bar.zip', 'bar'),
			('baz.zip', 'baz')]))

		requests_post.assert_called_with(
			"https://www.virustotal.com/vtapi/v2/file/report",
			{
				'apikey': 'my-api-key',
				'resource': 'bar, baz, foo'
			},
			timeout=10.0,
			headers={
				'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
			}
		)

	@mock.patch('amavisvt.client.requests.post')
	def test_check_vt_request_api_limit_exceeded(self, requests_post, avt):
		response = requests.Response()
		response.status_code = 204

		requests_post.return_value = response

		result = list(avt.check_vt([
			('foo.zip', 'foo'),
			('bar.zip', 'bar'),
			('baz.zip', 'baz')]))

		requests_post.assert_called_with(
			"https://www.virustotal.com/vtapi/v2/file/report",
			{
				'apikey': 'my-api-key',
				'resource': 'bar, baz, foo'
			},
			timeout=10.0,
			headers={
				'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
			}
		)

		assert not result

	@mock.patch('amavisvt.client.requests.post')
	def test_check_vt_request_exception(self, requests_post, avt):
		response = requests.Response()
		response.status_code = 403

		requests_post.return_value = response

		result = list(avt.check_vt([
			('foo.zip', 'foo'),
			('bar.zip', 'bar'),
			('baz.zip', 'baz')]))

		assert not result

	@mock.patch('amavisvt.client.requests.post')
	def test_check_vt_empty_result(self, requests_post, avt):
		response = requests.Response()
		response._content = "[]"
		response.status_code = 200

		requests_post.return_value = response

		result = list(avt.check_vt([
			('foo.zip', 'foo'),
			('bar.zip', 'bar'),
			('baz.zip', 'baz')]))

		assert not result

	@mock.patch('amavisvt.client.requests.post')
	@mock.patch('amavisvt.client.memcache.Client.set')
	def test_check_vt_single_response(self, memcached_mock, requests_post, avt):
		response = mock.MagicMock()
		response.status_code = 200
		response.json = lambda: RAW_DUMMY_RESPONSE

		requests_post.return_value = response

		result = list(avt.check_vt([
			('foo.zip', '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c'),
		]))

		assert len(result) == 1
		filename, vtresult = result[0]
		assert filename == 'foo.zip'
		assert isinstance(vtresult, VTResponse)


	@mock.patch('amavisvt.client.requests.post')
	@mock.patch('amavisvt.client.memcache.Client.set')
	def test_check_vt_response_code_0(self, memcached_mock, requests_post, avt):
		raw = RAW_DUMMY_RESPONSE.copy()
		raw['response_code'] = 0

		response = mock.MagicMock()
		response.status_code = 200
		response.json = lambda: raw

		requests_post.return_value = response

		result = list(avt.check_vt([
			('foo.zip', '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c'),
		]))

		assert len(result) == 1
		filename, vtresult = result[0]
		assert filename == 'foo.zip'
		assert vtresult is not None
		assert isinstance(vtresult, VTResponse)
		assert vtresult.infected


class TestClientRun(object):

	@mock.patch('amavisvt.client.requests.post')
	@mock.patch('amavisvt.client.memcache.Client.set')
	@mock.patch('amavisvt.client.Database')
	def test_run(self, database_mock, memcached_mock, requests_mock, avt):
		txt = os.path.join(os.path.dirname(__file__), 'samples/textfile.txt')
		result = avt.run(txt)
		assert not result
		assert not avt.clean_paths

	@mock.patch('amavisvt.client.requests.post')
	@mock.patch('amavisvt.client.memcache.Client.set')
	@mock.patch('amavisvt.client.memcache.Client.get')
	@mock.patch('amavisvt.client.Database')
	def test_run_with_unpack_and_cleanup(self, database_mock, memcached_get_mock, memcached_set_mock, requests_mock, avt):
		mail = os.path.join(os.path.dirname(__file__), 'samples/mail_with_attachment.eml')
		result = avt.run(mail)
		# the zip file in the attachment
		assert len(result) == 1
		# the zip file in the attachment and the file inside the attachment
		assert len(avt.clean_paths) == 2
		assert not any((os.path.exists(p) for p in avt.clean_paths))

	@mock.patch('amavisvt.client.requests.post')
	@mock.patch('amavisvt.client.memcache.Client.set')
	@mock.patch('amavisvt.client.memcache.Client.get')
	@mock.patch('amavisvt.client.Database')
	def test_run_cache_get(self, database_mock, memcached_get_mock, memcached_set_mock, requests_mock, avt):
		memcached_get_mock.return_value = None

		mail = os.path.join(os.path.dirname(__file__), 'samples/mail_with_attachment.eml')
		result = avt.run(mail)

		assert memcached_get_mock.called
		assert requests_mock.called

		assert len(result) == 0
		# the zip file in the attachment and the file inside the attachment
		assert len(avt.clean_paths) == 2
		assert not any((os.path.exists(p) for p in avt.clean_paths))

	@mock.patch('amavisvt.client.requests.post')
	@mock.patch('amavisvt.client.memcache.Client.set')
	@mock.patch('amavisvt.client.memcache.Client.get')
	@mock.patch('amavisvt.client.Database')
	def test_run_cache_get_result(self, database_mock, memcached_get_mock, memcached_set_mock, requests_mock, avt):
		memcached_get_mock.return_value = {
			"response_code": 1,
			"verbose_msg": "Scan finished, scan information embedded in this object",
			"resource": "99017f6eebbac24f351415dd410d522d",
			"scan_id": "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724",
			"md5": "e77d94e09fbcf6641c1f848d98963298",
			"sha1": "acbfc25a642cb7fa574f38a361932d1c2fdc1a9e",
			"sha256": "93440551540584e48d911586606c319744c8e671c20ee6b12cca4b922127a127",
			"scan_date": "2010-05-15 03:38:44",
			"positives": 40,
			"total": 40,
			"scans": {
				"nProtect": {"detected": True, "version": "2010-05-14.01", "result": "Trojan.Generic.3611249", "update": "20100514"},
			},
			"permalink": "https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/"
		}

		mail = os.path.join(os.path.dirname(__file__), 'samples/mail_with_attachment.eml')
		result = avt.run(mail)

		assert memcached_get_mock.called
		assert not requests_mock.called

		assert len(result) == 1
		# the zip file in the attachment and the file inside the attachment
		assert len(avt.clean_paths) == 2
		assert not any((os.path.exists(p) for p in avt.clean_paths))

	@mock.patch('amavisvt.client.requests.post')
	@mock.patch('amavisvt.client.memcache.Client.set')
	@mock.patch('amavisvt.client.memcache.Client.get')
	@mock.patch('amavisvt.client.Database')
	def test_run_with_directory(self, database_mock, memcached_get_mock, memcached_set_mock, requests_mock, tmpdir, avt):
		memcached_get_mock.return_value = None

		mail = os.path.join(os.path.dirname(__file__), 'samples/mail_with_attachment.eml')
		zip = os.path.join(os.path.dirname(__file__), 'samples/textfile.zip')
		shutil.copy(mail, os.path.join(tmpdir.strpath, 'mail_with_attachment.eml'))
		shutil.copy(zip, os.path.join(tmpdir.strpath, 'textfile.zip'))

		avt.run(tmpdir.strpath)

		assert memcached_get_mock.called
		requests_mock.assert_called_with(
			"https://www.virustotal.com/vtapi/v2/file/report",
			{
				'apikey': 'my-api-key',
				'resource': '93440551540584e48d911586606c319744c8e671c20ee6b12cca4b922127a127'
			},
			timeout=10.0,
			headers={
				'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
			}
		)

		# these resources should not be cleaned up
		assert os.path.exists(os.path.join(tmpdir.strpath, 'mail_with_attachment.eml'))
		assert os.path.exists(os.path.join(tmpdir.strpath, 'textfile.zip'))
		assert len(os.listdir(tmpdir.strpath)) == 2

	@mock.patch('amavisvt.client.requests.post')
	@mock.patch('amavisvt.client.memcache.Client.set')
	@mock.patch('amavisvt.client.memcache.Client.get')
	@mock.patch('amavisvt.client.Database')
	def test_run_with_filename_pattern_detection_no_match(self, database_mock, memcached_get_mock, memcached_set_mock, requests_mock):
		memcached_get_mock.return_value = None
		database_mock.filename_pattern_match = mock.MagicMock()
		database_mock.filename_pattern_match.return_value = False

		avt = AmavisVT(AmavisVTConfigurationParser({
			'database-path': ':memory:',
			'api-key': 'my-api-key',
			'filename-pattern-detection': 'true'
		}, path='/dev/null'))
		avt.database = database_mock

		mail = os.path.join(os.path.dirname(__file__), 'samples/mail_with_attachment.eml')
		result = avt.run(mail)

		assert database_mock.filename_pattern_match.called
		call_result = database_mock.filename_pattern_match.call_args
		assert len(call_result) == 2 # resource and localpart
		call_args, call_kwargs = call_result

		# assert that one arg and one kwarg are passed
		assert len(call_args) == 1
		assert len(call_kwargs) == 1

		# the first arg must be our resource
		assert isinstance(call_args[0], Resource)
		assert call_args[0].filename == 'textfile.zip'

		# the localpart kwarg should be 'alice'
		assert call_kwargs['localpart'] == 'alice'

		print(result)
		assert not result
		assert not any([os.path.exists(p) for p in avt.clean_paths])

	@mock.patch('amavisvt.client.requests.post')
	@mock.patch('amavisvt.client.memcache.Client.set')
	@mock.patch('amavisvt.client.memcache.Client.get')
	@mock.patch('amavisvt.client.Database')
	def test_run_with_filename_pattern_detection_match(self, database_mock, memcached_get_mock, memcached_set_mock,
														  requests_mock):
		memcached_get_mock.return_value = None
		database_mock.filename_pattern_match = mock.MagicMock()
		database_mock.filename_pattern_match.return_value = True

		avt = AmavisVT(AmavisVTConfigurationParser({
			'database-path': ':memory:',
			'api-key': 'my-api-key',
			'filename-pattern-detection': 'true'
		}, path='/dev/null'))
		avt.database = database_mock

		mail = os.path.join(os.path.dirname(__file__), 'samples/mail_with_attachment.eml')
		result = avt.run(mail)

		assert database_mock.filename_pattern_match.called
		call_result = database_mock.filename_pattern_match.call_args
		assert len(call_result) == 2 # resource and localpart
		call_args, call_kwargs = call_result

		# assert that one arg and one kwarg are passed
		assert len(call_args) == 1
		assert len(call_kwargs) == 1

		# the first arg must be our resource
		assert isinstance(call_args[0], Resource)
		assert call_args[0].filename == 'textfile.zip'

		# the localpart kwarg should be 'alice'
		assert call_kwargs['localpart'] == 'alice'

		#database_mock.filename_pattern_match.assert_called_with('textfile.zip')
		assert len(result) == 1
		resource, response = result[0]
		assert resource.filename == 'textfile.zip'
		assert response.infected

		assert not any([os.path.exists(p) for p in avt.clean_paths])

	@mock.patch('amavisvt.client.requests.post')
	@mock.patch('amavisvt.client.memcache.Client.set')
	@mock.patch('amavisvt.client.memcache.Client.get')
	@mock.patch('amavisvt.client.Database')
	def test_run_with_filename_pattern_detection_match_with_autoreport(self, database_mock, memcached_get_mock, memcached_set_mock,
													   requests_mock):
		memcached_get_mock.return_value = None
		database_mock.filename_pattern_match = mock.MagicMock()
		database_mock.filename_pattern_match.return_value = True

		avt = AmavisVT(AmavisVTConfigurationParser({
			'database-path': ':memory:',
			'api-key': 'my-api-key',
			'filename-pattern-detection': 'true',
			'auto-report': 'true'
		}, path='/dev/null'))
		avt.database = database_mock

		mail = os.path.join(os.path.dirname(__file__), 'samples/mail_with_attachment.eml')
		result = avt.run(mail)

		assert database_mock.filename_pattern_match.called
		call_result = database_mock.filename_pattern_match.call_args
		assert len(call_result) == 2 # resource and localpart
		call_args, call_kwargs = call_result

		# assert that one arg and one kwarg are passed
		assert len(call_args) == 1
		assert len(call_kwargs) == 1

		# the first arg must be our resource
		assert isinstance(call_args[0], Resource)
		assert call_args[0].filename == 'textfile.zip'

		# the localpart kwarg should be 'alice'
		assert call_kwargs['localpart'] == 'alice'

		assert requests_mock.called
		assert requests_mock.call_count == 2  # once for scan report and once for submitting

		assert len(result) == 1
		resource, response = result[0]
		assert resource.filename == 'textfile.zip'
		assert response.infected

		assert not any([os.path.exists(p) for p in avt.clean_paths])
