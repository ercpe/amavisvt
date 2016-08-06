# -*- coding: utf-8 -*-
import mock
from amavisvt.client import VTResponse, Resource

from amavisvt.daemon import ThreadedRequestHandler, AmavisVTDaemon
from tests.test_client import DummyResource, RAW_DUMMY_RESPONSE


class PyTestableThreadedRequestHandler(ThreadedRequestHandler):
	def __init__(self, request, client_address, server):
		self.request = request
		self.client_address = client_address
		self.server = server
		self.config = mock.MagicMock()

		self.handle()


class NoHandleRequestHandler(PyTestableThreadedRequestHandler):
	def __init__(self, request, client_address, server):
		self.request = request
		self.client_address = client_address
		self.server = server
		self.config = mock.MagicMock()


class TestRequestHandler(object):

	def test_handle_no_data(self):
		request_mock = mock.MagicMock()
		request_mock.recv.return_value = ''
		server_mock = mock.MagicMock()

		handler = PyTestableThreadedRequestHandler(request_mock, 'foo', server_mock)
		handler.parse_command = mock.MagicMock()

		request_mock.sendall.assert_called_with("ERROR: Invalid data: ''")
		assert not handler.parse_command.called

	def test_handle_empty_data(self):
		request_mock = mock.MagicMock()
		request_mock.recv.return_value = '\n'
		server_mock = mock.MagicMock()

		handler = PyTestableThreadedRequestHandler(request_mock, 'foo', server_mock)
		handler.parse_command = mock.MagicMock()

		request_mock.sendall.assert_called_with("ERROR: Unknown command 'None'")

	def test_handle_too_much_data(self):
		request_mock = mock.MagicMock()
		server_mock = mock.MagicMock()

		data = 'x' * 10000
		request_mock.recv.return_value = data

		handler = PyTestableThreadedRequestHandler(request_mock, 'foo', server_mock)
		handler.parse_command = mock.MagicMock()

		request_mock.sendall.assert_called_with("ERROR: Invalid data: '%s'" % data)
		assert not handler.parse_command.called

	def test_ping_command(self):
		request_mock = mock.MagicMock()
		server_mock = mock.MagicMock()

		request_mock.recv.return_value = 'PING\n'

		handler = PyTestableThreadedRequestHandler(request_mock, 'foo', server_mock)
		handler.request.sendall.assert_called_with('PONG')

	def test_contscan_command_no_argument(self):
		request_mock = mock.MagicMock()
		server_mock = mock.MagicMock()

		request_mock.recv.return_value = 'CONTSCAN\n'

		handler = PyTestableThreadedRequestHandler(request_mock, 'foo', server_mock)
		handler.request.sendall.assert_called_with("ERROR: Wrong argument ''")

	def test_contscan_command_directory_does_not_exist(self):
		request_mock = mock.MagicMock()
		server_mock = mock.MagicMock()

		request_mock.recv.return_value = 'CONTSCAN /tmp/this-directory-does-not-exist\n'

		handler = PyTestableThreadedRequestHandler(request_mock, 'foo', server_mock)
		handler.request.sendall.assert_called_with("ERROR: Wrong argument '/tmp/this-directory-does-not-exist'")

	def test_handle_report_command(self):
		request_mock = mock.MagicMock()
		server_mock = mock.MagicMock()

		request_mock.recv.return_value = 'REPORT /tmp\n'

		handler = PyTestableThreadedRequestHandler(request_mock, 'foo', server_mock)
		handler.request.sendall.assert_called_with("ERROR: File does not exist or is inaccessible: '/tmp'")

	@mock.patch('amavisvt.daemon.AmavisVT')
	def test_handle_error_in_command(self, avt):
		request_mock = mock.MagicMock()
		server_mock = mock.MagicMock()

		request_mock.recv.return_value = 'REPORT %s\n' % __file__

		# return value of the mocked AmavisVT constructor
		inner_mock = mock.MagicMock()
		avt.return_value = inner_mock

		report_to_vt_mock = mock.MagicMock()
		report_to_vt_mock.side_effect = Exception
		inner_mock.report_to_vt = report_to_vt_mock

		handler = PyTestableThreadedRequestHandler(request_mock, 'foo', server_mock)
		handler.request.sendall.assert_called_with('ERROR: Command error')

	@mock.patch('amavisvt.daemon.AmavisVT')
	def test_contscan_command(self, avt):
		request_mock = mock.MagicMock()
		server_mock = mock.MagicMock()

		# return value of the mocked AmavisVT constructor
		inner_mock = mock.MagicMock()
		avt.return_value = inner_mock

		run_mock = mock.MagicMock()
		inner_mock.run = run_mock

		handler = NoHandleRequestHandler(request_mock, None, server_mock)
		handler.do_contscan('/')

		assert avt.called
		run_mock.assert_called_with('/')
		request_mock.sendall.assert_called_with('AmavisVTd scan results:')

	@mock.patch('amavisvt.daemon.AmavisVT')
	def test_contscan_command_response(self, avt):
		request_mock = mock.MagicMock()
		server_mock = mock.MagicMock()

		# return value of the mocked AmavisVT constructor
		inner_mock = mock.MagicMock()
		avt.return_value = inner_mock

		run_mock = mock.MagicMock()

		infected_response = VTResponse(RAW_DUMMY_RESPONSE)
		infected_response.infected = True

		run_mock.return_value = [
			(DummyResource('test.zip', 'application/zip'), VTResponse(RAW_DUMMY_RESPONSE)),
			(DummyResource('other.zip', 'application/zip'), None),
			(DummyResource('broken.zip', 'application/zip'), Exception("broken")),
			(DummyResource('infected.zip', 'application/zip'), infected_response),
		]
		inner_mock.run = run_mock

		handler = NoHandleRequestHandler(request_mock, None, server_mock)
		handler.do_contscan('/')

		assert avt.called
		run_mock.assert_called_with('/')
		assert request_mock.sendall.called
		call_args, call_kwargs =  request_mock.sendall.call_args
		assert len(call_args) == 1
		lines = call_args[0].split('\n')
		assert len(lines) == 5
		assert lines[0] == "AmavisVTd scan results:"
		assert lines[1] == 'test.zip: Clean'
		assert lines[2] == 'other.zip: Not scanned by virustotal'
		assert lines[3] == 'broken.zip: Error (broken)'
		assert lines[4].startswith('infected.zip: Detected as ')

	@mock.patch('amavisvt.daemon.AmavisVT')
	def test_report_command_invalid_argument(self, avt):
		for invalid_path in (
			'/tmp/this-file-does-not-exist',  # does not exist
			'/',  # is a directory
			'/root/', # no permissions
		):
			request_mock = mock.MagicMock()
			server_mock = mock.MagicMock()

			handler = NoHandleRequestHandler(request_mock, None, server_mock)
			handler.do_report(invalid_path)

			assert not avt.called

	@mock.patch('amavisvt.daemon.AmavisVT')
	def test_report_command_valid_argument_no_response(self, avt):
		request_mock = mock.MagicMock()
		server_mock = mock.MagicMock()

		# return value of the mocked AmavisVT constructor
		inner_mock = mock.MagicMock()
		avt.return_value = inner_mock

		report_to_vt_mock = mock.MagicMock()
		report_to_vt_mock.return_value = None
		inner_mock.report_to_vt = report_to_vt_mock

		handler = NoHandleRequestHandler(request_mock, None, server_mock)
		handler.do_report(__file__)

		assert avt.called

		assert report_to_vt_mock.called
		call_args, call_kwargs = report_to_vt_mock.call_args
		assert len(call_args) == 1
		assert isinstance(call_args[0], Resource)
		assert call_args[0].path == __file__
		request_mock.sendall.assert_called_with('No response')

	@mock.patch('amavisvt.daemon.AmavisVT')
	def test_report_command_valid_argument_with_response(self, avt):
		request_mock = mock.MagicMock()
		server_mock = mock.MagicMock()

		# return value of the mocked AmavisVT constructor
		inner_mock = mock.MagicMock()
		avt.return_value = inner_mock

		report_to_vt_mock = mock.MagicMock()
		report_to_vt_mock.return_value = VTResponse(RAW_DUMMY_RESPONSE)
		inner_mock.report_to_vt = report_to_vt_mock

		handler = NoHandleRequestHandler(request_mock, None, server_mock)
		handler.do_report(__file__)

		assert avt.called

		assert report_to_vt_mock.called
		call_args, call_kwargs = report_to_vt_mock.call_args
		assert len(call_args) == 1
		assert isinstance(call_args[0], Resource)
		assert call_args[0].path == __file__
		request_mock.sendall.assert_called_with('99017f6eebbac24f351415dd410d522d: Scan finished, scan information embedded in this object')

	def test_parse_command_invalid(self):
		handler = NoHandleRequestHandler(None, None, None)

		assert handler.parse_command(None) == (None, None)
		assert handler.parse_command('') == (None, None)
		assert handler.parse_command(' ') == (None, None)
		assert handler.parse_command('\n') == (None, None)

	def test_parse_command_no_args(self):
		handler = NoHandleRequestHandler(None, None, None)

		assert handler.parse_command('PING') == ('PING', '')

	def test_parse_command_args(self):
		handler = NoHandleRequestHandler(None, None, None)
		assert handler.parse_command('PING foobar') == ('PING', 'foobar')


class TestDaemonSocketWorking(object):

	def test_is_socket_working_error(self):
		d = AmavisVTDaemon('dummy-socket')
		assert not d.is_socket_working('dummy-socket')

	def test_stop_do_nothing(self):
		d = AmavisVTDaemon('dummy-socket')
		d.stop()
		assert True

	@mock.patch('amavisvt.daemon.os')
	def test_stop_do_nothing(self, os_mock):
		d = AmavisVTDaemon('dummy-socket')
		d.server = mock.MagicMock()
		d.stop()
		assert d.server.shutdown.called
		assert d.server.server_close.called
		os_mock.remove.assert_called_with('dummy-socket')