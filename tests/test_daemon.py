# -*- coding: utf-8 -*-
import mock
from amavisvt.client import VTResponse

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
		request_mock.sendall.assert_called_with('')
	
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
		assert len(lines) == 4
		assert lines[0] == 'test.zip: Clean'
		assert lines[1] == 'other.zip: Not scanned by virustotal'
		assert lines[2] == 'broken.zip: Error (broken)'
		assert lines[3].startswith('infected.zip: Detected as ')
		
	
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