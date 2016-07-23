# -*- coding: utf-8 -*-
import socket
import threading
import logging
import os
import re

from amavisvt.client import AmavisVT
from amavisvt.config import Configuration

logger = logging.getLogger(__file__)

try:
	import SocketServer as socketserver
except ImportError:
	import socketserver

BUFFER_SIZE = 4096


class ThreadedRequestHandler(socketserver.BaseRequestHandler):

	def __init__(self, *args, **kwargs):
		# fixme: this is a dirty way to get a Configuration instance in the request handler
		# as it will re-read the configuration on every command which can lead to unexpected behaviour
		self.config = Configuration()
		socketserver.BaseRequestHandler.__init__(self, *args, **kwargs)

	def handle(self):
		data = self.request.recv(1024)
		command, argument = self.parse_command(data)

		if command:
			logger.info("Dispatching '%s' command", command)

		if command == "PING":
			self.send_response('PONG')
		elif command == "CONTSCAN":
			if os.path.exists(argument):
				self.do_contscan(argument)
			else:
				logger.error("Cannot handle CONTSCAN command with argument '%s'", argument)
				self.send_response("ERROR: Wrong argument '%s' for command '%s'" % (argument, command))
		else:
			self.send_response("ERROR: Unknown command '%s'" % command)

	def parse_command(self, data):
		if '\n' in data:
			s = data[:data.index('\n')]
			garbage = data[len(s):]
			if garbage:
				logger.info("Received %s chars garbage after command", len(garbage))
		else:
			s = data
		m = re.match(r"^([\w\d]+)(?:\s?(.*))", s, re.IGNORECASE)
		if m:
			return m.group(1), m.group(2)
		return None, None

	def send_response(self, msg):
		self.request.sendall(msg)

	def do_contscan(self, directory):
		responses = []
		for resource, scan_result in AmavisVT(self.config).run(directory):
			if scan_result is None:
				responses.append("%s: Not scanned by virustotal" % resource)
			elif isinstance(scan_result, Exception):
				responses.append("%s: Error (%s)" % (resource, scan_result))
			else:
				if scan_result.infected:
					matches = [v['result'] for _, v in scan_result.scans.items() if v['detected']][:5]
					responses.append("%s: Detected as %s (%s of %s)" % (resource, ', '.join(set(matches)), scan_result.positives, scan_result.total))
				else:
					responses.append("%s: Clean" % resource)
		self.request.sendall('\n'.join(responses))


class ThreadedUnixSocketServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
	pass


class AmavisVTDaemon(object):

	def __init__(self, socket_path=None):
		self.server = None
		self.server_thread = None
		self.config = Configuration()
		self.socket_path = socket_path or self.config.socket_path

	def run_and_wait(self):
		if os.path.exists(self.socket_path):
			if self.is_socket_working(self.socket_path):
				raise Exception("Cannot use %s - found working socket" % self.socket_path)
			logger.info("Removing stale socket path %s", self.socket_path)
			os.remove(self.socket_path)

		try:
			self.server = ThreadedUnixSocketServer(self.socket_path, ThreadedRequestHandler)

			# Start a thread with the server -- that thread will then start one
			# more thread for each request
			self.server_thread = threading.Thread(target=self.server.serve_forever, name='master')
			# Exit the server thread when the main thread terminates
			self.server_thread.daemon = True
			self.server_thread.start()
		except:
			self.stop()

	def is_socket_working(self, socket_path):
		"""Tests whether the socket in socket_path is working by sending the PING command"""
		try:
			sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			sock.connect(socket_path)
			sock.sendall("PING")
			data = sock.recv(BUFFER_SIZE)

			if data and data.strip() == "PONG":
				return True

			logger.info("Received garbage from socket %s: '%s'", socket_path, data)
			return False
		except Exception as ex:
			logger.error("Socket %s isn't working: %s", socket_path, ex)
			return False

	def stop(self):
		"""Stops the daemon."""

		if not self.server:
			return

		logger.info("Shutting down")
		self.server.shutdown()
		self.server.server_close()
		self.server = None
		os.remove(self.socket_path)
