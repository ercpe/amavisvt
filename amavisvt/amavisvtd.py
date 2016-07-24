#!/usr/bin/env python
# -*- coding: utf-8 -*-
import threading
import signal
import logging
from argparse import ArgumentParser
from logging.handlers import SysLogHandler

import sys

from amavisvt.daemon import AmavisVTDaemon

logger = logging.getLogger(__file__)

def main(args):
	logger.info("Starting up")
	daemon = None
	shutdown_sig = threading.Event()

	def _sig_handler(sig, frame):
		logger.debug("Handler received signal %s", sig)
		if sig in (signal.SIGTERM, signal.SIGKILL, signal.SIGINT):
			shutdown_sig.set()
			daemon.stop()

	signal.signal(signal.SIGUSR1, _sig_handler)
	signal.signal(signal.SIGINT, _sig_handler)

	error = False

	try:
		daemon = AmavisVTDaemon(socket_path=args.socket)
		daemon.run_and_wait()

		while True:
			shutdown_sig.wait(5)
			if shutdown_sig.is_set():
				break
	except KeyboardInterrupt:
		error = True
	except:
		logger.exception("Server error")
		error = True
	finally:
		if daemon:
			daemon.stop()

	return error

if __name__ == "__main__":  # pragma: no cover
	parser = ArgumentParser()
	parser.add_argument('-v', '--verbose', action='count', help='Increase verbosity', default=2)
	parser.add_argument('-d', '--debug', action='store_true', default=False, help='Send verbose log messages to stdout too')
	parser.add_argument('-s', '--socket', help='Socket path')

	args = parser.parse_args()

	logging.basicConfig(
		level=logging.FATAL - (10 * args.verbose),
		format='%(asctime)s %(levelname)-7s [%(threadName)s] %(message)s',
	)

	logger = logging.getLogger()

	if not args.debug:
		for h in logger.handlers:
			h.setLevel(logging.ERROR)

	handler = SysLogHandler(address='/dev/log')
	formatter = logging.Formatter('amavisvt: %(threadName)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	sys.exit(int(main(args)))