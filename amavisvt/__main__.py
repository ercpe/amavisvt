#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import logging
from argparse import ArgumentParser
from logging.handlers import SysLogHandler

from amavisvt.client import AmavisVT, Configuration

logger = logging.getLogger(__name__)


def main(args):
	config = Configuration({
		'api-key': args.apikey,
		'hits-required': "5",
		'scan-zips': str(args.scan_zips).lower(),
	})

	detected = False
	for full_filename, scan_result in AmavisVT(config).run(args.file_or_directory):
		filename = os.path.basename(full_filename)
		if scan_result is None:
			print("%s: Not scanned by virustotal" % filename)
		elif isinstance(scan_result, Exception):
			print("%s: Error (%s)" % (filename, scan_result))
		else:
			if scan_result.positives >= config.hits_required:
				detected = True
				matches = ["%s: %s" % (k, v['result']) for k, v in scan_result.scans.items() if v['detected']]
				print("%s: Detected as %s (%s of %s)" % (filename, ', '.join(matches), scan_result.positives, scan_result.total))
			else:
				print("%s: Clean" % filename)

	return detected

if __name__ == "__main__":
	parser = ArgumentParser()
	parser.add_argument('file_or_directory')
	parser.add_argument('--apikey')
	parser.add_argument('-v', '--verbose', action='count', help='Increase verbosity', default=2)
	parser.add_argument('-d', '--debug', action='store_true', default=False, help='Send verbose log messages to stdout too')
	parser.add_argument('-z', '--scan-zips', action='store_true', default=False)

	args = parser.parse_args()

	logging.basicConfig(
		level=logging.FATAL - (10 * args.verbose),
		format='%(asctime)s %(levelname)-7s %(message)s',
	)

	logger = logging.getLogger()

	if not args.debug:
		for h in logger.handlers:
			h.setLevel(logging.ERROR)

	handler = SysLogHandler(address='/dev/log')
	formatter = logging.Formatter('amavisvt: %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	sys.exit(int(main(args)))
