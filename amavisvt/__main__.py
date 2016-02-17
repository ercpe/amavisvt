#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import logging
from argparse import ArgumentParser

from amavisvt.daemon import AmavisVT

logger = logging.getLogger(__name__)


def main(args):
	detected = False
	for full_filename, scan_result in AmavisVT(args.api_key).run(args.file_or_directory):
		filename = os.path.basename(full_filename)
		if scan_result:
			if scan_result.detected:
				detected = True
				matches = ["%s: %s" % (k, v['result']) for k, v in scan_result.scans.items() if v['detected']]
				print("%s: Detected as %s (%s of %s)" % (filename, ', '.join(matches), scan_result.positives, scan_result.total))
			else:
				print("%s: Clean" % filename)
		else:
			print("%s: Not scanned" % filename)

	return detected

if __name__ == "__main__":
	parser = ArgumentParser()
	parser.add_argument('file_or_directory')
	parser.add_argument('--api-key')
	parser.add_argument('-v', '--verbose', action='count', help='Increase verbosity', default=2)
	args = parser.parse_args()

	logging.basicConfig(
		level=logging.FATAL - (10 * args.verbose),
		format='%(asctime)s %(levelname)-7s %(message)s',
	)
	sys.exit(int(main(args)))
