#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import logging
from argparse import ArgumentParser

from amavisvt.daemon import AmavisVT

logger = logging.getLogger(__name__)


def main(args):
	result = AmavisVT(args.api_key).run(args.directory)
	for x in result:
		if x.detected:
			matches = ["%s: %s" % (k, v['result']) for k, v in x.scans.items() if v['detected']]
			print("%s: Detected as %s (%s of %s)" % (x.resource, ', '.join(matches), x.positives, x.total))
		else:
			print("%s: Clean" % x.resource)

	return 0

if __name__ == "__main__":
	parser = ArgumentParser()
	parser.add_argument('directory')
	parser.add_argument('--api-key')
	parser.add_argument('-v', '--verbose', action='count', help='Increase verbosity', default=2)
	args = parser.parse_args()

	logging.basicConfig(
		level=logging.FATAL - (10 * args.verbose),
		format='%(asctime)s %(levelname)-7s %(message)s',
	)
	sys.exit(main(args))
