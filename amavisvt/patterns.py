# -*- coding: utf-8 -*-

from fuzzywuzzy import fuzz
import re

chunk_re = re.compile(r'[_\-\.]', re.IGNORECASE | re.UNICODE)

MIN_CHUNKS = 2

def calculate(s, choices):
	chunks = chunk_re.split(s)

	if len(chunks) <= MIN_CHUNKS:
		return None

	for other in [x.lower() for x in choices if x != s]:
		other_chunks = chunk_re.split(other)

		# ignore chunks with less than three items or if the number of chunks differ
		if len(other_chunks) <= MIN_CHUNKS or len(chunks) != len(other_chunks):
			continue

		ratios = [fuzz.ratio(chunks[i], other_chunks[i]) for i in range(0, len(chunks))]

		# skip if more than one chunk differs
		if len(filter(lambda x: x != 100, ratios)) > 1:
			continue

		return '-'.join([chunks[i] if ratios[i] == 100 else '[RANDOM]'for i in range(0, len(chunks))])
