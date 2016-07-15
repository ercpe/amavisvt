# -*- coding: utf-8 -*-

from fuzzywuzzy import fuzz
import re

SPLIT_CHARS = r'[_\-\.\s]'
chunk_split_re = re.compile(SPLIT_CHARS, re.IGNORECASE | re.UNICODE)
start_clean_re = re.compile(r'^(' + SPLIT_CHARS + r'+)', re.IGNORECASE|re.UNICODE)
end_clean_re = re.compile(r'(' + SPLIT_CHARS + r'+)$', re.IGNORECASE|re.UNICODE)

chunk_re = re.compile(r'[_\-\.]', re.IGNORECASE | re.UNICODE)

MIN_CHUNKS = 2

# This is a list of words often found in infected attachment names. Strings in this list
# will become part of the [STATIC] marker in the pattern.
STATIC_WORDS = (
	'profile', 'invoice', 'copy', 'copies', 'unpaid', 'forward',
	'update', 'updated', 'report', 'details', 'document', 'history',
	'caution',
)

def split_chunks(s, localpart=None):
	s = (s or "").strip()

	if not s:
		return ()

	s = start_clean_re.sub('', s)
	s = end_clean_re.sub('', s)

	chunks = chunk_split_re.split(s)
	chunks = [x for x in chunks if x.strip()] # remove all empty parts

	# - replace any chunk that matches the local part with [LOCALPART]
	# - replace any chunk that matches one of the static words with [STATIC]
	for i in range(0, len(chunks)):
		if localpart and chunks[i] == localpart:
			chunks[i] = '[LOCALPART]'
		elif chunks[i] in STATIC_WORDS:
			chunks[i] = '[STATIC]'

	return chunks


def calculate(filename, choices, localpart=None):
	"""Calculates the pattern of the given string in filename using the tuples in choices to find similarities."""
	if not (filename or "").strip():
		return None

	chunks = split_chunks(filename, localpart)

	if len(chunks) <= MIN_CHUNKS:
		return None

	for other_filename, other_localpart in choices:
		if other_filename == filename:
			continue

		other_chunks = split_chunks(other_filename, other_localpart)

		# ignore chunks with less than MIN_CHUNKS items or if the number of chunks differ
		if len(other_chunks) <= MIN_CHUNKS or len(chunks) != len(other_chunks):
			continue

		ratios = [fuzz.ratio(chunks[i], other_chunks[i]) for i in range(0, len(chunks))]

		# skip if more than one chunk differs
		if len(list(filter(lambda x: x != 100, ratios))) > 1:
			continue

		return '-'.join([chunks[i] if ratios[i] == 100 else '[RANDOM]'for i in range(0, len(chunks))])
