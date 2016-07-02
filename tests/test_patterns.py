# -*- coding: utf-8 -*-
from amavisvt import patterns


class TestPatterns(object):

	def test_empty_or_null(self):
		assert patterns.calculate(None, []) is None
		assert patterns.calculate('', []) is None

	def test_no_chunks(self):
		assert patterns.calculate('abc', []) is None

	def test_too_few_chunks(self):
		assert patterns.calculate('abc-def', []) is None

	def test_no_choices(self):
		assert patterns.calculate('abc-def-ghi', []) is None

	def test_no_matching_choice(self):
		# not enough chunks in choices
		assert patterns.calculate('abc-def-ghi', [
			'foo'
		]) is None

		# no choice has the same number of chunks as the s argument
		assert patterns.calculate('abc-def-ghi', [
			'foo',
			'foo-bar',
			'foo-bar-baz-bat'
		]) is None

	def test_too_many_different_chunks(self):
		# all chunks are different
		assert patterns.calculate('abc-def-ghi', [
			'foo-bar-baz'
		]) is None

		# more than one is different
		assert patterns.calculate('abc-def-ghi', [
			'abc-jkl-mno'
		]) is None

	def test_all_chunks_equal(self):
		assert patterns.calculate('foo-bar-baz', ['foo-bar-baz']) is None

	def test_pattern_ok(self):
		assert patterns.calculate('foo-bar-baz', [
			'foo-bar-bat'
		]) == 'foo-bar-[RANDOM]'

		assert patterns.calculate('foo-bar-baz', [
			'foo-bar-bat',
			'foo-bar-bar',
			'foo-bar-123',
		]) == 'foo-bar-[RANDOM]'

	def test_string_split(self):
		for separator in '_', '-', '.':
			assert patterns.calculate('foo-bar-baz', [
				'foo-bar-bat'.replace('-', separator)
			]) == 'foo-bar-[RANDOM]'

			assert patterns.calculate('foo-bar-baz'.replace('-', separator), [
				'foo-bar-bat'
			]) == 'foo-bar-[RANDOM]'
