# -*- coding: utf-8 -*-

import os
from amavisvt.client import Resource

class TestUnpack(object):
	samples_dir = os.path.join(os.path.dirname(__file__), 'samples')

	def _resource(self, name):
		return os.path.join(self.samples_dir, name)

	def test_empty_file(self):
		path = self._resource('test1_empty.eml')
		r = Resource(path)
		assert r.path == path
		assert r.can_unpack is False
		assert r.md5 == "d41d8cd98f00b204e9800998ecf8427e"
		assert r.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
		assert r.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		assert r.mime_type == 'application/x-empty'

	def test_mail_file(self):
		path = self._resource('test2_rfc822.eml')
		r = Resource(path)
		assert r.path == path
		assert r.can_unpack
		assert r.md5 == "0a7e2dfa25a3db3ab1a4773a17d1527e"
		assert r.sha1 == "b0c42741af78f8311abeff543be8f3c62247168a"
		assert r.sha256 == "8179aa7716740f099a43d6c0aa8b77622dbbd7050bc56ce21cda2109444cf3d6"
		assert r.mime_type == 'message/rfc822'

