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

	def test_zip(self):
		path = self._resource('textfile.zip')
		r = Resource(path)
		assert r.can_unpack
		assert r.md5 == "e77d94e09fbcf6641c1f848d98963298"
		assert r.sha1 == "acbfc25a642cb7fa574f38a361932d1c2fdc1a9e"
		assert r.sha256 == "93440551540584e48d911586606c319744c8e671c20ee6b12cca4b922127a127"
		assert r.mime_type == "application/zip"

		resources = list(r.unpack())

		assert len(resources) == 2

		zip_resource = resources[0]
		assert not zip_resource.can_unpack # Should have no_unpack set
		assert zip_resource.md5 == r.md5
		assert zip_resource.sha1 == r.sha1
		assert zip_resource.sha256 == r.sha256
		assert zip_resource.mime_type == r.mime_type

		text_resource = resources[1]
		assert not text_resource.can_unpack
		assert text_resource.md5 == "1b826051506f463f07307598fcf12fd6"
		assert text_resource.sha1 == "f10e562d8825ec2e17e0d9f58646f8084a658cfa"
		assert text_resource.sha256 == "e5ce4d21e7300ab8106d6c96e1464ae69124eb34371436b5bae6cc920cbdc6a0"
		assert text_resource.mime_type == "text/plain"

		for x in resources:
			if not x.path == r.path:
				os.remove(x.path)
