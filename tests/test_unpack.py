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

		assert len(resources) == 1

		text_resource = resources[0]
		assert not text_resource.can_unpack
		assert text_resource.md5 == "1b826051506f463f07307598fcf12fd6"
		assert text_resource.sha1 == "f10e562d8825ec2e17e0d9f58646f8084a658cfa"
		assert text_resource.sha256 == "e5ce4d21e7300ab8106d6c96e1464ae69124eb34371436b5bae6cc920cbdc6a0"
		assert text_resource.mime_type == "text/plain"

		for x in resources:
			if not x.path == r.path:
				os.remove(x.path)

	def test_unpack_break_recursion(self):
		path = self._resource('zipped10.zip')
		r = Resource(path)
		assert r.can_unpack
		assert r.md5 == "2d77f59ad8c89d78068f27b9ead04d99"
		assert r.sha1 == "85f4b202865a91013791bc84e54adc16ce54dffa"
		assert r.sha256 == "88de21dc5004b581a2a8fd5d72d999c8c9b696c43bae15e77865242b68f0def0"
		assert r.mime_type == "application/zip"

		resources = list(r)
		assert len(resources) == 10

		assert resources[0].filename == "zipped9.zip"
		assert resources[0].can_unpack
		assert resources[0].md5 == "d28338b589b0f2ef21561f164cfa1a18"
		assert resources[0].sha1 == "d606f4eb556ddb2217f071da63e27cbe18fc082f"
		assert resources[0].sha256 == "686dca07606e1ba6e7472c58da22978fb207bcd433d38487c214d897d2d4c527"

		assert resources[1].filename == "zipped8.zip"
		assert resources[1].can_unpack
		assert resources[1].md5 == "9b1c504577b06ec5a03c28924e5256b0"
		assert resources[1].sha1 == "3e76f9e6a2a9b9ba68b147fa5578acde2c7bdc4b"
		assert resources[1].sha256 == "e628179ef507b9720fc52082cc90ffb81d24b1dc5db5b40fdf6ca4ad75bff7a7"

		assert resources[2].filename == "zipped7.zip"
		assert resources[2].can_unpack
		assert resources[2].md5 == "761bd6eca841f21ed173641bfb51503c"
		assert resources[2].sha1 == "779d576ac20311d06164a1d39d15eba3c899cefa"
		assert resources[2].sha256 == "1340dc51374134e55670bd767b7cdfcee7cf01af12d0013a36cd018d41567f65"

		assert resources[3].filename == "zipped6.zip"
		assert resources[3].can_unpack
		assert resources[3].md5 == "babc99a5add3afa264513adb4ee629c7"
		assert resources[3].sha1 == "79c0972529b4040aa633f2d3ec4ac5351c9953df"
		assert resources[3].sha256 == "7af657bc6f4e96ec0e88e711c7901f9908af8bf99fdcbc7ed9906c398bff8efa"

		assert resources[4].filename == "zipped5.zip"
		assert resources[4].can_unpack
		assert resources[4].md5 == "db8129c0e0125195fed5cf01e3121762"
		assert resources[4].sha1 == "203878576a5eb0ac6ce37ca21f6e96b402e783b0"
		assert resources[4].sha256 == "c1db1a4a7908cc3eb0097e9bc38738fd60de4f5b769f04b926e6b376b8dcd876"

		assert resources[5].filename == "zipped4.zip"
		assert resources[5].can_unpack
		assert resources[5].md5 == "867b4116aff2e9bad02f5c02eb4b8e38"
		assert resources[5].sha1 == "e8007090d85921b85e7001c50c107bdb966bfbbb"
		assert resources[5].sha256 == "646ef19a0ea06da0e22eb7890f8ca8a85986dafc343b20215aa2eeff0c9dc334"

		assert resources[6].filename == "zipped3.zip"
		assert resources[6].can_unpack
		assert resources[6].md5 == "b2e246d112d126bc5c1d1bfe618607b6"
		assert resources[6].sha1 == "939adbb5ac38416660f1c1552609c05c3d4bb23a"
		assert resources[6].sha256 == "4827f51ea8c2c6e377353df396dd261b890906431f563a05404601fd73e9bae8"

		assert resources[7].filename == "zipped2.zip"
		assert resources[7].can_unpack
		assert resources[7].md5 == "2eb2c1511680d51abdaa7e3d4166d86f"
		assert resources[7].sha1 == "dc62ce1ec52b06c820fab0ee736e41ceb4658248"
		assert resources[7].sha256 == "92769bfc5e49f1c27bcfd6b627390a3194536e9d8600b7da43f701d825367d08"

		assert resources[8].filename == "zipped1.zip"
		assert resources[8].can_unpack
		assert resources[8].md5 == "a7edc11699c5a873f0792b289a06a298"
		assert resources[8].sha1 == "41b43a6bc9ce0ff0cfda662d42632d48e4773ae3"
		assert resources[8].sha256 == "77d9229e43970e220f862cca29ae9172144a42dfd52f076fa90b7e0b69016a39"

		assert resources[9].filename == "foo.sh"
		assert not resources[9].can_unpack
		assert resources[9].md5 == "fa92b57b1bcca37c7bd3a8a9aefa4afc"
		assert resources[9].sha1 == "ff9f379a1ea12b5cd88be15112846c3d60efaa84"
		assert resources[9].sha256 == "c20768a77532d80ee9985d2f260412c5478980269e5c11a806afb355970b1e63"
		assert resources[9].mime_type == "text/x-shellscript"
