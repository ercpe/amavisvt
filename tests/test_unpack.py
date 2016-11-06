# -*- coding: utf-8 -*-

import os
from amavisvt.client import Resource


class UnpackExceptionResource(Resource):
    @property
    def mime_type(self):
        return 'application/zip'
    
    def unpack_mail(self):
        raise Exception("Test")
    
    def unpack_zip(self):
        raise Exception("Test")


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
    
    def test_unpack_mail(self):
        path = self._resource('mail_with_attachment.eml')
        r = Resource(path)
        assert r.mime_type == "message/rfc822"
        assert r.can_unpack
        assert r.md5 == "b9a864ccc860e4f30193c7b75de116cf"
        assert r.sha1 == "5e1b7f725dad50407871b02a4a4558da0c734317"
        assert r.sha256 == "0eb18a25bcc56ca4b503b1406d9af35928e754aebbe55452299c9cf2cd8245f1"
        
        resources = list(r.unpack())
        
        assert len(resources) == 1
        
        zip_attachment = resources[0]
        assert not zip_attachment.can_unpack
        assert zip_attachment.md5 == "e77d94e09fbcf6641c1f848d98963298"
        assert zip_attachment.sha1 == "acbfc25a642cb7fa574f38a361932d1c2fdc1a9e"
        assert zip_attachment.sha256 == "93440551540584e48d911586606c319744c8e671c20ee6b12cca4b922127a127"
        assert zip_attachment.mime_type == "application/zip"
        
        for x in resources:
            if not x.path == r.path:
                os.remove(x.path)
    
    def test_unpack_error(self):
        uer = UnpackExceptionResource('/dev/null')
        assert not list(uer.unpack())
