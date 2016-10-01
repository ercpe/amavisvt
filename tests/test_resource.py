# -*- coding: utf-8 -*-
import os

from amavisvt.client import Resource, ResourceSet


class DummyResource(Resource):
    def __init__(self):
        super(DummyResource, self).__init__('/dev/null')
        self._examined = False
    
    def examine(self):
        self._examined = True


class TestResourceExamine(object):
    def test_examine_triggered(self):
        r = DummyResource()
        x = r.md5
        assert r._examined
        
        r = DummyResource()
        x = r.sha1
        assert r._examined
        
        r = DummyResource()
        x = r.sha256
        assert r._examined
        
        r = DummyResource()
        x = r.mime_type
        assert r._examined
    
    def test_property_size(self):
        r = Resource('/etc')
        assert r.size == os.path.getsize(r.path)


class TestResourceSet(object):
    def test_basic(self):
        rs = ResourceSet([])
        assert len(list(rs)) == 0
        assert rs.to_addresses == []
        assert rs.to_localpart is None
        assert rs.to_domain is None
    
    def test_iter(self):
        zipfile = os.path.join(os.path.dirname(__file__), 'samples/textfile.zip')
        r = Resource(zipfile)
        rs = ResourceSet([r])
        assert len(rs) == 1
        
        l = list(rs)
        assert len(l) == 1
        assert isinstance(l[0], Resource)
        assert l[0] == r
    
    def test_no_to_addresses(self):
        zipfile = os.path.join(os.path.dirname(__file__), 'samples/textfile.zip')
        r = Resource(zipfile)
        rs = ResourceSet([r])
        
        # we shouldn't be able to extract a to address because we only have a zip file
        assert rs.to_addresses == []
        assert rs.to_localpart is None
        assert rs.to_domain is None
    
    def test_to_addresses(self):
        mailfile = os.path.join(os.path.dirname(__file__), 'samples/mail_with_attachment.eml')
        r = Resource(mailfile)
        rs = ResourceSet([r])
        
        # we shouldn't be able to extract a to address because we only have a zip file
        assert rs.to_addresses == ['alice@example.com']
        assert rs.to_localpart == 'alice'
        assert rs.to_domain == 'example.com'
        
        # this mail has the To header set to
        #   To: Alice <alice@example.com>
        mailfile = os.path.join(os.path.dirname(__file__), 'samples/mail_full_email_in_to.eml')
        r = Resource(mailfile)
        rs = ResourceSet([r])
        
        # we shouldn't be able to extract a to address because we only have a zip file
        assert rs.to_addresses == ['alice@example.com']
        assert rs.to_localpart == 'alice'
        assert rs.to_domain == 'example.com'
        
        # this mail has the To header set to
        #   To: To: undisclosed-recipients:;
        mailfile = os.path.join(os.path.dirname(__file__), 'samples/mail_no_email_in_to.eml')
        r = Resource(mailfile)
        rs = ResourceSet([r])
        
        # we shouldn't be able to extract a to address because we only have a zip file
        assert rs.to_addresses == []
        assert rs.to_localpart is None
        assert rs.to_domain is None
