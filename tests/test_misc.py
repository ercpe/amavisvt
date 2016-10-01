# -*- coding: utf-8 -*-
import os

from amavisvt.client import clean_silent
import tempfile


class TestMisc(object):
    def test_clean_paths_empty(self):
        clean_silent([])
        assert True
    
    def test_clean_paths_file_does_not_exist(self):
        clean_silent(['/tmp/this-file-does-not-exist'])
        assert True
    
    def test_clean_paths_directory(self):
        tempdir = tempfile.mkdtemp()
        
        clean_silent(tempdir)
        assert not os.path.exists(tempdir)
    
    def test_clean_paths_directory_recursive(self):
        tempdir = tempfile.mkdtemp()
        
        with open(os.path.join(tempdir, 'lalala.txt'), 'w') as f:
            f.write('foobar')
        
        clean_silent(tempdir)
        assert not os.path.exists(os.path.join(tempdir, 'lalala.txt'))
        assert not os.path.exists(tempdir)
    
    def test_clean_paths_multiple_files(self):
        l = [
            tempfile.mkstemp()[1],
            tempfile.mkstemp()[1],
            tempfile.mkstemp()[1]
        ]
        
        clean_silent(l)
        
        for x in l:
            assert not os.path.exists(x)
