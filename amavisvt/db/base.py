# -*- coding: utf-8 -*-

class BaseDatabase(object):  # pragma: no cover

    def __init__(self, config):
        self.config = config

    def add_resource(self, resource, vtresult=None, localpart=None, domain=None):
        raise NotImplementedError

    def get_filenames(self):
        raise NotImplementedError

    def get_filename_localparts(self):
        raise NotImplementedError

    def update_patterns(self):
        raise NotImplementedError

    def clean(self):
        raise NotImplementedError

    def filename_pattern_match(self, resource, localpart=None):
        raise NotImplementedError

    def get_clean_hashes(self, limit=None):
        raise NotImplementedError

    def update_result(self, vtresponse):
        raise NotImplementedError

class NoopDatabase(BaseDatabase):  # pragma: no cover

    def add_resource(self, resource, vtresult=None, localpart=None, domain=None):
        pass

    def get_filenames(self):
        pass

    def get_filename_localparts(self):
        pass

    def update_patterns(self):
        pass

    def clean(self):
        pass

    def filename_pattern_match(self, resource, localpart=None):
        pass

    def get_clean_hashes(self, limit=None):
        return []

    def update_result(self, vtresponse):
        pass
