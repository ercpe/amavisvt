# -*- coding: utf-8 -*-
from amavisvt.config import AmavisVTConfigurationParser


class TestConfig(object):

	def test_init(self):
		c = AmavisVTConfigurationParser(path='/dev/null')
		assert True

	def test_cliargs(self):
		c = AmavisVTConfigurationParser(cliargs={
			'foo': 'bar'
		}, path='/dev/null')

		assert c.get('DEFAULT', 'foo') == 'bar'

	def test_none_cliargs_removed(self):
		c = AmavisVTConfigurationParser(cliargs={
			'foo': None
		}, path='/dev/null')

		assert not c.has_option('DEFAULT', 'foo')

	def test_default_options(self):
		c = AmavisVTConfigurationParser(cliargs={
			'api-key': 'api-key'
		}, path='/dev/null')

		assert c.apikey == 'api-key'
		assert c.positive_expire == 21 * 86400
		assert c.negative_expire == 12 * 3600
		assert c.unknown_expire == 12 * 3600
		assert c.api_url == "https://www.virustotal.com/vtapi/v2/file/report"
		assert c.report_url == "https://www.virustotal.com/vtapi/v2/file/scan"
		assert c.database_path == '/var/lib/amavisvt/amavisvt.sqlite3'
		assert c.timeout == 10
		assert c.pretend is False
		assert c.hits_required == 5

		assert c.filename_pattern_detection is False
		assert c.min_filename_patterns == 20
		assert c.min_infected_percent == 0.7
		assert c.auto_report is False

