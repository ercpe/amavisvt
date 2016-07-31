# -*- coding: utf-8 -*-

import logging
import os

try:
	from ConfigParser import SafeConfigParser as ConfigParser
except ImportError:  # pragma: no cover
	from configparser import ConfigParser

logger = logging.getLogger(__name__)

_instance = None

class AmavisVTConfigurationParser(ConfigParser):
	def __init__(self, cliargs=None, **kwargs):
		defaults = cliargs or {}
		for k in [k for k in defaults.keys() if not defaults[k]]:
			del defaults[k]

		defaults.setdefault('socket-path', '/run/amavisvtd.sock')

		defaults.setdefault('positive-expire', str(21 * 86400))
		defaults.setdefault('negative-expire', str(12 * 3600))
		defaults.setdefault('unknown-expire', str(12 * 3600))
		defaults.setdefault('timeout', '10')
		defaults.setdefault('hits-required', "5")
		defaults.setdefault('pretend', 'false')
		defaults.setdefault('api-url', "https://www.virustotal.com/vtapi/v2/file/report")
		defaults.setdefault('report-url', "https://www.virustotal.com/vtapi/v2/file/scan")
		defaults.setdefault('database-path', '/var/lib/amavisvt/amavisvt.sqlite3')

		defaults.setdefault('filename-pattern-detection', 'false')
		defaults.setdefault('min-filename-patterns', '20')
		defaults.setdefault('infected-percent', '0.7')
		defaults.setdefault('auto-report', 'false')

		ConfigParser.__init__(self, defaults=defaults)
		paths = kwargs.get('path', None)
		if paths:
			paths = [paths]
		else:
			paths = [
				'/etc/amavisvt.cfg',
				os.path.expanduser('~/.amavisvt.cfg'),
				'amavisvt.cfg'
			]
		files_read = self.read(paths)
		logger.info("Read configuration files: %s", files_read)

	@property
	def apikey(self):
		return self.get('DEFAULT', 'api-key')

	@property
	def socket_path(self):
		return self.get('daemon', 'socket-path')

	@property
	def socket_permissions(self):
		return self.get('daemon', 'socket-perm')

	@property
	def socket_group(self):
		return self.get('daemon', 'socket-group')

	@property
	def positive_expire(self):
		return int(self.get('DEFAULT', 'positive-expire'))

	@property
	def negative_expire(self):
		return int(self.get('DEFAULT', 'negative-expire'))

	@property
	def unknown_expire(self):
		return int(self.get('DEFAULT', 'unknown-expire'))

	@property
	def hits_required(self):
		return int(self.get('DEFAULT', 'hits-required'))

	@property
	def api_url(self):
		return self.get('DEFAULT', 'api-url')

	@property
	def report_url(self):
		return self.get('DEFAULT', 'report-url')

	@property
	def timeout(self):
		return int(self.get('DEFAULT', 'timeout'))

	@property
	def pretend(self):
		return (self.get('DEFAULT', 'pretend') or "false").lower() == "true"

	@property
	def database_path(self):
		return self.get('DEFAULT', 'database-path')

	@property
	def filename_pattern_detection(self):
		return self.get('DEFAULT', 'filename-pattern-detection').lower() == "true"

	@property
	def min_filename_patterns(self):
		return int(self.get('DEFAULT', 'min-filename-patterns'))

	@property
	def min_infected_percent(self):
		return float(self.get('DEFAULT', 'infected-percent'))

	@property
	def auto_report(self):
		return self.get('DEFAULT', 'auto-report').lower() == "true"


def Configuration():
	global _instance
	if _instance is None:
		logger.debug("loading new configuration")
		_instance = AmavisVTConfigurationParser()
	return _instance
