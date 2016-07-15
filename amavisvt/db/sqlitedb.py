# -*- coding: utf-8 -*-
from __future__ import division
import logging
import sqlite3
import datetime

from amavisvt import patterns
from amavisvt.db.base import BaseDatabase

logger = logging.getLogger(__name__)

LATEST_SCHEMA_VERSION = 2

MIGRATIONS = (
	(), # version 0
	(  # version 1
		"CREATE TABLE `schema_version` (`version` INTEGER NOT NULL);",
		"INSERT INTO schema_version (version) VALUES (0);",
		"""CREATE TABLE `filenames` (
	`id`	INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
	`filename`	TEXT UNIQUE,
	`pattern`	TEXT,
	`infected`	BOOLEAN,
	`timestamp`	INTEGER,
	`sha256`	TEXT
);""",
	),
	(  # version 2
		"ALTER TABLE filenames ADD COLUMN localpart TEXT",
		"ALTER TABLE filenames ADD COLUMN domain TEXT",
	),
)

class AmavisVTDatabase(BaseDatabase):

	def __init__(self, *args, **kwargs):
		self.schema_version = 0
		super(AmavisVTDatabase, self).__init__(*args, **kwargs)

	def connect(self):
		logger.debug("Connecting to database %s", self.config.database_path)
		self.conn = sqlite3.connect(self.config.database_path)
		self.conn.text_factory = str
		self.check_schema()

	def check_schema(self):
		cursor = self.conn.cursor()

		schema_version = 0
		try:
			cursor.execute("SELECT version FROM schema_version")
			result = cursor.fetchone()
			schema_version = result[0]
			logger.debug("Schema version: %s", schema_version)
		except sqlite3.OperationalError:
			logger.info("Database not set up yet")

		if schema_version < LATEST_SCHEMA_VERSION:
			self.migrate_schema(schema_version)
		else:
			self.schema_version = schema_version

	def close(self):
		logger.debug("Disconnecting database")
		if self.conn:
			try:
				self.conn.close()
			except:
				logger.exception("Could not close database connection")

	def migrate_schema(self, current_schema_version):
		for version in range(current_schema_version + 1, LATEST_SCHEMA_VERSION + 1):
			logger.info("Applying schema migrations for version %s" % version)

			for sql in MIGRATIONS[version]:
				logger.debug("Applying sql: %s", sql)

				cursor = self.conn.cursor()
				cursor.execute(sql)
				self.conn.commit()
				cursor.close()

			self.set_schema_version(version)

	def set_schema_version(self, version):
		logger.info("Setting database schema version to %s", version)
		cursor = self.conn.cursor()
		cursor.execute("UPDATE schema_version SET version=?", (version, ))
		self.conn.commit()
		cursor.close()
		self.schema_version = version

	def add_resource(self, resource, vtresult=None, localpart=None, domain=None):
		logger.debug("Adding resource %s with result %s and to (%s, %s) to database", resource, vtresult, localpart, domain)
		insert_sql = 'INSERT INTO filenames (filename, pattern, infected, "timestamp", sha256, localpart, domain) VALUES (?, ?, ?, ?, ?, ?, ?)'
		update_sql = 'UPDATE filenames SET pattern = ?, timestamp = ? WHERE filename=?'

		pattern = patterns.calculate(resource.filename, self.get_filename_localparts(), localpart=localpart)
		infected = vtresult.infected if vtresult else False

		values = (
			resource.filename,
			pattern,
			infected,
			datetime.datetime.utcnow(),
			resource.sha256,
			localpart,
			domain
		)

		cursor = None
		try:
			cursor = self.conn.cursor()
			cursor.execute(insert_sql, values)
		except sqlite3.IntegrityError:
			cursor.execute(update_sql, (pattern, datetime.datetime.utcnow(), resource.filename))
		finally:
			self.conn.commit()
			cursor.close()

		cursor = self.conn.cursor()
		cursor.execute("UPDATE filenames SET infected=? WHERE sha256=? AND infected=0", (int(infected), resource.sha256))
		self.conn.commit()
		cursor.close()

	def get_filenames(self):
		cursor = self.conn.cursor()
		cursor.execute('SELECT DISTINCT filename FROM filenames')
		l = [x[0] for x in cursor.fetchall()]
		self.conn.commit()
		cursor.close()
		return l

	def get_filename_localparts(self):
		cursor = self.conn.cursor()
		cursor.execute('SELECT DISTINCT filename, localpart FROM filenames')
		l = [tuple(x) for x in cursor.fetchall()]
		self.conn.commit()
		cursor.close()
		return l

	def update_patterns(self):
		logger.info("Updating patterns")
		sql = 'SELECT id, filename, localpart FROM filenames WHERE pattern IS NULL'

		cursor = self.conn.cursor()
		cursor.execute(sql)
		result = cursor.fetchall()
		self.conn.commit()
		cursor.close()

		update_sql = 'UPDATE filenames SET pattern=? WHERE id=?'
		other_filename_localparts = self.get_filename_localparts()

		for id, filename, localpart in result:
			pattern = patterns.calculate(filename, other_filename_localparts, localpart=localpart)
			if pattern:
				logger.debug("Updating pattern for %s to %s", filename, pattern)
				cursor = self.conn.cursor()
				cursor.execute(update_sql, (
					pattern,
					id
				))
				self.conn.commit()
				cursor.close()

	def clean(self):
		min_date = datetime.datetime.now() - datetime.timedelta(days=90)
		sql = 'DELETE FROM filenames WHERE timestamp <= ?'

		cursor = self.conn.cursor()
		cursor.execute(sql, (min_date, ))
		self.conn.commit()
		cursor.close()

	def filename_pattern_match(self, resource, localpart=None):
		if not resource:
			return False

		pattern = patterns.calculate(resource.filename, self.get_filename_localparts(), localpart=localpart)

		if not pattern:
			logger.debug("No pattern for filename '%s'.", resource)
			return

		logger.debug("Checking database for pattern: %s", pattern)
		sql = """SELECT DISTINCT
					f.pattern,
					(SELECT COUNT(*) FROM filenames f2 WHERE f2.pattern = f.pattern) AS total_cnt,
					(SELECT COUNT(*) FROM filenames f3 WHERE f3.pattern = f.pattern AND f3.infected=1) AS infected_cnt
				FROM filenames f
				WHERE f.pattern = ?"""

		cursor = self.conn.cursor()
		cursor.execute(sql, (pattern, ))
		result = cursor.fetchone()
		self.conn.commit()
		cursor.close()

		if not result:
			return False

		pattern, total, infected = result
		logger.info("Database result for '%s': total: %s, infected: %s", pattern, total, infected)

		infected_percent = infected / total

		logger.debug("Requirements: %s total matches, %s total (is: %s, %s infected)",
					self.config.min_filename_patterns,
					self.config.min_infected_percent,
					total,
					infected_percent)

		return total >= self.config.min_filename_patterns and infected_percent >= self.config.min_infected_percent
