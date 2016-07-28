# -*- coding: utf-8 -*-
from __future__ import division
import logging
import sqlite3
import datetime
import time

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

class AutoDB(object):
	
	def __init__(self, database_path):
		self.database_path = database_path
		self._entered = None
		self._connected = None
		self._conn = None
	
	def __enter__(self):
		self._entered = time.time()
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		stopped = time.time()
		logger.debug("Disconnecting database. Time in manager: %.2fs, connected: %.2fs.",
						(stopped - self._entered) if self._connected else 0,
						(stopped - self._connected) if self._connected else 0)
		if self._conn:
			try:
				self._conn.close()
			except:
				logger.exception("Could not close database connection")
	
	@property
	def connection(self):
		if not self._conn:
			self._conn = self.connect()
		return self._conn
	
	def connect(self):
		logger.debug("Connecting to database")
		self._connected = time.time()
		conn = sqlite3.connect(self.database_path, timeout=30.0)
		conn.text_factory = str
		return conn


class AmavisVTDatabase(BaseDatabase):

	def __init__(self, *args, **kwargs):
		self.schema_version = 0
		super(AmavisVTDatabase, self).__init__(*args, **kwargs)
		self.check_schema()

	def check_schema(self):

		with AutoDB(self.config.database_path) as db:
			cursor = db.connection.cursor()
	
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

	def migrate_schema(self, current_schema_version):
		with AutoDB(self.config.database_path) as db:
			for version in range(current_schema_version + 1, LATEST_SCHEMA_VERSION + 1):
				logger.info("Applying schema migrations for version %s" % version)
	
				for sql in MIGRATIONS[version]:
					logger.debug("Applying sql: %s", sql)
	
					cursor = db.connection.cursor()
					cursor.execute(sql)
					db.connection.commit()
					cursor.close()

				self.set_schema_version(version)

	def set_schema_version(self, version):
		with AutoDB(self.config.database_path) as db:
			logger.info("Setting database schema version to %s", version)
			cursor = db.connection.cursor()
			cursor.execute("UPDATE schema_version SET version=?", (version, ))
			db.connection.commit()
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
		
		with AutoDB(self.config.database_path) as db:
			cursor = None
			try:
				cursor = db.connection.cursor()
				cursor.execute(insert_sql, values)
			except sqlite3.IntegrityError:
				cursor.execute(update_sql, (pattern, datetime.datetime.utcnow(), resource.filename))
			finally:
				db.connection.commit()
				cursor.close()
	
			cursor = db.connection.cursor()
			cursor.execute("UPDATE filenames SET infected=? WHERE sha256=? AND infected=0", (int(infected), resource.sha256))
			db.connection.commit()
			cursor.close()

	def get_filenames(self):
		logger.debug("Loading filenames from database")
		with AutoDB(self.config.database_path) as db:
			cursor = db.connection.cursor()
			cursor.execute('SELECT DISTINCT filename FROM filenames')
			l = [x[0] for x in cursor.fetchall()]
			db.connection.commit()
			cursor.close()
			return l

	def get_filename_localparts(self):
		logger.debug("Loading filename and localparts")
		with AutoDB(self.config.database_path) as db:
			cursor = db.connection.cursor()
			cursor.execute('SELECT DISTINCT filename, localpart FROM filenames')
			l = [tuple(x) for x in cursor.fetchall()]
			db.connection.commit()
			cursor.close()
			return l

	def update_patterns(self):
		logger.info("Updating patterns")
		min_date = datetime.datetime.now() - datetime.timedelta(days=14)
		sql = 'SELECT id, filename, localpart FROM filenames WHERE pattern IS NULL AND timestamp >= ?'

		with AutoDB(self.config.database_path) as db:
			cursor = db.connection.cursor()
			cursor.execute(sql, (min_date, ))
			result = cursor.fetchall()
			db.connection.commit()
			cursor.close()

		update_sql = 'UPDATE filenames SET pattern=? WHERE id=?'
		other_filename_localparts = self.get_filename_localparts()

		update_data = []
		for id, filename, localpart in result:
			pattern = patterns.calculate(filename, other_filename_localparts, localpart=localpart)
			if pattern:
				update_data.append((pattern, id))
				
		with AutoDB(self.config.database_path) as db:
			for pattern, id in update_data:
				logger.debug("Updating pattern for %s to %s", filename, pattern)
				cursor = db.connection.cursor()
				cursor.execute(update_sql, (
					pattern,
					id
				))
				db.connection.commit()
				cursor.close()

	def clean(self):
		min_date = datetime.datetime.now() - datetime.timedelta(days=21)
		sql = 'DELETE FROM filenames WHERE timestamp <= ? AND (pattern IS NULL AND infected=0)'

		with AutoDB(self.config.database_path) as db:
			cursor = db.connection.cursor()
			cursor.execute(sql, (min_date, ))
			db.connection.commit()
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

		with AutoDB(self.config.database_path) as db:
			cursor = db.connection.cursor()
			cursor.execute(sql, (pattern, ))
			result = cursor.fetchone()
			db.connection.commit()
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

	def get_clean_hashes(self, limit=None):
		"""Query the database for hashes which have a pattern set but aren't marked as infected. Returns a **random** list
		of at most ``limit`` (or 999 if ``limit`` is ``None``).
		This is to avoid sending the same hashes over and over without receiving a result.

		:returns a list of sha256 hashes"""

		with AutoDB(self.config.database_path) as db:
			cursor = db.connection.cursor()
			cursor.execute('SELECT DISTINCT sha256 FROM filenames WHERE pattern IS NOT NULL AND infected=0 ORDER BY RANDOM() LIMIT ?', (limit or 999, ))
			l = [x[0] for x in cursor.fetchall()]
			db.connection.commit()
			cursor.close()
			return l

	def update_result(self, vtresponse):
		if not vtresponse or not vtresponse.infected:
			return

		with AutoDB(self.config.database_path) as db:
			cursor = db.connection.cursor()
			cursor.execute('UPDATE filenames SET infected=1 WHERE sha256=? AND infected=0', (vtresponse.sha256, ))
			db.connection.commit()
			cursor.close()
