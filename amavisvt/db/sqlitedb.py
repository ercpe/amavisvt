# -*- coding: utf-8 -*-
import logging
import sqlite3

from amavisvt.db.base import BaseDatabase

logger = logging.getLogger(__name__)

LATEST_SCHEMA_VERSION = 1

MIGRATIONS = (
	(), # version 0
	(  # version 1
		"CREATE TABLE `schema_version` (`version` INTEGER NOT NULL);",
		"INSERT INTO schema_version (version) VALUES (0);",
		"""CREATE TABLE `filenames` (
	`id`	INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
	`filename`	TEXT,
	`pattern`	TEXT,
	`infected`	INTEGER,
	`timestamp`	INTEGER,
	`sha256`	TEXT UNIQUE
);""",
	),
)

class AmavisVTDatabase(BaseDatabase):

	def connect(self):
		logger.debug("Connecting to database %s", self.db_path)
		self.conn = sqlite3.connect(self.db_path)
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

	def close(self):
		logger.debug("Disconnecting database")
		if self.conn:
			try:
				self.conn.close()
			except:
				logger.exception("Could not close database connection")
