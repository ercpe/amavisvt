# -*- coding: utf-8 -*-

import logging
logger = logging.getLogger(__name__)

try:
	from amavisvt.db.sqlitedb import AmavisVTDatabase
	Database = AmavisVTDatabase
except ImportError:
	logger.info("Database is NOT supported (could not import module sqlite3)")
	from amavisvt.db.base import NoopDatabase
	Database = NoopDatabase
