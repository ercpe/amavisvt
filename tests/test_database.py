# -*- coding: utf-8 -*-
import pytest

from amavisvt.client import Configuration
from amavisvt.db.base import NoopDatabase
from amavisvt.db.sqlitedb import AmavisVTDatabase

try:
	Database = AmavisVTDatabase
except ImportError:
	Database = NoopDatabase

is_real_database = pytest.mark.skipif(Database == NoopDatabase, reason='sqlite or fuzzywuzzy not available')

@pytest.fixture
def testdb():
	return Database(config=Configuration({'database-path': ':memory:' }, path='/dev/null'))

@is_real_database
class TestAmavisVTDatabase(object):
	import sqlite3

	def test_close_already_closed(self, tmpdir):
		db = Database(config=Configuration({
			'database-path': str(tmpdir + '/database.sqlite3')
		}, path='/dev/null'))
		db.conn.close()
		db.conn = None
		db.close()

	def test_check_schema_empty_database(self, tmpdir):
		db = Database(config=Configuration({
			'database-path': str(tmpdir + '/database.sqlite3')
		}, path='/dev/null'))
		db.close()
		assert db.schema_version == 1

	def test_schema_migration(self, testdb):
		assert testdb.schema_version == 1
		testdb.conn.commit()

		cursor = testdb.conn.cursor()
		assert cursor.execute('SELECT version FROM schema_version').fetchone()[0] == testdb.schema_version
		testdb.conn.close()

	def test_get_filenames(self, testdb):
		assert testdb.schema_version == 1
		testdb.conn.commit()

		cursor = testdb.conn.cursor()
		cursor.execute("""INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES
			('foo', 'foo', 0, 0, 'foo'),
			('bar', 'bar', 0, 0, 'bar'),
			('baz', 'baz', 0, 0, 'baz')
		""")
		testdb.conn.commit()

		assert sorted(testdb.get_filenames()) == ['bar', 'baz', 'foo']


	def test_clean(self, testdb):
		assert testdb.schema_version == 1
		testdb.conn.commit()

		cursor = testdb.conn.cursor()
		cursor.execute("INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES ('foo', 'bar', 0, 0, 'baz')")
		testdb.conn.commit()

		cursor = testdb.conn.cursor()
		assert cursor.execute('SELECT COUNT(*) FROM filenames').fetchone()[0] == 1

		testdb.clean()

		cursor = testdb.conn.cursor()
		assert cursor.execute('SELECT COUNT(*) FROM filenames').fetchone()[0] == 0
