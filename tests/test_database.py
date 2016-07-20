# -*- coding: utf-8 -*-
import pytest
import datetime

from amavisvt.client import Configuration, Resource, VTResponse
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

FAKE_TIME = datetime.datetime(2016, 7, 3, 7, 0, 0)
FAKE_TIME_S = FAKE_TIME.strftime("%Y-%m-%d %H:%M:%S")

@pytest.fixture
def frozen_datetime(monkeypatch):
	class mydatetime:
		@classmethod
		def utcnow(cls):
			return FAKE_TIME

	monkeypatch.setattr(datetime, 'datetime', mydatetime)


class DummyResource(Resource):

	def __init__(self, dummy_filename):
		super(DummyResource, self).__init__('/dev/null', filename=dummy_filename)

	@property
	def md5(self):
		return 'md5'

	@property
	def sha1(self):
		return 'sha1'

	@property
	def sha256(self):
		return 'sha256'


class DummyVTResult(VTResponse):

	def __init__(self, infected):
		d = {
			"response_code": 1,
			"verbose_msg": "Scan finished, scan information embedded in this object",
			"resource": "99017f6eebbac24f351415dd410d522d",
			"scan_id": "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724",
			"md5": "md5",
			"sha1": "sha1",
			"sha256": "sha256",
			"scan_date": "2010-05-15 03:38:44",
			"positives": 40,
			"total": 40,
			"scans": {
				"Symantec": {"detected": True, "version": "20101.1.0.89", "result": "Trojan.KillAV", "update": "20100515"},
			},
			"permalink": "https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/"
		}
		super(DummyVTResult, self).__init__(d)
		self.infected = infected


@is_real_database
class TestAmavisVTDatabase(object):

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
		assert db.schema_version == 2

	def test_schema_migration(self, testdb):
		assert testdb.schema_version == 2
		testdb.conn.commit()

		cursor = testdb.conn.cursor()
		assert cursor.execute('SELECT version FROM schema_version').fetchone()[0] == testdb.schema_version
		testdb.conn.close()

	def test_schema_migration_already_migrated(self, testdb):
		assert testdb.schema_version == 2
		testdb.conn.commit()

		cursor = testdb.conn.cursor()
		assert cursor.execute('SELECT version FROM schema_version').fetchone()[0] == testdb.schema_version

		testdb.check_schema()
		assert testdb.schema_version == 2
		testdb.conn.commit()

		testdb.conn.close()

	def test_get_filenames(self, testdb):
		assert testdb.schema_version == 2
		testdb.conn.commit()

		cursor = testdb.conn.cursor()
		cursor.execute("INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES ('foo', 'foo', 0, 0, 'foo')")
		cursor.execute("INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES ('bar', 'bar', 0, 0, 'bar')")
		cursor.execute("INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES ('baz', 'baz', 0, 0, 'baz')")
		testdb.conn.commit()

		assert sorted(testdb.get_filenames()) == ['bar', 'baz', 'foo']

	def test_get_filenames_localpart(self, testdb):
		assert testdb.schema_version == 2
		testdb.conn.commit()

		cursor = testdb.conn.cursor()
		cursor.execute(
			"INSERT INTO filenames (filename, pattern, infected, timestamp, sha256, localpart) VALUES ('foo', 'foo', 0, 0, 'foo', 'alice')")
		cursor.execute(
			"INSERT INTO filenames (filename, pattern, infected, timestamp, sha256, localpart) VALUES ('bar', 'bar', 0, 0, 'bar', 'bob')")
		cursor.execute(
			"INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES ('baz', 'baz', 0, 0, 'baz')")
		testdb.conn.commit()

		assert sorted(testdb.get_filename_localparts()) == [
			('bar', 'bob'),
			('baz', None),
			('foo', 'alice')
		]

	def test_clean(self, testdb):
		assert testdb.schema_version == 2
		testdb.conn.commit()

		cursor = testdb.conn.cursor()
		cursor.execute("INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES ('foo', 'bar', 0, 0, 'baz')")
		testdb.conn.commit()

		cursor = testdb.conn.cursor()
		assert cursor.execute('SELECT COUNT(*) FROM filenames').fetchone()[0] == 1

		testdb.clean()

		cursor = testdb.conn.cursor()
		assert cursor.execute('SELECT COUNT(*) FROM filenames').fetchone()[0] == 0

	def test_filename_pattern_match_no_pattern(self, testdb):
		assert not testdb.filename_pattern_match(None)
		assert not testdb.filename_pattern_match(DummyResource("a.zip"))
		assert not testdb.filename_pattern_match(DummyResource("abc-def.zip"))
		assert not testdb.filename_pattern_match(DummyResource("foo-bar-baz.zip"))

	def test_filename_pattern_match_no_infected_pattern(self, testdb):
		cursor = testdb.conn.cursor()
		for filename in ['foo-bar-1.zip', 'foo-bar-2.zip', 'foo-bar-3.zip']:
			cursor.execute("INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES (?, 'foo-bar-[RANDOM]-zip', 0, 0, ?)", (filename, filename))
		testdb.conn.commit()

		assert not testdb.filename_pattern_match(DummyResource("foo-bar-baz.zip"))

	def test_filename_pattern_match_not_enough_patterns(self, testdb):
		cursor = testdb.conn.cursor()
		for filename in ['foo-bar-1.zip', 'foo-bar-2.zip', 'foo-bar-3.zip']:
			cursor.execute(
				"INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES (?, 'foo-bar-[RANDOM]-zip', 1, 0, ?)",
				(filename, filename))
		testdb.conn.commit()

		assert not testdb.filename_pattern_match(DummyResource("foo-bar-baz.zip"))

	def test_filename_pattern_match_not_enough_infected(self, testdb):
		cursor = testdb.conn.cursor()
		for i in range(0, 20):
			filename = 'foo-bar-%s.zip' % i
			infected = i <= 10
			cursor.execute(
				"INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES (?, 'foo-bar-[RANDOM]-zip', ?, 0, ?)",
				(filename, infected, filename))
		testdb.conn.commit()
		assert not testdb.filename_pattern_match(DummyResource("foo-bar-baz.zip"))

	def test_filename_pattern_match(self, testdb):
		cursor = testdb.conn.cursor()
		for i in range(0, 20):
			filename = 'foo-bar-%s.zip' % i
			cursor.execute(
				"INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES (?, 'foo-bar-[RANDOM]-zip', 1, 0, ?)",
				(filename, filename))
		testdb.conn.commit()
		assert testdb.filename_pattern_match(DummyResource("foo-bar-baz.zip"))

	def test_update_patterns_nothing_to_update(self, testdb):
		cursor = testdb.conn.cursor()
		sql = "INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES (?, ?, ?, ?, ?)"
		data = [
			(u'foo-foo-1.zip', u'foo-foo-[RANDOM]-zip', 1, 0, u'foo-foo-1'),
		]
		cursor.executemany(sql, data)
		testdb.conn.commit()

		testdb.update_patterns()

		cursor = testdb.conn.cursor()
		cursor.execute("SELECT filename, pattern, infected, timestamp, sha256 FROM filenames")
		result = cursor.fetchall()

		assert result == data

	def test_update_patterns_no_pattern_after_update(self, testdb):
		cursor = testdb.conn.cursor()
		sql = "INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES (?, ?, ?, ?, ?)"
		data = [
			(u'foo-1.zip', None, 1, 0, u'foo-foo-1'),
		]
		cursor.executemany(sql, data)
		testdb.conn.commit()

		testdb.update_patterns()

		cursor = testdb.conn.cursor()
		cursor.execute("SELECT filename, pattern, infected, timestamp, sha256 FROM filenames")
		result = cursor.fetchall()

		assert result == data

	def test_update_patterns(self, testdb):
		cursor = testdb.conn.cursor()
		sql = "INSERT INTO filenames (filename, pattern, infected, timestamp, sha256) VALUES (?, ?, ?, ?, ?)"
		data = [
			(u'foo-bar-111.zip', None, 1, 0, u'foo-bar-1'),
			(u'foo-bar-222.zip', None, 1, 0, u'foo-bar-2'),
			(u'foo-bar-333.zip', None, 1, 0, u'foo-bar-3'),
		]
		cursor.executemany(sql, data)
		testdb.conn.commit()

		testdb.update_patterns()

		cursor = testdb.conn.cursor()
		cursor.execute("SELECT filename, pattern, infected, timestamp, sha256 FROM filenames")
		result = sorted(cursor.fetchall())

		new_data = [(f, 'foo-bar-[RANDOM]-zip', i, t, s) for f, _, i, t, s in data]
		assert result == new_data

	def validate_filenames_in_database(self, testdb, data):
		cursor = testdb.conn.cursor()
		cursor.execute("SELECT filename, pattern, infected, timestamp, sha256 FROM filenames")
		result = sorted(cursor.fetchall())
		assert data == result

	def test_add_resource(self, testdb, frozen_datetime):
		testdb.add_resource(DummyResource('file1'))

		self.validate_filenames_in_database(testdb, [
			(u'file1', None, 0, FAKE_TIME_S, u'sha256')
		])

	def test_add_resource_with_result(self, testdb, frozen_datetime):
		testdb.add_resource(DummyResource('file1'), vtresult=DummyVTResult(False))
		self.validate_filenames_in_database(testdb, [
			(u'file1', None, 0, FAKE_TIME_S, u'sha256')
		])

	def test_add_resource_update(self, testdb, frozen_datetime):
		testdb.add_resource(DummyResource('file1'), vtresult=DummyVTResult(False))
		self.validate_filenames_in_database(testdb, [
			(u'file1', None, 0, FAKE_TIME_S, u'sha256')
		])
		testdb.add_resource(DummyResource('file1'), vtresult=DummyVTResult(False))
		self.validate_filenames_in_database(testdb, [
			(u'file1', None, 0, FAKE_TIME_S, u'sha256')
		])

	def test_add_resource_update_pattern(self, testdb, frozen_datetime):
		testdb.add_resource(DummyResource('foo-bar-baz.zip'), vtresult=DummyVTResult(False))
		self.validate_filenames_in_database(testdb, [
			(u'foo-bar-baz.zip', None, 0, FAKE_TIME_S, u'sha256')
		])
		testdb.add_resource(DummyResource('foo-bar-123.zip'), vtresult=DummyVTResult(False))
		self.validate_filenames_in_database(testdb, [
			(u'foo-bar-123.zip', u'foo-bar-[RANDOM]-zip', 0, FAKE_TIME_S, u'sha256'),
			(u'foo-bar-baz.zip', None, 0, FAKE_TIME_S, u'sha256')
		])
