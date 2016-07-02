# -*- coding: utf-8 -*-
from amavisvt.client import VTResponse, FilenameResponse


class TestResponse(object):
	def test_vtresponse(self):
		d = {
			"response_code": 1,
			"verbose_msg": "Scan finished, scan information embedded in this object",
			"resource": "99017f6eebbac24f351415dd410d522d",
			"scan_id": "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724",
			"md5": "99017f6eebbac24f351415dd410d522d",
			"sha1": "4d1740485713a2ab3a4f5822a01f645fe8387f92",
			"sha256": "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c",
			"scan_date": "2010-05-15 03:38:44",
			"positives": 40,
			"total": 40,
			"scans": {
				"nProtect": {"detected": True, "version": "2010-05-14.01", "result": "Trojan.Generic.3611249", "update": "20100514"},
				"CAT-QuickHeal": {"detected": True, "version": "10.00", "result": "Trojan.VB.acgy", "update": "20100514"},
				"McAfee": {"detected": True, "version": "5.400.0.1158", "result": "Generic.dx!rkx", "update": "20100515"},
				"TheHacker": {"detected": True, "version": "6.5.2.0.280", "result": "Trojan/VB.gen", "update": "20100514"},
				"VirusBuster": {"detected": True, "version": "5.0.27.0", "result": "Trojan.VB.JFDE", "update": "20100514"},
				"NOD32": {"detected": True, "version": "5115", "result": "a variant of Win32/Qhost.NTY", "update": "20100514"},
				"F-Prot": {"detected": False, "version": "4.5.1.85", "result": None, "update": "20100514"},
				"Symantec": {"detected": True, "version": "20101.1.0.89", "result": "Trojan.KillAV", "update": "20100515"},
			},
			"permalink": "https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/"
		}
		r = VTResponse(d)
		assert r.response_code == 1
		assert r.verbose_message == "Scan finished, scan information embedded in this object"
		assert r.resource == "99017f6eebbac24f351415dd410d522d"
		assert r.scan_id == "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724"
		assert r.md5 == "99017f6eebbac24f351415dd410d522d"
		assert r.sha1 == "4d1740485713a2ab3a4f5822a01f645fe8387f92"
		assert r.sha256 == "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c"
		assert r.scan_date == "2010-05-15 03:38:44"
		assert r.positives == 40
		assert r.total == 40
		assert r.permalink == "https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/"
		assert r.scans == d['scans']

		assert r.infected is False

		assert str(r) == "99017f6eebbac24f351415dd410d522d: Scan finished, scan information embedded in this object"

	def test_filenameresponse(self):
		r = FilenameResponse()
		assert r.infected is True
		assert r.positives == 1
		assert r.total == 1
		assert r.sha256 == ''
		assert str(r) == '<filename>: <no message>'
