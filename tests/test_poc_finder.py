#!/usr/bin/env python3
"""
Tests para POCFinder.
"""

import pytest
import tempfile
import os
import sqlite3
from unittest.mock import patch, MagicMock

from poc_finder import POCFinder, POCInfo, EXPLOIT_SOURCES


class TestPOCFinder:

    def setup_method(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.finder = POCFinder(cache_file=self.temp_db.name)

    def teardown_method(self):
        os.unlink(self.temp_db.name)

    def test_cache_db_created(self):
        with sqlite3.connect(self.temp_db.name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            assert 'poc_cache' in tables

    def test_build_search_links(self):
        links = self.finder.build_search_links('CVE-2021-41773')
        assert 'exploit_db' in links
        assert 'CVE-2021-41773' in links['exploit_db']
        assert 'nvd' in links
        assert len(links) == len(EXPLOIT_SOURCES)

    def test_is_exploit_ref_with_tags(self):
        assert self.finder._is_exploit_ref('http://example.com', ['Exploit']) is True
        assert self.finder._is_exploit_ref('http://example.com', ['Vendor Advisory']) is False

    def test_is_exploit_ref_with_url_pattern(self):
        assert self.finder._is_exploit_ref('https://www.exploit-db.com/exploits/123', []) is True
        assert self.finder._is_exploit_ref('https://github.com/user/cve-2021-poc', []) is True
        assert self.finder._is_exploit_ref('https://example.com/advisory', []) is False

    def test_save_and_load_from_db(self):
        info = POCInfo(
            cve_id='CVE-2021-TEST',
            description='Test vulnerability',
            cvss_score=9.8,
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            severity='critical',
            cwe=['CWE-787'],
            affected_products=['TestProduct 1.0'],
            exploit_references=[{'url': 'https://exploit-db.com/test', 'tags': ['Exploit']}],
            search_links={'nvd': 'https://nvd.nist.gov/vuln/detail/CVE-2021-TEST'},
            has_public_exploit=True,
            published_date='2021-01-01',
            last_modified='2021-06-01'
        )
        self.finder._save_to_db(info)
        loaded = self.finder._load_from_db('CVE-2021-TEST')
        assert loaded is not None
        assert loaded.cve_id == 'CVE-2021-TEST'
        assert loaded.cvss_score == 9.8
        assert loaded.severity == 'critical'
        assert loaded.has_public_exploit is True
        assert 'CWE-787' in loaded.cwe

    def test_load_from_db_nonexistent(self):
        loaded = self.finder._load_from_db('CVE-NONEXISTENT')
        assert loaded is None

    def test_enrich_uses_db_cache(self):
        info = POCInfo(
            cve_id='CVE-CACHED',
            description='Cached vuln',
            cvss_score=7.5,
            severity='high',
            has_public_exploit=False
        )
        self.finder._save_to_db(info)
        result = self.finder.enrich('CVE-CACHED')
        assert result.cve_id == 'CVE-CACHED'
        assert result.cvss_score == 7.5

    def test_enrich_uses_memory_cache(self):
        info = POCInfo(cve_id='CVE-MEM', description='Memory cached')
        self.finder._cache['CVE-MEM'] = info
        result = self.finder.enrich('CVE-MEM')
        assert result.cve_id == 'CVE-MEM'

    @patch.object(POCFinder, 'fetch_circl', return_value=None)
    def test_enrich_no_api_data(self, mock_fetch):
        self.finder._cache.clear()
        result = self.finder.enrich('CVE-NOAPI')
        assert result.cve_id == 'CVE-NOAPI'
        assert result.severity == 'unknown'
        assert len(result.search_links) > 0

    def test_enrich_bulk(self):
        info1 = POCInfo(cve_id='CVE-B1', description='Bulk 1')
        info2 = POCInfo(cve_id='CVE-B2', description='Bulk 2')
        self.finder._cache['CVE-B1'] = info1
        self.finder._cache['CVE-B2'] = info2
        results = self.finder.enrich_bulk(['CVE-B1', 'CVE-B2'])
        assert len(results) == 2
        assert 'CVE-B1' in results

    def test_format_report(self):
        info = POCInfo(
            cve_id='CVE-FMT',
            description='Format test',
            cvss_score=5.5,
            severity='medium',
            cwe=['CWE-79'],
            has_public_exploit=False
        )
        report = self.finder.format_report(info)
        assert report['cve_id'] == 'CVE-FMT'
        assert report['cvss_score'] == 5.5
        assert report['severity'] == 'medium'

    @patch('poc_finder.requests.Session.get')
    def test_fetch_circl_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'containers': {'cna': {
                'descriptions': [{'lang': 'en', 'value': 'Test desc'}],
                'references': [{'url': 'https://exploit-db.com/test', 'tags': ['Exploit']}],
                'metrics': [{'cvssV3_1': {'baseScore': 9.1, 'vectorString': 'CVSS:3.1/AV:N'}}],
                'problemTypes': [{'descriptions': [{'cweId': 'CWE-119'}]}],
                'affected': [{'vendor': 'Test', 'product': 'App', 'versions': [{'version': '1.0'}]}]
            }},
            'cveMetadata': {'datePublished': '2021-01-01T00:00:00', 'dateUpdated': '2021-06-01T00:00:00'}
        }
        mock_get.return_value = mock_resp
        data = self.finder.fetch_circl('CVE-2021-TEST')
        assert data is not None
        assert 'containers' in data

    @patch('poc_finder.requests.Session.get')
    def test_fetch_circl_not_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp
        data = self.finder.fetch_circl('CVE-NOTFOUND')
        assert data is None
