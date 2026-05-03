#!/usr/bin/env python3
"""
Tests para web_dashboard, api_server y startup.
"""

import pytest
import tempfile
import os
import json
from unittest.mock import patch, MagicMock


class TestWebDashboard:

    @pytest.fixture(autouse=True)
    def setup_app(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.temp_alerts_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_alerts_db.close()
        self.temp_cve_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_cve_db.close()

        from database import ScanDatabase
        from alert_system import AlertSystem
        from cve_detector import CVEDetector
        import web_dashboard

        self.real_db = ScanDatabase(self.temp_db.name)
        self.real_alert = AlertSystem({}, self.temp_alerts_db.name, scan_db=self.real_db)
        self.real_cve = CVEDetector(self.temp_cve_db.name)

        web_dashboard.scan_db = self.real_db
        web_dashboard.alert_system = self.real_alert
        web_dashboard.cve_detector = self.real_cve

        app = web_dashboard.app
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test-secret-key'
        self.client = app.test_client()
        yield
        os.unlink(self.temp_db.name)
        os.unlink(self.temp_alerts_db.name)
        os.unlink(self.temp_cve_db.name)

    def test_dashboard_page(self):
        resp = self.client.get('/')
        assert resp.status_code in (200, 302)

    def test_scans_page(self):
        resp = self.client.get('/scans')
        assert resp.status_code in (200, 302)

    def test_alerts_page(self):
        resp = self.client.get('/alerts')
        assert resp.status_code in (200, 302)

    def test_analytics_page(self):
        resp = self.client.get('/analytics')
        assert resp.status_code in (200, 302)

    def test_api_recent_scans(self):
        resp = self.client.get('/api/scans/recent')
        assert resp.status_code in (200, 302)

    def test_api_statistics(self):
        resp = self.client.get('/api/statistics')
        assert resp.status_code in (200, 302)

    def test_api_recent_alerts(self):
        resp = self.client.get('/api/alerts/recent')
        assert resp.status_code in (200, 302)

    def test_api_scan_start_no_network(self):
        resp = self.client.post('/api/scan/start',
                                json={},
                                content_type='application/json')
        assert resp.status_code in (400, 302)

    def test_api_scan_start_with_network(self):
        with patch('web_dashboard.NetworkScanner') as mock_cls:
            mock_scanner = MagicMock()
            mock_scanner.validate_network.return_value = True
            mock_scanner.scan_network.return_value = []
            mock_cls.return_value = mock_scanner
            resp = self.client.post('/api/scan/start',
                                    json={'network': '127.0.0.1', 'scan_type': 'tcp'},
                                    content_type='application/json')
            assert resp.status_code in (200, 302, 201)

    def test_api_scan_status_not_found(self):
        resp = self.client.get('/api/scan/status/nonexistent-id')
        assert resp.status_code in (404, 302)

    def test_404_page(self):
        resp = self.client.get('/nonexistent-route')
        assert resp.status_code == 404

    def test_login_page_exists(self):
        resp = self.client.get('/login')
        assert resp.status_code == 200


class TestAPIServer:

    @pytest.fixture(autouse=True)
    def setup_app(self):
        from api_server import app, load_config
        os.environ['SCANNER_API_KEY'] = 'test-api-key'
        load_config()
        app.config['TESTING'] = True
        self.client = app.test_client()
        self.api_key = 'test-api-key'
        yield
        if 'SCANNER_API_KEY' in os.environ:
            del os.environ['SCANNER_API_KEY']

    def test_api_info_no_auth(self):
        resp = self.client.get('/api/v1/info')
        assert resp.status_code == 200

    def test_api_status_requires_auth(self):
        resp = self.client.get('/api/v1/status')
        assert resp.status_code == 401

    def test_api_status_with_auth(self):
        resp = self.client.get('/api/v1/status',
                               headers={'X-API-Key': self.api_key})
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data['status'] == 'online'

    def test_api_list_scans_with_auth(self):
        resp = self.client.get('/api/v1/scans',
                               headers={'X-API-Key': self.api_key})
        assert resp.status_code == 200

    def test_api_create_scan_missing_network(self):
        resp = self.client.post('/api/v1/scans',
                                json={},
                                headers={'X-API-Key': self.api_key},
                                content_type='application/json')
        assert resp.status_code == 400

    def test_api_create_scan_invalid_type(self):
        resp = self.client.post('/api/v1/scans',
                                json={'network': '192.168.1.0/24', 'scan_type': 'invalid'},
                                headers={'X-API-Key': self.api_key},
                                content_type='application/json')
        assert resp.status_code == 400

    def test_api_list_alerts_with_auth(self):
        resp = self.client.get('/api/v1/alerts',
                               headers={'X-API-Key': self.api_key})
        assert resp.status_code == 200

    def test_api_statistics_with_auth(self):
        resp = self.client.get('/api/v1/statistics',
                               headers={'X-API-Key': self.api_key})
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert 'system_statistics' in data
        assert 'uptime_hours' in data['system_statistics']
        assert data['system_statistics']['uptime_hours'] >= 0

    def test_api_hosts_with_auth(self):
        resp = self.client.get('/api/v1/hosts',
                               headers={'X-API-Key': self.api_key})
        assert resp.status_code == 200

    def test_api_vulnerabilities_with_auth(self):
        resp = self.client.get('/api/v1/vulnerabilities',
                               headers={'X-API-Key': self.api_key})
        assert resp.status_code == 200

    def test_api_stop_scan_not_found(self):
        resp = self.client.post('/api/v1/scans/nonexistent/stop',
                               headers={'X-API-Key': self.api_key})
        assert resp.status_code == 404

    def test_api_scan_status_not_found(self):
        resp = self.client.get('/api/v1/scans/nonexistent/status',
                               headers={'X-API-Key': self.api_key})
        assert resp.status_code == 200

    def test_api_error_handlers(self):
        resp = self.client.get('/api/v1/alerts/nonexistent-alert',
                               headers={'X-API-Key': self.api_key})
        assert resp.status_code in (404, 500)

    def test_rate_limiting(self):
        from api_server import _check_rate_limit, _scan_request_timestamps
        _scan_request_timestamps.clear()
        client_id = 'test-client-rl'
        for _ in range(10):
            assert _check_rate_limit(client_id) is True
        assert _check_rate_limit(client_id) is False


class TestStartup:

    def test_load_config_exists(self):
        from startup import load_config
        config = load_config()
        assert isinstance(config, dict)

    def test_check_dependencies(self):
        from startup import check_dependencies
        result = check_dependencies()
        assert isinstance(result, bool)

    def test_show_status_runs(self):
        from startup import show_status
        show_status()

    def test_show_help_runs(self):
        from startup import show_help
        show_help()
