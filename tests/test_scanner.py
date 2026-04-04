#!/usr/bin/env python3
"""
Tests para el Scanner de Red.
"""

import pytest
import time
import tempfile
import os
import sqlite3
from unittest.mock import MagicMock, patch, PropertyMock, mock_open

try:
    from scanner_v2 import NetworkScanner
    from parallel_scanner import ParallelScanner, ScanTarget, ScanResult
    from cve_detector import CVEDetector
    from database import ScanDatabase
    from alert_system import AlertSystem
except ImportError:
    pytest.skip("Modulos principales no disponibles", allow_module_level=True)


# ---------------------------------------------------------------------------
# NetworkScanner
# ---------------------------------------------------------------------------

class TestNetworkScanner:

    def _config(self, overrides=None):
        base = {
            'scan': {
                'default_scan_type': 'tcp',
                'default_tcp_args': '-sV -T4 --open',
                'default_udp_args': '-sU -T4 --open --top-ports 1000',
                'timeout': 60,
                'os_detection': False,
                'use_nse_scripts': False,
                'nse_scripts': []
            },
            'output': {
                'default_format': 'json',
                'output_dir': '/tmp',
                'timestamp_files': False,
                'auto_save': False
            },
            'database': {'enabled': False},
            'display': {'show_progress': False, 'verbose_stats': False,
                        'use_colors': False, 'show_banners': False},
            'network': {
                'allowed_ranges': ['192.168.0.0/16', '10.0.0.0/8',
                                   '172.16.0.0/12', '127.0.0.1/32'],
                'forbidden_ranges': [],
                'max_concurrent_hosts': 50
            },
            'advanced': {'log_level': 'ERROR', 'log_file': '/dev/null'}
        }
        if overrides:
            base.update(overrides)
        return base

    def _make_scanner(self, config=None):
        cfg = config or self._config()
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data='')), \
             patch('yaml.safe_load', return_value=cfg), \
             patch('nmap.PortScanner'):
            return NetworkScanner("test_config.yaml")

    def test_initialization(self):
        scanner = self._make_scanner()
        assert scanner.config is not None
        assert scanner.db is None  # database disabled

    def test_validate_network_allowed(self):
        scanner = self._make_scanner()
        assert scanner.validate_network("192.168.1.0/24") is True

    def test_validate_network_not_in_whitelist(self):
        cfg = self._config({'network': {
            'allowed_ranges': ['10.0.0.0/8'],
            'forbidden_ranges': [],
            'max_concurrent_hosts': 50
        }})
        scanner = self._make_scanner(cfg)
        assert scanner.validate_network("192.168.1.0/24") is False

    def test_validate_network_forbidden(self):
        cfg = self._config({'network': {
            'allowed_ranges': ['192.168.0.0/16'],
            'forbidden_ranges': ['192.168.1.0/24'],
            'max_concurrent_hosts': 50
        }})
        scanner = self._make_scanner(cfg)
        assert scanner.validate_network("192.168.1.0/24") is False

    def test_validate_network_invalid_format(self):
        scanner = self._make_scanner()
        assert scanner.validate_network("not-an-ip") is False

    def test_build_nmap_arguments_tcp(self):
        scanner = self._make_scanner()
        args = scanner.build_nmap_arguments('tcp', use_nse=False)
        assert '-sV' in args
        assert '-T4' in args

    def test_build_nmap_arguments_udp(self):
        scanner = self._make_scanner()
        args = scanner.build_nmap_arguments('udp', use_nse=False)
        assert '-sU' in args

    def test_build_nmap_arguments_with_nse(self):
        cfg = self._config()
        cfg['scan']['nse_scripts'] = ['safe', 'default']
        scanner = self._make_scanner(cfg)
        args = scanner.build_nmap_arguments('tcp', use_nse=True)
        assert '--script=' in args

    def test_process_results_empty(self):
        scanner = self._make_scanner()
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = []
        scanner.nm = mock_nm
        results = scanner.process_results()
        assert results == []

    def test_process_results_with_host(self):
        scanner = self._make_scanner()
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ['192.168.1.1']

        host_mock = MagicMock()
        host_mock.state.return_value = 'up'
        host_mock.__getitem__ = MagicMock(side_effect=lambda k: {
            'addresses': {'mac': 'AA:BB:CC:DD:EE:FF'},
            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'}
        }[k])
        host_mock.get.side_effect = lambda k, default=None: {
            'osmatch': [],
            'hostscript': []
        }.get(k, default)
        host_mock.all_protocols.return_value = ['tcp']

        tcp_port = {
            'state': 'open',
            'name': 'http',
            'product': 'nginx',
            'version': '1.20',
            'script': {}
        }
        host_mock.__contains__ = MagicMock(side_effect=lambda k: k == 'tcp')
        host_mock.__getitem__ = MagicMock(side_effect=lambda k: {
            'addresses': {'mac': 'AA:BB:CC:DD:EE:FF'},
            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'},
            'tcp': {80: tcp_port}
        }[k])

        mock_nm.__getitem__ = MagicMock(return_value=host_mock)
        scanner.nm = mock_nm

        results = scanner.process_results()
        assert len(results) == 1
        assert results[0]['host'] == '192.168.1.1'

    def test_save_results_json(self, tmp_path):
        scanner = self._make_scanner()
        scanner.config['output']['output_dir'] = str(tmp_path)
        scanner.config['output']['timestamp_files'] = False

        results = [{'host': '10.0.0.1', 'status': 'up', 'mac': 'N/A',
                    'vendor': 'N/A', 'ports': [], 'os': [], 'hostscript': []}]
        scanner.save_results(results, 'test_output', 'json')

        output_file = tmp_path / 'test_output.json'
        assert output_file.exists()
        import json
        data = json.loads(output_file.read_text())
        assert data[0]['host'] == '10.0.0.1'

    def test_save_results_csv(self, tmp_path):
        scanner = self._make_scanner()
        scanner.config['output']['output_dir'] = str(tmp_path)
        scanner.config['output']['timestamp_files'] = False

        results = [{'host': '10.0.0.1', 'status': 'up', 'mac': 'N/A',
                    'vendor': 'N/A',
                    'ports': [{'port': 22, 'protocol': 'tcp',
                               'service': 'ssh', 'version': 'OpenSSH 8.0',
                               'state': 'open', 'script': {}}],
                    'os': [], 'hostscript': []}]
        scanner.save_results(results, 'test_output', 'csv')

        output_file = tmp_path / 'test_output.csv'
        assert output_file.exists()
        content = output_file.read_text()
        assert 'ssh' in content

    def test_save_results_txt(self, tmp_path):
        scanner = self._make_scanner()
        scanner.config['output']['output_dir'] = str(tmp_path)
        scanner.config['output']['timestamp_files'] = False

        results = [{'host': '10.0.0.2', 'status': 'up', 'mac': 'N/A',
                    'vendor': 'N/A',
                    'ports': [{'port': 80, 'protocol': 'tcp',
                               'service': 'http', 'version': 'Apache',
                               'state': 'open', 'script': {}}],
                    'os': [], 'hostscript': []}]
        scanner.save_results(results, 'test_output', 'txt')

        output_file = tmp_path / 'test_output.txt'
        assert output_file.exists()
        content = output_file.read_text()
        assert '10.0.0.2' in content
        assert 'http' in content


# ---------------------------------------------------------------------------
# ParallelScanner
# ---------------------------------------------------------------------------

class TestParallelScanner:

    def setup_method(self):
        self.scanner = ParallelScanner(max_workers=2, timeout=30)

    def test_expand_cidr_slash30(self):
        hosts = self.scanner.expand_network_range("192.168.1.1/30")
        assert set(hosts) == {'192.168.1.1', '192.168.1.2'}

    def test_expand_single_host(self):
        hosts = self.scanner.expand_network_range("192.168.1.1")
        assert hosts == ['192.168.1.1']

    def test_expand_dash_range(self):
        hosts = self.scanner.expand_network_range("192.168.1.1-3")
        assert hosts == ['192.168.1.1', '192.168.1.2', '192.168.1.3']

    def test_expand_invalid_raises(self):
        with pytest.raises(ValueError):
            self.scanner.expand_network_range("not-valid-at-all")

    def test_create_scan_targets_single(self):
        targets = self.scanner.create_scan_targets("127.0.0.1", "tcp")
        assert len(targets) == 1
        assert targets[0].host == "127.0.0.1"
        assert targets[0].scan_type == "tcp"

    def test_create_scan_targets_range(self):
        targets = self.scanner.create_scan_targets("10.0.0.1-3", "tcp")
        assert len(targets) == 3
        hosts = [t.host for t in targets]
        assert '10.0.0.1' in hosts
        assert '10.0.0.3' in hosts

    def test_get_statistics_empty(self):
        stats = self.scanner.get_statistics([])
        assert stats['total_hosts'] == 0
        assert stats['total_ports'] == 0

    def test_get_statistics_with_results(self):
        results = [
            ScanResult(host='10.0.0.1', status='up',
                       ports=[{'port': 80, 'protocol': 'tcp', 'service': 'http', 'version': ''},
                               {'port': 443, 'protocol': 'tcp', 'service': 'https', 'version': ''}],
                       scan_time=1.2),
            ScanResult(host='10.0.0.2', status='down', ports=[], scan_time=0.5),
        ]
        stats = self.scanner.get_statistics(results)
        assert stats['total_hosts'] == 2
        assert stats['active_hosts'] == 1
        assert stats['down_hosts'] == 1
        assert stats['total_ports'] == 2
        assert 'http' in stats['services_found']

    def test_progress_callback(self):
        called = []
        self.scanner.add_progress_callback(lambda msg, pct: called.append(pct))
        self.scanner.report_progress("test", 50.0)
        assert called == [50.0]

    @patch('nmap.PortScanner')
    def test_scan_single_host_down(self, mock_nmap_cls):
        mock_nm = MagicMock()
        mock_nmap_cls.return_value = mock_nm
        mock_nm.all_hosts.return_value = []

        target = ScanTarget(host='10.0.0.1', scan_type='tcp')
        result = self.scanner.scan_single_host(target)

        assert result.host == '10.0.0.1'
        assert result.status == 'down'
        assert result.ports == []

    @patch('nmap.PortScanner')
    def test_scan_single_host_error(self, mock_nmap_cls):
        mock_nm = MagicMock()
        mock_nmap_cls.return_value = mock_nm
        mock_nm.scan.side_effect = Exception("connection refused")

        target = ScanTarget(host='10.0.0.1', scan_type='tcp')
        result = self.scanner.scan_single_host(target)

        assert result.status == 'error'
        assert result.error is not None


# ---------------------------------------------------------------------------
# CVEDetector
# ---------------------------------------------------------------------------

class TestCVEDetector:

    def setup_method(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.detector = CVEDetector(self.temp_db.name)

    def teardown_method(self):
        os.unlink(self.temp_db.name)

    def test_cache_db_tables_created(self):
        with sqlite3.connect(self.temp_db.name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
        assert 'cve_cache' in tables
        assert 'service_cves' in tables

    def test_extract_service_version_apache(self):
        service, version = self.detector.extract_service_version(
            "apache", "Apache/2.4.49 (Ubuntu)")
        assert service == "apache"
        assert version == "2.4.49"

    def test_extract_service_version_openssh(self):
        service, version = self.detector.extract_service_version(
            "openssh", "OpenSSH_7.4 protocol 2.0")
        assert service == "openssh"
        assert version == "7.4"

    def test_extract_service_version_no_version(self):
        service, version = self.detector.extract_service_version("unknown", "some service")
        assert version == ""

    def test_check_known_cves_exact(self):
        cves = self.detector.check_known_cves("apache", "2.4.49")
        assert "CVE-2021-41773" in cves

    def test_check_known_cves_wildcard(self):
        cves = self.detector.check_known_cves("openssh", "5.3")
        assert "CVE-2010-4755" in cves

    def test_check_known_cves_unknown_service(self):
        cves = self.detector.check_known_cves("unknownservice", "1.0")
        assert cves == []

    def test_check_known_cves_no_duplicates(self):
        cves = self.detector.check_known_cves("apache", "2.4.49")
        assert len(cves) == len(set(cves))

    def test_cache_and_retrieve_cve(self):
        from cve_detector import CVEInfo
        info = CVEInfo(
            cve_id='CVE-2021-99999',
            description='Test vulnerability',
            severity='high',
            score=8.5,
            published_date='2021-01-01',
            modified_date='2021-06-01',
            affected_versions=['1.0'],
            references=['https://example.com']
        )
        self.detector.cache_cve_info(info)
        retrieved = self.detector.get_cve_from_cache('CVE-2021-99999')
        assert retrieved is not None
        assert retrieved.cve_id == 'CVE-2021-99999'
        assert retrieved.score == 8.5

    def test_analyze_scan_results_empty(self):
        report = self.detector.analyze_scan_results([])
        assert report['total_cves'] == 0
        assert report['vulnerabilities_by_host'] == {}

    def test_analyze_scan_results_no_version(self):
        results = [{'host': '10.0.0.1', 'ports': [
            {'service': 'apache', 'version': '', 'port': 80}
        ]}]
        report = self.detector.analyze_scan_results(results)
        assert report['total_cves'] == 0

    def test_get_detection_statistics(self):
        stats = self.detector.get_detection_statistics()
        assert 'cached_cves' in stats
        assert 'total_detections' in stats


# ---------------------------------------------------------------------------
# ScanDatabase
# ---------------------------------------------------------------------------

class TestScanDatabase:

    def setup_method(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.db = ScanDatabase(self.temp_db.name)

    def teardown_method(self):
        os.unlink(self.temp_db.name)

    def test_tables_created(self):
        with sqlite3.connect(self.temp_db.name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
        assert {'scans', 'hosts', 'ports', 'vulnerabilities'} <= tables

    def test_save_scan_returns_int_id(self):
        results = [{'host': '192.168.1.1', 'status': 'up', 'mac': 'N/A',
                    'ports': [{'port': 80, 'service': 'http',
                               'version': 'Apache', 'protocol': 'tcp',
                               'state': 'open'}]}]
        scan_id = self.db.save_scan("192.168.1.0/24", "tcp", results, 5.0, "-sV -T4")
        assert isinstance(scan_id, int)
        assert scan_id > 0

    def test_save_scan_persists_protocol(self):
        results = [{'host': '10.0.0.1', 'status': 'up', 'mac': 'N/A',
                    'ports': [{'port': 53, 'service': 'dns',
                               'version': 'BIND', 'protocol': 'udp',
                               'state': 'open'}]}]
        self.db.save_scan("10.0.0.0/24", "udp", results, 3.0, "-sU")

        with sqlite3.connect(self.temp_db.name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT protocol FROM ports WHERE port=53")
            row = cursor.fetchone()
        assert row is not None
        assert row[0] == 'udp'

    def test_get_scan_history_empty(self):
        history = self.db.get_scan_history()
        assert history == []

    def test_get_scan_history_returns_records(self):
        results = [{'host': '10.0.0.1', 'status': 'up', 'mac': 'N/A', 'ports': []}]
        self.db.save_scan("10.0.0.0/24", "tcp", results, 2.0, "-sV")
        history = self.db.get_scan_history()
        assert len(history) == 1
        assert history[0]['network'] == "10.0.0.0/24"

    def test_get_scan_history_filter_by_network(self):
        results = [{'host': '10.0.0.1', 'status': 'up', 'mac': 'N/A', 'ports': []}]
        self.db.save_scan("10.0.0.0/24", "tcp", results, 1.0, "-sV")
        self.db.save_scan("192.168.1.0/24", "tcp", results, 1.0, "-sV")

        history = self.db.get_scan_history(network="10.0.0.0/24")
        assert len(history) == 1
        assert history[0]['network'] == "10.0.0.0/24"

    def test_get_statistics_after_scan(self):
        results = [{'host': '10.0.0.1', 'status': 'up', 'mac': 'N/A',
                    'ports': [{'port': 22, 'service': 'ssh',
                               'version': 'OpenSSH', 'protocol': 'tcp',
                               'state': 'open'}]}]
        self.db.save_scan("10.0.0.0/24", "tcp", results, 1.0, "-sV")

        stats = self.db.get_statistics()
        assert stats['total_scans'] == 1
        assert stats['unique_hosts'] == 1
        assert stats['total_ports'] == 1

    def test_compare_scans(self):
        results1 = [{'host': '10.0.0.1', 'status': 'up', 'mac': 'N/A',
                     'ports': [{'port': 22, 'service': 'ssh', 'version': '',
                                'protocol': 'tcp', 'state': 'open'}]}]
        results2 = [{'host': '10.0.0.1', 'status': 'up', 'mac': 'N/A',
                     'ports': [{'port': 22, 'service': 'ssh', 'version': '',
                                'protocol': 'tcp', 'state': 'open'},
                               {'port': 80, 'service': 'http', 'version': '',
                                'protocol': 'tcp', 'state': 'open'}]}]

        id1 = self.db.save_scan("10.0.0.0/24", "tcp", results1, 1.0, "-sV")
        id2 = self.db.save_scan("10.0.0.0/24", "tcp", results2, 1.0, "-sV")

        diff = self.db.compare_scans(id1, id2)
        assert '10.0.0.1' in diff['port_changes']
        assert any(p['port'] == 80 for p in diff['port_changes']['10.0.0.1']['new_ports'])

    def test_cleanup_old_scans(self):
        results = [{'host': '10.0.0.1', 'status': 'up', 'mac': 'N/A', 'ports': []}]
        self.db.save_scan("10.0.0.0/24", "tcp", results, 1.0, "-sV")

        # Forzar timestamp antiguo directamente en BD
        with sqlite3.connect(self.temp_db.name) as conn:
            conn.execute("UPDATE scans SET timestamp='2000-01-01T00:00:00'")

        self.db.cleanup_old_scans(retention_days=1)

        stats = self.db.get_statistics()
        assert stats['total_scans'] == 0


# ---------------------------------------------------------------------------
# AlertSystem
# ---------------------------------------------------------------------------

class TestAlertSystem:

    def setup_method(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.config = {'notifications': {'email': {'enabled': False}}}
        self.alert_system = AlertSystem(self.config, self.temp_db.name)

    def teardown_method(self):
        os.unlink(self.temp_db.name)

    def test_default_rules_loaded(self):
        rules = self.alert_system.get_active_rules()
        rule_ids = {r.id for r in rules}
        assert 'insecure_service_detected' in rule_ids
        assert 'high_risk_port_open' in rule_ids

    def test_get_rule_existing(self):
        rule = self.alert_system.get_rule('high_risk_port_open')
        assert rule is not None
        assert rule.severity == 'high'

    def test_get_rule_nonexistent(self):
        rule = self.alert_system.get_rule('this_does_not_exist')
        assert rule is None

    def test_evaluate_insecure_service(self):
        scan_data = {'scan_results': [
            {'host': '10.0.0.1', 'ports': [
                {'port': 23, 'service': 'telnet', 'version': ''}
            ]}
        ]}
        rule = self.alert_system.get_rule('insecure_service_detected')
        alerts = self.alert_system.evaluate_single_rule(rule, scan_data)
        assert len(alerts) > 0
        assert alerts[0].host == '10.0.0.1'

    def test_evaluate_high_risk_port(self):
        scan_data = {'scan_results': [
            {'host': '10.0.0.1', 'ports': [
                {'port': 3389, 'service': 'ms-wbt-server', 'version': ''}
            ]}
        ]}
        rule = self.alert_system.get_rule('high_risk_port_open')
        alerts = self.alert_system.evaluate_single_rule(rule, scan_data)
        assert any(a.port == 3389 for a in alerts)

    def test_acknowledge_alert(self):
        from alert_system import Alert
        from datetime import datetime
        alert = Alert(
            id='test-alert-001', rule_id='test', title='Test',
            message='Test alert', severity='low', host='10.0.0.1',
            port=None, service=None, data={},
            timestamp=datetime.now().isoformat()
        )
        self.alert_system.save_alert(alert)
        assert self.alert_system.acknowledge_alert('test-alert-001') is True

    def test_acknowledge_nonexistent_alert(self):
        assert self.alert_system.acknowledge_alert('does-not-exist') is False

    def test_get_recent_alerts_empty(self):
        alerts = self.alert_system.get_recent_alerts(hours=24)
        assert alerts == []

    def test_get_alert_statistics(self):
        stats = self.alert_system.get_alert_statistics()
        assert 'total_alerts' in stats
        assert 'by_severity' in stats
        assert 'recent_24h' in stats


# ---------------------------------------------------------------------------
# Performance / timing
# ---------------------------------------------------------------------------

class TestPerformance:

    def test_expand_network_range_is_fast(self):
        scanner = ParallelScanner(max_workers=5)
        start = time.time()
        targets = scanner.create_scan_targets("10.0.0.1-50", "tcp")
        elapsed = time.time() - start
        assert len(targets) == 50
        assert elapsed < 1.0

    def test_cve_lookup_known_service_is_fast(self):
        temp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        temp.close()
        try:
            detector = CVEDetector(temp.name)
            start = time.time()
            cves = detector.check_known_cves("apache", "2.4.49")
            elapsed = time.time() - start
            assert elapsed < 0.1
            assert len(cves) > 0
        finally:
            os.unlink(temp.name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
