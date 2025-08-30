#!/usr/bin/env python3
"""
Tests unitarios para el Advanced Network Scanner.
"""

import pytest
import unittest.mock as mock
from unittest.mock import MagicMock, patch
import tempfile
import os

# Importar módulos a testear
try:
    from scanner_v2 import NetworkScanner
    from parallel_scanner import ParallelScanner
    from cve_detector import CVEDetector
    from database import ScanDatabase
except ImportError:
    pytest.skip("Módulos principales no disponibles", allow_module_level=True)


class TestNetworkScanner:
    """Tests para NetworkScanner."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.config = {
            'scan': {
                'default_scan_type': 'tcp',
                'use_nse_scripts': True,
                'timeout': 60
            },
            'database': {
                'enabled': False
            }
        }
    
    @patch('yaml.safe_load')
    @patch('builtins.open')
    @patch('os.path.exists')
    def test_scanner_initialization(self, mock_exists, mock_open, mock_yaml):
        """Test inicialización del scanner."""
        mock_exists.return_value = True
        mock_yaml.return_value = self.config
        
        scanner = NetworkScanner("test_config.yaml")
        assert scanner.config == self.config
    
    @patch('nmap.PortScanner')
    def test_scan_network_basic(self, mock_nmap):
        """Test escaneo básico de red."""
        # Mock nmap scanner
        mock_nm = MagicMock()
        mock_nmap.return_value = mock_nm
        mock_nm.all_hosts.return_value = ['192.168.1.1']
        mock_nm.__getitem__.return_value = {
            'state': lambda: 'up',
            'addresses': {'mac': '00:11:22:33:44:55'},
            'vendor': {'00:11:22:33:44:55': 'Test Vendor'},
            'tcp': {80: {'state': 'open', 'name': 'http', 'product': 'Apache', 'version': '2.4'}},
            'osmatch': [],
            'hostscript': []
        }
        
        with patch('yaml.safe_load', return_value=self.config), \
             patch('os.path.exists', return_value=True):
            scanner = NetworkScanner("test_config.yaml")
            results = scanner.scan_network("192.168.1.1")
            
            assert len(results) == 1
            assert results[0]['host'] == '192.168.1.1'
            assert results[0]['status'] == 'up'
    
    def test_validate_network_valid(self):
        """Test validación de red válida."""
        with patch('yaml.safe_load', return_value=self.config), \
             patch('os.path.exists', return_value=True):
            scanner = NetworkScanner("test_config.yaml")
            result = scanner.validate_network("192.168.1.0/24")
            assert result is True
    
    def test_validate_network_invalid(self):
        """Test validación de red inválida."""
        config_with_restrictions = {
            **self.config,
            'network': {
                'allowed_ranges': ['10.0.0.0/8'],
                'forbidden_ranges': []
            }
        }
        
        with patch('yaml.safe_load', return_value=config_with_restrictions), \
             patch('os.path.exists', return_value=True):
            scanner = NetworkScanner("test_config.yaml")
            result = scanner.validate_network("192.168.1.0/24")
            assert result is False


class TestParallelScanner:
    """Tests para ParallelScanner."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.scanner = ParallelScanner(max_workers=2, timeout=30)
    
    def test_expand_network_range_cidr(self):
        """Test expansión de rango CIDR."""
        hosts = self.scanner.expand_network_range("192.168.1.1/30")
        expected = ['192.168.1.1', '192.168.1.2']
        assert set(hosts) == set(expected)
    
    def test_expand_network_range_single(self):
        """Test expansión de host único."""
        hosts = self.scanner.expand_network_range("192.168.1.1")
        assert hosts == ['192.168.1.1']
    
    def test_expand_network_range_dash(self):
        """Test expansión de rango con guiones."""
        hosts = self.scanner.expand_network_range("192.168.1.1-3")
        expected = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        assert hosts == expected
    
    def test_create_scan_targets(self):
        """Test creación de objetivos de escaneo."""
        targets = self.scanner.create_scan_targets("127.0.0.1", "tcp")
        assert len(targets) == 1
        assert targets[0].host == "127.0.0.1"
        assert targets[0].scan_type == "tcp"


class TestCVEDetector:
    """Tests para CVEDetector."""
    
    def setup_method(self):
        """Setup para cada test."""
        # Usar base de datos temporal
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.detector = CVEDetector(self.temp_db.name)
    
    def teardown_method(self):
        """Cleanup después de cada test."""
        os.unlink(self.temp_db.name)
    
    def test_extract_service_version(self):
        """Test extracción de servicio y versión."""
        service, version = self.detector.extract_service_version("apache", "Apache/2.4.49 (Ubuntu)")
        assert service == "apache"
        assert version == "2.4.49"
    
    def test_check_known_cves(self):
        """Test verificación de CVEs conocidos."""
        cves = self.detector.check_known_cves("apache", "2.4.49")
        assert isinstance(cves, list)
        # Apache 2.4.49 tiene CVEs conocidos
        assert len(cves) > 0
    
    def test_analyze_service_vulnerabilities(self):
        """Test análisis de vulnerabilidades de servicio."""
        vulns = self.detector.analyze_service_vulnerabilities("apache", "Apache/2.4.49", 80)
        assert isinstance(vulns, list)
        # Debería encontrar vulnerabilidades para Apache 2.4.49
        if vulns:  # Si hay CVEs conocidos configurados
            assert vulns[0]['service'] == 'apache'
            assert vulns[0]['version'] == '2.4.49'


class TestScanDatabase:
    """Tests para ScanDatabase."""
    
    def setup_method(self):
        """Setup para cada test."""
        # Usar base de datos temporal
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.db = ScanDatabase(self.temp_db.name)
    
    def teardown_method(self):
        """Cleanup después de cada test."""
        os.unlink(self.temp_db.name)
    
    def test_database_initialization(self):
        """Test inicialización de base de datos."""
        # Verificar que las tablas fueron creadas
        import sqlite3
        with sqlite3.connect(self.temp_db.name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            
            expected_tables = ['scans', 'hosts', 'ports', 'vulnerabilities']
            for table in expected_tables:
                assert table in tables
    
    def test_save_scan(self):
        """Test guardado de escaneo."""
        test_results = [{
            'host': '192.168.1.1',
            'status': 'up',
            'mac': '00:11:22:33:44:55',
            'ports': [
                {'port': 80, 'service': 'http', 'version': 'Apache/2.4', 'protocol': 'tcp'}
            ]
        }]
        
        scan_id = self.db.save_scan("192.168.1.0/24", "tcp", test_results, 10.5, "-sV -T4")
        assert isinstance(scan_id, int)
        assert scan_id > 0
    
    def test_get_statistics(self):
        """Test obtención de estadísticas."""
        stats = self.db.get_statistics()
        assert isinstance(stats, dict)
        assert 'total_scans' in stats
        assert 'unique_hosts' in stats


class TestIntegration:
    """Tests de integración."""
    
    @pytest.mark.slow
    @patch('nmap.PortScanner')
    def test_full_scan_workflow(self, mock_nmap):
        """Test workflow completo de escaneo."""
        # Mock nmap para evitar escaneo real
        mock_nm = MagicMock()
        mock_nmap.return_value = mock_nm
        mock_nm.all_hosts.return_value = ['127.0.0.1']
        mock_nm.__getitem__.return_value = {
            'state': lambda: 'up',
            'addresses': {'mac': 'N/A'},
            'vendor': {},
            'tcp': {22: {'state': 'open', 'name': 'ssh', 'product': 'OpenSSH', 'version': '7.4'}},
            'osmatch': [],
            'hostscript': []
        }
        
        config = {
            'scan': {'default_scan_type': 'tcp', 'use_nse_scripts': False},
            'database': {'enabled': True, 'db_file': ':memory:'},
            'network': {'allowed_ranges': ['127.0.0.0/8'], 'forbidden_ranges': []}
        }
        
        with patch('yaml.safe_load', return_value=config), \
             patch('os.path.exists', return_value=True):
            
            # Test scanner
            scanner = NetworkScanner("test_config.yaml")
            results = scanner.scan_network("127.0.0.1")
            
            assert len(results) == 1
            assert results[0]['host'] == '127.0.0.1'
            assert len(results[0]['ports']) == 1
            assert results[0]['ports'][0]['service'] == 'ssh'


# Tests de performance
class TestPerformance:
    """Tests de rendimiento."""
    
    @pytest.mark.slow
    def test_parallel_scanner_performance(self):
        """Test rendimiento del scanner paralelo."""
        scanner = ParallelScanner(max_workers=5)
        
        # Test con rango pequeño
        start_time = time.time()
        targets = scanner.create_scan_targets("127.0.0.1-2", "tcp")
        end_time = time.time()
        
        assert len(targets) == 2
        assert (end_time - start_time) < 1.0  # Debe ser rápido


if __name__ == "__main__":
    # Ejecutar tests si el script se ejecuta directamente
    pytest.main([__file__, "-v"])