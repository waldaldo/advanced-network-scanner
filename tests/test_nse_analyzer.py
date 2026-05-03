#!/usr/bin/env python3
"""
Tests para NSEAnalyzer.
"""

import pytest
import tempfile
import os

from nse_analyzer import NSEAnalyzer


class TestNSEAnalyzer:

    def setup_method(self):
        self.analyzer = NSEAnalyzer()

    def test_analyze_host_scripts_empty(self):
        host_data = {'hostscript': [], 'ports': []}
        findings = self.analyzer.analyze_host_scripts(host_data)
        assert 'vulnerabilities' in findings
        assert 'services_info' in findings
        assert 'security_issues' in findings
        assert 'recommendations' in findings

    def test_analyze_vuln_script_with_cve(self):
        findings = {'vulnerabilities': [], 'services_info': [], 'security_issues': [], 'recommendations': []}
        script = {'id': 'vuln', 'output': 'VULNERABLE: CVE-2017-0144 EternalBlue'}
        self.analyzer.analyze_script_output(script, findings)
        assert len(findings['vulnerabilities']) > 0

    def test_analyze_ssl_script_expired(self):
        findings = {'vulnerabilities': [], 'services_info': [], 'security_issues': [], 'recommendations': []}
        script = {'id': 'ssl-cert', 'output': 'The certificate has expired'}
        self.analyzer.analyze_script_output(script, findings)
        assert any('expirado' in str(s) for s in findings['security_issues'])

    def test_analyze_ssl_script_weak_cipher(self):
        findings = {'vulnerabilities': [], 'services_info': [], 'security_issues': [], 'recommendations': []}
        script = {'id': 'ssl-enum-ciphers', 'output': 'RC4 cipher detected'}
        self.analyzer.analyze_script_output(script, findings)
        assert any('RC4' in str(s) for s in findings['security_issues'])

    def test_analyze_ms17_010_vulnerable(self):
        findings = {'vulnerabilities': [], 'services_info': [], 'security_issues': [], 'recommendations': []}
        script = {'id': 'smb-vuln-ms17-010', 'output': 'VULNERABLE'}
        port_info = {'port': 445, 'service': 'smb'}
        self.analyzer.analyze_script_output(script, findings, port_info)
        assert any(v.get('type') == 'ms17_010' for v in findings['vulnerabilities'])

    def test_analyze_ssh_old_version(self):
        port_info = {'service': 'ssh', 'version': 'OpenSSH 4.3'}
        findings = self.analyzer.analyze_ssh(port_info)
        assert len(findings['security_issues']) > 0

    def test_analyze_ftp_insecure(self):
        port_info = {'service': 'ftp', 'version': 'vsftpd 3.0'}
        findings = self.analyzer.analyze_ftp(port_info)
        assert len(findings['security_issues']) > 0
        assert len(findings['recommendations']) > 0

    def test_analyze_http_old_apache(self):
        port_info = {'service': 'http', 'version': 'Apache/2.2.22'}
        findings = self.analyzer.analyze_http(port_info)
        assert len(findings['security_issues']) > 0

    def test_analyze_smb_exposed(self):
        port_info = {'service': 'smb', 'version': 'Samba 4.0'}
        findings = self.analyzer.analyze_smb(port_info)
        assert len(findings['security_issues']) > 0

    def test_analyze_mysql_exposed(self):
        port_info = {'service': 'mysql', 'version': 'MySQL 5.7'}
        findings = self.analyzer.analyze_mysql(port_info)
        assert any('MySQL' in s.get('description', '') for s in findings['security_issues'])

    def test_analyze_vnc_exposed(self):
        port_info = {'service': 'vnc', 'version': 'RealVNC 4.0'}
        findings = self.analyzer.analyze_vnc(port_info)
        assert any('VNC' in s.get('description', '') for s in findings['security_issues'])

    def test_analyze_telnet_insecure(self):
        port_info = {'service': 'telnet', 'version': 'Linux'}
        findings = self.analyzer.analyze_telnet(port_info)
        assert any('texto plano' in s.get('description', '') for s in findings['security_issues'])

    def test_merge_findings(self):
        target = {'vulnerabilities': [1], 'services_info': [2], 'security_issues': [3], 'recommendations': [4]}
        source = {'vulnerabilities': [5], 'services_info': [], 'security_issues': [6], 'recommendations': [7]}
        self.analyzer.merge_findings(target, source)
        assert target['vulnerabilities'] == [1, 5]
        assert target['security_issues'] == [3, 6]

    def test_generate_security_report_empty(self):
        report = self.analyzer.generate_security_report([])
        assert report['summary']['hosts_analyzed'] == 0
        assert 'recommendations' in report

    def test_http_enum_interesting_paths(self):
        findings = {'vulnerabilities': [], 'services_info': [], 'security_issues': [], 'recommendations': []}
        script = {'id': 'http-enum', 'output': '/admin/login.php\n/backup/db.sql\n/normal/page.html'}
        self.analyzer.analyze_script_output(script, findings)
        assert len(findings['services_info']) > 0

    def test_vulnerability_pattern_critical(self):
        findings = {'vulnerabilities': [], 'services_info': [], 'security_issues': [], 'recommendations': []}
        script = {'id': 'some-script', 'output': 'VULNERABLE: remote code execution detected'}
        self.analyzer.analyze_script_output(script, findings)
        high_or_critical = [v for v in findings['vulnerabilities'] if v['severity'] in ('high', 'critical')]
        assert len(high_or_critical) > 0
