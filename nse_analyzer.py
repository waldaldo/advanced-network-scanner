#!/usr/bin/env python3
"""
Analizador de resultados NSE para identificar vulnerabilidades y información de seguridad.
"""
import re
import json
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

class NSEAnalyzer:
    def __init__(self):
        self.console = Console()
        self.vulnerability_patterns = {
            'high': [
                r'VULNERABLE',
                r'CVE-\d{4}-\d{4,}',
                r'anonymous.*login.*allowed',
                r'default.*credentials',
                r'backdoor',
                r'RCE',
                r'remote.*code.*execution'
            ],
            'medium': [
                r'weak.*cipher',
                r'deprecated.*protocol',
                r'information.*disclosure',
                r'directory.*traversal',
                r'cross.*site.*scripting',
                r'XSS'
            ],
            'low': [
                r'information.*leak',
                r'banner.*grab',
                r'version.*detection'
            ]
        }
        
        self.service_analyzers = {
            'ssh': self.analyze_ssh,
            'ftp': self.analyze_ftp,
            'http': self.analyze_http,
            'https': self.analyze_https,
            'smb': self.analyze_smb,
            'mysql': self.analyze_mysql,
            'mssql': self.analyze_mssql,
            'vnc': self.analyze_vnc,
            'telnet': self.analyze_telnet
        }
    
    def analyze_host_scripts(self, host_data: Dict) -> Dict:
        """Analiza los scripts NSE ejecutados en un host."""
        findings = {
            'vulnerabilities': [],
            'services_info': [],
            'security_issues': [],
            'recommendations': []
        }
        
        # Analizar scripts a nivel de host
        for script in host_data.get('hostscript', []):
            self.analyze_script_output(script, findings)
        
        # Analizar scripts a nivel de puerto
        for port in host_data.get('ports', []):
            service = port.get('service', '').lower()
            
            # Análisis específico por servicio
            if service in self.service_analyzers:
                service_findings = self.service_analyzers[service](port)
                self.merge_findings(findings, service_findings)
            
            # Análisis de scripts NSE del puerto
            for script_name, script_output in port.get('script', {}).items():
                script_data = {'id': script_name, 'output': script_output}
                self.analyze_script_output(script_data, findings, port)
        
        return findings
    
    def analyze_script_output(self, script: Dict, findings: Dict, port_info: Dict = None):
        """Analiza la salida de un script NSE específico."""
        script_id = script.get('id', '')
        script_output = script.get('output', '')
        
        # Detectar vulnerabilidades por patrones
        for severity, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, script_output, re.IGNORECASE)
                for match in matches:
                    vulnerability = {
                        'type': 'pattern_match',
                        'severity': severity,
                        'script': script_id,
                        'match': match.group(),
                        'context': script_output[:200],
                        'port': port_info.get('port') if port_info else None,
                        'service': port_info.get('service') if port_info else None
                    }
                    findings['vulnerabilities'].append(vulnerability)
        
        # Análisis específico por script
        if script_id in ['vuln', 'vulners']:
            self.analyze_vuln_script(script_output, findings, port_info)
        elif script_id in ['ssl-cert', 'ssl-enum-ciphers']:
            self.analyze_ssl_script(script_output, findings, port_info)
        elif script_id == 'http-enum':
            self.analyze_http_enum_script(script_output, findings, port_info)
        elif script_id == 'smb-vuln-ms17-010':
            self.analyze_ms17_010_script(script_output, findings, port_info)
        elif 'enum' in script_id:
            self.analyze_enum_script(script_id, script_output, findings, port_info)
    
    def analyze_vuln_script(self, output: str, findings: Dict, port_info: Dict = None):
        """Analiza scripts de detección de vulnerabilidades."""
        lines = output.split('\n')
        current_vuln = None
        
        for line in lines:
            line = line.strip()
            
            # Detectar CVEs
            cve_match = re.search(r'CVE-(\d{4})-(\d{4,})', line)
            if cve_match:
                vulnerability = {
                    'type': 'cve',
                    'severity': 'high',
                    'cve_id': cve_match.group(),
                    'description': line,
                    'port': port_info.get('port') if port_info else None,
                    'service': port_info.get('service') if port_info else None
                }
                findings['vulnerabilities'].append(vulnerability)
            
            # Detectar estados de vulnerabilidad
            if 'VULNERABLE' in line.upper():
                vuln_name = line.split(':')[0].strip() if ':' in line else line
                vulnerability = {
                    'type': 'vulnerability',
                    'severity': 'high',
                    'name': vuln_name,
                    'description': line,
                    'port': port_info.get('port') if port_info else None,
                    'service': port_info.get('service') if port_info else None
                }
                findings['vulnerabilities'].append(vulnerability)
    
    def analyze_ssl_script(self, output: str, findings: Dict, port_info: Dict = None):
        """Analiza scripts SSL/TLS."""
        issues = []
        
        # Detectar certificados expirados
        if 'expired' in output.lower():
            issues.append("Certificado SSL expirado")
        
        # Detectar algoritmos débiles
        weak_ciphers = ['RC4', 'DES', 'MD5', 'SHA1']
        for cipher in weak_ciphers:
            if cipher in output:
                issues.append(f"Algoritmo débil detectado: {cipher}")
        
        # Detectar versiones inseguras de TLS/SSL
        if re.search(r'SSLv[23]|TLSv1\.0', output):
            issues.append("Versión insegura de SSL/TLS")
        
        for issue in issues:
            finding = {
                'type': 'ssl_issue',
                'severity': 'medium',
                'description': issue,
                'port': port_info.get('port') if port_info else None,
                'service': port_info.get('service') if port_info else None
            }
            findings['security_issues'].append(finding)
    
    def analyze_http_enum_script(self, output: str, findings: Dict, port_info: Dict = None):
        """Analiza enumeración HTTP."""
        interesting_paths = []
        
        lines = output.split('\n')
        for line in lines:
            if '/admin' in line.lower() or '/config' in line.lower() or '/backup' in line.lower():
                interesting_paths.append(line.strip())
        
        if interesting_paths:
            finding = {
                'type': 'http_enum',
                'severity': 'low',
                'description': 'Rutas interesantes encontradas',
                'details': interesting_paths,
                'port': port_info.get('port') if port_info else None,
                'service': port_info.get('service') if port_info else None
            }
            findings['services_info'].append(finding)
    
    def analyze_ms17_010_script(self, output: str, findings: Dict, port_info: Dict = None):
        """Analiza vulnerabilidad MS17-010 (EternalBlue)."""
        if 'VULNERABLE' in output.upper():
            vulnerability = {
                'type': 'ms17_010',
                'severity': 'critical',
                'name': 'MS17-010 (EternalBlue)',
                'description': 'Sistema vulnerable a EternalBlue',
                'cve_id': 'CVE-2017-0144',
                'port': port_info.get('port') if port_info else None,
                'service': port_info.get('service') if port_info else None
            }
            findings['vulnerabilities'].append(vulnerability)
    
    def analyze_enum_script(self, script_id: str, output: str, findings: Dict, port_info: Dict = None):
        """Analiza scripts de enumeración general."""
        if output.strip():
            finding = {
                'type': 'enumeration',
                'severity': 'info',
                'script': script_id,
                'description': f'Información de enumeración: {script_id}',
                'details': output[:300],
                'port': port_info.get('port') if port_info else None,
                'service': port_info.get('service') if port_info else None
            }
            findings['services_info'].append(finding)
    
    def analyze_ssh(self, port_info: Dict) -> Dict:
        """Análisis específico para SSH."""
        findings = {'security_issues': [], 'recommendations': []}
        
        version = port_info.get('version', '').lower()
        
        # Versiones vulnerables conocidas
        if 'openssh' in version:
            if any(v in version for v in ['2.', '3.', '4.', '5.']):
                findings['security_issues'].append({
                    'type': 'outdated_version',
                    'severity': 'medium',
                    'description': f'Versión antigua de OpenSSH: {version}'
                })
        
        findings['recommendations'].append("Deshabilitar autenticación por contraseña y usar solo llaves SSH")
        return findings
    
    def analyze_ftp(self, port_info: Dict) -> Dict:
        """Análisis específico para FTP."""
        findings = {'security_issues': [], 'recommendations': []}
        
        # FTP es inherentemente inseguro
        findings['security_issues'].append({
            'type': 'insecure_protocol',
            'severity': 'medium',
            'description': 'FTP transmite credenciales en texto plano'
        })
        
        findings['recommendations'].append("Migrar a SFTP o FTPS para transferencias seguras")
        return findings
    
    def analyze_http(self, port_info: Dict) -> Dict:
        """Análisis específico para HTTP."""
        findings = {'security_issues': [], 'recommendations': []}
        
        version = port_info.get('version', '').lower()
        
        # Servidores web con vulnerabilidades conocidas
        if 'apache' in version and any(v in version for v in ['1.', '2.0', '2.2']):
            findings['security_issues'].append({
                'type': 'outdated_version',
                'severity': 'medium',
                'description': f'Versión antigua de Apache: {version}'
            })
        
        findings['recommendations'].append("Implementar HTTPS y headers de seguridad")
        return findings
    
    def analyze_https(self, port_info: Dict) -> Dict:
        """Análisis específico para HTTPS."""
        findings = {'recommendations': []}
        findings['recommendations'].append("Verificar configuración SSL/TLS y certificados")
        return findings
    
    def analyze_smb(self, port_info: Dict) -> Dict:
        """Análisis específico para SMB."""
        findings = {'security_issues': [], 'recommendations': []}
        
        findings['security_issues'].append({
            'type': 'smb_exposed',
            'severity': 'medium',
            'description': 'Servicio SMB expuesto puede ser objetivo de ataques'
        })
        
        findings['recommendations'].append("Verificar vulnerabilidades SMB como MS17-010")
        return findings
    
    def analyze_mysql(self, port_info: Dict) -> Dict:
        """Análisis específico para MySQL."""
        findings = {'security_issues': [], 'recommendations': []}
        
        findings['security_issues'].append({
            'type': 'database_exposed',
            'severity': 'high',
            'description': 'Base de datos MySQL expuesta públicamente'
        })
        
        findings['recommendations'].append("Configurar firewall y autenticación fuerte")
        return findings
    
    def analyze_mssql(self, port_info: Dict) -> Dict:
        """Análisis específico para SQL Server."""
        findings = {'security_issues': [], 'recommendations': []}
        
        findings['security_issues'].append({
            'type': 'database_exposed',
            'severity': 'high',
            'description': 'SQL Server expuesto públicamente'
        })
        
        findings['recommendations'].append("Verificar configuración de seguridad y actualizaciones")
        return findings
    
    def analyze_vnc(self, port_info: Dict) -> Dict:
        """Análisis específico para VNC."""
        findings = {'security_issues': [], 'recommendations': []}
        
        findings['security_issues'].append({
            'type': 'remote_access',
            'severity': 'high',
            'description': 'Servicio VNC permite acceso remoto al escritorio'
        })
        
        findings['recommendations'].append("Configurar autenticación fuerte y túnel VPN")
        return findings
    
    def analyze_telnet(self, port_info: Dict) -> Dict:
        """Análisis específico para Telnet."""
        findings = {'security_issues': [], 'recommendations': []}
        
        findings['security_issues'].append({
            'type': 'insecure_protocol',
            'severity': 'high',
            'description': 'Telnet transmite todo en texto plano'
        })
        
        findings['recommendations'].append("Migrar a SSH inmediatamente")
        return findings
    
    def merge_findings(self, target: Dict, source: Dict):
        """Combina findings de diferentes análisis."""
        for key in ['vulnerabilities', 'services_info', 'security_issues', 'recommendations']:
            if key in source:
                target[key].extend(source[key])
    
    def display_findings(self, host: str, findings: Dict):
        """Muestra los findings de seguridad."""
        
        # Vulnerabilidades críticas
        critical_vulns = [v for v in findings['vulnerabilities'] if v.get('severity') == 'critical']
        if critical_vulns:
            table = Table(title=f"[red]VULNERABILIDADES CRÍTICAS - {host}[/red]")
            table.add_column("Tipo")
            table.add_column("Descripción")
            table.add_column("Puerto")
            
            for vuln in critical_vulns:
                table.add_row(
                    vuln.get('type', 'N/A'),
                    vuln.get('description', vuln.get('name', 'N/A')),
                    str(vuln.get('port', 'N/A'))
                )
            self.console.print(table)
        
        # Vulnerabilidades altas
        high_vulns = [v for v in findings['vulnerabilities'] if v.get('severity') == 'high']
        if high_vulns:
            table = Table(title=f"[orange1]VULNERABILIDADES ALTAS - {host}[/orange1]")
            table.add_column("Tipo")
            table.add_column("Descripción")
            table.add_column("Puerto")
            
            for vuln in high_vulns:
                table.add_row(
                    vuln.get('type', 'N/A'),
                    vuln.get('description', vuln.get('name', 'N/A')),
                    str(vuln.get('port', 'N/A'))
                )
            self.console.print(table)
        
        # Problemas de seguridad
        if findings['security_issues']:
            issues_text = "\n".join([f"• {issue.get('description', 'N/A')}" for issue in findings['security_issues']])
            self.console.print(Panel(issues_text, title=f"[yellow]Problemas de Seguridad - {host}[/yellow]"))
        
        # Recomendaciones
        if findings['recommendations']:
            rec_text = "\n".join([f"• {rec}" for rec in findings['recommendations']])
            self.console.print(Panel(rec_text, title=f"[blue]Recomendaciones - {host}[/blue]"))
    
    def generate_security_report(self, scan_results: List[Dict]) -> Dict:
        """Genera un reporte de seguridad completo."""
        report = {
            'summary': {
                'hosts_analyzed': len(scan_results),
                'critical_vulns': 0,
                'high_vulns': 0,
                'medium_vulns': 0,
                'low_vulns': 0
            },
            'findings_by_host': {},
            'recommendations': set(),
            'critical_actions': []
        }
        
        for host_data in scan_results:
            host = host_data['host']
            findings = self.analyze_host_scripts(host_data)
            report['findings_by_host'][host] = findings
            
            # Contar vulnerabilidades por severidad
            for vuln in findings['vulnerabilities']:
                severity = vuln.get('severity', 'low')
                if severity == 'critical':
                    report['summary']['critical_vulns'] += 1
                    report['critical_actions'].append(f"Host {host}: {vuln.get('description', 'N/A')}")
                elif severity == 'high':
                    report['summary']['high_vulns'] += 1
                elif severity == 'medium':
                    report['summary']['medium_vulns'] += 1
                else:
                    report['summary']['low_vulns'] += 1
            
            # Recopilar recomendaciones
            for rec in findings['recommendations']:
                report['recommendations'].add(rec)
            
            # Mostrar findings para este host
            if any([findings['vulnerabilities'], findings['security_issues']]):
                self.display_findings(host, findings)
        
        # Convertir set a list para JSON
        report['recommendations'] = list(report['recommendations'])
        
        return report