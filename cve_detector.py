#!/usr/bin/env python3
"""
Detector de vulnerabilidades CVE basado en información de servicios y versiones.
"""
import re
import json
import requests
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import time

@dataclass
class CVEInfo:
    """Información de una vulnerabilidad CVE."""
    cve_id: str
    description: str
    severity: str
    score: float
    published_date: str
    modified_date: str
    affected_versions: List[str]
    references: List[str]

class CVEDetector:
    """Detector de vulnerabilidades CVE para servicios encontrados."""
    
    def __init__(self, cache_file="cve_cache.db"):
        self.cache_file = cache_file
        self.logger = logging.getLogger(__name__)
        self.init_cache_db()
        
        # Patrones de versión comunes
        self.version_patterns = {
            'apache': r'apache[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'nginx': r'nginx[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'openssh': r'openssh[_\s]+(\d+\.\d+(?:p\d+)?)',
            'mysql': r'mysql[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'postgresql': r'postgresql[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'php': r'php[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'microsoft-iis': r'microsoft-iis[/\s]+(\d+\.\d+)',
            'tomcat': r'(?:apache[\s/])?tomcat[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'jenkins': r'jenkins[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'wordpress': r'wordpress[/\s]+(\d+\.\d+(?:\.\d+)?)'
        }
        
        # Base de conocimiento local de CVEs críticos
        self.known_cves = {
            'apache': {
                '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
                '2.4.50': ['CVE-2021-44224'],
                '2.2.x': ['CVE-2017-15710', 'CVE-2017-15715']
            },
            'openssh': {
                '7.4': ['CVE-2018-15473'],
                '6.6': ['CVE-2016-0777', 'CVE-2016-0778'],
                '5.x': ['CVE-2010-4755']
            },
            'nginx': {
                '1.20.0': ['CVE-2021-23017'],
                '1.18.0': ['CVE-2020-11724'],
                '1.16.x': ['CVE-2019-20372']
            },
            'mysql': {
                '8.0.27': ['CVE-2022-21245'],
                '5.7.x': ['CVE-2021-2154', 'CVE-2021-2166'],
                '5.6.x': ['CVE-2020-2814']
            },
            'microsoft-iis': {
                '10.0': ['CVE-2021-31207'],
                '7.5': ['CVE-2017-7269'],
                '6.0': ['CVE-2017-7269']
            }
        }
        
        # Mapeo de severidad CVSS a nuestro sistema
        self.severity_mapping = {
            (9.0, 10.0): 'critical',
            (7.0, 8.9): 'high',
            (4.0, 6.9): 'medium',
            (0.0, 3.9): 'low'
        }
    
    def init_cache_db(self):
        """Inicializa la base de datos de cache CVE."""
        try:
            with sqlite3.connect(self.cache_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cve_cache (
                        cve_id TEXT PRIMARY KEY,
                        description TEXT,
                        severity TEXT,
                        score REAL,
                        published_date TEXT,
                        modified_date TEXT,
                        affected_versions TEXT,
                        cve_refs TEXT,
                        cached_date TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS service_cves (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service TEXT,
                        version TEXT,
                        cve_id TEXT,
                        detection_date TEXT,
                        FOREIGN KEY (cve_id) REFERENCES cve_cache (cve_id)
                    )
                ''')
                conn.commit()
                
        except sqlite3.Error as e:
            self.logger.error(f"Error inicializando cache CVE: {e}")
    
    def extract_service_version(self, service: str, version_string: str) -> Tuple[str, str]:
        """Extrae el servicio y versión de una cadena de versión."""
        service_clean = service.lower().strip()
        version_string = version_string.lower().strip()
        
        # Buscar patrones específicos
        for service_pattern, regex in self.version_patterns.items():
            if service_pattern in service_clean or service_pattern in version_string:
                match = re.search(regex, version_string, re.IGNORECASE)
                if match:
                    return service_pattern, match.group(1)
        
        # Patrón genérico para versión
        generic_version = re.search(r'(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)', version_string)
        if generic_version:
            return service_clean, generic_version.group(1)
        
        return service_clean, ""
    
    def check_known_cves(self, service: str, version: str) -> List[str]:
        """Verifica CVEs conocidos en la base de conocimiento local."""
        cves = []
        
        if service in self.known_cves:
            service_cves = self.known_cves[service]
            
            # Verificación exacta
            if version in service_cves:
                cves.extend(service_cves[version])
            
            # Verificación por rango (ej: 5.x para versiones 5.*)
            for version_pattern, pattern_cves in service_cves.items():
                if 'x' in version_pattern:
                    base_version = version_pattern.replace('.x', '')
                    if version.startswith(base_version):
                        cves.extend(pattern_cves)
        
        return list(set(cves))  # Eliminar duplicados
    
    def get_cve_from_cache(self, cve_id: str) -> Optional[CVEInfo]:
        """Obtiene información de CVE desde el cache."""
        try:
            with sqlite3.connect(self.cache_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT cve_id, description, severity, score, published_date,
                           modified_date, affected_versions, cve_refs
                    FROM cve_cache WHERE cve_id = ?
                ''', (cve_id,))
                
                row = cursor.fetchone()
                if row:
                    return CVEInfo(
                        cve_id=row[0],
                        description=row[1],
                        severity=row[2],
                        score=row[3],
                        published_date=row[4],
                        modified_date=row[5],
                        affected_versions=json.loads(row[6]) if row[6] else [],
                        references=json.loads(row[7]) if row[7] else []  # col: cve_refs
                    )
        except Exception as e:
            self.logger.error(f"Error obteniendo CVE del cache: {e}")
        
        return None
    
    def cache_cve_info(self, cve_info: CVEInfo):
        """Guarda información de CVE en el cache."""
        try:
            with sqlite3.connect(self.cache_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO cve_cache
                    (cve_id, description, severity, score, published_date,
                     modified_date, affected_versions, cve_refs, cached_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_info.cve_id,
                    cve_info.description,
                    cve_info.severity,
                    cve_info.score,
                    cve_info.published_date,
                    cve_info.modified_date,
                    json.dumps(cve_info.affected_versions),
                    json.dumps(cve_info.references),
                    datetime.now().isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error guardando CVE en cache: {e}")
    
    def fetch_cve_info_online(self, cve_id: str) -> Optional[CVEInfo]:
        """Obtiene información de CVE desde APIs públicas."""
        # API del NIST NVD (National Vulnerability Database)
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        try:
            headers = {
                'User-Agent': 'NetworkScanner/2.0 (Security Research Tool)'
            }
            
            response = requests.get(nvd_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('totalResults', 0) > 0:
                    vuln = data['vulnerabilities'][0]['cve']
                    
                    # Extraer información básica
                    description = ""
                    if 'descriptions' in vuln:
                        for desc in vuln['descriptions']:
                            if desc['lang'] == 'en':
                                description = desc['value']
                                break
                    
                    # Extraer score CVSS
                    score = 0.0
                    severity = 'unknown'
                    if 'metrics' in vuln:
                        if 'cvssMetricV31' in vuln['metrics']:
                            cvss = vuln['metrics']['cvssMetricV31'][0]['cvssData']
                            score = cvss['baseScore']
                            severity = cvss['baseSeverity'].lower()
                        elif 'cvssMetricV30' in vuln['metrics']:
                            cvss = vuln['metrics']['cvssMetricV30'][0]['cvssData']
                            score = cvss['baseScore']
                            severity = cvss['baseSeverity'].lower()
                        elif 'cvssMetricV2' in vuln['metrics']:
                            cvss = vuln['metrics']['cvssMetricV2'][0]['cvssData']
                            score = cvss['baseScore']
                            # Mapear score CVSS v2 a severidad
                            for (min_score, max_score), sev in self.severity_mapping.items():
                                if min_score <= score <= max_score:
                                    severity = sev
                                    break
                    
                    # Extraer referencias
                    references = []
                    if 'references' in vuln:
                        references = [ref['url'] for ref in vuln['references'][:5]]  # Límite de 5
                    
                    cve_info = CVEInfo(
                        cve_id=cve_id,
                        description=description,
                        severity=severity,
                        score=score,
                        published_date=vuln.get('published', ''),
                        modified_date=vuln.get('lastModified', ''),
                        affected_versions=[],  # No siempre disponible en NVD
                        references=references
                    )
                    
                    # Guardar en cache
                    self.cache_cve_info(cve_info)
                    return cve_info
            
            # Esperar para evitar rate limiting
            time.sleep(1)
            
        except requests.RequestException as e:
            self.logger.warning(f"Error obteniendo CVE {cve_id} online: {e}")
        except Exception as e:
            self.logger.error(f"Error procesando CVE {cve_id}: {e}")
        
        return None
    
    def get_cve_info(self, cve_id: str) -> Optional[CVEInfo]:
        """Obtiene información de CVE, primero del cache, luego online."""
        # Intentar desde cache primero
        cve_info = self.get_cve_from_cache(cve_id)
        if cve_info:
            return cve_info
        
        # Si no está en cache, buscar online
        return self.fetch_cve_info_online(cve_id)
    
    def analyze_service_vulnerabilities(self, service: str, version: str, port: int = None) -> List[Dict]:
        """Analiza vulnerabilidades para un servicio específico."""
        vulnerabilities = []
        
        # Extraer servicio y versión limpios
        clean_service, clean_version = self.extract_service_version(service, version)
        
        if not clean_version:
            return vulnerabilities
        
        self.logger.info(f"Analizando {clean_service} {clean_version}")
        
        # Verificar CVEs conocidos
        known_cves = self.check_known_cves(clean_service, clean_version)
        
        for cve_id in known_cves:
            cve_info = self.get_cve_info(cve_id)
            
            if cve_info:
                vulnerability = {
                    'cve_id': cve_info.cve_id,
                    'description': cve_info.description,
                    'severity': cve_info.severity,
                    'score': cve_info.score,
                    'service': clean_service,
                    'version': clean_version,
                    'port': port,
                    'published_date': cve_info.published_date,
                    'references': cve_info.references
                }
                vulnerabilities.append(vulnerability)
                
                # Registrar detección
                self.log_service_cve_detection(clean_service, clean_version, cve_id)
        
        return vulnerabilities
    
    def log_service_cve_detection(self, service: str, version: str, cve_id: str):
        """Registra la detección de un CVE para un servicio."""
        try:
            with sqlite3.connect(self.cache_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO service_cves (service, version, cve_id, detection_date)
                    VALUES (?, ?, ?, ?)
                ''', (service, version, cve_id, datetime.now().isoformat()))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error registrando detección CVE: {e}")
    
    def analyze_scan_results(self, scan_results: List[Dict]) -> Dict:
        """Analiza resultados de escaneo completo para vulnerabilidades CVE."""
        cve_report = {
            'total_services': 0,
            'vulnerable_services': 0,
            'total_cves': 0,
            'critical_cves': 0,
            'high_cves': 0,
            'medium_cves': 0,
            'low_cves': 0,
            'vulnerabilities_by_host': {},
            'cve_summary': []
        }
        
        for host_data in scan_results:
            host = host_data['host']
            host_vulnerabilities = []
            
            for port_data in host_data.get('ports', []):
                service = port_data.get('service', '')
                version = port_data.get('version', '')
                port = port_data.get('port')
                
                if service and version:
                    cve_report['total_services'] += 1
                    
                    vulns = self.analyze_service_vulnerabilities(service, version, port)
                    
                    if vulns:
                        cve_report['vulnerable_services'] += 1
                        host_vulnerabilities.extend(vulns)
                        
                        for vuln in vulns:
                            cve_report['total_cves'] += 1
                            
                            # Contar por severidad
                            severity = vuln.get('severity', 'low')
                            if severity == 'critical':
                                cve_report['critical_cves'] += 1
                            elif severity == 'high':
                                cve_report['high_cves'] += 1
                            elif severity == 'medium':
                                cve_report['medium_cves'] += 1
                            else:
                                cve_report['low_cves'] += 1
            
            if host_vulnerabilities:
                cve_report['vulnerabilities_by_host'][host] = host_vulnerabilities
        
        # Crear resumen de CVEs únicos
        unique_cves = {}
        for host_vulns in cve_report['vulnerabilities_by_host'].values():
            for vuln in host_vulns:
                cve_id = vuln['cve_id']
                if cve_id not in unique_cves:
                    unique_cves[cve_id] = {
                        'cve_id': cve_id,
                        'description': vuln['description'],
                        'severity': vuln['severity'],
                        'score': vuln['score'],
                        'affected_hosts': 1
                    }
                else:
                    unique_cves[cve_id]['affected_hosts'] += 1
        
        # Ordenar por severidad y score
        cve_report['cve_summary'] = sorted(
            unique_cves.values(),
            key=lambda x: (x['severity'] == 'critical', x['score']),
            reverse=True
        )
        
        return cve_report
    
    def get_detection_statistics(self) -> Dict:
        """Obtiene estadísticas de detecciones CVE."""
        try:
            with sqlite3.connect(self.cache_file) as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Total de CVEs en cache
                cursor.execute('SELECT COUNT(*) FROM cve_cache')
                stats['cached_cves'] = cursor.fetchone()[0]
                
                # Total de detecciones
                cursor.execute('SELECT COUNT(*) FROM service_cves')
                stats['total_detections'] = cursor.fetchone()[0]
                
                # Detecciones por servicio
                cursor.execute('''
                    SELECT service, COUNT(*) as count
                    FROM service_cves
                    GROUP BY service
                    ORDER BY count DESC
                    LIMIT 10
                ''')
                stats['detections_by_service'] = [
                    {'service': row[0], 'count': row[1]}
                    for row in cursor.fetchall()
                ]
                
                # CVEs más detectados
                cursor.execute('''
                    SELECT cve_id, COUNT(*) as count
                    FROM service_cves
                    GROUP BY cve_id
                    ORDER BY count DESC
                    LIMIT 10
                ''')
                stats['most_detected_cves'] = [
                    {'cve_id': row[0], 'count': row[1]}
                    for row in cursor.fetchall()
                ]
                
                return stats
                
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas: {e}")
            return {}
    
    def cleanup_old_cache(self, days_old: int = 30):
        """Limpia entradas antiguas del cache."""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            cutoff_str = cutoff_date.isoformat()
            
            with sqlite3.connect(self.cache_file) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM cve_cache WHERE cached_date < ?', (cutoff_str,))
                deleted = cursor.rowcount
                conn.commit()
                
                self.logger.info(f"Eliminadas {deleted} entradas antiguas del cache CVE")
                
        except Exception as e:
            self.logger.error(f"Error limpiando cache: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Detector CVE standalone")
    parser.add_argument("--service", default="apache", help="Nombre del servicio")
    parser.add_argument("--version", default="Apache/2.4.49", help="Version del servicio")
    parser.add_argument("--port", type=int, default=80, help="Puerto")
    args = parser.parse_args()

    detector = CVEDetector()
    vulns = detector.analyze_service_vulnerabilities(args.service, args.version, args.port)
    print(json.dumps(vulns, indent=2))