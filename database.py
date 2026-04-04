import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import os

class ScanDatabase:
    def __init__(self, db_file: str = "scanner_history.db"):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Inicializa la base de datos y crea las tablas necesarias."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                # Tabla para escaneos
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        network TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        duration REAL,
                        total_hosts INTEGER,
                        active_hosts INTEGER,
                        arguments TEXT,
                        status TEXT DEFAULT 'completed'
                    )
                ''')
                
                # Tabla para hosts encontrados
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS hosts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        host TEXT NOT NULL,
                        status TEXT NOT NULL,
                        mac_address TEXT,
                        os_info TEXT,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (scan_id) REFERENCES scans (id)
                    )
                ''')
                
                # Tabla para puertos y servicios
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host_id INTEGER,
                        port INTEGER NOT NULL,
                        protocol TEXT NOT NULL,
                        service TEXT,
                        version TEXT,
                        state TEXT NOT NULL,
                        FOREIGN KEY (host_id) REFERENCES hosts (id)
                    )
                ''')
                
                # Tabla para vulnerabilidades detectadas
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host_id INTEGER,
                        port_id INTEGER,
                        vulnerability TEXT NOT NULL,
                        severity TEXT,
                        description TEXT,
                        cve_id TEXT,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (host_id) REFERENCES hosts (id),
                        FOREIGN KEY (port_id) REFERENCES ports (id)
                    )
                ''')
                
                # Índices para mejor rendimiento
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts (scan_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_host ON hosts (host)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_ports_host_id ON ports (host_id)')
                
                conn.commit()
                logging.info(f"Base de datos inicializada: {self.db_file}")
                
        except sqlite3.Error as e:
            logging.error(f"Error inicializando base de datos: {e}")
            raise
    
    def save_scan(self, network: str, scan_type: str, results: List[Dict], 
                  duration: float, arguments: str) -> int:
        """Guarda un escaneo completo en la base de datos."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                # Insertar escaneo principal
                scan_timestamp = datetime.now().isoformat()
                cursor.execute('''
                    INSERT INTO scans (network, scan_type, timestamp, duration, 
                                     total_hosts, active_hosts, arguments)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (network, scan_type, scan_timestamp, duration, 
                      len(results), len([r for r in results if r['status'] == 'up']), arguments))
                
                scan_id = cursor.lastrowid
                
                # Insertar hosts y puertos
                for host_data in results:
                    cursor.execute('''
                        INSERT INTO hosts (scan_id, host, status, mac_address, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (scan_id, host_data['host'], host_data['status'], 
                          host_data.get('mac', 'N/A'), scan_timestamp))
                    
                    host_id = cursor.lastrowid
                    
                    # Insertar puertos
                    for port_data in host_data.get('ports', []):
                        cursor.execute('''
                            INSERT INTO ports (host_id, port, protocol, service, version, state)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (host_id, port_data['port'],
                              port_data.get('protocol', 'tcp'),
                              port_data['service'], port_data['version'],
                              port_data.get('state', 'open')))
                
                conn.commit()
                logging.info(f"Escaneo guardado con ID: {scan_id}")
                return scan_id
                
        except sqlite3.Error as e:
            logging.error(f"Error guardando escaneo: {e}")
            raise
    
    def get_scan_history(self, network: str = None, limit: int = 10) -> List[Dict]:
        """Obtiene el historial de escaneos."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT id, network, scan_type, timestamp, duration, 
                           total_hosts, active_hosts, status
                    FROM scans
                '''
                params = []
                
                if network:
                    query += ' WHERE network = ?'
                    params.append(network)
                
                query += ' ORDER BY timestamp DESC LIMIT ?'
                params.append(limit)
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                return [{
                    'id': row[0],
                    'network': row[1],
                    'scan_type': row[2],
                    'timestamp': row[3],
                    'duration': row[4],
                    'total_hosts': row[5],
                    'active_hosts': row[6],
                    'status': row[7]
                } for row in rows]
                
        except sqlite3.Error as e:
            logging.error(f"Error obteniendo historial: {e}")
            return []
    
    def compare_scans(self, scan_id1: int, scan_id2: int) -> Dict:
        """Compara dos escaneos y devuelve las diferencias."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                # Obtener datos de ambos escaneos
                def get_scan_data(scan_id):
                    cursor.execute('''
                        SELECT h.host, p.port, p.service, p.version
                        FROM hosts h
                        LEFT JOIN ports p ON h.id = p.host_id
                        WHERE h.scan_id = ?
                        ORDER BY h.host, p.port
                    ''', (scan_id,))
                    
                    data = {}
                    for row in cursor.fetchall():
                        host = row[0]
                        if host not in data:
                            data[host] = []
                        if row[1]:  # Si hay puerto
                            data[host].append({
                                'port': row[1],
                                'service': row[2],
                                'version': row[3]
                            })
                    return data
                
                data1 = get_scan_data(scan_id1)
                data2 = get_scan_data(scan_id2)
                
                # Encontrar diferencias
                new_hosts = set(data2.keys()) - set(data1.keys())
                removed_hosts = set(data1.keys()) - set(data2.keys())
                
                port_changes = {}
                for host in set(data1.keys()) & set(data2.keys()):
                    ports1 = {p['port']: p for p in data1[host]}
                    ports2 = {p['port']: p for p in data2[host]}
                    
                    new_ports = set(ports2.keys()) - set(ports1.keys())
                    closed_ports = set(ports1.keys()) - set(ports2.keys())
                    
                    if new_ports or closed_ports:
                        port_changes[host] = {
                            'new_ports': [ports2[p] for p in new_ports],
                            'closed_ports': [ports1[p] for p in closed_ports]
                        }
                
                return {
                    'new_hosts': list(new_hosts),
                    'removed_hosts': list(removed_hosts),
                    'port_changes': port_changes
                }
                
        except sqlite3.Error as e:
            logging.error(f"Error comparando escaneos: {e}")
            return {}
    
    def cleanup_old_scans(self, retention_days: int):
        """Elimina escaneos antiguos según la política de retención."""
        if retention_days <= 0:
            return
        
        try:
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            cutoff_str = cutoff_date.isoformat()
            
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                # Obtener IDs de escaneos a eliminar
                cursor.execute('SELECT id FROM scans WHERE timestamp < ?', (cutoff_str,))
                old_scan_ids = [row[0] for row in cursor.fetchall()]
                
                if old_scan_ids:
                    # Eliminar en orden: vulnerabilities -> ports -> hosts -> scans
                    for scan_id in old_scan_ids:
                        cursor.execute('DELETE FROM vulnerabilities WHERE host_id IN (SELECT id FROM hosts WHERE scan_id = ?)', (scan_id,))
                        cursor.execute('DELETE FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE scan_id = ?)', (scan_id,))
                        cursor.execute('DELETE FROM hosts WHERE scan_id = ?', (scan_id,))
                        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
                    
                    conn.commit()
                    logging.info(f"Eliminados {len(old_scan_ids)} escaneos antiguos")
                
        except sqlite3.Error as e:
            logging.error(f"Error limpiando escaneos antiguos: {e}")
    
    def get_statistics(self) -> Dict:
        """Obtiene estadísticas generales de la base de datos."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Total de escaneos
                cursor.execute('SELECT COUNT(*) FROM scans')
                stats['total_scans'] = cursor.fetchone()[0]
                
                # Total de hosts únicos
                cursor.execute('SELECT COUNT(DISTINCT host) FROM hosts')
                stats['unique_hosts'] = cursor.fetchone()[0]
                
                # Total de puertos encontrados
                cursor.execute('SELECT COUNT(*) FROM ports')
                stats['total_ports'] = cursor.fetchone()[0]
                
                # Servicios más comunes
                cursor.execute('''
                    SELECT service, COUNT(*) as count 
                    FROM ports 
                    WHERE service IS NOT NULL 
                    GROUP BY service 
                    ORDER BY count DESC 
                    LIMIT 10
                ''')
                stats['top_services'] = [{'service': row[0], 'count': row[1]} 
                                       for row in cursor.fetchall()]
                
                # Último escaneo
                cursor.execute('SELECT timestamp FROM scans ORDER BY timestamp DESC LIMIT 1')
                result = cursor.fetchone()
                stats['last_scan'] = result[0] if result else None
                
                return stats
                
        except sqlite3.Error as e:
            logging.error(f"Error obteniendo estadísticas: {e}")
            return {}