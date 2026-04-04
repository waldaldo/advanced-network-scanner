#!/usr/bin/env python3
"""
API REST del scanner de red para integración con otros sistemas.
"""
from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import yaml
import json
import threading
import time
import uuid
import functools
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging
import os
import sqlite3

from database import ScanDatabase
from alert_system import AlertSystem
from cve_detector import CVEDetector
from scanner_v2 import NetworkScanner

app = Flask(__name__)
CORS(app)

# Configuración global
config = {}
scan_db = None
alert_system = None
cve_detector = None
active_scans = {}  # Diccionario para trackear escaneos activos

class ScanThread(threading.Thread):
    """Hilo para ejecutar escaneos en background."""
    
    def __init__(self, scan_id: str, network: str, scan_type: str, options: Dict):
        super().__init__()
        self.scan_id = scan_id
        self.network = network
        self.scan_type = scan_type
        self.options = options
        self.status = 'pending'
        self.results = None
        self.error = None
        self.start_time = None
        self.end_time = None
        self.scanner = None
        
    def run(self):
        """Ejecuta el escaneo."""
        try:
            self.status = 'running'
            self.start_time = datetime.now()
            
            # Crear scanner instance
            config_file = self.options.get('config_file', 'config.yaml')
            self.scanner = NetworkScanner(config_file)
            
            # Ejecutar escaneo
            self.results = self.scanner.scan_network(
                network=self.network,
                scan_type=self.scan_type,
                use_nse=self.options.get('use_nse', True)
            )
            
            self.status = 'completed'
            self.end_time = datetime.now()
            
        except Exception as e:
            self.status = 'failed'
            self.error = str(e)
            self.end_time = datetime.now()
            logging.error(f"Error en escaneo {self.scan_id}: {e}")
        
        finally:
            # Remover de escaneos activos después de un tiempo
            threading.Timer(300, lambda: active_scans.pop(self.scan_id, None)).start()

def load_config():
    """Carga la configuración."""
    global config, scan_db, alert_system, cve_detector
    
    try:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        config = {
            'database': {'db_file': 'scanner_history.db'},
            'api': {'host': '127.0.0.1', 'port': 5001, 'debug': False},
            'security': {'api_key_required': True}
        }
    
    # Inicializar componentes
    scan_db = ScanDatabase(config['database']['db_file'])
    alert_system = AlertSystem(config, 'alerts.db')
    cve_detector = CVEDetector('cve_cache.db')

def require_api_key(f):
    """Decorador para requerir API key."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if config.get('security', {}).get('api_key_required', True):
            api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
            expected_key = os.environ.get('SCANNER_API_KEY') or config.get('security', {}).get('api_key')

            if not api_key or not expected_key or api_key != expected_key:
                abort(401, description="API key requerida o inválida")

        return f(*args, **kwargs)

    return decorated_function

# === ENDPOINTS DE INFORMACIÓN ===

@app.route('/api/v1/info', methods=['GET'])
def api_info():
    """Información de la API."""
    return jsonify({
        'name': 'Scanner de Red API',
        'version': '2.0',
        'description': 'API REST para el scanner de red',
        'endpoints': {
            'info': 'GET /api/v1/info',
            'status': 'GET /api/v1/status',
            'scans': {
                'list': 'GET /api/v1/scans',
                'create': 'POST /api/v1/scans',
                'get': 'GET /api/v1/scans/{id}',
                'stop': 'POST /api/v1/scans/{id}/stop',
                'status': 'GET /api/v1/scans/{id}/status'
            },
            'alerts': {
                'list': 'GET /api/v1/alerts',
                'get': 'GET /api/v1/alerts/{id}',
                'acknowledge': 'POST /api/v1/alerts/{id}/acknowledge'
            },
            'statistics': 'GET /api/v1/statistics',
            'hosts': 'GET /api/v1/hosts',
            'vulnerabilities': 'GET /api/v1/vulnerabilities'
        }
    })

@app.route('/api/v1/status', methods=['GET'])
@require_api_key
def api_status():
    """Estado del sistema."""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'active_scans': len(active_scans),
        'database_connected': os.path.exists(scan_db.db_file),
        'components': {
            'scanner': 'online',
            'database': 'online',
            'alerts': 'online',
            'cve_detector': 'online'
        }
    })

# === ENDPOINTS DE ESCANEOS ===

@app.route('/api/v1/scans', methods=['GET'])
@require_api_key
def api_list_scans():
    """Lista todos los escaneos."""
    limit = request.args.get('limit', 50, type=int)
    network = request.args.get('network')
    scan_type = request.args.get('type')
    
    # Obtener escaneos de la base de datos
    scans = scan_db.get_scan_history(network=network, limit=limit)
    
    # Filtrar por tipo si se especifica
    if scan_type:
        scans = [s for s in scans if s['scan_type'] == scan_type]
    
    # Añadir escaneos activos
    for scan_id, scan_thread in active_scans.items():
        scan_info = {
            'id': scan_id,
            'network': scan_thread.network,
            'scan_type': scan_thread.scan_type,
            'timestamp': scan_thread.start_time.isoformat() if scan_thread.start_time else datetime.now().isoformat(),
            'status': scan_thread.status,
            'duration': (datetime.now() - scan_thread.start_time).total_seconds() if scan_thread.start_time else 0
        }
        scans.insert(0, scan_info)
    
    return jsonify({
        'scans': scans,
        'total': len(scans),
        'active_scans': len(active_scans)
    })

@app.route('/api/v1/scans', methods=['POST'])
@require_api_key
def api_create_scan():
    """Crea un nuevo escaneo."""
    data = request.get_json()
    
    if not data:
        abort(400, description="JSON data required")
    
    # Validar campos requeridos
    required_fields = ['network']
    for field in required_fields:
        if field not in data:
            abort(400, description=f"Missing required field: {field}")
    
    # Parámetros del escaneo
    network = data['network']
    scan_type = data.get('scan_type', 'tcp')
    use_nse = data.get('use_nse', True)
    config_file = data.get('config_file', 'config.yaml')
    
    # Validar tipo de escaneo
    if scan_type not in ['tcp', 'udp', 'both']:
        abort(400, description="Invalid scan_type. Must be 'tcp', 'udp', or 'both'")
    
    # Generar ID único para el escaneo
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    
    # Crear y iniciar hilo de escaneo
    options = {
        'use_nse': use_nse,
        'config_file': config_file
    }
    
    scan_thread = ScanThread(scan_id, network, scan_type, options)
    active_scans[scan_id] = scan_thread
    scan_thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'network': network,
        'scan_type': scan_type,
        'message': 'Scan started successfully'
    }), 201

@app.route('/api/v1/scans/<scan_id>', methods=['GET'])
@require_api_key
def api_get_scan(scan_id):
    """Obtiene detalles de un escaneo específico."""
    
    # Verificar si es un escaneo activo
    if scan_id in active_scans:
        scan_thread = active_scans[scan_id]
        
        response = {
            'scan_id': scan_id,
            'network': scan_thread.network,
            'scan_type': scan_thread.scan_type,
            'status': scan_thread.status,
            'start_time': scan_thread.start_time.isoformat() if scan_thread.start_time else None,
            'end_time': scan_thread.end_time.isoformat() if scan_thread.end_time else None,
            'duration': (
                (scan_thread.end_time or datetime.now()) - scan_thread.start_time
            ).total_seconds() if scan_thread.start_time else 0,
            'error': scan_thread.error,
            'results': scan_thread.results
        }
        
        return jsonify(response)
    
    # Buscar en base de datos histórica
    try:
        scan_id_int = int(scan_id.replace('scan_', '').split('_')[0])
        
        with sqlite3.connect(scan_db.db_file) as conn:
            cursor = conn.cursor()
            
            # Obtener información del escaneo
            cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id_int,))
            scan_row = cursor.fetchone()
            
            if not scan_row:
                abort(404, description="Scan not found")
            
            # Obtener hosts y puertos
            cursor.execute('''
                SELECT h.host, h.status, h.mac_address, h.os_info,
                       p.port, p.protocol, p.service, p.version, p.state
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id
                WHERE h.scan_id = ?
                ORDER BY h.host, p.port
            ''', (scan_id_int,))
            
            hosts_data = {}
            for row in cursor.fetchall():
                host = row[0]
                if host not in hosts_data:
                    hosts_data[host] = {
                        'host': host,
                        'status': row[1],
                        'mac': row[2],
                        'os': row[3],
                        'ports': []
                    }
                
                if row[4]:  # Si hay puerto
                    hosts_data[host]['ports'].append({
                        'port': row[4],
                        'protocol': row[5],
                        'service': row[6],
                        'version': row[7],
                        'state': row[8]
                    })
            
            response = {
                'scan_id': scan_id,
                'network': scan_row[1],
                'scan_type': scan_row[2],
                'status': 'completed',
                'timestamp': scan_row[3],
                'duration': scan_row[4],
                'total_hosts': scan_row[5],
                'active_hosts': scan_row[6],
                'arguments': scan_row[7],
                'results': list(hosts_data.values())
            }
            
            return jsonify(response)
            
    except (ValueError, sqlite3.Error) as e:
        abort(404, description="Scan not found")

@app.route('/api/v1/scans/<scan_id>/status', methods=['GET'])
@require_api_key
def api_scan_status(scan_id):
    """Obtiene solo el estado de un escaneo."""
    if scan_id in active_scans:
        scan_thread = active_scans[scan_id]
        return jsonify({
            'scan_id': scan_id,
            'status': scan_thread.status,
            'progress': 'unknown',  # Nmap no proporciona progreso fácilmente
            'duration': (
                (scan_thread.end_time or datetime.now()) - scan_thread.start_time
            ).total_seconds() if scan_thread.start_time else 0
        })
    else:
        return jsonify({
            'scan_id': scan_id,
            'status': 'completed_or_not_found',
            'message': 'Scan not found in active scans'
        })

@app.route('/api/v1/scans/<scan_id>/stop', methods=['POST'])
@require_api_key
def api_stop_scan(scan_id):
    """Detiene un escaneo activo."""
    if scan_id not in active_scans:
        abort(404, description="Active scan not found")
    
    scan_thread = active_scans[scan_id]
    
    if scan_thread.status != 'running':
        return jsonify({
            'scan_id': scan_id,
            'message': f'Scan is {scan_thread.status}, cannot stop'
        }), 400
    
    try:
        # Intentar detener el proceso de manera elegante
        if hasattr(scan_thread, 'scanner') and scan_thread.scanner:
            # Esto requeriría modificaciones en NetworkScanner para soportar cancelación
            pass
        
        scan_thread.status = 'stopped'
        scan_thread.end_time = datetime.now()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'stopped',
            'message': 'Scan stop requested'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to stop scan: {str(e)}'
        }), 500

# === ENDPOINTS DE ALERTAS ===

@app.route('/api/v1/alerts', methods=['GET'])
@require_api_key
def api_list_alerts():
    """Lista todas las alertas."""
    hours = request.args.get('hours', 24, type=int)
    severity = request.args.get('severity')
    acknowledged = request.args.get('acknowledged', type=bool)
    
    alerts = alert_system.get_recent_alerts(hours=hours, severity=severity)
    
    # Filtrar por estado de reconocimiento si se especifica
    if acknowledged is not None:
        alerts = [a for a in alerts if a['acknowledged'] == acknowledged]
    
    return jsonify({
        'alerts': alerts,
        'total': len(alerts),
        'filters': {
            'hours': hours,
            'severity': severity,
            'acknowledged': acknowledged
        }
    })

@app.route('/api/v1/alerts/<alert_id>', methods=['GET'])
@require_api_key
def api_get_alert(alert_id):
    """Obtiene detalles de una alerta específica."""
    try:
        with sqlite3.connect(alert_system.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
            row = cursor.fetchone()
            
            if not row:
                abort(404, description="Alert not found")
            
            alert = {
                'id': row[0],
                'rule_id': row[1],
                'title': row[2],
                'message': row[3],
                'severity': row[4],
                'host': row[5],
                'port': row[6],
                'service': row[7],
                'data': json.loads(row[8]) if row[8] else {},
                'timestamp': row[9],
                'acknowledged': bool(row[10])
            }
            
            return jsonify(alert)
            
    except sqlite3.Error as e:
        abort(500, description="Database error")

@app.route('/api/v1/alerts/<alert_id>/acknowledge', methods=['POST'])
@require_api_key
def api_acknowledge_alert(alert_id):
    """Marca una alerta como reconocida."""
    success = alert_system.acknowledge_alert(alert_id)
    
    if success:
        return jsonify({
            'alert_id': alert_id,
            'status': 'acknowledged',
            'timestamp': datetime.now().isoformat()
        })
    else:
        abort(404, description="Alert not found or already acknowledged")

# === ENDPOINTS DE ESTADÍSTICAS ===

@app.route('/api/v1/statistics', methods=['GET'])
@require_api_key
def api_statistics():
    """Obtiene estadísticas generales del sistema."""
    stats = scan_db.get_statistics()
    alert_stats = alert_system.get_alert_statistics()
    cve_stats = cve_detector.get_detection_statistics()
    
    return jsonify({
        'scan_statistics': stats,
        'alert_statistics': alert_stats,
        'cve_statistics': cve_stats,
        'system_statistics': {
            'active_scans': len(active_scans),
            'uptime_hours': 0,  # Implementar si es necesario
            'api_version': '2.0'
        }
    })

# === ENDPOINTS DE HOSTS ===

@app.route('/api/v1/hosts', methods=['GET'])
@require_api_key
def api_list_hosts():
    """Lista todos los hosts descubiertos."""
    limit = request.args.get('limit', 100, type=int)
    network = request.args.get('network')
    
    try:
        with sqlite3.connect(scan_db.db_file) as conn:
            cursor = conn.cursor()
            
            query = '''
                SELECT DISTINCT h.host, h.status, h.mac_address, 
                       COUNT(p.id) as port_count,
                       MAX(h.timestamp) as last_seen
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id
            '''
            params = []
            
            if network:
                query += ' WHERE h.host LIKE ?'
                params.append(f'{network}%')
            
            query += ' GROUP BY h.host ORDER BY h.host LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            
            hosts = []
            for row in cursor.fetchall():
                hosts.append({
                    'host': row[0],
                    'status': row[1],
                    'mac_address': row[2],
                    'port_count': row[3],
                    'last_seen': row[4]
                })
            
            return jsonify({
                'hosts': hosts,
                'total': len(hosts)
            })
            
    except sqlite3.Error as e:
        abort(500, description="Database error")

# === ENDPOINTS DE VULNERABILIDADES ===

@app.route('/api/v1/vulnerabilities', methods=['GET'])
@require_api_key
def api_list_vulnerabilities():
    """Lista todas las vulnerabilidades detectadas."""
    severity = request.args.get('severity')
    limit = request.args.get('limit', 100, type=int)
    
    try:
        with sqlite3.connect(alert_system.db_file) as conn:
            cursor = conn.cursor()
            
            query = '''
                SELECT id, title, message, severity, host, port, service, 
                       data, timestamp, acknowledged
                FROM alerts
                WHERE title LIKE '%CVE%' OR message LIKE '%vulnerability%'
            '''
            params = []
            
            if severity:
                query += ' AND severity = ?'
                params.append(severity)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            
            vulnerabilities = []
            for row in cursor.fetchall():
                vulnerabilities.append({
                    'id': row[0],
                    'title': row[1],
                    'description': row[2],
                    'severity': row[3],
                    'host': row[4],
                    'port': row[5],
                    'service': row[6],
                    'data': json.loads(row[7]) if row[7] else {},
                    'timestamp': row[8],
                    'acknowledged': bool(row[9])
                })
            
            return jsonify({
                'vulnerabilities': vulnerabilities,
                'total': len(vulnerabilities)
            })
            
    except sqlite3.Error as e:
        abort(500, description="Database error")

# === MANEJO DE ERRORES ===

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad Request', 'message': str(error.description)}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized', 'message': str(error.description)}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not Found', 'message': str(error.description)}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    load_config()
    
    api_config = config.get('api', {})
    host = api_config.get('host', '127.0.0.1')
    port = api_config.get('port', 5001)
    debug = api_config.get('debug', False)
    
    print(f"Iniciando API REST en http://{host}:{port}")
    print(f"Documentacion en http://{host}:{port}/api/v1/info")

    if config.get('security', {}).get('api_key_required', True):
        key_source = "variable de entorno SCANNER_API_KEY" if os.environ.get('SCANNER_API_KEY') else "config.yaml"
        print(f"Autenticacion requerida (API key desde {key_source})")
    
    app.run(host=host, port=port, debug=debug)