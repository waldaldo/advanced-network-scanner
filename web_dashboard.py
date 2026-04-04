#!/usr/bin/env python3
"""
Dashboard web para el scanner de red usando Flask.
"""
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_cors import CORS
import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import plotly.graph_objs as go
import plotly.utils
from database import ScanDatabase
from alert_system import AlertSystem
from cve_detector import CVEDetector
import yaml

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
CORS(app)

# Configuración global
config = {}
scan_db = None
alert_system = None
cve_detector = None

def load_config():
    """Carga la configuración."""
    global config, scan_db, alert_system, cve_detector
    
    try:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        config = {
            'database': {'db_file': 'scanner_history.db'},
            'notifications': {'email': {'enabled': False}},
            'web': {'host': '127.0.0.1', 'port': 5000, 'debug': True}
        }
    
    # Inicializar componentes
    scan_db = ScanDatabase(config['database']['db_file'])
    alert_system = AlertSystem(config, 'alerts.db')
    cve_detector = CVEDetector('cve_cache.db')

@app.route('/')
def dashboard():
    """Página principal del dashboard."""
    return render_template('dashboard.html')

@app.route('/api/scans/recent')
def api_recent_scans():
    """API: Obtiene escaneos recientes."""
    limit = request.args.get('limit', 10, type=int)
    scans = scan_db.get_scan_history(limit=limit)
    return jsonify(scans)

@app.route('/api/scans/<int:scan_id>')
def api_scan_details(scan_id):
    """API: Obtiene detalles de un escaneo específico."""
    try:
        with sqlite3.connect(scan_db.db_file) as conn:
            cursor = conn.cursor()
            
            # Obtener información del escaneo
            cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
            scan_row = cursor.fetchone()
            
            if not scan_row:
                return jsonify({'error': 'Scan not found'}), 404
            
            # Obtener hosts y puertos
            cursor.execute('''
                SELECT h.host, h.status, h.mac_address, h.os_info,
                       p.port, p.protocol, p.service, p.version, p.state
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id
                WHERE h.scan_id = ?
                ORDER BY h.host, p.port
            ''', (scan_id,))
            
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
            
            scan_details = {
                'scan_info': {
                    'id': scan_row[0],
                    'network': scan_row[1],
                    'scan_type': scan_row[2],
                    'timestamp': scan_row[3],
                    'duration': scan_row[4],
                    'total_hosts': scan_row[5],
                    'active_hosts': scan_row[6],
                    'arguments': scan_row[7]
                },
                'hosts': list(hosts_data.values())
            }
            
            return jsonify(scan_details)
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics')
def api_statistics():
    """API: Obtiene estadísticas generales."""
    stats = scan_db.get_statistics()
    alert_stats = alert_system.get_alert_statistics()
    cve_stats = cve_detector.get_detection_statistics()
    
    return jsonify({
        'scan_stats': stats,
        'alert_stats': alert_stats,
        'cve_stats': cve_stats
    })

@app.route('/api/alerts/recent')
def api_recent_alerts():
    """API: Obtiene alertas recientes."""
    hours = request.args.get('hours', 24, type=int)
    severity = request.args.get('severity')
    
    alerts = alert_system.get_recent_alerts(hours=hours, severity=severity)
    return jsonify(alerts)

@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
def api_acknowledge_alert(alert_id):
    """API: Marca una alerta como reconocida."""
    success = alert_system.acknowledge_alert(alert_id)
    
    if success:
        return jsonify({'status': 'acknowledged'})
    else:
        return jsonify({'error': 'Failed to acknowledge alert'}), 500

@app.route('/api/charts/scans_timeline')
def api_scans_timeline_chart():
    """API: Gráfico de línea temporal de escaneos."""
    try:
        with sqlite3.connect(scan_db.db_file) as conn:
            cursor = conn.cursor()
            
            # Obtener escaneos de los últimos 30 días
            cutoff = (datetime.now() - timedelta(days=30)).isoformat()
            cursor.execute('''
                SELECT DATE(timestamp) as date, COUNT(*) as count
                FROM scans 
                WHERE timestamp >= ?
                GROUP BY DATE(timestamp)
                ORDER BY date
            ''', (cutoff,))
            
            dates = []
            counts = []
            
            for row in cursor.fetchall():
                dates.append(row[0])
                counts.append(row[1])
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=dates,
                y=counts,
                mode='lines+markers',
                name='Escaneos por día',
                line=dict(color='#00D4AA', width=3),
                marker=dict(size=8)
            ))
            
            fig.update_layout(
                title='Actividad de Escaneos (Últimos 30 días)',
                xaxis_title='Fecha',
                yaxis_title='Número de Escaneos',
                template='plotly_dark',
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)'
            )
            
            return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/charts/alerts_severity')
def api_alerts_severity_chart():
    """API: Gráfico de alertas por severidad."""
    try:
        alert_stats = alert_system.get_alert_statistics()
        severity_data = alert_stats.get('by_severity', {})
        
        severities = list(severity_data.keys())
        counts = list(severity_data.values())
        
        colors = ['#FF4444', '#FF8C00', '#FFD700', '#32CD32']
        
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=severities,
            y=counts,
            marker_color=colors[:len(severities)],
            name='Alertas por Severidad'
        ))
        
        fig.update_layout(
            title='Distribución de Alertas por Severidad',
            xaxis_title='Severidad',
            yaxis_title='Número de Alertas',
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/charts/top_services')
def api_top_services_chart():
    """API: Gráfico de servicios más comunes."""
    try:
        stats = scan_db.get_statistics()
        services_data = stats.get('top_services', [])
        
        services = [item['service'] for item in services_data]
        counts = [item['count'] for item in services_data]
        
        fig = go.Figure()
        fig.add_trace(go.Pie(
            labels=services,
            values=counts,
            name='Servicios',
            marker_colors=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', 
                          '#DDA0DD', '#F4A460', '#FFB347', '#98FB98', '#F0E68C']
        ))
        
        fig.update_layout(
            title='Top 10 Servicios Detectados',
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scans')
def scans_page():
    """Página de escaneos."""
    return render_template('scans.html')

@app.route('/alerts')
def alerts_page():
    """Página de alertas."""
    return render_template('alerts.html')

@app.route('/analytics')
def analytics_page():
    """Página de análisis."""
    return render_template('analytics.html')

@app.errorhandler(404)
def not_found_error(error):
    """Manejo de errores 404."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Manejo de errores 500."""
    return render_template('500.html'), 500

if __name__ == '__main__':
    load_config()
    
    web_config = config.get('web', {})
    host = web_config.get('host', '127.0.0.1')
    port = web_config.get('port', 5000)
    debug = web_config.get('debug', True)
    
    print(f"Iniciando Dashboard Web en http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)