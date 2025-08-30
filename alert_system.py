#!/usr/bin/env python3
"""
Sistema de alertas y notificaciones para el scanner de red.
"""
import smtplib
import json
import logging
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import requests
from pathlib import Path

@dataclass
class AlertRule:
    """Regla de alerta."""
    id: str
    name: str
    description: str
    enabled: bool
    conditions: Dict[str, Any]
    actions: List[str]
    severity: str
    created_date: str
    last_triggered: Optional[str] = None

@dataclass
class Alert:
    """Alerta generada."""
    id: str
    rule_id: str
    title: str
    message: str
    severity: str
    host: str
    port: Optional[int]
    service: Optional[str]
    data: Dict[str, Any]
    timestamp: str
    acknowledged: bool = False

class AlertSystem:
    """Sistema de gestión de alertas y notificaciones."""
    
    def __init__(self, config: Dict, db_file: str = "alerts.db"):
        self.config = config
        self.db_file = db_file
        self.logger = logging.getLogger(__name__)
        self.init_database()
        self.load_default_rules()
    
    def init_database(self):
        """Inicializa la base de datos de alertas."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                # Tabla de reglas de alerta
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alert_rules (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        enabled BOOLEAN DEFAULT 1,
                        conditions TEXT,
                        actions TEXT,
                        severity TEXT,
                        created_date TEXT,
                        last_triggered TEXT
                    )
                ''')
                
                # Tabla de alertas generadas
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id TEXT PRIMARY KEY,
                        rule_id TEXT,
                        title TEXT NOT NULL,
                        message TEXT,
                        severity TEXT,
                        host TEXT,
                        port INTEGER,
                        service TEXT,
                        data TEXT,
                        timestamp TEXT,
                        acknowledged BOOLEAN DEFAULT 0,
                        FOREIGN KEY (rule_id) REFERENCES alert_rules (id)
                    )
                ''')
                
                # Tabla de historial de notificaciones
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS notification_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_id TEXT,
                        method TEXT,
                        recipient TEXT,
                        status TEXT,
                        timestamp TEXT,
                        FOREIGN KEY (alert_id) REFERENCES alerts (id)
                    )
                ''')
                
                conn.commit()
                
        except sqlite3.Error as e:
            self.logger.error(f"Error inicializando base de datos de alertas: {e}")
    
    def load_default_rules(self):
        """Carga reglas de alerta por defecto."""
        default_rules = [
            {
                'id': 'critical_cve_detected',
                'name': 'CVE Crítico Detectado',
                'description': 'Se detectó una vulnerabilidad CVE crítica',
                'enabled': True,
                'conditions': {
                    'type': 'cve',
                    'severity': 'critical',
                    'score_min': 9.0
                },
                'actions': ['email', 'slack'],
                'severity': 'critical'
            },
            {
                'id': 'insecure_service_detected',
                'name': 'Servicio Inseguro Detectado',
                'description': 'Se detectó un servicio potencialmente inseguro',
                'enabled': True,
                'conditions': {
                    'type': 'service',
                    'services': ['telnet', 'ftp', 'rsh', 'rlogin']
                },
                'actions': ['email'],
                'severity': 'high'
            },
            {
                'id': 'new_host_discovered',
                'name': 'Nuevo Host Descubierto',
                'description': 'Se descubrió un nuevo host en la red',
                'enabled': False,
                'conditions': {
                    'type': 'new_host'
                },
                'actions': ['email'],
                'severity': 'medium'
            },
            {
                'id': 'port_change_detected',
                'name': 'Cambio de Puertos Detectado',
                'description': 'Se detectaron cambios en puertos abiertos',
                'enabled': True,
                'conditions': {
                    'type': 'port_change',
                    'change_types': ['new_ports', 'closed_ports']
                },
                'actions': ['email'],
                'severity': 'medium'
            },
            {
                'id': 'high_risk_port_open',
                'name': 'Puerto de Alto Riesgo Abierto',
                'description': 'Se detectó un puerto de alto riesgo abierto',
                'enabled': True,
                'conditions': {
                    'type': 'port',
                    'ports': [21, 23, 135, 445, 1433, 3389, 5900, 6000]
                },
                'actions': ['email', 'slack'],
                'severity': 'high'
            }
        ]
        
        for rule_data in default_rules:
            if not self.get_rule(rule_data['id']):
                rule = AlertRule(
                    id=rule_data['id'],
                    name=rule_data['name'],
                    description=rule_data['description'],
                    enabled=rule_data['enabled'],
                    conditions=rule_data['conditions'],
                    actions=rule_data['actions'],
                    severity=rule_data['severity'],
                    created_date=datetime.now().isoformat()
                )
                self.save_rule(rule)
    
    def save_rule(self, rule: AlertRule):
        """Guarda una regla de alerta."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO alert_rules 
                    (id, name, description, enabled, conditions, actions, severity, created_date, last_triggered)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    rule.id, rule.name, rule.description, rule.enabled,
                    json.dumps(rule.conditions), json.dumps(rule.actions),
                    rule.severity, rule.created_date, rule.last_triggered
                ))
                conn.commit()
                
        except sqlite3.Error as e:
            self.logger.error(f"Error guardando regla: {e}")
    
    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Obtiene una regla por ID."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM alert_rules WHERE id = ?', (rule_id,))
                row = cursor.fetchone()
                
                if row:
                    return AlertRule(
                        id=row[0],
                        name=row[1],
                        description=row[2],
                        enabled=bool(row[3]),
                        conditions=json.loads(row[4]) if row[4] else {},
                        actions=json.loads(row[5]) if row[5] else [],
                        severity=row[6],
                        created_date=row[7],
                        last_triggered=row[8]
                    )
        except Exception as e:
            self.logger.error(f"Error obteniendo regla: {e}")
        
        return None
    
    def get_active_rules(self) -> List[AlertRule]:
        """Obtiene todas las reglas activas."""
        rules = []
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM alert_rules WHERE enabled = 1')
                
                for row in cursor.fetchall():
                    rule = AlertRule(
                        id=row[0],
                        name=row[1],
                        description=row[2],
                        enabled=bool(row[3]),
                        conditions=json.loads(row[4]) if row[4] else {},
                        actions=json.loads(row[5]) if row[5] else [],
                        severity=row[6],
                        created_date=row[7],
                        last_triggered=row[8]
                    )
                    rules.append(rule)
                    
        except Exception as e:
            self.logger.error(f"Error obteniendo reglas activas: {e}")
        
        return rules
    
    def evaluate_rules(self, scan_data: Dict) -> List[Alert]:
        """Evalúa las reglas de alerta contra datos de escaneo."""
        alerts = []
        active_rules = self.get_active_rules()
        
        for rule in active_rules:
            rule_alerts = self.evaluate_single_rule(rule, scan_data)
            alerts.extend(rule_alerts)
            
            if rule_alerts:
                # Actualizar última vez activada
                rule.last_triggered = datetime.now().isoformat()
                self.save_rule(rule)
        
        return alerts
    
    def evaluate_single_rule(self, rule: AlertRule, scan_data: Dict) -> List[Alert]:
        """Evalúa una regla específica."""
        alerts = []
        conditions = rule.conditions
        condition_type = conditions.get('type')
        
        if condition_type == 'cve':
            alerts.extend(self.evaluate_cve_rule(rule, scan_data))
        elif condition_type == 'service':
            alerts.extend(self.evaluate_service_rule(rule, scan_data))
        elif condition_type == 'port':
            alerts.extend(self.evaluate_port_rule(rule, scan_data))
        elif condition_type == 'new_host':
            alerts.extend(self.evaluate_new_host_rule(rule, scan_data))
        elif condition_type == 'port_change':
            alerts.extend(self.evaluate_port_change_rule(rule, scan_data))
        
        return alerts
    
    def evaluate_cve_rule(self, rule: AlertRule, scan_data: Dict) -> List[Alert]:
        """Evalúa reglas de CVE."""
        alerts = []
        conditions = rule.conditions
        
        cve_data = scan_data.get('cve_report', {})
        vulnerabilities_by_host = cve_data.get('vulnerabilities_by_host', {})
        
        for host, vulnerabilities in vulnerabilities_by_host.items():
            for vuln in vulnerabilities:
                # Verificar severidad
                if 'severity' in conditions:
                    if vuln.get('severity') != conditions['severity']:
                        continue
                
                # Verificar score mínimo
                if 'score_min' in conditions:
                    if vuln.get('score', 0) < conditions['score_min']:
                        continue
                
                # Crear alerta
                alert = Alert(
                    id=f"{rule.id}_{host}_{vuln['cve_id']}_{int(datetime.now().timestamp())}",
                    rule_id=rule.id,
                    title=f"CVE {vuln['severity'].upper()}: {vuln['cve_id']}",
                    message=f"Se detectó {vuln['cve_id']} en {host}:{vuln.get('port', 'N/A')} - {vuln['description'][:200]}",
                    severity=rule.severity,
                    host=host,
                    port=vuln.get('port'),
                    service=vuln.get('service'),
                    data=vuln,
                    timestamp=datetime.now().isoformat()
                )
                alerts.append(alert)
        
        return alerts
    
    def evaluate_service_rule(self, rule: AlertRule, scan_data: Dict) -> List[Alert]:
        """Evalúa reglas de servicios."""
        alerts = []
        conditions = rule.conditions
        target_services = conditions.get('services', [])
        
        scan_results = scan_data.get('scan_results', [])
        
        for host_data in scan_results:
            host = host_data['host']
            for port_data in host_data.get('ports', []):
                service = port_data.get('service', '').lower()
                
                if service in target_services:
                    alert = Alert(
                        id=f"{rule.id}_{host}_{port_data['port']}_{int(datetime.now().timestamp())}",
                        rule_id=rule.id,
                        title=f"Servicio Inseguro: {service}",
                        message=f"Servicio inseguro '{service}' detectado en {host}:{port_data['port']}",
                        severity=rule.severity,
                        host=host,
                        port=port_data['port'],
                        service=service,
                        data=port_data,
                        timestamp=datetime.now().isoformat()
                    )
                    alerts.append(alert)
        
        return alerts
    
    def evaluate_port_rule(self, rule: AlertRule, scan_data: Dict) -> List[Alert]:
        """Evalúa reglas de puertos."""
        alerts = []
        conditions = rule.conditions
        target_ports = conditions.get('ports', [])
        
        scan_results = scan_data.get('scan_results', [])
        
        for host_data in scan_results:
            host = host_data['host']
            for port_data in host_data.get('ports', []):
                port = port_data.get('port')
                
                if port in target_ports:
                    alert = Alert(
                        id=f"{rule.id}_{host}_{port}_{int(datetime.now().timestamp())}",
                        rule_id=rule.id,
                        title=f"Puerto de Riesgo Abierto: {port}",
                        message=f"Puerto de alto riesgo {port} abierto en {host}",
                        severity=rule.severity,
                        host=host,
                        port=port,
                        service=port_data.get('service'),
                        data=port_data,
                        timestamp=datetime.now().isoformat()
                    )
                    alerts.append(alert)
        
        return alerts
    
    def evaluate_new_host_rule(self, rule: AlertRule, scan_data: Dict) -> List[Alert]:
        """Evalúa reglas de nuevos hosts."""
        # Implementación simplificada - requeriría comparación con escaneos previos
        return []
    
    def evaluate_port_change_rule(self, rule: AlertRule, scan_data: Dict) -> List[Alert]:
        """Evalúa reglas de cambios en puertos."""
        # Implementación simplificada - requeriría comparación con escaneos previos
        return []
    
    def save_alert(self, alert: Alert):
        """Guarda una alerta en la base de datos."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO alerts 
                    (id, rule_id, title, message, severity, host, port, service, data, timestamp, acknowledged)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.id, alert.rule_id, alert.title, alert.message,
                    alert.severity, alert.host, alert.port, alert.service,
                    json.dumps(alert.data), alert.timestamp, alert.acknowledged
                ))
                conn.commit()
                
        except sqlite3.Error as e:
            self.logger.error(f"Error guardando alerta: {e}")
    
    def process_alerts(self, alerts: List[Alert]):
        """Procesa y envía alertas."""
        for alert in alerts:
            self.save_alert(alert)
            
            # Obtener regla para acciones
            rule = self.get_rule(alert.rule_id)
            if rule:
                for action in rule.actions:
                    self.send_notification(alert, action)
    
    def send_notification(self, alert: Alert, method: str):
        """Envía una notificación."""
        success = False
        
        try:
            if method == 'email':
                success = self.send_email_notification(alert)
            elif method == 'slack':
                success = self.send_slack_notification(alert)
            elif method == 'webhook':
                success = self.send_webhook_notification(alert)
            
        except Exception as e:
            self.logger.error(f"Error enviando notificación {method}: {e}")
        
        # Registrar en historial
        self.log_notification(alert.id, method, success)
    
    def send_email_notification(self, alert: Alert) -> bool:
        """Envía notificación por email."""
        email_config = self.config.get('notifications', {}).get('email', {})
        
        if not email_config.get('enabled', False):
            return False
        
        try:
            smtp_server = email_config.get('smtp_server')
            smtp_port = email_config.get('smtp_port', 587)
            username = email_config.get('username')
            password = email_config.get('password')
            from_email = email_config.get('from_email', username)
            recipients = email_config.get('recipients', [])
            
            if not all([smtp_server, username, password, recipients]):
                self.logger.error("Configuración de email incompleta")
                return False
            
            # Crear mensaje
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"[SCANNER ALERT] {alert.title}"
            
            # Cuerpo del email
            body = f"""
ALERTA DE SEGURIDAD - Scanner de Red

Título: {alert.title}
Severidad: {alert.severity.upper()}
Host: {alert.host}
Puerto: {alert.port or 'N/A'}
Servicio: {alert.service or 'N/A'}
Timestamp: {alert.timestamp}

Descripción:
{alert.message}

Datos adicionales:
{json.dumps(alert.data, indent=2)}

---
Este mensaje fue generado automáticamente por el Scanner de Red.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Enviar email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email enviado para alerta {alert.id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error enviando email: {e}")
            return False
    
    def send_slack_notification(self, alert: Alert) -> bool:
        """Envía notificación a Slack."""
        slack_config = self.config.get('notifications', {}).get('slack', {})
        
        if not slack_config.get('enabled', False):
            return False
        
        try:
            webhook_url = slack_config.get('webhook_url')
            
            if not webhook_url:
                self.logger.error("URL de webhook de Slack no configurada")
                return False
            
            # Color basado en severidad
            color_map = {
                'critical': '#FF0000',
                'high': '#FF8C00',
                'medium': '#FFD700',
                'low': '#32CD32'
            }
            
            color = color_map.get(alert.severity, '#808080')
            
            payload = {
                "attachments": [{
                    "color": color,
                    "title": f"🚨 {alert.title}",
                    "text": alert.message,
                    "fields": [
                        {"title": "Host", "value": alert.host, "short": True},
                        {"title": "Puerto", "value": str(alert.port or 'N/A'), "short": True},
                        {"title": "Servicio", "value": alert.service or 'N/A', "short": True},
                        {"title": "Severidad", "value": alert.severity.upper(), "short": True}
                    ],
                    "footer": "Scanner de Red",
                    "ts": int(datetime.fromisoformat(alert.timestamp).timestamp())
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                self.logger.info(f"Mensaje Slack enviado para alerta {alert.id}")
                return True
            else:
                self.logger.error(f"Error enviando a Slack: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error enviando notificación Slack: {e}")
            return False
    
    def send_webhook_notification(self, alert: Alert) -> bool:
        """Envía notificación por webhook."""
        webhook_config = self.config.get('notifications', {}).get('webhook', {})
        
        if not webhook_config.get('enabled', False):
            return False
        
        try:
            url = webhook_config.get('url')
            headers = webhook_config.get('headers', {'Content-Type': 'application/json'})
            
            if not url:
                return False
            
            payload = asdict(alert)
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Error enviando webhook: {e}")
            return False
    
    def log_notification(self, alert_id: str, method: str, success: bool):
        """Registra el resultado de una notificación."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO notification_history 
                    (alert_id, method, recipient, status, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    alert_id, method, 'configured',
                    'success' if success else 'failed',
                    datetime.now().isoformat()
                ))
                conn.commit()
                
        except sqlite3.Error as e:
            self.logger.error(f"Error registrando notificación: {e}")
    
    def get_recent_alerts(self, hours: int = 24, severity: str = None) -> List[Dict]:
        """Obtiene alertas recientes."""
        alerts = []
        
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            cutoff_str = cutoff_time.isoformat()
            
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                query = 'SELECT * FROM alerts WHERE timestamp >= ?'
                params = [cutoff_str]
                
                if severity:
                    query += ' AND severity = ?'
                    params.append(severity)
                
                query += ' ORDER BY timestamp DESC'
                
                cursor.execute(query, params)
                
                for row in cursor.fetchall():
                    alert_data = {
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
                    alerts.append(alert_data)
                    
        except Exception as e:
            self.logger.error(f"Error obteniendo alertas recientes: {e}")
        
        return alerts
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Marca una alerta como reconocida."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE alerts SET acknowledged = 1 WHERE id = ?',
                    (alert_id,)
                )
                conn.commit()
                return cursor.rowcount > 0
                
        except sqlite3.Error as e:
            self.logger.error(f"Error reconociendo alerta: {e}")
            return False
    
    def get_alert_statistics(self) -> Dict:
        """Obtiene estadísticas de alertas."""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Total de alertas
                cursor.execute('SELECT COUNT(*) FROM alerts')
                stats['total_alerts'] = cursor.fetchone()[0]
                
                # Alertas por severidad
                cursor.execute('''
                    SELECT severity, COUNT(*) 
                    FROM alerts 
                    GROUP BY severity
                ''')
                stats['by_severity'] = dict(cursor.fetchall())
                
                # Alertas recientes (24h)
                cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
                cursor.execute('SELECT COUNT(*) FROM alerts WHERE timestamp >= ?', (cutoff,))
                stats['recent_24h'] = cursor.fetchone()[0]
                
                # Hosts con más alertas
                cursor.execute('''
                    SELECT host, COUNT(*) as count
                    FROM alerts
                    WHERE host IS NOT NULL
                    GROUP BY host
                    ORDER BY count DESC
                    LIMIT 10
                ''')
                stats['top_hosts'] = [{'host': row[0], 'count': row[1]} for row in cursor.fetchall()]
                
                return stats
                
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas: {e}")
            return {}