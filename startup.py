#!/usr/bin/env python3
"""
Script de inicio unificado para el scanner de red.
Permite iniciar diferentes componentes del sistema.
"""
import argparse
import subprocess
import sys
import os
import time
import threading
import yaml
from pathlib import Path

def load_config():
    """Carga la configuración."""
    try:
        with open('config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print("❌ Archivo config.yaml no encontrado. Usando configuración por defecto.")
        return {
            'web': {'host': '127.0.0.1', 'port': 5000},
            'api': {'host': '127.0.0.1', 'port': 5001}
        }

def check_dependencies():
    """Verifica que las dependencias estén instaladas."""
    try:
        import nmap
        import flask
        import yaml
        import rich
        print("✅ Dependencias principales verificadas")
        return True
    except ImportError as e:
        print(f"❌ Dependencia faltante: {e}")
        print("📦 Ejecuta: pip install -r requirements.txt")
        return False

def start_web_dashboard(config):
    """Inicia el dashboard web."""
    web_config = config.get('web', {})
    host = web_config.get('host', '127.0.0.1')
    port = web_config.get('port', 5000)
    
    print(f"🌐 Iniciando Dashboard Web en http://{host}:{port}")
    
    try:
        subprocess.run([
            sys.executable, 'web_dashboard.py'
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error iniciando dashboard web: {e}")
    except KeyboardInterrupt:
        print("🛑 Dashboard web detenido")

def start_api_server(config):
    """Inicia el servidor API."""
    api_config = config.get('api', {})
    host = api_config.get('host', '127.0.0.1')
    port = api_config.get('port', 5001)
    
    print(f"🚀 Iniciando API REST en http://{host}:{port}")
    
    try:
        subprocess.run([
            sys.executable, 'api_server.py'
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error iniciando API server: {e}")
    except KeyboardInterrupt:
        print("🛑 API server detenido")

def start_scanner_cli(args):
    """Inicia el scanner CLI."""
    cmd = [sys.executable, 'scanner_v2.py']
    
    # Añadir argumentos
    if hasattr(args, 'network') and args.network:
        cmd.append(args.network)
    
    if hasattr(args, 'type') and args.type:
        cmd.extend(['-t', args.type])
    
    if hasattr(args, 'output') and args.output:
        cmd.extend(['-o', args.output])
    
    if hasattr(args, 'format') and args.format:
        cmd.extend(['-f', args.format])
    
    if hasattr(args, 'no_nse') and args.no_nse:
        cmd.append('--no-nse')
    
    print(f"🔍 Ejecutando scanner: {' '.join(cmd[2:])}")
    
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error ejecutando scanner: {e}")
    except KeyboardInterrupt:
        print("🛑 Scanner detenido")

def start_all_services(config):
    """Inicia todos los servicios en paralelo."""
    print("🚀 Iniciando todos los servicios...")
    
    def run_web():
        start_web_dashboard(config)
    
    def run_api():
        # Pequeña pausa para evitar conflictos de puerto
        time.sleep(2)
        start_api_server(config)
    
    # Crear hilos para cada servicio
    web_thread = threading.Thread(target=run_web, daemon=True)
    api_thread = threading.Thread(target=run_api, daemon=True)
    
    # Iniciar servicios
    web_thread.start()
    api_thread.start()
    
    print("✅ Servicios iniciados")
    print(f"🌐 Dashboard Web: http://{config.get('web', {}).get('host', '127.0.0.1')}:{config.get('web', {}).get('port', 5000)}")
    print(f"🚀 API REST: http://{config.get('api', {}).get('host', '127.0.0.1')}:{config.get('api', {}).get('port', 5001)}")
    print("📖 Documentación API: /api/v1/info")
    print("\n⚠️  Presiona Ctrl+C para detener todos los servicios")
    
    try:
        # Mantener el proceso principal vivo
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Deteniendo servicios...")
        print("✅ Servicios detenidos")

def show_status():
    """Muestra el estado del sistema."""
    print("📊 Estado del Sistema Scanner de Red")
    print("=" * 50)
    
    # Verificar archivos
    files_to_check = [
        'scanner_v2.py',
        'web_dashboard.py', 
        'api_server.py',
        'database.py',
        'config.yaml'
    ]
    
    for file in files_to_check:
        status = "✅" if os.path.exists(file) else "❌"
        print(f"{status} {file}")
    
    # Verificar bases de datos
    db_files = ['scanner_history.db', 'alerts.db', 'cve_cache.db']
    print("\n📁 Bases de Datos:")
    for db in db_files:
        if os.path.exists(db):
            size = os.path.getsize(db)
            print(f"✅ {db} ({size} bytes)")
        else:
            print(f"⚪ {db} (no creada)")
    
    # Mostrar configuración
    config = load_config()
    print(f"\n⚙️  Configuración:")
    print(f"   Web Dashboard: {config.get('web', {}).get('host', '127.0.0.1')}:{config.get('web', {}).get('port', 5000)}")
    print(f"   API Server: {config.get('api', {}).get('host', '127.0.0.1')}:{config.get('api', {}).get('port', 5001)}")
    print(f"   Workers paralelos: {config.get('parallel', {}).get('max_workers', 20)}")
    print(f"   Scripts NSE: {'Habilitados' if config.get('scan', {}).get('use_nse_scripts', False) else 'Deshabilitados'}")

def main():
    parser = argparse.ArgumentParser(
        description="Sistema Scanner de Red - Startup Manager",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')
    
    # Comando para iniciar dashboard web
    web_parser = subparsers.add_parser('web', help='Iniciar dashboard web')
    
    # Comando para iniciar API server
    api_parser = subparsers.add_parser('api', help='Iniciar servidor API')
    
    # Comando para escaneo CLI
    scan_parser = subparsers.add_parser('scan', help='Ejecutar escaneo CLI')
    scan_parser.add_argument('network', nargs='?', help='Red a escanear')
    scan_parser.add_argument('-t', '--type', choices=['tcp', 'udp', 'both'], 
                            help='Tipo de escaneo')
    scan_parser.add_argument('-o', '--output', help='Archivo de salida')
    scan_parser.add_argument('-f', '--format', choices=['json', 'csv', 'txt'], 
                            help='Formato de salida')
    scan_parser.add_argument('--no-nse', action='store_true', 
                            help='Deshabilitar scripts NSE')
    
    # Comando para iniciar todos los servicios
    all_parser = subparsers.add_parser('all', help='Iniciar todos los servicios')
    
    # Comando para mostrar estado
    status_parser = subparsers.add_parser('status', help='Mostrar estado del sistema')
    
    # Comando de ayuda extendida
    help_parser = subparsers.add_parser('help', help='Mostrar ayuda extendida')
    
    args = parser.parse_args()
    
    # Verificar dependencias
    if not check_dependencies():
        sys.exit(1)
    
    # Cargar configuración
    config = load_config()
    
    # Ejecutar comando
    if args.command == 'web':
        start_web_dashboard(config)
        
    elif args.command == 'api':
        start_api_server(config)
        
    elif args.command == 'scan':
        if not args.network:
            print("❌ Red requerida para escaneo")
            print("Ejemplo: python startup.py scan 192.168.1.0/24")
            sys.exit(1)
        start_scanner_cli(args)
        
    elif args.command == 'all':
        start_all_services(config)
        
    elif args.command == 'status':
        show_status()
        
    elif args.command == 'help':
        show_help()
        
    else:
        parser.print_help()
        print("\n💡 Comandos de ejemplo:")
        print("  python startup.py status                    # Ver estado")
        print("  python startup.py scan 192.168.1.0/24     # Escanear red")
        print("  python startup.py web                      # Dashboard web")
        print("  python startup.py api                      # API server")
        print("  python startup.py all                      # Todos los servicios")

def show_help():
    """Muestra ayuda extendida."""
    help_text = """
🔍 Scanner de Red - Ayuda Extendida
==================================

COMPONENTES DEL SISTEMA:
• scanner_v2.py      - Scanner CLI principal con funciones avanzadas
• web_dashboard.py   - Dashboard web interactivo
• api_server.py      - API REST para integraciones
• parallel_scanner.py - Motor de escaneo paralelo
• database.py        - Sistema de base de datos SQLite
• alert_system.py    - Sistema de alertas y notificaciones
• cve_detector.py    - Detector de vulnerabilidades CVE

COMANDOS PRINCIPALES:

1. Escaneo CLI:
   python startup.py scan 192.168.1.0/24
   python startup.py scan 10.0.0.1-50 -t udp
   python startup.py scan target.com -o results -f json

2. Servicios Web:
   python startup.py web    # Dashboard en puerto 5000
   python startup.py api    # API REST en puerto 5001
   python startup.py all    # Ambos servicios

3. Administración:
   python startup.py status    # Estado del sistema
   python startup.py help      # Esta ayuda

CONFIGURACIÓN:
El archivo config.yaml controla todos los aspectos del sistema:
• Parámetros de escaneo y scripts NSE
• Configuración de base de datos y retención
• Alertas y notificaciones (email, Slack, webhook)
• Configuración web y API
• Paralelización y rendimiento

EJEMPLOS DE USO:

# Escaneo básico
python startup.py scan 192.168.1.0/24

# Escaneo UDP con scripts NSE
python startup.py scan 10.0.0.0/8 -t udp

# Iniciar dashboard para análisis visual
python startup.py web

# API para integración con otros sistemas
python startup.py api

# Todos los servicios para monitoreo continuo
python startup.py all

PUERTOS Y SERVICIOS:
• Dashboard Web: http://127.0.0.1:5000
• API REST: http://127.0.0.1:5001
• Documentación API: http://127.0.0.1:5001/api/v1/info

Para más información consulta README.md
    """
    print(help_text)

if __name__ == "__main__":
    main()