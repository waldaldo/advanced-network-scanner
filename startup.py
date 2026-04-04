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
        print("config.yaml no encontrado. Usando configuracion por defecto.")
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
        print("Dependencias principales verificadas")
        return True
    except ImportError as e:
        print(f"Dependencia faltante: {e}")
        print("Ejecuta: pip install -r requirements.txt")
        return False

def start_web_dashboard(config):
    """Inicia el dashboard web."""
    web_config = config.get('web', {})
    host = web_config.get('host', '127.0.0.1')
    port = web_config.get('port', 5000)

    print(f"Iniciando Dashboard Web en http://{host}:{port}")

    try:
        subprocess.run([sys.executable, 'web_dashboard.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error iniciando dashboard web: {e}")
    except KeyboardInterrupt:
        print("Dashboard web detenido")

def start_api_server(config):
    """Inicia el servidor API."""
    api_config = config.get('api', {})
    host = api_config.get('host', '127.0.0.1')
    port = api_config.get('port', 5001)

    print(f"Iniciando API REST en http://{host}:{port}")

    try:
        subprocess.run([sys.executable, 'api_server.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error iniciando API server: {e}")
    except KeyboardInterrupt:
        print("API server detenido")

def start_scanner_cli(args):
    """Inicia el scanner CLI."""
    cmd = [sys.executable, 'scanner_v2.py']

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

    print(f"Ejecutando scanner: {' '.join(cmd[2:])}")

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error ejecutando scanner: {e}")
    except KeyboardInterrupt:
        print("Scanner detenido")

def start_all_services(config):
    """Inicia todos los servicios en paralelo."""
    print("Iniciando todos los servicios...")

    def run_web():
        start_web_dashboard(config)

    def run_api():
        time.sleep(2)
        start_api_server(config)

    web_thread = threading.Thread(target=run_web, daemon=True)
    api_thread = threading.Thread(target=run_api, daemon=True)

    web_thread.start()
    api_thread.start()

    web_host = config.get('web', {}).get('host', '127.0.0.1')
    web_port = config.get('web', {}).get('port', 5000)
    api_host = config.get('api', {}).get('host', '127.0.0.1')
    api_port = config.get('api', {}).get('port', 5001)

    print(f"Dashboard Web: http://{web_host}:{web_port}")
    print(f"API REST:      http://{api_host}:{api_port}")
    print(f"Documentacion: http://{api_host}:{api_port}/api/v1/info")
    print("Presiona Ctrl+C para detener todos los servicios")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Deteniendo servicios...")

def show_status():
    """Muestra el estado del sistema."""
    print("Estado del Sistema - Scanner de Red")
    print("=" * 50)

    files_to_check = ['scanner_v2.py', 'web_dashboard.py', 'api_server.py', 'database.py', 'config.yaml']

    for file in files_to_check:
        status = "OK  " if os.path.exists(file) else "FALTA"
        print(f"  [{status}] {file}")

    db_files = ['scanner_history.db', 'alerts.db', 'cve_cache.db']
    print("\nBases de Datos:")
    for db in db_files:
        if os.path.exists(db):
            size = os.path.getsize(db)
            print(f"  [OK   ] {db} ({size} bytes)")
        else:
            print(f"  [NUEVA] {db} (se creara al ejecutar)")

    config = load_config()
    print("\nConfiguracion:")
    print(f"  Web Dashboard: {config.get('web', {}).get('host', '127.0.0.1')}:{config.get('web', {}).get('port', 5000)}")
    print(f"  API Server:    {config.get('api', {}).get('host', '127.0.0.1')}:{config.get('api', {}).get('port', 5001)}")
    print(f"  Workers:       {config.get('parallel', {}).get('max_workers', 20)}")
    nse = 'habilitados' if config.get('scan', {}).get('use_nse_scripts', False) else 'deshabilitados'
    print(f"  Scripts NSE:   {nse}")

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
            print("Red requerida. Ejemplo: python startup.py scan 192.168.1.0/24")
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
        print("\nEjemplos:")
        print("  python startup.py status")
        print("  python startup.py scan 192.168.1.0/24")
        print("  python startup.py web")
        print("  python startup.py api")
        print("  python startup.py all")

def show_help():
    """Muestra ayuda extendida."""
    help_text = """
Scanner de Red - Ayuda
======================

COMPONENTES:
  scanner_v2.py       Scanner CLI principal
  web_dashboard.py    Dashboard web (puerto 5000)
  api_server.py       API REST (puerto 5001)
  parallel_scanner.py Motor de escaneo paralelo
  database.py         Persistencia SQLite
  alert_system.py     Alertas y notificaciones
  cve_detector.py     Detector de vulnerabilidades CVE

COMANDOS:

  scan <red> [-t tcp|udp|both] [-o archivo] [-f json|csv|txt] [--no-nse]
    python startup.py scan 192.168.1.0/24
    python startup.py scan 10.0.0.1-50 -t udp
    python startup.py scan 192.168.1.1 -o resultados -f json

  web       Iniciar dashboard (http://127.0.0.1:5000)
  api       Iniciar API REST  (http://127.0.0.1:5001)
  all       Iniciar ambos servicios
  status    Mostrar estado del sistema

CONFIGURACION:
  Editar config.yaml para ajustar escaneo, base de datos,
  alertas, notificaciones y paralelizacion.

  La API key se configura via variable de entorno:
    export SCANNER_API_KEY=<clave>
"""
    print(help_text)

if __name__ == "__main__":
    main()