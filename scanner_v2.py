#!/usr/bin/env python3
import nmap
import sys
import argparse
import json
import csv
import os
import yaml
import logging
import time
import ipaddress
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from rich.panel import Panel
from rich.text import Text
from database import ScanDatabase

class NetworkScanner:
    def __init__(self, config_file="config.yaml"):
        self.console = Console()
        self.config = self.load_config(config_file)
        self.setup_logging()
        
        if self.config['database']['enabled']:
            self.db = ScanDatabase(self.config['database']['db_file'])
        else:
            self.db = None
        
        self.nm = nmap.PortScanner()
    
    def load_config(self, config_file):
        """Carga la configuración desde el archivo YAML."""
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    return yaml.safe_load(f)
            else:
                self.console.print(f"[yellow]Archivo de configuración {config_file} no encontrado. Usando valores por defecto.[/yellow]")
                return self.get_default_config()
        except Exception as e:
            self.console.print(f"[red]Error cargando configuración: {e}[/red]")
            return self.get_default_config()
    
    def get_default_config(self):
        """Retorna configuración por defecto."""
        return {
            'scan': {
                'default_scan_type': 'tcp',
                'default_tcp_args': '-sV -T4 --open',
                'default_udp_args': '-sU -T4 --open --top-ports 1000',
                'timeout': 300,
                'os_detection': True,
                'use_nse_scripts': True,
                'nse_scripts': ['vuln', 'safe', 'default']
            },
            'output': {
                'default_format': 'json',
                'output_dir': './results',
                'timestamp_files': True,
                'auto_save': True
            },
            'database': {
                'enabled': True,
                'db_file': './scanner_history.db',
                'retention_days': 90
            },
            'display': {
                'show_progress': True,
                'verbose_stats': True,
                'use_colors': True,
                'show_banners': True
            },
            'network': {
                'allowed_ranges': ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12', '127.0.0.1/32'],
                'forbidden_ranges': [],
                'max_concurrent_hosts': 50
            }
        }
    
    def setup_logging(self):
        """Configura el sistema de logging."""
        log_level = getattr(logging, self.config.get('advanced', {}).get('log_level', 'INFO'))
        log_file = self.config.get('advanced', {}).get('log_file', './scanner.log')
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_network(self, network):
        """Valida que la red esté en los rangos permitidos."""
        try:
            target_network = ipaddress.ip_network(network, strict=False)
        except ValueError:
            self.console.print(f"[red]Red inválida: {network}[/red]")
            return False
        
        allowed_ranges = self.config['network']['allowed_ranges']
        forbidden_ranges = self.config['network']['forbidden_ranges']
        
        # Verificar rangos prohibidos
        for forbidden in forbidden_ranges:
            forbidden_net = ipaddress.ip_network(forbidden)
            if target_network.overlaps(forbidden_net):
                self.console.print(f"[red]Red prohibida: {network}[/red]")
                return False
        
        # Verificar rangos permitidos
        for allowed in allowed_ranges:
            allowed_net = ipaddress.ip_network(allowed)
            if target_network.subnet_of(allowed_net) or target_network.overlaps(allowed_net):
                return True
        
        self.console.print(f"[red]Red no permitida: {network}[/red]")
        return False
    
    def build_nmap_arguments(self, scan_type, use_nse=None):
        """Construye los argumentos de Nmap según el tipo de escaneo."""
        if scan_type == 'tcp':
            args = self.config['scan']['default_tcp_args']
        elif scan_type == 'udp':
            args = self.config['scan']['default_udp_args']
        elif scan_type == 'both':
            # Para escaneo mixto, usar argumentos TCP con UDP
            args = self.config['scan']['default_tcp_args'] + ' -sU --top-ports 100'
        else:
            args = self.config['scan']['default_tcp_args']
        
        # Agregar detección de OS si está habilitada y se ejecuta como root
        if self.config['scan']['os_detection'] and os.name != 'nt' and os.geteuid() == 0:
            args += ' -O'
        
        # Agregar scripts NSE
        if use_nse is None:
            use_nse = self.config['scan']['use_nse_scripts']
        
        if use_nse:
            nse_scripts = ','.join(self.config['scan']['nse_scripts'])
            args += f' --script={nse_scripts}'
        
        return args
    
    def scan_network(self, network, scan_type='tcp', output_file=None, 
                    output_format=None, use_nse=None):
        """Escanea la red especificada."""
        start_time = time.time()
        
        # Validar red
        if not self.validate_network(network):
            return None
        
        # Preparar argumentos
        arguments = self.build_nmap_arguments(scan_type, use_nse)
        
        self.console.print(Panel(
            f"[bold cyan]Iniciando escaneo {scan_type.upper()}[/bold cyan]\n"
            f"Red: {network}\n"
            f"Argumentos: {arguments}",
            title="Configuración del Escaneo"
        ))
        
        # Ejecutar escaneo
        spinner_text = f"Escaneando {network} ({scan_type.upper()})... esto puede tardar varios minutos."
        spinner = Spinner("dots", text=spinner_text)
        
        results = []
        with Live(spinner, console=self.console, transient=True):
            try:
                self.nm.scan(hosts=network, arguments=arguments)
                self.logger.info(f"Escaneo completado para {network}")
            except nmap.PortScannerError as e:
                self.console.print(f"[bold red]Error de Nmap: {e}[/bold red]")
                return None
            except Exception as e:
                self.console.print(f"[bold red]Error inesperado: {e}[/bold red]")
                return None
        
        # Procesar resultados
        results = self.process_results()
        
        # Mostrar resultados
        self.display_results(network, results, scan_type)
        
        # Calcular duración
        duration = time.time() - start_time
        
        # Guardar en base de datos
        if self.db:
            try:
                scan_id = self.db.save_scan(network, scan_type, results, duration, arguments)
                self.console.print(f"[green]Escaneo guardado en BD con ID: {scan_id}[/green]")
            except Exception as e:
                self.logger.error(f"Error guardando en BD: {e}")
        
        # Guardar archivo si se especifica
        if output_file and output_format:
            self.save_results(results, output_file, output_format)
        elif self.config['output']['auto_save']:
            # Auto-guardar con timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{network.replace('/', '_')}_{scan_type}_{timestamp}"
            self.save_results(results, filename, self.config['output']['default_format'])
        
        return results
    
    def process_results(self):
        """Procesa los resultados del escaneo."""
        results = []
        
        for host in self.nm.all_hosts():
            host_data = {
                'host': host,
                'status': self.nm[host].state(),
                'mac': self.nm[host]['addresses'].get('mac', 'N/A'),
                'vendor': self.nm[host]['vendor'].get(
                    self.nm[host]['addresses'].get('mac', ''), 'N/A'
                ),
                'ports': [],
                'os': self.nm[host].get('osmatch', []),
                'hostscript': self.nm[host].get('hostscript', [])
            }
            
            # Procesar puertos TCP
            if 'tcp' in self.nm[host]:
                for port in self.nm[host]['tcp']:
                    port_info = self.nm[host]['tcp'][port]
                    port_data = {
                        'port': port,
                        'protocol': 'tcp',
                        'service': port_info.get('name', 'unknown'),
                        'version': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                        'state': port_info.get('state', 'unknown'),
                        'script': port_info.get('script', {})
                    }
                    host_data['ports'].append(port_data)
            
            # Procesar puertos UDP
            if 'udp' in self.nm[host]:
                for port in self.nm[host]['udp']:
                    port_info = self.nm[host]['udp'][port]
                    port_data = {
                        'port': port,
                        'protocol': 'udp',
                        'service': port_info.get('name', 'unknown'),
                        'version': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                        'state': port_info.get('state', 'unknown'),
                        'script': port_info.get('script', {})
                    }
                    host_data['ports'].append(port_data)
            
            results.append(host_data)
        
        return results
    
    def display_results(self, network, results, scan_type):
        """Muestra los resultados del escaneo."""
        table = Table(
            title=f"Resultados del Escaneo {scan_type.upper()} - [bold cyan]{network}[/bold cyan]",
            show_header=True,
            header_style="bold magenta"
        )
        
        table.add_column("Host", style="dim", width=15)
        table.add_column("MAC/Vendor", width=25)
        table.add_column("Puerto", justify="right", width=10)
        table.add_column("Proto", width=5)
        table.add_column("Servicio", width=15)
        table.add_column("Versión", width=25)
        table.add_column("Estado", justify="center", width=10)
        
        active_hosts = 0
        total_ports = 0
        
        for host_data in results:
            if host_data['status'] == 'up':
                active_hosts += 1
            
            vendor_info = f"{host_data['mac']}"
            if host_data['vendor'] != 'N/A':
                vendor_info += f"\n{host_data['vendor'][:20]}"
            
            if not host_data['ports']:
                table.add_row(
                    f"[bold yellow]{host_data['host']}[/bold yellow]",
                    vendor_info,
                    "[italic]N/A[/italic]",
                    "",
                    "[italic]Sin puertos abiertos[/italic]",
                    "",
                    f"[green]{host_data['status']}[/green]"
                )
            else:
                for i, port_data in enumerate(host_data['ports']):
                    total_ports += 1
                    host_display = f"[bold yellow]{host_data['host']}[/bold yellow]" if i == 0 else ""
                    vendor_display = vendor_info if i == 0 else ""
                    
                    # Color según protocolo
                    proto_color = "cyan" if port_data['protocol'] == 'tcp' else "magenta"
                    
                    table.add_row(
                        host_display,
                        vendor_display,
                        f"[{proto_color}]{port_data['port']}[/{proto_color}]",
                        port_data['protocol'].upper(),
                        f"[green]{port_data['service']}[/green]",
                        port_data['version'][:25],
                        f"[green]{port_data['state']}[/green]"
                    )
        
        self.console.print(table)
        
        # Estadísticas
        stats = Panel(
            f"[bold]Estadísticas del Escaneo:[/bold]\n"
            f"• Hosts escaneados: [bold cyan]{len(results)}[/bold cyan]\n"
            f"• Hosts activos: [bold green]{active_hosts}[/bold green]\n"
            f"• Puertos encontrados: [bold yellow]{total_ports}[/bold yellow]",
            title="Resumen"
        )
        self.console.print(stats)
    
    def save_results(self, results, filename, format_type):
        """Guarda los resultados en el formato especificado."""
        try:
            # Crear directorio si no existe
            output_dir = Path(self.config['output']['output_dir'])
            output_dir.mkdir(exist_ok=True)
            
            # Construir ruta completa — añadir extensión si no la tiene
            if not filename.endswith(f'.{format_type}'):
                filename = f"{filename}.{format_type}"
            filepath = output_dir / filename
            
            with open(filepath, 'w', newline='') as f:
                if format_type == 'json':
                    json.dump(results, f, indent=4, default=str)
                elif format_type == 'csv':
                    writer = csv.writer(f)
                    writer.writerow(['Host', 'MAC', 'Vendor', 'Port', 'Protocol', 'Service', 'Version', 'State'])
                    for host in results:
                        for port_info in host['ports']:
                            writer.writerow([
                                host['host'], host['mac'], host['vendor'],
                                port_info['port'], port_info['protocol'],
                                port_info['service'], port_info['version'], port_info['state']
                            ])
                elif format_type == 'txt':
                    for host in results:
                        f.write(f"Host: {host['host']} (MAC: {host['mac']}) - Status: {host['status']}\n")
                        if host['vendor'] != 'N/A':
                            f.write(f"  Vendor: {host['vendor']}\n")
                        for port_info in host['ports']:
                            f.write(f"  - Port: {port_info['port']}/{port_info['protocol']}\n")
                            f.write(f"    Service: {port_info['service']}\n")
                            f.write(f"    Version: {port_info['version']}\n")
                            f.write(f"    State: {port_info['state']}\n")
                        f.write("\n")
            
            self.console.print(f"[bold green]Resultados guardados en '{filepath}'[/bold green]")
            
        except IOError as e:
            self.console.print(f"[bold red]Error guardando archivo: {e}[/bold red]")

def main():
    parser = argparse.ArgumentParser(
        description="Scanner de Red Avanzado con Nmap - Versión 2.0",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("network", 
                       help="Red a escanear (ej. '192.168.1.0/24' o '192.168.1.1-100')")
    
    parser.add_argument("-t", "--type", 
                       choices=['tcp', 'udp', 'both'], 
                       default='tcp',
                       help="Tipo de escaneo: tcp, udp, o both (default: tcp)")
    
    parser.add_argument("-o", "--output", 
                       help="Archivo de salida")
    
    parser.add_argument("-f", "--format", 
                       choices=['json', 'csv', 'txt'], 
                       help="Formato del archivo de salida")
    
    parser.add_argument("-c", "--config", 
                       default="config.yaml",
                       help="Archivo de configuración (default: config.yaml)")
    
    parser.add_argument("--no-nse", 
                       action="store_true",
                       help="Deshabilitar scripts NSE")
    
    parser.add_argument("--history", 
                       action="store_true",
                       help="Mostrar historial de escaneos")
    
    parser.add_argument("--stats", 
                       action="store_true",
                       help="Mostrar estadísticas de la base de datos")
    
    args = parser.parse_args()
    
    # Crear scanner
    scanner = NetworkScanner(args.config)
    
    # Mostrar historial si se solicita
    if args.history:
        if scanner.db:
            history = scanner.db.get_scan_history()
            if history:
                table = Table(title="Historial de Escaneos")
                table.add_column("ID")
                table.add_column("Red")
                table.add_column("Tipo")
                table.add_column("Fecha")
                table.add_column("Hosts")
                table.add_column("Duración")
                
                for scan in history:
                    table.add_row(
                        str(scan['id']),
                        scan['network'],
                        scan['scan_type'],
                        scan['timestamp'][:19],
                        f"{scan['active_hosts']}/{scan['total_hosts']}",
                        f"{scan['duration']:.1f}s"
                    )
                scanner.console.print(table)
            else:
                scanner.console.print("[yellow]No hay historial de escaneos[/yellow]")
        return
    
    # Mostrar estadísticas si se solicita
    if args.stats:
        if scanner.db:
            stats = scanner.db.get_statistics()
            scanner.console.print(Panel(
                f"[bold]Estadísticas Generales:[/bold]\n"
                f"• Total escaneos: [cyan]{stats.get('total_scans', 0)}[/cyan]\n"
                f"• Hosts únicos: [cyan]{stats.get('unique_hosts', 0)}[/cyan]\n"
                f"• Puertos encontrados: [cyan]{stats.get('total_ports', 0)}[/cyan]\n"
                f"• Último escaneo: [cyan]{stats.get('last_scan', 'N/A')}[/cyan]",
                title="Estadísticas de Base de Datos"
            ))
        return
    
    # Validar argumentos
    if args.output and not args.format:
        parser.error("--format es requerido cuando se especifica --output.")
    
    # Ejecutar escaneo
    use_nse = not args.no_nse
    results = scanner.scan_network(
        args.network, 
        args.type, 
        args.output, 
        args.format, 
        use_nse
    )
    
    if results is None:
        sys.exit(1)

if __name__ == "__main__":
    main()