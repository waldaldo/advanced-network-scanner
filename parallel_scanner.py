#!/usr/bin/env python3
"""
Scanner paralelo con threading para mejorar el rendimiento.
"""
import nmap
import threading
import concurrent.futures
import time
import ipaddress
import logging
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from queue import Queue, Empty
from rich.console import Console
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.live import Live
from rich.table import Table

@dataclass
class ScanTarget:
    """Objetivo de escaneo."""
    host: str
    ports: Optional[List[int]] = None
    scan_type: str = 'tcp'
    arguments: str = '-sV -T4 --open'

@dataclass
class ScanResult:
    """Resultado de escaneo."""
    host: str
    status: str
    ports: List[Dict]
    error: Optional[str] = None
    scan_time: float = 0.0
    mac_address: str = 'N/A'
    vendor: str = 'N/A'
    os_info: List = None

class ParallelScanner:
    """Scanner paralelo con threading."""
    
    def __init__(self, max_workers: int = 10, timeout: int = 300):
        self.max_workers = max_workers
        self.timeout = timeout
        self.console = Console()
        self.results_queue = Queue()
        self.progress_callbacks = []
        self.logger = logging.getLogger(__name__)
        
    def add_progress_callback(self, callback: Callable[[str, float], None]):
        """Añade callback para reportar progreso."""
        self.progress_callbacks.append(callback)
    
    def report_progress(self, message: str, progress: float):
        """Reporta progreso a todos los callbacks."""
        for callback in self.progress_callbacks:
            try:
                callback(message, progress)
            except Exception as e:
                self.logger.error(f"Error en callback de progreso: {e}")
    
    def expand_network_range(self, network: str) -> List[str]:
        """Expande un rango de red a lista de IPs individuales."""
        hosts = []
        
        try:
            # Manejo de diferentes formatos de red
            if '/' in network:
                # CIDR notation (e.g., 192.168.1.0/24)
                net = ipaddress.ip_network(network, strict=False)
                hosts = [str(ip) for ip in net.hosts()]
                
            elif '-' in network:
                # Range notation (e.g., 192.168.1.1-50)
                if network.count('-') == 1:
                    base, range_part = network.rsplit('.', 1)
                    start, end = range_part.split('-')
                    start_ip = int(start)
                    end_ip = int(end)
                    
                    for i in range(start_ip, end_ip + 1):
                        hosts.append(f"{base}.{i}")
                else:
                    # Full IP range (e.g., 192.168.1.1-192.168.1.50)
                    start_ip, end_ip = network.split('-')
                    start = ipaddress.ip_address(start_ip.strip())
                    end = ipaddress.ip_address(end_ip.strip())
                    
                    current = start
                    while current <= end:
                        hosts.append(str(current))
                        current += 1
            else:
                # Single host
                hosts = [network]
                
        except (ipaddress.AddressValueError, ValueError) as e:
            self.logger.error(f"Error procesando rango de red {network}: {e}")
            raise ValueError(f"Formato de red inválido: {network}")
        
        return hosts
    
    def create_scan_targets(self, network: str, scan_type: str = 'tcp', 
                          arguments: str = '-sV -T4 --open') -> List[ScanTarget]:
        """Crea objetivos de escaneo para una red."""
        hosts = self.expand_network_range(network)
        
        targets = []
        for host in hosts:
            target = ScanTarget(
                host=host,
                scan_type=scan_type,
                arguments=arguments
            )
            targets.append(target)
        
        return targets
    
    def scan_single_host(self, target: ScanTarget) -> ScanResult:
        """Escanea un solo host."""
        start_time = time.time()
        
        try:
            nm = nmap.PortScanner()
            
            # Ejecutar escaneo
            nm.scan(hosts=target.host, arguments=target.arguments)
            
            # Procesar resultados
            if target.host in nm.all_hosts():
                host_info = nm[target.host]
                
                # Información básica del host
                status = host_info.state()
                mac_address = host_info['addresses'].get('mac', 'N/A')
                vendor = host_info['vendor'].get(mac_address, 'N/A') if mac_address != 'N/A' else 'N/A'
                os_info = host_info.get('osmatch', [])
                
                # Procesar puertos
                ports = []
                
                # Puertos TCP
                if 'tcp' in host_info:
                    for port in host_info['tcp']:
                        port_info = host_info['tcp'][port]
                        ports.append({
                            'port': port,
                            'protocol': 'tcp',
                            'state': port_info.get('state', 'unknown'),
                            'service': port_info.get('name', 'unknown'),
                            'version': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                            'script': port_info.get('script', {})
                        })
                
                # Puertos UDP
                if 'udp' in host_info:
                    for port in host_info['udp']:
                        port_info = host_info['udp'][port]
                        ports.append({
                            'port': port,
                            'protocol': 'udp',
                            'state': port_info.get('state', 'unknown'),
                            'service': port_info.get('name', 'unknown'),
                            'version': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                            'script': port_info.get('script', {})
                        })
                
                scan_time = time.time() - start_time
                
                return ScanResult(
                    host=target.host,
                    status=status,
                    ports=ports,
                    scan_time=scan_time,
                    mac_address=mac_address,
                    vendor=vendor,
                    os_info=os_info
                )
            else:
                # Host no responde
                scan_time = time.time() - start_time
                return ScanResult(
                    host=target.host,
                    status='down',
                    ports=[],
                    scan_time=scan_time
                )
                
        except Exception as e:
            scan_time = time.time() - start_time
            self.logger.error(f"Error escaneando {target.host}: {e}")
            
            return ScanResult(
                host=target.host,
                status='error',
                ports=[],
                error=str(e),
                scan_time=scan_time
            )
    
    def scan_network_parallel(self, network: str, scan_type: str = 'tcp',
                            arguments: str = '-sV -T4 --open') -> List[ScanResult]:
        """Escanea una red usando threading paralelo."""
        
        # Crear objetivos de escaneo
        targets = self.create_scan_targets(network, scan_type, arguments)
        total_targets = len(targets)
        
        self.console.print(f"[bold cyan]Iniciando escaneo paralelo de {total_targets} hosts[/bold cyan]")
        self.console.print(f"[dim]Workers: {self.max_workers}, Timeout: {self.timeout}s[/dim]")
        
        results = []
        completed = 0
        
        # Crear progreso visual
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False
        ) as progress:
            
            scan_task = progress.add_task("Escaneando hosts", total=total_targets)
            
            # Función worker con progreso
            def scan_with_progress(target):
                nonlocal completed
                result = self.scan_single_host(target)
                completed += 1
                
                # Actualizar progreso
                progress.update(scan_task, completed=completed)
                
                # Callback de progreso
                progress_pct = (completed / total_targets) * 100
                self.report_progress(f"Completado {completed}/{total_targets} hosts", progress_pct)
                
                return result
            
            # Ejecutar escaneos en paralelo
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Enviar todos los trabajos
                future_to_target = {
                    executor.submit(scan_with_progress, target): target 
                    for target in targets
                }
                
                # Recopilar resultados
                for future in concurrent.futures.as_completed(future_to_target, timeout=self.timeout * total_targets):
                    target = future_to_target[future]
                    try:
                        result = future.result()
                        results.append(result)
                        
                    except Exception as e:
                        self.logger.error(f"Error procesando resultado para {target.host}: {e}")
                        # Añadir resultado de error
                        results.append(ScanResult(
                            host=target.host,
                            status='error',
                            ports=[],
                            error=str(e)
                        ))
        
        return results
    
    def scan_ports_parallel(self, host: str, ports: List[int], 
                          scan_type: str = 'tcp') -> ScanResult:
        """Escanea puertos específicos de un host en paralelo."""
        
        # Dividir puertos en chunks para paralelizar
        chunk_size = max(1, len(ports) // self.max_workers)
        port_chunks = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]
        
        all_ports = []
        
        def scan_port_chunk(port_list):
            """Escanea un chunk de puertos."""
            port_range = ','.join(map(str, port_list))
            arguments = f'-p {port_range} -sV -T4'
            
            if scan_type == 'udp':
                arguments = f'-sU -p {port_range} -T4'
            elif scan_type == 'both':
                arguments = f'-sS -sU -p {port_range} -sV -T4'
            
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=host, arguments=arguments)
                
                chunk_ports = []
                if host in nm.all_hosts():
                    host_info = nm[host]
                    
                    # Procesar TCP
                    if 'tcp' in host_info:
                        for port in host_info['tcp']:
                            port_info = host_info['tcp'][port]
                            chunk_ports.append({
                                'port': port,
                                'protocol': 'tcp',
                                'state': port_info.get('state', 'unknown'),
                                'service': port_info.get('name', 'unknown'),
                                'version': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                            })
                    
                    # Procesar UDP
                    if 'udp' in host_info:
                        for port in host_info['udp']:
                            port_info = host_info['udp'][port]
                            chunk_ports.append({
                                'port': port,
                                'protocol': 'udp',
                                'state': port_info.get('state', 'unknown'),
                                'service': port_info.get('name', 'unknown'),
                                'version': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                            })
                
                return chunk_ports
                
            except Exception as e:
                self.logger.error(f"Error escaneando chunk de puertos {port_list} en {host}: {e}")
                return []
        
        # Ejecutar chunks en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(port_chunks)) as executor:
            future_to_chunk = {
                executor.submit(scan_port_chunk, chunk): chunk 
                for chunk in port_chunks
            }
            
            for future in concurrent.futures.as_completed(future_to_chunk):
                try:
                    chunk_results = future.result()
                    all_ports.extend(chunk_results)
                except Exception as e:
                    self.logger.error(f"Error procesando chunk de puertos: {e}")
        
        return ScanResult(
            host=host,
            status='up' if all_ports else 'filtered',
            ports=all_ports
        )
    
    def display_results(self, results: List[ScanResult], show_down_hosts: bool = False):
        """Muestra los resultados del escaneo en una tabla."""
        
        # Filtrar hosts según configuración
        display_results = results
        if not show_down_hosts:
            display_results = [r for r in results if r.status != 'down' or r.ports]
        
        # Crear tabla
        table = Table(title="Resultados del Escaneo Paralelo")
        table.add_column("Host", style="bold yellow", width=15)
        table.add_column("Estado", justify="center", width=10)
        table.add_column("Puerto", justify="right", width=8)
        table.add_column("Protocolo", width=8)
        table.add_column("Servicio", width=15)
        table.add_column("Versión", width=25)
        table.add_column("Tiempo", justify="right", width=8)
        
        active_hosts = 0
        total_ports = 0
        total_time = 0
        
        for result in display_results:
            if result.status in ['up', 'open']:
                active_hosts += 1
            
            total_time += result.scan_time
            
            # Color del estado
            status_color = {
                'up': '[green]UP[/green]',
                'down': '[red]DOWN[/red]',
                'filtered': '[yellow]FILTERED[/yellow]',
                'error': '[red]ERROR[/red]'
            }.get(result.status, result.status)
            
            if not result.ports:
                table.add_row(
                    result.host,
                    status_color,
                    "-",
                    "-",
                    "Sin puertos abiertos" if result.status == 'up' else result.error or '-',
                    "-",
                    f"{result.scan_time:.1f}s"
                )
            else:
                for i, port in enumerate(result.ports):
                    total_ports += 1
                    
                    # Solo mostrar host en primera fila
                    host_display = result.host if i == 0 else ""
                    status_display = status_color if i == 0 else ""
                    time_display = f"{result.scan_time:.1f}s" if i == 0 else ""
                    
                    # Color del protocolo
                    proto_color = "[cyan]TCP[/cyan]" if port['protocol'] == 'tcp' else "[magenta]UDP[/magenta]"
                    
                    table.add_row(
                        host_display,
                        status_display,
                        str(port['port']),
                        proto_color,
                        f"[green]{port['service']}[/green]",
                        port['version'][:25] if port['version'] else '-',
                        time_display
                    )
        
        self.console.print(table)
        
        # Estadísticas
        avg_time = total_time / len(results) if results else 0
        stats_text = f"""
[bold]Estadísticas del Escaneo Paralelo:[/bold]
• Hosts escaneados: [cyan]{len(results)}[/cyan]
• Hosts activos: [green]{active_hosts}[/green]
• Puertos encontrados: [yellow]{total_ports}[/yellow]
• Tiempo promedio por host: [cyan]{avg_time:.2f}s[/cyan]
• Tiempo total: [cyan]{total_time:.2f}s[/cyan]
        """
        
        self.console.print(stats_text.strip())
    
    def get_statistics(self, results: List[ScanResult]) -> Dict:
        """Obtiene estadísticas del escaneo."""
        stats = {
            'total_hosts': len(results),
            'active_hosts': len([r for r in results if r.status == 'up']),
            'down_hosts': len([r for r in results if r.status == 'down']),
            'error_hosts': len([r for r in results if r.status == 'error']),
            'total_ports': sum(len(r.ports) for r in results),
            'total_time': sum(r.scan_time for r in results),
            'avg_time_per_host': sum(r.scan_time for r in results) / len(results) if results else 0,
            'services_found': {},
            'top_ports': {}
        }
        
        # Contar servicios
        for result in results:
            for port in result.ports:
                service = port.get('service', 'unknown')
                stats['services_found'][service] = stats['services_found'].get(service, 0) + 1
                
                port_num = port.get('port')
                stats['top_ports'][port_num] = stats['top_ports'].get(port_num, 0) + 1
        
        return stats

if __name__ == "__main__":
    # Ejemplo de uso
    scanner = ParallelScanner(max_workers=20)
    
    # Callback de progreso
    def progress_callback(message, progress):
        print(f"Progreso: {message} ({progress:.1f}%)")
    
    scanner.add_progress_callback(progress_callback)
    
    # Escanear red
    network = "192.168.1.1-10"  # Escaneo pequeño para prueba
    results = scanner.scan_network_parallel(network)
    
    # Mostrar resultados
    scanner.display_results(results, show_down_hosts=True)
    
    # Estadísticas
    stats = scanner.get_statistics(results)
    print(f"\nEstadísticas: {stats}")