# scanner_mejorado.py
import nmap
import sys
import argparse
import json
import csv
import os
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner

def scan_network(network, output_file=None, output_format=None):
    """
    Escanea la red en busca de hosts activos y sus puertos abiertos,
    mostrando los resultados en una tabla y opcionalmente guardándolos en un archivo.
    """
    console = Console()
    nm = nmap.PortScanner()
    
    spinner = Spinner("dots", text=" Escaneando la red... esto puede tardar unos minutos.")
    with Live(spinner, console=console, transient=True, vertical_overflow="visible"):
        try:
            # -sV: Detección de versión de servicio
            # -T4: Escaneo más rápido
            # --open: Muestra solo hosts con puertos abiertos
            # -O: Detección de sistema operativo (requiere sudo)
            # -sC: Ejecuta scripts por defecto (útil para más info)
            arguments = '-sV -T4 --open'
            if sys.platform != 'win32' and os.geteuid() == 0:
                arguments += ' -O' # Añadir detección de OS si se ejecuta como root en Linux/macOS
                
            nm.scan(hosts=network, arguments=arguments)
        except nmap.PortScannerError:
            console.print("[bold red]Error: Nmap no está instalado o no se encuentra en el PATH.[/bold red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Ocurrió un error inesperado: {e}[/bold red]")
            sys.exit(1)

    results = []
    table = Table(title=f"Resultados del Escaneo para la Red [bold cyan]{network}[/bold cyan]", show_header=True, header_style="bold magenta")
    table.add_column("Host", style="dim", width=15)
    table.add_column("MAC Address", width=18)
    table.add_column("Puerto", justify="right")
    table.add_column("Servicio")
    table.add_column("Versión")
    table.add_column("Estado", justify="center")

    for host in nm.all_hosts():
        host_data = {
            'host': host,
            'status': nm[host].state(),
            'mac': nm[host]['addresses'].get('mac', 'N/A'),
            'ports': []
        }
        
        if not nm[host].all_protocols():
            table.add_row(host, host_data['mac'], "[italic]N/A[/italic]", "[italic]No open ports found[/italic]", "", f"[green]{host_data['status']}[/green]")
        
        for proto in nm[host].all_protocols():
            lport = sorted(nm[host][proto].keys())
            for port in lport:
                service_info = nm[host][proto][port]
                port_data = {
                    'port': port,
                    'service': service_info.get('name', 'unknown'),
                    'version': f"{service_info.get('product', '')} {service_info.get('version', '')}".strip()
                }
                host_data['ports'].append(port_data)
                table.add_row(
                    f"[bold yellow]{host}[/bold yellow]",
                    host_data['mac'],
                    f"[cyan]{port}[/cyan]",
                    f"[green]{port_data['service']}[/green]",
                    port_data['version'],
                    f"[green]{host_data['status']}[/green]"
                )
        results.append(host_data)

    console.print(table)
    console.print(f"\n[bold]Resumen del escaneo:[/bold]")
    console.print(f"- Total de hosts escaneados: [bold cyan]{len(nm.all_hosts())}[/bold cyan]")
    
    if output_file and output_format:
        save_results(results, output_file, output_format, console)

def save_results(results, filename, format, console):
    """Guarda los resultados en el formato especificado."""
    try:
        with open(filename, 'w', newline='') as f:
            if format == 'json':
                json.dump(results, f, indent=4)
            elif format == 'csv':
                writer = csv.writer(f)
                writer.writerow(['Host', 'MAC Address', 'Port', 'Service', 'Version'])
                for host in results:
                    for port_info in host['ports']:
                        writer.writerow([host['host'], host['mac'], port_info['port'], port_info['service'], port_info['version']])
            elif format == 'txt':
                for host in results:
                    f.write(f"Host: {host['host']} (MAC: {host['mac']}) - Status: {host['status']}\n")
                    for port_info in host['ports']:
                        f.write(f"  - Port: {port_info['port']}\n")
                        f.write(f"    Service: {port_info['service']}\n")
                        f.write(f"    Version: {port_info['version']}\n")
                    f.write("\n")
        console.print(f"\n[bold green]Resultados guardados exitosamente en '{filename}'[/bold green]")
    except IOError as e:
        console.print(f"\n[bold red]Error al guardar el archivo: {e}[/bold red]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Escáner de red con Nmap. Muestra hosts activos, puertos abiertos, servicios y versiones.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("network", help="La red a escanear (ej. '192.168.1.0/24' o '192.168.1.1-100').")
    parser.add_argument("-o", "--output", help="Nombre del archivo para guardar los resultados.")
    parser.add_argument("-f", "--format", choices=['txt', 'csv', 'json'], help="Formato del archivo de salida (requerido si se usa --output).")

    args = parser.parse_args()

    if args.output and not args.format:
        parser.error("--format es requerido cuando se especifica --output.")

    scan_network(args.network, args.output, args.format)