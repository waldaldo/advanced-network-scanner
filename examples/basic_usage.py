#!/usr/bin/env python3
"""
Ejemplos de uso del Scanner de Red.
"""

from scanner_v2 import NetworkScanner
from parallel_scanner import ParallelScanner
from cve_detector import CVEDetector
from alert_system import AlertSystem
from database import ScanDatabase


def example_basic_scan():
    """Ejemplo de escaneo basico."""
    print("Ejemplo 1: Escaneo Basico")
    print("-" * 40)

    scanner = NetworkScanner("config.yaml")
    results = scanner.scan_network("127.0.0.1", scan_type="tcp")

    print(f"Hosts encontrados: {len(results)}")
    for result in results:
        if result['ports']:
            print(f"Host: {result['host']} - Puertos: {len(result['ports'])}")


def example_parallel_scan():
    """Ejemplo de escaneo paralelo."""
    print("\nEjemplo 2: Escaneo Paralelo")
    print("-" * 40)

    scanner = ParallelScanner(max_workers=5)
    results = scanner.scan_network_parallel("127.0.0.1", "tcp")

    stats = scanner.get_statistics(results)
    print(f"Estadisticas: {stats}")


def example_cve_detection():
    """Ejemplo de deteccion CVE."""
    print("\nEjemplo 3: Deteccion CVE")
    print("-" * 40)

    detector = CVEDetector()

    test_results = [{
        'host': '192.168.1.100',
        'ports': [
            {'service': 'apache', 'version': 'Apache/2.4.49', 'port': 80},
            {'service': 'openssh', 'version': 'OpenSSH_7.4', 'port': 22}
        ]
    }]

    report = detector.analyze_scan_results(test_results)
    print(f"CVEs encontrados: {report['total_cves']}")


def example_database_usage():
    """Ejemplo de uso de base de datos."""
    print("\nEjemplo 4: Base de Datos")
    print("-" * 40)

    db = ScanDatabase()
    stats = db.get_statistics()
    print(f"Estadisticas BD: {stats}")

    history = db.get_scan_history(limit=5)
    print(f"Escaneos recientes: {len(history)}")


def example_alert_system():
    """Ejemplo del sistema de alertas."""
    print("\nEjemplo 5: Sistema de Alertas")
    print("-" * 40)

    config = {'notifications': {'email': {'enabled': False}}}
    alert_system = AlertSystem(config)

    rules = alert_system.get_active_rules()
    print(f"Reglas de alerta activas: {len(rules)}")


def example_configuration():
    """Ejemplo de configuracion."""
    print("\nEjemplo 6: Configuracion")
    print("-" * 40)

    import yaml

    custom_config = {
        'scan': {
            'default_scan_type': 'tcp',
            'use_nse_scripts': True,
            'timeout': 120
        },
        'parallel': {
            'max_workers': 10,
            'enabled': True
        },
        'database': {
            'enabled': True,
            'retention_days': 30
        }
    }

    with open('custom_config.yaml', 'w') as f:
        yaml.dump(custom_config, f, indent=2)

    print("Configuracion guardada en: custom_config.yaml")


def main():
    """Ejecutar todos los ejemplos."""
    print("Advanced Network Scanner - Ejemplos de Uso")
    print("=" * 50)

    try:
        example_basic_scan()
        example_parallel_scan()
        example_cve_detection()
        example_database_usage()
        example_alert_system()
        example_configuration()

        print("\nTodos los ejemplos ejecutados correctamente")

    except Exception as e:
        print(f"\nError ejecutando ejemplos: {e}")
        print("Asegurate de tener todas las dependencias instaladas: pip install -r requirements.txt")


if __name__ == "__main__":
    main()
