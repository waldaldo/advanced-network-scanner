#!/usr/bin/env python3
"""
Ejemplos básicos de uso del Advanced Network Scanner.
"""

from scanner_v2 import NetworkScanner
from parallel_scanner import ParallelScanner
from cve_detector import CVEDetector
from alert_system import AlertSystem
from database import ScanDatabase

def example_basic_scan():
    """Ejemplo de escaneo básico."""
    print("🔍 Ejemplo 1: Escaneo Básico")
    print("-" * 40)
    
    # Crear scanner
    scanner = NetworkScanner("config.yaml")
    
    # Escanear red local
    results = scanner.scan_network("127.0.0.1", scan_type="tcp")
    
    print(f"Hosts encontrados: {len(results)}")
    for result in results:
        if result['ports']:
            print(f"Host: {result['host']} - Puertos: {len(result['ports'])}")

def example_parallel_scan():
    """Ejemplo de escaneo paralelo."""
    print("\n⚡ Ejemplo 2: Escaneo Paralelo")
    print("-" * 40)
    
    # Crear scanner paralelo
    scanner = ParallelScanner(max_workers=5)
    
    # Escanear rango pequeño
    results = scanner.scan_network_parallel("127.0.0.1", "tcp")
    
    # Mostrar estadísticas
    stats = scanner.get_statistics(results)
    print(f"Estadísticas: {stats}")

def example_cve_detection():
    """Ejemplo de detección CVE."""
    print("\n🔍 Ejemplo 3: Detección CVE")
    print("-" * 40)
    
    # Crear detector CVE
    detector = CVEDetector()
    
    # Datos de ejemplo
    test_results = [{
        'host': '192.168.1.100',
        'ports': [
            {'service': 'apache', 'version': 'Apache/2.4.49', 'port': 80},
            {'service': 'openssh', 'version': 'OpenSSH_7.4', 'port': 22}
        ]
    }]
    
    # Analizar vulnerabilidades
    report = detector.analyze_scan_results(test_results)
    print(f"CVEs encontrados: {report['total_cves']}")

def example_database_usage():
    """Ejemplo de uso de base de datos."""
    print("\n📊 Ejemplo 4: Base de Datos")
    print("-" * 40)
    
    # Crear conexión a BD
    db = ScanDatabase()
    
    # Obtener estadísticas
    stats = db.get_statistics()
    print(f"Estadísticas BD: {stats}")
    
    # Obtener historial
    history = db.get_scan_history(limit=5)
    print(f"Escaneos recientes: {len(history)}")

def example_alert_system():
    """Ejemplo del sistema de alertas."""
    print("\n📢 Ejemplo 5: Sistema de Alertas")
    print("-" * 40)
    
    # Configuración básica
    config = {
        'notifications': {
            'email': {'enabled': False}
        }
    }
    
    # Crear sistema de alertas
    alert_system = AlertSystem(config)
    
    # Obtener reglas activas
    rules = alert_system.get_active_rules()
    print(f"Reglas de alerta activas: {len(rules)}")

def example_configuration():
    """Ejemplo de configuración."""
    print("\n⚙️ Ejemplo 6: Configuración")
    print("-" * 40)
    
    import yaml
    
    # Ejemplo de configuración personalizada
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
    
    # Guardar configuración
    with open('custom_config.yaml', 'w') as f:
        yaml.dump(custom_config, f, indent=2)
    
    print("Configuración personalizada creada: custom_config.yaml")

def main():
    """Ejecutar todos los ejemplos."""
    print("🛡️ Advanced Network Scanner - Ejemplos de Uso")
    print("=" * 50)
    
    try:
        example_basic_scan()
        example_parallel_scan()
        example_cve_detection()
        example_database_usage()
        example_alert_system()
        example_configuration()
        
        print("\n✅ Todos los ejemplos ejecutados correctamente")
        print("\n💡 Para más ejemplos, revisa la documentación:")
        print("   - README.md")
        print("   - docs/")
        print("   - python startup.py help")
        
    except Exception as e:
        print(f"\n❌ Error ejecutando ejemplos: {e}")
        print("💡 Asegúrate de tener todas las dependencias instaladas")

if __name__ == "__main__":
    main()