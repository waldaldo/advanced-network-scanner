#!/usr/bin/env python3
"""
Script para configurar entorno de desarrollo del Advanced Network Scanner.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Verifica que la versión de Python sea compatible."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8+ requerido")
        print(f"   Versión actual: {version.major}.{version.minor}.{version.micro}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
    return True

def check_nmap():
    """Verifica que Nmap esté instalado."""
    try:
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"✅ {version_line}")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    print("❌ Nmap no encontrado")
    print_nmap_install_instructions()
    return False

def print_nmap_install_instructions():
    """Muestra instrucciones para instalar Nmap."""
    system = platform.system().lower()
    
    print("\n📦 Instrucciones para instalar Nmap:")
    
    if 'linux' in system:
        print("   # Ubuntu/Debian:")
        print("   sudo apt update && sudo apt install nmap")
        print("   # CentOS/RHEL/Fedora:")
        print("   sudo dnf install nmap")
    elif 'darwin' in system:  # macOS
        print("   # macOS (Homebrew):")
        print("   brew install nmap")
    elif 'windows' in system:
        print("   # Windows:")
        print("   Descargar desde: https://nmap.org/download.html")
    
    print()

def create_virtual_environment():
    """Crea un entorno virtual si no existe."""
    venv_path = Path("venv")
    
    if venv_path.exists():
        print("✅ Virtual environment ya existe")
        return True
    
    print("📦 Creando virtual environment...")
    try:
        subprocess.run([sys.executable, '-m', 'venv', 'venv'], 
                      check=True, timeout=60)
        print("✅ Virtual environment creado")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"❌ Error creando virtual environment: {e}")
        return False

def get_activation_command():
    """Obtiene el comando para activar el entorno virtual."""
    system = platform.system().lower()
    
    if 'windows' in system:
        return "venv\\Scripts\\activate"
    else:
        return "source venv/bin/activate"

def install_dependencies():
    """Instala las dependencias del proyecto."""
    print("📦 Instalando dependencias...")
    
    # Determinar el ejecutable de pip en el venv
    system = platform.system().lower()
    if 'windows' in system:
        pip_path = "venv/Scripts/pip"
    else:
        pip_path = "venv/bin/pip"
    
    try:
        # Instalar dependencias principales
        subprocess.run([pip_path, 'install', '-r', 'requirements.txt'], 
                      check=True, timeout=300)
        print("✅ Dependencias principales instaladas")
        
        # Crear requirements-dev.txt si no existe
        dev_requirements = [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0", 
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
            "isort>=5.10.0"
        ]
        
        dev_req_path = Path("requirements-dev.txt")
        if not dev_req_path.exists():
            with open(dev_req_path, 'w') as f:
                for req in dev_requirements:
                    f.write(f"{req}\n")
            print("📝 requirements-dev.txt creado")
        
        # Instalar dependencias de desarrollo
        subprocess.run([pip_path, 'install', '-r', 'requirements-dev.txt'], 
                      check=True, timeout=180)
        print("✅ Dependencias de desarrollo instaladas")
        
        return True
        
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"❌ Error instalando dependencias: {e}")
        return False

def create_dev_files():
    """Crea archivos útiles para desarrollo."""
    
    # Crear .env de ejemplo
    env_example = """# Configuración de desarrollo
FLASK_ENV=development
FLASK_DEBUG=1
SCANNER_CONFIG_FILE=config.yaml
SCANNER_LOG_LEVEL=DEBUG
"""
    
    env_path = Path(".env.example")
    if not env_path.exists():
        with open(env_path, 'w') as f:
            f.write(env_example)
        print("📝 .env.example creado")
    
    # Crear pytest.ini
    pytest_config = """[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    unit: marks tests as unit tests
"""
    
    pytest_path = Path("pytest.ini")
    if not pytest_path.exists():
        with open(pytest_path, 'w') as f:
            f.write(pytest_config)
        print("📝 pytest.ini creado")
    
    # Crear setup.cfg para flake8
    setup_cfg = """[flake8]
max-line-length = 88
extend-ignore = E203, W503
exclude = venv/, .git/, __pycache__/

[mypy]
python_version = 3.8
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True

[isort]
profile = black
multi_line_output = 3
"""
    
    setup_path = Path("setup.cfg")
    if not setup_path.exists():
        with open(setup_path, 'w') as f:
            f.write(setup_cfg)
        print("📝 setup.cfg creado")

def run_initial_tests():
    """Ejecuta tests básicos para verificar la instalación."""
    print("🧪 Ejecutando tests básicos...")
    
    system = platform.system().lower()
    if 'windows' in system:
        python_path = "venv/Scripts/python"
    else:
        python_path = "venv/bin/python"
    
    try:
        # Test básico de importación
        test_script = '''
import sys
try:
    import nmap
    import yaml
    import rich
    import flask
    print("✅ Todas las dependencias principales importadas correctamente")
    sys.exit(0)
except ImportError as e:
    print(f"❌ Error importando dependencia: {e}")
    sys.exit(1)
'''
        
        result = subprocess.run([python_path, '-c', test_script], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(result.stdout.strip())
            return True
        else:
            print(result.stderr.strip())
            return False
            
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"❌ Error ejecutando tests básicos: {e}")
        return False

def print_next_steps():
    """Muestra los próximos pasos para el desarrollador."""
    activation_cmd = get_activation_command()
    
    print("\n🎉 Configuración de desarrollo completada!")
    print("\n📝 Próximos pasos:")
    print(f"   1. Activar entorno virtual: {activation_cmd}")
    print("   2. Verificar instalación: python startup.py status")
    print("   3. Ejecutar tests: pytest tests/")
    print("   4. Iniciar desarrollo: python startup.py web")
    
    print("\n🛠️ Comandos útiles para desarrollo:")
    print("   • python startup.py help     # Ayuda completa")
    print("   • black .                    # Formatear código")
    print("   • flake8 .                   # Linter")
    print("   • pytest --cov=.            # Tests con coverage")
    print("   • python examples/basic_usage.py  # Ejemplos")

def main():
    """Función principal."""
    print("🛠️ Advanced Network Scanner - Setup de Desarrollo")
    print("=" * 55)
    
    # Verificaciones previas
    if not check_python_version():
        sys.exit(1)
    
    if not check_nmap():
        print("⚠️  Continúa sin Nmap (funcionalidad limitada)")
    
    # Configuración del entorno
    steps = [
        ("Crear virtual environment", create_virtual_environment),
        ("Instalar dependencias", install_dependencies),
        ("Crear archivos de desarrollo", create_dev_files),
        ("Ejecutar tests básicos", run_initial_tests)
    ]
    
    for step_name, step_func in steps:
        print(f"\n📋 {step_name}...")
        if not step_func():
            print(f"❌ Falló: {step_name}")
            sys.exit(1)
    
    print_next_steps()

if __name__ == "__main__":
    main()