# 🤝 Contributing to Advanced Network Scanner

¡Gracias por tu interés en contribuir a Advanced Network Scanner! Este documento proporciona guías y estándares para contribuidores.

## 📋 Tabla de Contenidos

- [Code of Conduct](#-code-of-conduct)
- [Cómo Contribuir](#-cómo-contribuir)  
- [Reportar Bugs](#-reportar-bugs)
- [Sugerir Funcionalidades](#-sugerir-funcionalidades)
- [Desarrollo](#-desarrollo)
- [Pull Requests](#-pull-requests)
- [Estándares de Código](#-estándares-de-código)
- [Testing](#-testing)
- [Documentación](#-documentación)

---

## 📜 Code of Conduct

Este proyecto adhiere al Contributor Covenant [code of conduct](CODE_OF_CONDUCT.md). Al participar, se espera que mantengas este código. Por favor reporta comportamiento inaceptable a [project-email@domain.com].

### Principios Fundamentales

- **Respeto**: Trata a todos con respeto y profesionalismo
- **Inclusión**: Bienvenimos contribuidores de todos los backgrounds
- **Colaboración**: Trabajamos juntos hacia objetivos comunes
- **Ética**: Solo contribuciones para uso legítimo de ciberseguridad

---

## 🎯 Cómo Contribuir

Hay muchas maneras de contribuir a este proyecto:

### 🐛 Reportar Issues
- Bugs y problemas técnicos
- Vulnerabilidades de seguridad (usar disclosure responsable)
- Mejoras de documentación
- Sugerencias de funcionalidades

### 💻 Contribuir Código
- Bug fixes
- Nuevas funcionalidades
- Optimizaciones de rendimiento  
- Tests adicionales
- Mejoras de UI/UX

### 📚 Documentación
- Mejoras al README
- Documentación de API
- Tutoriales y ejemplos
- Traducción a otros idiomas

### 🧪 Testing
- Reportar resultados de testing
- Crear nuevos test cases
- Testing en diferentes plataformas
- Performance benchmarking

---

## 🐛 Reportar Bugs

### Antes de Reportar
1. **Busca issues existentes** para evitar duplicados
2. **Verifica la versión** que estás usando
3. **Intenta reproducir** el problema consistentemente
4. **Recopila información** del entorno

### Template de Bug Report

```markdown
**Descripción del Bug**
Una descripción clara y concisa del bug.

**Para Reproducir**
Pasos para reproducir el comportamiento:
1. Ejecutar comando '...'
2. Con configuración '...'
3. Ver error

**Comportamiento Esperado**
Descripción clara de lo que esperabas que pasara.

**Comportamiento Actual**
Lo que realmente pasó.

**Screenshots/Logs**
Si aplica, añade screenshots o logs del error.

**Entorno (completa la información):**
- OS: [e.g. Ubuntu 20.04]
- Python Version: [e.g. 3.9.5]
- Scanner Version: [e.g. 2.0.0]
- Nmap Version: [e.g. 7.80]

**Información Adicional**
Cualquier otro contexto sobre el problema.
```

### 🚨 Reportar Vulnerabilidades de Seguridad

**NO** reportes vulnerabilidades de seguridad via issues públicos.

En su lugar:
1. Email a [security@project.com] con detalles
2. Usa GPG key si está disponible
3. Incluye pasos para reproducir
4. Permite tiempo razonable para fix antes de disclosure público

---

## 💡 Sugerir Funcionalidades

### Template de Feature Request

```markdown
**¿La funcionalidad está relacionada a un problema?**
Descripción clara del problema: "Estoy siempre frustrado cuando [...]"

**Describe la solución que te gustaría**
Descripción clara y concisa de lo que quieres que pase.

**Describe alternativas consideradas**
Descripción clara de cualquier solución alternativa que hayas considerado.

**Casos de Uso**
Ejemplos específicos de cómo usarías esta funcionalidad.

**Información Adicional**
Cualquier otro contexto o screenshots sobre el feature request.
```

---

## 🛠️ Desarrollo

### Configuración del Entorno

```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/advanced-network-scanner.git
cd advanced-network-scanner

# Crear virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate     # Windows

# Instalar dependencias
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Dependencias de desarrollo

# Verificar instalación
python startup.py status
```

### Estructura de Desarrollo

```
advanced-network-scanner/
├── core/                   # Módulos principales
├── web/                    # Dashboard web
├── api/                    # API REST
├── tests/                  # Tests automatizados
├── docs/                   # Documentación
├── scripts/                # Scripts de utilidad
└── examples/               # Ejemplos de uso
```

### Branch Strategy

- `main` - Producción estable
- `develop` - Desarrollo activo
- `feature/feature-name` - Nuevas funcionalidades
- `bugfix/bug-description` - Bug fixes
- `hotfix/critical-fix` - Fixes críticos a producción

---

## 📬 Pull Requests

### Checklist antes de PR

- [ ] Code sigue las convenciones del proyecto
- [ ] Tests pasan (`python -m pytest`)
- [ ] Linter pasa (`flake8`, `black`)
- [ ] Documentación actualizada si es necesario
- [ ] CHANGELOG.md actualizado
- [ ] Issue relacionado linkead

### Template de Pull Request

```markdown
## Descripción
Descripción clara de los cambios realizados.

## Tipo de Cambio
- [ ] Bug fix (cambio que arregla un issue)
- [ ] Nueva funcionalidad (cambio que añade funcionalidad)
- [ ] Breaking change (fix o feature que causa cambios incompatibles)
- [ ] Documentación

## ¿Cómo Ha Sido Testado?
Describe los tests que ejecutaste para verificar tus cambios.

## Checklist:
- [ ] Mi código sigue las convenciones de este proyecto
- [ ] He realizado self-review de mi código
- [ ] He comentado código difícil de entender
- [ ] He actualizado la documentación correspondiente
- [ ] Mis cambios no generan warnings nuevos
- [ ] He añadido tests que prueban que mi fix es efectivo
- [ ] Tests nuevos y existentes pasan localmente
```

### Proceso de Review

1. **Automated Checks**: CI/CD ejecuta tests automáticos
2. **Code Review**: Maintainers revisan el código
3. **Testing**: Funcionalidad es testada
4. **Merge**: Una vez aprobado, se hace merge

---

## 📏 Estándares de Código

### Python Style Guide

Seguimos [PEP 8](https://www.python.org/dev/peps/pep-0008/) con algunas modificaciones:

```python
# Imports
import os
import sys
from typing import Dict, List, Optional

import nmap
import yaml
from rich.console import Console

# Constants
MAX_WORKERS = 50
DEFAULT_TIMEOUT = 300

# Classes
class NetworkScanner:
    """Network scanner with advanced capabilities.
    
    Attributes:
        config: Scanner configuration
        console: Rich console for output
    """
    
    def __init__(self, config: Dict):
        """Initialize scanner with configuration."""
        self.config = config
        self.console = Console()
    
    def scan_network(self, network: str) -> List[Dict]:
        """Scan network and return results.
        
        Args:
            network: Network range to scan
            
        Returns:
            List of scan results
            
        Raises:
            ValueError: If network format is invalid
        """
        pass
```

### Naming Conventions

- **Classes**: PascalCase (`NetworkScanner`)
- **Functions**: snake_case (`scan_network`)
- **Variables**: snake_case (`max_workers`)
- **Constants**: UPPER_SNAKE_CASE (`MAX_WORKERS`)
- **Files**: snake_case (`network_scanner.py`)

### Code Quality Tools

```bash
# Linting
flake8 .
pylint src/

# Formatting
black .
isort .

# Type checking
mypy src/
```

---

## 🧪 Testing

### Testing Strategy

- **Unit Tests**: Funciones individuales
- **Integration Tests**: Componentes trabajando juntos
- **End-to-End Tests**: Workflows completos
- **Performance Tests**: Benchmarks de rendimiento

### Escribir Tests

```python
import pytest
from unittest.mock import patch, MagicMock

from scanner_v2 import NetworkScanner

class TestNetworkScanner:
    """Test cases for NetworkScanner class."""
    
    def setup_method(self):
        """Setup for each test method."""
        self.config = {'scan': {'timeout': 300}}
        self.scanner = NetworkScanner(self.config)
    
    def test_scan_network_valid_input(self):
        """Test scanning with valid network input."""
        with patch('nmap.PortScanner') as mock_nmap:
            mock_nm = MagicMock()
            mock_nmap.return_value = mock_nm
            mock_nm.all_hosts.return_value = ['192.168.1.1']
            
            result = self.scanner.scan_network('192.168.1.0/24')
            
            assert isinstance(result, list)
            mock_nm.scan.assert_called_once()
    
    def test_scan_network_invalid_input(self):
        """Test scanning with invalid network input."""
        with pytest.raises(ValueError):
            self.scanner.scan_network('invalid-network')
```

### Ejecutar Tests

```bash
# Todos los tests
python -m pytest

# Tests específicos
python -m pytest tests/test_scanner.py

# Con coverage
python -m pytest --cov=src tests/

# Tests de integración
python -m pytest tests/integration/

# Tests de performance
python -m pytest tests/performance/ --benchmark-only
```

---

## 📖 Documentación

### Docstrings

Usamos formato Google para docstrings:

```python
def scan_network(self, network: str, scan_type: str = 'tcp') -> List[Dict]:
    """Scan a network for active hosts and services.
    
    Args:
        network: Network range in CIDR notation (e.g., '192.168.1.0/24')
        scan_type: Type of scan to perform ('tcp', 'udp', or 'both')
        
    Returns:
        List of dictionaries containing scan results for each host.
        Each dictionary contains:
            - host: IP address of the host
            - status: Host status ('up' or 'down')
            - ports: List of open ports with service information
            
    Raises:
        ValueError: If network format is invalid
        ScanError: If scan operation fails
        
    Example:
        >>> scanner = NetworkScanner(config)
        >>> results = scanner.scan_network('192.168.1.0/24')
        >>> print(f"Found {len(results)} hosts")
    """
```

### Comentarios

```python
# TODO: Add IPv6 support
# FIXME: Handle edge case where nmap returns empty results
# NOTE: This function assumes nmap is installed and accessible

# Complex logic explanation
# We use threading here because nmap scanning can be I/O bound
# when scanning large networks. Each thread handles a subnet.
with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
    futures = []
    for subnet in subnets:
        future = executor.submit(self._scan_subnet, subnet)
        futures.append(future)
```

---

## 🎯 Contribución Específica por Área

### 🔍 Core Scanner
- Mejoras de algoritmos de escaneo
- Optimizaciones de rendimiento
- Nuevos tipos de escaneo
- Integración con herramientas adicionales

### 🌐 Web Dashboard
- Mejoras de UI/UX
- Nuevas visualizaciones
- Responsive design
- Accessibility improvements

### 🚀 API REST
- Nuevos endpoints
- Mejoras de documentación
- Rate limiting
- Authentication improvements

### 🛡️ Security Features
- Detección de vulnerabilidades
- Nuevas reglas de alertas
- Integración con threat intelligence
- Compliance frameworks

---

## 🏆 Recognition

Los contribuidores serán reconocidos en:

- README.md contributors section
- CHANGELOG.md para cambios específicos
- Release notes
- Hall of Fame para contribuidores mayores

---

## 📞 Contacto

- **GitHub Issues**: Para bugs y features
- **Discussions**: Para preguntas generales  
- **Email**: [maintainers@project.com] para temas privados
- **Discord/Slack**: [Invite link] para chat en tiempo real

---

## 📚 Recursos Adicionales

- [Development Setup Guide](docs/development.md)
- [Architecture Overview](docs/architecture.md)
- [API Documentation](docs/api.md)
- [Security Guidelines](docs/security.md)

---

¡Gracias por contribuir a Advanced Network Scanner! 🎉

*Tu contribución hace que la ciberseguridad sea más accesible para todos.*