# 🛡️ Escáner Avanzado de Red

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Nmap](https://img.shields.io/badge/Nmap-Requerido-red.svg)
![Licencia](https://img.shields.io/badge/Licencia-MIT-green.svg)
![Estado](https://img.shields.io/badge/Estado-Producción-brightgreen.svg)

*Una plataforma completa de análisis de red y ciberseguridad defensiva*

[Características](#-características) •
[Instalación](#-instalación) •
[Uso](#-uso-rápido) •
[API](#-api-rest) •
[Documentación](#-documentación)

</div>

---

## 🎯 Descripción

**Escáner Avanzado de Red** es una plataforma completa de ciberseguridad defensiva que combina escaneo de red, detección de vulnerabilidades, análisis de seguridad y monitoreo continuo. Desarrollado con Python y basado en Nmap, ofrece tanto interfaces de línea de comandos como web para diferentes necesidades operacionales.

### ⚡ Características Principales

- 🔍 **Escaneo Avanzado**: TCP, UDP, scripts NSE y detección de SO
- ⚡ **Paralelización**: Escaneos concurrentes para redes grandes  
- 🌐 **Panel Web**: Interfaz gráfica con estadísticas en tiempo real
- 🚀 **API REST**: Integración con otros sistemas de seguridad
- 🔍 **Detector CVE**: Base de conocimiento local + API NVD
- 📢 **Sistema de Alertas**: Email, Slack, webhooks automáticos
- 📊 **Análisis Histórico**: Base de datos SQLite con comparaciones
- 🎛️ **Gestión Centralizada**: Administrador de inicio unificado

## 🏗️ Arquitectura

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Escáner CLI    │    │   Panel Web      │    │ Servidor API    │
│   (Puerto CLI)  │    │  (Puerto 5000)   │    │  (Puerto 5001)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
              ┌──────────────────────────────────┐
              │      Motor Principal             │
              ├──────────────────────────────────┤
              │  • Escáner Paralelo              │
              │  • Detector CVE                  │
              │  • Sistema Alertas               │
              │  • Analizador NSE                │
              │  • Base de Datos SQLite          │
              └──────────────────────────────────┘
```

## 🚀 Instalación Rápida

### Requisitos Previos

- **Python 3.8+**
- **Nmap** instalado y accesible desde PATH
- **Permisos sudo** (opcional, para detección de SO)

### Instalación

```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/escaner-avanzado-red.git
cd escaner-avanzado-red

# Instalar dependencias
pip install -r requirements.txt

# Verificar instalación
python startup.py status
```

### Instalación de Nmap

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap

# CentOS/RHEL/Fedora
sudo dnf install nmap

# macOS (Homebrew)
brew install nmap

# Verificar instalación
nmap --version
```

## 💻 Uso Rápido

### 🎛️ Administrador de Inicio (Recomendado)

```bash
# Ver estado del sistema
python startup.py status

# Escaneo básico
python startup.py scan 192.168.1.0/24

# Escaneo avanzado
python startup.py scan 10.0.0.0/16 -t both -o resultados -f json

# Panel web
python startup.py web

# Servidor API REST
python startup.py api

# Todos los servicios
python startup.py all

# Ayuda completa
python startup.py help
```

### 🔍 Escáner CLI Directo

```bash
# Escaneo TCP con scripts NSE
./scanner_v2.py 192.168.1.0/24

# Escaneo UDP rápido
./scanner_v2.py 192.168.1.0/24 -t udp

# Escaneo completo (TCP + UDP)
./scanner_v2.py 192.168.1.0/24 -t both --no-nse

# Ver historial
./scanner_v2.py --history

# Estadísticas
./scanner_v2.py --stats
```

## 🌐 Panel Web

El panel proporciona una interfaz visual completa para monitoreo y análisis:

**Características:**
- 📊 **Gráficos Interactivos**: Línea de tiempo de actividad, distribución de alertas
- 📈 **Estadísticas en Tiempo Real**: Hosts, vulnerabilidades, servicios
- 🔍 **Tablas Dinámicas**: Escaneos recientes, alertas activas
- 📱 **Diseño Responsivo**: Compatible con dispositivos móviles

**Acceso:** http://127.0.0.1:5000

## 🚀 API REST

API completa para integración con sistemas externos:

### Endpoints Principales

```bash
# Información de la API
GET /api/v1/info

# Gestión de escaneos
POST /api/v1/scans                    # Crear escaneo
GET  /api/v1/scans                    # Listar escaneos
GET  /api/v1/scans/{id}               # Detalles de escaneo
GET  /api/v1/scans/{id}/status        # Estado de escaneo
POST /api/v1/scans/{id}/stop          # Detener escaneo

# Gestión de alertas
GET  /api/v1/alerts                   # Listar alertas
GET  /api/v1/alerts/{id}              # Detalles de alerta
POST /api/v1/alerts/{id}/acknowledge  # Reconocer alerta

# Datos del sistema
GET /api/v1/statistics               # Estadísticas generales
GET /api/v1/hosts                    # Hosts descubiertos
GET /api/v1/vulnerabilities          # Vulnerabilidades detectadas
```

### Ejemplo de Uso

```bash
# Crear escaneo asíncrono
curl -X POST http://127.0.0.1:5001/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "network": "192.168.1.0/24",
    "scan_type": "tcp",
    "use_nse": true
  }'

# Verificar estado
curl http://127.0.0.1:5001/api/v1/scans/scan_123456789/status

# Obtener resultados
curl http://127.0.0.1:5001/api/v1/scans/scan_123456789
```

## ⚙️ Configuración

### Archivo config.yaml

```yaml
# Configuración de escaneo
scan:
  default_scan_type: "tcp"
  use_nse_scripts: true
  nse_scripts: ["vuln", "safe", "default"]
  os_detection: true

# Paralelización
parallel:
  max_workers: 20
  enabled: true
  host_timeout: 60

# Base de datos
database:
  enabled: true
  retention_days: 90

# Alertas
alerts:
  enabled: true
  critical_services: ["telnet", "ftp"]
  critical_ports: [21, 23, 445, 3389]

# Notificaciones
notifications:
  email:
    enabled: false
    smtp_server: "smtp.gmail.com"
    recipients: ["admin@empresa.com"]
  
  slack:
    enabled: false
    webhook_url: "https://hooks.slack.com/..."

# Seguridad
security:
  api_key_required: false
  api_key: "tu-clave-api-segura"
```

## 🔒 Características de Seguridad

### Detección de Vulnerabilidades
- **Base CVE Local**: Conocimiento de vulnerabilidades críticas
- **Integración NVD**: Consulta automática a la base nacional
- **Análisis NSE**: Scripts de Nmap para detección avanzada
- **Puntuación CVSS**: Clasificación automática por severidad

### Sistema de Alertas
- **Reglas Configurables**: Condiciones personalizables
- **Múltiples Canales**: Email, Slack, webhooks
- **Escalamiento**: Por severidad y tipo de amenaza
- **Historial Completo**: Auditoría de todas las alertas

### Análisis de Servicios
- **Identificación**: Identificación de servicios y versiones  
- **Protocolo Inseguro**: Detección automática (Telnet, FTP, etc.)
- **Configuración Débil**: Análisis SSL/TLS, credenciales por defecto
- **Superficie de Ataque**: Mapeo completo de puertos expuestos

## 📊 Casos de Uso

### 🏢 Empresarial
- **Auditorías de Red**: Escaneos programados y reportes
- **Monitoreo Continuo**: Panel para equipos de seguridad  
- **Gestión de Vulnerabilidades**: Seguimiento y remediación
- **Cumplimiento**: Reportes para auditorías y certificaciones

### 🔬 Investigación
- **Análisis Forense**: Investigación de incidentes de red
- **Búsqueda de Amenazas**: Búsqueda proactiva de amenazas
- **Pruebas de Penetración**: Reconocimiento autorizado de infraestructura
- **Educación**: Laboratorios de ciberseguridad

### 🛡️ Defensivo
- **Detección de Intrusos**: Identificación de hosts no autorizados
- **Cambio de Configuración**: Monitoreo de modificaciones
- **Endurecimiento**: Validación de configuraciones seguras
- **Respuesta a Incidentes**: Análisis rápido durante incidentes

## 🧪 Pruebas

```bash
# Ejecutar pruebas unitarias
python -m pytest tests/

# Pruebas de integración
python -m pytest tests/integration/

# Pruebas de cobertura
python -m pytest --cov=scanner tests/

# Pruebas de rendimiento
python tests/performance_test.py
```

## 📚 Documentación

### Estructura del Proyecto

```
escaner-avanzado-red/
├── 📁 core/                   # Módulos principales
│   ├── scanner_v2.py          # Escáner CLI principal
│   ├── parallel_scanner.py    # Motor paralelo
│   ├── cve_detector.py        # Detector CVE
│   ├── alert_system.py        # Sistema alertas
│   └── nse_analyzer.py        # Analizador NSE
├── 📁 web/                    # Panel web
│   ├── web_dashboard.py       # Aplicación Flask
│   └── templates/             # Plantillas HTML
├── 📁 api/                    # API REST
│   └── api_server.py          # Servidor API
├── 📁 config/                 # Configuraciones
│   └── config.yaml            # Configuración principal
├── 📁 docs/                   # Documentación
├── 📁 tests/                  # Pruebas automatizadas
├── startup.py                 # Gestor principal
└── requirements.txt           # Dependencias
```

### Componentes Principales

| Componente | Descripción | Puerto |
|------------|-------------|--------|
| `scanner_v2.py` | Escáner CLI con funciones avanzadas | - |
| `web_dashboard.py` | Panel web interactivo | 5000 |
| `api_server.py` | API REST para integraciones | 5001 |
| `parallel_scanner.py` | Motor de escaneo paralelo | - |
| `cve_detector.py` | Detector de vulnerabilidades | - |
| `alert_system.py` | Sistema de alertas | - |

## 🤝 Contribución

¡Las contribuciones son bienvenidas! Por favor:

1. Haz Fork del repositorio
2. Crea una rama feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)  
5. Crea un Pull Request

Ver [CONTRIBUTING.md](CONTRIBUTING.md) para más detalles.

## 📋 Hoja de Ruta

Ver [TODO.md](TODO.md) para la hoja de ruta completa de funcionalidades futuras.

### Próximas Características

- 🐳 **Contenedorización**: Docker y Kubernetes
- ☁️ **Integración Cloud**: AWS, Azure, GCP
- 📊 **Machine Learning**: Detección de anomalías
- 🔗 **Integración SIEM**: Splunk, ELK, QRadar
- 📱 **App Móvil**: Aplicación móvil
- 🎨 **Temas**: Temas personalizables

## 📈 Registro de Cambios

Ver [CHANGELOG.md](CHANGELOG.md) para el historial completo de cambios.

## 🛡️ Uso Ético

Esta herramienta está diseñada exclusivamente para:

✅ **Uso Autorizado**
- Auditorías de seguridad autorizadas
- Evaluación de redes propias
- Investigación de ciberseguridad
- Educación y laboratorios

❌ **Uso Prohibido**  
- Escanear redes sin autorización
- Actividades maliciosas
- Violación de términos de servicio
- Uso comercial sin licencia

**⚖️ Responsabilidad Legal**: Los usuarios son responsables del cumplimiento de las leyes locales e internacionales.

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT. Ver [LICENSE](LICENSE) para más detalles.

## 👨‍💻 Autor

**Eduardo Hurtado**
- 🌐 Portfolio: [tu-portfolio.com](https://tu-portfolio.com)
- 💼 LinkedIn: [tu-linkedin](https://linkedin.com/in/tu-perfil)
- 📧 Email: contacto@eduardohurtado.info
- 🐱 GitHub: [@tu-usuario](https://github.com/tu-usuario)

## 🙏 Reconocimientos

- **Proyecto Nmap**: Por la herramienta de escaneo base
- **Comunidad Python**: Por las excelentes librerías
- **NIST NVD**: Por la base de datos de vulnerabilidades
- **Comunidad de Ciberseguridad**: Por el feedback y contribuciones

---

<div align="center">

**⭐ Si este proyecto te resulta útil, considera darle una estrella ⭐**

*Desarrollado con ❤️ para la comunidad de ciberseguridad*

</div>