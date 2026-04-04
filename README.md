# Escáner Avanzado de Red

Plataforma de ciberseguridad defensiva para análisis de red, detección de vulnerabilidades y monitoreo continuo. Construida sobre Nmap con Python, ofrece interfaz de línea de comandos, panel web y API REST.

---

## Requisitos

- Python 3.8+
- Nmap instalado y accesible en PATH
- `sudo` para detección de sistema operativo (opcional)

```bash
# Ubuntu/Debian
sudo apt install nmap

# Fedora/RHEL
sudo dnf install nmap

# macOS
brew install nmap
```

## Instalación

```bash
git clone <repo>
cd advanced-network-scanner
pip install -r requirements.txt
```

## Uso

### Administrador de inicio (recomendado)

```bash
python startup.py status                        # Estado del sistema
python startup.py scan 192.168.1.0/24          # Escaneo TCP
python startup.py scan 192.168.1.0/24 -t udp  # Escaneo UDP
python startup.py scan 192.168.1.0/24 -t both -o resultados -f json
python startup.py web                           # Panel web (puerto 5000)
python startup.py api                           # API REST (puerto 5001)
python startup.py all                           # Ambos servicios
```

### Scanner CLI directo

```bash
python scanner_v2.py 192.168.1.0/24
python scanner_v2.py 192.168.1.0/24 -t udp --no-nse
python scanner_v2.py --history
python scanner_v2.py --stats
```

## API REST

```bash
# Crear escaneo
curl -X POST http://127.0.0.1:5001/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $SCANNER_API_KEY" \
  -d '{"network": "192.168.1.0/24", "scan_type": "tcp"}'

# Estado del escaneo
curl -H "X-API-Key: $SCANNER_API_KEY" \
  http://127.0.0.1:5001/api/v1/scans/<scan_id>/status

# Documentación de endpoints
curl http://127.0.0.1:5001/api/v1/info
```

**Endpoints disponibles:**

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/v1/info` | Documentación |
| GET | `/api/v1/status` | Estado del sistema |
| POST | `/api/v1/scans` | Crear escaneo |
| GET | `/api/v1/scans` | Listar escaneos |
| GET | `/api/v1/scans/{id}` | Detalle de escaneo |
| GET | `/api/v1/scans/{id}/status` | Estado de escaneo |
| POST | `/api/v1/scans/{id}/stop` | Detener escaneo |
| GET | `/api/v1/alerts` | Listar alertas |
| POST | `/api/v1/alerts/{id}/acknowledge` | Reconocer alerta |
| GET | `/api/v1/statistics` | Estadísticas |
| GET | `/api/v1/hosts` | Hosts descubiertos |
| GET | `/api/v1/vulnerabilities` | Vulnerabilidades |

## Configuración

El archivo `config.yaml` controla todos los aspectos del sistema. Los valores más relevantes:

```yaml
scan:
  default_scan_type: "tcp"
  use_nse_scripts: true
  nse_scripts: ["vuln", "safe", "default"]
  os_detection: true

parallel:
  max_workers: 20

database:
  enabled: true
  retention_days: 90

security:
  api_key_required: true
  api_key: ""        # preferir variable de entorno

notifications:
  email:
    enabled: false
  slack:
    enabled: false
```

**API key** — se recomienda configurar via variable de entorno en lugar de `config.yaml`:

```bash
export SCANNER_API_KEY=<clave-segura>
```

## Arquitectura

```
startup.py              Punto de entrada unificado
scanner_v2.py           Escáner CLI
parallel_scanner.py     Motor de escaneo paralelo (ThreadPoolExecutor)
cve_detector.py         Detección CVE: base local + API NVD
nse_analyzer.py         Análisis de resultados de scripts NSE
alert_system.py         Alertas: email, Slack, webhooks
database.py             Persistencia SQLite
web_dashboard.py        Panel web Flask (puerto 5000)
api_server.py           API REST Flask (puerto 5001)
config.yaml             Configuración centralizada
```

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Uso ético

Esta herramienta está destinada exclusivamente a:

- Auditorías de seguridad en redes propias o con autorización explícita por escrito
- Investigación y laboratorios de ciberseguridad
- Monitoreo defensivo de infraestructura propia

El escaneo de redes sin autorización puede constituir un delito. El usuario es el único responsable del cumplimiento de las leyes aplicables.

## Licencia

MIT — ver [LICENSE](LICENSE).

## Autor

Eduardo Hurtado
