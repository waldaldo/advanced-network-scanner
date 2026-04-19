# Escáner Avanzado de Red

Plataforma de pentesting y auditoría de red construida sobre Nmap y Python. Realiza descubrimiento de hosts, enumeración de servicios, detección de vulnerabilidades CVE con referencias de exploits y POCs, análisis NSE, sistema de alertas y persistencia histórica. Disponible como CLI, panel web y API REST.

---

## Características

- **Descubrimiento de hosts** — ARP + ICMP en LAN (con `setcap`), TCP SYN ping como fallback sin privilegios
- **Escaneo TCP, UDP o combinado** — SYN scan privilegiado, detección de versiones (`-sV`), OS detection
- **Scripts NSE** — categoría `vuln` + `vulners` para mapeo automático de CVEs a servicios detectados
- **Inteligencia CVE/POC** — por cada vulnerabilidad encontrada: score CVSS, vector, CWE, productos afectados, referencias directas de exploits y links de búsqueda a Exploit-DB, GitHub, PacketStorm, Vulners y Rapid7
- **Panel web** — dashboard con historial, alertas, gráficos y lanzamiento de escaneos desde el navegador
- **API REST** — integración con otros sistemas; endpoints para escaneos, alertas, estadísticas y vulnerabilidades
- **Persistencia SQLite** — historial de escaneos, comparación entre ejecuciones, limpieza automática por retención
- **Sistema de alertas** — reglas por severidad, servicios inseguros, puertos de alto riesgo; notificaciones email/Slack/webhook
- **56 tests automatizados** — cobertura de todos los módulos principales

---

## Requisitos

- Python 3.8+
- Nmap instalado

```bash
# Arch / CachyOS / Manjaro
sudo pacman -S nmap

# Ubuntu / Debian
sudo apt install nmap

# Fedora / RHEL
sudo dnf install nmap

# macOS
brew install nmap
```

---

## Instalación

```bash
git clone git@github.com:waldaldo/advanced-network-scanner.git
cd advanced-network-scanner

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Configuración de privilegios (recomendado)

Para que nmap use ARP scanning, ICMP y SYN scan sin necesidad de `sudo`, aplica Linux capabilities al binario una sola vez:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap

# Verificar
getcap /usr/bin/nmap
# → /usr/bin/nmap cap_net_raw,cap_net_admin=eip
```

El scanner detecta automáticamente si nmap tiene estos privilegios al arrancar y ajusta los argumentos:

| Modo | Descubrimiento | Port scan | OS detection |
|------|---------------|-----------|--------------|
| Con `setcap` | ARP + ICMP | SYN scan | Sí |
| Sin `setcap` | TCP SYN ping (puertos comunes) | TCP connect | No |

---

## Uso

### Panel web (recomendado)

```bash
source venv/bin/activate
python web_dashboard.py
# → http://127.0.0.1:5000
```

Desde el panel puedes lanzar escaneos TCP, UDP o combinados directamente desde el navegador, ver el historial con detalle por host/puerto, revisar alertas y consultar gráficos de actividad.

### CLI

```bash
# Escaneo TCP con análisis CVE/NSE
python scanner_v2.py 192.168.1.0/24

# Escaneo UDP
python scanner_v2.py 192.168.1.0/24 -t udp

# TCP + UDP combinado
python scanner_v2.py 192.168.1.0/24 -t both

# Sin scripts NSE (más rápido)
python scanner_v2.py 192.168.1.0/24 --no-nse

# Guardar resultados
python scanner_v2.py 192.168.1.0/24 -o resultado -f json

# Historial y estadísticas
python scanner_v2.py --history
python scanner_v2.py --stats
```

### Startup manager

```bash
python startup.py status                        # Estado del sistema
python startup.py scan 192.168.1.0/24          # Escaneo TCP
python startup.py scan 192.168.1.0/24 -t udp  # Escaneo UDP
python startup.py web                           # Panel web (puerto 5000)
python startup.py api                           # API REST (puerto 5001)
python startup.py all                           # Ambos servicios
```

### POC Finder (standalone)

Consulta inteligencia para un CVE específico:

```bash
python poc_finder.py CVE-2021-41773
```

```
============================================================
CVE: CVE-2021-41773  |  Score: 7.5  |  Severidad: HIGH
============================================================
Descripción: A flaw was found in a change made to path normalization...
CWE: CWE-22
Productos: Apache Software Foundation Apache HTTP Server (2.4.49)

Exploit público conocido: SÍ ⚠
Referencias de exploit:
  → http://packetstormsecurity.com/files/164418/...
  → https://httpd.apache.org/security/vulnerabilities_24.html

Links de búsqueda:
  [exploit_db      ] https://www.exploit-db.com/search?cve=CVE-2021-41773
  [github_poc      ] https://github.com/search?q=CVE-2021-41773+poc&...
  [packet_storm    ] https://packetstormsecurity.com/search/?q=CVE-2021-41773
  [vulners         ] https://vulners.com/cve/CVE-2021-41773
  [rapid7          ] https://www.rapid7.com/db/?q=CVE-2021-41773
```

---

## Pipeline de inteligencia CVE

Cuando se ejecuta un escaneo con NSE activado (por defecto), el flujo completo es:

```
nmap -sV  →  versiones de servicios detectadas
    ↓
vulners.nse  →  mapeo CPE → CVEs en tiempo real
vuln NSE     →  verificación de vulnerabilidades específicas (ms17-010, etc.)
    ↓
cve_detector.py  →  base de conocimiento local + API NVD
    ↓
poc_finder.py    →  enriquecimiento via circl.lu (sin clave API)
    ↓
Por cada CVE:
  • CVSS score + vector
  • CWE
  • Productos y versiones afectadas
  • Referencias directas a exploits conocidos
  • Links de búsqueda: Exploit-DB, GitHub POCs,
    PacketStorm, Vulners, Rapid7, Shodan, MITRE, NVD
```

---

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

# Documentación completa
curl http://127.0.0.1:5001/api/v1/info
```

**Endpoints:**

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

**API key** — configurar via variable de entorno:

```bash
export SCANNER_API_KEY=<clave-segura>
```

---

## Configuración

El archivo `config.yaml` controla todos los aspectos del sistema:

```yaml
scan:
  default_scan_type: "tcp"
  default_tcp_args: "-sV -T4 --open"
  default_udp_args: "-sU -T4 --open --top-ports 1000"
  use_nse_scripts: true
  nse_scripts:
    - "vuln"      # Detección de vulnerabilidades conocidas
    - "vulners"   # CVEs via Vulners API (requiere -sV)
    - "default"   # Scripts seguros por defecto
  os_detection: true

parallel:
  max_workers: 20

database:
  enabled: true
  db_file: "./scanner_history.db"
  retention_days: 90

security:
  api_key_required: true
  api_key: ""     # preferir variable de entorno SCANNER_API_KEY

notifications:
  email:
    enabled: false
  slack:
    enabled: false
```

---

## Arquitectura

```
startup.py              Punto de entrada unificado
scanner_v2.py           Escáner CLI con detección automática de privilegios
parallel_scanner.py     Motor de escaneo paralelo (ThreadPoolExecutor)
cve_detector.py         Detección CVE: base local + API NVD + POC enrichment
poc_finder.py           Inteligencia POC/exploit via circl.lu y links directos
nse_analyzer.py         Análisis y clasificación de resultados NSE
alert_system.py         Alertas: email, Slack, webhooks
database.py             Persistencia SQLite con historial y comparación
web_dashboard.py        Panel web Flask (puerto 5000)
api_server.py           API REST Flask (puerto 5001)
config.yaml             Configuración centralizada
web/templates/          dashboard, scans, alerts, analytics, 404, 500
tests/                  56 tests automatizados
```

---

## Tests

```bash
source venv/bin/activate
python -m pytest tests/ -v
# 56 passed
```

---

## Uso ético

Esta herramienta está destinada exclusivamente a:

- Auditorías de seguridad en redes propias o con autorización explícita por escrito
- Investigación y laboratorios de ciberseguridad
- Monitoreo defensivo de infraestructura propia

El escaneo de redes sin autorización puede constituir un delito. El usuario es el único responsable del cumplimiento de las leyes aplicables.

---

## Licencia

MIT — ver [LICENSE](LICENSE).

## Autor

Eduardo Hurtado — [contacto@eduardohurtado.info](mailto:contacto@eduardohurtado.info)
