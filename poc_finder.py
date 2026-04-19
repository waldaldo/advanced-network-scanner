#!/usr/bin/env python3
"""
POC Finder — enriquece CVEs con referencias de exploits y recursos de investigación.
Fuentes: circl.lu (gratis, sin clave), NVD, y links de búsqueda directa.
No ejecuta nada — solo recopila inteligencia para el investigador.
"""
import re
import time
import logging
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

EXPLOIT_SOURCES = {
    'exploit_db':    'https://www.exploit-db.com/search?cve={cve}',
    'github_poc':    'https://github.com/search?q={cve}+poc&type=repositories&sort=updated',
    'packet_storm':  'https://packetstormsecurity.com/search/?q={cve}',
    'vulners':       'https://vulners.com/cve/{cve}',
    'nvd':           'https://nvd.nist.gov/vuln/detail/{cve}',
    'rapid7':        'https://www.rapid7.com/db/?q={cve}&type=nexpose',
    'shodan_exploits':'https://exploits.shodan.io/search?query={cve}',
    'mitre':         'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}',
}

# Tags de referencia que indican un exploit o POC
EXPLOIT_TAGS = {
    'Exploit', 'exploit', 'patch', 'Patch', 'Third Party Advisory',
    'x_refsource_EXPLOIT-DB', 'x_refsource_MISC'
}

EXPLOIT_URL_PATTERNS = [
    r'exploit-db\.com',
    r'exploitdb\.com',
    r'packetstormsecurity\.com',
    r'github\.com.*(?:poc|exploit|cve)',
    r'rapid7\.com/db',
    r'metasploit\.com',
    r'seebug\.org',
    r'vulhub\.org',
]


@dataclass
class POCInfo:
    cve_id: str
    description: str = ''
    cvss_score: float = 0.0
    cvss_vector: str = ''
    severity: str = 'unknown'
    cwe: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    # Referencias directas a exploits/POCs encontradas en las APIs
    exploit_references: List[Dict] = field(default_factory=list)
    # Links de búsqueda preformados (siempre disponibles)
    search_links: Dict[str, str] = field(default_factory=dict)
    # Indicador de si hay exploits públicos conocidos
    has_public_exploit: bool = False
    published_date: str = ''
    last_modified: str = ''


class POCFinder:
    """Busca referencias de exploits y POCs para CVEs encontrados en escaneos."""

    CIRCL_URL = 'https://cve.circl.lu/api/cve/{cve}'
    REQUEST_DELAY = 1.0  # segundos entre llamadas para no saturar las APIs

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'NetworkScanner/2.0 (Security Research; Educational)'
        })
        self._cache: Dict[str, POCInfo] = {}

    def build_search_links(self, cve_id: str) -> Dict[str, str]:
        """Genera links de búsqueda directa para todas las fuentes."""
        return {name: url.format(cve=cve_id) for name, url in EXPLOIT_SOURCES.items()}

    def _is_exploit_ref(self, url: str, tags: List[str]) -> bool:
        """Determina si una referencia apunta a un exploit o POC."""
        if any(t in EXPLOIT_TAGS for t in tags):
            return True
        url_lower = url.lower()
        return any(re.search(p, url_lower) for p in EXPLOIT_URL_PATTERNS)

    def fetch_circl(self, cve_id: str) -> Optional[Dict]:
        """Obtiene datos del CVE desde circl.lu (gratis, sin clave API)."""
        try:
            resp = self.session.get(
                self.CIRCL_URL.format(cve=cve_id), timeout=10
            )
            if resp.status_code == 200:
                return resp.json()
            logger.debug(f"circl.lu retornó {resp.status_code} para {cve_id}")
        except requests.RequestException as e:
            logger.warning(f"Error consultando circl.lu para {cve_id}: {e}")
        return None

    def enrich(self, cve_id: str) -> POCInfo:
        """
        Enriquece un CVE con descripción, score CVSS y referencias de exploits.
        Resultado cacheado para evitar llamadas repetidas.
        """
        if cve_id in self._cache:
            return self._cache[cve_id]

        info = POCInfo(
            cve_id=cve_id,
            search_links=self.build_search_links(cve_id)
        )

        data = self.fetch_circl(cve_id)
        time.sleep(self.REQUEST_DELAY)

        if data:
            cna = data.get('containers', {}).get('cna', {})

            # Descripción
            for desc in cna.get('descriptions', []):
                if desc.get('lang') == 'en':
                    info.description = desc.get('value', '')
                    break

            # Fecha
            info.published_date = data.get('cveMetadata', {}).get('datePublished', '')[:10]
            info.last_modified  = data.get('cveMetadata', {}).get('dateUpdated', '')[:10]

            # CWE
            for pt in cna.get('problemTypes', []):
                for pd in pt.get('descriptions', []):
                    cwe_id = pd.get('cweId') or pd.get('description', '')
                    if cwe_id:
                        info.cwe.append(cwe_id)

            # Productos afectados
            for affected in cna.get('affected', []):
                vendor  = affected.get('vendor', '')
                product = affected.get('product', '')
                versions = [v.get('version', '') for v in affected.get('versions', [])]
                label = f"{vendor} {product} ({', '.join(versions[:3])})" if versions else f"{vendor} {product}"
                info.affected_products.append(label.strip())

            # CVSS — buscar en métricas de todas las fuentes
            adp_list = data.get('containers', {}).get('adp', [])
            all_containers = [cna] + (adp_list if isinstance(adp_list, list) else [adp_list])
            for container in all_containers:
                metrics = container.get('metrics', [])
                for metric in metrics:
                    for key in ('cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
                        if key in metric:
                            cvss = metric[key]
                            info.cvss_score  = cvss.get('baseScore', 0.0)
                            info.cvss_vector = cvss.get('vectorString', '')
                            score = info.cvss_score
                            if score >= 9.0:
                                info.severity = 'critical'
                            elif score >= 7.0:
                                info.severity = 'high'
                            elif score >= 4.0:
                                info.severity = 'medium'
                            else:
                                info.severity = 'low'
                            break
                    if info.cvss_score:
                        break
                if info.cvss_score:
                    break

            # Referencias — separar exploits del resto
            for ref in cna.get('references', []):
                url  = ref.get('url', '')
                tags = ref.get('tags', [])
                if self._is_exploit_ref(url, tags):
                    info.exploit_references.append({'url': url, 'tags': tags})
                    info.has_public_exploit = True

        self._cache[cve_id] = info
        return info

    def enrich_bulk(self, cve_ids: List[str]) -> Dict[str, POCInfo]:
        """Enriquece una lista de CVEs con delay entre llamadas."""
        results = {}
        for cve_id in cve_ids:
            results[cve_id] = self.enrich(cve_id)
        return results

    def format_report(self, info: POCInfo) -> Dict:
        """Devuelve el POCInfo como dict plano para serializar o mostrar."""
        return {
            'cve_id':             info.cve_id,
            'description':        info.description,
            'severity':           info.severity,
            'cvss_score':         info.cvss_score,
            'cvss_vector':        info.cvss_vector,
            'cwe':                info.cwe,
            'affected_products':  info.affected_products,
            'has_public_exploit': info.has_public_exploit,
            'exploit_references': info.exploit_references,
            'search_links':       info.search_links,
            'published_date':     info.published_date,
            'last_modified':      info.last_modified,
        }


if __name__ == '__main__':
    import argparse, json
    parser = argparse.ArgumentParser(description='Buscar referencias POC para un CVE')
    parser.add_argument('cve', help='CVE ID (ej. CVE-2021-41773)')
    args = parser.parse_args()

    finder = POCFinder()
    info = finder.enrich(args.cve)

    print(f"\n{'='*60}")
    print(f"CVE: {info.cve_id}  |  Score: {info.cvss_score}  |  Severidad: {info.severity.upper()}")
    print(f"{'='*60}")
    print(f"Descripción: {info.description[:200]}")
    if info.cwe:
        print(f"CWE: {', '.join(info.cwe)}")
    if info.affected_products:
        print(f"Productos: {'; '.join(info.affected_products[:3])}")
    print(f"\nExploit público conocido: {'SÍ ⚠' if info.has_public_exploit else 'No encontrado'}")
    if info.exploit_references:
        print("Referencias de exploit:")
        for ref in info.exploit_references:
            print(f"  → {ref['url']}")
    print("\nLinks de búsqueda:")
    for name, url in info.search_links.items():
        print(f"  [{name:15}] {url}")
