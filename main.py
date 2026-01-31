import re
import logging
import requests
import idna
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List, Tuple, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Konfiguration ---
SOURCES_FILE = "sources.txt"
WHITELIST_FILE = "whitelist.txt"
OUTPUT_FILE = "pihole_blocklist.txt"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}
# Verbessertes Regex für Domains
DOMAIN_REGEX = re.compile(
    r'^(?!-)[a-z0-9-\w]{1,63}(?:\.[a-z0-9-\w]{1,63})+(?<!-)$',
    re.IGNORECASE
)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Verbesserte Funktionen ---

def get_session():
    """Erstellt eine Requests-Session mit automatischen Retries."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def fetch_url(url: str) -> Optional[str]:
    """Lädt den Inhalt einer URL mit verbessertem Error-Handling."""
    session = get_session()
    try:
        r = session.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        return r.text
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP Fehler bei {url}: {e.response.status_code}")
    except requests.exceptions.ConnectionError:
        logger.error(f"Verbindungsfehler bei {url}")
    except Exception as e:
        logger.error(f"Unerwarteter Fehler bei {url}: {e}")
    return None

def process_line(line: str, whitelist: Set[str]) -> Optional[str]:
    """Bereinigt eine Zeile und extrahiert die Domain (Host- & Adblock-Style)."""
    # 1. Kommentare entfernen
    line = line.split('#')[0].split('!')[0].strip().lower()
    
    # 2. Adblock-Syntax bereinigen (||domain.com^$option)
    line = line.replace('||', '').replace('^', '')
    line = line.split('$')[0] # Optionen nach $ entfernen
    
    # 3. In Teile zerlegen (für 0.0.0.0 domain.com)
    parts = line.split()
    if not parts:
        return None
    
    # Die Domain als letztes Element in einer Hosts-Zeile
    domain = parts[-1]
    
    if is_valid_domain(domain, whitelist):
        return domain
    return None

def is_valid_domain(domain: str, whitelist: Set[str]) -> bool:
    """Prüft Gültigkeit, Whitelist und konvertiert IDNA."""
    if not domain or domain in whitelist:
        return False
    
    # IP-Adressen ignorieren
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return False
        
    try:
        # IDNA Konvertierung (z.B. für Umlaute)
        encoded_domain = idna.encode(domain).decode('ascii')
        return bool(DOMAIN_REGEX.match(encoded_domain))
    except (idna.IDNAError, UnicodeError):
        return False

# --- Restliche Logik (angepasst für GitHub Summary) ---

def hole_und_bereinige(urls: List[str], whitelist: Set[str]) -> Tuple[Set[str], List[str]]:
    alle_domains = set()
    stats = []
    
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(fetch_url, url): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            content = future.result()
            if content:
                count = 0
                for line in content.splitlines():
                    domain = process_line(line, whitelist)
                    if domain:
                        alle_domains.add(domain)
                        count += 1
                stats.append(f"✅ {url}: {count} Domains")
            else:
                stats.append(f"❌ {url}: Download fehlgeschlagen")
    return alle_domains, stats

def speichern(domains: Set[str], whitelist_count: int, stats: List[str]):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Pi-hole Blocklist Aggregator\n# Update: {timestamp}\n")
        f.write(f"# Total Domains: {len(domains)}\n\n")
        for domain in sorted(domains):
            f.write(f"{domain}\n")
    
    # GitHub Action Summary
    if "GITHUB_STEP_SUMMARY" in os.environ:
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as gss:
            gss.write(f"### 🛡️ Blocklist Update Summary ({timestamp})\n")
            gss.write(f"- **Gesamtanzahl Domains:** {len(domains)}\n")
            gss.write("- **Details pro Quelle:**\n")
            for s in stats:
                gss.write(f"  - {s}\n")

if __name__ == "__main__":
    logger.info("Starte Update...")
    # Lade Dateien
    try:
        with open(SOURCES_FILE, 'r') as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        with open(WHITELIST_FILE, 'r') as f:
            whitelist = {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}
    except FileNotFoundError as e:
        logger.error(f"Datei fehlt: {e}")
        exit(1)

    domains, stats = hole_und_bereinige(urls, whitelist)
    speichern(domains, len(whitelist), stats)
    logger.info(f"Fertig! {len(domains)} Domains gespeichert.")
