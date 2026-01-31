import re
import logging
import requests
import idna
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List, Tuple, Optional

# --- Konfiguration ---
SOURCES_FILE = "sources.txt"
WHITELIST_FILE = "whitelist.txt"
OUTPUT_FILE = "pihole_blocklist.txt"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}
DOMAIN_REGEX = re.compile(
    r'^(?!-)[a-z0-9-\w]{1,63}(?:\.[a-z0-9-\w]{1,63})+(?<!-)$',
    re.IGNORECASE
)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# --- Hilfsfunktionen ---
def load_text_file(filename: str) -> List[str]:
    """Lädt eine Textdatei und gibt die Zeilen als Liste zurück."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        logger.warning(f"Datei {filename} nicht gefunden!")
        return []

def is_valid_domain(domain: str, whitelist: Set[str]) -> bool:
    """Prüft, ob eine Domain gültig ist und nicht auf der Whitelist steht."""
    if not domain or domain in whitelist:
        return False
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):  # IP-Adressen ignorieren
        return False
    try:
        domain = idna.encode(domain).decode('ascii')  # Unicode-Domains konvertieren
    except idna.IDNAError:
        return False
    return bool(DOMAIN_REGEX.match(domain))

def fetch_url(url: str) -> Optional[str]:
    """Lädt den Inhalt einer URL mit Fehlerbehandlung."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=15, verify=True)
        r.raise_for_status()
        return r.text
    except Exception as e:
        logger.error(f"Fehler beim Laden von {url}: {e}")
        return None

def process_line(line: str, whitelist: Set[str]) -> Optional[str]:
    """Bereinigt eine Zeile und extrahiert die Domain."""
    line = line.split('#')[0].split('!')[0].strip().lower()
    line = line.replace('||', '').replace('^', '')
    parts = line.split()
    if not parts:
        return None
    domain = parts[-1]
    return domain if is_valid_domain(domain, whitelist) else None

def hole_und_bereinige(urls: List[str], whitelist: Set[str]) -> Tuple[Set[str], List[str]]:
    """Lädt und bereinigt Domains aus allen URLs."""
    stats = []
    alle_domains = set()

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_url, url): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            content = future.result()
            if not content:
                stats.append(f"❌ {url} (Fehler)")
                continue

            domains_in_list = 0
            for line in content.splitlines():
                domain = process_line(line, whitelist)
                if domain:
                    alle_domains.add(domain)
                    domains_in_list += 1
            stats.append(f"✅ {url} ({domains_in_list} Domains)")

    return alle_domains, stats

def speichern(domains: Set[str], whitelist_count: int) -> None:
    """Speichert die Domains in die Ausgabedatei."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Pi-hole Blocklist Aggregator\n")
        f.write(f"# Generiert am: {timestamp}\n")
        f.write(f"# Total Domains: {len(domains)}\n")
        f.write(f"# Whitelist-Einträge: {whitelist_count}\n\n")
        for domain in sorted(domains):
            f.write(f"{domain}\n")
    logger.info(f"{len(domains)} Domains in {OUTPUT_FILE} gespeichert.")

# --- Hauptprogramm ---
if __name__ == "__main__":
    logger.info("Starte Aggregation...")
    urls = load_text_file(SOURCES_FILE)
    whitelist = set(load_text_file(WHITELIST_FILE))

    domains, stats = hole_und_bereinige(urls, whitelist)

    logger.info("\n--- ZUSAMMENFASSUNG ---")
    for stat in stats:
        logger.info(stat)

    speichern(domains, len(whitelist))
