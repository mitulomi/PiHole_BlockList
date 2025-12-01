import requests
import re
from datetime import datetime

# Dateien definieren
SOURCES_FILE = "sources.txt"
WHITELIST_FILE = "whitelist.txt"
OUTPUT_FILE = "pihole_blocklist.txt"

# Regex für gültige Domains
DOMAIN_REGEX = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+(?<!-)$')

# Tarnung als Browser, damit man nicht geblockt wird
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

def load_text_file(filename):
    """Liest eine Datei ein und gibt eine Liste von nicht-leeren Zeilen zurück."""
    try:
        with open(filename, 'r') as f:
            # Zeilen lesen, Leerzeichen entfernen, leere Zeilen ignorieren, Kommentare ignorieren
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"Warnung: Datei {filename} nicht gefunden!")
        return []

def hole_und_bereinige():
    urls = load_text_file(SOURCES_FILE)
    whitelist = set(load_text_file(WHITELIST_FILE))
    
    alle_domains = set()
    stats = [] # Speichern der Statistiken für jede Liste

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starte Aggregation von {len(urls)} Quellen...")

    for url in urls:
        domains_in_dieser_liste = 0
        try:
            print(f" Lade: {url}")
            r = requests.get(url, headers=HEADERS, timeout=15)
            
            if r.status_code != 200:
                print(f"  Warnung: Fehlercode {r.status_code}")
                stats.append(f"❌ {url} (Fehler: {r.status_code})")
                continue

            for zeile in r.text.splitlines():
                # Bereinigung
                zeile = zeile.split('#')[0].split('!')[0].strip().lower()
                
                # Hosts-Format oder reines Domain-Format erkennen
                parts = zeile.split()
                if not parts: continue
                domain = parts[-1] 

                # Validierung & Whitelist Check
                if (not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) and 
                    "." in domain and 
                    domain not in whitelist and
                    DOMAIN_REGEX.match(domain)):
                    
                    alle_domains.add(domain)
                    domains_in_dieser_liste += 1
            
            stats.append(f"✅ {url} ({domains_in_dieser_liste} Domains)")

        except Exception as e:
            print(f"  Fehler: {e}")
            stats.append(f"⚠️ {url} (Exception: {str(e)})")

    # Statistik ausgeben
    print("\n--- ZUSAMMENFASSUNG ---")
    for s in stats:
        print(s)
    
    return sorted(alle_domains), len(whitelist)

def speichern(domains, whitelist_count):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(OUTPUT_FILE, 'w') as f:
        f.write(f"# Pi-hole Blocklist Aggregator\n")
        f.write(f"# Generiert am: {timestamp}\n")
        f.write(f"# Total Domains: {len(domains)}\n")
        f.write(f"# Whitelist Eintraege: {whitelist_count}\n\n")
        for domain in domains:
            f.write(f"{domain}\n")
    print(f"\nFertig! {len(domains)} Domains in {OUTPUT_FILE} gespeichert.")

if __name__ == "__main__":
    domains, wl_count = hole_und_bereinige()
    speichern(domains, wl_count)
