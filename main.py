import requests
import datetime

# --- Konfiguration ---
OUTPUT_FILE = "pihole_blocklist.txt"

# Simuliere einen echten Browser, um Blockaden (wie bei OISD) zu umgehen
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

# Bereinigte URLs (OISD auf big.oisd.nl und HaGeZi auf jsDelivr CDN umgestellt)
BLOCKLIST_URLS = [
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://adaway.org/hosts.txt",
    "https://big.oisd.nl/", 
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/fake.txt",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "https://v.firebog.net/hosts/Easyprivacy.txt",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Win10Telemetry",
    "https://v.firebog.net/hosts/Easylist.txt",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/crypto",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/spam.mails",
    "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/gambling",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.txt"
]

def fetch_lists():
    all_domains = set()
    print(f"🛡️ Blocklist Update gestartet ({datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
    print("-" * 60)

    for url in BLOCKLIST_URLS:
        try:
            # Timeout auf 15 Sekunden gesetzt, damit ein hängender Server den Action-Run nicht blockiert
            response = requests.get(url, headers=HEADERS, timeout=15)
            response.raise_for_status()
            
            lines = response.text.splitlines()
            valid_domains = 0
            
            for line in lines:
                line = line.strip()
                
                # Ignoriere Kommentare und leere Zeilen
                if not line or line.startswith('#') or line.startswith('!'):
                    continue
                    
                # Extrahiere die Domain (falls im Hosts-Format geliefert, z.B. "0.0.0.0 bad-domain.com")
                parts = line.split()
                domain = parts[-1] if len(parts) > 0 else line
                
                # Ignoriere Standard-Lokaleinträge
                if domain in ['localhost', '127.0.0.1', '0.0.0.0', 'broadcasthost']:
                    continue
                    
                all_domains.add(domain)
                valid_domains += 1
                
            print(f"✅ {url}: {valid_domains} Domains")
            
        except requests.exceptions.RequestException as e:
            # Fängt Timeouts, 403 Forbidden, 404 Not Found etc. ab
            print(f"❌ {url}: Download fehlgeschlagen ({e})")

    print("-" * 60)
    print(f"Gesamtanzahl einzigartiger Domains nach Deduplizierung: {len(all_domains)}")
    
    # In Datei schreiben (alphabetisch sortiert für saubere Git-Diffs)
    with open(OUTPUT_FILE, 'w') as f:
        for domain in sorted(all_domains):
            f.write(f"{domain}\n")
            
    print(f"Erfolgreich in {OUTPUT_FILE} gespeichert.")

if __name__ == "__main__":
    fetch_lists()
