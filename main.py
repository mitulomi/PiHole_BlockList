import requests
import datetime

# --- Konfiguration ---
# Der Basisname für die aufgeteilten Dateien
OUTPUT_BASE_NAME = "pihole_blocklist_part"
# Maximale Anzahl an Domains pro Datei (2.500.000 = ca. 55 MB)
CHUNK_SIZE = 2500000 

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

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
            response = requests.get(url, headers=HEADERS, timeout=15)
            response.raise_for_status()
            
            lines = response.text.splitlines()
            valid_domains = 0
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('!'):
                    continue
                    
                parts = line.split()
                domain = parts[-1] if len(parts) > 0 else line
                
                if domain in ['localhost', '127.0.0.1', '0.0.0.0', 'broadcasthost']:
                    continue
                    
                all_domains.add(domain)
                valid_domains += 1
                
            print(f"✅ {url}: {valid_domains} Domains")
            
        except requests.exceptions.RequestException as e:
            print(f"❌ {url}: Download fehlgeschlagen ({e})")

    print("-" * 60)
    print(f"Gesamtanzahl einzigartiger Domains: {len(all_domains)}")
    
    # --- NEU: Datei aufteilen (Splitting) ---
    domains_list = sorted(list(all_domains))
    
    for i in range(0, len(domains_list), CHUNK_SIZE):
        chunk = domains_list[i:i + CHUNK_SIZE]
        part_num = (i // CHUNK_SIZE) + 1
        filename = f"{OUTPUT_BASE_NAME}{part_num}.txt"
        
        with open(filename, 'w') as f:
            for domain in chunk:
                f.write(f"{domain}\n")
                
        print(f"Erfolgreich {len(chunk)} Domains in {filename} gespeichert.")

if __name__ == "__main__":
    fetch_lists()
