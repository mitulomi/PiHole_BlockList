import requests
import re
from datetime import datetime

# --- KONFIGURATION ---

# Eine sorgfältig ausgewählte Liste.
# Ich habe die toten Bank-Listen entfernt und konzentriere mich auf
# große, gepflegte Listen, um den Pi-hole nicht zu überlasten.
QUELLEN = [
    # --- Basis Listen (Werbung & Tracker) ---
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://v.firebog.net/hosts/Easylist.txt",
    "https://v.firebog.net/hosts/Easyprivacy.txt",
    "https://adaway.org/hosts.txt",
    "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    
    # --- RPiList Specials (Malware, Phishing, Scam) ---
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/crypto",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/gambling",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Win10Telemetry",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/spam.mails",
    
    # --- Sicherheit & Bedrohungen ---
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt"
]

OUTPUT_FILE = "pihole_blocklist.txt"

# Whitelist: Diese Domains werden NIEMALS in die Liste aufgenommen
WHITELIST = {
    "google.com", "microsoft.com", "apple.com", "amazon.de", 
    "whatsapp.com", "netflix.com", "paypal.com"
}

# Regex für gültige Domains (keine IP-Adressen, keine Sonderzeichen außer - und .)
DOMAIN_REGEX = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+(?<!-)$')

def hole_und_bereinige():
    alle_domains = set()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starte Aggregation...")

    for url in QUELLEN:
        try:
            print(f" Lade: {url}")
            r = requests.get(url, timeout=10)
            
            if r.status_code != 200:
                print(f"  Warnung: Fehlercode {r.status_code} - Überspringe Liste.")
                continue

            for zeile in r.text.splitlines():
                # 1. Kommentare und Whitespace entfernen
                zeile = zeile.split('#')[0].split('!')[0].strip().lower()
                
                if not zeile: continue

                # 2. Hosts-Datei Format bereinigen (0.0.0.0 domain.com -> domain.com)
                parts = zeile.split()
                if not parts: continue
                domain_kandidat = parts[-1] 

                # 3. Validierung
                # Ist es keine IP? Hat es einen Punkt? Ist es nicht in der Whitelist? Passt das Regex?
                if (not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_kandidat) and 
                    "." in domain_kandidat and 
                    domain_kandidat not in WHITELIST and
                    DOMAIN_REGEX.match(domain_kandidat)):
                    
                    alle_domains.add(domain_kandidat)

        except Exception as e:
            print(f"  Fehler beim Laden von {url}: {e}")

    return sorted(alle_domains)

def speichern(domains):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Speichere Datei...")
    with open(OUTPUT_FILE, 'w') as f:
        f.write(f"# Pi-hole Blocklist Aggregator von mitulomi\n")
        f.write(f"# Generiert am: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Anzahl Domains: {len(domains)}\n")
        f.write(f"# Lizenz: MIT License\n\n")
        for domain in domains:
            f.write(f"{domain}\n")
    print(f"Fertig! {len(domains)} Domains in {OUTPUT_FILE} gespeichert.")

if __name__ == "__main__":
    domains = hole_und_bereinige()
    speichern(domains)
