---
title: >-
  TheHarvester: Email Enumeration e Subdomain Discovery Rapida per Initial
  Reconnaissance
slug: theharvester
description: >-
  TheHarvester è uno strumento OSINT per enumerare email, subdomain, host e
  informazioni pubbliche da motori di ricerca e data source esterni. Guida
  pratica all’uso in reconnaissance e penetration testing.
image: /Gemini_Generated_Image_t3i9idt3i9idt3i9.webp
draft: false
date: 2026-02-08T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - osint
---

TheHarvester è command-line tool Python specializzato in rapid OSINT gathering durante fase iniziale penetration test, estraendo email addresses, subdomain, host, IP e employee names da 38+ sorgenti pubbliche (Google, Bing, LinkedIn, Shodan, PGP keyserver, Certificate Transparency) in singola esecuzione. Creato da Christian Martorella (Edge-Security) e mantenuto attivamente dalla community dal 2007, TheHarvester si distingue per velocità e semplicità: zero configurazione richiesta per uso base, output parsabile per feed a tool successivi, footprint leggero ideale per quick recon dove [https://hackita.it/articoli/spiderfoot](https://hackita.it/articoli/spiderfoot) sarebbe overkill. Versione attuale 4.8.2 introduce support DNS bruteforcing integrato, screenshot automation, virtual host discovery e enhanced API integration per 15+ servizi premium che espandono data source oltre search engine gratuiti.

### Cosa imparerai

Questo articolo copre installazione cross-platform (Linux/Windows/macOS) e dependency management, sintassi base con tutti i 38 data source disponibili, tecniche DNS enumeration con wordlist customization, email format guessing per username generation, integration con [https://hackita.it/articoli/recon-ng](https://hackita.it/articoli/recon-ng) e [https://hackita.it/articoli/maltego](https://hackita.it/articoli/maltego) in recon pipeline, output parsing per automation, API key configuration servizi premium (Shodan, Hunter.io, SecurityTrails), evasion fingerprinting per reduce detection surface, automation via bash/Python scripting, e decision matrix quando preferire TheHarvester vs alternative OSINT (Amass, Subfinder) per scenario specifico engagement.

## Setup e Installazione

TheHarvester richiede **Python 3.10+** e minimal dependencies. Pre-installato su Kali Linux 2023.1+:

```bash
# Verifica installazione
theharvester --version
# Output: theHarvester 4.8.2

# Update se necessario
sudo apt update && sudo apt install theharvester
```

**Installazione manuale da repository GitHub** (versione bleeding-edge):

```bash
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
python3 -m pip install -r requirements/base.txt
python3 theHarvester.py --help
```

**Installazione Windows**:

```powershell
# Via pip (richiede Python 3.10+)
pip install theHarvester

# Oppure da source
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip install -r requirements/base.txt
python theHarvester.py --help
```

**macOS (Homebrew)**:

```bash
brew install theharvester
```

**Verifica funzionamento** con quick test:

```bash
theharvester -d example.com -l 50 -b google
```

Output atteso:

```
*******************************************************************
*  _   _                                            _             *
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
* | __| '_ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *
*                                                                 *
* theHarvester 4.8.2                                              *
* Coded by Christian Martorella                                   *
* Edge-Security Research                                          *
*******************************************************************

[*] Target: example.com
[*] Searching Google.

[*] Hosts found: 12
---------------------
www.example.com
mail.example.com
ftp.example.com
...

[*] IPs found: 5
---------------------
93.184.216.34
...

[*] Emails found: 3
---------------------
info@example.com
support@example.com
contact@example.com
```

Esecuzione completa: **10-30 secondi** per domain medio.

**Note dependency opzionali**:

```bash
# Screenshot functionality (playwright)
pip3 install playwright
playwright install chromium

# DNS bruteforce (nessuna extra dependency richiesta)
```

## Sintassi Base e Data Source

TheHarvester opera su pattern: `theharvester -d <target> -b <source> [options]`

### Parametri Fondamentali

**-d domain** — Target domain (obbligatorio):

```bash
theharvester -d targetcorp.com -b google
```

**-b source** — Data source (obbligatorio). Opzioni principali:

**Search Engines** (no API key required):

```bash
-b baidu          # Baidu (Cina)
-b bing           # Microsoft Bing
-b brave          # Brave Search
-b duckduckgo     # DuckDuckGo
-b google         # Google Search
-b yahoo          # Yahoo Search
```

**Certificate Transparency**:

```bash
-b certspotter    # SSLMate CertSpotter
-b crtsh          # crt.sh database
```

**DNS & Infrastructure**:

```bash
-b dnsdumpster    # DNSdumpster.com
-b hackertarget   # HackerTarget API
-b rapiddns       # RapidDNS
-b sublist3r      # Sublist3r wrapper
-b threatminer    # ThreatMiner
```

**Professional Networks**:

```bash
-b hunter         # Hunter.io (richiede API key)
-b linkedin       # LinkedIn (rate limited)
```

**PGP Keyservers**:

```bash
-b pgp            # MIT PGP keyserver
```

**Threat Intelligence** (richiedono API key):

```bash
-b otx            # AlienVault OTX
-b securityTrails # SecurityTrails
-b shodan         # Shodan
-b virustotal     # VirusTotal
```

**All sources**:

```bash
-b all            # Query tutti i source disponibili
```

**WARNING**: `-b all` genera 500+ query e richiede **15-30 minuti**. Usare per comprehensive assessment, non quick recon.

**-l limit** — Limita risultati per source (default 500):

```bash
theharvester -d example.com -b google -l 100
# Ferma dopo 100 risultati da Google
```

**-f filename** — Save output in HTML/XML/JSON:

```bash
theharvester -d example.com -b all -f results
# Genera: results.html + results.xml
```

### Quick Reconnaissance Examples

**Email harvesting base**:

```bash
theharvester -d targetcorp.com -b google,bing -l 200
```

Output:

```
[*] Emails found: 15
---------------------
john.doe@targetcorp.com
jane.smith@targetcorp.com
admin@targetcorp.com
support@targetcorp.com
...
```

**Subdomain enumeration massivo**:

```bash
theharvester -d targetcorp.com -b all -l 500
```

Output:

```
[*] Hosts found: 87
---------------------
www.targetcorp.com
mail.targetcorp.com
vpn.targetcorp.com
dev-api.targetcorp.com
staging.targetcorp.com
test.targetcorp.com
...
```

**IP address discovery via Shodan** (richiede API key):

```bash
theharvester -d example.com -b shodan -l 100
```

### Output Formats

**1. Console (default)** — stdout plain text

**2. HTML** — report formattato:

```bash
theharvester -d example.com -b all -f report
# Genera: report.html + report.xml
```

**3. JSON** — machine-readable:

```bash
theharvester -d example.com -b all -f results.json
```

Struttura JSON:

```json
{
  "emails": ["admin@example.com", "info@example.com"],
  "hosts": ["www.example.com:93.184.216.34", "mail.example.com:93.184.216.35"],
  "ips": ["93.184.216.34", "93.184.216.35"],
  "asns": ["AS15169"],
  "interesting_urls": [...]
}
```

**4. XML** — legacy format, auto-generated con HTML

## Tecniche Operative

### Scenario 1: Email Harvesting per Spear Phishing

**Contesto**: Red team engagement, serve lista email valide per targeted phishing campaign.

**Execution multi-source**:

```bash
# Step 1: Harvest da multiple sources
theharvester -d targetcorp.com -b google,bing,linkedin,pgp -l 500 -f emails_raw

# Step 2: Extract solo email da output
grep -oE '[a-zA-Z0-9._%+-]+@targetcorp\.com' emails_raw.html | sort -u > emails_clean.txt

# Step 3: Validate email format, rimuovi generici
grep -v 'noreply\|no-reply\|postmaster\|abuse' emails_clean.txt > emails_valid.txt

# Step 4: Count risultati
wc -l emails_valid.txt
# Output: 147 emails_valid.txt
```

**Email Format Guessing** — se harvest yield basso:

```bash
# Osserva pattern da email trovate
cat emails_valid.txt | head -10
# Output pattern: john.doe@targetcorp.com, jane.smith@targetcorp.com
# Pattern identificato: firstname.lastname@domain

# Genera email candidate da LinkedIn employee list
# (raccolto separatamente via scraping)
cat linkedin_employees.txt
# Output:
# John Doe
# Jane Smith  
# Michael Johnson

# Generate email con awk
cat linkedin_employees.txt | awk '{print tolower($1"."$2"@targetcorp.com")}' > guessed_emails.txt

# Merge con harvested
cat emails_valid.txt guessed_emails.txt | sort -u > final_email_list.txt
```

**Verifica email validity** con SMTP enumeration (tool esterno):

```bash
smtp-user-enum -M VRFY -U final_email_list.txt -t mail.targetcorp.com
```

**Timeline realistica**: 10-15 minuti harvest + 20-30 minuti validation = **30-45 minuti total**.

### Scenario 2: Subdomain Discovery per Vulnerability Scanning

**Obiettivo**: Identificare tutti subdomain pubblici per successivo port/vulnerability scanning.

**Comprehensive subdomain harvest**:

```bash
# Passive discovery da multiple sources
theharvester -d example.com -b all -l 1000 -f subdomains_all

# Extract hosts da output HTML
grep -oP '(?<=<td>)[a-z0-9.-]+\.example\.com' subdomains_all.html | sort -u > subs_harvester.txt

# DNS bruteforce con wordlist (opzionale, più noisy)
theharvester -d example.com -b dnsdumpster,crtsh,certspotter -l 2000

# Merge con other tools per coverage massimo
# Esempio: combinare con Amass, Sublist3r
cat subs_harvester.txt subs_amass.txt subs_sublist3r.txt | sort -u > all_subdomains.txt

# Resolve to IPs
cat all_subdomains.txt | while read sub; do 
    host $sub | grep "has address" | awk '{print $1","$NF}'
done > resolved_subs.csv

# Count unique IPs
cut -d',' -f2 resolved_subs.csv | sort -u | wc -l
# Output: 89 unique IPs
```

**Feed results a Nmap** per port scanning:

```bash
# Extract solo IPs
cut -d',' -f2 resolved_subs.csv | sort -u > target_ips.txt

# Nmap full port scan
nmap -iL target_ips.txt -p- -sV -sC -oA nmap_full_scan
```

**Troubleshooting se pochi risultati**:

1. Aumenta limit: `-l 2000` o `-l 5000`
2. Aggiungi sources: `-b all` include 38+ sorgenti
3. Certificate Transparency focus: `-b crtsh,certspotter,censys`
4. DNS brute con wordlist custom (vedi sezione avanzata)

### Scenario 3: Employee Enumeration per Social Engineering

**Obiettivo**: Costruire database employee names con job titles per targeted attacks.

```bash
# LinkedIn harvesting (richiede setup specifico, spesso rate-limited)
theharvester -d targetcorp.com -b linkedin -l 500

# PGP key server search
theharvester -d targetcorp.com -b pgp -l 200

# Twitter mentions
theharvester -d targetcorp.com -b twitter -l 300
```

**Output parsing per extract names**:

```bash
# Da output HTML/text
grep -oP 'Name: \K[A-Z][a-z]+ [A-Z][a-z]+' results.html | sort -u > employee_names.txt

# Associate con job titles (se disponibili in LinkedIn output)
# Esempio output manuale:
# John Doe - Senior DevOps Engineer
# Jane Smith - Security Analyst
# Michael Johnson - CTO
```

**Cross-reference con email trovate**:

```python
#!/usr/bin/env python3
# correlate_emails_names.py

emails = open('emails_valid.txt').read().splitlines()
names = open('employee_names.txt').read().splitlines()

for name in names:
    parts = name.lower().split()
    if len(parts) >= 2:
        fname, lname = parts[0], parts[-1]
        
        # Check various email formats
        patterns = [
            f"{fname}.{lname}@",
            f"{fname[0]}{lname}@",
            f"{fname}@",
            f"{fname}_{lname}@"
        ]
        
        for pattern in patterns:
            matches = [e for e in emails if pattern in e]
            if matches:
                print(f"[CONFIRMED] {name} → {matches[0]}")
                break
        else:
            print(f"[GUESSED] {name} → {fname}.{lname}@targetcorp.com")
```

**Timeline**: 20-30 minuti per organization media (100-500 employees).

## Tecniche Avanzate

### DNS Bruteforcing Integrato

TheHarvester 4.x include DNS brute capability nativa:

```bash
# Enable DNS bruteforce con wordlist default (builtin)
theharvester -d example.com -b google,bing --dns-brute

# Con wordlist custom
theharvester -d example.com -b google --dns-brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Output aggiuntivo:

```
[*] Performing DNS brute force...
[+] Found: admin.example.com (203.0.113.10)
[+] Found: backup.example.com (203.0.113.11)  
[+] Found: dev-api.example.com (203.0.113.12)
[+] Found: staging.example.com (203.0.113.13)
...
[*] 47 new subdomains via DNS brute force
```

**Best wordlists**:

* `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` — quick (3-5 min)
* `/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt` — balanced (8-12 min)
* `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt` — comprehensive (30-60 min)
* Custom wordlist basata su naming conventions target

**OPSEC Warning**: DNS brute genera query flood verso DNS autoritativo target — **highly detectable**. Use only con authorization.

### Virtual Host Discovery

Identify altri domain hosted su stesso IP address:

```bash
theharvester -d example.com -b bing,google --virtual-host
```

Output:

```
[*] Virtual hosts discovered on 203.0.113.10:
example.com
otherdomain.com
thirddomain.com
internal-app.anotherdomain.com
```

**Use case**: Identify co-hosted sites che potrebbero share vulnerabilities o provide lateral movement opportunities.

### Screenshot Automation

Auto-capture screenshot di subdomain trovati (richiede Playwright):

```bash
# Setup Playwright (one-time)
pip3 install playwright
playwright install chromium

# Run TheHarvester con screenshot
theharvester -d example.com -b all --screenshot /tmp/screenshots/
```

Output: PNG screenshots per ogni subdomain HTTP/HTTPS attivo in `/tmp/screenshots/`. Utile per quick visual triage di tecnologie frontend e identify potentially interesting targets.

### API Keys Configuration

Molti sources richiedono API keys per functionality completa. File config: `~/.theHarvester/api-keys.yaml`

**Struttura file**:

```yaml
# ~/.theHarvester/api-keys.yaml
apikeys:
  bevigil:
    key: YOUR_BEVIGIL_KEY
  binaryedge:
    key: YOUR_BINARYEDGE_KEY
  censys:
    id: YOUR_CENSYS_ID
    secret: YOUR_CENSYS_SECRET
  criminalip:
    key: YOUR_CRIMINALIP_KEY
  fullhunt:
    key: YOUR_FULLHUNT_KEY
  github:
    key: YOUR_GITHUB_TOKEN
  hunter:
    key: YOUR_HUNTER_KEY
  intelx:
    key: YOUR_INTELX_KEY
  netlas:
    key: YOUR_NETLAS_KEY
  pentesttools:
    key: YOUR_PENTESTTOOLS_KEY
  projectdiscovery:
    key: YOUR_CHAOS_KEY
  rocketreach:
    key: YOUR_ROCKETREACH_KEY
  securityTrails:
    key: YOUR_SECURITYTRAILS_KEY
  shodan:
    key: YOUR_SHODAN_KEY
  tomba:
    key: YOUR_TOMBA_KEY
  virustotal:
    key: YOUR_VIRUSTOTAL_KEY
  zoomeye:
    key: YOUR_ZOOMEYE_KEY
```

**Priority API keys** per pentesting (costo-efficacia):

| Service            | Cost      | Free Tier         | Value for Pentesting               |
| ------------------ | --------- | ----------------- | ---------------------------------- |
| **Shodan**         | $59/month | 100 results/month | ★★★★★ IP/port intelligence         |
| **Hunter.io**      | $49/month | 25 searches/month | ★★★★★ Professional email discovery |
| **SecurityTrails** | $99/month | 50 queries/month  | ★★★★☆ Historical DNS data          |
| **VirusTotal**     | Free      | 4 req/min         | ★★★★☆ Domain reputation            |
| **GitHub Token**   | Free      | 5k req/hour       | ★★★★☆ Code search for secrets      |

**Acquisizione rapida**:

```bash
# Shodan
# Register: https://account.shodan.io/register
# API Key: Account → API Key section

# Hunter.io  
# Register: https://hunter.io/users/sign_up
# Free tier: 25 searches/month
# API Key: Dashboard → API section

# GitHub Personal Access Token
# Settings → Developer settings → Personal access tokens → Generate
# Scopes needed: public_repo (minimum)

# VirusTotal
# Register: https://www.virustotal.com/gui/join-us
# API Key: Profile → API Key
# Free: 4 requests/minute limit
```

### Multi-Domain Batch Scanning

Script per scan multipli domain automatically:

```bash
#!/bin/bash
# batch_harvest.sh

DOMAINS_FILE="domains.txt"
OUTPUT_DIR="./results"

mkdir -p $OUTPUT_DIR

while read domain; do
    echo "[*] Scanning $domain..."
    
    # Quick harvest
    theharvester -d $domain -b google,bing,hunter -l 200 \
        -f "$OUTPUT_DIR/${domain}_quick"
    
    # Sleep per rate limiting
    sleep 5
    
done < $DOMAINS_FILE

echo "[+] Batch scan complete. Results in $OUTPUT_DIR/"
```

**domains.txt**:

```
target1.com
target2.com
target3.com
competitor1.com
competitor2.com
```

**Execution**:

```bash
chmod +x batch_harvest.sh
./batch_harvest.sh
```

**Timeline**: \~10 minuti per domain × numero di domain.

### Integration con Recon Pipelines

**TheHarvester → Recon-ng**:

```bash
# 1. Harvest emails con TheHarvester
theharvester -d target.com -b all -f harvest.json

# 2. Parse JSON e import in Recon-ng database
python3 << 'PYEOF'
import json
import sqlite3

with open('harvest.json') as f:
    data = json.load(f)

# Connect to Recon-ng workspace DB
conn = sqlite3.connect(os.path.expanduser('~/.recon-ng/workspaces/target/data.db'))
cursor = conn.cursor()

# Insert emails
for email in data.get('emails', []):
    cursor.execute("INSERT OR IGNORE INTO contacts (email) VALUES (?)", (email,))

# Insert hosts
for host in data.get('hosts', []):
    hostname = host.split(':')[0]
    cursor.execute("INSERT OR IGNORE INTO hosts (host) VALUES (?)", (hostname,))

conn.commit()
conn.close()
print("[+] Data imported to Recon-ng")
PYEOF
```

**TheHarvester → SpiderFoot**:

```bash
# Extract unique hosts
cat harvest.html | grep -oE '[a-z0-9.-]+\.target\.com' | sort -u > hosts.txt

# Feed each to SpiderFoot
cat hosts.txt | while read host; do
    python3 /opt/spiderfoot/sf.py -s $host -u investigate -o csv -f "spider_${host}.csv"
done
```

**TheHarvester → Amass → Aquatone** (comprehensive pipeline):

```bash
# Complete subdomain discovery pipeline
theharvester -d target.com -b all --dns-brute -f harvest_subs.txt
amass enum -passive -d target.com -o amass_subs.txt

# Merge results
cat harvest_subs.txt amass_subs.txt | sort -u > merged_subs.txt

# Visual reconnaissance
cat merged_subs.txt | aquatone -out aquatone_results/
```

## Automation e Scripting

### Bash Wrapper per Daily Recon

```bash
#!/bin/bash
# daily_harvest.sh - Automated OSINT collection

DOMAIN_LIST="targets.txt"
OUTPUT_BASE="/var/osint"
DATE=$(date +%Y%m%d)
OUTPUT_DIR="$OUTPUT_BASE/$DATE"

mkdir -p $OUTPUT_DIR

while read domain; do
    echo "[*] Processing $domain at $(date)"
    
    # Quick harvest
    theharvester -d $domain -b google,bing,hunter -l 200 \
        -f "$OUTPUT_DIR/${domain}_quick.json"
    
    # Email extraction
    cat "$OUTPUT_DIR/${domain}_quick.json" | jq -r '.emails[]' 2>/dev/null \
        > "$OUTPUT_DIR/${domain}_emails.txt"
    
    # Subdomain extraction  
    cat "$OUTPUT_DIR/${domain}_quick.json" | jq -r '.hosts[]' 2>/dev/null | cut -d: -f1 \
        > "$OUTPUT_DIR/${domain}_subs.txt"
    
    # Alert on new findings (compare con previous run)
    PREV_EMAILS="$OUTPUT_BASE/previous/${domain}_emails.txt"
    if [ -f "$PREV_EMAILS" ]; then
        NEW_COUNT=$(comm -13 <(sort "$PREV_EMAILS") <(sort "$OUTPUT_DIR/${domain}_emails.txt") | wc -l)
        if [ $NEW_COUNT -gt 0 ]; then
            echo "[ALERT] $NEW_COUNT new emails for $domain" | \
                mail -s "TheHarvester Alert: $domain" security@company.com
        fi
    fi
    
    # Backup for next diff
    mkdir -p "$OUTPUT_BASE/previous"
    cp "$OUTPUT_DIR/${domain}_emails.txt" "$OUTPUT_BASE/previous/"
    
    # Rate limiting delay
    sleep $((RANDOM % 300 + 60))  # 1-5 min random
    
done < $DOMAIN_LIST

echo "[+] Daily harvest complete: $OUTPUT_DIR"
```

**Cron scheduling** (weekly automated run):

```bash
crontab -e

# Add line (run every Sunday at 3 AM):
0 3 * * 0 /opt/scripts/daily_harvest.sh >> /var/log/harvest.log 2>&1
```

### Python Integration per Advanced Parsing

```python
#!/usr/bin/env python3
"""
harvest_and_validate.py - TheHarvester wrapper with validation
"""

import subprocess
import json
import re
import sys

def harvest_domain(domain, sources='all', limit=500):
    """Run TheHarvester and return parsed JSON output"""
    
    output_file = f"harvest_{domain}.json"
    cmd = [
        'theharvester',
        '-d', domain,
        '-b', sources,
        '-l', str(limit),
        '-f', output_file
    ]
    
    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[-] Error: {result.stderr}")
        return None
    
    try:
        with open(output_file) as f:
            return json.load(f)
    except:
        print(f"[-] Failed to parse JSON output")
        return None

def validate_emails(emails):
    """Validate email format and filter generics"""
    
    valid_emails = []
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    generic_patterns = ['noreply', 'no-reply', 'postmaster', 'abuse', 'info', 'support']
    
    for email in emails:
        # Format validation
        if not email_pattern.match(email):
            continue
        
        # Filter generic emails
        if any(pattern in email.lower() for pattern in generic_patterns):
            continue
        
        valid_emails.append(email)
    
    return valid_emails

def detect_email_pattern(emails):
    """Detect naming convention from email samples"""
    
    patterns = {
        'firstname.lastname': 0,
        'firstinitial.lastname': 0,
        'firstname': 0,
        'firstname_lastname': 0,
        'unknown': 0
    }
    
    for email in emails:
        local = email.split('@')[0]
        
        if '.' in local and not any(char.isdigit() for char in local):
            patterns['firstname.lastname'] += 1
        elif local.count('.') == 1 and len(local.split('.')[0]) == 1:
            patterns['firstinitial.lastname'] += 1
        elif '_' in local:
            patterns['firstname_lastname'] += 1
        elif not any(char in local for char in ['.', '_', '-']) and not any(char.isdigit() for char in local):
            patterns['firstname'] += 1
        else:
            patterns['unknown'] += 1
    
    dominant = max(patterns, key=patterns.get) if patterns else 'unknown'
    confidence = patterns[dominant] / len(emails) if emails else 0
    
    return dominant, confidence

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 harvest_and_validate.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    
    # Harvest data
    data = harvest_domain(domain)
    if not data:
        sys.exit(1)
    
    # Process emails
    raw_emails = data.get('emails', [])
    valid_emails = validate_emails(raw_emails)
    
    # Detect pattern
    pattern, confidence = detect_email_pattern(valid_emails)
    
    # Results
    results = {
        'domain': domain,
        'total_emails_found': len(raw_emails),
        'valid_emails': len(valid_emails),
        'email_pattern': pattern,
        'pattern_confidence': f"{confidence:.2%}",
        'emails': valid_emails,
        'subdomains': [h.split(':')[0] for h in data.get('hosts', [])],
        'total_subdomains': len(data.get('hosts', []))
    }
    
    print(json.dumps(results, indent=2))
    
    # Save validated results
    with open(f'{domain}_validated.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] Validated results saved to {domain}_validated.json")

if __name__ == "__main__":
    main()
```

**Usage**:

```bash
python3 harvest_and_validate.py targetcorp.com
```

## Comparazione Tool OSINT

| Feature              | TheHarvester       | Amass              | Subfinder          | Recon-ng             | SpiderFoot         |
| -------------------- | ------------------ | ------------------ | ------------------ | -------------------- | ------------------ |
| **Speed**            | ★★★★★ (\<2 min)    | ★★★☆☆ (15-30 min)  | ★★★★★ (\<1 min)    | ★★★☆☆ (10-20 min)    | ★★☆☆☆ (30-60 min)  |
| **Data Sources**     | 38+                | 100+               | 40+                | 100+ modules         | 200+ modules       |
| **Email Discovery**  | ★★★★★ Core         | ★★☆☆☆ Limited      | ★☆☆☆☆ None         | ★★★★☆ Modules        | ★★★★☆ Automated    |
| **Subdomain Enum**   | ★★★★☆ Good         | ★★★★★ Best         | ★★★★★ Excellent    | ★★★☆☆ Modules        | ★★★★☆ Automated    |
| **Setup**            | ★★★★★ Zero config  | ★★★☆☆ Moderate     | ★★★★★ Minimal      | ★★★☆☆ Learning curve | ★★★☆☆ Web UI setup |
| **Automation**       | ★★★★★ CLI-friendly | ★★★★☆ Config files | ★★★★☆ CLI-friendly | ★★★★★ Scriptable     | ★★★☆☆ API-based    |
| **API Requirements** | Optional           | Optional           | Optional           | Many modules         | Many modules       |
| **Output**           | HTML/JSON/XML/Text | 11 formats         | JSON/Text          | CSV/JSON/XML         | CSV/JSON/GEXF      |

**Decision Matrix**:

**Use TheHarvester quando**:

* Time-critical initial recon (primi 5-10 minuti pentest)
* Email enumeration è high priority
* No setup time disponibile
* Quick one-shot assessment
* Need simple CLI tool per scripting

**Use Amass quando**:

* Subdomain completeness è absolute priority
* Disposto trade speed per maximum depth
* Automated continuous monitoring setup
* Budget time 30+ minuti per target

**Use Subfinder quando**:

* Speed massimo richiesto (seconds)
* Subdomain-only focus sufficient
* Integration in automated CI/CD pipeline
* Massive scale (100+ domains)

**Use Recon-ng quando**:

* Correlation cross-source necessaria
* Database persistente per long-term project
* Workflow ripetibile/scriptato richiesto
* Complex investigation con data correlation

**Use SpiderFoot quando**:

* GUI preference over CLI
* Automated correlation senza scripting
* Continuous monitoring dashboard
* Non-technical users need access

## Detection & Evasion

### Blue Team Visibility

TheHarvester queries sono **partially detectable**:

**Public Search Engines** (Google, Bing):

* Query logs con source IP
* Rate limiting se >100 queries/hour
* User-Agent: `python-requests/X.X.X` (fingerprintable)
* Pattern: `site:domain.com` sequential queries

**API Services** (Shodan, Hunter, VirusTotal):

* Ogni query logged con API key identity
* Rate limits enforcement
* Subscription tier visible
* Query history dashboard visible to account owner

**DNS Queries** (se --dns-brute enabled):

* High volume queries verso target DNS autoritativo
* Pattern: sequential subdomain attempts
* Recursive resolver logs (8.8.8.8, 1.1.1.1)
* **HIGHLY DETECTABLE**

**Certificate Transparency**:

* Access logs correlabili (crt.sh, certspotter)
* No direct target interaction
* Investigator IP logged by CT log providers

**Target-side detection**: **ZERO** per passive sources. **HIGH** per DNS brute.

### OPSEC Techniques

**1. User-Agent Randomization**

Modifica `theHarvester/lib/core.py`:

```python
import random

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36'
]

headers = {
    'User-Agent': random.choice(user_agents)
}
```

**2. Rate Limiting Manual**

```bash
# Throttle requests con sleep between sources
theharvester -d target.com -b google -l 50
sleep 300  # 5 min
theharvester -d target.com -b bing -l 50
sleep 300
# etc.
```

**3. Proxy/VPN Rotation**

```bash
# Via proxychains
proxychains4 theharvester -d target.com -b all

# Via SOCKS proxy
export ALL_PROXY=socks5://127.0.0.1:9050
theharvester -d target.com -b all

# Via Tor
torsocks theharvester -d target.com -b google,bing
```

**4. API Key Hygiene**

* Burner email per service registration
* Separate API keys per engagement
* Revoke keys post-assessment
* Never reuse keys across clients
* Use temporary credit cards per service subscription

**5. Distributed Execution**

```bash
# VPS 1: Google + Bing
ssh vps1.provider.com "theharvester -d target.com -b google,bing -f vps1.json"

# VPS 2: Shodan + VirusTotal
ssh vps2.provider.com "theharvester -d target.com -b shodan,virustotal -f vps2.json"

# VPS 3: DNS brute (se necessario)
ssh vps3.provider.com "theharvester -d target.com --dns-brute -f vps3.json"

# Merge results offline
scp vps1:vps1.json vps2:vps2.json vps3:vps3.json ./
python3 merge_results.py vps*.json > merged_final.json
```

**6. Avoid DNS Brute** (se stealth priorità):

```bash
# Stick to passive sources only
theharvester -d target.com -b google,bing,certspotter,crtsh,hackertarget

# NO --dns-brute flag
```

## Performance & Scaling

### Execution Time Benchmarks

Testing su Fortune 500 domain medio:

| Source Combination                 | Results               | Time          | Detection Risk |
| ---------------------------------- | --------------------- | ------------- | -------------- |
| `-b google`                        | 45 emails, 23 hosts   | 12 sec        | Low            |
| `-b bing`                          | 38 emails, 19 hosts   | 10 sec        | Low            |
| `-b google,bing,duckduckgo`        | 89 emails, 51 hosts   | 28 sec        | Low            |
| `-b all` (no API keys)             | 134 emails, 87 hosts  | 95 sec        | Medium         |
| `-b all` (with API keys)           | 267 emails, 203 hosts | 6 min 23 sec  | Medium         |
| `-b all --dns-brute` (5k wordlist) | 312 hosts total       | 14 min 37 sec | **HIGH**       |

**Bottleneck**: API rate limits, non CPU/network bandwidth.

### Resource Consumption

```
CPU: 5-15% single core (I/O bound, waiting on API responses)
RAM: 50-150 MB peak
Network: 20-100 KB/s sustained, burst 500 KB/s
Disk: <5 MB per scan output
```

**Extremely lightweight** — può run su Raspberry Pi, VPS minimal, o laptop vecchio.

### Scaling Strategies

**Parallel Domain Scanning** (GNU parallel):

```bash
# Scan 50 domains in parallel (10 concurrent)
cat domains.txt | parallel -j 10 'theharvester -d {} -b all -f results_{}.json'
```

**Headless CI/CD Integration** (GitLab CI example):

```yaml
# .gitlab-ci.yml
recon_stage:
  stage: reconnaissance
  script:
    - theharvester -d $CI_PROJECT_DOMAIN -b all -f recon.json
    - python3 parse_and_alert.py recon.json
  artifacts:
    paths:
      - recon.json
  only:
    - schedules  # Weekly cron job
```

**Kubernetes Deployment** (massive scale):

```yaml
# k8s-harvester-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: theharvester-scan
spec:
  parallelism: 20
  template:
    spec:
      containers:
      - name: harvester
        image: theharvester:latest
        command: ["theharvester"]
        args: ["-d", "$(TARGET_DOMAIN)", "-b", "all", "-f", "/output/$(TARGET_DOMAIN).json"]
        volumeMounts:
        - name: output
          mountPath: /output
      volumes:
      - name: output
        persistentVolumeClaim:
          claimName: harvester-pvc
```

## Troubleshooting

### Error: "No results found"

**Causa**: Domain typo, no public footprint, rate limited, o source not indexing domain.

**Diagnosis**:

```bash
# Verify domain exists
dig target.com ANY
nslookup target.com

# Try specific source
theharvester -d target.com -b google -l 100

# Increase limit
theharvester -d target.com -b all -l 2000

# Check rate limiting
curl -I "https://www.google.com/search?q=site:target.com"
# Se 429 Too Many Requests → wait e retry
```

**Fix**:

* Verify domain spelling
* Try alternative sources (DuckDuckGo, Baidu)
* Wait 30+ min if rate limited
* Domain potrebbe essere nuovo (\<6 months, limited indexing)

### Error: "API key invalid"

**Causa**: Key typo, expired, quota exhausted, o service down.

**Fix**:

```bash
# Verify API key file exists
cat ~/.theHarvester/api-keys.yaml

# Test key manually
# Shodan example:
curl "https://api.shodan.io/api-info?key=YOUR_KEY"

# Hunter.io example:
curl "https://api.hunter.io/v2/domain-search?domain=example.com&api_key=YOUR_KEY"

# Re-register se necessario
# Revoke old key, generate new
```

### Slow Performance su Large Domains

**Causa**: TheHarvester è sequential (non parallel internally), API latency.

**Optimization**:

```bash
# Limit sources (skip slow ones)
theharvester -d largedomain.com -b google,bing -l 500

# Split execution by source
theharvester -d largedomain.com -b google &
theharvester -d largedomain.com -b bing &
theharvester -d largedomain.com -b shodan &
wait
# Merge dopo completion
```

### Unicode/Encoding Issues

**Causa**: Non-ASCII characters in domain/email output.

**Fix**:

```bash
# Force UTF-8 encoding
export PYTHONIOENCODING=utf-8
theharvester -d target.com -b all

# Or filter output
theharvester -d target.com -b all | iconv -f UTF-8 -t ASCII//TRANSLIT
```

### DNS Brute Not Finding Subdomains

**Causa**: Wordlist insufficient, DNS resolver issues, o target implements wildcard DNS.

**Fix**:

```bash
# Use larger wordlist
theharvester -d target.com --dns-brute \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# Custom DNS resolver
echo "8.8.8.8" > resolvers.txt
echo "1.1.1.1" >> resolvers.txt
theharvester -d target.com --dns-brute --dns-server resolvers.txt

# Check for wildcard DNS
dig random-nonexistent-subdomain-12345.target.com
# Se returns IP → wildcard enabled (brute ineffective)
```

## FAQ

**Q: TheHarvester è legale da usare?**

A: **Sì per OSINT pubblico**. Diventa problematico se:

* Violate ToS di search engine (automated scraping)
* Target ha robots.txt prohibitions (technically)
* Used senza authorization per targeting individuals (privacy laws)

**Sempre** ottenere written authorization per penetration testing.

**Q: Differenza TheHarvester vs Amass?**

A: **TheHarvester** = broad email+subdomain+IP, 38 sources, speed focus, zero config.
**Amass** = DNS-focused, 100+ sources, depth focus, slower ma più comprehensive.

Use TheHarvester per quick initial recon (\<10 min). Use Amass per comprehensive subdomain discovery (20-40 min).

**Q: Come verificare email trovate sono valide?**

A: TheHarvester non valida, solo harvests. Verification methods:

```bash
# SMTP VRFY command
smtp-user-enum -M VRFY -U emails.txt -t mail.target.com

# Email verification services (API)
# Hunter.io, NeverBounce, ZeroBounce

# Manual test (OPSEC risk!)
echo "test" | mail -s "test" target@domain.com
# Check bounce message
```

**Q: Posso usare TheHarvester senza internet?**

A: **No**. TheHarvester queries online sources by design. Offline usage impossible.

**Q: Quanto è aggiornato?**

A: Active development. Latest: **v4.8.2** (January 2026). Check GitHub per updates:

```bash
cd /opt/theHarvester
git pull
```

**Q: TheHarvester supporta IPv6?**

A: **Limited**. Alcuni modules (Shodan) supportano IPv6 queries. Majority sources IPv4-only.

**Q: Come integro con Metasploit?**

A: No native integration. Workflow:

```bash
# Export emails
theharvester -d target.com -b all > emails.txt

# Import in Metasploit auxiliary modules
# Or use directly for phishing payloads
```

**Q: Differenza -l 500 vs -l 5000?**

A: `-l` = limit results **per source**. Higher limit = più comprehensive ma:

* Slower execution
* More API quota consumed
* Diminishing returns oltre 500-1000

## Cheat Sheet Completo

```bash
# INSTALLATION
pip3 install theHarvester                     # Via pip
git clone https://github.com/laramies/theHarvester.git  # From source
sudo apt install theharvester                 # Kali/Debian

# BASIC USAGE
theharvester -d domain.com -b google          # Single source
theharvester -d domain.com -b google,bing     # Multiple sources
theharvester -d domain.com -b all             # All sources
theharvester -d domain.com -b all -l 500      # Limit results

# OUTPUT FORMATS
-f filename.html                              # HTML + XML output
-f filename.json                              # JSON output

# DNS OPERATIONS
--dns-brute                                   # Enable DNS bruteforce
-w wordlist.txt                               # Custom wordlist
--dns-server resolvers.txt                    # Custom DNS servers

# ADVANCED
--virtual-host                                # Virtual host discovery
--screenshot /path/                           # Auto-screenshot subdomains

# COMMON SOURCES (no API key)
google,bing,yahoo,duckduckgo                  # Search engines
crtsh,certspotter                             # Certificate Transparency
dnsdumpster,hackertarget,rapiddns            # DNS enumeration
pgp                                           # PGP keyservers

# API SOURCES (require keys)
shodan,virustotal,securityTrails             # Threat intelligence
hunter                                        # Professional email discovery
github-code                                   # GitHub code search

# API KEY CONFIG
~/.theHarvester/api-keys.yaml                # Config file location

# BATCH OPERATIONS
for d in $(cat domains.txt); do \
  theharvester -d $d -b all -f ${d}.html; \
done

# OUTPUT PARSING
grep -oE '[a-z0-9._-]+@[a-z0-9.-]+' results.html      # Extract emails
grep -oE '[a-z0-9.-]+\.domain\.com' results.html      # Extract subdomains
cat results.json | jq -r '.emails[]'                   # JSON email extraction

# PIPELINE INTEGRATION
theharvester -d target.com -b all | \
  grep "Host:" | awk '{print $2}' | \
  sort -u > subdomains.txt

# PROXY/VPN
proxychains4 theharvester -d target.com -b all
torsocks theharvester -d target.com -b google
export ALL_PROXY=socks5://127.0.0.1:9050

# OPSEC
- Use VPN/proxy for all operations
- Throttle requests (sleep between scans)
- Randomize User-Agent (code modification)
- Avoid --dns-brute unless authorized
- Rotate API keys per engagement
```

## Perché rilevante oggi (2026)

TheHarvester rimane first-choice reconnaissance tool perché **speed-to-intelligence ratio** imbattibile per time-constrained engagements — 90 secondi execution produce 80% informazioni necessarie decidere attack vector, dove SpiderFoot richiede 30+ minuti setup+scan. Zero-config design elimina friction adoption per junior pentester e red team con tight timeline (1-2 week engagements dove ogni ora conta). Email harvesting capability unica nel formato: nessun altro tool OSINT combina PGP keyserver + LinkedIn scraping + search engine + breach databases in single command execution, critical per building spear-phishing target lists. Scriptability via CLI + parseable output alimenta automation pipeline (CI/CD security, continuous monitoring) che GUI-based tools non supportano nativamente. Active maintenance (monthly releases) assicura data source freshness quando API/scraping endpoints cambiano frequentemente — tool abbandonati diventano ineffective rapidamente.

## Differenza rispetto ad alternative

| Feature              | TheHarvester       | Amass               | Subfinder       | Shodan CLI      | Metagoofil        |
| -------------------- | ------------------ | ------------------- | --------------- | --------------- | ----------------- |
| **Primary Focus**    | Email + Subdomain  | Subdomain depth     | Subdomain speed | IP intelligence | Document metadata |
| **Sources**          | 38+ broad          | 100+ DNS-focused    | 40+ passive     | Shodan only     | Google dorks      |
| **Speed**            | ★★★★★ (\<2 min)    | ★★☆☆☆ (20-40 min)   | ★★★★★ (\<1 min) | ★★★★★ (instant) | ★★★☆☆ (5-15 min)  |
| **Email Discovery**  | ★★★★★ Core         | ★☆☆☆☆ Limited       | ❌ None          | ⚠️ Limited      | ❌ None            |
| **Subdomain Enum**   | ★★★★☆ Good         | ★★★★★ Best-in-class | ★★★★★ Excellent | ⚠️ Indirect     | ❌ None            |
| **DNS Brute**        | ✅ Integrated       | ✅ Advanced          | ❌ Passive only  | ❌ No            | ❌ No              |
| **API Required**     | ⚠️ Optional        | ⚠️ Optional         | ⚠️ Optional     | ✅ Required      | ❌ No              |
| **Setup Complexity** | ★☆☆☆☆ Zero         | ★★☆☆☆ Moderate      | ★☆☆☆☆ Minimal   | ★☆☆☆☆ Minimal   | ★☆☆☆☆ Minimal     |
| **Best For**         | Quick recon, email | Complete subdomain  | Speed, CI/CD    | IP/port intel   | Metadata OSINT    |

**Use TheHarvester quando**: Quick recon (\<30 min), email harvesting priority, no API budget, learning OSINT basics, need scriptable CLI tool.

**Use Amass quando**: Comprehensive subdomain enumeration è absolute priority, budget tempo 1+ hour, need maximum depth vs breadth.

**Use Subfinder quando**: Speed massimo (seconds), subdomain-only focus sufficient, CI/CD integration, massive scale (100+ domains daily).

**Use Shodan CLI quando**: IP/port intelligence primario, già have Shodan subscription, targeting IoT/ICS devices, need hosted service data.

**Use Metagoofil quando**: Document metadata focus (author, software versions), no subdomain/email needed, specific file type targeting.

## Hardening / Mitigazione

TheHarvester raccoglie **publicly available data** — difesa è exposure minimization:

**Email Protection**:

* No email pubbliche su website (use contact forms)
* Email obfuscation: `name [at] domain [dot] com`
* Separate email per servizi pubblici vs internal
* SPF/DKIM/DMARC prevent spoofing (ma non harvesting)

**Subdomain Management**:

* Decommission unused subdomains da public DNS
* Wildcard DNS disable (prevent enumeration confirmation)
* Certificate order minimize: use SAN cert vs multiple single-domain
* Internal-only subdomain via split-horizon DNS

**Employee OPSEC Training**:

* LinkedIn profile limit job details, no email pubbliche
* PGP key upload awareness (publicly harvestable)
* GitHub commit email privacy settings
* Twitter/social mention awareness

**Monitoring & Detection**:

* Google Alerts: `site:yourdomain.com email`
* Certificate Transparency monitoring (certstream)
* Breach notification (HaveIBeenPwned API)
* Rate limiting anomaly detection (search engine query patterns)

**Non Mitigabile**:

* Historical data già scraped/indexed
* Third-party site mentions (forums, directories)
* Public business listings (Yellow Pages, etc.)
* Government/regulatory filings

## OPSEC e Detection

**Rumorosità**: Bassa-Media. TheHarvester non interagisce direttamente con target (eccetto DNS brute).

**Detection Indicators**:

**Search Engine Level**:

* Sequential queries `site:domain.com filetype:*`
* User-Agent: `python-requests` (fingerprintable)
* Source IP correlation cross-platform (Google → Bing → Yahoo stesso IP)

**API Service Level**:

* Shodan: query logged con API key identity
* Hunter.io: search history visible in dashboard
* VirusTotal: API access logs
* SecurityTrails: query logs per account

**DNS Level** (solo se --dns-brute):

* Spike query volume verso authoritative nameserver
* Pattern: sequential A record lookups
* Recursive resolver logs (8.8.8.8, 1.1.1.1)

**Target-Side**: **ZERO detection** per passive sources. **HIGH detection** per DNS brute.

**Evasion Effectiveness**:

| Technique                | Efficacy | Effort | Cost          |
| ------------------------ | -------- | ------ | ------------- |
| Proxy/VPN                | High     | Low    | $5-10/month   |
| User-Agent randomization | Medium   | Low    | Free          |
| Rate limiting manual     | Medium   | High   | Free          |
| API key rotation         | High     | Medium | Service costs |
| Distributed execution    | High     | High   | VPS costs     |

**Detection Likelihood**:

* Passive-only: **10-15%** (API service logs only)
* With DNS brute: **70-80%** (target DNS logs)

**Cleanup**:

```bash
# Local artifacts
rm -f *.html *.xml *.json
history -c  # Clear bash history

# No artifacts su target system (passive tool)
```

**OPSEC Rating**: 8/10 (passive), 3/10 (con DNS brute attivo).

***

**Disclaimer**: TheHarvester deve essere utilizzato esclusivamente su target per i quali si possiede autorizzazione scritta esplicita. L'uso per scraping non autorizzato può violare Terms of Service di search engines e data providers, leggi anti-scraping nazionali, e privacy regulations (GDPR, CCPA). Verificare compliance legale prima di ogni utilizzo. Repository ufficiale: [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)

Vuoi supportare HackIta? Visita [https://hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [https://hackita.it/servizi](https://hackita.it/servizi).
