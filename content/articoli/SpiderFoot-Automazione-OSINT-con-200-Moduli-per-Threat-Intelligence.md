---
title: 'SpiderFoot: Automazione OSINT con 200+ Moduli per Threat Intelligence'
slug: spiderfoot
description: 'SpiderFoot è uno strumento OSINT automatizzato con oltre 200 moduli per la raccolta e correlazione di intelligence su domini, IP, email e breach. Guida completa all’uso in ambito penetration testing e threat intelligence.'
image: /Gemini_Generated_Image_saexy2saexy2saex.webp
draft: true
date: 2026-02-08T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - osint
  - threat-intelligence
featured: false
---

SpiderFoot automatizza la raccolta di intelligence da oltre 200 sorgenti pubbliche attraverso un'architettura modulare publisher-subscriber che correla automaticamente entità tra domini, IP, email, breach e social media. Sviluppato da Steve Micallef dal 2012 e attivamente mantenuto con rilasci trimestrali, SpiderFoot offre sia GUI web-based che CLI per scan programmabili, rendendolo strumento primario per mapping attack surface in penetration testing e continuous security monitoring. A differenza di tool single-purpose come TheHarvester, SpiderFoot costruisce grafi relazionali completi tra asset identificati, evidenziando automaticamente finding ad alto rischio tramite correlation engine YAML-configurabile con 37 regole predefinite.

### Cosa imparerai

Questo articolo copre installazione standalone e Docker, configurazione moduli per passive/active reconnaissance, setup API key per servizi premium (Shodan, VirusTotal, HaveIBeenPwned), creazione scan profile custom, interpretazione risultati tramite dashboard e graph view, export formati multipli (CSV/JSON/GEXF), integrazione CLI in pipeline automation, best practices detection evasion, e confronto operativo con [https://hackita.it/articoli/recon-ng](https://hackita.it/articoli/recon-ng), [https://hackita.it/articoli/maltego](https://hackita.it/articoli/maltego) e tool OSINT alternativi per selezionare approccio ottimale per scenario specifico.

## Setup e Installazione

SpiderFoot richiede **Python 3.9+** e dipendenze specificate in requirements.txt. Versione corrente: **v4.0** (gennaio 2024). Su Kali Linux 2023.4+:

```bash
sudo apt update && sudo apt install spiderfoot
```

Installazione da sorgente (metodo consigliato per ultima versione):

```bash
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip3 install -r requirements.txt
python3 ./sf.py -l 127.0.0.1:5001
```

**Deployment Docker** (production-ready):

```bash
docker pull spiderfoot/spiderfoot:latest
docker run -p 5001:5001 spiderfoot/spiderfoot
```

Verifica funzionamento navigando a `http://127.0.0.1:5001`:

```
SpiderFoot 4.0
[*] Web server started on 127.0.0.1:5001
[*] Navigate to http://127.0.0.1:5001 in your browser
```

Dashboard mostra:

* **Scans**: cronologia scan precedenti
* **New Scan**: creazione nuovo scan
* **Settings**: configurazione moduli e API keys
* **Documentation**: inline help

**Configurazione iniziale critica**:

```bash
# File di configurazione
nano spiderfoot/conf/default.ini

# Parametri chiave
[global]
__database = sfdb.sqlite
__modules = modules/
__logfile = sf.log
__correlationrulesdir = correlationrules/
```

**Requisiti sistema**:

* RAM: minimo 2GB, raccomandato 4GB per scan large-scale
* Storage: 500MB-5GB in base a scan history
* Network: connessione stabile per API queries (no strict bandwidth requirement)

## Uso Base

Workflow SpiderFoot segue pattern: target selection → scan type → module configuration → execution → results analysis.

### Creazione Scan Nuovo

Navigare a **New Scan** nella dashboard:

```
1. Target Seed
   - Domain Name: example.com
   - IP Address: 203.0.113.1
   - Subnet: 203.0.113.0/24
   - Email: admin@example.com
   - Human Name: "John Doe"
   - Username: johndoe
   - Phone Number: +39 123 456789
   - Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

2. Scan Name (opzionale): target_assessment_2026

3. Use Case (scan profile):
   - All: esegue TUTTI i moduli (lento, completo)
   - Footprint: mapping pubblico senza attive probing
   - Investigate: ricerca indicatori malicious + footprinting
   - Passive: ZERO interazione diretta con target

4. Click "Run Scan Now"
```

**Output esecuzione** — sezione "Scans" mostra:

```
Scan Name: target_assessment_2026
Target: example.com
Status: RUNNING (23%)
Started: 2026-02-06 10:15:34
Found: 127 results across 18 data types
```

Real-time progress bar aggiornato ogni 2 secondi. Scan può richiedere 5-90 minuti in base a use case e target size.

### Module Selection Manuale

Alternative a use case predefiniti: selezione moduli granulare.

In "New Scan", selezionare "By Required Data" o "By Modules":

**By Required Data** — seleziona cosa cercare:

```
✓ Email Addresses
✓ IP Addresses
✓ Subdomains
✓ Social Media Profiles
✓ Breach Records
□ Phone Numbers
□ Physical Addresses
□ SSL Certificates
```

SpiderFoot abilita automaticamente moduli necessari per target selezionati.

**By Modules** — controllo fine-grained:

```
DNS:
  ✓ sfp_dns: DNS resolution
  ✓ sfp_dnsbrute: DNS bruteforcing
  ✓ sfp_dnsresolve: Reverse DNS

Email:
  ✓ sfp_hunter: Hunter.io email search
  ✓ sfp_emailformat: Email format guessing
  □ sfp_pgp: PGP key server search

Threat Intelligence:
  ✓ sfp_threatcrowd: ThreatCrowd queries
  ✓ sfp_virustotal: VirusTotal lookups
  ✓ sfp_abuseipdb: AbuseIPDB checks
```

Totale: **200+ moduli** categorizzati in 15 gruppi.

### Interpretazione Risultati

Post-scan, navigare a **Browse** tab per visualizzare findings:

```
Data Type Breakdown:
- IP_ADDRESS: 45
- INTERNET_NAME: 89
- EMAILADDR: 23
- SSL_CERTIFICATE_RAW: 12
- WEBSERVER_BANNER: 8
- CO_HOSTED_SITE: 156
- LEAKED_CREDENTIALS: 3
- MALICIOUS_IPADDR: 1
```

**Drill-down per tipo**:

Click su "LEAKED\_CREDENTIALS" mostra:

```
admin@example.com | LinkedIn breach (2021)
support@example.com | Collection #1 (2019)
john.doe@example.com | Adobe breach (2013)
```

**Graph View** — rappresentazione visuale connessioni:

```
[example.com]
    ├── [IP: 203.0.113.1]
    │   ├── [Co-hosted: site1.com]
    │   └── [Co-hosted: site2.com]
    ├── [admin@example.com]
    │   └── [LinkedIn Breach 2021]
    └── [Subdomain: dev.example.com]
        └── [IP: 203.0.113.45]
```

Graph exportabile in formato **GEXF** per analisi in Gephi.

## Tecniche Operative in Pentesting

### Scenario 1: External Attack Surface Mapping

**Obiettivo**: Identificare tutti asset pubblici di targetcorp.com per penetration test esterno.

```bash
# CLI usage
python3 sf.py -s targetcorp.com -u footprint -o csv
```

**Output atteso** (footprint use case):

```
[*] Target: targetcorp.com
[*] Starting scan with 'Footprint' profile...
[*] Loaded 78 modules

Module: sfp_dns
[+] Found: mail.targetcorp.com (203.0.113.10)
[+] Found: www.targetcorp.com (203.0.113.11)
[+] Found: vpn.targetcorp.com (203.0.113.12)

Module: sfp_sslcert
[+] Found: *.targetcorp.com (wildcard cert)
    Issuer: Let's Encrypt
    Expiry: 2026-05-15

Module: sfp_shodan
[+] Found: 203.0.113.10 running Microsoft Exchange 2019
[+] Found: Open port 443/tcp on 203.0.113.11

Module: sfp_hunter
[+] Found: admin@targetcorp.com
[+] Found: support@targetcorp.com
[+] Found: ceo@targetcorp.com
```

**Timeline realistica**: 15-20 minuti per domain medio, 45-60 minuti per organizzazione enterprise.

**Cosa fare se fallisce**:

* Errore "API rate limit": configurare API keys in Settings
* Nessun risultato: verificare domain typo, controllare che sia pubblicamente risolvibile con `dig targetcorp.com`
* Timeout connessione: aumentare timeout in sf.conf `__timeout = 60`

### Scenario 2: Credential Leak Investigation

**Obiettivo**: Verificare se email aziendali sono presenti in data breach noti.

GUI workflow:

```
1. New Scan
   Target: targetcorp.com
   Use Case: Investigate

2. Settings → Modules → abilita:
   ✓ sfp_haveibeenpwned
   ✓ sfp_leakix
   ✓ sfp_dehashed
   ✓ sfp_intelx

3. Run Scan
```

**Output**:

```
[LEAKED_CREDENTIALS]
- john.doe@targetcorp.com
  Breaches: LinkedIn (2021), Dailymotion (2016)
  Password hash: 5f4dcc3b5aa765d61d8327deb882cf99

- admin@targetcorp.com
  Breaches: Collection #1 (2019)
  Cleartext password: P@ssw0rd123
```

**Azioni post-discovery**:

1. Verificare password riutilizzata su servizi aziendali (VPN, O365, SSO)
2. Forzare password reset per account compromessi
3. Implementare MFA dove assente
4. Monitorare login anomali post-disclosure

**Troubleshooting**:

* HaveIBeenPwned richiede API key (free tier: 1 req/1.5sec)
* Dehashed richiede account premium ($5/month)
* False positive: verificare timestamp breach vs data creazione account

### Scenario 3: Subdomain Enumeration Massivo

**Obiettivo**: Enumerare TUTTE le subdomain di target per identificare staging/dev environments.

Configurazione avanzata:

```bash
# Creare file custom module config
nano spiderfoot/modules.ini

# Modificare sfp_dnsbrute settings
[sfp_dnsbrute]
enabled = True
wordlist = /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
threads = 50
```

GUI execution:

```
1. New Scan: example.com
2. By Modules: seleziona solo DNS-related
   ✓ sfp_dns
   ✓ sfp_dnsbrute
   ✓ sfp_certspotter (Certificate Transparency)
   ✓ sfp_crtsh (crt.sh database)
   ✓ sfp_dnsdumpster

3. Run Scan
```

**Output atteso**:

```
[INTERNET_NAME]
- www.example.com
- mail.example.com
- dev.example.com ← INTERESSANTE
- staging.example.com ← INTERESSANTE
- test-api.example.com ← INTERESSANTE
- admin.example.com ← CRITICO
... (250+ subdomains trovati)
```

**Timeline**: 20-45 minuti con wordlist 110k, 5-10 minuti con top 10k.

**Export risultati** per active scanning successivo:

```bash
# Da GUI: Browse → Export → CSV
# Filtrare solo INTERNET_NAME con grep
grep "INTERNET_NAME" results.csv | cut -d',' -f2 > subdomains.txt

# Feed a nmap
nmap -iL subdomains.txt -p 80,443,8080,8443 -sV -oA nmap_results
```

## Tecniche Avanzate

### Custom Module Development

SpiderFoot supporta moduli Python custom. Struttura base:

```python
# modules/sfp_custom_example.py
from spiderfoot import SpiderFootPlugin, SpiderFootEvent

class sfp_custom_example(SpiderFootPlugin):
    meta = {
        'name': 'Custom Example Module',
        'summary': 'Descrizione funzionalità',
        'flags': ['apikey'],  # se richiede API
        'useCases': ['Footprint', 'Investigate'],
        'categories': ['Passive DNS'],
        'dataSource': {
            'website': 'https://api.example.com',
            'model': 'FREE_AUTH_UNLIMITED',
            'references': [],
            'apiKeyInstructions': []
        }
    }

    opts = {
        'api_key': '',
        'timeout': 30
    }

    optdescs = {
        'api_key': 'API key per servizio custom',
        'timeout': 'Timeout richieste HTTP'
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['DOMAIN_NAME']  # eventi da monitorare

    def producedEvents(self):
        return ['RAW_RIR_DATA', 'INTERNET_NAME']  # eventi generati

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return
        self.results[eventData] = True

        # Custom logic
        api_url = f"https://api.example.com/lookup?domain={eventData}"
        res = self.sf.fetchUrl(api_url, timeout=self.opts['timeout'])

        if res['content']:
            evt = SpiderFootEvent('INTERNET_NAME', 
                                  f"subdomain.{eventData}", 
                                  self.__name__, event)
            self.notifyListeners(evt)
```

**Reload moduli** senza restart:

```bash
# GUI: Settings → Reload All Modules
# CLI: restart sf.py
```

### Correlation Rules Custom

SpiderFoot usa file YAML per definire correlation automatiche. Esempio:

```yaml
# correlationrules/custom_high_risk.yaml
---
- id: HIGH_RISK_EXPOSED_SERVICE
  name: "Exposed High-Risk Service"
  risk: HIGH
  description: "Servizio critico esposto pubblicamente"
  trigger:
    event_type: TCP_PORT_OPEN
    port: [3389, 22, 445, 1433, 3306]
  action: ALERT

- id: BREACH_WITH_ADMIN_ACCOUNT
  name: "Admin Account in Data Breach"
  risk: CRITICAL
  description: "Account amministrativo trovato in breach"
  trigger:
    event_type: LEAKED_CREDENTIALS
    email_pattern: "admin@|root@|administrator@"
  action: ALERT
```

Correlation engine processa automatically e evidenzia in rosso nella dashboard.

### Headless Automation per CI/CD

SpiderFoot integrato in pipeline continuous security:

```bash
#!/bin/bash
# daily_osint_scan.sh

DOMAIN="$1"
OUTPUT_DIR="/var/scans/$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

# Launch scan via CLI
python3 /opt/spiderfoot/sf.py \
    -s $DOMAIN \
    -u footprint \
    -o csv \
    -f $OUTPUT_DIR/results.csv \
    -q  # quiet mode

# Parse critical findings
grep -i "LEAKED_CREDENTIALS\|MALICIOUS" $OUTPUT_DIR/results.csv > $OUTPUT_DIR/alerts.txt

# Notify se trovati
if [ -s $OUTPUT_DIR/alerts.txt ]; then
    mail -s "OSINT Alert for $DOMAIN" security@company.com < $OUTPUT_DIR/alerts.txt
fi
```

**Cron scheduling**:

```bash
crontab -e
0 2 * * * /opt/scripts/daily_osint_scan.sh targetdomain.com
```

### Integration con External Tools

**SpiderFoot → Maltego**:

```bash
# Export GEXF format da GUI
Browse → Export → GEXF

# Import in Maltego tramite custom transform o manual import
```

**SpiderFoot → Elasticsearch**:

```python
# Custom output module
import json
from elasticsearch import Elasticsearch

es = Elasticsearch(['http://localhost:9200'])

with open('results.json') as f:
    data = json.load(f)
    for record in data:
        es.index(index='osint-findings', document=record)
```

**TheHarvester → SpiderFoot**:

```bash
# TheHarvester genera lista email
theharvester -d target.com -b all -f emails.html

# Parse HTML, extract email, feed a SpiderFoot
# SpiderFoot scan singole email per breach/social profiles
```

## Integrazione Toolchain

### SpiderFoot nella Recon Chain

Pipeline completa OSINT:

```
1. Passive DNS (crt.sh, SecurityTrails)
   ↓
2. SpiderFoot (subdomain enum + correlation)
   ↓ export subdomains
3. Amass (aggressive DNS brute)
   ↓ merge results
4. Aquatone (HTTP screenshot)
   ↓ identify interesting targets
5. Nmap (active service scan)
   ↓
6. Nuclei (vuln scanning)
```

**Script integration**:

```bash
#!/bin/bash
TARGET=$1

# Stage 1: SpiderFoot
python3 sf.py -s $TARGET -u footprint -o csv -f spider_out.csv

# Extract subdomains
grep "INTERNET_NAME" spider_out.csv | cut -d',' -f2 > subs_spider.txt

# Stage 2: Amass
amass enum -passive -d $TARGET -o subs_amass.txt

# Merge & deduplicate
cat subs_spider.txt subs_amass.txt | sort -u > all_subs.txt

# Stage 3: Aquatone
cat all_subs.txt | aquatone -out aquatone_results/

# Stage 4: Nmap
nmap -iL all_subs.txt -p- -sV -oA nmap_full
```

### Comparazione Operativa

| Feature            | SpiderFoot                      | Recon-ng              | Maltego                | TheHarvester        |
| ------------------ | ------------------------------- | --------------------- | ---------------------- | ------------------- |
| **Moduli**         | 200+                            | 100+                  | 50+ transforms         | 38 sources          |
| **Automation**     | ★★★★★                           | ★★★★☆                 | ★★☆☆☆                  | ★★★☆☆               |
| **GUI**            | Web-based                       | CLI only              | Desktop GUI            | CLI only            |
| **Correlation**    | Automatica (YAML rules)         | Manuale (SQL queries) | Visuale (graph)        | Nessuna             |
| **API Coverage**   | Ampia (free+paid)               | Media                 | Extensive ($$)         | Limitata            |
| **Stealth**        | Configurabile per modulo        | Alta                  | Bassa (molte query)    | Media               |
| **Learning Curve** | Bassa                           | Media                 | Alta                   | Bassa               |
| **Best For**       | Automated continuous monitoring | Scriptable workflows  | Investigazioni visuali | Quick one-shot enum |

**Quando usare SpiderFoot**:

* Need correlazione automatica cross-source
* Continuous security monitoring
* Team non-technical (GUI intuitive)
* Attack surface management enterprise

**Quando evitare**:

* Need stealth massimo (→ passive manual OSINT)
* Budget zero API (molti moduli richiedono keys)
* Investigazioni visual-heavy (→ Maltego)

## Scenari Pratici Completi

### Scenario A: Bug Bounty Reconnaissance

**Contesto**: Bug bounty su acmecorp.com, scope: \*.acmecorp.com, API endpoints, mobile app backend.

**Execution**:

```
Day 1 Morning (2h):
1. SpiderFoot scan "All" su acmecorp.com
2. Export subdomain list → feed a ffuf per directory brute
3. Identify API endpoints da WEBSERVER_BANNER

Day 1 Afternoon (3h):
4. SpiderFoot scan singoli subdomain interessanti (dev., staging., api.)
5. Check breach per admin@ email trovate
6. Social engineering recon su employee tramite LinkedIn correlation

Timeline: 5h total
Risultati: 300+ subdomain, 15 API endpoints, 3 leaked admin creds
```

**Output critico**:

```
dev-api.acmecorp.com → Swagger UI exposed
staging.acmecorp.com → Basic Auth admin:admin
admin@acmecorp.com → Password in Collection #1: Password123!
```

**Bug submitted**: P2 (Information Disclosure), P4 (Credentials in breach)

### Scenario B: M\&A Due Diligence

**Contesto**: Security audit pre-acquisition di startup tech.

**Workflow**:

```
Week 1:
- SpiderFoot "Investigate" su tutti domain aziendali
- Identify exposed services (RDP, SSH, databases)
- Enumerate employee email + check against breach DB
- Social media footprint analysis

Week 2:
- Generate report con findings categorizzati per risk level
- Quantify remediation effort per issue
- Present to stakeholder con visual graph

Output formato: Excel pivot table con:
- Asset inventory completo
- Risk scoring (Critical/High/Medium/Low)
- Remediation roadmap
```

**Finding esempio**:

```
CRITICAL:
- 3 SQL Server instances pubblicamente accessibili (port 1433)
- CEO email in 5 different breach con password riutilizzata

HIGH:
- 15 subdomain con SSL cert scaduti
- S3 bucket pubblico con backups database
```

### Scenario C: Red Team Passive Recon

**Contesto**: Red team engagement con strict OPSEC — NO active probing.

**Constraints**:

* Zero direct interaction con target network
* Solo OSINT passive
* No account creation su servizi target

**SpiderFoot config**:

```
Use Case: Passive (critical!)

Moduli enabled:
✓ DNS (passive only via public resolvers)
✓ Certificate Transparency
✓ Shodan (via API, no direct scan)
✓ Breach databases
✗ Port scanning
✗ DNS brute forcing
✗ Web crawling
```

**Timeline**: 7 giorni continuous passive collection

**Output utilizzabile**:

```
Employee list → Spear phishing targets
Email formats → Username enumeration
Tech stack → Exploit selection
Leaked VPN creds → Initial access vector
```

**Red team feedback**: SpiderFoot passive mode fornito 40% intelligence necessaria senza trigger IDS.

## Detection & Evasion OPSEC

### Blue Team Detection

SpiderFoot genera traffic pattern rilevabili:

**Network-Level Indicators**:

* Spike query DNS verso DNS pubblici (8.8.8.8, 1.1.1.1)
* User-Agent: `Mozilla/5.0 (compatible; SpiderFoot/4.0; +https://www.spiderfoot.net)`
* Sequential HTTP requests con timing regolare
* Query pattern: DNS → WHOIS → SSL cert → Port check

**Third-Party Service Logs**:

* Shodan query logs (associati ad API key)
* VirusTotal API access logs
* Hunter.io search history
* Certificate Transparency log access

**Endpoint Detection** (se eseguito su compromised host):

```
Process Name: python3 sf.py
Network Connections: 50+ concurrent outbound HTTPS
DNS Queries: 200+ unique domains in 10 minuti
User-Agent String: SpiderFoot (signature)
```

### OPSEC Considerations

**1. User-Agent Randomization**

Modificare `spiderfoot/sflib.py`:

```python
def fetchUrl(self, url, ...):
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)...',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...',
        'Mozilla/5.0 (X11; Linux x86_64)...'
    ]
    headers['User-Agent'] = random.choice(user_agents)
```

**2. Request Throttling**

```ini
# sf.conf
[global]
__requestdelay = 3  # seconds tra requests
__maxthreads = 5    # limit concurrent connections
```

**3. Proxy Rotation**

```bash
# Via SOCKS proxy
ALL_PROXY=socks5://127.0.0.1:9050 python3 sf.py -s target.com

# Tor integration
apt install tor
service tor start
# Modifica sf.conf per usare 127.0.0.1:9050
```

**4. Distributed Scanning**

Eseguire SpiderFoot da multiple VPS:

```bash
# VPS 1: DNS modules only
# VPS 2: Email modules only
# VPS 3: Social media modules only
# Merge results offline
```

**5. API Key Rotation**

Usare multiple API key per stesso servizio, rotate automaticamente:

```python
# Custom module modificato
api_keys = ['key1', 'key2', 'key3']
current_key = api_keys[self.request_count % len(api_keys)]
```

## Performance & Scaling

### Single Target vs Multi-Target

**Single domain** (acmecorp.com):

* Footprint scan: 10-15 minuti
* All scan: 45-90 minuti
* Results: 200-500 data points
* DB size: 10-50 MB

**Multi-domain** (50 domains):

* Sequential scans: 40-75 ore
* Parallel scans (5 concurrent): 8-15 ore
* DB size: 500 MB - 2.5 GB

**Optimization**:

```bash
# Parallel execution con GNU parallel
cat domains.txt | parallel -j 5 'python3 sf.py -s {} -u footprint -o csv -f {}.csv'
```

### Resource Consumption

Monitoring durante scan "All" su domain medio:

```
CPU: 40-60% single core (Python GIL限制)
RAM: 500 MB - 1.5 GB peak
Network: 50-200 KB/s outbound
Disk I/O: Minimal (SQLite writes ogni 10 sec)
```

**Bottleneck principale**: API rate limits, non risorse locali.

### Scaling Strategies

**Database optimization**:

```sql
-- Periodic VACUUM per ridurre DB size
sqlite3 spiderfoot/sfdb.db "VACUUM;"

-- Index creation per query performance
CREATE INDEX idx_results_data ON tbl_scan_results(scan_instance_id, data);
```

**Headless deployment** su server dedicato:

```yaml
# docker-compose.yml
version: '3'
services:
  spiderfoot:
    image: spiderfoot/spiderfoot:latest
    ports:
      - "5001:5001"
    volumes:
      - ./sfdb:/home/spiderfoot/spiderfoot
      - ./modules:/home/spiderfoot/spiderfoot/modules
    environment:
      - SF_HOST=0.0.0.0
      - SF_PORT=5001
    restart: unless-stopped
```

**Load balancing** per team multi-user:

```
Nginx Reverse Proxy
    ↓
[SpiderFoot Instance 1] [SpiderFoot Instance 2] [SpiderFoot Instance 3]
    ↓                       ↓                       ↓
Shared PostgreSQL Database
```

## Troubleshooting

### Errore: "Module failed to load"

**Causa**: Dipendenza Python mancante per modulo specifico.

**Fix**:

```bash
# Identificare modulo fallito nel log
tail -f spiderfoot/sf.log | grep ERROR

# Esempio: sfp_shodan richiede shodan library
pip3 install shodan

# Reload modules in GUI
Settings → Reload All Modules
```

### Scan bloccato al 0%

**Causa**: No moduli abilitati per target type.

**Fix**:

```
1. Verify target format corretto (domain vs IP vs email)
2. Check module selection:
   - "Footprint" richiede domain name, non IP
   - Email scan richiede explicit email module selection
3. Check logs: sf.log per errori startup
```

### API Rate Limit Exceeded

**Causa**: Troppi request a servizio con free tier limitato.

**Fix**:

```bash
# Temporary: aumenta delay tra requests
[sfp_shodan]
_request_delay = 5  # seconds

# Permanent: upgrade API plan o usa multiple keys
[sfp_virustotal]
api_key_1 = KEY1
api_key_2 = KEY2
# Modify module per rotate
```

### Results non vengono salvati

**Causa**: Permessi database SQLite o disk full.

**Fix**:

```bash
# Check disk space
df -h /path/to/spiderfoot

# Fix permissions
chmod 644 spiderfoot/sfdb.db
chown $(whoami) spiderfoot/sfdb.db

# Test write access
sqlite3 spiderfoot/sfdb.db ".tables"
```

### Memory leak su scan lunghi

**Causa**: Bug noto in alcune versioni per scan >24h.

**Workaround**:

```bash
# Split large scan in smaller chunks
python3 sf.py -s target.com -m sfp_dns,sfp_whois -o csv -f part1.csv
python3 sf.py -s target.com -m sfp_shodan,sfp_virustotal -o csv -f part2.csv
# Merge results offline
```

## FAQ

**Q: SpiderFoot è rilevabile dal target?**

A: Dipende da use case. "Passive" mode = zero detection. "Footprint/All" = possibile detection via:

* Certificate Transparency log access
* Shodan API queries (logged con API key)
* Active port scan (se enabled)

Mitigazione: proxy/VPN, User-Agent spoofing, request throttling.

**Q: Differenza tra "Footprint" e "Investigate"?**

A: **Footprint** = mapping pubblico (DNS, WHOIS, cert, breach). **Investigate** = Footprint + threat intelligence (malicious IP check, darkweb mentions, reputation scoring).

**Q: SpiderFoot può essere usato per continuous monitoring?**

A: Sì. Deploy Docker + cron job per scan scheduled. Store results in time-series DB (InfluxDB) per trend analysis.

**Q: Come gestire false positive?**

A: Correlation rules permettono whitelist. Esempio:

```yaml
- id: IGNORE_INTERNAL_IPS
  action: IGNORE
  trigger:
    event_type: IP_ADDRESS
    ip_range: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
```

**Q: SpiderFoot può eseguire exploit?**

A: No. SpiderFoot è **recon-only**. Per exploitation usare Metasploit/Cobalt Strike post-recon.

**Q: Quanto costa SpiderFoot HX (versione commerciale)?**

A: SpiderFoot opensource = free. **SpiderFoot HX** = $1,200/anno (single user), enterprise pricing custom. HX aggiunge: multi-tenant, advanced correlation, automated reporting, premium data sources.

**Q: Come exportare risultati per management report?**

A: Browse → Export → CSV/JSON. Parse con Python:

```python
import csv
import json

with open('results.csv') as f:
    reader = csv.DictReader(f)
    critical = [row for row in reader if 'LEAKED' in row['Type'] or 'MALICIOUS' in row['Type']]

with open('executive_summary.json', 'w') as f:
    json.dump({'critical_findings': len(critical), 'details': critical}, f)
```

**Q: SpiderFoot supporta IPv6?**

A: Parzialmente. Alcuni moduli (DNS, Shodan) supportano IPv6. Altri limitati a IPv4.

## Cheat Sheet Finale

```bash
# Installazione
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot && pip3 install -r requirements.txt

# Launch GUI
python3 sf.py -l 127.0.0.1:5001

# CLI scans
python3 sf.py -s target.com -u all          # Full scan
python3 sf.py -s target.com -u footprint    # Passive mapping
python3 sf.py -s target.com -u investigate  # Threat intel
python3 sf.py -s target.com -u passive      # Zero interaction

# Output formats
-o csv                                       # CSV export
-o json                                      # JSON export
-f results.csv                               # Save to file

# Module control
-m sfp_dns,sfp_whois                        # Specific modules only
-t sfp_shodan -m sfp_virustotal             # Exclude modules

# Automation
-q                                           # Quiet mode (no stdout)
--max-threads 10                             # Concurrent threads

# Docker
docker run -p 5001:5001 spiderfoot/spiderfoot

# Headless scan
nohup python3 sf.py -s target.com -u all -o csv -f out.csv -q &

# Database query direct
sqlite3 spiderfoot/sfdb.db "SELECT data FROM tbl_scan_results WHERE type='EMAILADDR';"

# API key management (GUI alternative)
# Edit: spiderfoot/modules/sfp_<module>.py
# Add: 'opts': {'api_key': 'YOUR_KEY'}

# Common module categories
DNS: sfp_dns, sfp_dnsbrute, sfp_dnsresolve
Email: sfp_hunter, sfp_emailformat, sfp_pgp
Breach: sfp_haveibeenpwned, sfp_leakix, sfp_dehashed
Threat: sfp_virustotal, sfp_abuseipdb, sfp_threatcrowd
Social: sfp_twitter, sfp_instagram, sfp_github
SSL: sfp_sslcert, sfp_certspotter, sfp_crtsh
```

## Perché è rilevante oggi (2026)

SpiderFoot mantiene rilevanza in era cloud-native perchè attack surface enterprise è frammentata tra on-premise, cloud pubblico, SaaS e shadow IT — nessun tool singolo copre tutte sorgenti OSINT necessarie senza 200+ integration che SpiderFoot fornisce out-of-box. Automation via correlation engine riduce effort manuale da giorni a ore per assessment iniziale, critico quando red team ha timeline compresse (1-2 settimane). GUI web-based elimina friction per team SOC non-developer, democratizing OSINT che storicamente richiedeva skillset CLI/scripting. Continuous monitoring use case allinea a shift-left security: deploy SpiderFoot headless + webhook integration per alert real-time su nuovi breach/exposed asset prima che diventino vettori attacco. Open-source nature permette customizzazione moduli per data source proprietari/region-specific che tool commerciali ignorano.

## Differenza rispetto ad alternative

| Caratteristica     | SpiderFoot                           | Recon-ng                       | Maltego                                     | TheHarvester               |
| ------------------ | ------------------------------------ | ------------------------------ | ------------------------------------------- | -------------------------- |
| **Approach**       | Automated correlation                | Modular scripting              | Visual investigation                        | Quick enumeration          |
| **Interface**      | Web GUI + CLI                        | CLI only                       | Desktop GUI                                 | CLI only                   |
| **Modules**        | 200+ (auto-discover)                 | 100+ (manual chain)            | 50+ transforms                              | 38 sources (parallel)      |
| **Correlation**    | Automatic (YAML rules)               | Manual (SQL)                   | Visual (graph)                              | None                       |
| **Best Scenario**  | Continuous monitoring, team non-tech | Repeatable workflows, scripted | Complex investigation, relationship mapping | Fast recon, single-purpose |
| **Learning Curve** | 1-2 ore                              | 4-8 ore                        | 16+ ore                                     | 30 minuti                  |
| **Pricing**        | Free / HX $1.2k/yr                   | Free                           | Free / Classic $999 / XL $3k                | Free                       |

**Scegliere SpiderFoot quando**: Serve correlation automatica cross-source, team non ha Python skills, continuous security monitoring richiesto, attack surface >100 asset.

**Evitare quando**: Stealth assoluto necessario (ogni tool automation genera pattern), budget API zero (molti moduli richiedono paid keys), investigation singola one-off dove TheHarvester sufficiente.

## Hardening / Mitigazione

SpiderFoot raccoglie OSINT pubblico — difesa richiede riduzione footprint:

**Minimizzare esposizione subdomain**:

* Rimuovere wildcard DNS (\*. pointings)
* Decommission staging/dev environments da DNS pubblico
* Usare split-horizon DNS (internal-only subdomain)
* Implementare subdomain takeover monitoring

**Breach prevention**:

* Password manager aziendale con unique passwords
* MFA enforcement su tutti servizi esterni
* Breach monitoring proattivo (HaveIBeenPwned Enterprise API)
* Password rotation policy post-breach disclosure

**Metadata sanitization**:

* Strip metadata da PDF/Office docs pubblici
* Disable banner verbosity su web/mail server (HTTP headers, SMTP banner)
* SSL certificate con minimal organization info (DV cert vs OV)

**Social media policy**:

* Employee training su information disclosure LinkedIn/Twitter
* Limit job posting technical detail (stack specifico, versioni)
* Restrict GitHub repository visibility

**Monitoring**:

* Deploy Shodan monitoring per exposed services alert
* Certificate Transparency monitoring via certstream
* Google Alerts per domain mentions + leak

**Non mitigabile**:

* WHOIS pubblico (required per domain registration)
* Certificate Transparency logs (mandatorio CA)
* Historical breach data (già disclosed)

## OPSEC e Detection

**Rumorosità**: Media-Alta. SpiderFoot genera centinaia query API/DNS in timeframe breve, correlabile via traffic analysis.

**Detection Indicators**:

Network-level:

* DNS query burst verso public resolver
* User-Agent: `SpiderFoot/4.0`
* Sequential HTTPS requests (Shodan API, VirusTotal, etc.)
* Certificate Transparency log access patterns

Endpoint (se compromised host):

* Process: `python3 sf.py`
* Network connections: 20-100 concurrent
* Disk: SQLite database writes `sfdb.db`

Third-party logs:

* Shodan query history (API key linkable)
* VirusTotal searches logged
* DNS provider logs (if using recursive resolver)

**Riduzione visibilità**:

1. **Proxy chaining**: Tor/VPN per obfuscate source IP
2. **User-Agent spoofing**: Modificare sflib.py randomize UA
3. **Request throttling**: `__requestdelay` config aumentare a 5-10 sec
4. **Distributed execution**: Multiple VPS con API key separate
5. **Passive-only mode**: Disabilitare tutti active modules
6. **API key hygiene**: Burner email per registrazione servizi

**Cleanup post-scan**:

```bash
# Rimuovere database scan
rm spiderfoot/sfdb.db

# Clear logs
rm spiderfoot/sf.log

# Se Docker, remove container
docker rm -f <container_id>
```

**OPSEC Rating**: 4/10 (out-of-box), 7/10 (con hardening). Intrinsically noisy per design automation, ma configurabile per reduce footprint.

***

**Disclaimer**: SpiderFoot deve essere utilizzato esclusivamente su domini e sistemi per i quali si possiede autorizzazione esplicita scritta. L'uso non autorizzato di strumenti OSINT può violare termini di servizio di API provider, privacy regulations (GDPR/CCPA), e leggi anti-hacking nazionali. Verificare compliance legale prima di ogni engagement. Repository ufficiale: [https://github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot)

Vuoi supportare HackIta? Visita [https://hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [https://hackita.it/servizi](https://hackita.it/servizi).
