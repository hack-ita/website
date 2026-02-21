---
title: 'ReconSpider: Automated Web Recon e OSINT Crawler'
slug: reconspider
description: >-
  ReconSpider è uno strumento di web reconnaissance che raccoglie email,
  metadati e informazioni pubbliche tramite crawling automatico.
image: /Gemini_Generated_Image_c0i9crc0i9crc0i9.webp
draft: false
date: 2026-02-22T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - osint
---

### Introduzione

ReconSpider è un **framework Python per automated OSINT (Open Source Intelligence)** che aggrega dati da multiple fonti pubbliche in un'unica interfaccia. Invece di manually querying Google, social media platforms, WHOIS databases, e altri servizi, ReconSpider automatizza il processo e genera comprehensive reports su target domains, companies, e individuals.

Il tool integra con 50+ public APIs e web scraping engines per raccogliere: email addresses, social media profiles, domain registration data, IP geolocation, technology stack, breached credentials, e public documents. Output è structured JSON perfetto per subsequent analysis o integration con altri security tools.

ReconSpider risolve il problema della OSINT fragmentation: devi visitare 10+ websites, create accounts, learn diverse APIs, handle rate limiting. ReconSpider abstraction layer gestisce tutte queste complessità, offrendo unified interface per comprehensive target profiling in minuti invece di ore.

Il framework è particolarmente useful per social engineering preparation, bug bounty reconnaissance, e pre-engagement information gathering dove devi rapidamente build complete picture del target senza direct interaction. API integrations significa data is sempre fresh e automated, eliminando manual copy-paste errors.

In questo articolo imparerai come usare ReconSpider per complete OSINT profiling, interpretare multi-source aggregated results, customize con proprietary data sources, e integrate nel tuo reconnaissance pipeline. Vedrai scenari reali dove OSINT automation ha revealed critical information per successful penetration tests.

ReconSpider si posiziona nella kill chain in **Reconnaissance → Information Gathering** fase, prima di direct target interaction.

***

## 1️⃣ Setup e Installazione

### Requisiti

```bash
# Python 3.6+
python3 --version

# pip per dependencies
sudo apt install python3-pip

# Git
git --version
```

### Installazione

```bash
# Clone repository
git clone https://github.com/bhavsec/reconspider.git
cd reconspider

# Install dependencies
pip3 install -r requirements.txt

# Verifica
python3 reconspider.py --help
```

**Dependencies principali:**

* `requests` (HTTP API calls)
* `beautifulsoup4` (web scraping)
* `dnspython` (DNS queries)
* `python-whois` (WHOIS lookups)
* `shodan` (Shodan API integration)

### API Keys configuration

ReconSpider supporta multiple optional API keys per enhanced functionality:

```bash
# Edit config.json
nano config.json
```

**config.json:**

```json
{
  "shodan_api_key": "YOUR_SHODAN_KEY",
  "virustotal_api_key": "YOUR_VT_KEY",
  "hunter_api_key": "YOUR_HUNTER_KEY",
  "fullcontact_api_key": "YOUR_FC_KEY",
  "github_token": "YOUR_GITHUB_TOKEN"
}
```

**Ottenere API keys:**

* Shodan: [https://account.shodan.io/](https://account.shodan.io/)
* VirusTotal: [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
* Hunter.io: [https://hunter.io/api](https://hunter.io/api)
* FullContact: [https://www.fullcontact.com/developer/](https://www.fullcontact.com/developer/)
* GitHub: [https://github.com/settings/tokens](https://github.com/settings/tokens)

**Note:** Tool funziona senza API keys ma con reduced functionality (solo public sources).

***

## 2️⃣ Uso Base

### Domain reconnaissance

```bash
python3 reconspider.py -t company.com
```

**Output:**

```
ReconSpider v1.0 - OSINT Automation Framework

[*] Target: company.com
[*] Starting reconnaissance...

[+] WHOIS Information
    Registrar: GoDaddy.com
    Creation Date: 2010-03-15
    Expiration: 2027-03-15
    Registrant: Company Inc.
    Registrant Email: admin@company.com
    Name Servers: ns1.provider.com, ns2.provider.com

[+] DNS Records
    A: 203.0.113.10
    MX: mail.company.com (10)
    TXT: v=spf1 include:_spf.google.com ~all

[+] Subdomain Enumeration
    www.company.com
    api.company.com
    mail.company.com
    dev.company.com
    admin.company.com
    [Total: 47 subdomains]

[+] Email Addresses Found
    admin@company.com
    contact@company.com
    support@company.com
    hr@company.com
    [Total: 15 emails]

[+] Technology Stack
    Web Server: nginx/1.18.0
    Backend: Node.js, Express
    CDN: Cloudflare
    Analytics: Google Analytics

[+] Shodan Results
    Open Ports: 22, 80, 443
    Services: SSH, HTTP, HTTPS
    Vulnerabilities: CVE-2021-3156 (sudo)

[+] Social Media Profiles
    LinkedIn: https://linkedin.com/company/company-inc
    Twitter: @companyofficial
    GitHub: https://github.com/company-org

[*] Report saved to: reports/company_com_20260206.json
```

### Person reconnaissance

```bash
python3 reconspider.py -t john.doe@company.com --person
```

**Output:**

```
[+] Email Intelligence
    Email: john.doe@company.com
    Domain: company.com
    Format: firstname.lastname@domain
    Validation: Valid (SMTP verified)

[+] Data Breach Check
    [!] Found in 3 breaches:
        - Collection #1 (2019)
        - LinkedIn Breach (2021)
        - Compilation of Many Breaches (2020)
    Leaked Passwords: [REDACTED - use --show-passwords]

[+] Social Media Profiles
    LinkedIn: https://linkedin.com/in/johndoe
    Twitter: @johndoe_dev
    GitHub: https://github.com/jdoe

[+] Public Documents
    PDF: Company_Presentation_2024.pdf (contains john.doe@company.com)
    DOCX: Annual_Report_2025.docx (authored by John Doe)

[+] Professional Information
    Position: Senior Developer
    Company: Company Inc.
    Location: San Francisco, CA
    Skills: Python, JavaScript, AWS
```

### Company intelligence

```bash
python3 reconspider.py -t "Company Inc" --company
```

**Output:**

```
[+] Company Profile
    Name: Company Inc.
    Industry: Technology
    Founded: 2010
    Headquarters: San Francisco, CA
    Employees: 500-1000

[+] Domain Assets
    Primary: company.com
    Additional: company.io, company-tech.com

[+] IP Ranges
    203.0.113.0/24 (AS12345)
    198.51.100.0/24 (AS67890)

[+] Email Pattern
    Format: firstname.lastname@company.com
    Confidence: 95%

[+] Key Personnel
    CEO: Jane Smith (jane.smith@company.com)
    CTO: Bob Johnson (bob.johnson@company.com)
    [Total: 25 employees identified]

[+] Technology Stack
    Cloud: AWS (us-west-2, us-east-1)
    CI/CD: Jenkins, GitHub Actions
    Databases: PostgreSQL, Redis
```

***

## 3️⃣ Tecniche Operative (CORE)

### Scenario 1: Pre-engagement OSINT per social engineering

**COMANDO:**

```bash
# Target: techcorp.com
python3 reconspider.py -t techcorp.com --full-scan --output-format json
```

**Flags:**

* `--full-scan`: Attiva tutte le API integrations
* `--output-format json`: Structured output per parsing

**OUTPUT ATTESO:**

```json
{
  "target": "techcorp.com",
  "scan_date": "2026-02-06T10:30:00Z",
  "whois": {
    "registrant_email": "admin@techcorp.com"
  },
  "emails": [
    "john.smith@techcorp.com",
    "sarah.jones@techcorp.com",
    "mike.wilson@techcorp.com"
  ],
  "email_pattern": "firstname.lastname@techcorp.com",
  "employees": [
    {
      "name": "John Smith",
      "position": "IT Manager",
      "linkedin": "https://linkedin.com/in/johnsmith-it",
      "email": "john.smith@techcorp.com"
    }
  ],
  "technologies": [
    "Microsoft Exchange",
    "Cisco VPN",
    "Office 365"
  ]
}
```

**Social Engineering Attack Plan:**

```
Phase 1: Email Crafting
- Target: john.smith@techcorp.com (IT Manager)
- Pretext: Microsoft Exchange security update
- Technologies confirmed: Exchange, O365
- Email format validated: firstname.lastname@

Phase 2: Phishing Email
Subject: [URGENT] Exchange Security Patch Required
From: microsoft-security@outlook.com (spoofed)
Body:
  Dear John,
  
  We've detected a critical vulnerability in your Exchange server
  (version identified via Shodan: Exchange 2016).
  
  Please apply the patch immediately: [malicious link]
  
  Microsoft Security Team

Phase 3: Credential Harvesting
- Link → Fake Microsoft login page
- Captures john.smith@techcorp.com credentials
- Use for VPN access (Cisco VPN confirmed via ReconSpider)
```

**COSA FARE SE FALLISCE:**

1. **Email pattern incorrect:** Try variations (firstnamelastname@, first.last@, f.lastname@). Test con email verification tools.
2. **No employee data found:** LinkedIn scraping può essere rate-limited. Use manual LinkedIn search con company name.
3. **Technology stack unknown:** Shodan API key missing. Register for free tier (100 queries/month).

**Timeline:** 15 minuti ReconSpider scan + 30 minuti social engineering prep

Per approfondire social engineering techniques, consulta [advanced social engineering tactics e pretexting](https://hackita.it/articoli/social-engineering).

***

### Scenario 2: Bug bounty - Asset discovery e email harvesting

**COMANDO:**

```bash
# Massive subdomain + email harvest
python3 reconspider.py -t bugcrowd-target.com --subdomains --emails --save-txt
```

**Flags:**

* `--subdomains`: Focus su subdomain enumeration
* `--emails`: Email harvesting priority
* `--save-txt`: Export plain text lists

**OUTPUT ATTESO:**

```
[*] Subdomain Enumeration (via 5 sources)

crt.sh: 234 subdomains
VirusTotal: 89 subdomains
Shodan: 45 subdomains
Google Dorking: 12 subdomains
DNS Brute Force: 67 subdomains

[+] Unique subdomains: 387
    Saved to: subdomains_bugcrowd-target.txt

[*] Email Harvesting (via 4 sources)

Hunter.io: 45 emails
Google Search: 23 emails
GitHub: 12 emails
Pastebin: 8 emails

[+] Unique emails: 78
    Saved to: emails_bugcrowd-target.txt
```

**Use cases:**

```bash
# Feed subdomains to Aquatone
cat subdomains_bugcrowd-target.txt | aquatone

# Test email addresses per password spraying
cat emails_bugcrowd-target.txt | while read email; do
  # Extract username
  user=$(echo $email | cut -d@ -f1)
  # Try common passwords
  echo "Testing $email with password: Welcome2024!"
done

# GitHub code search per leaked credentials
for email in $(cat emails_bugcrowd-target.txt); do
  echo "Searching GitHub for $email"
  gh search code "$email password" --limit 50
done
```

**COSA FARE SE FALLISCE:**

* **Low subdomain count:** Add custom wordlist: `--subdomain-wordlist custom.txt`
* **Email harvesting blocked:** Hunter.io free tier = 25 searches/month. Use alternative: `theHarvester -d target.com -b google`
* **Rate limiting:** Split execution over multiple days or use premium API plans.

**Timeline:** 20 minuti ReconSpider + 1 ora manual verification

***

### Scenario 3: Red Team - Complete target profiling

**COMANDO:**

```bash
# Comprehensive intelligence gathering
python3 reconspider.py -t redteam-client.com \
  --full-scan \
  --breach-check \
  --social-media \
  --documents \
  --output-format html
```

**Flags:**

* `--breach-check`: Search breached credentials
* `--social-media`: Profile company social presence
* `--documents`: Find public documents (PDF, DOCX, XLSX)
* `--output-format html`: Generate HTML report

**OUTPUT ATTESO (HTML Report):**

```html
<!DOCTYPE html>
<html>
<head><title>OSINT Report: redteam-client.com</title></head>
<body>
  <h1>Target Intelligence Report</h1>
  <h2>Executive Summary</h2>
  <ul>
    <li>Domains: 3 (redteam-client.com, redteam-client.io, rtc-internal.com)</li>
    <li>Subdomains: 156</li>
    <li>Email Addresses: 89</li>
    <li>Breached Credentials: 23</li>
    <li>Public Documents: 45</li>
  </ul>
  
  <h2>Breach Intelligence</h2>
  <table>
    <tr>
      <th>Email</th>
      <th>Breach</th>
      <th>Password</th>
    </tr>
    <tr>
      <td>admin@redteam-client.com</td>
      <td>LinkedIn (2021)</td>
      <td>P@ssw0rd123</td>
    </tr>
    <tr>
      <td>john.doe@redteam-client.com</td>
      <td>Collection #1 (2019)</td>
      <td>Welcome2019!</td>
    </tr>
  </table>
  
  <h2>Document Metadata</h2>
  <ul>
    <li>Network_Diagram_2025.pdf
        <br>Author: IT Department
        <br>Contains: Internal IP addressing (10.10.0.0/16)
    </li>
    <li>Employee_Handbook_2026.docx
        <br>Author: HR Manager (hr@redteam-client.com)
        <br>Contains: VPN access instructions
    </li>
  </ul>
</body>
</html>
```

**Intelligence exploitation:**

```
High-Value Findings:

1. Breached Credentials
   - admin@redteam-client.com : P@ssw0rd123
   - Test on: VPN, Email, Admin panels
   - Password pattern: P@ssw0rd + year
   
2. Internal Network Info
   - IP Range: 10.10.0.0/16 (from leaked PDF)
   - VPN Gateway: vpn.redteam-client.com (from handbook)
   
3. Key Personnel
   - IT Manager: john.doe@redteam-client.com
   - HR Manager: hr@redteam-client.com
   - Social engineering targets identified
   
4. Technology Stack
   - Microsoft environment (Exchange, AD)
   - Cisco VPN
   - AWS infrastructure (us-east-1)
```

**Timeline:** 30 minuti comprehensive scan + 2 ore report analysis

***

## 4️⃣ Tecniche Avanzate

### Custom API integration

ReconSpider è extensible. Aggiungi proprietary data sources:

```python
# modules/custom_api.py

import requests

def custom_lookup(target):
    """
    Query proprietary threat intelligence feed
    """
    api_key = "YOUR_CUSTOM_API_KEY"
    url = f"https://api.custom-ti.com/lookup/{target}"
    
    headers = {"Authorization": f"Bearer {api_key}"}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    return None

# Add to reconspider.py
from modules.custom_api import custom_lookup

results = custom_lookup(target)
if results:
    print("[+] Custom Threat Intelligence")
    print(f"    Risk Score: {results['risk_score']}")
    print(f"    IOCs: {results['iocs']}")
```

### Automated reporting workflow

```bash
#!/bin/bash
# osint_pipeline.sh

TARGET=$1

# ReconSpider OSINT
python3 reconspider.py -t $TARGET --full-scan -o json > /tmp/${TARGET}_osint.json

# Parse results
EMAILS=$(jq -r '.emails[]' /tmp/${TARGET}_osint.json)
SUBDOMAINS=$(jq -r '.subdomains[]' /tmp/${TARGET}_osint.json)

# Feed to other tools
echo "$SUBDOMAINS" | aquatone -out ${TARGET}_aquatone

# Credential testing
for email in $EMAILS; do
  echo "Testing $email"
  # [credential spray logic]
done

# Generate executive summary
python3 generate_summary.py /tmp/${TARGET}_osint.json ${TARGET}_aquatone/ > ${TARGET}_final_report.html
```

### Continuous monitoring

```bash
# Schedule periodic scans
# crontab -e

# Daily OSINT refresh
0 2 * * * cd /opt/reconspider && python3 reconspider.py -t company.com --full-scan --output-format json > /var/log/osint/$(date +\%Y\%m\%d)_company.json

# Alert on new findings
0 3 * * * python3 /opt/scripts/compare_osint.py /var/log/osint/$(date -d yesterday +\%Y\%m\%d)_company.json /var/log/osint/$(date +\%Y\%m\%d)_company.json
```

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: External pentest - Target profiling

**COMANDO:**

```bash
python3 reconspider.py -t external-target.com --full-scan --breach-check
```

**OUTPUT ATTESO:**

```
[+] Domain Intelligence
    Registrar: GoDaddy
    Name Servers: Cloudflare
    
[+] Infrastructure
    IP: 104.16.1.23 (Cloudflare CDN)
    Origin IP: 203.0.113.50 (via Shodan historical)
    
[+] Email Addresses (45 found)
    CEO: ceo@external-target.com
    IT: it@external-target.com
    Support: support@external-target.com
    
[+] Breached Credentials
    [!] admin@external-target.com
        Breach: LinkedIn 2021
        Password: Summer2021!
        
    [!] john.smith@external-target.com
        Breach: Collection #1
        Password: Password123
```

**Exploitation:**

```bash
# Test breached credentials on VPN
echo "admin@external-target.com:Summer2021!" | openconnect vpn.external-target.com -u admin
# [Successfully connected]

# Now on internal network
nmap -sV 10.0.0.0/24
# [enumerate internal services]
```

**COSA FARE SE FALLISCE:**

* **Credentials don't work:** Password likely changed since breach. Try variations: Summer2022!, Summer2023!, Summer2024!
* **No VPN found:** Test credentials on: email (OWA/O365), admin panels, SSH
* **Cloudflare blocks origin IP discovery:** Use censys.io historical data or certificate transparency logs.

**Timeline:** 15 minuti OSINT + 10 minuti credential testing

***

### Scenario B: Red Team - Employee targeting

**COMANDO:**

```bash
# Identify employees for spear-phishing
python3 reconspider.py -t redteam-company.com --employees --social-media
```

**OUTPUT ATTESO:**

```
[+] Employee Enumeration (LinkedIn scraping)

Name: Sarah Johnson
Position: IT Security Manager
Email: sarah.johnson@redteam-company.com
LinkedIn: linkedin.com/in/sarahjohnson-infosec
Interests: Cybersecurity, Cloud Security, AWS

Name: Mike Davis  
Position: Developer
Email: mike.davis@redteam-company.com
LinkedIn: linkedin.com/in/mikedavis-dev
GitHub: github.com/mdavis-dev
Interests: Python, Machine Learning

[Total: 67 employees identified]
```

**Spear-phishing strategy:**

```
Target: Sarah Johnson (IT Security Manager)

Pretext: AWS Security Advisory
Email:
  Subject: [AWS SECURITY] Critical Vulnerability in Your Account
  From: aws-security@amazon-security.com
  
  Dear Sarah,
  
  We've detected unusual activity in your AWS account (us-east-1).
  A critical vulnerability (CVE-2026-XXXXX) affects your EC2 instances.
  
  Please review immediately: [phishing link]
  
  AWS Security Team

Likelihood: HIGH (targets her AWS interest from LinkedIn)
```

**Timeline:** 20 minuti employee enum + 15 minuti phishing prep

***

### Scenario C: Bug Bounty - GitHub secrets hunting

**COMANDO:**

```bash
python3 reconspider.py -t bounty-target.com --github --emails
```

**OUTPUT ATTESO:**

```
[+] GitHub Organization
    Org: bounty-target
    Public Repos: 45
    
[+] Employee GitHub Accounts
    john-dev (john@bounty-target.com)
    sarah-coder (sarah@bounty-target.com)
    mike-devops (mike@bounty-target.com)

[+] Interesting Commits
    Repo: bounty-target/legacy-app
    Commit: a3f2b9c
    Author: john-dev
    Message: "Remove hardcoded password"
    File: config/database.yml
    [!] Deleted line: password: 'Pr0d_DB_P@ss2024!'
```

**Exploitation:**

```bash
# Clone repository
git clone https://github.com/bounty-target/legacy-app
cd legacy-app

# Check commit history
git log --all --full-history --grep="password\|secret\|key"

# View deleted content
git show a3f2b9c:config/database.yml
# password: 'Pr0d_DB_P@ss2024!'

# Test credentials
mysql -h db.bounty-target.com -u admin -p'Pr0d_DB_P@ss2024!'
# mysql> [access to production database]
```

**Timeline:** 10 minuti GitHub enum + 15 minuti secret hunting

***

## 6️⃣ Toolchain Integration

### Pre-ReconSpider: Target identification

```bash
# Identify company from IP/domain
whois 203.0.113.10
# Organization: Company Inc.

# Feed to ReconSpider
python3 reconspider.py -t "Company Inc" --company
```

### ReconSpider → theHarvester combination

```bash
# ReconSpider for API-based OSINT
python3 reconspider.py -t target.com -o json > reconspider.json

# theHarvester for search engine scraping
theHarvester -d target.com -b all -f theharvester.html

# Merge results
python3 merge_osint.py reconspider.json theharvester.html > merged_osint.json
```

### ReconSpider → Maltego integration

```bash
# Export to Maltego CSV format
python3 reconspider.py -t target.com --output-format csv

# Import in Maltego
# File → Import → CSV
# Map fields: email, domain, person, company
```

Per OSINT workflow automation completa, leggi [building comprehensive OSINT pipelines](https://hackita.it/articoli/osint-pipeline-building).

### Comparazione tool

| **Tool**         | **API Integration** | **Breach Check**  | **Social Media** | **Automation** | **Best For**          |
| ---------------- | ------------------- | ----------------- | ---------------- | -------------- | --------------------- |
| **ReconSpider**  | ✅ 50+ APIs          | ✅ Yes             | ✅ Yes            | ✅ High         | All-in-one OSINT      |
| **theHarvester** | ⚠️ Limited          | ❌ No              | ⚠️ Basic         | ✅ Good         | Email/subdomain focus |
| **Maltego**      | ✅✅ Extensive        | ⚠️ Via transforms | ✅ Yes            | ⚠️ GUI-based   | Visual analysis       |
| **Recon-ng**     | ✅ Good              | ⚠️ Modules        | ✅ Modules        | ✅ Framework    | Customizable          |
| **SpiderFoot**   | ✅✅ 100+ modules     | ✅ Yes             | ✅ Yes            | ✅✅ Excellent   | Enterprise OSINT      |

**Quando usare ReconSpider:**

* Need quick comprehensive OSINT
* Want simple CLI tool (no framework learning curve)
* API integration è priority
* Automated reporting needed

***

## 7️⃣ Attack Chain Completa

### OSINT → Social Engineering → Network Access

**FASE 1: OSINT Gathering**

```bash
python3 reconspider.py -t techcorp.com --full-scan --breach-check
```

**Timeline:** 20 minuti

***

**FASE 2: Target Selection**

```
Employee: john.smith@techcorp.com
Position: IT Manager
LinkedIn: Active, posts about cloud security
Breached Password: Welcome2020!

Technologies: Microsoft Exchange, Office 365, Cisco VPN
```

**Timeline:** 10 minuti analysis

***

**FASE 3: Credential Testing**

```bash
# Test VPN with breached password
openconnect vpn.techcorp.com -u john.smith
# Password: Welcome2020!
# [Failed]

# Try password variation (year increment pattern)
# Password: Welcome2024!
# [Success! Connected to VPN]
```

**Timeline:** 5 minuti

***

**FASE 4: Internal Network Access**

```bash
# Now on internal network (10.10.0.0/16)
nmap -sV 10.10.0.0/24

# Found:
# 10.10.0.10 - Domain Controller (AD)
# 10.10.0.20 - File Server (SMB)
# 10.10.0.50 - SQL Server
```

**Timeline:** 30 minuti

***

**FASE 5: Privilege Escalation**

```bash
# john.smith credentials work on network resources
crackmapexec smb 10.10.0.0/24 -u john.smith -p 'Welcome2024!'
# [+] Multiple hosts accessible

# John is Domain Admin (lucky!)
secretsdump.py DOMAIN/john.smith:Welcome2024!@10.10.0.10
# [*] Dumping Domain Credentials
# Administrator:500:aad3b...:31d6cfe...
```

**Timeline:** 15 minuti

***

**TOTALE:** 1.5 ore da OSINT a Domain Admin.

**Ruolo ReconSpider:** OSINT automation in 20 minuti identified breached credential che, con password pattern analysis, granted VPN access. Single tool execution = critical intelligence.

***

## 8️⃣ Detection & Evasion

### Cosa detecta Blue Team

**API rate limiting alerts:**

```
Shodan API: Excessive queries from IP 203.0.113.50
Hunter.io: API key abc123 exceeded rate limit
LinkedIn: Automated profile scraping detected
```

**Web scraping detection:**

```
Pattern: Sequential page access
User-Agent: Python-urllib/3.x
Behavior: No JavaScript execution, no cookies
Rate: 10 requests/second
```

**OSINT fingerprinting:**

```
Multiple WHOIS queries in short timeframe
DNS enumeration patterns (sequential subdomain attempts)
Certificate transparency log bulk downloads
```

### Evasion techniques

**1. API key rotation**

```bash
# Use multiple API keys
# config.json
{
  "shodan_keys": ["key1", "key2", "key3"],
  "rotate": true
}

# ReconSpider automatically rotates per query
```

**2. Request throttling**

```bash
# Add delays
python3 reconspider.py -t target.com --delay 5

# Random jitter
python3 reconspider.py -t target.com --delay-random 3-10
```

**3. Distributed OSINT**

```bash
# Split queries across multiple IPs/VPS
# VPS 1: WHOIS + DNS
python3 reconspider.py -t target.com --whois --dns

# VPS 2: Email + Social
python3 reconspider.py -t target.com --emails --social-media

# VPS 3: Shodan + GitHub
python3 reconspider.py -t target.com --shodan --github
```

**4. Residential proxies**

```bash
# Use residential proxy service
export HTTP_PROXY="http://residential-proxy:8080"
python3 reconspider.py -t target.com
```

### Cleanup

```bash
# Remove reports con sensitive data
shred -u reports/*.json reports/*.html

# Clear API key cache
rm -f ~/.reconspider/cache/*

# Clear command history
history | grep reconspider | cut -d' ' -f4- | xargs -I {} history -d {}
```

***

## 9️⃣ Performance & Scaling

### Benchmark

**Single domain (no API keys):**

```bash
time python3 reconspider.py -t example.com
# real: 2m15s
# Limited to public sources
```

**Single domain (with all API keys):**

```bash
time python3 reconspider.py -t example.com --full-scan
# real: 5m30s
# 50+ API queries, comprehensive
```

**Batch processing (10 domains):**

```bash
time cat 10_domains.txt | xargs -I {} python3 reconspider.py -t {}
# real: 55m (sequential)

# Parallel (5 concurrent)
time cat 10_domains.txt | xargs -P 5 -I {} python3 reconspider.py -t {}
# real: 15m
```

### Resource usage

**CPU:** Low (10-15%, mostly network I/O wait)

**RAM:** \~150MB per instance

**Network:** Moderate (depends on API response sizes)

**Disk:** Minimal (reports \~100-500KB each)

***

## 10️⃣ Tabelle Tecniche

### Command Reference

| **Command**                               | **Function**      | **Use Case**         |
| ----------------------------------------- | ----------------- | -------------------- |
| `reconspider.py -t DOMAIN`                | Basic domain scan | Quick reconnaissance |
| `reconspider.py -t EMAIL --person`        | Person profiling  | Individual targeting |
| `reconspider.py -t "COMPANY" --company`   | Company intel     | Corporate profiling  |
| `reconspider.py -t DOMAIN --full-scan`    | Comprehensive     | Deep intelligence    |
| `reconspider.py -t DOMAIN --breach-check` | Credential search | Password discovery   |
| `reconspider.py -t DOMAIN --github`       | Code search       | Secret hunting       |
| `reconspider.py -t DOMAIN -o json`        | JSON output       | Automation/parsing   |

### API Integration Coverage

| **Data Source** | **Free Tier**     | **Premium Required** | **Information Type**  |
| --------------- | ----------------- | -------------------- | --------------------- |
| **Shodan**      | 100 queries/month | Full access          | Infrastructure, vulns |
| **Hunter.io**   | 25 searches/month | Unlimited            | Email addresses       |
| **VirusTotal**  | 4 requests/min    | Higher rate          | Domain reputation     |
| **GitHub**      | 60 requests/hour  | 5000 req/hour        | Code, commits         |
| **FullContact** | 50 queries/month  | Higher volume        | Person enrichment     |

***

## 11️⃣ Troubleshooting

### API key errors

**Errore:**

```
[!] Shodan API Error: Invalid API key
```

**Fix:**

```bash
# Verify API key
curl "https://api.shodan.io/api-info?key=YOUR_KEY"

# Update config.json
nano config.json
# Ensure quotes: "shodan_api_key": "abc123xyz"
```

***

### Rate limiting

**Errore:**

```
[!] Hunter.io: Rate limit exceeded (25/month)
```

**Fix:**

```bash
# Wait for monthly reset
# Or upgrade to paid plan
# Or use alternative: theHarvester -d target.com -b google

# Distributed approach
# Use different tools for email harvesting
python3 reconspider.py -t target.com --emails-basic  # No API
```

***

### Missing dependencies

**Errore:**

```
ModuleNotFoundError: No module named 'shodan'
```

**Fix:**

```bash
pip3 install shodan
# Or reinstall all
pip3 install -r requirements.txt --upgrade
```

***

## 12️⃣ FAQ

**Q: ReconSpider richiede API keys?**

A: **No** per basic functionality. API keys sono optional per enhanced features (Shodan, Hunter.io, etc). Tool funziona con public sources senza keys.

**Q: È legale fare OSINT con ReconSpider?**

A: **Generally yes** - OSINT usa publicly available information. Però: accessing breached databases può violare ToS, automated scraping viola policies di alcuni siti. Use responsibly e only per authorized assessments.

**Q: ReconSpider bypassa privacy protections?**

A: **No**. Tool query solo public data. Se qualcuno ha privacy settings correct (LinkedIn private, WHOIS privacy), ReconSpider non trova quella info.

**Q: Quanto è accurate il breach checking?**

A: **Depends on database**. ReconSpider query HaveIBeenPwned API + altri breach databases. Accuracy \~85-90% per major breaches. Older/smaller breaches potrebbero essere missing.

**Q: Posso usare ReconSpider per monitoring continuo?**

A: **Yes**! Schedule con cron per periodic scans. Alert quando new data appears (new emails, new breaches, new subdomains). Perfect per attack surface monitoring.

**Q: ReconSpider è detection-resistant?**

A: **Partially**. API queries sono logged da providers (Shodan logs your IP). Web scraping può trigger rate limits. Use proxies/VPN e throttling per reduce footprint.

***

## 13️⃣ Cheat Sheet Finale

| **Scenario**        | **Command**                                           |
| ------------------- | ----------------------------------------------------- |
| **Basic domain**    | `python3 reconspider.py -t domain.com`                |
| **Full scan**       | `python3 reconspider.py -t domain.com --full-scan`    |
| **Person lookup**   | `python3 reconspider.py -t email@domain.com --person` |
| **Company intel**   | `python3 reconspider.py -t "Company" --company`       |
| **Breach check**    | `python3 reconspider.py -t domain.com --breach-check` |
| **GitHub secrets**  | `python3 reconspider.py -t domain.com --github`       |
| **JSON output**     | `python3 reconspider.py -t domain.com -o json`        |
| **HTML report**     | `python3 reconspider.py -t domain.com -o html`        |
| **Subdomain focus** | `python3 reconspider.py -t domain.com --subdomains`   |

***

## Perché è rilevante oggi (2026)

OSINT è increasingly critical con remote work normalization: employees post job details su LinkedIn, companies share technology stacks publicly. Data breaches sono epidemic (2025: 6+ billion records exposed). ReconSpider automatizza aggregation di questa intelligence explosion. Social engineering attacks sono #1 initial access vector - OSINT gathering è prerequisite per targeted attacks. Manual OSINT requires visiting 20+ sites, creating accounts, learning APIs - ReconSpider reduce questo a single command. Bug bounty programs reward OSINT findings (exposed credentials, leaked docs).

***

## Differenza rispetto ad alternative

| **Tool**         | **Quando usare**                            | **Limiti**                                |
| ---------------- | ------------------------------------------- | ----------------------------------------- |
| **ReconSpider**  | All-in-one quick OSINT, automated reporting | Less customizable than frameworks         |
| **Maltego**      | Visual relationship mapping, enterprise     | Expensive, GUI-only, steep learning curve |
| **Recon-ng**     | Customizable modules, scripting             | Requires framework knowledge              |
| **theHarvester** | Simple email/subdomain harvesting           | Limited scope, no breach checking         |
| **SpiderFoot**   | Comprehensive automated OSINT               | Resource-intensive, slower                |

**ReconSpider best quando:** Need quick comprehensive OSINT, want CLI tool, automated reporting è priority, don't want framework overhead.

***

## Hardening / Mitigazione

**Per defenders:**

1. **Employee training:** Educate su OSINT risks (LinkedIn oversharing, GitHub commits)
2. **Data minimization:** Remove unnecessary public information (old WHOIS data, exposed docs)
3. **Breach monitoring:** Subscribe to HaveIBeenPwned alerts for company domain
4. **GitHub secrets scanning:** Enable GitHub Advanced Security, periodic audit di repositories
5. **Privacy settings:** Enforce LinkedIn privacy policies, limit company information sharing

***

## OPSEC e Detection

**Noise level:** Basso-Medio. API queries sono logged ma appear as legitimate usage. Web scraping può trigger alerts.

**Log footprint:**

* API provider logs (Shodan, Hunter.io log your queries)
* Web server logs (se scraping direct)
* LinkedIn automation detection (profile view patterns)

**Reduce visibility:**

* Use API keys (appears as legit API usage vs scraping)
* Request throttling
* Residential proxies invece of datacenter IPs
* Distribute queries temporalmente (today: emails, tomorrow: subdomains)

**Detection difficulty:** Hard. OSINT queries blend con legitimate research, security scanning, competitive intelligence. Distinguishing malicious from benign è challenging.

***

## Disclaimer

ReconSpider è tool per **authorized OSINT gathering e security research**. Collecting information senza proper authorization può violare privacy laws, anti-hacking statutes, e platform ToS. Accessing breached credentials databases può violare Computer Fraud and Abuse Act. Usa solo in:

* Authorized penetration tests con signed SOW
* Bug bounty programs
* Your own organization for security assessment
* Educational/research purposes con proper authorization

**Repository:** [https://github.com/bhavsec/reconspider](https://github.com/bhavsec/reconspider)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
