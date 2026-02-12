---
title: 'FOCA: Metadata Extraction e OSINT su Documenti per Information Gathering'
slug: foca
description: >-
  FOCA è uno strumento OSINT per estrarre metadata da documenti pubblici,
  mappare infrastruttura interna e identificare utenti, server e percorsi
  esposti.
image: /Gemini_Generated_Image_5np0265np0265np0.webp
draft: false
date: 2026-02-13T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - metadata-analysis
  - document-enumeration
---

FOCA (Fingerprinting Organizations with Collected Archives) automatizza estrazione metadata da documenti pubblici (PDF, DOCX, XLSX, PPTX) per rivelare informazioni sensibili nascoste: username interni, hostname workstation, software versions, network paths, email addresses e org chart structure. Sviluppato da Informatica64 (Spain) e parte suite ElevenPaths, FOCA eccelle in passive reconnaissance dove [https://hackita.it/articoli/theharvester](https://hackita.it/articoli/theharvester) scopre email ma non infrastructure detail, e dove [https://hackita.it/articoli/maltego](https://hackita.it/articoli/maltego) necessita data source che FOCA genera autonomamente crawlando Google/Bing per documenti pubblici target organization. Versione attuale 4.3.5 (Windows-only) introduce support Office 365 cloud documents, enhanced search engine integration e export formato integrabile con altre piattaforme OSINT.

### Cosa imparerai

Questo articolo copre installazione Windows e workaround Linux (Wine/VM), configurazione search engine per document discovery, tecniche metadata extraction da 8+ file types, analysis pattern per identify infrastructure topology, username enumeration per password spraying attacks, software inventory per vulnerability mapping, geolocation inference da timezone metadata, integration con [https://hackita.it/articoli/recon-ng](https://hackita.it/articoli/recon-ng) per data enrichment, countermeasure document sanitization, blue team detection metadata leakage, e enterprise deployment per continuous document monitoring su attack surface pubblico.

## Setup e Installazione

FOCA richiede **Windows 7+** e **.NET Framework 4.7.2+**. Tool è **Windows-only** (no native Linux/macOS).

**Download**:

```
Official: https://github.com/ElevenPaths/FOCA
Latest release: v4.3.5 (2023)
File size: ~15 MB
```

**Installazione Windows**:

```powershell
# Download latest release
Invoke-WebRequest -Uri "https://github.com/ElevenPaths/FOCA/releases/download/v4.3.5/FOCA_4.3.5.zip" -OutFile "FOCA.zip"

# Extract
Expand-Archive -Path "FOCA.zip" -DestinationPath "C:\Tools\FOCA"

# Run
cd C:\Tools\FOCA
.\FOCA.exe
```

**Requisiti**:

* Windows 7/8/10/11 (64-bit recommended)
* .NET Framework 4.7.2+ (auto-prompt install se mancante)
* Internet connection per document crawling
* 2GB RAM minimum, 4GB recommended
* Storage: 500MB-5GB per project (dipende da document count)

**Linux Workaround (Wine)**:

```bash
# Install Wine
sudo apt install wine64 winetricks

# Install .NET Framework in Wine
winetricks dotnet472

# Run FOCA
wine FOCA.exe
```

**Note**: Wine support è experimental. Alcune feature potrebbero non funzionare. Raccomandazione: Windows VM.

**Verifica installazione**:

1. Launch FOCA.exe
2. Create New Project: Project → New Project
3. Domain: example.com
4. Click "Search All" → deve iniziare document discovery
5. Se funziona, setup OK

## Architettura e Funzionalità

FOCA opera su workflow: **Discovery** → **Download** → **Metadata Extraction** → **Analysis**.

### Document Types Supportati

FOCA processa 10+ file formats:

**Office Documents**:

```
- Microsoft Word (.doc, .docx)
- Excel (.xls, .xlsx)
- PowerPoint (.ppt, .pptx)
- Visio (.vsd, .vsdx)
```

**Adobe**:

```
- PDF (Portable Document Format)
- InDesign (.indd)
```

**Images**:

```
- JPEG/JPG (EXIF metadata)
- PNG (metadata limited)
- SVG (embedded text/metadata)
```

**Other**:

```
- Open Document Format (.odt, .ods, .odp)
- Publisher (.pub)
```

### Metadata Categories

FOCA extracts 8 categorie informazioni:

**1. User Information**:

```
- Author name
- Last modified by
- Creator
- Company name
- Manager
```

**2. Software Information**:

```
- Application name/version (es. Microsoft Word 16.0)
- Operating System (es. Windows 10 Pro)
- Producer (PDF creator)
- Creation tool
```

**3. Network Information**:

```
- Computer hostname
- Network paths (UNC paths: \\server\share\file)
- Printers (network printer paths)
- SharePoint URLs
```

**4. Temporal Information**:

```
- Creation date
- Modification date
- Print date
- Last access date
```

**5. Geographic Information** (EXIF from images):

```
- GPS coordinates
- Camera make/model
- Timestamp with timezone
```

**6. Email Addresses**:

```
- Author email
- Embedded contact info
- mailto: links
```

**7. Internal Paths**:

```
- File system paths (C:\Users\jdoe\Documents\)
- Template locations
- Linked files
```

**8. Custom Properties**:

```
- Project name
- Client name
- Internal reference numbers
```

## Uso Base

### Scenario 1: Basic Document Discovery

**Obiettivo**: Identify tutti public documents da targetcorp.com.

**Step-by-step**:

1. **New Project**:

```
Project → New Project
Name: TargetCorp_Assessment
Domain: targetcorp.com
Save Location: C:\FOCA_Projects\TargetCorp\
```

1. **Document Search**:

```
Metadata → Search All
FOCA queries:
- Google
- Bing
- Exalead
```

**Search queries automatiche**:

```
site:targetcorp.com filetype:pdf
site:targetcorp.com filetype:doc
site:targetcorp.com filetype:docx
site:targetcorp.com filetype:xls
site:targetcorp.com filetype:xlsx
site:targetcorp.com filetype:ppt
site:targetcorp.com filetype:pptx
```

1. **Results**:

```
FOCA GUI mostra:
- Total documents found: 347
- PDFs: 189
- Word: 87
- Excel: 45
- PowerPoint: 26
```

1. **Download Documents**:

```
Select all found documents → Right-click → Download
Wait completion (5-20 minuti per 300+ files)
```

1. **Extract Metadata**:

```
Select downloaded documents → Right-click → Extract Metadata
Progress bar: Processing 347 files... (~2-5 minuti)
```

**Output visualizzato**:

```
Metadata Tab mostra:
- Users: 45 unique usernames
- Paths: 89 UNC paths discovered
- Software: Microsoft Office 2019, Adobe Acrobat DC
- Domains: targetcorp.com, targetcorp.local
- Printers: 12 network printers identified
```

### Scenario 2: User Enumeration

**Obiettivo**: Build comprehensive username list per password spraying.

**Analysis workflow**:

1. **Navigate**: Metadata → Users
2. **Output list**:

```
john.doe
jane.smith
admin
michael.johnson
susan.lee
...
(45 total users)
```

1. **Username pattern detection**:

```
Pattern identified: firstname.lastname
Exceptions: admin, root, sysadmin (generic accounts)
```

1. **Export usernames**:

```
Right-click users list → Export → TXT
Save: targetcorp_users.txt
```

**Use case**: Feed username list a:

* **Kerbrute**: Kerberos pre-authentication attack
* **CrackMapExec**: SMB authentication brute
* **Password spraying tools**: Single password against all users

**Timeline**: 10-15 minuti da zero a exported username list.

### Scenario 3: Infrastructure Mapping

**Obiettivo**: Identify internal infrastructure da network paths leaked in metadata.

**Analysis**:

1. **Navigate**: Metadata → Paths
2. **Output**:

```
\\fileserver01\shared\documents\report.docx
\\dc01.targetcorp.local\sysvol\policies\
\\printserver\hp_laserjet_4\
\\backup01\archives\2023\
C:\Users\jdoe\AppData\Local\Temp\
```

1. **Hostname extraction**:

```
Hostnames discovered:
- fileserver01
- dc01.targetcorp.local (Domain Controller!)
- printserver
- backup01
```

1. **Domain identification**:

```
Internal domain: targetcorp.local (vs public targetcorp.com)
```

1. **Asset inventory**:

```
- File servers: 3
- Domain controllers: 1
- Print servers: 1
- Backup servers: 1
- Workstations: 45 (from C:\ paths)
```

**Tactical advantage**: Internal network topology revealed senza active scanning.

## Tecniche Operative Avanzate

### Custom Search Filters

FOCA supporta Google dork customization:

```
Metadata → Search → Advanced Search

Custom query examples:
site:targetcorp.com filetype:pdf "confidential"
site:targetcorp.com filetype:xls "salary"
site:targetcorp.com filetype:ppt "roadmap"
site:targetcorp.com intitle:"index of" "backup"
```

**High-value document targeting**:

```
Keywords interessanti:
- "internal use only"
- "confidential"
- "proprietary"
- "draft"
- "budget"
- "architecture"
- "network diagram"
```

### Email Extraction e Format Analysis

```
1. Metadata → Emails
2. Output list:
   john.doe@targetcorp.com
   jane.smith@targetcorp.com
   admin@targetcorp.com
   
3. Pattern analysis:
   Format: firstname.lastname@domain
   Exceptions: admin@, support@, info@
   
4. Cross-reference con Users tab:
   Users trovati: john.doe, michael.johnson, susan.lee
   Email NOT found: michael.johnson@, susan.lee@
   
5. Email guessing:
   Generate: michael.johnson@targetcorp.com
            susan.lee@targetcorp.com
```

**Validation step**: Use [https://hackita.it/articoli/theharvester](https://hackita.it/articoli/theharvester) per verificare guessed emails.

### Software Version Inventory

```
Metadata → Software

Output example:
- Microsoft Office 2019 (16.0.xxxxx) - 234 documents
- Microsoft Office 2016 (15.0.xxxxx) - 89 documents
- Adobe Acrobat DC 2021 - 67 documents
- LibreOffice 6.4 - 3 documents
```

**Security implications**:

```
Office 2016 (EOL 2025) → Check CVEs for unpatched versions
Acrobat DC 2021 → Known vulns: CVE-2021-xxxxx
LibreOffice usage → Potential BYOD policy, less control
```

**Vulnerability mapping**:

```bash
# Export software list
# Query Exploit-DB per version
searchsploit "Microsoft Office 2016"
searchsploit "Adobe Acrobat DC 2021"
```

### Geolocation via EXIF

Se target pubblica images (annual reports, blog, social media), FOCA extracts GPS:

```
1. Search images: site:targetcorp.com filetype:jpg
2. Download images
3. Extract EXIF metadata
4. Navigate: Metadata → Graphic Documents → Geolocation

Output:
- Photo1.jpg: 40.7128° N, 74.0060° W (New York City)
- Photo2.jpg: 37.7749° N, 122.4194° W (San Francisco)

Inference:
- Office locations identified
- Employee travel patterns
- Event locations
```

**Map visualization**:

```
Right-click GPS coordinates → Show in Google Maps
Result: Visual map con marker per ogni location
```

### Printer Name Analysis

Network printer paths rivelano:

```
\\printserver\HP_LaserJet_4_Floor3_East
\\printserver\Xerox_Copier_HQ_Reception
\\printserver\Canon_Legal_Department

Intelligence extracted:
- Floor layout: Floor 3 East
- Department structure: Legal Department
- HQ location: Reception area
- Equipment: HP, Xerox, Canon (vendor info)
```

**Social engineering use**:

```
Phone call: "Hi, I'm from HP support regarding the LaserJet on Floor 3 East..."
Physical security: "I need access to Floor 3 to service the printer..."
```

### Temporal Analysis

```
Metadata → Dates

Creation date analysis:
- Spike documents creati: Lunedì 9:00-11:00 (start settimana)
- Off-hours creation: Sabato 22:00 (overtime? contractor?)
- Historical: Documents dal 2015 → long-term employees

Modification patterns:
- Last modified: Consistent timezone (EST) → HQ location inference
- Version control visible: Report_v1, Report_v2, Report_final
```

## Integration Toolchain

### FOCA → CrackMapExec (Password Spraying)

```bash
# Export usernames da FOCA
# File: targetcorp_users.txt

# CrackMapExec password spray
crackmapexec smb 10.10.10.0/24 -u targetcorp_users.txt -p 'Summer2024!' --continue-on-success

# Or Kerbrute for Kerberos pre-auth
kerbrute userenum -d targetcorp.local --dc 10.10.10.5 targetcorp_users.txt
```

### FOCA → BloodHound (Active Directory)

```
1. FOCA identifies: dc01.targetcorp.local
2. SharpHound collection targeting DC:
   .\SharpHound.exe -c All -d targetcorp.local --domaincontroller dc01.targetcorp.local
3. BloodHound analysis con context da FOCA (usernames, hostnames)
```

### FOCA → Metasploit

```ruby
# Use hostnames trovati per targeting
use auxiliary/scanner/smb/smb_version
set RHOSTS fileserver01.targetcorp.local
run

# Username enumeration validation
use auxiliary/scanner/smb/smb_enumusers
set RHOSTS dc01.targetcorp.local
run
```

### FOCA + TheHarvester Pipeline

```bash
# Step 1: TheHarvester per email
theharvester -d targetcorp.com -b all -f emails.txt

# Step 2: FOCA per username + infrastructure
# (GUI-based, export users)

# Step 3: Cross-reference
python3 << EOF
emails = open('emails.txt').read().splitlines()
users = open('foca_users.txt').read().splitlines()

# Match email local part con FOCA usernames
for user in users:
    possible_email = f"{user}@targetcorp.com"
    if possible_email in emails:
        print(f"[CONFIRMED] {user} → {possible_email}")
    else:
        print(f"[GUESSED] {user} → {possible_email}")
EOF
```

## Detection & OPSEC

### Blue Team Detection

FOCA è **completely passive** — no direct interaction con target infrastructure.

**Detection likelihood: \<5%**

**Traceable activities**:

1. **Search Engine Queries**:

```
Google/Bing logs query patterns:
- site:targetcorp.com filetype:pdf (sequential file types)
- Same source IP, rapid succession
- User-Agent: FOCA-specific? (da verificare in source)
```

Mitigation: Use VPN/proxy, randomize User-Agent.

1. **Document Downloads**:

```
Web server logs:
GET /documents/annual_report.pdf HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; FOCA/4.3.5)
Referer: https://www.google.com/search?q=...
```

Target può vedere:

* Which documents accessed
* Download frequency/pattern
* Source IP

Mitigation: Throttle downloads, proxy rotation.

1. **No metadata extraction detection**:

```
Metadata extraction = local file processing
Target has ZERO visibility on questo step
```

### OPSEC Best Practices

**1. VPN/Proxy for All Operations**:

```powershell
# Configure system proxy Windows
netsh winhttp set proxy proxy-server="socks5://127.0.0.1:9050"

# Or use Tor
# Download Tor Browser, set SOCKS proxy in FOCA (se supportato)
```

**2. Throttle Document Downloads**:

```
FOCA settings:
- Download delay: 5-10 seconds between files
- Limit concurrent downloads: 2-3 max
- Spread over days for large projects (300+ files)
```

**3. User-Agent Randomization**:

```
Modifica FOCA source (C# .NET):
// File: DownloadManager.cs
string[] userAgents = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
    // ... more
};
request.UserAgent = userAgents[random.Next(userAgents.Length)];
```

**4. Distributed Downloads**:

```
- Operator 1: PDFs only, VPN endpoint 1
- Operator 2: Word docs, VPN endpoint 2
- Operator 3: Excel/PPT, VPN endpoint 3
Merge results offline
```

**5. Avoid Honeypot Documents**:

```
Suspicious documents:
- File size 0 bytes
- Filename: "confidential_do_not_download.pdf"
- Unrealistic content (decoy)
- Recent upload dopo recon iniziato

Skip download se sospetto
```

## Defense & Metadata Sanitization

### Document Sanitization

Organizations devono rimuovere metadata prima pubblicazione:

**Microsoft Office** (builtin):

```
File → Info → Inspect Document → Inspect
Check: Document Properties, Author, Paths
Remove All → Save
```

**Adobe Acrobat**:

```
File → Properties → Description → Remove metadata
Tools → Protect → Remove Hidden Information
```

**Batch processing** (PowerShell):

```powershell
# Remove metadata da tutti .docx in folder
Get-ChildItem -Path "C:\Documents" -Filter *.docx -Recurse | ForEach-Object {
    $doc = [System.IO.Packaging.Package]::Open($_.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
    
    # Remove core properties
    $doc.PackageProperties.Creator = ""
    $doc.PackageProperties.LastModifiedBy = ""
    $doc.PackageProperties.Title = ""
    $doc.PackageProperties.Subject = ""
    $doc.PackageProperties.Keywords = ""
    $doc.PackageProperties.Description = ""
    
    $doc.Close()
    Write-Host "Sanitized: $($_.Name)"
}
```

**Automated tools**:

```
- mat2 (Linux): metadata anonymization toolkit
- ExifTool: command-line metadata editor
- Metadata Cleaner (GUI): batch processing
```

### Policy & Training

**Document publication checklist**:

```
✓ Metadata removed (author, company, paths)
✓ Review comments removed
✓ Hidden text/layers removed
✓ Internal references sanitized
✓ Print date/history cleared
✓ Approved by security team
```

**Employee training**:

* Awareness metadata risks
* Proper document handling procedures
* Use of sanitization tools
* Verification before upload

### Monitoring & Detection

**Proactive FOCA self-assessment**:

```
1. Run FOCA against own domain monthly
2. Identify leaked metadata
3. Remove problematic documents
4. Update publication procedures
```

**Google Alerts**:

```
site:yourcompany.com filetype:pdf
site:yourcompany.com "confidential"
site:yourcompany.com "internal use only"
```

**Automated scanning** (Python):

```python
import requests
from bs4 import BeautifulSoup

def scan_domain_for_documents(domain):
    query = f"site:{domain} filetype:pdf OR filetype:docx"
    # Use Google Custom Search API
    results = google_search(query)
    
    for url in results:
        # Download document
        # Extract metadata con PyPDF2, python-docx
        # Flag if sensitive metadata found
        pass
```

## Troubleshooting

### Error: "No documents found"

**Cause**: Domain ha pochi/zero public documents, o search engines non indicizzati.

**Fix**:

```
1. Verify domain corretto (typo?)
2. Manual Google search: site:domain.com filetype:pdf
3. Try alternative search engines: Exalead, DuckDuckGo
4. Expand search: include subdomains
5. Historical search: use Archive.org Wayback Machine
```

### Error: "Download failed"

**Cause**: Network issue, link rotto, o authentication required.

**Fix**:

```
1. Check internet connectivity
2. Verify URL accessible in browser
3. Check if document behind login (skip)
4. Retry download con VPN/proxy alternative
5. Manual download if critical
```

### Error: "Metadata extraction failed"

**Cause**: File corrupted, encrypted, or unsupported format.

**Fix**:

```
1. Verify file integrity: open in native app (Word, Acrobat)
2. Check if password-protected (FOCA can't extract)
3. Try alternative tool: ExifTool, mat2
4. Skip problematic file, continue con others
```

### Performance Issues (Large Projects)

**Symptoms**: FOCA slow, crashes, high memory usage.

**Solutions**:

1. **Split project**: Analyze 100 documents at time
2. **Increase RAM**: Close other applications
3. **Disable real-time AV**: Temporary for analysis phase
4. **Use SSD**: Faster I/O for metadata extraction
5. **Project cleanup**: Delete downloaded files after extraction

## FAQ

**Q: FOCA è rilevabile dal target?**

A: **Barely**. FOCA queries search engines (logged ma not directly target) e downloads public documents (logged come normal web traffic). No active scanning o direct interaction con infrastructure interna.

**Q: FOCA funziona su Linux?**

A: **Experimental** via Wine. Raccomandazione: Windows VM. Alternative Linux: ExifTool + custom scripts.

**Q: Differenza tra FOCA e Maltego?**

A: **FOCA**: Specializzato metadata documents, passive only, Windows GUI. **Maltego**: General OSINT, visual graph, multi-platform, transform ecosystem. FOCA genera data che Maltego può visualizzare.

**Q: Quanti documenti sono "abbastanza"?**

A: Dipende. **50-100 docs** = reasonable sample. **300+** = comprehensive. **1000+** = enterprise con large footprint.

**Q: FOCA può crack password-protected files?**

A: No. FOCA skippa documenti encrypted. Need separate password cracking.

**Q: Come validate usernames trovati?**

A: Use **Kerbrute** (Kerberos), **CrackMapExec** (SMB), o **LDAP enumeration** se AD accessible.

**Q: Metadata extraction è legale?**

A: **Sì** per public documents. Metadata è public information. Usare data per attacchi = illegale senza authorization.

**Q: Alternative a FOCA?**

A: **ExifTool** (CLI), **mat2** (Linux GUI), **Metagoofil** (Python script), custom Python (PyPDF2, python-docx).

## Cheat Sheet

```
# PROJECT MANAGEMENT
File → New Project → Enter domain
Project → Save Project → .foca file
File → Open Project → Load previous

# DOCUMENT DISCOVERY
Metadata → Search All (Google, Bing, Exalead)
Metadata → Search → Customize query
Metadata → Search → Advanced (custom dorks)

# DOCUMENT DOWNLOAD
Select found documents → Right-click → Download
Settings → Download delay: 5-10 sec (OPSEC)
Check download progress: bottom status bar

# METADATA EXTRACTION
Select downloaded docs → Right-click → Extract Metadata
Wait completion (1-5 min per 100 docs)
View results: Metadata tab

# ANALYSIS TABS
Metadata → Users: Lista usernames
Metadata → Paths: UNC paths, file paths
Metadata → Software: Application versions
Metadata → Emails: Email addresses
Metadata → Printers: Network printers
Metadata → Dates: Creation/modification times

# EXPORT DATA
Right-click any list → Export → TXT/CSV/XML
File → Export Project → Full project export
Screenshot: PrtScn (manual)

# ADVANCED
DNS → Discover hostnames from paths
Network → Map infrastructure
Reports → Generate finding report

# METADATA REMOVAL (Defense)
Office: File → Info → Inspect Document
Acrobat: Tools → Protect → Remove Hidden Info
Batch: PowerShell script or ExifTool

# COMMON GOOGLE DORKS
site:domain.com filetype:pdf
site:domain.com filetype:docx "confidential"
site:domain.com intitle:"index of" backup
site:domain.com filetype:xls "budget"

# OPSEC
- Use VPN/proxy for all operations
- Throttle downloads (5-10 sec delay)
- Randomize User-Agent (code modification)
- Distribute downloads across operators/IPs
- Avoid honeypot documents (suspicious files)

# ALTERNATIVE TOOLS (Linux)
exiftool: Extract metadata any file
mat2: Metadata anonymization toolkit
metagoofil: Python FOCA alternative
PyPDF2 + python-docx: Custom scripting
```

## Perché è rilevante oggi (2026)

FOCA rimane critico perché **document-based intelligence gap** che altri OSINT tool non coprono — [https://hackita.it/articoli/theharvester](https://hackita.it/articoli/theharvester) trova email ma non internal username format, [https://hackita.it/articoli/spiderfoot](https://hackita.it/articoli/spiderfoot) enumera subdomain ma non hostname workstation, [https://hackita.it/articoli/maltego](https://hackita.it/articoli/maltego) visualizza ma non genera initial infrastructure data. Remote work expansion aumenta document sharing pubblico (Google Drive, Dropbox link sharing, website uploads) senza proper sanitization — 70%+ organizations non implementano automated metadata removal. Compliance framework (GDPR, CCPA) enforcement crescente rende metadata leakage legal liability oltre che security risk. Supply chain attacks necessitano vendor assessment dove FOCA reveals third-party infrastructure via loro public documents. Ransomware groups increasingly use FOCA-style reconnaissance pre-attack per identify high-value targets e internal network topology.

## Differenza rispetto ad alternative

| Tool           | Platform       | Focus        | Automation    | Metadata Types       | Output        |
| -------------- | -------------- | ------------ | ------------- | -------------------- | ------------- |
| **FOCA**       | Windows        | Documents    | High          | 8 categories         | GUI + Export  |
| **ExifTool**   | Cross-platform | Images/Docs  | CLI scripting | Extensive            | Text/JSON/XML |
| **Metagoofil** | Python/Linux   | Documents    | Medium        | Basic                | Text          |
| **mat2**       | Linux          | Sanitization | High          | Removal focus        | Clean files   |
| **Maltego**    | Cross-platform | Visual OSINT | High          | Not metadata-focused | Graph         |

**Use FOCA quando**: Windows environment, need GUI, comprehensive doc analysis, targeting enterprise organization con public docs.

**Use ExifTool quando**: Linux/scripting preference, need max flexibility, automation required, cross-platform support.

**Use Metagoofil quando**: Quick Python-based assessment, Linux-only environment, basic metadata sufficient.

**Evitare FOCA quando**: Linux-only environment (no Wine), zero public documents target, real-time monitoring needed (FOCA è batch tool).

## Hardening / Mitigazione

**Organizational Level**:

1. **Metadata Removal Policy**:

```
- Mandatory sanitization prima publication
- Automated tools in workflow (Office inspector)
- Verification step in approval process
```

1. **Document Access Control**:

```
- Limit public document uploads
- Authentication per sensitive documents
- Regular audit public-facing documents
```

1. **Employee Training**:

```
- Metadata awareness training (annual)
- Proper document handling procedures
- Use of sanitization tools
```

1. **Technical Controls**:

```
- DLP (Data Loss Prevention) per block unsanitized uploads
- Proxy filtering per outbound document uploads
- Automated scanning public website for metadata leaks
```

**Individual Level**:

1. **Before Publishing ANY Document**:

```
✓ Run Office Inspector / Acrobat Sanitizer
✓ Verify author field empty
✓ Check for internal paths/references
✓ Remove comments/tracked changes
✓ Review embedded objects
```

1. **Sanitization Tools**:

```
- Microsoft Office: Builtin Inspector
- Adobe Acrobat: Sanitize Document
- ExifTool: exiftool -all= file.pdf
- mat2: mat2 file.pdf
```

1. **Verification**:

```
# Check metadata post-sanitization
exiftool file.pdf | grep -i "author\|creator\|producer"
# Should return empty/generic values
```

**Monitoring**:

```bash
# Automated monthly check
#!/bin/bash
domain="yourcompany.com"
python3 foca_check.py $domain
if grep -q "SENSITIVE" results.txt; then
    mail -s "FOCA Alert: Metadata Leak" security@company.com < results.txt
fi
```

## OPSEC e Detection

**Rumorosità**: Molto Bassa. Completamente passive approach.

**Detection Likelihood**: \<5% con basic OPSEC, \<1% con advanced measures.

**Traceable Indicators**:

Search Engine Level:

* Query patterns (sequential filetype searches)
* User-Agent string (se non randomizzato)

Target Web Server:

* Document downloads logged (normal web traffic)
* Access patterns (multiple docs, short timeframe)

**NO Detection**:

* Metadata extraction (local processing)
* Analysis (offline)
* Export (local file operations)

**Evasion Effectiveness**:

| Technique             | Impact | Effort |
| --------------------- | ------ | ------ |
| VPN/Proxy             | High   | Low    |
| Download throttling   | Medium | Low    |
| User-Agent rotation   | Medium | Medium |
| Distributed downloads | High   | High   |

**Cleanup**:

```
- Delete downloaded documents: C:\FOCA_Projects\<project>\downloads\
- Clear FOCA project: File → Delete Project
- Clear browser cache (se integrated browser used)
- No artifacts on target
```

**OPSEC Rating**: 9/10 (uno dei tool più stealth in OSINT arsenal).

***

**Disclaimer**: FOCA deve essere utilizzato solo su organization per le quali si possiede autorizzazione scritta esplicita. Anche se documenti sono pubblici, automated bulk download può violare website terms of service. Uso di metadata per attacchi senza authorization è illegale. Metadata extraction da documenti pubblici = legale, ma uso per scopi malevoli = illegale. Repository ufficiale: [https://github.com/ElevenPaths/FOCA](https://github.com/ElevenPaths/FOCA)

Vuoi supportare HackIta? Visita [https://hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [https://hackita.it/servizi](https://hackita.it/servizi).
