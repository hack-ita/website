---
title: 'Nikto: Web Server Scanner per Vulnerabilità e Misconfiguration'
slug: nikto
description: 'Nikto è uno scanner web per individuare vulnerabilità note, file sensibili, configurazioni errate e software obsoleto su server HTTP/HTTPS.'
image: /Gemini_Generated_Image_ghwknrghwknrghwk.webp
draft: true
date: 2026-02-19T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - web-scanning
---

Nikto è lo scanner di vulnerabilità web più utilizzato per identificare misconfiguration, file pericolosi e software obsoleto sui web server. In questa guida impari a scansionare target, identificare vulnerabilità sfruttabili e integrare Nikto nel tuo workflow offensivo. Dalla scansione base all'exploitation delle findings.

## Cos'è Nikto

Nikto è uno scanner open source che testa web server per:

* Oltre 6700 file/CGI potenzialmente pericolosi
* Versioni obsolete di oltre 1250 server
* Problemi specifici su oltre 270 versioni server
* Misconfiguration comuni
* File di default e backup
* Header HTTP insicuri

## Installazione e Setup

### Kali Linux

```bash
# Preinstallato su Kali, verifica
nikto -Version

# Aggiorna database
nikto -update
```

### Debian/Ubuntu

```bash
# Installa da repository
sudo apt update && sudo apt install nikto -y

# Verifica installazione
nikto -Version
```

### Installazione da Source

```bash
# Clone repository
git clone https://github.com/sullo/nikto.git /opt/nikto
cd /opt/nikto/program

# Esegui
perl nikto.pl -Version
```

Output atteso:

```
Nikto v2.5.0
```

## Uso Base di Nikto

### Scansione Singolo Host

```bash
# Scan base
nikto -h http://target.com

# Scan HTTPS
nikto -h https://target.com

# Scan con porta specifica
nikto -h target.com -p 8080
```

Output esempio:

```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.100
+ Target Hostname:    target.com
+ Target Port:        80
+ Start Time:         2024-01-15 10:30:00
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set.
+ /admin/: Directory indexing found.
+ /backup.sql: Database backup file found.
+ /phpinfo.php: PHP info file found.
+ /server-status: Apache server-status found.
```

### Parametri Fondamentali

| Parametro  | Funzione          | Esempio                |
| ---------- | ----------------- | ---------------------- |
| `-h`       | Host target       | `-h http://target.com` |
| `-p`       | Porta             | `-p 80,443,8080`       |
| `-ssl`     | Forza HTTPS       | `-ssl`                 |
| `-nossl`   | Disabilita SSL    | `-nossl`               |
| `-root`    | Prepend path      | `-root /app`           |
| `-Tuning`  | Tipo test         | `-Tuning x`            |
| `-timeout` | Timeout           | `-timeout 10`          |
| `-Pause`   | Delay tra request | `-Pause 2`             |
| `-output`  | Output file       | `-output report.txt`   |
| `-Format`  | Formato output    | `-Format htm`          |
| `-evasion` | Evasion tecnica   | `-evasion 1`           |
| `-Plugins` | Plugin specifici  | `-Plugins apache`      |

### Tuning Options

Controlla quali test eseguire:

```bash
# Lista tuning options
nikto -list-plugins

# Opzioni tuning
# 1 - Interesting File / Seen in logs
# 2 - Misconfiguration / Default File
# 3 - Information Disclosure
# 4 - Injection (XSS/Script/HTML)
# 5 - Remote File Retrieval - Inside Web Root
# 6 - Denial of Service
# 7 - Remote File Retrieval - Server Wide
# 8 - Command Execution / Remote Shell
# 9 - SQL Injection
# 0 - File Upload
# a - Authentication Bypass
# b - Software Identification
# c - Remote Source Inclusion
# x - Reverse Tuning (exclude)

# Solo injection e command execution
nikto -h http://target.com -Tuning 48

# Tutto tranne DoS
nikto -h http://target.com -Tuning x6
```

## Tecniche di Scansione Avanzate

### Multiple Ports

```bash
# Scan multiple porte
nikto -h target.com -p 80,443,8080,8443

# Range porte
nikto -h target.com -p 80-90
```

### Virtual Hosts

```bash
# Specifica virtual host
nikto -h 192.168.1.100 -vhost target.com

# Utile quando IP e hostname danno risultati diversi
```

### Autenticazione

```bash
# Basic Auth
nikto -h http://target.com -id admin:password

# Digest Auth
nikto -h http://target.com -id admin:password:digest
```

### Scan Attraverso Proxy

```bash
# Proxy HTTP
nikto -h http://target.com -useproxy http://127.0.0.1:8080

# Integrazione Burp Suite
nikto -h http://target.com -useproxy http://127.0.0.1:8080
```

## Evasion Techniques

### IDS/WAF Evasion

```bash
# Tecniche evasion disponibili
# 1 - Random URI encoding
# 2 - Directory self-reference (/./)
# 3 - Premature URL ending
# 4 - Prepend long random string
# 5 - Fake parameter
# 6 - TAB as request spacer
# 7 - Change case of URL
# 8 - Use Windows directory separator (\)
# A - Use carriage return (0x0d)
# B - Use binary value 0x0b

# Applica evasion
nikto -h http://target.com -evasion 1

# Multiple evasion
nikto -h http://target.com -evasion 1234
```

### User-Agent Spoofing

```bash
# User-Agent custom
nikto -h http://target.com -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Randomizza User-Agent
nikto -h http://target.com -useragent "Googlebot/2.1"
```

### Timing Control

```bash
# Delay tra richieste (evita rate limit)
nikto -h http://target.com -Pause 2

# Timeout aumentato
nikto -h http://target.com -timeout 15
```

## Output e Reporting

### Formati Output

```bash
# Output CSV
nikto -h http://target.com -output report.csv -Format csv

# Output HTML
nikto -h http://target.com -output report.html -Format htm

# Output XML
nikto -h http://target.com -output report.xml -Format xml

# Output JSON
nikto -h http://target.com -output report.json -Format json
```

### Report Professionale

```bash
# Report completo HTML
nikto -h http://target.com \
      -output /tmp/nikto_report.html \
      -Format htm \
      -Tuning x6 \
      -timeout 10
```

## Scenari Pratici di Penetration Test

### Scenario 1: Reconnaissance Web Server

```bash
# Step 1: Scan iniziale
nikto -h http://target.com -Tuning b

# Output: identifica server e versioni
# Server: Apache/2.4.41 (Ubuntu)
# PHP/7.4.3

# Step 2: Cerca vulnerabilità per quelle versioni
searchsploit apache 2.4.41
searchsploit php 7.4

# Step 3: Deep scan
nikto -h http://target.com -Tuning 123
```

### Scenario 2: File Discovery

```bash
# Cerca file sensibili
nikto -h http://target.com -Tuning 1357

# File comuni trovati:
# /backup.sql
# /config.php.bak
# /.git/
# /phpinfo.php
# /.htpasswd

# Scarica file trovati
curl http://target.com/backup.sql -o backup.sql
curl http://target.com/config.php.bak -o config.php.bak
```

### Scenario 3: Vulnerability Assessment

```bash
# Scan completo
nikto -h http://target.com \
      -output full_scan.html \
      -Format htm \
      -Tuning x6

# Analizza findings:
# - Outdated software
# - Missing security headers
# - Default files
# - Information disclosure

# Prioritizza per exploitation
```

### Scenario 4: Mass Scanning

```bash
# File con lista target
# targets.txt:
# http://target1.com
# http://target2.com
# http://target3.com

# Scan tutti
for target in $(cat targets.txt); do
    nikto -h $target -output "$(echo $target | cut -d'/' -f3).html" -Format htm
done
```

## Interpretazione Risultati

### Severity Classification

| Finding                   | Severity | Action                                                                     |
| ------------------------- | -------- | -------------------------------------------------------------------------- |
| Outdated server version   | Alta     | Cerca exploit con [Searchsploit](https://hackita.it/articoli/searchsploit) |
| Directory listing         | Media    | Enumera file sensibili                                                     |
| Backup files (.bak, .old) | Alta     | Scarica e analizza                                                         |
| Default credentials       | Critica  | Testa login                                                                |
| Missing security headers  | Bassa    | Report per hardening                                                       |
| Information disclosure    | Media    | Raccogli info per fasi successive                                          |
| phpinfo exposed           | Media    | Estrai configuration details                                               |
| Admin panel exposed       | Alta     | Bruteforce con [Hydra](https://hackita.it/articoli/hydra)                  |

### Common Findings Exploitation

```bash
# Finding: /server-status exposed
curl http://target.com/server-status
# Rivela: IP interni, richieste attive, virtual hosts

# Finding: /.git/ exposed
git-dumper http://target.com/.git/ output_dir
# Scarica intero repository

# Finding: /backup.sql found
curl http://target.com/backup.sql -o dump.sql
# Analizza per credenziali

# Finding: phpinfo.php
curl http://target.com/phpinfo.php | grep -i "document_root\|server_admin"
# Estrai path e email
```

## Plugin e Estensioni

### Lista Plugin

```bash
# Mostra plugin disponibili
nikto -list-plugins

# Plugin comuni:
# apache - Apache specific tests
# apache_expect_xss - Apache Expect header XSS
# cgi - CGI script tests
# clientaccesspolicy - Silverlight policy
# content_search - Content patterns search
# cookies - Cookie flags
# dictionary - Dictionary attack paths
# drupal - Drupal CMS tests
# embedded - Embedded device tests
# favicon - Favicon fingerprint
# headers - HTTP headers
# httpoptions - HTTP methods
# ms10_070 - ASP.NET padding oracle
# robots - Robots.txt analysis
# ssl - SSL/TLS tests
```

### Uso Plugin Specifici

```bash
# Solo test Apache
nikto -h http://target.com -Plugins "apache"

# Test SSL/TLS
nikto -h https://target.com -Plugins "ssl"

# Multiple plugins
nikto -h http://target.com -Plugins "cgi;robots;headers"
```

## Integrazione con Altri Tool

### Nikto + [Nmap](https://hackita.it/articoli/nmap)

Prima enumera con [nmap](https://hackita.it/articoli/nmap), poi scansiona:

```bash
# Trova web server
nmap -sV -p 80,443,8080,8443 192.168.1.0/24 -oG web_servers.txt

# Estrai IP con web
grep "80/open\|443/open" web_servers.txt | cut -d " " -f 2 > targets.txt

# Scan Nikto su tutti
for ip in $(cat targets.txt); do
    nikto -h http://$ip -output nikto_$ip.html -Format htm
done
```

### Nikto + [Nuclei](https://hackita.it/articoli/nuclei)

```bash
# Nikto per discovery
nikto -h http://target.com -output nikto.txt

# Nuclei per vulnerability validation
nuclei -u http://target.com -t cves/
```

### Script Automation

```bash
#!/bin/bash
# web_scan.sh - Automated web scanning

TARGET=$1
OUTPUT_DIR="scan_$(date +%Y%m%d)"
mkdir -p $OUTPUT_DIR

echo "[*] Starting Nikto scan on $TARGET"

nikto -h $TARGET \
      -output $OUTPUT_DIR/nikto.html \
      -Format htm \
      -Tuning x6 \
      -timeout 10

echo "[+] Report saved to $OUTPUT_DIR/nikto.html"

# Parse findings
grep -oP 'OSVDB-\d+' $OUTPUT_DIR/nikto.html | sort -u > $OUTPUT_DIR/osvdb_ids.txt
echo "[+] Found $(wc -l < $OUTPUT_DIR/osvdb_ids.txt) unique OSVDB entries"
```

## Troubleshooting

### Scan Troppo Lento

```bash
# Problema: scan impiega ore
# Fix: limita test
nikto -h http://target.com -Tuning 12 -timeout 5

# Riduci maxtime
nikto -h http://target.com -maxtime 30m
```

### Troppi False Positive

```bash
# Problema: risultati non verificabili
# Fix: verifica manualmente i finding critici

# Verifica file esiste
curl -I http://target.com/admin/

# Verifica vulnerability
curl http://target.com/cgi-bin/test.cgi
```

### Connection Refused

```bash
# Problema: impossibile connettersi
# Fix: verifica porta e protocollo
nmap -p 80,443 target.com

# Prova SSL/non-SSL esplicito
nikto -h target.com -ssl
nikto -h target.com -nossl
```

### SSL Certificate Error

```bash
# Problema: SSL verification failed
# Nikto ignora errori SSL di default
# Se persiste, prova:
nikto -h https://target.com -ssl -nossl
```

## Tabella Comparativa Scanner Web

| Feature         | Nikto | Nmap NSE | Nuclei | ZAP        |
| --------------- | ----- | -------- | ------ | ---------- |
| Speed           | Medio | Veloce   | Veloce | Lento      |
| Depth           | Alto  | Medio    | Alto   | Molto Alto |
| False Positives | Medio | Basso    | Basso  | Basso      |
| Customization   | Medio | Alto     | Alto   | Alto       |
| Reporting       | Base  | Base     | Buono  | Ottimo     |
| Active Scanning | Sì    | Sì       | Sì     | Sì         |

## FAQ

**Nikto è rumoroso?**

Sì, genera molto traffico e log. Non usare per stealth assessment. Usa evasion techniques per ridurre detection, ma non garantiscono invisibilità.

**Come riduco i false positive?**

Verifica sempre manualmente i finding critici con curl o browser. Non tutti i file "trovati" sono realmente accessibili o vulnerabili.

**Nikto trova vulnerabilità zero-day?**

No, Nikto testa solo vulnerabilità note nel suo database. Per zero-day usa fuzzing o testing manuale.

**Quanti test esegue Nikto?**

Oltre 6700 test nel database completo. Con tuning puoi limitare a categorie specifiche.

**Posso usare Nikto per bug bounty?**

Sì, ma verifica sempre le regole del programma. Alcuni vietano scanner automatici o richiedono rate limiting. Per pentest autorizzati, [hackita.it/servizi](https://hackita.it/servizi).

**Come aggiorno il database?**

`nikto -update` scarica le ultime signatures. Esegui regolarmente per avere test aggiornati.

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [Nikto GitHub](https://github.com/sullo/nikto) | [CIRT.net](https://cirt.net/Nikto2)
