---
title: 'Feroxbuster: Directory Bruteforcing Veloce e Ricorsivo per Web Hacking'
slug: feroxbuster
description: 'Feroxbuster è uno strumento ad alte prestazioni per directory e content discovery. Bruteforce ricorsivo, multi-thread e supporto proxy per test web avanzati.'
image: /Gemini_Generated_Image_msyul3msyul3msyu.webp
draft: true
date: 2026-02-13T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - directory-enumeration
---

# Feroxbuster: Directory Brute-Force Ricorsivo in Rust per Web App Pentesting

**DESCRIPTION:** Feroxbuster è un directory fuzzer ricorsivo scritto in Rust. Guida operativa: installazione, wordlist strategy, WAF bypass, integration con Burp, detection e OPSEC.

## Introduzione

Feroxbuster è uno scanner di directory e file web scritto in Rust con ricorsione automatica, link extraction e resume capability. Si posiziona tra [Nmap](https://hackita.it/articoli/nmap) service detection e exploitation: dopo aver identificato porte HTTP/HTTPS aperte, Feroxbuster enumera endpoint nascosti (admin panel, backup file, API routes, config esposti) che diventano entry point per privilege escalation o data exfiltration.

La kill chain tipica: Reconnaissance (SpiderFoot/Amass) → Port Scan (Nmap) → **Content Discovery (Feroxbuster)** → Vulnerability Scanning (Nikto/Nuclei) → Exploitation (Metasploit/manual).

Questo articolo copre comandi completi, wordlist selection, filtering avanzato, WAF evasion, integration con Burp Suite, blue team detection e difese.

**Versione attuale:** v2.13.1 (13 dicembre 2025)\
**Repository:** [https://github.com/epi052/feroxbuster](https://github.com/epi052/feroxbuster)\
**Linguaggio:** Rust (async/await + tokio runtime)

***

## Setup e Installazione

Cinque metodi di deployment da più veloce a più configurabile:

```bash
# Metodo 1: Kali Linux (pre-installato, 12.28 MB)
sudo apt update && sudo apt install feroxbuster
feroxbuster --version  # v2.13.1

# Metodo 2: Release binary GitHub
wget https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-linux-feroxbuster.zip
unzip x86_64-linux-feroxbuster.zip
sudo mv feroxbuster /usr/local/bin/
sudo chmod +x /usr/local/bin/feroxbuster

# Metodo 3: Cargo (Rust package manager)
cargo install feroxbuster

# Metodo 4: Snap (sandboxed, wordlist caveat)
sudo snap install feroxbuster
# Snap può leggere SOLO da ~/snap/feroxbuster/common/
ln -s /usr/share/seclists ~/snap/feroxbuster/common/wordlists

# Metodo 5: Docker
docker pull epi052/feroxbuster:latest
docker run --init -it epi052/feroxbuster -u http://target.com
```

**Verifica installazione:**

```bash
feroxbuster -u http://example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -n
```

Output atteso: lista di directory/file scoperti con status code e size.

**Configurazione opzionale:**

```bash
# Crea config file per preset personali
mkdir -p ~/.config/feroxbuster
nano ~/.config/feroxbuster/ferox-config.toml
```

Esempio `ferox-config.toml`:

```toml
threads = 50
timeout = 10
depth = 4
wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
extensions = ["php", "js", "txt"]
status_codes = [200, 301, 302, 401, 403]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

**Requisiti sistema:**

* Kali/Ubuntu/Debian o qualsiasi distro Linux
* 50-200 MB RAM per scan tipico
* SecLists wordlists installate: `sudo apt install seclists`

***

## Uso Base

**Sintassi minima:**

```bash
feroxbuster -u http://target.com
```

Questo usa default: 50 thread, depth 4, wordlist `raft-medium-directories.txt`, nessun filtro.

### Comandi fondamentali con output

**Scan standard WordPress:**

```bash
feroxbuster -u http://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt \
  -x php,txt,bak \
  -s 200,301,302,401,403 \
  -o wordpress_scan.txt
```

Output esempio:

```
200      GET       45l      156w     2048c http://target.com/wp-admin/
302      GET        0l        0w        0c http://target.com/wp-login.php => /wp-admin/
200      GET      234l      890w    15234c http://target.com/readme.html
403      GET        7l       10w      178c http://target.com/wp-config.php
200      GET       12l       45w      678c http://target.com/xmlrpc.php
```

Colonne: `status | method | lines | words | bytes | URL`

**Scan API REST:**

```bash
feroxbuster -u https://api.target.com \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -x json -n \
  --json -o api_results.json
```

Flag `-n`: disabilita ricorsione (API non hanno directory nidificate).

**Scan autenticato con sessione:**

```bash
feroxbuster -u http://target.com/admin \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -b "PHPSESSID=abc123def456" \
  -x php,asp \
  -r  # segue redirect
```

### Parametri chiave spiegati

| Flag        | Funzione           | Esempio                         |
| ----------- | ------------------ | ------------------------------- |
| `-u URL`    | Target URL         | `-u http://10.10.10.50`         |
| `-w FILE`   | Wordlist path      | `-w /path/to/wordlist.txt`      |
| `-x EXT`    | Estensioni file    | `-x php,asp,jsp,txt`            |
| `-t N`      | Thread concorrenti | `-t 100` (default: 50)          |
| `-d N`      | Depth ricorsione   | `-d 2` (default: 4, 0=infinito) |
| `-n`        | No recursion       | Scan flat                       |
| `-s CODE`   | Allow status codes | `-s 200,301,302`                |
| `-C CODE`   | Block status codes | `-C 404,403`                    |
| `-o FILE`   | Output file        | `-o results.txt`                |
| `--json`    | JSON output        | Parsing automatizzato           |
| `-H HEADER` | Custom header      | `-H "X-Custom: value"`          |
| `-b COOKIE` | Cookie             | `-b "session=xyz"`              |

**Default behavior:** Feroxbuster parte da URL base, trova directory (es. `/admin`), entra ricorsivamente, applica wordlist, ripete fino a depth 4. Link extraction è SEMPRE attiva: analizza HTML/JS delle risposte per trovare URL aggiuntivi.

***

## Tecniche Operative

### Recursive Scanning Strategy

La ricorsione è il differenziatore principale di Feroxbuster vs Gobuster/dirb:

```bash
# Ricorsione completa (default depth 4)
feroxbuster -u http://target.com -x php

# Scansione piatta (no recursion)
feroxbuster -u http://target.com -x php -n

# Ricorsione infinita (warning: può durare ore)
feroxbuster -u http://target.com -x php -d 0

# Force ricorsione su ogni endpoint (anche file)
feroxbuster -u http://target.com --force-recursion
```

**Esempio output ricorsivo:**

```
[##>-----------------] - 2m    4500/30000  scanning: http://target.com/admin
[##>-----------------] - 1m    2300/30000  scanning: http://target.com/admin/users
[#>------------------] - 30s    900/30000  scanning: http://target.com/admin/users/logs
```

Ogni directory scoperta genera una nuova scansione parallela fino a `--scan-limit`.

### Dynamic Collection per Max Coverage

**Collect words:** estrae parole dalle risposte e le aggiunge alla wordlist in realtime.

```bash
feroxbuster -u http://target.com -g
```

Se una pagina contiene "dashboard", "settings", "profile", queste parole vengono aggiunte alla queue di brute-force.

**Collect extensions:** auto-scopre estensioni dai file trovati.

```bash
feroxbuster -u http://target.com -E
```

Trova `index.php` → aggiunge `.php` a tutte le entry wordlist future. Trova `config.json` → aggiunge `.json`.

**Collect backups:** per ogni URL trovato, prova varianti backup.

```bash
feroxbuster -u http://target.com -B
```

Pattern testati: `file~`, `file.bak`, `file.bak2`, `file.old`, `file.1`, `file.save`.

**Preset thorough (tutto insieme + scan directory listings):**

```bash
feroxbuster -u http://target.com --thorough
```

Equivale a: `-g -E -B --scan-dir-listings`.

### Filtering Avanzato: Eliminare Falsi Positivi

**Problema:** wildcard response (tutte le 404 restituiscono 200 con pagina custom).

**Soluzione 1: Filter by similarity**

```bash
# Test manuale URL inesistente
curl http://target.com/nonexistent_xyz_test

# Se risponde 200 con pagina "Not Found", filtra per similarità
feroxbuster -u http://target.com \
  --filter-similar-to http://target.com/nonexistent_xyz_test
```

**Soluzione 2: Filter by size**

```bash
# Se wildcard 404 è sempre 4912 bytes
feroxbuster -u http://target.com -S 4912
```

**Soluzione 3: Regex filter**

```bash
# Filtra risposte contenenti specifiche stringhe
feroxbuster -u http://target.com -X "Page not found|Error 404|Not Found"
```

**Soluzione 4: Unique responses only (v2.13.1)**

```bash
# Usa SimHash per filtrare risposte duplicate
feroxbuster -u http://target.com --unique
```

SimHash calcola fingerprint della risposta, distance di Hamming \< threshold = duplicate filtrato.

### Rate Limiting e Stealth Mode

```bash
# Stealth completo: 2 req/sec, 2 thread, SOCKS proxy, random UA
feroxbuster -u http://target.com \
  --rate-limit 2 \
  --threads 2 \
  --scan-limit 2 \
  --proxy socks5h://127.0.0.1:9050 \
  -A \
  --auto-tune
```

`--auto-tune`: riduce automaticamente rate se rileva errori 429/503.\
`--auto-bail`: stoppa scan se troppi errori consecutivi.

**Rate limit formula:**

```
Connessioni attive = threads × scan-limit
Con --threads 2 --scan-limit 4 = 8 connessioni totali
```

Per WAF-protected target: `--threads 2-10`, `--rate-limit 5-10`.

***

## Tecniche Avanzate

### Integration con Burp Suite

**Replay Proxy:** invia solo risposte interessanti a Burp per analisi manuale.

```bash
feroxbuster -u http://target.com \
  --replay-proxy http://127.0.0.1:8080 \
  --replay-codes 200,302,403 \
  -x php,asp
```

Solo status 200/302/403 vengono inviati a Burp (porta 8080). Il resto viene scartato. Risparmio enorme di tempo vs inviare tutto a proxy.

**Feroxbuster attraverso Burp (tutto passa):**

```bash
feroxbuster -u http://target.com \
  --burp \
  -x php
```

`--burp` è shorthand per `--proxy http://127.0.0.1:8080 --insecure`.

### POST Request Fuzzing

```bash
# JSON body fuzzing
feroxbuster -u http://target.com/api \
  --data-json '{"username":"FUZZ","password":"test"}' \
  -m POST \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt

# URL-encoded body
feroxbuster -u http://target.com/login \
  --data-urlencoded "username=admin&password=FUZZ" \
  -m POST \
  -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
```

### Resume Interrupted Scans

Feroxbuster salva stato automaticamente in `ferox-http_<host>-<timestamp>.state`:

```bash
# Scan interrotto (Ctrl+C)
feroxbuster -u http://target.com -x php

# Resume
feroxbuster --resume-from ferox-http_target_com-1723370176.state
```

Unico tool tra dirb/Gobuster/ffuf con resume nativo.

### Multi-Target Pipeline

```bash
# Da stdin (output di altri tool)
cat urls.txt | feroxbuster --stdin --silent -x js,php -s 200,301

# Parallel scan multipli
cat targets.txt | xargs -P 5 -I {} feroxbuster -u {} -x php -o {}_results.txt
```

***

## Scenari Pratici di Pentest

### Scenario 1: CTF Web Challenge Fast Solve

**Obiettivo:** Trovare flag nascosta in directory sconosciuta.

**Timeline:** 5-15 minuti

```bash
# COMANDO
feroxbuster -u http://ctf-challenge.com \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x txt,php,html,zip \
  -t 100 \
  --depth 3 \
  --silent

# OUTPUT ATTESO
# 200    GET  /robots.txt
# 200    GET  /admin/
# 403    GET  /admin/backup/
# 200    GET  /admin/backup/flag.txt

# FOLLOW UP
curl http://ctf-challenge.com/admin/backup/flag.txt
# → FLAG{h1dd3n_d1r3ct0ry_br0k3n_4cc3ss}
```

**COSA FARE SE FALLISCE:**

* Nessun risultato? Cambia wordlist: prova `directory-list-2.3-medium.txt` (220k entries)
* 403 ovunque? Testa [bypass tecniche](https://hackita.it/articoli/bypass): `X-Original-URL`, `X-Rewrite-URL` headers
* Timeout? Aumenta `--timeout 20`

### Scenario 2: Enterprise Web App - Admin Panel Discovery

**Obiettivo:** Trovare admin interface nascosto su applicazione enterprise.

**Timeline:** 30-60 minuti

```bash
# FASE 1: Scan iniziale rapido
feroxbuster -u https://webapp.enterprise.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,asp,aspx,jsp \
  -s 200,301,302,401,403 \
  -o phase1.txt

# RISULTATI FASE 1
# 200  /login
# 200  /dashboard
# 403  /admin  ← INTERESSANTE
# 401  /api
# 200  /static/

# FASE 2: Focus su /admin con wordlist specifica
feroxbuster -u https://webapp.enterprise.com/admin \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -x php,asp \
  --rate-limit 10 \
  -s 200,302 \
  -o phase2_admin.txt

# RISULTATI FASE 2
# 302  /admin/login.php → /admin/dashboard
# 200  /admin/users.php
# 200  /admin/settings.php
# 200  /admin/backup.php  ← JACKPOT

# FASE 3: Test accesso diretto
curl -v https://webapp.enterprise.com/admin/backup.php
# → 200 OK, download database backup non protetto
```

**COSA FARE SE FALLISCE:**

* 403 su `/admin`? Prova path traversal: `/admin../admin/`, header bypass
* Rate limited? `--rate-limit 5`, `--threads 10`
* Nessun backup trovato? Prova `--collect-backups` (`-B`)

### Scenario 3: Bug Bounty - API Endpoint Enumeration

**Obiettivo:** Scoprire endpoint API non documentati per privilege escalation.

**Timeline:** 45-90 minuti

```bash
# FASE 1: Base API discovery
feroxbuster -u https://api.bugcrowd-target.com/v1 \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -x json \
  -H "Authorization: Bearer $TOKEN" \
  -n \
  --json -o api_base.json

# FASE 2: Smart collection (trova pattern)
feroxbuster -u https://api.bugcrowd-target.com/v1 \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  --smart \
  -H "Authorization: Bearer $TOKEN" \
  -x json \
  --json -o api_smart.json

# RISULTATI
# 200  /v1/users
# 200  /v1/users/{id}
# 200  /v1/admin  ← Non documentato
# 200  /v1/admin/users  ← Privilege escalation path
# 403  /v1/internal

# FASE 3: Test privilege escalation
curl -H "Authorization: Bearer $TOKEN" \
  https://api.bugcrowd-target.com/v1/admin/users
# → 200, lista tutti gli utenti inclusi admin (IDOR)
```

**COSA FARE SE FALLISCE:**

* Token scaduto? Refresh token in loop script
* Pochi endpoint? Usa `--collect-words` per estrarre path da risposte
* WAF block? `--rate-limit 2`, `--threads 5`, cambia User-Agent

***

## Toolchain Integration

### Flusso Attack Chain Completo

```
1. Nmap port scan
   ↓
2. Identificazione servizi HTTP/HTTPS
   ↓
3. Screenshot web (EyeWitness/Aquatone)
   ↓
4. FEROXBUSTER content discovery
   ↓
5. Vulnerability scan (Nikto/Nuclei)
   ↓
6. Manual exploitation
```

**Automazione pipeline:**

```bash
#!/bin/bash
# Step 1: Nmap scan per porte HTTP
nmap -p- --open -oG scan.txt $TARGET
grep -oP '\d+/open/tcp/http' scan.txt | cut -d'/' -f1 > http_ports.txt

# Step 2: Feroxbuster su ogni porta
while read port; do
  feroxbuster -u "http://$TARGET:$port" \
    -x php,asp,jsp,txt \
    -o "ferox_$port.txt" &
done < http_ports.txt
wait

# Step 3: Consolida risultati
cat ferox_*.txt | grep -E "200|301|302" > all_interesting.txt

# Step 4: Feed a Nuclei
cat all_interesting.txt | cut -d' ' -f7 | nuclei -t /path/to/templates/
```

### Integrazione dati tra tool

```bash
# Da SpiderFoot a Feroxbuster
jq -r '.[] | select(.type=="LINKED_URL_INTERNAL") | .data' spiderfoot.json \
  | feroxbuster --stdin -x php,js

# Da Amass a Feroxbuster
amass enum -d target.com -o subdomains.txt
cat subdomains.txt | sed 's/^/http:\/\//' | feroxbuster --stdin -n -x php

# Da Feroxbuster a SQLMap
grep "200.*php?id=" ferox_results.txt | cut -d' ' -f7 > sqli_targets.txt
cat sqli_targets.txt | xargs -I {} sqlmap -u {} --batch --risk 3
```

***

## Attack Chain Completa

**Scenario Red Team: Corporate Web Application Compromise**

```bash
# STEP 1: Reconnaissance (2h)
# Già completato con SpiderFoot: 30 subdomains, 50 IP

# STEP 2: Port Scan (30 min)
nmap -iL targets.txt -p- -T4 -oA nmap_scan

# STEP 3: HTTP Services Identification (10 min)
cat nmap_scan.gnmap | grep "80/open\|443/open\|8080/open" \
  | cut -d' ' -f2 > web_targets.txt

# STEP 4: FEROXBUSTER Mass Scan (2h)
cat web_targets.txt | while read target; do
  feroxbuster -u "http://$target" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -x php,asp,aspx,jsp,txt,bak \
    --rate-limit 10 \
    --threads 20 \
    -s 200,301,302,401,403,500 \
    -o "ferox_${target//\//_}.txt" &
done
wait

# STEP 5: Identificazione Vulnerabilità (1h)
# Trovato: backup.php su staging.target.com
curl http://staging.target.com/backup.php
# → Download database backup con hash password

# STEP 6: Password Cracking (30 min)
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
# → 3 password crackate

# STEP 7: Credential Testing (15 min)
hydra -L usernames.txt -P cracked_passwords.txt ssh://target.com
# → SSH access con user "developer"

# STEP 8: Privilege Escalation (varia)
# Pivot interno con [Chisel](https://hackita.it/articoli/chisel) + [LinPEAS](https://hackita.it/articoli/linpeas)
```

**Risultato:** Accesso SSH → pivot rete interna → Active Directory compromise.

***

## Detection & Evasion

### Blue Team Detection Signatures

**Nginx access log pattern:**

```
192.168.1.100 - - [06/Feb/2026:10:23:45 +0000] "GET /admin HTTP/1.1" 403 178
192.168.1.100 - - [06/Feb/2026:10:23:45 +0000] "GET /administrator HTTP/1.1" 404 196
192.168.1.100 - - [06/Feb/2026:10:23:45 +0000] "GET /wp-admin HTTP/1.1" 302 0
192.168.1.100 - - [06/Feb/2026:10:23:46 +0000] "GET /backup HTTP/1.1" 404 196
...
(50+ richieste in 60 secondi)
```

Pattern riconoscibili:

* **High 404 rate:** 50+ in 1 minuto
* **Sequential wordlist pattern:** `/admin`, `/administrator`, `/admin123`
* **User-Agent:** `feroxbuster/2.13.1` (default, trivialmente rilevabile)

**Splunk Detection Query:**

```spl
index=web_logs sourcetype=access_combined
| bin _time span=1m
| stats count as requests, dc(uri) as unique_paths by clientip, _time
| where requests > 50 AND unique_paths > 40
| table _time, clientip, requests, unique_paths
```

**Elastic SIEM Query:**

```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-5m"}}},
        {"term": {"http.response.status_code": 404}}
      ]
    }
  },
  "aggs": {
    "by_ip": {
      "terms": {"field": "source.ip"},
      "aggs": {"count_404": {"value_count": {"field": "http.response.status_code"}}}
    }
  }
}
```

### WAF Bypass Techniques

**Cloudflare bypass stack:**

```bash
# 1. User-Agent rotation
feroxbuster -u https://target.com -A  # random UA ogni richiesta

# 2. Rate limiting severo
feroxbuster -u https://target.com --rate-limit 2 --threads 2

# 3. Custom headers
feroxbuster -u https://target.com \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Original-URL: /admin"

# 4. SOCKS proxy (Cloudflare blocca molti proxy HTTP)
feroxbuster -u https://target.com \
  --proxy socks5h://127.0.0.1:9050

# 5. Auto-tune per adaptive throttling
feroxbuster -u https://target.com --auto-tune --auto-bail
```

**AWS WAF bypass:**

```bash
# Case sensitivity bypass
# Se WAF blocca /admin, prova /Admin, /ADMIN, /aDmIn
feroxbuster -u https://target.com \
  -w wordlist-case-variants.txt

# Path traversal bypass
# /admin → blocca
# /./admin → potrebbe passare
# /admin/../admin/ → potrebbe passare
```

**ModSecurity bypass:**

```bash
# Payload obfuscation in extensions
feroxbuster -u https://target.com \
  -x php,php3,php5,phtml,phps,pht
```

### OPSEC Stealth Matrix

| Configurazione                                       | Detectability   | Speed       | Use Case               |
| ---------------------------------------------------- | --------------- | ----------- | ---------------------- |
| Default (50 thread)                                  | **Alta**        | Veloce      | Lab locale             |
| `--threads 10 --rate-limit 10`                       | Media           | Media       | Target remoto standard |
| `--threads 2 --rate-limit 2 -A`                      | Bassa           | Lenta       | WAF-protected          |
| `--threads 2 --rate-limit 2 --proxy socks5://TOR -A` | **Molto bassa** | Molto lenta | Bug bounty / Red team  |

**OPSEC checklist:**

* ✅ Custom User-Agent (`-a` o `-A`)
* ✅ Rate limiting (`--rate-limit`)
* ✅ Thread control (`--threads`)
* ✅ Proxy/VPN (`--proxy`)
* ✅ Time-of-day (scan di notte UTC quando SOC ha meno personale)
* ❌ Non usare IP corporate
* ❌ Non scannare da IP già flaggato in threat intel

***

## Performance & Scaling

### Threading Ottimale per Scenario

```bash
# Lab localhost (nessun limite)
feroxbuster -u http://localhost -t 200 -w huge.txt

# VPS remoto (10-100ms latency)
feroxbuster -u http://remote.com -t 50  # default ok

# Shared hosting (rate limited server)
feroxbuster -u http://shared.com -t 10 --rate-limit 10

# WAF-protected
feroxbuster -u https://waf-protected.com -t 2 --rate-limit 2 --auto-tune

# Bug bounty (low-and-slow)
feroxbuster -u https://bounty-target.com -t 5 --rate-limit 3
```

**Benchmark reale (Intel i7, 50 thread, common.txt 4600 entries, target localhost):**

```
Time: 52 seconds
Requests: 4600
Req/sec: ~88
```

Identico a Gobuster stessa configurazione. La differenza è nella **ricorsione** che moltiplica coverage.

### Wordlist Strategy Optimization

| Fase          | Wordlist                        | Entries | Tempo (50t) | Coverage   |
| ------------- | ------------------------------- | ------- | ----------- | ---------- |
| **Quick win** | `common.txt`                    | 4.6k    | \~1 min     | Basso      |
| **Standard**  | `raft-medium-directories.txt`   | 30k     | \~5 min     | Medio      |
| **Thorough**  | `directory-list-2.3-medium.txt` | 220k    | \~30 min    | Alto       |
| **Maximum**   | `directory-list-2.3-big.txt`    | 1.2M    | \~2h        | Molto alto |
| **Targeted**  | `CMS/wordpress.txt`             | varia   | varia       | Specifico  |

**Best practice:** Start small, go big se necessario.

```bash
# 1. Quick scan
feroxbuster -u $TARGET -w common.txt -x php

# 2. Se trovi poco, escalate
feroxbuster -u $TARGET -w raft-medium-directories.txt -x php

# 3. Se ancora poco, full power
feroxbuster -u $TARGET -w directory-list-2.3-medium.txt -x php --depth 2
```

***

## Tabelle Tecniche

### Command Reference Completo

| Comando                                                                            | Scenario                | Output        |
| ---------------------------------------------------------------------------------- | ----------------------- | ------------- |
| `feroxbuster -u http://target.com`                                                 | Scan base default       | Terminale     |
| `feroxbuster -u http://target.com -x php,txt,bak -o results.txt`                   | Backup file hunt        | File output   |
| `feroxbuster -u http://target.com --burp -x php`                                   | Proxy attraverso Burp   | Burp history  |
| `feroxbuster -u http://target.com --replay-proxy http://127.0.0.1:8080 -R 200,302` | Replay selettivo a Burp | Burp + file   |
| `feroxbuster -u http://target.com -H "Authorization: Bearer $TOKEN" -x json`       | API autenticata         | JSON results  |
| `feroxbuster -u http://target.com --rate-limit 5 -t 10 --auto-tune`                | WAF evasion             | Stealth mode  |
| `cat urls.txt \| feroxbuster --stdin --silent -x js`                               | Multi-target pipeline   | Batch output  |
| `feroxbuster --resume-from state-file.state`                                       | Resume scan             | Continue scan |

### Comparison Table: Feroxbuster vs Competitors

| Feature                   | Feroxbuster         | Gobuster      | ffuf             | dirb   | dirsearch  |
| ------------------------- | ------------------- | ------------- | ---------------- | ------ | ---------- |
| **Linguaggio**            | Rust                | Go            | Go               | C      | Python     |
| **Ricorsione automatica** | ✅ depth 4           | ❌             | ⚠️ manuale       | ✅      | ✅          |
| **Link extraction**       | ✅ HTML/JS/robots    | ❌             | ❌                | ❌      | ❌          |
| **Resume scan**           | ✅ state files       | ❌             | ❌                | ❌      | ❌          |
| **Replay proxy**          | ✅ selettivo         | ❌             | ❌                | ❌      | ❌          |
| **FUZZ keyword**          | ❌ (URL only)        | ❌             | ✅                | ❌      | ❌          |
| **Auto-tune rate**        | ✅                   | ❌             | ❌                | ❌      | ❌          |
| **Performance**           | ★★★★★               | ★★★★★         | ★★★★★            | ★★     | ★★★        |
| **Best for**              | Recursive discovery | Fast one-shot | Advanced fuzzing | Legacy | Python env |

**Quando scegliere Feroxbuster:**

* Scan ricorsivi profondi su web app complesse
* Resume capability necessaria (scan lunghi)
* Replay proxy per analisi manuale ridotta
* Link extraction per coverage massima

**Quando scegliere ffuf:**

* Fuzzing parametri GET/POST
* Virtual host discovery
* Header fuzzing
* Keyword FUZZ in path/body/header

***

## Troubleshooting

### Errore: "Too Many Requests (429)"

```bash
# Causa: Rate limiting server/WAF
# Fix 1: Rate limit
feroxbuster -u $TARGET --rate-limit 5

# Fix 2: Auto-tune (riduce automaticamente rate)
feroxbuster -u $TARGET --auto-tune

# Fix 3: Meno thread
feroxbuster -u $TARGET --threads 5
```

### Errore: "Connection Timeout"

```bash
# Causa: Server lento o firewall
# Fix: Aumenta timeout (default 7s)
feroxbuster -u $TARGET --timeout 20
```

### Problema: Falsi positivi massivi (tutte 200)

```bash
# Causa: Wildcard response
# Fix 1: Filter by size
feroxbuster -u $TARGET -S 4912  # size wildcard response

# Fix 2: Filter by similarity
feroxbuster -u $TARGET --filter-similar-to http://target.com/xyz-nonexistent

# Fix 3: Unique responses (SimHash)
feroxbuster -u $TARGET --unique
```

### Problema: Memory exhaustion

```bash
# Causa: Risposte enormi (es. file download endpoint)
# Fix: Limit response size (v2.13.1+)
feroxbuster -u $TARGET --response-size-limit 2097152  # 2MB

# Default è 4MB, riducilo se necessario
```

### Warning: "SecLists not found"

```bash
# Causa: Wordlist non installate
# Fix Debian/Ubuntu:
sudo apt install seclists

# Fix Arch:
yay -S seclists

# Manual:
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
```

***

## FAQ

**Q: Feroxbuster è rilevabile dai WAF?**\
A: Sì, se usi configurazione default. User-Agent `feroxbuster/2.13.1` è signature palese. Mitiga con `-A` (random UA), rate limiting, proxy rotation.

**Q: Quanto è più veloce di dirb?**\
A: 10-50x più veloce grazie a Rust async/await. dirb è single-threaded in C, Feroxbuster usa green threads (tokio runtime).

**Q: Posso usare Feroxbuster per fuzzing parametri?**\
A: Limitato. Supporta POST body fuzzing (`--data-json`, `--data-urlencoded`) ma non ha keyword FUZZ come ffuf. Per fuzzing completo usa ffuf.

**Q: Come integro con nuclei per vulnerability scan?**\
A: `feroxbuster -u $TARGET --silent | nuclei -l -`. Pipe URL trovati direttamente a Nuclei templates.

**Q: La ricorsione automatica è un problema?**\
A: Può generare scan lunghissimi. Usa `-d 2` per limitare depth, o `-n` per disabilitare completamente.

**Q: State files occupano spazio. Come gestirli?**\
A: Elimina vecchi state: `find . -name "ferox-*.state" -mtime +7 -delete` (più vecchi di 7 giorni).

**Q: Qual è la differenza tra --proxy e --replay-proxy?**\
A: `--proxy`: TUTTE le richieste passano dal proxy. `--replay-proxy`: solo richieste con status code specificati (`-R`) vanno al replay proxy. Utile per inviare solo 200/302 a Burp.

***

## Cheat Sheet Finale

```bash
# SCAN STANDARD
feroxbuster -u http://target.com -x php,txt,bak

# CTF FAST MODE
feroxbuster -u http://ctf.com -t 100 -x txt,php,html -w common.txt -n

# WORDPRESS HUNT
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt -x php

# API DISCOVERY
feroxbuster -u https://api.target.com -w api-endpoints.txt -x json -n --json

# AUTHENTICATED SCAN
feroxbuster -u http://target.com -H "Authorization: Bearer $TOKEN" -b "session=$SESS" -x php

# STEALTH MODE
feroxbuster -u http://target.com --rate-limit 2 -t 2 --proxy socks5://127.0.0.1:9050 -A

# BURP INTEGRATION (tutto passa)
feroxbuster -u http://target.com --burp -x php

# BURP REPLAY (solo status interessanti)
feroxbuster -u http://target.com --replay-proxy http://127.0.0.1:8080 -R 200,302,403

# BACKUP FILE HUNT
feroxbuster -u http://target.com -B -x bak,old,txt,zip

# MULTI-TARGET
cat targets.txt | feroxbuster --stdin --silent -x php,js -o all_results.txt

# RESUME SCAN
feroxbuster --resume-from ferox-http_target-1234567890.state

# SMART COLLECTION
feroxbuster -u http://target.com --smart -x php

# THOROUGH (all features)
feroxbuster -u http://target.com --thorough -x php,asp,jsp

# UNIQUE RESPONSES ONLY
feroxbuster -u http://target.com --unique -x php
```

***

## Perché è ancora molto rilevante nel 2026

Il web moderno usa Single Page Applications (React/Vue/Angular), API REST/GraphQL, e microservizi containerizzati. I path endpoint non sono più semplici `/admin.php` ma `/api/v2/admin/users/{uuid}/permissions`. Feroxbuster con **link extraction** scopre questi endpoint dinamici analizzando JavaScript bundle, mentre scanner tradizionali come dirb falliscono. La **ricorsione** permette di navigare architetture API complesse (5-10 livelli depth). La **resume capability** è critica per scan 2-3 ore su target enterprise vasti. EDR/XDR moderni bloccano exploit — trovare admin panel dimenticato è spesso più efficace.

## Differenza rispetto ad alternative

**Gobuster:** Identica velocità, ma nessuna ricorsione → Gobuster per scan flat veloci (virtual hosts, DNS), Feroxbuster per content discovery ricorsiva.

**ffuf:** Superiore per fuzzing parametri/headers/vhost, ma nessun link extraction → ffuf per fuzzing complesso, Feroxbuster per directory discovery.

**dirb:** Molto più lento (single thread), ricorsione c'è ma limitata → dirb è legacy, Feroxbuster lo sostituisce completamente.

**dirsearch:** Veloce ma Python (overhead), nessun resume → dirsearch accettabile, Feroxbuster è upgrade diretto.

## Hardening / Mitigazione

**Difese contro Feroxbuster:**

1. Rate limiting Nginx/Apache

```nginx
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req zone=api_limit burst=20 nodelay;
```

1. Fail2ban per directory brute-force

```ini
[web-dirbrute]
enabled = true
filter = web-dirbrute
logpath = /var/log/nginx/access.log
maxretry = 30
findtime = 60
bantime = 3600
```

1. WAF rules ModSecurity

```apache
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)feroxbuster|gobuster|dirb" \
"id:1001,phase:1,deny,status:403"
```

1. Directory listing disable

```apache
Options -Indexes
```

1. File extension blocking

```nginx
location ~* \.(bak|old|save|backup|config)$ {
    deny all;
}
```

## OPSEC e Detection

**Footprint lato target:**

* Log: 50-1000 richieste GET in 1-5 minuti
* Pattern: Wordlist sequenziale riconoscibile
* User-Agent: `feroxbuster/2.13.1` di default
* Status code: Spike di 404 + alcune 200/403

**Evasione:**

* User-Agent rotation (`-A`)
* Rate limiting (`--rate-limit 2-5`)
* Thread control (`--threads 2-10`)
* Proxy/TOR (`--proxy socks5://...`)
* Time-of-day (night scan quando SOC understaff)

**Windows Event ID (se tool gira da Windows):**

* **EventID 4688:** Process creation `feroxbuster.exe`
* **Sysmon ID 3:** Network connections (volume HTTP request anomalo)

***

## Disclaimer

Questo contenuto è esclusivamente per penetration testing autorizzato e formazione educativa. L'uso di Feroxbuster contro target senza permesso scritto è illegale. Assicurati di operare solo in scope autorizzati: contratti pentest, bug bounty program in-scope, ambienti lab personali. Le tecniche WAF bypass descritte sono per comprendere difese, non per abuso.

**Repository ufficiale:** [https://github.com/epi052/feroxbuster](https://github.com/epi052/feroxbuster)\
**Documentazione:** [https://epi052.github.io/feroxbuster-docs/](https://epi052.github.io/feroxbuster-docs/)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
