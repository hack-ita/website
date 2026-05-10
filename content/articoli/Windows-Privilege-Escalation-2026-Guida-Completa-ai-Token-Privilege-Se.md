---
title: 'Windows Privilege Escalation 2026: Guida Completa ai Token Privilege (Se*)'
slug: windowsprivilegeescalation
description: 'Mappa completa dei token privilege Windows sfruttabili in un pentest. Da whoami /priv a SYSTEM: cheat sheet, tabelle, workflow e link alle guide operative.'
image: /windows-privilege-escalation-token-cheat-sheet.webp
draft: true
date: 2026-07-01T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - privilege-escalation
tags:
  - windows-privilege-escalation
  - token-privilege
  - se privesc
featured: true
---

# Windows Privilege Escalation 2026: Guida Completa ai Token Privilege (Se\*)

Hai una shell su una macchina Windows. Il passo successivo è quasi sempre lo stesso: `whoami /priv`. Quella riga sola ti dice tutto — quali privilegi hai, quali vettori sono disponibili, quanto sei vicino a `nt authority\system`. Questa guida copre tutti i **token privilege di Windows** sfruttabili in un pentest, con link alle guide operative complete per ognuno.

***

## Cos'è un Token Privilege su Windows

Windows assegna a ogni processo un **access token** — una struttura che contiene l'identità dell'utente, i gruppi di appartenenza e un elenco di privilegi (SePrivilege). Questi privilegi controllano cosa il processo può fare a livello di sistema: impersonare utenti, debuggare altri processi, caricare driver, leggere file bypassando le ACL.

La maggior parte dei privilegi è presente nel token ma **disabilitata** — i processi li abilitano quando ne hanno bisogno tramite `AdjustTokenPrivileges`. Alcuni tool come GodPotato, mimikatz e i vari Potato attack li abilitano automaticamente prima dell'exploit.

***

## Enumerazione — Il Primo Passo

### Verifica rapida dei privilegi

```cmd
whoami /priv
```

Questo è il comando più importante del post-exploitation Windows. Eseguilo sempre subito dopo aver ottenuto accesso.

### Enumerazione automatica completa

**winPEAS** — lo strumento più usato per l'enumeration automatica su Windows. Rileva privilegi, servizi vulnerabili, credenziali salvate, path hijackable e molto altro:

```cmd
winPEAS.exe quiet tokencheck
winPEAS.exe
```

**Seatbelt** — C# tool per audit di sicurezza host-side, più silenzioso di winPEAS:

```cmd
Seatbelt.exe TokenPrivileges
Seatbelt.exe -group=all
```

**accesschk** — Sysinternals, verifica chi ha un privilegio specifico nel sistema:

```cmd
accesschk.exe -a SeImpersonatePrivilege *
accesschk.exe -a SeDebugPrivilege *
```

**SharpUp** — audit rapido dei vettori di escalation più comuni:

```cmd
SharpUp.exe audit
```

**PrivescCheck** — script PowerShell alternativo a winPEAS:

```powershell
. .\PrivescCheck.ps1; Invoke-PrivescCheck
```

***

## Mappa dei Token Privilege — Da Privilegio a SYSTEM

Ogni privilegio apre vettori diversi. Questa tabella è il riferimento rapido — trova il privilegio che hai e vai direttamente alla guida operativa.

### Tier 1 — SYSTEM Immediato

I più comuni nei pentest reali. Se ne hai uno di questi, sei vicino a SYSTEM.

| Privilegio                        | Impatto                      | Vettore principale               | Guida                                                                         |
| --------------------------------- | ---------------------------- | -------------------------------- | ----------------------------------------------------------------------------- |
| **SeImpersonatePrivilege**        | SYSTEM shell                 | Potato attack (GodPotato)        | [→ Guida completa](https://hackita.it/articoli/seimpersonateprivilege)        |
| **SeAssignPrimaryTokenPrivilege** | SYSTEM shell                 | Potato attack (GodPotato `-t 2`) | [→ Guida completa](https://hackita.it/articoli/seassignprimarytokenprivilege) |
| **SeDebugPrivilege**              | LSASS dump → hash AD         | comsvcs.dll / nanodump           | [→ Guida completa](https://hackita.it/articoli/sedebugprivilege)              |
| **SeLoadDriverPrivilege**         | Ring-0, kill EDR, bypass PPL | BYOVD (Capcom.sys, RTCore64)     | [→ Guida completa](https://hackita.it/articoli/seloaddriverprivilege)         |

### Tier 2 — SYSTEM con un Servizio Target

Richiedono un servizio SYSTEM sfruttabile nell'ambiente — quasi sempre presente.

| Privilegio                   | Impatto                             | Vettore principale                | Guida                                                                    |
| ---------------------------- | ----------------------------------- | --------------------------------- | ------------------------------------------------------------------------ |
| **SeBackupPrivilege**        | SAM + NTDS.dit → tutti gli hash AD  | reg save + secretsdump            | [→ Guida completa](https://hackita.it/articoli/sebackupprivilege)        |
| **SeRestorePrivilege**       | Binary replacement → SYSTEM         | reg add ImagePath + robocopy /B   | [→ Guida completa](https://hackita.it/articoli/serestoreprivilege)       |
| **SeTakeOwnershipPrivilege** | File/registry arbitrari → SYSTEM    | takeown + icacls + binary replace | [→ Guida completa](https://hackita.it/articoli/setakeownershipprivilege) |
| **SeRelabelPrivilege**       | Bypass MIC → scrittura su file High | icacls /setintegritylevel         | [→ Guida completa](https://hackita.it/articoli/serelabelprivilege)       |
| **SeManageVolumePrivilege**  | Raw disk → SAM/NTDS.dit             | RawCopy + secretsdump             | [→ Guida completa](https://hackita.it/articoli/semanagevolumeprivilege)  |

### Tier 3 — Domain Compromise

Vettori che partono da account di dominio anche senza privilegi locali.

| Privilegio                    | Impatto      | Vettore principale            | Guida                                                                     |
| ----------------------------- | ------------ | ----------------------------- | ------------------------------------------------------------------------- |
| **SeMachineAccountPrivilege** | Domain Admin | RBCD + getST.py + secretsdump | [→ Guida completa](https://hackita.it/articoli/semachineaccountprivilege) |

### Tier 4 — Condizionali / Specifici

Richiedono condizioni particolari nell'ambiente o sono rari su account non di sistema.

| Privilegio                                    | Impatto                                | Vettore principale             | Guida                                                                                     |
| --------------------------------------------- | -------------------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------- |
| **SeCreateSymbolicLinkPrivilege**             | Scrittura arbitraria via TOCTOU        | mklink + race condition        | [→ Guida completa](https://hackita.it/articoli/secreatesymboliclinkprivilege)             |
| **SeDelegateSessionUserImpersonatePrivilege** | Token steal cross-session (RDS/Citrix) | NtObjectManager                | [→ Guida completa](https://hackita.it/articoli/sedelegatesessionuserimpersonateprivilege) |
| **SeSecurityPrivilege**                       | OpSec: cancella log, rimuovi SACL      | wevtutil + SetACL              | [→ Guida completa](https://hackita.it/articoli/sesecurityprivilege)                       |
| **SeTrustedCredManAccessPrivilege**           | Dump Credential Manager                | cmdkey + mimikatz + SharpDPAPI | [→ Guida completa](https://hackita.it/articoli/setrustedcredmanaccessprivilege)           |
| **SeSystemEnvironmentPrivilege**              | PATH hijacking / UEFI persistence      | reg add PATH + Process Monitor | [→ Guida completa](https://hackita.it/articoli/sesystemenvironmentprivilege)              |

### Tier 5 — Critici: Documenta Immediatamente

Quasi esclusivi di processi SYSTEM. Trovarli su account non di sistema è un finding P0.

| Privilegio                 | Impatto                                         | Nota                   | Guida                                                                  |
| -------------------------- | ----------------------------------------------- | ---------------------- | ---------------------------------------------------------------------- |
| **SeCreateTokenPrivilege** | Token forgery da zero con NtCreateToken         | **Finding critico P0** | [→ Guida completa](https://hackita.it/articoli/secreatetokenprivilege) |
| **SeTcbPrivilege**         | Logon session arbitrarie via LSA con SID custom | **Finding critico P0** | [→ Guida completa](https://hackita.it/articoli/setcbprivilege)         |

***

## Workflow di Escalation — Dalla Shell a SYSTEM

### Fase 1 — Enumera subito

```cmd
whoami /priv
whoami /groups
whoami /all
```

Poi automatizza:

```cmd
winPEAS.exe quiet tokencheck
Seatbelt.exe TokenPrivileges
```

### Fase 2 — Identifica il vettore

**Hai SeImpersonatePrivilege o SeAssignPrimaryTokenPrivilege?**
→ Potato attack → SYSTEM in 2 comandi.

**Sei nel gruppo Backup Operators?**
→ SeBackupPrivilege + SeRestorePrivilege → SAM dump + binary replacement.

**Hai SeDebugPrivilege in token elevato?**
→ comsvcs.dll MiniDump → LSASS → hash NTLM → PTH.

**Sei in Print Operators?**
→ SeLoadDriverPrivilege → BYOVD → ring-0 → bypass PPL e EDR.

**Hai solo credenziali di dominio?**
→ MachineAccountQuota → RBCD → Domain Admin.

### Fase 3 — Esegui il Quick Exploit

Ogni guida della serie ha un blocco **Quick Exploit** con i comandi minimi. Inizia sempre da lì.

### Fase 4 — Post-SYSTEM: Dump e Persistence

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

Oppure senza tool esterni:

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump [PID lsass] C:\temp\lsass.dmp full
```

Su macchina attaccante:

```bash
python3 pypykatz lsa minidump lsass.dmp
python3 secretsdump.py -sam sam.hive -system system.hive LOCAL
```

***

## Tool Essenziali — Cheatsheet

### Enumeration

| Tool         | Uso                             | Download                                                                           |
| ------------ | ------------------------------- | ---------------------------------------------------------------------------------- |
| winPEAS      | Enumeration automatica completa | [PEASS-ng GitHub](https://github.com/carlospolop/PEASS-ng)                         |
| Seatbelt     | Host survey offensivo           | [GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)                        |
| SharpUp      | Audit vettori comuni            | [GhostPack/SharpUp](https://github.com/GhostPack/SharpUp)                          |
| accesschk    | Verifica permessi e privilegi   | [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) |
| PrivescCheck | Script PowerShell alternativo   | [itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck)                        |

### Potato Attack (SeImpersonatePrivilege)

| Tool         | Versioni supportate   | Download                                                              |
| ------------ | --------------------- | --------------------------------------------------------------------- |
| GodPotato    | Win10 / Srv 2016–2022 | [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)   |
| PrintSpoofer | Win10 / Srv 2016–2019 | [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)           |
| SweetPotato  | Win10 / Srv 2016–2022 | [CCob/SweetPotato](https://github.com/CCob/SweetPotato)               |
| JuicyPotato  | Win7 / Srv 2008–2016  | [ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)             |
| RoguePotato  | Win10 / Srv 2016–2022 | [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato) |

### Credential Dump

| Tool                   | Uso                                              |
| ---------------------- | ------------------------------------------------ |
| `comsvcs.dll MiniDump` | LSASS dump — built-in Windows, zero tool esterni |
| mimikatz               | Dump LSASS, vault, DPAPI, ticket Kerberos        |
| nanodump               | LSASS dump con direct syscalls — evasion EDR     |
| SharpDPAPI             | Catena DPAPI completa — vault, credenziali       |
| Impacket secretsdump   | Dump offline SAM/NTDS + via rete su DC           |

### Active Directory

| Tool                                       | Uso                                  |
| ------------------------------------------ | ------------------------------------ |
| Impacket (addcomputer, getST, secretsdump) | RBCD, hash dump, ticket Kerberos     |
| Rubeus                                     | Ticket Kerberos, S4U, PTT — Windows  |
| PowerMad                                   | Computer account creation da Windows |
| PowerView                                  | Enumeration AD, ACL, RBCD config     |
| BloodHound                                 | Grafo AD — trova path verso DA       |

### Kernel / Driver

| Tool          | Uso                                     |
| ------------- | --------------------------------------- |
| EoPLoadDriver | Carica driver con SeLoadDriverPrivilege |
| ExploitCapcom | Kernel exec via Capcom.sys              |
| EDRSandBlast  | Kill EDR via kernel driver BYOVD        |
| LOLDrivers    | Lista driver firmati vulnerabili        |

***

## Gruppi AD da Controllare Sempre

Alcuni gruppi Active Directory assegnano privilegi critici per design. Verificali sempre nell'enumeration:

```cmd
net localgroup "Backup Operators"
net localgroup "Print Operators"
net localgroup "Server Operators"
net localgroup Administrators
```

```powershell
Get-ADGroupMember "Backup Operators" -Recursive | Select-Object Name, SamAccountName
Get-ADGroupMember "Print Operators" -Recursive | Select-Object Name, SamAccountName
```

| Gruppo               | Privilegi critici                      | Vettore                            |
| -------------------- | -------------------------------------- | ---------------------------------- |
| **Backup Operators** | SeBackupPrivilege + SeRestorePrivilege | SAM/NTDS dump + binary replacement |
| **Print Operators**  | SeLoadDriverPrivilege                  | BYOVD → ring-0 (anche sui DC)      |
| **Server Operators** | SeBackupPrivilege + altri              | Simile a Backup Operators          |

***

## Verifica Token Elevato o Non Elevato (UAC)

Molti privilegi — SeDebugPrivilege, SeTakeOwnershipPrivilege, SeImpersonatePrivilege — sono presenti nel token ma Disabled fuori da un processo elevato.

```cmd
whoami /groups | findstr "Mandatory"
```

* `High Mandatory Level` → token elevato → privilegi abilitabili
* `Medium Mandatory Level` → token non elevato (UAC split) → alcuni privilegi Disabled

Se sei in Medium e hai bisogno di un token elevato:

```cmd
runas /user:Administrator cmd
```

Oppure usa un bypass UAC (fuori scope di questa guida — dipende dall'ambiente).

***

## Detection — Cosa Logga Windows

Se sei in un ambiente monitorato, questi sono gli Event ID che generano alert più frequentemente:

|                Evento                | ID           | Trigger                       |
| :----------------------------------: | ------------ | ----------------------------- |
| Processo figlio anomalo (w3wp → cmd) | 4688         | Potato attack post-escalation |
|          Named pipe anomalo          | Sysmon 17/18 | GodPotato / PrintSpoofer      |
|          Accesso a lsass.exe         | Sysmon 10    | LSASS dump                    |
|    Pattern comsvcs.dll + lsass PID   | Sysmon 1     | LSASS dump built-in           |
|    Driver caricato da path anomalo   | Sysmon 6     | BYOVD                         |
|         Security log cleared         | 1102         | SeSecurityPrivilege           |
| Computer account creato da non-admin | 4741         | RBCD attack                   |
|        SAM / NTDS.dit accessed       | 4663         | SeBackupPrivilege             |

Per la gestione dell'OpSec e come ridurre il rumore: [→ SeSecurityPrivilege — Cancellare Log e Operare Invisibili](https://hackita.it/articoli/sesecurityprivilege)

***

## Riferimenti Esterni

* [HackTricks — Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
* [PayloadsAllTheThings — Windows PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
* [MITRE ATT\&CK — Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
* [LOLDrivers — Vulnerable Driver List](https://www.loldrivers.io)

***

## Indice Completo della Serie

Guida operativa completa per ogni privilegio Windows sfruttabile in un pentest:

1. [SeImpersonatePrivilege — Potato Attack da Webshell a SYSTEM](https://hackita.it/articoli/seimpersonateprivilege)
2. [SeAssignPrimaryTokenPrivilege — Potato Attack anche Senza SeImpersonate](https://hackita.it/articoli/seassignprimarytokenprivilege)
3. [SeBackupPrivilege — Dump SAM e NTDS.dit senza Shell sul DC](https://hackita.it/articoli/sebackupprivilege)
4. [SeRestorePrivilege — Binary Replacement e Backdoor Persistente](https://hackita.it/articoli/serestoreprivilege)
5. [SeDebugPrivilege — LSASS Dump e Credential Access](https://hackita.it/articoli/sedebugprivilege)
6. [SeTakeOwnershipPrivilege — Ownership Arbitraria su File e Servizi SYSTEM](https://hackita.it/articoli/setakeownershipprivilege)
7. [SeLoadDriverPrivilege — BYOVD, Kernel Code Execution e Kill EDR](https://hackita.it/articoli/seloaddriverprivilege)
8. [SeCreateSymbolicLinkPrivilege — Symlink Attack e Scrittura Arbitraria](https://hackita.it/articoli/secreatesymboliclinkprivilege)
9. [SeManageVolumePrivilege — Raw Disk Access per Estrarre SAM e NTDS.dit](https://hackita.it/articoli/semanagevolumeprivilege)
10. [SeDelegateSessionUserImpersonatePrivilege — Token Stealing Cross-Session su RDS](https://hackita.it/articoli/sedelegatesessionuserimpersonateprivilege)
11. [SeCreateTokenPrivilege — Token Forgery da Zero con NtCreateToken](https://hackita.it/articoli/secreatetokenprivilege)
12. [SeTcbPrivilege — Logon Session Arbitrarie via LSA](https://hackita.it/articoli/setcbprivilege)
13. [SeSecurityPrivilege — Cancellare Log e Operare Invisibili](https://hackita.it/articoli/sesecurityprivilege)
14. [SeTrustedCredManAccessPrivilege — Dump Credenziali RDP e Password Salvate](https://hackita.it/articoli/setrustedcredmanaccessprivilege)
15. [SeRelabelPrivilege — Bypass Mandatory Integrity Control](https://hackita.it/articoli/serelabelprivilege)
16. [SeMachineAccountPrivilege — RBCD da Utente di Dominio a Domain Admin](https://hackita.it/articoli/semachineaccountprivilege)
17. [SeSystemEnvironmentPrivilege — PATH Hijacking e Persistenza UEFI](https://hackita.it/articoli/sesystemenvironmentprivilege)

***

Hai trovato un privilegio non in questa lista o hai bisogno di supporto su un engagement specifico? [hackita.it/supporto](https://hackita.it/supporto)

Per assessment completi di privilege escalation e Active Directory: [hackita.it/servizi](https://hackita.it/servizi)
