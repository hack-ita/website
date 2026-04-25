---
title: >-
  Porta 138 NetBIOS Datagram: Guida al Penetration Testing del Servizio
  Broadcast Windows
slug: porta-138-netbios-datagram
description: >-
  Porta 138 aperta? Attack surface minimal nel 2026, ma indica NetBIOS
  abilitato. Focus su porta 137 con Responder e 445 con SMB — quelli sono i
  vettori reali.
image: /porta-138-netbios-datagram.webp
draft: false
date: 2026-04-26T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - netbios
---

La porta 138 espone **NetBIOS Datagram Service** (NBDS) — il protocollo UDP connectionless per broadcast messaging su reti Windows legacy, operante come transport layer per Windows Browser Service, Messenger Service e Workgroup Announcements. NetBIOS Datagram usa UDP porta 138 per inviare messaggi broadcast/multicast senza connessione affidabile, permettendo a servizi Windows di annunciare presenza (Master Browser elections), inviare popup messages (net send legacy), e coordinare browse lists di risorse di rete condivise. In penetration testing, la porta 138 ha **attack surface limitato** rispetto a porte 137/139 ma rimane vettore per: information disclosure via browser service enumeration, denial of service tramite malformed datagrams, e historical exploits (MS06-035 Mailslot vulnerability). Ogni rete Windows legacy con NetBIOS abilitato espone porta 138 ma exploitation moderna è minimal — focus primario è reconnaissance e understanding Windows networking stack.

NetBIOS porta 138 sopravvive nel 2026 come **dependency tecnica** di porta 137 (Name Service) — impossibile avere 137 senza 138 perché Windows NetBIOS stack richiede entrambi. Windows 10/11 con NetBIOS disabled chiude automaticamente 138, ma legacy systems (Windows 7/8, Server 2008/2012) con NetBIOS abilitato espongono 138 di default. Attack surface moderna è minimal: Mailslot exploits patched (MS06-035), net send disabled post-XP, Browser Service deprecato. In CTF/AD labs, porta 138 è **rarely exploited directly** — serve più per understanding NetBIOS architecture che per vettori offensive specifici.

***

## Anatomia tecnica di NetBIOS Datagram

NetBIOS Datagram usa **UDP porta 138** con protocollo connectionless broadcast.

**Flow NetBIOS datagram:**

1. **Broadcast Message** — Host invia datagram UDP 138 a broadcast address (255.255.255.255)
2. **All Hosts Receive** — Ogni host su LAN segment riceve datagram
3. **Service Processing** — Windows service (Browser, Messenger) processa message
4. **No Response** — Datagram è one-way, no acknowledgment

**NetBIOS datagram types:**

| Type          | Function                      | Modern relevance                 |
| ------------- | ----------------------------- | -------------------------------- |
| Direct Unique | Point-to-point message        | Minimal (replaced by SMB)        |
| Direct Group  | Multicast to group            | Browser elections                |
| Broadcast     | All hosts on segment          | **Legacy service announcements** |
| Error         | Datagram failure notification | Debugging                        |

**Services using NetBIOS Datagram (legacy):**

| Service                 | Function                      | Status 2026             |
| ----------------------- | ----------------------------- | ----------------------- |
| Browser Service         | Network resource browse lists | Deprecato               |
| Messenger Service       | net send popup messages       | **Disabled post-XP**    |
| Mailslot                | IPC for SMB                   | Replaced by named pipes |
| Workgroup Announcements | Computer presence broadcast   | Legacy only             |

**NetBIOS Datagram vs alternatives:**

| Feature      | NBDS (UDP 138)     | Modern alternative     |
| ------------ | ------------------ | ---------------------- |
| Transport    | UDP connectionless | TCP reliable (SMB 445) |
| Discovery    | Broadcast          | DNS, Active Directory  |
| Messaging    | net send           | Email, Slack, Teams    |
| Browse lists | Browser Service    | Active Directory       |

Le **misconfigurazioni** (rare nel 2026): NetBIOS abilitato su workstations modern (security risk minimo ma surface inutile), firewall permette UDP 138 da untrusted networks (reconnaissance facilitato), e legacy Windows XP/2003 con Mailslot unpatched (CVE-2006-3439).

***

## Enumerazione base

```bash
nmap -sU -p 138 10.10.10.138
```

```
PORT    STATE         SERVICE
138/udp open|filtered netbios-dgm
```

**Parametri:** `-sU` UDP scan. Output `open|filtered` normale per UDP — NetBIOS Datagram è broadcast, difficile distinguere open vs filtered senza traffico.

**Verifica manuale con broadcast test:**

```bash
# Send NetBIOS broadcast datagram
# Tool: nbtscan con opzione verbose
nbtscan -v 10.10.10.0/24
```

**Se porta 138 attiva, broadcast datagrams processed.**

### NSE NetBIOS Datagram scripts

```bash
nmap -sU -p 138 --script nbns-interfaces 10.10.10.138
```

```
PORT    STATE SERVICE
138/udp open  netbios-dgm
| nbns-interfaces:
|   hostname: WORKSTATION01
|   interfaces:
|     10.10.10.138
|_    fe80::1234:5678:abcd:ef01
```

***

## Tecniche offensive (limitate)

### 1. Information disclosure via Browser Service

**Legacy technique (pre-Windows 10):**

```bash
# Query Master Browser
nmblookup -M -- -
```

```
10.10.10.10    CORP<1D>
```

**Master Browser identified:** 10.10.10.10 (likely Domain Controller).

**Enumerate browse list:**

```bash
smbclient -L //10.10.10.10 -N
```

```
Sharename       Type      Comment
---------       ----      -------
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
SYSVOL          Disk      Logon server share
```

**Note:** Browser Service usa datagram 138 ma query effettiva via SMB 139/445.

### 2. Denial of Service (historical)

**MS06-035 Mailslot vulnerability (patched 2006):**

```bash
# Exploit CVE-2006-3439 (Windows 2000/XP/2003)
# Malformed Mailslot datagram → buffer overflow → DoS/RCE
```

**Modern relevance:** Zero. Tutti systems post-2006 patched.

### 3. Network reconnaissance passivo

```bash
# Capture NetBIOS datagrams (browser elections, announcements)
tcpdump -i eth0 -n port 138
```

```
15:30:00.123 IP 10.10.10.100.138 > 10.10.10.255.138: NBT UDP PACKET(138): BROADCAST
    Host Announcement: WORKSTATION01 running Windows 10
15:30:15.456 IP 10.10.10.50.138 > 10.10.10.255.138: NBT UDP PACKET(138): BROADCAST
    Master Browser Election: FILESERVER
```

**Intelligence:** WORKSTATION01 (Windows 10), FILESERVER (Master Browser candidate).

### 4. Messenger Service abuse (Windows XP legacy)

**Historical attack (pre-XP SP2):**

```bash
# net send spam (Windows XP era)
net send * "Your computer has a virus! Call 1-800-SCAM"
```

**Modern relevance:** Zero. Messenger Service disabled post-XP SP2 (2004).

***

## Scenari pratici

### Scenario 1 — Passive NetBIOS Datagram monitoring → network map

**Contesto:** Stealth reconnaissance, avoid active scanning.

```bash
# Passive capture UDP 138 traffic
sudo tcpdump -i eth0 -n port 138 -w netbios_dgm.pcap

# Let run for 1-2 hours during business hours
```

```bash
# Analyze captured datagrams
tshark -r netbios_dgm.pcap -Y "nbdgm" -T fields -e ip.src -e nbdgm.source_name -e frame.time | sort -u
```

```
10.10.10.10  DC01          2026-02-06 09:00:00
10.10.10.50  FILESERVER    2026-02-06 09:15:30
10.10.10.100 WORKSTATION01 2026-02-06 10:30:00
```

**Network topology discovered** senza attivescanning!

**Timeline:** 2 ore passive monitoring, zero detection risk.

**COSA FARE SE FALLISCE:**

* **No datagrams captured:** NetBIOS disabled (expected modern), focus on other vectors
* **Firewall blocks:** Unlikely UDP 138 inbound filtered, more likely NetBIOS fully disabled

### Scenario 2 — Browser Service enumeration (legacy Windows)

**Contesto:** CTF Windows XP/2003 legacy network.

```bash
# Find Master Browser
nmblookup -M -- -
```

```
10.10.10.50    __MSBROWSE__<01>
```

**Master Browser:** 10.10.10.50

```bash
# Enumerate network resources
net view /domain:WORKGROUP
```

```
Server Name            Remark
-------------------------------------------------------------------------------
\\FILESERVER          File Server
\\PRINTSERVER         Print Server
\\OLDXP               Windows XP Legacy
```

```bash
# Target old systems
nmap -sV -O 10.10.10.50
```

```
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
OS: Windows XP SP2
```

**Windows XP identified** → target for [MS08-067](https://hackita.it/articoli/ms08-067).

### Scenario 3 — Understanding why port 138 is open

**Contesto:** Security audit, minimize attack surface.

```bash
# Check NetBIOS status on Windows
Get-NetAdapter | Get-NetAdapterBinding -ComponentID ms_netbios
```

```
Name             : Ethernet
DisplayName      : Client for Microsoft Networks
ComponentID      : ms_netbios
Enabled          : True
```

**NetBIOS enabled** → porta 138 aperta.

**Disable NetBIOS:**

```powershell
Get-NetAdapter | Set-NetAdapterBinding -ComponentID ms_netbios -Enabled $false
```

**Verify:**

```bash
nmap -sU -p 138 localhost
# 138/udp closed netbios-dgm
```

***

## Detection & evasion

### Lato Blue Team

**Monitoring (minimal logging port 138):**

```powershell
# Windows Event Log - no specific Event ID for port 138
# Generic network activity in System log
```

**IoC critici:**

* High volume UDP 138 traffic (unusual, potential DoS)
* Broadcast datagrams from unexpected IPs (rogue hosts)
* Legacy protocols active su modern Windows (misconfiguration)

**Mitigation:**

```powershell
# Disable NetBIOS (disabilita anche 137, 138, 139)
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable
}
```

### Lato Red Team

**Port 138 attack surface è minimal** — no modern exploits, limited reconnaissance value. Focus su porte 137 (name poisoning) e 139/445 (SMB).

***

## Performance & scaling

**UDP 138 scan (subnet):**

```bash
time nmap -sU -p 138 10.10.10.0/24
# ~10 minutes per /24 (UDP scan slow)
```

**Passive monitoring:**

```bash
# tcpdump port 138 capture: <1% network bandwidth
# Minimal resource usage
```

***

## Tabelle tecniche

### Command reference

| Comando                                                         | Scopo                          | Note                   |
| --------------------------------------------------------------- | ------------------------------ | ---------------------- |
| `nmap -sU -p 138 <target>`                                      | NetBIOS Datagram detection     | UDP scan               |
| `tcpdump -i eth0 port 138`                                      | Passive monitoring             | Capture broadcasts     |
| `nmblookup -M -- -`                                             | Find Master Browser            | Legacy Browser Service |
| `Get-NetAdapterBinding -ComponentID ms_netbios`                 | Check NetBIOS status (Windows) | PowerShell             |
| `Set-NetAdapterBinding -ComponentID ms_netbios -Enabled $false` | Disable NetBIOS                | PowerShell             |

### NetBIOS ports comparison

| Porta | Protocol | Service      | Attack surface 2026           |
| ----- | -------- | ------------ | ----------------------------- |
| 137   | UDP      | Name Service | **High** (Responder)          |
| 138   | UDP      | Datagram     | ⚠️ Low (reconnaissance only)  |
| 139   | TCP      | Session      | **High** (SMB attacks)        |
| 445   | TCP      | SMB Direct   | **Critical** (primary target) |

***

## Troubleshooting

| Errore                | Causa                                  | Fix                        |
| --------------------- | -------------------------------------- | -------------------------- |
| Port closed           | NetBIOS disabled (expected modern)     | Normal, no action needed   |
| No datagrams captured | No broadcast traffic or VLAN isolation | Extend capture time        |
| nmblookup fails       | Browser Service disabled               | Expected on modern Windows |

***

## FAQ

**Porta 138 è vulnerabile nel 2026?**

No. Legacy exploits (MS06-035 Mailslot) patched 2006. Attack surface moderna è minimal.

**Perché porta 138 è aperta se non ha exploits?**

Technical dependency: NetBIOS stack richiede 137+138+139 together. Se 137 abilitato, 138 presente automaticamente.

**Posso disabilitare solo porta 138?**

No. Disabling NetBIOS disabilita 137, 138, 139 simultaneously (bundle).

**Porta 138 ha valore in pentest moderno?**

Minimal. Passive reconnaissance only. Focus su [porte 137](https://hackita.it/articoli/netbios-name) (Responder) e [445](https://hackita.it/articoli/smb) (SMB).

**Browser Service funziona ancora nel 2026?**

Deprecato. Windows 10+ usa Active Directory per network browsing. Legacy systems (Win7/Server 2008) might still use.

***

## Cheat sheet finale

| Azione               | Comando                                                         |
| -------------------- | --------------------------------------------------------------- |
| Scan port 138        | `nmap -sU -p 138 <target>`                                      |
| Passive monitoring   | `tcpdump -i eth0 -n port 138`                                   |
| Find Master Browser  | `nmblookup -M -- -`                                             |
| Check NetBIOS status | `Get-NetAdapterBinding -ComponentID ms_netbios`                 |
| Disable NetBIOS      | `Set-NetAdapterBinding -ComponentID ms_netbios -Enabled $false` |

***

## Perché porta 138 è documentata (minimal attack surface)

NetBIOS Datagram (porta 138) ha **attack surface minimal** nel 2026 ma è documentato per:

1. **NetBIOS architecture completeness** — Understanding 137/138/139 triad
2. **Legacy system identification** — Presence indica Windows legacy (potential other vulns)
3. **Network reconnaissance** — Passive monitoring browser elections/announcements
4. **Security audit** — Verify NetBIOS disabled su modern Windows

**Pentest strategy:** Se porta 138 open → assume NetBIOS abilitato → focus su [porta 137 (Responder)](https://hackita.it/articoli/responder) e [porta 139/445 (SMB)](https://hackita.it/articoli/smb).

## Differenza porta 138 vs altri NetBIOS ports

| Porta | Attack value                          | Modern relevance         |
| ----- | ------------------------------------- | ------------------------ |
| 137   | **High** (Responder credential theft) | 40%+ networks vulnerable |
| 138   | Low (reconnaissance only)             | Minimal exploitation     |
| 139   | **High** (SMB null sessions)          | Legacy but present       |
| 445   | **Critical** (SMB primary)            | Universal Windows        |

## Hardening: disable porta 138

**Disabling NetBIOS (ports 137, 138, 139):**

```powershell
# Per-adapter disable
Get-NetAdapter | ForEach-Object {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($_.InterfaceGuid)" -Name NetbiosOptions -Value 2
}

# Verify
Get-NetAdapter | Get-NetAdapterBinding -ComponentID ms_netbios
# Enabled: False
```

**Network-level:**

```bash
# Firewall block (defense-in-depth)
netsh advfirewall firewall add rule name="Block NetBIOS Datagram" dir=in action=block protocol=UDP localport=138
```

***

> **Disclaimer:** Porta 138 ha attack surface minimal nel 2026. Documentato per completeness NetBIOS architecture. L'autore e HackIta declinano responsabilità. RFC 1001/1002 NetBIOS: [https://www.rfc-editor.org/rfc/rfc1001.html](https://www.rfc-editor.org/rfc/rfc1001.html)

Vuoi supportare HackIta? Visita hackita.it/supporto.
