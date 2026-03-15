---
title: 'Sshuttle: pivoting e tunneling trasparente via SSH verso reti interne'
slug: sshuttle
description: 'Guida a Sshuttle per creare un tunnel trasparente over SSH, raggiungere subnet interne, instradare DNS e usare un host compromesso come pivot durante lateral movement e post-exploitation in pentest autorizzati.'
image: /sshuttle.webp
draft: true
date: 2026-03-31T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - pivoting
  - tunneling
---

Sshuttle trasforma qualsiasi accesso SSH in una VPN completa senza richiedere configurazione lato server. A differenza di tunnel SSH tradizionali che richiedono port forwarding manuale, Sshuttle crea un tunnel trasparente che instrada automaticamente tutto il traffico verso subnet specifiche. In questa guida impari a usare Sshuttle per pivoting attraverso host compromessi e raggiungere reti interne altrimenti isolate.

## Posizione nella Kill Chain

Sshuttle opera nella fase di pivoting/lateral movement. Dopo aver ottenuto accesso SSH a un host con [Hydra](https://hackita.it/articoli/hydra) o chiavi rubate, Sshuttle ti permette di usare quell'host come gateway per raggiungere reti interne dove puoi continuare l'assessment con altri tool.

| Fase             | Tool Precedente            | Sshuttle                | Tool Successivo      |
| ---------------- | -------------------------- | ----------------------- | -------------------- |
| Initial Access   | Metasploit, SSH bruteforce | → Pivot point stabilito | → Scan rete interna  |
| Network Pivoting | Credenziali SSH valide     | → Tunnel trasparente    | → Nmap, CrackMapExec |
| Lateral Movement | Host compromesso           | → Accesso nuove subnet  | → SMBExec, WMIExec   |

## Installazione e Setup

Su Kali Linux Sshuttle è nei repository:

```bash
sudo apt update && sudo apt install sshuttle -y
```

Su altre distribuzioni:

```bash
pip3 install sshuttle
```

O da source:

```bash
git clone https://github.com/sshuttle/sshuttle.git
cd sshuttle
sudo ./setup.py install
```

Verifica installazione:

```bash
sshuttle --version
```

Output atteso:

```
sshuttle 1.1.1
```

### Requisiti

* Accesso SSH al pivot host (password o chiave)
* Python sul pivot host (quasi sempre presente)
* Privilegi root/sudo sulla macchina attaccante (per iptables)
* Il pivot host deve poter raggiungere la rete target

## Uso Base

La sintassi minima richiede credenziali SSH e subnet da raggiungere:

```bash
sudo sshuttle -r user@pivot-host 10.10.10.0/24
```

Questo comando:

1. Connette via SSH a `pivot-host`
2. Configura iptables locali per redirigere traffico verso `10.10.10.0/24`
3. Instrada tutto attraverso il tunnel SSH

Output tipico:

```
[local sudo] Password: 
user@pivot-host's password: 
Connected.
```

Da questo momento, qualsiasi connessione verso `10.10.10.0/24` passa attraverso il pivot.

## Configurazioni Comuni

### Tunnel con Chiave SSH

Per accesso senza password interattiva:

```bash
sudo sshuttle -r user@pivot-host -e "ssh -i /path/to/key" 10.10.10.0/24
```

### Multiple Subnet

Specifica più reti da raggiungere:

```bash
sudo sshuttle -r user@pivot-host 10.10.10.0/24 192.168.100.0/24 172.16.0.0/16
```

### Porta SSH Non Standard

Quando SSH è su porta custom:

```bash
sudo sshuttle -r user@pivot-host:2222 10.10.10.0/24
```

### Escludere Subnet

Escludi specifiche reti dal tunnel (utile per mantenere connettività locale):

```bash
sudo sshuttle -r user@pivot-host 10.0.0.0/8 -x 10.10.20.0/24
```

### DNS Through Tunnel

Forza anche le query [DNS](https://hackita.it/articoli/dns) attraverso il tunnel:

```bash
sudo sshuttle --dns -r user@pivot-host 10.10.10.0/24
```

Fondamentale quando i nomi host interni sono risolvibili solo dal DNS interno.

## Tecniche di Pivoting Avanzate

### Scenario Multi-Hop

Quando devi attraversare più host per raggiungere la rete target:

```
Attaccante → Pivot1 → Pivot2 → Target Network
```

Configura SSH ProxyJump nel tuo `~/.ssh/config`:

```
Host pivot2
    HostName 10.10.10.50
    User admin
    ProxyJump user@pivot1.example.com
```

Poi usa Sshuttle:

```bash
sudo sshuttle -r pivot2 192.168.200.0/24
```

### Tunnel Persistente con Autoreconnect

Per engagement lunghi dove la connessione potrebbe cadere:

```bash
sudo sshuttle -r user@pivot-host 10.10.10.0/24 --auto-hosts --auto-nets
```

Le opzioni `--auto-hosts` e `--auto-nets` tentano di determinare automaticamente host e reti raggiungibili.

## Scenari Pratici di Penetration Test

### Scenario 1: Accesso a Rete Interna da DMZ

**Timeline stimata: 10 minuti**

Hai compromesso un webserver nella DMZ che ha doppia interfaccia: una pubblica e una verso la rete interna 10.10.10.0/24.

```bash
# COMANDO: Stabilisci tunnel
sudo sshuttle -r www-data@dmz-webserver 10.10.10.0/24
```

## OUTPUT ATTESO

```
www-data@dmz-webserver's password: 
Connected.
```

```bash
# COMANDO: Scansiona rete interna
nmap -sn 10.10.10.0/24
```

## OUTPUT ATTESO

```
Nmap scan report for 10.10.10.1
Host is up (0.052s latency).
Nmap scan report for 10.10.10.10
Host is up (0.048s latency).
Nmap scan report for 10.10.10.50
Host is up (0.051s latency).
```

### COSA FARE SE FALLISCE

* **"Connection refused"**: SSH non attivo o porta sbagliata. Verifica con `nc -zv host 22`.
* **"Permission denied"**: Credenziali errate. Verifica username/password.
* **Tunnel attivo ma no connettività**: Il pivot host potrebbe non avere routing verso la subnet.

### Scenario 2: Pivoting per Active Directory Assessment

**Timeline stimata: 30 minuti**

Hai credenziali SSH per un server Linux nella rete corporate che può raggiungere i Domain Controller.

```bash
# COMANDO: Tunnel con DNS
sudo sshuttle --dns -r admin@linux-server 10.0.0.0/8

# COMANDO: Enumera AD con CrackMapExec
crackmapexec smb 10.0.0.10 -u 'guest' -p '' --shares
```

### Scenario 3: Accesso a Segmento di Rete Isolato

**Timeline stimata: 15 minuti**

Il target è una rete 192.168.100.0/24 raggiungibile solo da un jump host intermedio.

```bash
# COMANDO: Tunnel attraverso jump host
sudo sshuttle -r operator@jumphost.corp.local 192.168.100.0/24

# COMANDO: Usa Impacket per enumerazione
python3 /opt/impacket/examples/GetADUsers.py -all -dc-ip 192.168.100.10 corp.local/user:password
```

## Integration Matrix

| Sshuttle +                                                     | Risultato                       | Uso                                 |
| -------------------------------------------------------------- | ------------------------------- | ----------------------------------- |
| [Nmap](https://hackita.it/articoli/nmap)                       | Scan rete interna trasparente   | `nmap -sV 10.10.10.0/24`            |
| [CrackMapExec](https://hackita.it/articoli/crackmapexec)       | AD enumeration attraverso pivot | `cme smb 10.10.10.0/24`             |
| [Metasploit](https://hackita.it/articoli/metasploit-framework) | Exploit su target interni       | Configura route in msf              |
| [BloodHound](https://hackita.it/articoli/bloodhound)           | Collection AD remota            | bloodhound-python attraverso tunnel |

## Confronto con Alternative di Pivoting

| Caratteristica   | Sshuttle    | SSH Port Forward  | Chisel  | ProxyChains    |
| ---------------- | ----------- | ----------------- | ------- | -------------- |
| Setup            | Semplice    | Manuale per porta | Medio   | Configurazione |
| Trasparenza      | Totale      | Per porta         | SOCKS   | SOCKS          |
| Requisiti Server | Solo SSH    | Solo SSH          | Binary  | Proxy          |
| Performance      | Buona       | Ottima            | Buona   | Media          |
| Protocolli       | TCP         | TCP               | TCP/UDP | TCP            |
| Richiede root    | Sì (locale) | No                | No      | No             |

**Quando usare Sshuttle**: accesso SSH disponibile, vuoi trasparenza totale senza configurare proxy per ogni tool.

**Quando usare alternative**: non hai root locale, serve [UDP](https://hackita.it/articoli/udp), o preferisci approccio SOCKS.

## Defense Evasion

### Tecnica 1: Traffic Blending

Il traffico Sshuttle appare come normale SSH. Per ulteriore mimetismo:

```bash
sudo sshuttle -r user@pivot-host -e "ssh -o 'ServerAliveInterval 30'" 10.10.10.0/24
```

### Tecnica 2: Porta SSH Alternativa

Se 22 è monitorata, usa porta alternativa configurata su 443:

```bash
sudo sshuttle -r user@pivot-host:443 10.10.10.0/24
```

### Tecnica 3: Limitare Scan Aggressivi

Scansioni massive attraverso il tunnel sono rilevabili:

```bash
nmap -sV -T2 10.10.10.0/24
```

## Detection e Countermeasures

### Cosa Cerca il Blue Team

* Connessioni SSH prolungate con alto volume dati
* Pattern traffico anomalo da server che normalmente non genera molto traffico
* Connessioni a subnet insolite dall'host pivot
* Processo Python sull'host pivot

## Troubleshooting

### Errore: "iptables not found"

```bash
sudo apt install iptables -y
```

### Errore: "Failed to connect"

```bash
# Test connessione SSH diretta
ssh user@pivot-host
```

### Tunnel Attivo ma Nessuna Connettività

Il pivot host potrebbe non avere route verso la subnet target:

```bash
ssh user@pivot-host "ip route"
```

### Performance Lenta

Usa cipher più veloce:

```bash
sudo sshuttle -r user@pivot-host -e "ssh -c aes128-gcm@openssh.com" 10.10.10.0/24
```

## Cheat Sheet Comandi

| Operazione      | Comando                                             |
| --------------- | --------------------------------------------------- |
| Tunnel base     | `sudo sshuttle -r user@host subnet/mask`            |
| Con chiave SSH  | `sudo sshuttle -r user@host -e "ssh -i key" subnet` |
| Multiple subnet | `sudo sshuttle -r user@host net1 net2 net3`         |
| Includi DNS     | `sudo sshuttle --dns -r user@host subnet`           |
| Escludi subnet  | `sudo sshuttle -r user@host subnet -x excluded`     |
| Porta custom    | `sudo sshuttle -r user@host:port subnet`            |
| Verbose debug   | `sudo sshuttle -vvr user@host subnet`               |

## FAQ

**Sshuttle funziona con Windows come pivot?**

No, richiede Python. Per pivot Windows usa [Chisel](https://hackita.it/articoli/chisel).

**Posso usare UDP attraverso Sshuttle?**

No, solo TCP. Per UDP usa altri tool come Chisel.

**Perché serve root locale?**

Sshuttle modifica iptables per intercettare traffico.

**Come termino il tunnel?**

`Ctrl+C` nel terminale. Le regole iptables vengono ripulite automaticamente.

**È legale usare Sshuttle?**

Solo su reti autorizzate. Per penetration test professionali, [hackita.it/servizi](https://hackita.it/servizi).

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [Sshuttle GitHub](https://github.com/sshuttle/sshuttle) | [Sshuttle Docs](https://sshuttle.readthedocs.io/)
