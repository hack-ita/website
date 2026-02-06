---
title: 'SSHuttle: VPN over SSH per Pivoting nel Penetration Testing'
slug: sshuttle
description: 'SSHuttle: guida completa per creare VPN over SSH nel penetration testing. Pivoting, tunneling e accesso a reti interne senza configurazioni.'
image: /Gemini_Generated_Image_56102d56102d5610.webp
draft: true
date: 2026-02-07T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - pivoting
  - tunneling
---

# SSHuttle: VPN over SSH per Pivoting nel Penetration Testing

## Introduzione

Quando comprometti una macchina in una rete interna e devi raggiungere subnet non direttamente accessibili dal tuo attacker box, hai bisogno di pivoting. SSHuttle risolve questo problema creando una VPN trasparente attraverso una connessione SSH — senza richiedere privilegi root sul target, senza installare software aggiuntivo sul sistema compromesso e senza configurare tunnel manuali.

A differenza di un classico port forwarding SSH, SSHuttle instrada interi range di IP attraverso il tunnel. Il tuo traffico verso la rete interna passa attraverso la macchina compromessa come se fossi collegato direttamente. Nella kill chain, operiamo nella fase di **Lateral Movement / Pivoting** (MITRE ATT\&CK T1572).

Questo articolo copre installazione, configurazione operativa, scenari di pivoting multi-hop e integrazione con strumenti come [Nmap](https://hackita.it/articoli/nmap) e [ProxyChains](https://hackita.it/articoli/proxychains).

***

## 1️⃣ Setup e Installazione

SSHuttle si installa solo sull'attacker box. Il target necessita esclusivamente di un server SSH attivo e Python disponibile.

**Installazione su Kali/Debian:**

```bash
sudo apt install sshuttle
```

**Installazione da pip:**

```bash
pip install sshuttle --break-system-packages
```

**Installazione da sorgente (versione più recente):**

```bash
git clone https://github.com/sshuttle/sshuttle.git
cd sshuttle
sudo ./setup.py install
```

**Verifica:**

```bash
sshuttle --version
```

Output:

```
sshuttle 1.1.2
```

**Requisiti sul target:**

* SSH server attivo (OpenSSH)
* Python 3.x installato (SSHuttle carica un piccolo script Python via SSH)
* Credenziali SSH o chiave valida

***

## 2️⃣ Uso Base

Instrada tutto il traffico verso la subnet 172.16.0.0/24 attraverso il target 10.10.10.50:

```bash
sshuttle -r user@10.10.10.50 172.16.0.0/24
```

Output:

```
client: Connected.
```

Da questo momento, qualsiasi tool lanciato dalla tua macchina verso 172.16.0.0/24 passa attraverso 10.10.10.50 in modo trasparente.

**Parametri fondamentali:**

* `-r user@host` → specifica il jump host SSH
* `172.16.0.0/24` → subnet da instradare (puoi specificarne multiple)
* `--dns` → instrada anche le query DNS attraverso il tunnel
* `-e 'ssh -i key.pem'` → usa una chiave SSH specifica
* `-x host` → esclude un host dal routing
* `--no-latency-control` → disabilita il controllo di latenza per connessioni lente

Esempio con chiave SSH e DNS routing:

```bash
sshuttle -r user@10.10.10.50 172.16.0.0/24 10.10.20.0/24 --dns -e 'ssh -i id_rsa'
```

Qui instrada due subnet e le query DNS, autenticandosi con chiave privata.

***

## 3️⃣ Tecniche Operative

### Pivoting verso rete interna dopo initial access

Hai compromesso una macchina dual-homed (interfaccia esterna 10.10.10.50, interfaccia interna 172.16.0.1). Devi scansionare la rete interna.

```bash
sshuttle -r www-data@10.10.10.50 172.16.0.0/24 -e 'ssh -p 2222'
```

SSH gira su porta non standard 2222. Una volta connesso:

```bash
nmap -sT -Pn 172.16.0.0/24
```

Nmap funziona direttamente — SSHuttle gestisce il routing. Nota: solo scan TCP (`-sT`) funzionano attraverso SSHuttle. SYN scan (`-sS`) richiede raw socket e non passa attraverso il tunnel.

### Accesso a servizi interni senza port forwarding

Un database PostgreSQL ascolta su 172.16.0.10:5432, raggiungibile solo dalla rete interna:

```bash
sshuttle -r user@10.10.10.50 172.16.0.10/32
```

Ora dal tuo box:

```bash
psql -h 172.16.0.10 -U admin -d corporate
```

Connessione diretta, senza bisogno di `ssh -L`.

### Esclusione del jump host dal tunnel

Se instradare il traffico verso il jump host stesso causa loop:

```bash
sshuttle -r user@10.10.10.50 172.16.0.0/24 -x 10.10.10.50
```

Il flag `-x` esclude l'IP specificato dal routing SSHuttle.

***

## 4️⃣ Tecniche Avanzate

### Multi-hop pivoting

Devi raggiungere una terza subnet (192.168.1.0/24) accessibile solo da 172.16.0.5, che a sua volta è raggiungibile solo da 10.10.10.50.

**Hop 1 — dal tuo box a 172.16.0.0/24:**

```bash
sshuttle -r user@10.10.10.50 172.16.0.0/24
```

**Hop 2 — da 172.16.0.5 a 192.168.1.0/24:**

In un secondo terminale, con il primo tunnel attivo:

```bash
sshuttle -r user@172.16.0.5 192.168.1.0/24
```

Il secondo SSHuttle passa attraverso il primo tunnel. Ora raggiungi 192.168.1.0/24 dal tuo attacker box con due hop.

### Tunneling con porta SSH non standard e proxy SOCKS

Combinazione con porta custom e autenticazione via password (usando `sshpass`):

```bash
sshpass -p 'P@ssw0rd!' sshuttle -r user@10.10.10.50:2222 172.16.0.0/24
```

### Modalità daemon

Per sessioni lunghe, lancia SSHuttle in background:

```bash
sshuttle -r user@10.10.10.50 172.16.0.0/24 -D --pidfile /tmp/sshuttle.pid
```

* `-D` → daemonizza il processo
* `--pidfile` → salva il PID per kill successivo

Per chiudere:

```bash
kill $(cat /tmp/sshuttle.pid)
```

### Evasion: traffico su porta 443

Se il firewall del target permette solo traffico HTTPS in uscita, configura SSH sul target sulla porta 443 e connettiti:

```bash
sshuttle -r user@10.10.10.50:443 172.16.0.0/24
```

Il traffico SSH sulla porta 443 si mimetizza con il traffico web legittimo dal punto di vista dei firewall L3/L4.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Rete enterprise segmentata — Raggiungere il domain controller

```bash
sshuttle -r admin@10.10.10.50 172.16.0.0/16 --dns
```

**Output atteso:** `client: Connected.`

**Cosa fare se fallisce:**

* `Connection refused` → SSH non attivo o porta diversa. Scansiona con nmap: `nmap -p 22,2222,443 10.10.10.50`.
* `Python not found on remote` → Python mancante sul target. Installa Python o usa un tunnel SSH classico (`ssh -D 1080`) con [ProxyChains](https://hackita.it/articoli/proxychains).

**Timeline:** Connessione in 5 secondi. Scansione della subnet interna con nmap in 5-15 minuti a seconda dell'ampiezza.

### Scenario 2: Laboratorio HTB/THM con doppia rete

```bash
sshuttle -r htb-user@10.129.45.12 10.10.0.0/16 -e 'ssh -i htb_key'
```

**Output atteso:** `client: Connected.`

**Cosa fare se fallisce:**

* `Warning: remote port forwarding failed` → Non è un errore SSHuttle ma SSH. Ignora se la connessione funziona.
* Scan nmap non restituisce risultati → Usa `-sT -Pn` (TCP connect scan senza ping). SSHuttle non supporta ICMP.

**Timeline:** Setup immediato. Enumerazione target in 5-10 minuti.

### Scenario 3: Pivoting attraverso container con rete bridge

```bash
sshuttle -r root@10.10.10.50 172.17.0.0/16
```

**Output atteso:** `client: Connected.`

**Cosa fare se fallisce:**

* Container non ha SSH → Non puoi usare SSHuttle. Alternativa: [chisel](https://hackita.it/articoli/chisel) per creare un tunnel TCP.
* Routing non funziona → Verifica che il target abbia effettivamente un'interfaccia su 172.17.0.0/16: `ip addr show`.

**Timeline:** 3 secondi per connessione. Accesso ai container interni immediato.

***

## 6️⃣ Toolchain Integration

SSHuttle si posiziona come bridge tra l'accesso iniziale e l'enumerazione/exploitation della rete interna.

**Flusso operativo:**

Initial Access → [Crontab Backdoor](https://hackita.it/articoli/crontab-backdoor) (persistence) → **SSHuttle (pivoting)** → Nmap/CrackMapExec (enum interna)

L'output di linpeas o altri tool di enumerazione ti dà le subnet interne raggiungibili. Quelle subnet diventano il target di SSHuttle.

**Passaggio dati concreto:**

```bash
# Sulla macchina compromessa: identifica subnet
ip route show
# Output: 172.16.0.0/24 dev eth1 proto kernel scope link src 172.16.0.1

# Sul tuo box: avvia SSHuttle con quella subnet
sshuttle -r user@10.10.10.50 172.16.0.0/24

# Ora usa crackmapexec direttamente
crackmapexec smb 172.16.0.0/24
```

| Scenario                      | SSHuttle         | SSH -D (SOCKS)       | Chisel      | Ligolo-ng  |
| ----------------------------- | ---------------- | -------------------- | ----------- | ---------- |
| Setup complessità             | Bassa            | Bassa                | Media       | Media      |
| Richiede software sul target  | No (solo Python) | No                   | Sì (binary) | Sì (agent) |
| Supporta TCP scan Nmap        | Sì (`-sT`)       | Sì (via proxychains) | Sì          | Sì         |
| Supporta UDP                  | No               | No                   | No          | Sì         |
| Supporta ICMP/ping            | No               | No                   | No          | Sì         |
| Trasparenza (no proxy config) | Sì               | No                   | No          | Sì         |

***

## 7️⃣ Attack Chain Completa

**Obiettivo:** Compromettere il domain controller in una rete enterprise segmentata.

**Fase 1 — Recon esterna (20 min)**

Scansione perimetrale. Trovi una webapp vulnerabile su 10.10.10.50:8080.

**Fase 2 — Initial Access (30 min)**

Exploit della webapp → reverse shell come `tomcat`. Stabilisci persistenza con un cron job.

**Fase 3 — Enumerazione interna (5 min)**

```bash
ip addr show
# eth0: 10.10.10.50/24
# eth1: 172.16.0.1/24
```

La macchina è dual-homed.

**Fase 4 — Pivoting con SSHuttle (2 min)**

Dalla tua macchina:

```bash
sshuttle -r tomcat@10.10.10.50 172.16.0.0/24 --dns
```

**Fase 5 — Enumerazione rete interna (15 min)**

```bash
crackmapexec smb 172.16.0.0/24
```

Trovi il domain controller su 172.16.0.10 e workstation su 172.16.0.20-30.

**Fase 6 — Exploitation DC (40 min)**

Attacco diretto al DC (ZeroLogon, Kerberoasting, pass-the-hash) tramite SSHuttle. Tutto il traffico passa in modo trasparente.

**Timeline totale stimata:** \~110 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* Connessioni SSH prolungate con alto volume di traffico insolito dal jump host verso la rete interna
* Processo Python anomalo sul jump host (SSHuttle carica uno script Python remoto)
* Traffico anomalo dall'IP del jump host verso risorse interne a cui normalmente non accede

### Log rilevanti

* `/var/log/auth.log` → login SSH dall'attacker verso il jump host
* Firewall logs → traffico dal jump host verso subnet interne su porte multiple
* Netflow → volume di traffico anomalo dal jump host

### Tecniche di evasion

1. **Limita le subnet:** instrada solo le subnet necessarie, non tutto (`0.0.0.0/0`). Meno traffico = meno alert.
2. **Usa credenziali legittime:** se hai credenziali di un utente autorizzato ad accedere via SSH, la connessione appare legittima nei log.
3. **Orari lavorativi:** opera durante orari d'ufficio quando il traffico SSH è normale. Una connessione SSH alle 3 di notte è un red flag.

### Cleanup

SSHuttle non lascia artefatti sul target. Basta chiudere il processo locale:

```bash
kill $(cat /tmp/sshuttle.pid)
```

Se hai modificato la configurazione SSH del target (es. porta), ripristina il file originale.

***

## 9️⃣ Performance & Scaling

**Single target:** SSHuttle su un singolo hop gestisce senza problemi scansioni Nmap e traffico SMB/HTTP. Latenza aggiuntiva: 10-50ms a seconda della connessione SSH.

**Multi-hop:** ogni hop aggiunge latenza. Con 2 hop, aspettati 50-150ms aggiuntivi. Le scansioni Nmap rallentano proporzionalmente — una `-sT` su /24 richiede 10-15 minuti con un hop, 20-30 con due.

**Ottimizzazione per scansioni grandi:**

```bash
sshuttle -r user@10.10.10.50 172.16.0.0/24 --no-latency-control
```

Disabilita il controllo di latenza interno. Utile su connessioni stabili dove il throttling automatico è controproducente.

**Consumo risorse:** sull'attacker box, SSHuttle usa \~15-30MB di RAM. Sul target, il processo Python remoto usa \~5-10MB.

***

## 🔟 Tabelle Tecniche

### Command Reference

| Comando                                        | Descrizione                 |
| ---------------------------------------------- | --------------------------- |
| `sshuttle -r user@host subnet`                 | Tunnel base                 |
| `sshuttle -r user@host subnet --dns`           | Tunnel con DNS routing      |
| `sshuttle -r user@host:port subnet`            | Porta SSH custom            |
| `sshuttle -r user@host subnet -x IP`           | Escludi IP dal routing      |
| `sshuttle -r user@host subnet -D`              | Modalità daemon             |
| `sshuttle -r user@host 0/0`                    | Instrada tutto il traffico  |
| `sshuttle -r user@host subnet -e 'ssh -i key'` | Usa chiave SSH              |
| `sshuttle -l 0.0.0.0 -r user@host subnet`      | Bind su tutte le interfacce |

### SSHuttle vs alternative — Quando usare cosa

| Criterio                   | SSHuttle | ProxyChains + SSH -D | Chisel        |
| -------------------------- | -------- | -------------------- | ------------- |
| Velocità setup             | ★★★★★    | ★★★☆☆                | ★★★☆☆         |
| Richiede binary sul target | No       | No                   | Sì            |
| Scan Nmap trasparente      | Sì (TCP) | Sì (lento)           | Sì            |
| UDP support                | No       | No                   | Sì (limitato) |
| Multi-hop                  | Sì       | Sì                   | Sì            |
| Stealth                    | ★★★☆☆    | ★★★★☆                | ★★☆☆☆         |

***

## 11️⃣ Troubleshooting

| Problema                      | Causa                             | Fix                                             |
| ----------------------------- | --------------------------------- | ----------------------------------------------- |
| `Python not found` sul target | Python non installato             | Installa Python o usa `ssh -D` + ProxyChains    |
| Nmap non trova host           | Stai usando `-sS` (SYN scan)      | Usa `-sT -Pn` (TCP connect, no ping)            |
| Connessione cade dopo minuti  | Timeout SSH                       | Aggiungi `ServerAliveInterval 60` in ssh config |
| `iptables permission denied`  | SSHuttle necessita root locale    | Esegui con `sudo sshuttle ...`                  |
| Traffico lento                | Latency control troppo aggressivo | Usa `--no-latency-control`                      |
| DNS non risolve nomi interni  | DNS non instradato                | Aggiungi `--dns`                                |

***

## 12️⃣ FAQ

**SSHuttle richiede root sul target?**
No. Serve solo un account SSH con Python disponibile. Root è necessario solo sull'attacker box per manipolare le iptables locali.

**Posso usare SSHuttle con una reverse shell?**
Non direttamente. SSHuttle necessita una connessione SSH. Se hai solo una reverse shell, prima stabilisci un accesso SSH (aggiungi la tua chiave pubblica a `authorized_keys`).

**ICMP funziona attraverso SSHuttle?**
No. Ping non funziona. Usa `nmap -Pn` per scansioni senza ping.

**Posso instradare tutto il traffico?**
Sì, con `sshuttle -r user@host 0/0 --dns`. Utile per forzare tutto il traffico attraverso il tunnel, ma genera molto rumore.

**Qual è il limite di subnet instradabili?**
Non c'è un limite tecnico. Puoi specificare quante subnet vuoi nella riga di comando.

**SSHuttle funziona su Windows?**
Solo come client su WSL. Non esiste un client nativo Windows. Per Windows, usa [Plink](https://hackita.it/articoli/plink) o Chisel.

***

## 13️⃣ Cheat Sheet

| Azione            | Comando                                                 |
| ----------------- | ------------------------------------------------------- |
| Tunnel base       | `sshuttle -r user@host 172.16.0.0/24`                   |
| Tunnel con DNS    | `sshuttle -r user@host 172.16.0.0/24 --dns`             |
| Porta SSH custom  | `sshuttle -r user@host:2222 172.16.0.0/24`              |
| Chiave SSH        | `sshuttle -r user@host subnet -e 'ssh -i key.pem'`      |
| Escludi host      | `sshuttle -r user@host subnet -x 10.10.10.50`           |
| Multi-subnet      | `sshuttle -r user@host 172.16.0.0/24 10.10.20.0/24`     |
| Background        | `sshuttle -r user@host subnet -D --pidfile /tmp/ss.pid` |
| Kill daemon       | `kill $(cat /tmp/ss.pid)`                               |
| Tutto il traffico | `sudo sshuttle -r user@host 0/0 --dns`                  |

***

**Disclaimer:** Le tecniche descritte sono riservate a penetration test autorizzati e attività di Red Team con permesso scritto. L'accesso non autorizzato a reti informatiche è un reato penale. Repository ufficiale: [github.com/sshuttle/sshuttle](https://github.com/sshuttle/sshuttle).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
