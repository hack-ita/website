---
title: 'Wireshark in Azione: Analizza Il Traffico e Ruba Credenziali'
slug: wireshark
description: >
  Guida operativa a Wireshark per hacker etici in lab. Cos’è, come usarlo su
  Kali, filtri per isolare traffico target, estrarre password e file. Tutorial
  pratico per CTF, HTB e ambienti autorizzati.
image: /WIRESHARK.webp
draft: false
date: 2026-01-20T00:00:00.000Z
lastmod: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - Wireshark
featured: true
---

# Wireshark in Azione: Analizza Il Traffico e Ruba Credenziali

Durante un internal assessment, hai accesso a un segmento di rete o hai compromesso una workstation. Wireshark diventa i tuoi occhi sul traffico di rete: lo strumento chiave per catturare credenziali in transito, decodificare protocolli legacy e mappare comunicazioni interne critiche. Questa guida copre l'uso offensivo del packet analysis da reconnaissance a evidence collection.

## TL;DR Operativo (Flusso a Step)

1. **Targeted Capture Setup:** Configurazione di catture filtrate su interfacce critiche con BPF filters per isolare traffico rilevante.
2. **Protocol-Specific Filtering:** Applicazione di display filters avanzati per identificare protocolli in chiaro e sessioni di autenticazione.
3. **Credential Harvesting:** Estrazione di credenziali da HTTP, FTP, Telnet, SMTP e analisi di handshake SMB/NTLM.
4. **Stream Reconstruction:** Utilizzo di Follow TCP/HTTP Stream per ricostruire sessioni complete e identificare dati sensibili.
5. **File & Artifact Extraction:** Recupero di file trasferiti via rete attraverso Export Objects e ricostruzione di flussi binari.
6. **Network Intelligence:** Mappatura delle comunicazioni interne e identificazione di pattern per pivot planning.
7. **Stealth & Detection Evasion:** Tecniche per minimizzare l'impronta di cattura e identificazione di counter-measures.

***

## Fase 1: Ricognizione & Enumeration

**Scenario:** Accesso iniziale a una workstation in segmento interno. Devi capire cosa c'è sulla rete senza generare traffico attivo.

**Configurazione Permessi per Cattura Non-Privilegiata:**

```bash
sudo usermod -a -G wireshark $USER
newgrp wireshark
```

**Identificazione Interfacce di Rete Attive:**

```bash
ip -br addr show
```

**Capture Filter BPF per Isolare Subnet Target:**

```bash
dumpcap -i eth0 -f "net 192.168.1.0/24" -w initial_capture.pcapng
```

**Display Filter per Traffico verso Specifici Servizi:**

```
tcp.port == 445 or tcp.port == 3389 or tcp.port == 22 or tcp.port == 23
```

**Identificazione Comunicazioni DNS Interne:**

```
dns and ip.src == 192.168.1.0/24
```

**Analisi Broadcast/Multicast Traffic:**

```
(arp or icmp) and not icmp.type == 8
```

**Cattura Mirata su Interfaccia VPN (HTB/PG):**

```bash
wireshark -k -i tun0
```

**Capture Filter per Escludere Traffico Non Rilevante:**

```bash
dumpcap -i eth0 -f "not port 53 and not arp" -w filtered_traffic.pcapng
```

***

## Fase 2: Initial Exploitation - Credential Harvesting

**Cattura Traffico HTTP in Chiaro:**

```bash
dumpcap -i eth0 -f "port 80" -w http_clear.pcapng
```

**Display Filter per Richieste POST (Login Forms):**

```
http.request.method == "POST"
```

**Estrazione Credenziali HTTP Basic Auth:**

```
http.authorization contains "Basic"
```

**Decodifica Base64 HTTP Basic in Wireshark:**

1. Clicca su pacchetto con Authorization header
2. Vai a `File → Export Packet Bytes → Decode As → Base64`
3. Analizza l'output per username:password

**Cattura Sessioni FTP con Credenziali:**

```bash
dumpcap -i eth0 -f "port 21" -w ftp_sessions.pcapng
```

**Display Filter per Comandi FTP Sensibili:**

```
ftp.request.command == "USER" or ftp.request.command == "PASS"
```

**Analisi Traffico Telnet per Credenziali:**

```
telnet and telnet.data
```

**Cattura Autenticazioni SMTP:**

```bash
dumpcap -i eth0 -f "port 25" -w smtp_auth.pcapng
```

**Display Filter per SMTP AUTH:**

```
smtp.req.command == "AUTH"
```

**Analisi Handshake SMB/NTLM:**

```
smb2 or ntlmssp
```

**Identificazione NTLMSSP Authentication:**

```
ntlmssp.auth
```

**Estrazione Challenge-Response NTLM per Offline Cracking:**

1. Filtra: `ntlmssp`
2. Clic destro su pacchetto NTLMSSP → Follow → TCP Stream
3. Cerca i blocchi `NTLMSSP_CHALLENGE` e `NTLMSSP_AUTH`
4. Estrai NT/LM hashes per strumenti come Hashcat

**Ricerca Token in Header HTTP:**

```
http contains "Authorization: Bearer" or http contains "session="
```

**Cattura Cookie di Sessione:**

```
http.cookie
```

***

## Fase 3: Post-Compromise & Protocol Analysis

**Analisi Traffico da Host Remoto via SSH Tunnel:**

```bash
ssh user@target-host "sudo tcpdump -i eth0 -U -w -" | wireshark -k -i -
```

**Display Filter per Identificazione Servizi Database:**

```
tcp.port == 1433 or tcp.port == 3306 or tcp.port == 5432
```

**Ricerca Query SQL in Chiaro:**

```
mysql.query or pgsql.type == "Q"
```

**Analisi Traffico SNMP con Community String:**

```
snmp and snmp.community
```

**Identificazione Configurazioni Trasferite in Chiaro:**

```
http contains "config" or ftp-data contains "password"
```

**Cattura Traffico TFTP per File Transfer:**

```bash
dumpcap -i eth0 -f "port 69" -w tftp_transfers.pcapng
```

**Display Filter per TFTP Operations:**

```
tftp.opcode == 1 or tftp.opcode == 2
```

**Analisi Protocolli Industrial/OT in Chiaro:**

```
modbus or enip
```

**Estrazione File da HTTP con Export Objects:**

1. `File → Export Objects → HTTP...`
2. Filtra per tipo (exe, zip, config)
3. Salva e analizza offline

**Ricostruzione File Binari da TCP Stream:**

1. Follow TCP Stream
2. Imposta "Show data as" → "Raw"
3. Salva come file binario
4. Verifica magic bytes e tipo file

***

## Fase 4: Lateral Movement Intelligence

**Mappatura Conversazioni tra Host Interni:**

```
ip.addr == 192.168.1.50 and ip.addr == 192.168.1.100
```

**Analisi Statistiche Comunicazioni:**

1. `Statistics → Conversations`
2. Filtra per protocollo TCP/IP
3. Identifica host con più connessioni

**Identificazione Trust Relationships:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == 192.168.1.50
```

**Display Filter per RDP Sessioni:**

```
tcp.port == 3389
```

**Analisi JA3 Fingerprint per Client Identification:**

```
tls.handshake.ja3
```

**Identificazione SNI in TLS Handshake:**

```
tls.handshake.extensions_server_name
```

**Cattura Beaconing Patterns:**

```
dns.qry.type == 1 and frame.time_delta > 60
```

**Analisi Timing per C2 Detection:**

```
tcp.time_delta > 5 and tcp.len > 0
```

**Ricerca DNS Tunneling Indicators:**

```
dns.qry.name.len > 50 or dns.count.queries > 5
```

***

## Fase 5: Detection & Hardening

**Rilevamento Promiscuous Mode via Network:**

```
eth.dst == ff:ff:ff:ff:ff:ff and arp.proto.type == 0x0806
```

**Monitoraggio ARP Anomalies:**

```
arp.duplicate-address-detected or arp.isgratuitous
```

**Detect SPAN/Mirror Port Configurations:**

```
tcp.analysis.duplicate_ack or tcp.analysis.retransmission
```

**Hardening: Disabilitazione Protocolli Insecure:**

```bash
systemctl disable --now telnet.socket
systemctl disable --now vsftpd
```

**Configurazione EDR per Monitorare Npcap/WinPcap Installations:**

* Monitor registry: `HKLM\SYSTEM\CurrentControlSet\Services\NPF`
* File system: `C:\Windows\System32\drivers\npf.sys`
* Process creation: `windump.exe`, `dumpcap.exe`

**Network Segmentation Detection via TTL Analysis:**

```
ip.ttl < 64 and ip.src == 192.168.1.0/24
```

**Implementazione Encrypted Protocols Only Policy:**

```bash
# Blocca HTTP in chiaro su rete management
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 80 -j DROP
```

**Monitoraggio Port Mirroring Abuse:**

```
tcp.flags == 0x0000 and tcp.len > 0
```

**Rilevamento Wireshark Remote Capture:**

```
tcp.port == 2002 and tcp.payload contains "WIRESHARK"
```

***

## Errori Comuni Che Vedo Negli Assessment Reali

1. **Capture Filters Inesistenti o Errati:** Cattura di tutto il traffico che porta a PCAP di gigabyte e performance degradation.
2. **Display Filters troppo Ampi:** Uso di `ip.addr == subnet` senza ulteriore filtraggio, risultando in migliaia di pacchetti irrilevanti.
3. **Ignorare Protocolli Legacy:** Non filtrare per Telnet (23), FTP (21), SMTP (25) in reti dove questi servizi sono ancora attivi.
4. **Mancata Analisi NTLMSSP:** Non cercare autenticazioni NTLM in traffico SMB, perdendo opportunità di credential harvesting.
5. **Export Objects Non Utilizzato:** Non estrarre file da HTTP quando disponibili, richiedendo successivi transfer manuali.
6. **TLS Considerato "Impenetrabile":** Non analizzare metadata TLS (SNI, JA3, certificate info) che forniscono intelligence preziosa.

***

## Playbook Operativo 80/20: Wireshark in Internal Assessment

| Obiettivo                           | Azione Concreta                               | Strumento/Filtro                       |
| ----------------------------------- | --------------------------------------------- | -------------------------------------- |
| Isolamento traffico target          | Capture filter BPF su IP/port specifici       | `host 10.10.10.10 and port 80`         |
| Identificazione login HTTP          | Display filter per richieste POST             | `http.request.method == "POST"`        |
| Estrazione credenziali HTTP Basic   | Decodifica header Authorization               | `http.authorization contains "Basic"`  |
| Analisi autenticazioni SMB          | Filtro per handshake NTLMSSP                  | `ntlmssp`                              |
| Ricostruzione sessioni applicative  | Follow TCP Stream su conversazioni specifiche | Click destro → Follow → TCP Stream     |
| Estrazione file da rete             | Export Objects HTTP/SMB                       | File → Export Objects → HTTP...        |
| Identificazione servizi vulnerabili | Filtro per protocolli legacy                  | `tcp.port == 23 or tcp.port == 21`     |
| Mappatura comunicazioni interne     | Statistics → Conversations                    | Analisi tabella conversations          |
| Rilevamento anomalie TLS            | Analisi SNI e JA3 fingerprint                 | `tls.handshake.extensions_server_name` |
| Hardening evidenza                  | Disabilitazione protocolli in chiaro rilevati | `systemctl disable [service]`          |

***

## Lab Realistico: Internal Network Traffic Analysis

**Scenario "Clear-Text Compromise":** In un ambiente di lab che replica una rete enterprise con segmenti misti (prod, dev, legacy), identifica e sfrutta le vulnerabilità nei protocolli di rete.

**Fasi del Lab:**

1. **Passive Reconnaissance:** Cattura traffico di rete su un segmento mirrorato senza generare alcun pacchetto.
2. **Protocol Identification:** Identifica tutti i protocolli attivi, con focus su quelli in chiaro.
3. **Credential Harvesting:** Estrai credenziali da HTTP Basic Auth, FTP, e sessioni Telnet.
4. **NTLM Analysis:** Analizza handshake SMB per identificare utenti di dominio e estrarre challenge-response.
5. **File Extraction:** Recupera file di configurazione e documenti trasferiti via rete.
6. **Intelligence Reporting:** Genera un report di intelligence sulle comunicazioni interne e trust relationships.

**Technical Learning Objectives:**

* Configurazione avanzata di capture e display filters per scenari reali
* Tecniche di estrazione e decodifica credenziali da protocolli multipli
* Analisi forense di handshake di autenticazione (NTLM, Kerberos)
* Ricostruzione di sessioni applicative e file transfer
* Identificazione di misconfigurazioni di rete attraverso l'analisi passiva

**CTA Tecnica e Concreta:** Questo scenario hands-on, con traffico di rete reale e debrief tecnico dettagliato, è parte del percorso **"Network Forensic Analysis & Offensive Traffic Intelligence"** di HackITA. Impara a trasformare l'analisi passiva del traffico in azioni offensive concrete e intelligence operativa.

## 🔗 Approfondisci e Metti in Pratica

Se vuoi applicare queste tecniche in scenari reali di **internal assessment, traffic intelligence e Red Team operativo**, puoi esplorare i nostri servizi professionali:

👉 [https://hackita.it/servizi](https://hackita.it/servizi)
👉 [https://hackita.it/supporta](https://hackita.it/supporta)

Per approfondire la documentazione ufficiale e rafforzare la tua padronanza tecnica su Wireshark e analisi del traffico di rete:

* Wireshark Official Documentation: [https://www.wireshark.org/docs/](https://www.wireshark.org/docs/)
* Wireshark Display Filter Reference: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)
* RFC 4559 – SPNEGO-based Kerberos and NTLM HTTP Authentication: [https://datatracker.ietf.org/doc/html/rfc4559](https://datatracker.ietf.org/doc/html/rfc4559)

La differenza tra analisi superficiale e offensive traffic intelligence sta nella capacità di interpretare correttamente protocolli, handshake e metadata di rete in contesti enterprise reali.

***

*Questa guida è per scopi formativi in ambienti controllati e autorizzati. Ogni test su sistemi di terze parti richiede autorizzazione scritta esplicita.*
