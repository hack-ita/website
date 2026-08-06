---
title: 'Wireshark per Pentesting: Filtri, NTLM, DNS e TCP Stream'
slug: wireshark
description: 'Wireshark per ethical hacking: filtri avanzati, NTLM, DNS e TCP Stream. Scopri come isolare traffico, leggere sessioni e trovare indicatori utili in lab e HTB.'
image: /wireshark-guide-network-protocol-analyzer-hackita (1).webp
draft: false
date: 2026-01-20T00:00:00.000Z
lastmod: 2026-08-06T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - Wireshark
featured: false
---

# Wireshark per Ethical Hacking: Filtri Avanzati, NTLM, DNS, SMB e TCP Stream

Wireshark serve a isolare il traffico rilevante con filtri mirati, estrarre credenziali da protocolli in chiaro (HTTP, FTP, NTLM) e ricostruire sessioni complete con il Follow TCP Stream. Durante un internal assessment, hai accesso a un segmento di rete o hai compromesso una workstation: Wireshark diventa i tuoi occhi sul traffico, cattura credenziali in transito, decodifica protocolli legacy e mappa comunicazioni interne critiche. Questa guida copre l'uso offensivo del packet analysis, da reconnaissance a evidence collection, con i filtri pronti all'uso per HTB, CTF e assessment autorizzati.

## Cos'è Wireshark e a cosa serve nel pentesting

Wireshark è un analizzatore di protocolli di rete open source che permette di catturare e ispezionare il traffico pacchetto per pacchetto. In ambito offensive security serve a intercettare credenziali in chiaro, analizzare handshake di autenticazione (NTLM, Kerberos), ricostruire sessioni applicative e identificare protocolli vulnerabili ancora attivi in rete.

## Flusso Operativo in 7 Step

1. **Setup di Cattura Mirata:** configurazione di catture filtrate su interfacce critiche con filtri BPF.
2. **Filtraggio per Protocollo:** display filter avanzati per protocolli in chiaro e sessioni di autenticazione.
3. **Raccolta Credenziali:** estrazione da HTTP, FTP, Telnet, SMTP e handshake SMB/NTLM.
4. **Ricostruzione degli Stream:** Follow TCP/HTTP Stream per ricostruire sessioni complete.
5. **Estrazione File e Artefatti:** recupero file trasferiti via Export Objects.
6. **Intelligence di Rete:** mappatura comunicazioni interne per pianificare il pivot.
7. **Stealth ed Elusione del Rilevamento:** minimizzare l'impronta di cattura.

***

## Wireshark vs tcpdump vs tshark vs dumpcap: quando usare cosa

Sono tool complementari, non alternativi. In un assessment reale li usi insieme: `dumpcap`/`tcpdump` per catturare in background senza overhead grafico, `tshark` per filtrare e automatizzare in pipeline, Wireshark per l'analisi visuale approfondita.

| Tool                                                | Interfaccia | Punto di forza                                    | Quando usarlo                                              |
| --------------------------------------------------- | ----------- | ------------------------------------------------- | ---------------------------------------------------------- |
| **Wireshark**                                       | GUI         | Analisi visuale, Follow Stream, Export Objects    | Analisi approfondita post-cattura, ricostruzione sessioni  |
| **[tshark](https://hackita.it/articoli/tshark/)**   | CLI         | Stessa engine di Wireshark, scriptabile           | Automazione, parsing in pipeline, ambienti senza GUI       |
| **[tcpdump](https://hackita.it/articoli/tcpdump/)** | CLI         | Leggero, presente ovunque su Linux                | Cattura rapida su host remoto/compromesso via SSH          |
| **dumpcap**                                         | CLI         | Solo cattura, motore di Wireshark senza dissector | Cattura long-running a basso overhead, poi analisi offline |

Workflow tipico: `tcpdump`/`dumpcap` sul target per catturare senza appesantire la macchina compromessa → trasferisci il `.pcapng` in locale → apri con Wireshark per l'analisi fine.

***

## Fase 1: Ricognizione ed Enumerazione

**Scenario:** accesso iniziale a una workstation in segmento interno. Devi capire cosa c'è in rete senza generare traffico attivo.

**Configurazione permessi per cattura non privilegiata:**

```bash
sudo usermod -a -G wireshark $USER
newgrp wireshark
```

**Identificazione interfacce di rete attive:**

```bash
ip -br addr show
```

**Capture filter BPF per isolare subnet target:**

```bash
dumpcap -i eth0 -f "net 192.168.1.0/24" -w initial_capture.pcapng
```

**Display filter per traffico verso servizi specifici:**

```
tcp.port == 445 or tcp.port == 3389 or tcp.port == 22 or tcp.port == 23
```

**Identificazione comunicazioni DNS interne:**

```
dns and ip.src == 192.168.1.0/24
```

**Analisi broadcast/multicast traffic:**

```
(arp or icmp) and not icmp.type == 8
```

**Cattura mirata su interfaccia VPN (HTB/PG):**

```bash
wireshark -k -i tun0
```

**Capture filter per escludere traffico non rilevante:**

```bash
dumpcap -i eth0 -f "not port 53 and not arp" -w filtered_traffic.pcapng
```

***

## Fase 2: Sfruttamento Iniziale - Raccolta Credenziali

**Cattura traffico HTTP in chiaro:**

```bash
dumpcap -i eth0 -f "port 80" -w http_clear.pcapng
```

**Display filter per richieste POST (login form):**

```
http.request.method == "POST"
```

**Estrazione credenziali HTTP Basic Auth:**

```
http.authorization contains "Basic"
```

**Decodifica Base64 HTTP Basic in Wireshark:**

1. Clicca sul pacchetto con Authorization header
2. `File → Export Packet Bytes → Decode As → Base64`
3. Analizza l'output per username:password

**Cattura sessioni FTP con credenziali:**

```bash
dumpcap -i eth0 -f "port 21" -w ftp_sessions.pcapng
```

**Display filter per comandi FTP sensibili:**

```
ftp.request.command == "USER" or ftp.request.command == "PASS"
```

**Analisi traffico Telnet per credenziali:**

```
telnet and telnet.data
```

**Cattura autenticazioni SMTP:**

```bash
dumpcap -i eth0 -f "port 25" -w smtp_auth.pcapng
```

**Display filter per SMTP AUTH:**

```
smtp.req.command == "AUTH"
```

Se durante un internal assessment ottieni una shell su una workstation Windows, Wireshark permette di identificare autenticazioni NTLM, protocolli legacy e comunicazioni interne senza generare traffico aggiuntivo — è l'approccio passivo per eccellenza prima di passare a tecniche attive come [Responder](https://hackita.it/articoli/responder/) o mitm6.

**Analisi handshake [SMB](https://hackita.it/articoli/smb/)/NTLM:**

```
smb2 or ntlmssp
```

**Identificazione NTLMSSP Authentication:**

```
ntlmssp.auth
```

**Estrazione challenge-response NTLM per offline cracking:**

1. Filtra: `ntlmssp`
2. Clic destro sul pacchetto NTLMSSP → Follow → TCP Stream
3. Cerca i blocchi `NTLMSSP_CHALLENGE` e `NTLMSSP_AUTH`
4. Estrai NT/LM hash per strumenti come Hashcat

Se intercetti un handshake NTLM completo puoi valutare anche il relay invece del solo cracking offline — approfondisci in [NTLM Relay](https://hackita.it/articoli/ntlm-relay/).

**Ricerca token in header HTTP:**

```
http contains "Authorization: Bearer" or http contains "session="
```

**Cattura cookie di sessione:**

```
http.cookie
```

***

## Fase 3: Post-Compromissione e Analisi dei Protocolli

**Analisi traffico da host remoto via SSH tunnel:**

```bash
ssh user@target-host "sudo tcpdump -i eth0 -U -w -" | wireshark -k -i -
```

**Display filter per servizi database:**

```
tcp.port == 1433 or tcp.port == 3306 or tcp.port == 5432
```

**Ricerca query SQL in chiaro:**

```
mysql.query or pgsql.type == "Q"
```

**Analisi traffico SNMP con community string:**

```
snmp and snmp.community
```

**Identificazione configurazioni trasferite in chiaro:**

```
http contains "config" or ftp-data contains "password"
```

**Cattura traffico TFTP per file transfer:**

```bash
dumpcap -i eth0 -f "port 69" -w tftp_transfers.pcapng
```

**Display filter per TFTP operations:**

```
tftp.opcode == 1 or tftp.opcode == 2
```

**Analisi protocolli industrial/OT in chiaro:**

```
modbus or enip
```

**Estrazione file da HTTP con Export Objects:**

1. `File → Export Objects → HTTP...`
2. Filtra per tipo (exe, zip, config)
3. Salva e analizza offline

**Ricostruzione file binari da TCP Stream:**

1. Follow TCP Stream
2. Imposta "Show data as" → "Raw"
3. Salva come file binario
4. Verifica magic bytes e tipo file

***

## Fase 4: Intelligence per il Movimento Laterale

**Mappatura conversazioni tra host interni:**

```
ip.addr == 192.168.1.50 and ip.addr == 192.168.1.100
```

**Analisi statistiche comunicazioni:**

1. `Statistics → Conversations`
2. Filtra per protocollo TCP/IP
3. Identifica host con più connessioni

**Identificazione trust relationship:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == 192.168.1.50
```

**Display filter per sessioni RDP:**

```
tcp.port == 3389
```

**Filtro per traffico [Kerberos](https://hackita.it/articoli/kerberos/):**

```
kerberos
```

**Analisi JA3 fingerprint per client identification:**

```
tls.handshake.ja3
```

**Identificazione SNI in TLS handshake:**

```
tls.handshake.extensions_server_name
```

**Cattura beaconing pattern:**

```
dns.qry.type == 1 and frame.time_delta > 60
```

**Analisi timing per C2 detection:**

```
tcp.time_delta > 5 and tcp.len > 0
```

**Ricerca DNS tunneling indicator:**

```
dns.qry.name.len > 50 or dns.count.queries > 5
```

***

## Fase 5: Rilevamento e Hardening

**Rilevamento promiscuous mode via network:**

```
eth.dst == ff:ff:ff:ff:ff:ff and arp.proto.type == 0x0806
```

**Monitoraggio ARP anomalies:**

```
arp.duplicate-address-detected or arp.isgratuitous
```

**Detect SPAN/Mirror port configurations:**

```
tcp.analysis.duplicate_ack or tcp.analysis.retransmission
```

**Hardening: disabilitazione protocolli insecure:**

```bash
systemctl disable --now telnet.socket
systemctl disable --now vsftpd
```

**Configurazione EDR per monitorare Npcap/WinPcap:**

* Monitor registry: `HKLM\SYSTEM\CurrentControlSet\Services\NPF`
* File system: `C:\Windows\System32\drivers\npf.sys`
* Process creation: `windump.exe`, `dumpcap.exe`

**Network segmentation detection via TTL analysis:**

```
ip.ttl < 64 and ip.src == 192.168.1.0/24
```

**Implementazione encrypted protocols only policy:**

```bash
# Blocca HTTP in chiaro su rete management
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 80 -j DROP
```

**Monitoraggio port mirroring abuse:**

```
tcp.flags == 0x0000 and tcp.len > 0
```

**Rilevamento Wireshark remote capture:**

```
tcp.port == 2002 and tcp.payload contains "WIRESHARK"
```

## Solo Traffico Tra Me e il Target

**Quando usarlo:** su HTB, CTF o assessment con rete rumorosa, vuoi vedere solo il dialogo tra la tua macchina e il target — non tutto il broadcast della subnet.

```
(ip.src == 10.129.30.85 && ip.dst == 10.10.14.146) ||
(ip.src == 10.10.14.146 && ip.dst == 10.129.30.85)
```

Evita migliaia di pacchetti inutili quando lavori su HTB o durante un assessment. Mostra esclusivamente il traffico tra attacker e target.

## Solo Se il Sito Mi Chiama (Solo Risposte del Server)

**Quando usarlo:** vuoi isolare solo ciò che il server ti risponde, ignorando le tue richieste in uscita — utile per capire cosa arriva davvero indietro senza il rumore delle tue probe.

```
ip.src == TARGET_IP
```

Variante per porta specifica (solo risposte da quella porta):

```
tcp.srcport == 80
tcp.srcport == 443
```

***

## Filtri Tricky da Pentester: Altri Casi Utili

**Errori e anomalie TCP** — quando: connessione instabile o firewall che droppa pacchetti, capisci dov'è il problema di rete:

```
tcp.analysis.retransmission
tcp.analysis.fast_retransmission
tcp.analysis.out_of_order
```

**Reset delle connessioni:**

```
tcp.flags.reset == 1
```

**Solo pacchetti SYN (scan detection):**

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Solo pacchetti con payload (esclude ACK vuoti):**

```
tcp.len > 0
```

**Codici di risposta HTTP interessanti:**

```
http.response.code == 500
http.response.code == 302
http.response.code == 401
```

**Cookie, Authorization, User-Agent:**

```
http.set_cookie
http.authorization
http.user_agent
```

**Solo risposte DNS:**

```
dns.flags.response == 1
```

**Comandi SMB2:**

```
smb2.cmd
```

**TLS SNI (dominio richiesto in handshake):**

```
tls.handshake.extensions_server_name
```

**Escludere il rumore di broadcast (ARP, mDNS, LLMNR, NBNS):**

```
!(arp || mdns || llmnr || nbns)
```

Utilissimo in laboratorio per isolare solo traffico rilevante quando la rete è piena di broadcast automatici di Windows.

***

## Cheat Sheet: Problema → Filtro

| Problema                        | Filtro                                                   |
| ------------------------------- | -------------------------------------------------------- |
| Solo traffico attacker ↔ target | `(ip.src==A && ip.dst==B) \|\| (ip.src==B && ip.dst==A)` |
| Solo risposte del server        | `ip.src == TARGET`                                       |
| Errori TCP                      | `tcp.analysis.retransmission`                            |
| Reset TCP                       | `tcp.flags.reset == 1`                                   |
| HTTP POST                       | `http.request.method == "POST"`                          |
| Cookie                          | `http.set_cookie` / `http.cookie`                        |
| Bearer token                    | `http contains "Bearer"`                                 |
| Solo risposte DNS               | `dns.flags.response == 1`                                |
| Traffico SMB                    | `smb2 or smb`                                            |
| Traffico Kerberos               | `kerberos`                                               |
| TLS SNI                         | `tls.handshake.extensions_server_name`                   |
| RDP                             | `tcp.port == 3389`                                       |
| LDAP                            | `ldap`                                                   |
| WinRM                           | `tcp.port == 5985`                                       |
| ICMP                            | `icmp`                                                   |
| SSH                             | `tcp.port == 22`                                         |

***

## Errori Comuni Che Vedo Negli Assessment Reali

1. **Capture filter inesistenti o errati:** cattura di tutto il traffico, PCAP di gigabyte e performance degradation.
2. **Display filter troppo ampi:** `ip.addr == subnet` senza ulteriore filtraggio, migliaia di pacchetti irrilevanti.
3. **Ignorare protocolli legacy:** non filtrare Telnet (23), FTP (21), SMTP (25) dove ancora attivi.
4. **Mancata analisi NTLMSSP:** non cercare autenticazioni NTLM in traffico SMB, perdendo credential harvesting.
5. **Export Objects non utilizzato:** non estrarre file da HTTP quando disponibili.
6. **TLS considerato "impenetrabile":** non analizzare metadata TLS (SNI, JA3, certificate info).

***

## Playbook Operativo 80/20: Wireshark in Internal Assessment

| Obiettivo                           | Azione Concreta                         | Strumento/Filtro                       |
| ----------------------------------- | --------------------------------------- | -------------------------------------- |
| Isolamento traffico target          | Capture filter BPF su IP/port specifici | `host 10.10.10.10 and port 80`         |
| Identificazione login HTTP          | Display filter per richieste POST       | `http.request.method == "POST"`        |
| Estrazione credenziali HTTP Basic   | Decodifica header Authorization         | `http.authorization contains "Basic"`  |
| Analisi autenticazioni SMB          | Filtro per handshake NTLMSSP            | `ntlmssp`                              |
| Ricostruzione sessioni applicative  | Follow TCP Stream                       | Click destro → Follow → TCP Stream     |
| Estrazione file da rete             | Export Objects HTTP/SMB                 | File → Export Objects → HTTP...        |
| Identificazione servizi vulnerabili | Filtro per protocolli legacy            | `tcp.port == 23 or tcp.port == 21`     |
| Mappatura comunicazioni interne     | Statistics → Conversations              | Analisi tabella conversations          |
| Rilevamento anomalie TLS            | Analisi SNI e JA3 fingerprint           | `tls.handshake.extensions_server_name` |
| Hardening evidenza                  | Disabilitazione protocolli in chiaro    | `systemctl disable [service]`          |

***

## Lab Realistico: Internal Network Traffic Analysis

**Scenario "Clear-Text Compromise":** in un lab che replica una rete enterprise con segmenti misti (prod, dev, legacy), identifica e sfrutta le vulnerabilità nei protocolli di rete.

**Fasi del lab:**

1. **Passive Reconnaissance:** cattura su segmento mirrorato senza generare pacchetti.
2. **Protocol Identification:** identifica protocolli attivi, focus su quelli in chiaro.
3. **Credential Harvesting:** estrai credenziali da HTTP Basic Auth, FTP, Telnet.
4. **NTLM Analysis:** analizza handshake SMB, estrai challenge-response.
5. **File Extraction:** recupera file di configurazione trasferiti via rete.
6. **Intelligence Reporting:** genera report su comunicazioni interne e trust relationship.

**Technical Learning Objectives:**

* Configurazione avanzata di capture e display filter per scenari reali
* Estrazione e decodifica credenziali da protocolli multipli
* Analisi forense di handshake di autenticazione (NTLM, Kerberos)
* Ricostruzione di sessioni applicative e file transfer
* Identificazione di misconfigurazioni tramite analisi passiva

***

## Domande Frequenti su Wireshark per Pentesting

**Wireshark è legale da usare?**
Sì, ma solo su reti e sistemi per cui hai autorizzazione esplicita — lab, CTF, piattaforme come HTB o assessment autorizzati per iscritto. Usarlo su reti altrui senza permesso è reato.

**Wireshark può catturare traffico HTTPS in chiaro?**
No, non di default. Serve avere le chiavi di sessione (es. SSLKEYLOGFILE) o eseguire un MITM attivo sulla connessione per decriptare il traffico in post-analisi.

**Qual è la differenza tra capture filter e display filter?**
Il capture filter (sintassi BPF) agisce durante la cattura e riduce il traffico salvato su disco. Il display filter agisce dopo, sulla cattura già fatta, ed è più espressivo per l'analisi.

**Wireshark serve ancora se ho tshark?**
Sì, sono complementari: tshark è la CLI per script e pipeline automatizzate, Wireshark è l'interfaccia grafica per l'analisi approfondita e la ricostruzione visuale degli stream.

**Come estraggo un hash NTLM da una cattura Wireshark?**
Filtra `ntlmssp`, segui lo stream TCP del pacchetto di autenticazione, individua i blocchi NTLMSSP\_CHALLENGE e NTLMSSP\_AUTH e ricostruisci l'hash nel formato compatibile con Hashcat.

**Come filtro il traffico di un IP specifico in Wireshark?**
Usa `ip.addr == 192.168.1.10` per vedere tutto il traffico da/verso quell'host, oppure `ip.src ==` / `ip.dst ==` per isolare solo una direzione.

**Come vedo solo traffico HTTP in Wireshark?**
Digita `http` nella barra dei display filter. Per isolare solo le richieste: `http.request`; per le risposte: `http.response`.

**Come vedo solo traffico DNS?**
Filtro `dns`. Per isolare solo le risposte: `dns.flags.response == 1`; per le query: `dns.flags.response == 0`.

**Come seguo uno stream TCP completo?**
Clic destro su un pacchetto TCP → Follow → TCP Stream. Wireshark ricostruisce l'intera conversazione in ordine, utile per leggere credenziali in chiaro o comandi FTP/Telnet.

**Come esporto un file da una cattura Wireshark?**
`File → Export Objects → HTTP/SMB/FTP`, poi seleziona il file dalla lista e salvalo. Funziona solo se il trasferimento non era cifrato.

**Come filtro solo l'autenticazione NTLM?**
Usa il filtro `ntlmssp`; per isolare solo la fase di autenticazione vera e propria, `ntlmssp.auth`.

**Come catturo solo traffico SMB?**
Display filter `smb2 or smb`, oppure come capture filter in fase di cattura: `port 445`.

**Come trovo credenziali FTP in una cattura?**
Filtra `ftp.request.command == "USER" or ftp.request.command == "PASS"` — FTP invia le credenziali in chiaro per default.

***

## 🔗 Approfondisci

Documentazione ufficiale e approfondimenti tecnici:

* Wireshark Official Documentation: [https://www.wireshark.org/docs/](https://www.wireshark.org/docs/)
* Wireshark Display Filter Reference: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)
* RFC 4559 – SPNEGO-based Kerberos and NTLM HTTP Authentication: [https://datatracker.ietf.org/doc/html/rfc4559](https://datatracker.ietf.org/doc/html/rfc4559)
* [Open-Source Security Tools: Building a Robust Tech Stack on a Budget](https://www.techonent.com/2025/09/top-open-source-security-tools.html) — panoramica su Techonent di altri tool open source (Wireshark incluso) per costruire uno stack di sicurezza a basso costo

La differenza tra analisi superficiale e offensive traffic intelligence sta nella capacità di interpretare correttamente protocolli, handshake e metadata di rete in contesti enterprise reali.

***

*Questa guida è per scopi formativi in ambienti controllati e autorizzati. Ogni test su sistemi di terze parti richiede autorizzazione scritta esplicita.*
