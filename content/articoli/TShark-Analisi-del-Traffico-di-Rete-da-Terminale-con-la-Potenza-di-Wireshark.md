---
title: 'TShark: Analizzare il Traffico di Rete da Terminale'
slug: tshark
description: >
  Usa TShark da terminale come Wireshark CLI. Cattura, filtra e analizza
  traffico di rete in lab di pentesting con comandi reali e filtri avanzati.
image: /TSHARK.webp
draft: false
date: 2026-01-21T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - TShark
---

# TShark: Analizzare il Traffico di Rete da Terminale

**Sei dentro la rete interna, magari dopo un primo pivot riuscito, e inizi a guardarti intorno sul segmento di gestione. Noti traffico che viaggia ancora in chiaro: pannelli HTTP di amministrazione, sessioni FTP, query verso database. Con uno sniffing mirato e capture filter ben costruiti in TShark, quel traffico diventa intelligence concreta: credenziali riutilizzabili, account di servizio attivi e indizi perfetti per escalation e movimento laterale.**

## TL;DR Operativo (Flusso a Step)

1. Ricognizione: Identifica l'interfaccia di rete sul pivot (`tun0`, `eth1`) e cattura una slice iniziale con buffer tuning.
2. Filtraggio: Applica **TShark capture filter** (`-f`) per ridurre il rumore in cattura, poi usa i **TShark display filter** (`-Y`) per analisi mirata.
3. Harvesting: Esegui una TShark credential extraction sistematica per credenziali in cleartext, NTLM challenge/responses e stringhe SNMP.
4. Analisi: Utilizza le statistiche conversazioni (`-z conv`) e il TShark follow stream per mappare relazioni e processi.
5. Sfruttamento: Applica password reuse e utilizza le informazioni raccolte per l'accesso a nuovi host.
6. Pivoting: Esegui una nuova cattura dai sistemi compromessi per un'approfondita internal traffic analysis su segmenti precedentemente invisibili.

## Perché TShark in un Internal Pentest Enterprise

In un contesto Red Team reale, TShark è preferibile a Wireshark per:

* **Nessuna GUI** → meno visibile su server compromessi e minor footprint di memoria/CPU.
* **Esecuzione via SSH su pivot** → non richiede forwarding X11 o sessioni grafiche instabili.
* **Output parsabile** → ideale per automazione, pipeline e integrazione in script di post-exploitation.
* **Minor footprint EDR** → un processo CLI minimalista (`tshark`) può essere meno sospetto di una GUI completa (`wireshark`) in ambienti server monitorati.

## Capture Filter vs Display Filter: Performance e Stealth

La scelta tra `-f` (capture filter, sintassi BPF) e `-Y` (display filter) è critica per performance e stealth in un assessment reale.

**Capture Filter (`-f`): Filtro a livello kernel prima della scrittura su disco.**

```bash
sudo tshark -i eth1 -f "port 80 or port 443" -w web_traffic.pcapng
```

* **Performance:** Riduce drasticamente l'uso di CPU e memoria, poiché i pacchetti non matching sono scartati immediatamente.
* **Stealth:** Genera file PCAP più piccoli, riducendo l'I/O disco sul sistema compromesso (pivot).
* **Enterprise Context:** In ambienti con traffico elevato, stringere il BPF è obbligatorio per evitare di saturare risorse e causare detection.

**Display Filter (`-Y`): Filtro applicato dopo il parsing completo del pacchetto.**

```bash
tshark -r full_capture.pcapng -Y "http.authorization and ip.src==192.168.1.10"
```

* **Flessibilità:** Permette filtri complessi sui campi applicativi (es. `http.authorization`, `smb2.filename`).
* **Use Case:** Ideale per analisi post-cattura o quando non si è certi del traffico target. Meno efficiente per catture live prolungate.

**Regola Operativa:** Usa `-f` per escludere il traffico noto non utile (es. `not port 22`). Usa `-Y` per hunting e analisi approfondita sul traffico già catturato.

## Fase 1 – Ricognizione & Enumeration

**Fingerprinting del Traffico Attivo e Enterprise Tuning.**
In un contesto enterprise, le catture devono essere efficienti, silenziose e affidabili. Il tuning di performance, buffer e rotation è cruciale.

**Cattura con Buffer Tuning e Rotation Controllata:**

```bash
sudo tshark -i eth1 -f "not host 192.168.1.50 and not port 22" -B 4096 -b filesize:100000 -b files:5 -a duration:300 -w rotating_cap.pcapng
```

* `-B 4096`: Aumenta il capture buffer a 4 MB. Su segmenti ad alto throughput, il buffer di default può causare packet loss. Un Red Teamer deve ottimizzare questo parametro.
* `-b filesize:100000`: Ruota il file dopo \~100MB.
* `-b files:5`: Mantiene solo gli ultimi 5 file, elimina i più vecchi.
* `-a duration:300`: Cattura per 5 minuti, poi termina.
* **Contesto Red Team:** Evita di riempire il disco del pivot. Minimizza l'uso di risorse prolungato (EDR/performance monitoring).

**Verifica Packet Loss Post-Cattura:**

```bash
tshark -r rotating_cap_00001.pcapng -q -z io,stat,0
```

* **Interpretazione:** Controlla l'output per voci come `Dropped packets`. Se >0, il buffer (`-B`) era insufficiente o il BPF troppo largo. In un assessment reale, packet loss significa dati persi potenzialmente critici. Aggire restringendo il filtro `-f` o aumentando il valore di `-B`.

**Identificazione Protocolli Dominanti:**

```bash
tshark -r rotating_cap_00001.pcapng -q -z io,phs --color
```

Determina se il segmento è dominato da SMB, HTTP/S, database o protocolli di gestione.

## Micro-Decision Tree Operativo Iniziale:

* **HTTP/FTP in chiaro trovato?** → Credential harvesting immediato con estrazione campi.
* **Solo TLS?** → Analisi SNI (`tls.handshake.extensions_server_name`) + JA3 fingerprinting (`tls.handshake.ja3`) + analisi certificati.
* **SMB con NTLM?** → Estrarre username/domain da `ntlmssp.auth` → password spraying o relaying target.
* **SNMPv2?** → Community string → pivot su network device.
* **Traffico Kerberos?** → Identificare SPN (`kerberos.SPName`) → possibile Kerberoasting target.

## Fase 2 – Initial Exploitation

**Credential Harvesting e Estrazione Dati Sensibili.**
L'interpretazione corretta dei campi estratti è fondamentale per l'azione offensiva. Una corretta TShark credential extraction richiede filtri precisi.

**Estrazione e Interpretazione di Credenziali HTTP Basic:**

```bash
tshark -r rotating_cap.pcapng -Y "http.authorization" -T fields -e ip.src -e http.authorization | grep Basic
```

* **Interpretazione:** Il campo `http.authorization` contiene la stringa `Basic <base64>`. Decodificandola si ottiene `username:password` in chiaro. Credenziali spesso riutilizzate per SSH o pannelli di amministrazione.

**Hunting NTLMSSP per Target Prioritization:**

```bash
tshark -r rotating_cap.pcapng -Y "ntlmssp.auth" -T fields \
-e ntlmssp.auth.username -e ntlmssp.auth.domain -e ip.dst | sort -u
```

* **Interpretazione Operativa Avanzata:** Se più utenti (`ntlmssp.auth.username`) autenticano verso lo stesso `ip.dst`, quel sistema è probabilmente un Domain Controller, un File Server centrale o un application server critico. Questo identifica target prioritari per:
  * **Password spraying** utilizzando gli username raccolti.
  * **NTLM relay** se il servizio di destinazione è vulnerabile.
  * **Kerberoasting correlato** se gli account sono service accounts.

**Caccia a Token e Sessioni:**

```bash
tshark -r rotating_cap.pcapng -Y "http.request.uri contains ?" -T fields -e http.host -e http.request.uri | grep -oE "([Ss][Ii][Dd]|[Tt]oken|[Aa]uth)=[^&]+"
```

Cerca parametri URL che contengono identificatori di sessione riutilizzabili per il session hijacking.

## Fase 3 – Post-Compromise & Privilege Escalation

**Analisi del Traffico per Escalation e Intel.**
Dopo l'accesso a un host, l'analisi del traffico locale rivela opportunità.

**TLS Intelligence senza Decifratura (SNI Hunting):**

```bash
tshark -r rotating_cap.pcapng -Y "tls.handshake.type == 1" -T fields -e ip.src -e tls.handshake.extensions_server_name 2>/dev/null | sort -u
```

* **Interpretazione Operativa:** Il Server Name Indication (SNI) rivela l'hostname a cui il client si sta connettendo, anche su HTTPS. Mappa l'infrastruttura web interna (es. `wiki.internal`, `gitlab.corp`) senza dover decifrare il traffico.

**Interpretazione del Traffico Kerberos per Target Prioritization:**

```bash
tshark -r rotating_cap.pcapng -Y "kerberos.SPName" -T fields -e ip.src -e kerberos.SPName 2>/dev/null | grep -v "krbtgt" | sort -u
```

* **Interpretazione Operativa:** Gli SPN (Service Principal Names) come `MSSQLSvc/db.corp:1433` o `HTTP/webapp.corp` identificano service account. Questi sono target ad alto valore per attacchi Kerberoasting.

**Interpretazione delle SNMP Community String:**

```bash
tshark -r rotating_cap.pcapng -Y "snmp.community.string" -T fields -e snmp.community.string | sort -u
```

* **Interpretazione Operativa:** La `snmp.community.string` (es. `public`, `private`, `internal`) funge da password per lettura/scrittura su dispositivi di rete. Spesso è identica a password di default o deboli su switch, router, stampanti, permettendo il pivot.

## Correlazione Offensiva dei Dati Raccolti

Una cattura isolata non basta. L'analisi strategica richiede di incrociare i dataset per la target prioritization:

* **Host più comunicativi** (da `-z conv`)
* **Account più attivi** (da `ntlmssp.auth.username`)
* **Servizi esposti in chiaro** (HTTP/FTP/Telnet)
* **Hostname interni** (da SNI TLS)

**Esempio Decisionale Operativo:**
Se:

* `user_svc` autentica NTLM verso `10.0.0.5`
* `10.0.0.5` è top talker su porta 445 (SMB)
* `10.0.0.5` riceve molte richieste Kerberos con SPN `cifs/...`

→ Target ad altissima probabilità di essere un file server critico, con credenziali potenzialmente riutilizzabili su altri servizi. La correlazione trasforma i dati in intelligenza attaccabile.

## Fase 4 – Lateral Movement & Pivoting

**Sfruttamento delle Relazioni di Trust e Nuovi Segmenti.**

**Mappatura delle Conversazioni per Identificare Trust:**

```bash
tshark -r rotating_cap.pcapng -q -z conv,tcp --color | head -20
```

Identifica le coppie IP:porta che comunicano più intensamente (es. un server che dialoga con molti client su porta 445 → potenziale domain controller o file server).

**Cattura da Pivot su Nuovo Segmento con Tuning:**

```bash
# Sul pivot (es. 192.168.2.10), avvia cattura ottimizzata
ssh compromised@192.168.2.10 "sudo tshark -i eth0 -f 'host 192.168.3.20' -B 2048 -b filesize:50000 -b files:2 -a duration:180 -w /tmp/dc_traffic.pcapng -q 2>/dev/null &"
```

Utilizza le credenziali raccolte per SSH ed esegui una cattura remota ottimizzata su un segmento critico (es. rete dei server).

**Ricostruzione Flussi Applicativi (TShark Follow Stream):**

```bash
tshark -r dc_traffic.pcapng -q -z "follow,tcp,ascii,0"
```

Dopo aver scaricato il PCAP, ricostruisci flussi per analizzare protocolli in chiaro o parti di handshake.

## OPSEC Red Team – Ridurre Impronta Operativa

In un ambiente enterprise reale, lo sniffing deve bilanciare raccolta dati e stealth:

* **Evita catture lunghe:** Usa durate brevi (`-a duration:120`) e mirate.
* **Usa rotazione file:** (`-b filesize: -b files:`) per non saturare il disco del pivot.
* **Trasferisci ed elimina:** Sposta i PCAP sul tuo controller e cancella le tracce dal target.
* **Scegli directory con attenzione:** `/tmp` è spesso monitorato. Valuta `/dev/shm` (memoria) o directory utente meno sospette.
* **Sniffing non è invisibile:** È meno rumoroso di uno scanning attivo, ma processi `tshark` lunghi, alto I/O disco o packet loss possono essere rilevati.

## Fase 5 – Detection & Hardening

**Indicatori di Compromissione e Mitigazioni Concrete.**

**IoC per il Blue Team:**

* **IoC 1:** Processo `tshark` o `dumpcap` in esecuzione su host server (non workstation di amministrazione) con parametri di buffer tuning (`-B`).
* **IoC 2:** Connessioni SSH o RDP originate da host interni che utilizzano credenziali trovate in log di protocolli in chiaro (correlazione log).
* **IoC 3:** Picchi di traffico di piccolo volume ma costante su porte specifiche (es. 21, 23, 161) verso un singolo host interno (sniffing mirato).
* **IoC 4:** Creazione e successiva eliminazione di file `.pcapng` in directory temporanee, specialmente con pattern di rotazione (`_00001`, `_00002`).

**Hardening Concreto:**

* **Eliminare Protocolli in Cleartext:** Policy di sicurezza che vietano FTP, Telnet, HTTP non-TLS, SNMP v2/2c. Sostituzione con alternative cifrate (SFTP/SSH, HTTPS, SNMPv3).
* **Segmentazione e Filtering East-West:** Firewall interni o micro-segmentazione (es. con NSX, ACLs) per limitare le comunicazioni orizzontali. Il principio: un server web non deve poter inviare traffico raw alla porta 445 di un domain controller.
* **Monitoraggio Attivo del Traffico e dei Processi:** Implementare soluzioni NDR/EDR per rilevare l'esecuzione di tool di cattura di rete e parametri anomali (`-B`, `-b`). Monitorare le connessioni di rete originate da processi insoliti.
* **Encryption Everywhere e Certificate Pinning:** Forzare l'uso di channel cifrati per tutte le gestioni. L'uso di certificate pinning rende più difficile l'intercettazione MITM anche in scenari di post-compromise.

## Errori Comuni Che Vedo Negli Assessment Reali

* **Catturare senza `-f` e buffer tuning:** Inondare il disco del pivot con traffico irrilevante e causare packet loss, ottenendo dati incompleti.
* **Ignorare la verifica del packet loss:** Non controllare le statistiche I/O post-cattura, credendo di avere un dataset completo quando invece è corroso.
* **Non sfruttare i metadati TLS (SNI, JA3):** Perdersi intelligence preziosissima su hostname interni e tipologie di client.
* **Estrazione NTLM superficiale:** Limitarsi a vedere il traffico senza estrarre sistematicamente `username` e `domain` per il successivo password spraying.
* **Non correlare le evidenze:** Avere una lista di credenziali e una mappa di conversazioni separata, senza incrociare i dati per identificare gli account usati sugli host più critici.

## Mini Tabella 80/20 Finale

| Obiettivo                           | Azione                               | Comando                                                                                               |
| :---------------------------------- | :----------------------------------- | :---------------------------------------------------------------------------------------------------- |
| **Cattura Ottimizzata Enterprise**  | Buffer tuning + rotazione file       | `sudo tshark -i eth1 -B 4096 -b filesize:100000 -b files:3 -a duration:240 -w cap.pcapng`             |
| **Verifica Integrità Cattura**      | Controllo packet loss                | `tshark -r cap.pcapng -q -z io,stat,0`                                                                |
| **Target Prioritization**           | Correlazione utenti ↔ server critico | `tshark -r cap.pcapng -Y "ntlmssp.auth" -T fields -e ntlmssp.auth.username -e ip.dst`                 |
| **Internal Traffic Analysis (TLS)** | Estrai hostname da SNI               | `tshark -r cap.pcapng -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name` |
| **TShark Follow Stream**            | Ricostruisci flusso applicativo      | `tshark -r cap.pcapng -q -z "follow,tcp,ascii,2"`                                                     |

Approfondisci tecniche correlate di network discovery ed enumeration in:

* 👉 [https://hackita.it/articoli/netdiscover](https://hackita.it/articoli/netdiscover)
* 👉 [https://hackita.it/articoli/tcpdump](https://hackita.it/articoli/tcpdump)
* 👉 [https://hackita.it/articoli/snmp](https://hackita.it/articoli/snmp)

Per assessment interni, simulazioni Red Team e test di sicurezza su infrastrutture reali:
👉 [https://hackita.it/servizi](https://hackita.it/servizi)

Per supportare il progetto e i lab avanzati:
👉 [https://hackita.it/supporta](https://hackita.it/supporta)

Riferimenti tecnici ufficiali:

* Wireshark / TShark Documentation: [https://www.wireshark.org/docs/](https://www.wireshark.org/docs/)
* MITRE ATT\&CK – Network Sniffing (T1040): [https://attack.mitre.org/techniques/T1040/](https://attack.mitre.org/techniques/T1040/)
* RFC 8446 – TLS 1.3: [https://datatracker.ietf.org/doc/html/rfc8446](https://datatracker.ietf.org/doc/html/rfc8446)
