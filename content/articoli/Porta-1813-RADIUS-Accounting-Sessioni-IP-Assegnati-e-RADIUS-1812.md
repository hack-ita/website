---
title: 'Porta 1813 RADIUS Accounting: Sessioni, IP Assegnati e RADIUS 1812'
slug: porta-1813-radius-accounting
description: >-
  Pentest RADIUS Accounting sulla porta 1813/UDP: session tracking, Framed-IP,
  Accounting-Request, correlazione con 1812 e visibilità sulle sessioni di rete
  in lab.
image: /porta-1813-radius-accounting.webp
draft: false
date: 2026-04-12T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - RADIUS Accounting
  - Session Tracking
  - Framed-IP
---

> **Executive Summary** — La porta 1813/UDP ospita il servizio di accounting RADIUS, il componente che registra l'inizio/fine delle sessioni, il traffico consumato, gli IP assegnati e la durata di connessione. Mentre la porta 1812 gestisce l'autenticazione (chi può connettersi), la 1813 traccia le sessioni (chi è connesso, da quando, con quale IP). Per il pentester, l'accounting RADIUS è una fonte di intelligence: rivela quali utenti sono connessi, i loro IP interni e i tempi di connessione. Lo shared secret è lo stesso della porta 1812 — compromettere uno compromette entrambi.

**TL;DR**

* La porta 1813/UDP gestisce il RADIUS Accounting — traccia sessioni, IP assegnati, durata e traffico degli utenti
* Lo *shared secret* è condiviso con la 1812 — compromesso una volta, valido anche per l’accounting
* I pacchetti accounting intercettati rivelano utenti attivi e IP assegnati — intelligence diretta per lateral movement

Per il dettaglio completo su RADIUS (shared secret cracking, credential spray, evil twin), consulta la [guida alla porta 1812 RADIUS Auth](https://hackita.it/articoli/porta-1812-radius-auth). Qui ci concentriamo sulle specificità dell'accounting.

## 1. Anatomia Tecnica

La porta 1813 è registrata IANA come `radacct`. I pacchetti di accounting seguono lo stesso formato RADIUS della 1812, con lo stesso shared secret.

| Tipo pacchetto             | Direzione    | Contenuto                                                    |
| -------------------------- | ------------ | ------------------------------------------------------------ |
| Accounting-Request (Start) | NAS → Server | Username, NAS-IP, session ID, Framed-IP                      |
| Accounting-Request (Stop)  | NAS → Server | + Session-Time, Input-Octets, Output-Octets, Terminate-Cause |
| Accounting-Response        | Server → NAS | ACK                                                          |

Informazioni presenti nei pacchetti accounting:

* **User-Name**: chi è connesso
* **Framed-IP-Address**: IP assegnato all'utente (VPN/802.1X)
* **NAS-IP-Address**: da quale switch/AP/VPN concentrator
* **Session-Time**: durata sessione
* **Acct-Terminate-Cause**: perché la sessione è terminata

## 2. Enumerazione

```bash
nmap -sU -p 1813 10.10.10.5
```

**Output:**

```
PORT     STATE         SERVICE
1813/udp open|filtered radius-acct
```

```bash
# Cattura pacchetti accounting
tcpdump -i eth0 udp port 1813 -w radius_acct.pcap
```

## 3. Intelligence dai pacchetti accounting

Con lo shared secret (lo stesso della 1812), decifra i pacchetti:

```bash
# Analizza con tshark usando lo shared secret
tshark -r radius_acct.pcap -o "radius.shared_secret:testing123" \
  -T fields -e radius.User_Name -e radius.Framed_IP_Address -e radius.NAS_IP_Address
```

**Output:**

```
j.smith     10.10.10.201    10.10.10.1
admin       10.10.10.202    10.10.10.1
ceo         10.10.10.203    10.10.10.2
```

**Lettura dell'output:** tre utenti connessi via VPN/Wi-Fi con i loro IP interni. `admin` sulla 10.10.10.202 è un target — il suo IP ti permette di attaccarlo direttamente. `ceo` arriva da un AP diverso (10.10.10.2). Queste informazioni alimentano il [lateral movement](https://hackita.it/articoli/post-exploitation).

## 4. Cosa puoi fare con l'accounting

* **Mappare utenti → IP**: sai esattamente quale IP ha ciascun utente connesso
* **Identificare utenti privilegiati**: admin, DA, C-level — i loro IP sono target primari
* **Tracciare orari di connessione**: sai quando un utente si connette/disconnette — utile per timing gli attacchi
* **Identificare NAS**: mappa switch/AP attivi nella rete

## 5. Cheat Sheet

| Azione         | Comando                                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------------------ |
| Scan           | `nmap -sU -p 1813 [target]`                                                                                        |
| Capture        | `tcpdump -i eth0 udp port 1813 -w acct.pcap`                                                                       |
| Decode         | `tshark -r acct.pcap -o "radius.shared_secret:[secret]" -T fields -e radius.User_Name -e radius.Framed_IP_Address` |
| Correlate auth | Usa lo stesso shared secret sulla [porta 1812](https://hackita.it/articoli/porta-1812-radius-auth)                 |

### Perché Porta 1813 è rilevante

L'accounting RADIUS è una miniera di intelligence passiva: utenti connessi, IP assegnati, NAS attivi. Con lo shared secret (identico alla 1812), decifri tutto. In un engagement, sapere che `admin` ha IP 10.10.10.202 ti permette di mirare gli attacchi.

### Hardening

* Stesso hardening della 1812: shared secret forte, RADSEC per TLS
* Limita l'accesso alla 1813 da soli NAS autorizzati
* Log accounting centralizzati con retention policy

***

Riferimento: RFC 2866 (RADIUS Accounting). Uso esclusivo in ambienti autorizzati. [https://tcp-udp-ports.com/port-1813.htm](https://tcp-udp-ports.com/port-1813.htm)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
