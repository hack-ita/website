---
title: 'NBTSscan: NetBIOS Enumeration Rapida su Reti Windows'
slug: nbtsscan
description: >-
  NBTSscan è un tool leggero per enumerazione NetBIOS su reti Windows.
  Identifica hostname, domain e MAC address tramite query NetBIOS.
image: /Gemini_Generated_Image_cw5ihecw5ihecw5i.webp
draft: false
date: 2026-02-19T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - netbios
---

## Introduzione

Nbtscan scansiona range IP per estrarre informazioni NetBIOS — hostname, workgroup/dominio, MAC address e servizi attivi. Su reti Windows è uno dei metodi più rapidi per ottenere una mappa degli host con i loro nomi e ruoli (file server, domain controller, browser master).

Dove Nmap impiega minuti per un service scan completo, Nbtscan enumera un /24 in pochi secondi con richieste UDP lightweight sulla porta 137. Informazioni che nel contesto di un pentest interno sono fondamentali per identificare target di valore.

Kill chain: **Enumeration** (MITRE ATT\&CK T1046).

***

## 1️⃣ Setup e Installazione

```bash
sudo apt install nbtscan
```

Verifica: `nbtscan -h`.

***

## 2️⃣ Uso Base

```bash
nbtscan 10.10.10.0/24
```

Output:

```
IP address       NetBIOS Name     Server    User             MAC address
------------------------------------------------------------------------------
10.10.10.10      DC01             <server>  <unknown>        00:50:56:aa:bb:01
10.10.10.20      FILESERVER       <server>  <unknown>        00:50:56:aa:bb:02
10.10.10.30      WS-JSMITH                  JSMITH           00:50:56:aa:bb:03
10.10.10.40      WS-AJONES                  AJONES           00:50:56:aa:bb:04
```

Hostname, flag server, utente loggato e MAC — tutto in 3 secondi.

**Verbose:**

```bash
nbtscan -v 10.10.10.0/24
```

Mostra tutti i servizi NetBIOS registrati per ogni host.

**Human-readable:**

```bash
nbtscan -hv 10.10.10.0/24
```

***

## 3️⃣ Tecniche Operative

### Scansione con timeout ridotto

```bash
nbtscan -t 500 10.10.10.0/24
```

Timeout 500ms — velocizza la scansione su reti stabili.

### Output per file

```bash
nbtscan -s , 10.10.10.0/24 > nbtscan_results.csv
```

`-s ,` usa la virgola come separatore — CSV ready.

### Scansione di range grandi

```bash
nbtscan 172.16.0.0/16
```

Nbtscan è abbastanza veloce per scansionare /16 in tempi ragionevoli (1-2 minuti).

***

## 4️⃣ Tecniche Avanzate

### Identificare Domain Controller

```bash
nbtscan -v 10.10.10.0/24 | grep "1C"
```

Il suffisso `1C` identifica il domain controller.

### Trovare utenti loggati

```bash
nbtscan 10.10.10.0/24 | grep -v "unknown" | awk '{print $4, $1}'
```

Utenti con sessione attiva — target per token impersonation dopo compromissione.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Mappatura rapida rete interna

```bash
nbtscan 10.10.10.0/24
```

**Timeline:** 3-5 secondi per /24. **Output atteso:** hostname e ruoli di ogni host Windows.

### Scenario 2: Trovare DC e file server

```bash
nbtscan -v 10.10.10.0/24 | grep -E "1C|20"
```

### Scenario 3: Scansione multi-subnet post-pivot

```bash
for net in 10.10.10 10.10.20 10.10.30 172.16.0; do
  nbtscan "$net.0/24"
done
```

***

## 6️⃣ Toolchain Integration

**Flusso:** **Nbtscan (NetBIOS enum)** → [Smbmap](https://hackita.it/articoli/smbmap/) (share enum) → [Rpcclient](https://hackita.it/articoli/rpcclient/) (AD enum) → Lateral movement

| Tool         | NetBIOS  | Velocità /24 | Utente loggato | MAC |
| ------------ | -------- | ------------ | -------------- | --- |
| Nbtscan      | Sì       | 3-5 sec      | Sì             | Sì  |
| Nmap -sU 137 | Sì       | 30+ sec      | Con script     | No  |
| Enum4linux   | Limitato | Singolo host | No             | No  |

***

## 7️⃣ Attack Chain Completa

**Fase 1:** Nbtscan → mappa 50 host (5 sec). **Fase 2:** DC identificato → [Ldapsearch](https://hackita.it/articoli/ldapsearch/) enum (10 sec). **Fase 3:** Credenziali trovate → lateral movement (15 min). **Timeline:** \~16 min.

***

## 8️⃣ Detection & Evasion

**Blue Team:** burst di query UDP 137. **Evasion:** Traffico NetBIOS è normale su reti Windows — bassa detection in ambienti enterprise.

***

## 9️⃣ Performance & Scaling

/24: 3-5 sec. /16: 1-2 min. Consumo: trascurabile.

***

## 🔟 Tabelle Tecniche

| Flag     | Descrizione               |
| -------- | ------------------------- |
| `-v`     | Verbose (tutti i servizi) |
| `-h`     | Human-readable            |
| `-t ms`  | Timeout                   |
| `-s sep` | Separatore output         |

### NetBIOS Suffix Codes

| Code | Significato           |
| ---- | --------------------- |
| `00` | Workstation           |
| `03` | Messenger             |
| `20` | File Server           |
| `1B` | Domain Master Browser |
| `1C` | Domain Controller     |
| `1D` | Master Browser        |

***

## 11️⃣ Troubleshooting

| Problema         | Fix                             |
| ---------------- | ------------------------------- |
| Nessun risultato | NetBIOS disabilitato sugli host |
| Timeout          | Rete lenta — aumenta `-t`       |

***

## 12️⃣ FAQ

**NetBIOS è ancora usato nel 2025?** Sì, su reti enterprise Windows è ancora diffuso. Molte organizzazioni non lo disabilitano.

***

## 13️⃣ Cheat Sheet

| Azione         | Comando                                |
| -------------- | -------------------------------------- |
| Scan /24       | `nbtscan 10.10.10.0/24`                |
| Verbose        | `nbtscan -v 10.10.10.0/24`             |
| CSV output     | `nbtscan -s , 10.10.10.0/24 > out.csv` |
| Trova DC       | `nbtscan -v range \| grep "1C"`        |
| Utenti loggati | `nbtscan range \| grep -v unknown`     |

***

**Disclaimer:** Nbtscan per penetration test autorizzati. Genera traffico UDP sulla rete target.

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
