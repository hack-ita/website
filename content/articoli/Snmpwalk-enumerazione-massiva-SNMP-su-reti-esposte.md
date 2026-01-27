---
title: 'Snmpwalk: enumerazione massiva SNMP su reti esposte'
slug: snmpwalk
description: >-
  Snmpwalk è il tool ideale per interrogare agent SNMP e raccogliere info
  dettagliate su dispositivi di rete. Usato per recon low-noise e attacchi
  mirati.
image: /snmpwalk.webp
draft: false
date: 2026-01-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - snmpwalk
  - snmp
---

# Snmpwalk: Enumerazione Massiva SNMP su Reti Esposte

## Introduzione Tattica

Una VLAN di management contiene switch Cisco con SNMPv2c attivo. La community `public` è attiva e permette l'accesso in lettura. In un internal pentest, **snmpwalk** è il comando che trasforma una community string valida in una mappa infrastrutturale completa: estrai l'intero MIB tree, trasformando un protocollo di gestione nella blueprint della rete interna, inclusi percorsi di routing, processi attivi e potenziali credenziali hardcoded. **snmpwalk** non è uno strumento tra tanti: è il vettore principale per il network mapping.

## Perché SNMPWALK è il Tool Chiave in un Internal Pentest

**snmpwalk** differisce radicalmente da `snmpget` (query singola) o tool come `onesixtyone` (bruteforce community). Mentre questi forniscono dati puntuali, **snmpwalk** esegue un'enumerazione strutturata e completa attraverso richieste **GETNEXT iterative**: ogni OID interrogato restituisce il successivo nel MIB tree, permettendo di mappare intere sezioni della configurazione. Questo meccanismo lo rende estremamente potente per il mapping infrastrutturale, ma genera pattern di traffico facilmente rilevabili da sistemi NDR: sequenze consecutive di richieste su OID ascendenti sono un IoC immediato.

## TL;DR Operativo (Flusso a Step)

1. **Bruteforce Preliminare:** `onesixtyone` per identificare community valide (soglia: \<50 query/minuto per evitare detection).
2. **Walk Strategico:** **snmpwalk** mirato su MIB-2 (`1.3.6.1.2.1`) per estrazione di routing table, interfacce, ARP cache.
3. **Decision Tree:** Walk completo in ambienti poco monitorati; walk mirato su `ipRouteTable` e `hrSWRunTable` in ambienti enterprise.
4. **Parsing Offensivo:** Estrazione e analisi dell'output per credential leakage, naming convention AD, subnet nascoste.
5. **Prioritizzazione:** Classifica target per impatto: SNMP su Domain Controller → critico, router con routing table → alto.
6. **Pivot Concrete:** Utilizza subnet scoperte via **snmpwalk** per tunnel e scanning interno.
7. **Detection Awareness:** Minimizza GETNEXT massivi; threshold realistici: >200 OID in 60 secondi generano alert.

## SNMPWALK Deep Usage: Ottimizzazione per Red Team

**Sintassi Avanzata e Opzioni Critiche:**

```bash
snmpwalk -v2c -c public -On -t 3 -r 0 -Cc TARGET 1.3.6.1.2.1.4.21
```

**Spiegazione Opzioni:**

* `-On`: Output numerico OID. Evita lookup MIB, riducendo DNS queries e rumore. Essenziale per parsing automatizzato.
* `-t 3`: Timeout di 3 secondi. In ambienti enterprise instabili, previene hanging delle sessioni.
* `-r 0`: Zero retry. Riduce drasticamente il traffico UDP generato, minimizzando la footprint.
* `-Cc`: Non interrompere su errori. Continua il walk nonostante timeout parziali, massimizzando la raccolta dati.
* `-Oa`, `-Ob`, `-Os`: Formati output alternativi per l'automazione del parsing.

**Walk Parziale vs Walk Completo - Tecnica Pura:**

```bash
# Walk completo di tutto il tree (altamente rumoroso, non raccomandato)
snmpwalk -v2c -c public TARGET 1

# Walk limitato a MIB-2 (strategico, raccomandato)
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1

# Walk mirato su routing table (low noise)
snmpwalk -v2c -c public -Cr10 TARGET 1.3.6.1.2.1.4.21
```

**Impatto Operativo:** Il walk completo su `.1` interroga migliaia di OID, generando un picco di traffico immediatamente rilevabile. Il walk su MIB-2 (`1.3.6.1.2.1`) è più controllato e fornisce il 90% dei dati utili per il pivoting. L'opzione `-Cr10` limita le max-repetitions a 10, riducendo la dimensione dei pacchetti di risposta e migliorando l'OPSEC.

**Meccanismo GETNEXT e Implicazioni OPSEC:**
**snmpwalk** utilizza richieste SNMP **GETNEXT iterative**: ogni pacchetto richiede l'OID successivo a quello ricevuto. Questo crea pattern sequenziali facilmente rilevabili:

* **NDR Signature:** Sequenza ascendente di OID (es. `.1.3.6.1.2.1.1.1` → `.1.3.6.1.2.1.1.2` → `.1.3.6.1.2.1.1.3`)
* **Threshold Realistici:** >200 richieste GETNEXT in 60 secondi da singolo IP generano alert in SIEM enterprise.
* **Mitigazione:** Walk mirato su sotto-alberi specifici, introduzione di delay randomizzati tra le query.

## Fase 1 – Ricognizione & Enumeration con SNMPWALK

**Walk Mirato vs Walk Completo - Decision Tree:**

```
Ambiente monitorato (NDR attivo)?
    ├── SÌ → Walk mirato su OID critici
    │       ├── ipRouteTable (1.3.6.1.2.1.4.21)
    │       ├── ipNetToMediaTable (1.3.6.1.2.1.4.22)
    │       └── hrSWRunTable (1.3.6.1.2.1.25.4.2)
    └── NO → Walk completo MIB-2 (1.3.6.1.2.1)
```

**Walk Strategico per Estrazione Routing Table:**

```bash
snmpwalk -v2c -c public -On -t 3 -r 0 -Cr10 10.0.1.10 1.3.6.1.2.1.4.21 > routing_table.txt
```

**Output Critico da Analizzare:**

```
.1.3.6.1.2.1.4.21.1.1.10.0.1.0 = IpAddress: 10.0.1.0
.1.3.6.1.2.1.4.21.1.1.192.168.50.0 = IpAddress: 192.168.50.0
.1.3.6.1.2.1.4.21.1.7.192.168.50.0 = IpAddress: 10.0.1.254
```

**Interpretazione Operativa:** La subnet `192.168.50.0/24` è raggiungibile tramite gateway `10.0.1.254` - potenziale VLAN di management o backup non precedentemente mappata.

## Fase 2 – Initial Exploitation via SNMPWALK Output

**Parsing Offensivo dell'Output - Tecniche Concrete:**

```bash
# Estrazione hostname e correlazione AD
grep -i "STRING.*DC\|AD\|SRV\|FS\|SQL" mib2_walk.txt | awk -F'STRING: ' '{print $2}'
# Output: DC01.company.local - Domain Controller identificato

# Ricerca credential leakage in hrSWRunTable
snmpwalk -v2c -c public -On 10.0.1.20 1.3.6.1.2.1.25.4.2 | grep -i -E "pass|pwd|login|user" -A 1 -B 1
# Output: /usr/bin/backup --password Backup2024@DC01

# Estrazione interfacce di rete per IP secondari
snmpwalk -v2c -c public -On 10.0.1.10 1.3.6.1.2.1.4.20 | grep -i "ipaddress" | awk -F'IpAddress: ' '{print $2}'
```

**Correlazione Realistica con Active Directory:**

* **Naming Convention:** Hostname come `DC01`, `FS01`, `SQL-PROD-01` rivelano ruolo e criticità
* **SNMP su Domain Controller:** Configurazione legacy ad alto rischio. **snmpwalk** su DC può leakare:
  * Informazioni di sistema (uptime, servizi)
  * Processi attivi (potenzialmente con credenziali)
  * Configurazioni di rete interne
* **Prioritizzazione:** SNMP su DC → finding critico da escalation immediata

## Fase 3 – Post-Compromise & Privilege Escalation

**Analisi della hrSWRunTable per Escalation Path:**

```bash
# Estrazione completa processi con parsing avanzato
snmpwalk -v2c -c public -On 10.0.1.20 1.3.6.1.2.1.25.4.2 | \
awk -F' = STRING: ' '/hrSWRunPath/ {print "Path: "$2} /hrSWRunParameters/ && !/""/ {print "Args: "$2}'
```

**Output Critico Identificato:**

```
Path: /opt/scripts/backup.py
Args: --server db01 --user backup_admin --password s3cur3P@ss2024
```

**Impact Analysis:** Credenziali hardcoded in script di backup → potenziale accesso a server database.

## Fase 4 – Lateral Movement & Pivoting Basato su SNMPWALK

**Workflow di Pivoting Concrete:**

1. **Discovery:** **snmpwalk** rivela subnet `192.168.50.0/24` tramite `ipRouteTable`
2. **Accesso:** Compromissione host nella VLAN corrente (`10.0.1.0/24`)
3. **Enumeration Interna:** Esecuzione di **snmpwalk** mirato attraverso tunnel:

```bash
proxychains snmpwalk -v2c -c public -On -t 5 192.168.50.1 1.3.6.1.2.1.4.21
```

1. **Expansion:** Ripetizione del processo per ogni nuova subnet scoperta

**Identificazione VLAN di Management:**

```bash
# Estrazione descrizioni interfacce
snmpwalk -v2c -c public 10.0.1.10 1.3.6.1.2.1.2.2.1.2 | grep -i "management\|mgmt\|admin"
```

## Fase 5 – Detection & Hardening Enterprise-Grade

**Pattern di Detection Specifici per SNMPWALK:**

* **NDR Signature:** Sequenza di >100 pacchetti UDP/161 con OID ascending in \<2 minuti
* **SIEM Rule:** `source_ip` genera >200 eventi `snmp_get_next` in 60 secondi
* **Correlazione Metrica:** Numero OID interrogati (>300) + tempo totale walk (\<90s) + dimensione risposta (>500KB) = high confidence attack
* **Network Device Alert:** `%SNMP-4-THROTTLED` su Cisco (threshold superato)
* **Anomaly Detection:** Picco improvviso di traffico UDP/161 verso singolo target

**SNMPWALK su SNMPv3 (Complessità Aggiuntiva):**

```bash
snmpwalk -v3 -u snmp-user -l authPriv -a SHA -A AuthPass123 -x AES -X PrivPass123 TARGET 1.3.6.1.2.1
```

**Impatto Operativo:** SNMPv3 introduce autenticazione (authNoPriv) e cifratura (authPriv), aumentando esponenzialmente la complessità dell'attacco. In internal pentest, se SNMPv3 è configurato correttamente, il walk diventa impraticabile senza credenziali valide.

**Hardening Concrete per Mitigare SNMPWALK Exploitation:**

1. **SNMPv3 con AuthPriv:** Implementare SHA-256/AES-256, eliminare v2c
2. **View-Based Access Control:** Limitare gli OID accessibili per community
3. **Rate Limiting:** Configurare `snmp-server queue-length 50` e `snmp-server trap-timeout 30`
4. **ACL Strict:** Permettere connessioni SNMP solo da specifici IP di management
5. **Logging Granulare:** Abilitare `snmp-server enable traps snmp authentication`
6. **Disabilitare OID Pericolose:** Rimuovere l'accesso a `hrSWRunTable` e `ipNetToMediaTable`
7. **Monitoraggio Continuo:** Alert su qualsiasi walk che superi i 50 OID interrogati

## Errori Comuni Che Vedo Negli Assessment Reali

* **Walk Completo Non Contestualizzato:** Eseguire `snmpwalk` senza valutare l'ambiente, generando alert immediati
* **Ignorare l'OPSEC di GETNEXT:** Non introdurre delay tra le query, creando pattern facilmente rilevabili
* **Parsing Superficiale dell'Output:** Non cercare credential leakage in `hrSWRunParameters`
* **Non Correlare con AD:** Ignorare hostname che rivelano ruolo critico (DC, FS, SQL)
* **Threshold di Detection Ignorati:** Superare i 200 OID/minuto senza considerare le conseguenze
* **Walk su SNMPv3 Senza Valutazione:** Tentare brute force authPriv senza comprendere la complessità

## Mini Tabella 80/20 Finale

| Obiettivo              | Azione                     | Comando SNMPWALK                                            |
| :--------------------- | :------------------------- | :---------------------------------------------------------- |
| Walk Completo MIB-2    | Estrazione dati di base    | `snmpwalk -v2c -c public -On TARGET 1.3.6.1.2.1`            |
| Identificazione Subnet | Estrazione routing table   | `snmpwalk -v2c -c public -On -Cr10 TARGET 1.3.6.1.2.1.4.21` |
| Credential Leakage     | Estrazione processi attivi | `snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2`         |
| Host Discovery         | Estrazione ARP cache       | `snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.4.22`           |
| Interface Mapping      | Enumerazione interfacce    | `snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.2.2`            |

**snmpwalk** è il moltiplicatore di forza per il dominio della rete. Il nostro lab enterprise multi-step replica un ambiente dove un singolo comando **snmpwalk** su uno switch di management diventa il punto di partenza per il compromissione dell'intero dominio Active Directory.

Approfondisci le tecniche di enumerazione correlate in:

* [https://hackita.it/articoli/snmp](https://hackita.it/articoli/snmp)
* [https://hackita.it/articoli/nmap](https://hackita.it/articoli/nmap)
* [https://hackita.it/articoli/pivoting](https://hackita.it/articoli/pivoting)

Riferimenti tecnici ufficiali e documentazione:

* [https://www.net-snmp.org/docs/man/snmpwalk.html](https://www.net-snmp.org/docs/man/snmpwalk.html)
* [https://datatracker.ietf.org/doc/html/rfc3416](https://datatracker.ietf.org/doc/html/rfc3416)
* [https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/7281-snmp-best-practices.html](https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/7281-snmp-best-practices.html)

Se vuoi migliorare la postura di sicurezza della tua azienda o testare realisticamente queste tecniche in un contesto controllato:
[https://hackita.it/servizi](https://hackita.it/servizi)

Se vuoi supportare il progetto HackITA:
[https://hackita.it/supporta](https://hackita.it/supporta)
