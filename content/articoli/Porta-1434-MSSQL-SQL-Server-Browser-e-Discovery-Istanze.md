---
title: 'Porta 1434 MSSQL: SQL Server Browser e Discovery Istanze'
slug: porta-1434-mssql-monitor
description: 'Pentest MSSQL sulla porta 1434/UDP: enumerazione SQL Server Browser, named instance, versione, porte dinamiche e discovery delle istanze SQL in lab.'
image: /porta-1434-mssql-monitor.webp
draft: true
date: 2026-04-12T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - SQL Server Browser
  - MSSQL
  - UDP 1434
---

La porta 1434/UDP ospita il SQL Server Browser Service, il servizio di discovery che risponde alle query sulle istanze MSSQL installate su un host. Un singolo pacchetto UDP alla 1434 restituisce nome istanza, versione, porta TCP e pipe name di ogni istanza SQL — senza autenticazione. Queste informazioni alimentano direttamente l'attacco alla [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql): sapere che esiste un'istanza `SQLEXPRESS` sulla porta 49200 è il primo step per il credential attack.

**COSA C'È NELLA PORTA 1434?**

* La porta 1434/UDP è il SQL Browser — risponde senza autenticazione con nome istanza, versione e porta TCP di ogni SQL Server sull'host
* Un singolo pacchetto `0x02` rivela tutte le istanze — incluse quelle su porte non standard che un port scan potrebbe non trovare
* La versione esatta permette CVE matching; la porta TCP individuata diventa il target per brute force e `xp_cmdshell`

Porta 1434 MSSQL Monitor è il canale UDP del SQL Server Browser Service. La porta 1434 vulnerabilità principali sono l'information disclosure (istanze, versioni, porte senza auth), l'amplification per DDoS (il pacchetto di risposta è molto più grande della richiesta) e storicamente il worm SQL Slammer (CVE-2002-0649). L'enumerazione porta 1434 è il primo passo del MSSQL pentest: rivela istanze nascoste su porte non standard che altrimenti richiederebbero un full port scan.

## 1. Anatomia Tecnica della Porta 1434

Il SQL Browser Service ascolta sulla 1434/UDP e risponde a due tipi di query:

| Byte inviato | Query             | Risposta                                  |
| ------------ | ----------------- | ----------------------------------------- |
| `0x02`       | Tutte le istanze  | Nome, versione, porta TCP di ogni istanza |
| `0x03`       | Istanza specifica | Dettagli della singola istanza            |

Perché esiste: SQL Server supporta istanze multiple sullo stesso host. Solo l'istanza default usa la porta 1433 — le named instance ricevono porte dinamiche. Il Browser Service è la "rubrica" che mappa nomi a porte.

```
Misconfig: SQL Browser attivo su server con una sola istanza default (1433)
Impatto: information disclosure gratuita — versione esatta senza autenticazione
Come si verifica: nmap -sU -p 1434 --script ms-sql-info [target]
```

```
Misconfig: SQL Browser esposto su Internet
Impatto: discovery istanze + amplification DDoS (fattore ~8x)
Come si verifica: echo -ne '\x02' | nc -u -w 2 [target] 1434
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sU -sV -p 1434 --script ms-sql-info 10.10.10.15
```

**Output atteso:**

```
PORT     STATE SERVICE  VERSION
1434/udp open  ms-sql-m Microsoft SQL Server 2019 15.0.4375

| ms-sql-info:
|   10.10.10.15:
|     Instance: MSSQLSERVER
|       Version: Microsoft SQL Server 2019 (RTM-CU25)
|       Product: Microsoft SQL Server 2019
|       TCP port: 1433
|
|     Instance: SQLEXPRESS
|       Version: Microsoft SQL Server 2019 (RTM-CU25)
|       Product: Microsoft SQL Server Express
|       TCP port: 49200
|
|     Instance: DEVDB
|       Version: Microsoft SQL Server 2022 (RTM-CU10)
|_      TCP port: 49300
```

**Cosa ci dice questo output:** tre istanze SQL sullo stesso host. L'istanza default `MSSQLSERVER` è sulla 1433, ma `SQLEXPRESS` è sulla 49200 e `DEVDB` sulla 49300 — porte che un nmap standard (`-p 1-10000`) non avrebbe trovato. `SQLEXPRESS` è spesso configurata con credenziali deboli. `DEVDB` è un'istanza di sviluppo — probabilmente con meno restrizioni di sicurezza.

### Comando 2: Probe manuale con netcat

```bash
echo -ne '\x02' | nc -u -w 2 10.10.10.15 1434 | strings
```

**Output:**

```
ServerName;SQL01;InstanceName;MSSQLSERVER;IsClustered;No;Version;15.0.4375.4;tcp;1433;;
ServerName;SQL01;InstanceName;SQLEXPRESS;IsClustered;No;Version;15.0.4375.4;tcp;49200;;
ServerName;SQL01;InstanceName;DEVDB;IsClustered;No;Version;16.0.4100.1;tcp;49300;;
```

**Lettura dell'output:** formato chiave-valore con separatore `;`. Ogni istanza con il suo nome, stato cluster, versione esatta e porta TCP. La versione `15.0.4375.4` corrisponde a SQL Server 2019 CU25 — verifica su [sqlserverbuilds.blogspot.com](https://hackita.it/articoli/porta-1433-mssql) per CVE applicabili.

## 3. Enumerazione Avanzata

### Discovery su subnet

```bash
# Scan massivo per trovare tutti i SQL Server sulla subnet
nmap -sU -p 1434 --script ms-sql-info 10.10.10.0/24 --open
```

**Output:**

```
Nmap scan report for 10.10.10.15
1434/udp open  ms-sql-m
| ms-sql-info: MSSQLSERVER tcp:1433, SQLEXPRESS tcp:49200

Nmap scan report for 10.10.10.25
1434/udp open  ms-sql-m
| ms-sql-info: HRDB tcp:1433

Nmap scan report for 10.10.10.35
1434/udp open  ms-sql-m
| ms-sql-info: FINANCEDB tcp:1433, REPORTING tcp:49500
```

**Lettura dell'output:** tre host con SQL Server nella subnet — sei istanze totali. La 1434/UDP è il modo più rapido per scoprire tutti i SQL Server in una rete. Per l'[attacco a ciascuna istanza](https://hackita.it/articoli/porta-1433-mssql), usa le porte TCP scoperte.

### Metasploit UDP sweep

```bash
msfconsole -q
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS 10.10.10.0/24
run
```

**Output:**

```
[*] SQL Server information for 10.10.10.15:
[+]    ServerName = SQL01
[+]    InstanceName = MSSQLSERVER
[+]    Version = 15.0.4375.4
[+]    tcp = 1433
```

## 4. Tecniche Offensive

**Brute force mirato sulle istanze scoperte**

Contesto: il Browser ha rivelato tre istanze con le loro porte. Attacca ciascuna.

```bash
# Istanza default
crackmapexec mssql 10.10.10.15 -p 1433 -u sa -p passwords.txt

# SQLEXPRESS (spesso con sa:sa o sa vuota)
crackmapexec mssql 10.10.10.15 -p 49200 -u sa -p '' 
crackmapexec mssql 10.10.10.15 -p 49200 -u sa -p 'sa'

# DEVDB (istanza dev — credenziali deboli probabili)
crackmapexec mssql 10.10.10.15 -p 49300 -u sa -p 'Password1'
crackmapexec mssql 10.10.10.15 -p 49300 -u sa -p 'dev'
```

**Cosa fai dopo:** SQLEXPRESS e istanze dev sono i target più probabili per credenziali deboli. Con accesso sysadmin su qualsiasi istanza: [xp\_cmdshell per RCE](https://hackita.it/articoli/porta-1433-mssql).

**CVE matching con versione esatta**

```
Versione trovata: 15.0.4375.4 (SQL Server 2019 CU25)
→ Verifica CVE per questa build specifica
→ Se non è l'ultimo CU, potrebbe essere vulnerabile a CVE recenti
```

Le CVE SQL Server più rilevanti:

* **CVE-2024-37334**: RCE (CVSS 8.8) — OLE DB driver
* **CVE-2024-37333**: EoP — SQL Server Agent
* **CVE-2023-36728**: DoS — versioni pre-CU20

**Amplification DDoS (documentazione, non uso)**

La risposta del Browser (200-400 byte) è 8-10x il pacchetto di richiesta (1 byte: `0x02`). Storicamente usato per amplificazione [DDoS](https://hackita.it/articoli/ddos). È un finding di severità bassa ma documentabile.

## 5. Scenari Pratici

### Scenario 1: Discovery istanze nascoste

**Situazione:** il port scan TCP ha trovato solo la 1433. Il Browser rivela altre istanze.

```bash
echo -ne '\x02' | nc -u -w 2 10.10.10.15 1434 | strings
# Scopri SQLEXPRESS sulla 49200 e DEVDB sulla 49300
crackmapexec mssql 10.10.10.15 -p 49200 -u sa -p 'sa'
```

**Tempo stimato:** 2-5 minuti

### Scenario 2: Subnet enumeration per SQL Server

**Situazione:** assessment interno. Devi trovare tutti i SQL Server nella rete.

```bash
nmap -sU -p 1434 --script ms-sql-info --open 10.10.10.0/24 172.16.0.0/24
```

**Tempo stimato:** 5-15 minuti per subnet (UDP scan è lento)

### Scenario 3: Browser esposto su Internet

**Situazione:** assessment perimetrale. 1434/UDP aperta su IP pubblico.

```bash
echo -ne '\x02' | nc -u -w 2 [target_ip] 1434 | strings
# Se risponde: hai versione, istanze, porte — finding di information disclosure
# Attacca la porta TCP rivelata direttamente
```

**Tempo stimato:** 1-2 minuti

## 6. Attack Chain

| Fase        | Tool        | Comando                              | Risultato          |
| ----------- | ----------- | ------------------------------------ | ------------------ |
| Discovery   | nmap/nc     | `echo '\x02' \| nc -u [target] 1434` | Istanze + porte    |
| Version     | parsing     | Versione → CVE matching              | Vulnerabilità note |
| Brute Force | cme         | Per ogni porta TCP scoperta          | Credenziali        |
| Exploit     | mssqlclient | xp\_cmdshell sulla porta trovata     | RCE                |

## 7. Detection & Evasion

### Blue Team

* **Firewall**: 1434/UDP aperta = information disclosure passiva
* **IDS**: query 0x02 ripetute = enumeration
* **Log**: il SQL Browser Service non logga le query di default

### Evasion

La query al Browser è un singolo pacchetto UDP — quasi invisibile. Non genera log sul server. È il probe più silenzioso per trovare SQL Server.

## 8. Cheat Sheet Finale

| Azione          | Comando                                                                 |
| --------------- | ----------------------------------------------------------------------- |
| Scan            | `nmap -sU -p 1434 --script ms-sql-info [target]`                        |
| Probe manuale   | `echo -ne '\x02' \| nc -u -w 2 [target] 1434 \| strings`                |
| Subnet sweep    | `nmap -sU -p 1434 --script ms-sql-info --open [subnet]`                 |
| Metasploit      | `use auxiliary/scanner/mssql/mssql_ping`                                |
| Attacca istanza | `crackmapexec mssql [target] -p [porta_trovata] -u sa -p passwords.txt` |
| Connect istanza | `mssqlclient.py sa:pass@[target] -port [porta_trovata]`                 |

### Perché Porta 1434 è rilevante nel 2026

È il modo più rapido e silenzioso per trovare tutti i SQL Server in una rete. Rivela istanze su porte non standard che un port scan TCP non troverebbe. La versione esatta permette CVE matching preciso. SQLEXPRESS e istanze dev trovate via Browser sono spesso i target con credenziali più deboli.

### Hardening

* Disabilita SQL Browser Service se non necessario (una sola istanza sulla 1433)
* Se necessario: firewall 1434/UDP solo verso client autorizzati
* Non esporre mai 1434/UDP su Internet

***

Riferimento: MS-SQLR, SQL Slammer CVE-2002-0649. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
