---
title: 'FTP Bounce Attack: cos’è, come funziona e come prevenirlo'
slug: ftp-bounce
description: >-
  FTP Bounce Attack: cos’è, come funziona il comando PORT, perché può permettere
  il port scanning indiretto e come rilevarlo e prevenirlo.
image: /ftp-bounce-attack.webp
draft: false
date: 2026-09-15T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - ftp-bounce
  - nmap
  - port-scanning
  - network-reconnaissance
  - firewall-bypass
---

# FTP Bounce Attack: Cos'è, Come Funziona e Come Prevenirlo

FTP bounce è una tecnica che sfrutta un server FTP configurato in modo insicuro per indurlo a effettuare connessioni verso un altro host. In questo modo il server FTP può essere usato come intermediario per verificare la raggiungibilità di porte e sistemi che il client non potrebbe raggiungere direttamente — per esempio perché bloccati da un firewall.

È una tecnica storica (anni '90), rara sui server moderni correttamente configurati, ma ancora rilevante durante assessment autorizzati su sistemi legacy che espongono FTP.

## Cos'è il comando PORT e perché è centrale

FTP usa due connessioni separate:

1. **Control connection** (porta 21): il client manda comandi al server (`LIST`, `RETR`, `STOR`, ecc.)
2. **Data connection** (porta variabile): dati e listing di directory passano da qui

In modalità attiva (PORT mode), è il client a dire al server dove aprire la connessione dati, con il comando:

```
PORT <IP_bytes>,<port_bytes>
```

Esempio:

```bash
ftp> PORT 192,168,1,100,13,80
```

Gli ultimi due numeri codificano la porta: `primo_byte × 256 + secondo_byte`. Nell'esempio: `(13 × 256) + 80 = 3408`. Il comando dice al server: "apri una connessione verso 192.168.1.100:3408 e mandami lì i dati".

Il comando `PORT` permette quindi al client di indicare al server l'indirizzo e la porta verso cui instaurare la connessione dati. Un server configurato in modo insicuro può accettare una destinazione diversa dall'host che ha aperto la connessione di controllo — ed è proprio questa condizione a creare la vulnerabilità alla base del FTP bounce.

## Come funziona l'attacco

Se il server FTP non verifica che l'IP indicato nel comando `PORT` corrisponda al client connesso, un attaccante può:

1. Connettersi a un server FTP vulnerabile (es. `10.10.20.50`)
2. Inviare `PORT` verso un terzo host (es. `10.10.20.100:80`)
3. Il server FTP tenta una connessione TCP verso quella destinazione
4. In base a successo o fallimento della connessione, il server FTP restituisce un messaggio diverso

Il risultato è un port scan indiretto: il target vede la connessione arrivare dal server FTP, non dall'attaccante. Questo però non equivale a essere invisibili. Il target vede la connessione provenire dal server FTP, mentre l'origine reale della richiesta rimane separata a livello della connessione verso il target — ma l'attività può essere comunque correlata e registrata su log FTP, firewall, IDS/IPS e NetFlow. Non è un attacco anonimo, è un attacco con un'origine diversa da tracciare.

## FTP Bounce è ancora una vulnerabilità reale?

Nella pratica quotidiana, raramente. I server FTP moderni (vsftpd, ProFTPD, Pure-FTPd aggiornati) verificano che l'indirizzo nel comando `PORT` corrisponda al client che ha aperto la connessione di controllo, e rifiutano la richiesta in caso contrario. FTP stesso è largamente sostituito da SSH/SFTP.

Resta rilevante in due casi concreti: assessment autorizzati su infrastrutture legacy (dispositivi embedded, sistemi non aggiornati da anni) e come promemoria didattico su cosa succede quando un protocollo si fida ciecamente dell'input del client.

## Requisiti per un FTP Bounce Attack

1. Server FTP vulnerabile accessibile, spesso via accesso anonimo
2. Server non patchato: non verifica l'origine dei comandi `PORT`
3. Un target raggiungibile dal server FTP (stesso segmento di rete o routing interno), anche se non raggiungibile direttamente dall'attaccante

## Come verificare se un server FTP è vulnerabile

Il modo affidabile per verificare la vulnerabilità è uno strumento di assessment dedicato, non l'osservazione manuale dei codici di risposta FTP — il comportamento esatto varia in base a server, modalità di trasferimento e destinazione.

### Con Nmap NSE (metodo consigliato)

```bash
nmap --script ftp-bounce --script-args ftp-bounce.username=anonymous,ftp-bounce.password=anonymous -p 21 <FTP_SERVER_IP>
```

* `--script ftp-bounce`: esegue lo script che testa la vulnerabilità
* `--script-args`: passa username/password per il login FTP
* `-p 21`: limita la scansione alla porta FTP standard

Output se vulnerabile:

```
| ftp-bounce: 
|_  bounce working! -- I can use the server to bounce scans off another host
```

### Verifica manuale indicativa (via telnet)

Può dare un'indicazione preliminare, ma non sostituisce il test con Nmap:

```bash
telnet <FTP_SERVER_IP> 21
```

```
USER anonymous
PASS anything@example.com
PORT 192,168,1,100,0,80
LIST
```

Una risposta `150`/`226` è un'indicazione di comportamento permissivo, non una conferma definitiva. Un errore `500 Illegal PORT command` indica invece un server che verifica la corrispondenza dell'indirizzo, e quindi non è vulnerabile a questa tecnica.

## Scansione con Nmap FTP Bounce (`-b`)

Confermata la vulnerabilità, si può usare Nmap per scansionare attraverso il bounce server:

```bash
nmap -v -Pn -p 22,80,443,3306 -b anonymous:ftp@10.10.20.50:21 10.10.20.100
```

* `-Pn`: salta il ping (spesso bloccato da firewall verso il target interno)
* `-p 22,80,443,3306`: porte specifiche invece di una scansione completa
* `-b anonymous:ftp@10.10.20.50:21`: credenziali e server FTP usati come bounce
* `10.10.20.100`: target da scansionare

Anche una subnet intera:

```bash
nmap -v -Pn -p 80,443 -b anonymous:ftp@192.168.1.50:21 192.168.50.0/24
```

La scansione tramite bounce è più lenta di una scansione diretta, perché ogni connessione passa attraverso il server FTP: è un trade-off tra visibilità ridotta e velocità.

## Metasploit: scanner automatizzato

```bash
msfconsole -q
use auxiliary/scanner/ftp/ftp_bounce
set RHOSTS <FTP_SERVER_IP>
set RPORT 21
set FTP_USERNAME anonymous
set FTP_PASSWORD anything
run
```

Il modulo si connette al server, testa automaticamente un set di porte comuni e riporta quali risultano aperte sul target.

## Scenario tipico

```
[Attaccante] --firewall blocca scansioni dirette--> [Rete interna]
                                                        |
                                              [Server FTP vulnerabile]
                                                        |
                                              [Target interno non raggiungibile direttamente]
```

L'attaccante non può scansionare il target interno direttamente, ma il server FTP interno è raggiungibile (per il trasferimento file) e può essere usato come intermediario per raggiungere segmenti altrimenti bloccati dal firewall.

Un caso concreto tuttora osservabile in assessment su infrastrutture datate: dispositivi embedded (stampanti/multifunzione con servizio FTP integrato) rimasti non aggiornati per anni.

## FTP Bounce vs Proxy vs Pivot

Tre concetti spesso confusi da chi inizia:

* **FTP bounce**: il server FTP effettua una connessione verso una destinazione indicata dal client, sfruttando il comando `PORT`. È specifico del protocollo FTP.
* **Proxy**: inoltra traffico tra client e destinazione secondo un modello di proxying esplicito (es. SOCKS, HTTP proxy).
* **Pivot**: usa un sistema compromesso o comunque accessibile come punto intermedio per raggiungere una rete altrimenti non raggiungibile direttamente. Approfondimento: [pivoting](https://hackita.it/articoli/pivoting/).

FTP bounce non equivale automaticamente ad avere accesso alla rete interna: la tecnica permette di sfruttare il server FTP per effettuare determinate connessioni verso altri host, ma cosa sia effettivamente raggiungibile dipende da routing, firewall e configurazione del server FTP stesso.

## Come rilevare un FTP Bounce Attack

Dal lato difensivo, i segnali da monitorare sono:

* Comandi `PORT` verso indirizzi IP esterni al client che ha aperto la connessione di controllo
* Connessioni originate dal server FTP verso host o porte insolite rispetto al traffico normale
* Correlazione tra log FTP e dati firewall/NetFlow sulla stessa finestra temporale
* Tentativi ripetuti verso molte destinazioni o molte porte in sequenza (pattern da scan)
* Alert IDS/IPS su comandi `PORT` anomali

Esempio di regola indicativa (pseudocodice):

```
alert ftp any any -> any 21 (msg:"FTP PORT command verso IP esterno"; content:"PORT"; sid:1000001;)
```

## Come prevenire FTP Bounce

* Aggiornare il server FTP a una versione recente: i server moderni verificano che l'indirizzo nel comando `PORT` corrisponda al client della connessione di controllo
* Su vsftpd, disabilitare esplicitamente la modalità PORT (`port_enable=NO`) se non serve
* Segmentazione di rete interna: limitare cosa un server FTP compromesso può effettivamente raggiungere
* Monitoraggio attivo dei log FTP per comandi `PORT` verso indirizzi non appartenenti alla rete interna attesa

## FAQ

**FTP Bounce è invisibile?**
No. Nasconde l'origine della connessione verso il target agli occhi del target stesso, ma l'attività resta tracciabile tramite log FTP, firewall e IDS/IPS.

**Che differenza c'è tra FTP bounce e SSH dynamic forwarding?**
SSH forwarding richiede credenziali SSH valide sull'host intermedio. FTP bounce richiede solo un server FTP vulnerabile, spesso accessibile in anonimo.

**Posso usare FTP bounce se il firewall blocca la porta 21?**
No. Serve poter raggiungere il server FTP sulla sua porta di controllo: se quella è bloccata, la tecnica non è applicabile.

**Cosa serve se il server FTP richiede autenticazione?**
Servono credenziali valide da passare al comando (`-b username:password@host`). Senza credenziali, la tecnica non è utilizzabile su quel server.

**È legale fare FTP bounce?**
È una forma di port scanning, quindi rientra tra le attività che richiedono un'autorizzazione esplicita (es. contratto di penetration test che la includa). Senza autorizzazione è un accesso non autorizzato.

## Risorse esterne

* [Nmap – FTP Bounce Scan](https://nmap.org/book/scan-methods-ftp-bounce-scan.html): documentazione ufficiale sul flag `-b`
* [RFC 2577 – FTP Security Considerations](https://datatracker.ietf.org/doc/html/rfc2577): RFC che standardizza le mitigazioni al bounce attack
* [SecForce – FTP Bounce Network Scanning](https://www.secforce.com/blog/ftp-bounce-network-scan/): caso reale su dispositivo embedded vulnerabile
* [The Hacker Recipes – FTP Bounce](https://www.thehacker.recipes/infra/protocols/ftp): guida operativa con comandi e NSE script
* [Hackviser – FTP Pentesting Guide](https://hackviser.com/tactics/pentesting/services/ftp): assessment FTP completo, incluso bounce

## Conclusioni

FTP bounce è un attacco vecchio, oggi raro, ma utile da conoscere per due motivi: mostra concretamente cosa succede quando un protocollo si fida senza verifica dell'input del client, e resta un vettore reale su sistemi legacy incontrati durante assessment autorizzati. Se in un test trovi un server FTP aperto, verificarne la vulnerabilità con Nmap costa pochi secondi.
