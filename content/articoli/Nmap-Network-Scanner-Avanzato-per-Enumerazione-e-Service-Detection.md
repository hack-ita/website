---
title: 'Nmap per Pentesting: Port Scanning, Network Recon e NSE'
slug: nmap
description: 'Nmap per penetration testing e network recon: comandi, host discovery, port scanning TCP/UDP, service detection, OS fingerprinting, NSE ed enumeration.'
image: /nmap-pentesting-port-scanning-network-recon-nse.webp
draft: false
date: 2026-02-20T00:00:00.000Z
lastmod: 2026-09-15T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - Port Scanning
  - Nmap
  - Network Enumeration
  - NSE
  - Network Reconnaissance
---

# Nmap: Scansione Porte, Enumeration e NSE

Nmap è uno dei principali strumenti open source nel pentest per **network discovery, port scanning e security auditing**. Viene utilizzato per identificare host raggiungibili,enumerare porte esposte, servizi, versioni software, sistemi operativi e informazioni aggiuntive tramite il **Nmap Scripting Engine (NSE)**.

Nel penetration testing, però, Nmap non dovrebbe essere considerato semplicemente uno scanner di porte. Il suo valore sta soprattutto nella capacità di trasformare uno scan superficie di rete sconosciuta in una sequenza di informazioni utili per le fasi successive:

```text
Target
  ↓
Host Discovery
  ↓
Port Scanning
  ↓
Service / Version Detection
  ↓
OS Detection
  ↓
NSE
  ↓
Interpretazione
  ↓
Enumeration mirata
  ↓
Validation
```

Questa guida è un tutorial pratico a Nmap che copre installazione, host discovery, TCP e UDP scanning, service detection, OS fingerprinting, NSE, enumeration per servizio, output, performance, troubleshooting, tecniche di evasion e automazione con **myNmap**. Un Nmap scan tipico parte proprio dall'host discovery e prosegue con port scanning, service detection, OS fingerprinting e NSE, nell'ordine mostrato sopra.

> Esegui scansioni esclusivamente su sistemi, reti e infrastrutture per cui disponi di autorizzazione.

## Comandi Nmap Essenziali: Quale Usare e Quando

| Comando                | Cosa fa                                 | Quando usarlo                                                       |
| ---------------------- | --------------------------------------- | ------------------------------------------------------------------- |
| `nmap target`          | Scan base sulle porte più comuni        | Prima ricognizione veloce                                           |
| `nmap -p- target`      | Tutte le 65535 porte TCP                | Enumerazione completa, non perdere servizi su porte non standard    |
| `nmap -sV target`      | Rileva servizio e versione              | Dopo aver trovato porte aperte, prima di scegliere il prossimo tool |
| `nmap -sC target`      | Script NSE della categoria default      | Enumerazione iniziale automatica                                    |
| `nmap -sS target`      | SYN scan (richiede privilegi)           | Scansione TCP standard con root/sudo disponibile                    |
| `nmap -sT target`      | Connect scan                            | Senza privilegi raw-packet                                          |
| `nmap -sU target`      | UDP scan                                | Servizi UDP (DNS, SNMP, NTP...)                                     |
| `nmap -Pn target`      | Salta l'host discovery                  | L'host sembra down ma sospetti sia filtrato l'ICMP                  |
| `nmap -O target`       | OS fingerprinting                       | Serve stimare il sistema operativo remoto                           |
| `nmap -A target`       | OS + version + NSE default + traceroute | Enumerazione approfondita in un solo comando                        |
| `nmap -oA scan target` | Salva in tutti i formati principali     | Sempre, quando i risultati vanno riusati o riportati                |

## Cos'è Nmap e a cosa serve

Nmap può essere utilizzato per diverse fasi della reconnaissance:

| Funzione          | Obiettivo                                                   |
| ----------------- | ----------------------------------------------------------- |
| Host Discovery    | Identificare host raggiungibili                             |
| Port Scanning     | Individuare porte TCP e UDP accessibili                     |
| Service Detection | Identificare il servizio presente su una porta              |
| Version Detection | Determinare prodotto e versione quando possibile            |
| OS Detection      | Stimare il sistema operativo remoto                         |
| NSE               | Automatizzare discovery, enumeration e security checks      |
| Output            | Salvare e processare i risultati                            |
| Timing            | Controllare velocità e carico della scansione               |
| Scan Evasion      | Modificare caratteristiche delle probe in scenari specifici |

Un risultato Nmap non è necessariamente il finding finale. Spesso è il punto di partenza di un workflow — la sezione [Porte Principali](#porte-principali-cosa-fare-dopo) più sotto è la mappa completa porta→prossimo tool.

## Installazione Nmap e Setup

La versione di Nmap installata può essere verificata con `nmap --version`. Per scaricare la release corrente è consigliabile utilizzare la pagina ufficiale di download, evitando di hardcodare una versione specifica nel contenuto della guida.

### Nmap su Linux — Debian e Ubuntu

```bash
sudo apt update
sudo apt install nmap -y
nmap --version
```

La versione presente nel repository della distribuzione può essere diversa da quella distribuita più recentemente dal progetto Nmap.

### Nmap su Kali Linux

```bash
nmap --version
sudo apt update && sudo apt install --only-upgrade nmap
```

### Nmap su Windows

Nmap dispone di un installer ufficiale per Windows e utilizza Npcap per diverse funzionalità di packet capture e packet manipulation.

```powershell
nmap --version
nmap -sV 192.168.1.100
```

### Nmap su macOS

```bash
nmap --version
```

### Compilazione da sorgente

```bash
tar xvf nmap-<version>.tar.bz2
cd nmap-<version>
./configure
make
sudo make install
```

Tarball delle release: [nmap.org/download.html](https://nmap.org/download.html)

### Privilegi necessari

Le tecniche che inviano e ricevono raw packet, come la SYN scan, richiedono normalmente privilegi appropriati su Linux e Unix. La TCP connect scan può invece essere eseguita senza privilegi raw-packet equivalenti.

```bash
sudo nmap -sS target   # richiede privilegi
nmap -sT target        # alternativa senza raw packet
```

## Come funziona una scansione Nmap

```text
1. Host Discovery
2. Port Scanning
3. Service Detection
4. Version Detection
5. OS Detection
6. NSE
7. Interpretation
8. Targeted Enumeration
```

La sequenza può essere ridotta o ampliata in base all'obiettivo — ogni fase risponde a una domanda specifica: quali host sono raggiungibili, quali porte rispondono, quale servizio le usa, quale versione, quale OS, cosa aggiunge NSE, e infine quale tool specifico usare dopo.

## Sintassi Nmap

```bash
nmap [options] target
```

```bash
nmap -sV -p 22,80,443 192.168.1.100
```

`-sV` abilita la service/version detection, `-p` seleziona le porte, `192.168.1.100` è il target.

## Parametri Nmap fondamentali

| Opzione     | Funzione                                                  | Esempio                    |
| ----------- | --------------------------------------------------------- | -------------------------- |
| `-sS`       | TCP SYN scan                                              | `sudo nmap -sS target`     |
| `-sT`       | TCP connect scan                                          | `nmap -sT target`          |
| `-sU`       | UDP scan                                                  | `sudo nmap -sU target`     |
| `-sV`       | Service e version detection                               | `nmap -sV target`          |
| `-O`        | OS detection                                              | `sudo nmap -O target`      |
| `-p`        | Specifica le porte                                        | `nmap -p 22,80,443 target` |
| `-p-`       | Scansiona le porte TCP 1–65535                            | `nmap -p- target`          |
| `-sC`       | Esegue gli script NSE della categoria `default`           | `nmap -sC target`          |
| `-A`        | OS detection, version detection, default NSE e traceroute | `sudo nmap -A target`      |
| `-Pn`       | Salta l'host discovery                                    | `nmap -Pn target`          |
| `-n`        | Disabilita la risoluzione DNS                             | `nmap -n target`           |
| `-sn`       | Host discovery senza port scan                            | `nmap -sn target`          |
| `-sL`       | Elenca i target senza eseguire il port scan               | `nmap -sL 192.168.1.0/24`  |
| `-T0`–`-T5` | Timing template                                           | `nmap -T4 target`          |
| `-oA`       | Salva i principali formati di output                      | `nmap -oA scan target`     |

## Uso base di Nmap

```bash
nmap 192.168.1.100          # singolo host
nmap 192.168.1.1-50         # range
nmap 192.168.1.0/24         # subnet
nmap -iL targets.txt        # da file
nmap -sL 192.168.1.0/24     # elenca senza scansionare
```

```text
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  open   https
```

`-sL` è utile quando vuoi verificare quali indirizzi appartengono a un range e come vengono risolti i nomi, senza eseguire il normale port scan.

## Host Discovery

```bash
nmap -sn 192.168.1.0/24              # ping scan
sudo nmap -sn -PR 192.168.1.0/24     # ARP discovery, efficace in LAN
sudo nmap -sn -PE -PS443 192.168.1.0/24   # probe combinate ICMP+TCP
```

### `-Pn`: Skip Host Discovery

```bash
nmap -Pn target
```

Nmap salta la fase di host discovery e tratta il target come attivo. `-Pn` non è un bypass universale dei firewall: significa che Nmap non si basa sulla precedente fase di discovery per decidere se continuare la scansione. Utile quando ICMP o altri probe di discovery vengono filtrati, ma il target espone comunque servizi raggiungibili.

```bash
nmap -n target   # disabilita risoluzione DNS, riduce traffico e accelera alcuni workflow
```

## Nmap Port Scanning: Scansione delle Porte

```bash
sudo nmap -sS target       # SYN scan, richiede privilegi raw-packet
nmap -sT target            # connect scan, senza privilegi
sudo nmap -sU target       # UDP, più lento e con semantica di risposta diversa
nmap -p 22,80,443 target   # porte specifiche
nmap -p 1-1024 target      # range
nmap -p- target            # tutte le porte TCP
nmap --top-ports 100 target
nmap -F target
```

Un workflow efficace è separare la scoperta delle porte dalla successiva enumeration:

```bash
nmap -p- target
nmap -sC -sV -p 22,80,443,445 target
```

### Altri Tipi di Scan TCP: ACK, FIN, Null, Xmas

Oltre a SYN/Connect/UDP, Nmap supporta scan meno usati ma utili in scenari specifici:

```bash
sudo nmap -sA target   # ACK scan
sudo nmap -sF target   # FIN scan
sudo nmap -sN target   # Null scan (nessun flag)
sudo nmap -sX target   # Xmas scan (FIN+PSH+URG)
```

`-sA` non distingue open da closed: dice solo se una porta è `unfiltered` o `filtered`, utile per mappare le regole di un firewall stateless senza determinare quali porte sono realmente in ascolto.

`-sF`, `-sN` e `-sX` sfruttano il comportamento previsto da RFC 793 (porta closed risponde RST, porta open non risponde) per passare inosservati ad alcuni filtri stateless. **Non sono affidabili contro Windows** e molti altri stack TCP moderni, che non seguono quel comportamento e mostrano tutte le porte come closed indipendentemente dallo stato reale — utili soprattutto contro target Unix-like con firewall semplici, non come tecnica primaria.

## Stati delle porte Nmap

Gli stati riconosciuti da Nmap descrivono **come il port scanner vede una porta dal punto di osservazione corrente e con il tipo di scansione utilizzato**, non una proprietà assoluta della porta stessa.

| Stato              | Significato                                                                                           |
| ------------------ | ----------------------------------------------------------------------------------------------------- |
| `open`             | Un'applicazione sta accettando connessioni TCP, datagrammi UDP o associazioni SCTP                    |
| `closed`           | La porta è raggiungibile ma nessuna applicazione sta ascoltando                                       |
| `filtered`         | Un filtro impedisce a Nmap di determinare se la porta è open o closed                                 |
| `unfiltered`       | La porta risponde ai probe, ma Nmap non riesce a stabilire se sia open o closed con quel tipo di scan |
| `open\|filtered`   | Nmap non riesce a distinguere tra open e filtered                                                     |
| `closed\|filtered` | Nmap non riesce a distinguere tra closed e filtered in determinate condizioni                         |

Una porta `open` non significa automaticamente "vulnerabile". Significa che Nmap ha osservato un servizio raggiungibile e che esiste una superficie da identificare ed eventualmente enumerare.

## Nmap Service e Version Detection

```bash
nmap -sV target
```

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.x
80/tcp   open  http    Apache httpd
443/tcp  open  https   nginx
445/tcp  open  microsoft-ds
```

```text
Port → Protocol → Service → Product → Version
```

```bash
nmap -sV --version-intensity 9 target
```

`--version-intensity` accetta valori da 0 a 9; il default con `-sV` è 7. Valori più alti provano più probe e possono identificare servizi su porte non standard o configurazioni insolite, ma aumentano il tempo della scansione — non è garanzia automatica di un risultato migliore in ogni ambiente.

Un risultato come `Apache httpd 2.4.x` non significa automaticamente che Apache sia vulnerabile: è un elemento di reconnaissance da correlare a documentazione del vendor e advisory, poi validare.

## Nmap OS Detection e OS Fingerprinting

```bash
sudo nmap -O target
sudo nmap -O -sV target   # combinazione comune
```

La precisione dipende dalle risposte ricevute, dalla qualità del fingerprint e dalla presenza di firewall o middlebox che alterano le probe.

## Aggressive Scan

```bash
sudo nmap -A target
```

`-A` abilita OS detection, version detection, default NSE scripts e traceroute insieme. Non è semplicemente una modalità "più potente": quando vuoi controllare con precisione ciò che viene eseguito, è spesso preferibile scegliere esplicitamente le funzionalità con `nmap -sC -sV target`.

## Come leggere l'output di Nmap

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.x
80/tcp   open  http    Apache httpd
443/tcp  open  https   nginx
445/tcp  open  microsoft-ds
```

```text
22 → SSH enumeration
80 → HTTP enumeration
443 → HTTPS enumeration
445 → SMB enumeration
```

## Porte Principali: Cosa Fare Dopo

Questa è la mappa porta → prossimo strumento che uso io stesso durante un assessment. Non esaustiva, ma copre la maggior parte dei casi reali:

| Porta/e   | Servizio   | Comando Nmap iniziale                                       | Prossimo passo                                                                                                                                                                                                                                                  |
| --------- | ---------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 21        | FTP        | `nmap -p21 -sV --script ftp-anon target`                    | [Porta 21 FTP](https://hackita.it/articoli/porta-21-ftp/)                                                                                                                                                                                                       |
| 22        | SSH        | `nmap -p22 -sV --script ssh-auth-methods target`            | [SSH](https://hackita.it/articoli/ssh/)                                                                                                                                                                                                                         |
| 25        | SMTP       | `nmap -p25 -sV --script smtp-commands target`               | [Porta 25 SMTP](https://hackita.it/articoli/porta-25-smtp/)                                                                                                                                                                                                     |
| 53        | DNS        | `nmap -p53 --script dns-zone-transfer target`               | [DNS](https://hackita.it/articoli/dns/)                                                                                                                                                                                                                         |
| 80/443    | HTTP/HTTPS | `nmap -p80,443 -sV --script http-title,http-headers target` | [Burp Suite](https://hackita.it/articoli/burp-suite/), [ffuf](https://hackita.it/articoli/ffuf/), [Gobuster](https://hackita.it/articoli/gobuster/)                                                                                                             |
| 88        | Kerberos   | `nmap -p88 -sV target`                                      | [Kerberos](https://hackita.it/articoli/kerberos/), [Kerberoasting](https://hackita.it/articoli/kerberoasting/), [AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting/)                                                                                 |
| 135/445   | RPC/SMB    | `nmap -p135,445 --script smb-enum-shares target`            | [SMB](https://hackita.it/articoli/smb/), [smbclient](https://hackita.it/articoli/smbclient/), [rpcclient](https://hackita.it/articoli/rpcclient/), [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/), [NetExec](https://hackita.it/articoli/netexec/) |
| 389/636   | LDAP/LDAPS | `nmap -p389,636 --script ldap-rootdse target`               | [Porta 389 LDAP](https://hackita.it/articoli/porta-389-ldap/), [ldapsearch](https://hackita.it/articoli/ldapsearch/)                                                                                                                                            |
| 1433      | MSSQL      | `nmap -p1433 --script ms-sql-info target`                   | [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)                                                                                                                                                                                               |
| 3306      | MySQL      | `nmap -p3306 --script mysql-info target`                    | [Porta 3306 MySQL](https://hackita.it/articoli/porta-3306-mysql/)                                                                                                                                                                                               |
| 3389      | RDP        | `nmap -p3389 -sV target`                                    | [Porta 3389 RDP](https://hackita.it/articoli/porta-3389-rdp/)                                                                                                                                                                                                   |
| 5985/5986 | WinRM      | `nmap -p5985 -sV target`                                    | [Porta 5985 WinRM](https://hackita.it/articoli/porta-5985-winrm/), [Evil-WinRM](https://hackita.it/articoli/evilwinrm/)                                                                                                                                         |

## Nmap NSE: lo Scripting Engine

Il **Nmap Scripting Engine (NSE)** estende Nmap tramite script Lua per automatizzare attività di discovery, enumeration, service/version detection, vulnerability detection e, in alcuni casi, exploitation.

```bash
ls /usr/share/nmap/scripts/            # script installati localmente
sudo nmap --script-updatedb            # aggiorna il database locale
ls /usr/share/nmap/scripts/ | grep -i smb
nmap --script-help smb-enum-shares
```

```bash
nmap -sC target          # script della categoria default
nmap -sC -sV target      # combinazione comune
```

### Categorie NSE

| Categoria   | Funzione                                     |
| ----------- | -------------------------------------------- |
| `auth`      | Attività relative all'autenticazione         |
| `broadcast` | Discovery tramite broadcast                  |
| `brute`     | Credential guessing                          |
| `default`   | Script inclusi nella categoria predefinita   |
| `discovery` | Raccolta di informazioni                     |
| `dos`       | Test di denial of service                    |
| `exploit`   | Script di exploitation                       |
| `external`  | Interazione con servizi esterni              |
| `fuzzer`    | Fuzzing                                      |
| `info`      | Informazioni aggiuntive                      |
| `intrusive` | Script potenzialmente impattanti             |
| `malware`   | Rilevamento malware                          |
| `safe`      | Script classificati come generalmente sicuri |
| `version`   | Version detection                            |
| `vuln`      | Vulnerability detection                      |

Gli script NSE non sono sandboxati. Prima di eseguire una categoria ampia o uno script sconosciuto è importante comprenderne il comportamento e il possibile impatto.

### Vulnerability checks con NSE

```bash
nmap --script vuln target
```

Non equivale a una piattaforma completa di vulnerability management: Nmap può eseguire security checks mirati tramite NSE, ma strumenti dedicati forniscono inventario, correlazione e gestione su scala più ampia.

## SMB Enumeration

```bash
nmap -p 445 --script smb-enum-shares target
nmap -p 445 --script smb-enum-users target
nmap -p 445 --script smb-enum-sessions target
nmap -p 445 --script "smb-vuln*" target
```

```text
445/tcp → SMB detection → NSE enumeration → strumenti dedicati
```

Nmap fornisce discovery e prima enumeration; per approfondire passa a [rpcclient](https://hackita.it/articoli/rpcclient/), [smbclient](https://hackita.it/articoli/smbclient/), [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/) o [NetExec](https://hackita.it/articoli/netexec/) — vedi la tabella [Porte Principali](#porte-principali-cosa-fare-dopo) sopra per il quadro completo.

## LDAP e Active Directory Enumeration

```bash
nmap -p 389,636 --script ldap-rootdse target
nmap -p 389 --script ldap-search target
```

```text
389/636 → LDAP/LDAPS detection → RootDSE → Naming Context → enumerazione
```

Nmap contribuisce alla discovery iniziale; per l'enumerazione approfondita passa a [ldapsearch](https://hackita.it/articoli/ldapsearch/). Attività come [Kerberoasting](https://hackita.it/articoli/kerberoasting/) e [AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting/) richiedono poi strumenti dedicati, non Nmap direttamente.

## Web Server Enumeration

```bash
nmap -p 80,443,8080,8443 --open -sV target
nmap -p 80,443 --script http-title,http-headers,http-methods target
nmap -p 80,443 --script http-enum target
nmap -p 80,443 --script http-waf-detect,http-waf-fingerprint target
```

```text
80/443/8080/8443 → service detection → HTTP NSE → technology identification → enumerazione mirata
```

Dopo il fingerprinting iniziale, passa a [Burp Suite](https://hackita.it/articoli/burp-suite/), [ffuf](https://hackita.it/articoli/ffuf/) o [Gobuster](https://hackita.it/articoli/gobuster/) per l'enumerazione web vera e propria.

## SSH Enumeration

```bash
nmap -p 22 -sV target
nmap -p 22 --script ssh-auth-methods target
```

Per l'enumerazione e l'hardening SSH nel dettaglio vedi l'articolo dedicato su [SSH](https://hackita.it/articoli/ssh/).

## DNS Enumeration

```bash
nmap -p 53 --script dns-service-discovery target
nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com ns.example.com
```

Per la reconnaissance DNS completa vedi l'articolo su [DNS](https://hackita.it/articoli/dns/).

## Database Discovery

```bash
nmap -p 3306 --script mysql-info target        # MySQL
nmap -p 1433 --script ms-sql-info target       # MSSQL
nmap -p 5432 -sV target                        # PostgreSQL, poi script dedicati
```

```bash
ls /usr/share/nmap/scripts/ | grep -Ei 'postgres|pgsql'
nmap --script-help <script>
```

Per l'attacco mirato ai singoli DBMS vedi [Porta 3306 MySQL](https://hackita.it/articoli/porta-3306-mysql/) e [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

## IoT e OT Discovery

```bash
nmap -p 502 --script modbus-discover target    # Modbus
nmap -p 102 --script s7-info target            # Siemens S7
nmap -p 1883,8883 --open target                # MQTT
```

In ambienti OT/ICS considera sempre il possibile impatto operativo: tecniche appropriate in una rete IT possono avere conseguenze diverse su sistemi industriali e dispositivi embedded.

## Firewall, IDS e Scan Evasion

Le opzioni di evasion modificano traffico, struttura dei pacchetti o timing delle probe. **Non costituiscono bypass universali di firewall/IDS/IPS e non garantiscono invisibilità.**

```bash
sudo nmap -f target                    # fragmentation
sudo nmap -f -f target                 # doppia frammentazione
sudo nmap --mtu 24 target              # MTU custom
sudo nmap -D RND:5 target              # decoy random
sudo nmap -D 192.168.1.50,ME,192.168.1.52 target   # decoy specifici
sudo nmap --source-port 53 target      # source port spoofing
nmap --badsum target                   # checksum errato (studio comportamento firewall)
nmap --data-length 25 target           # dati random aggiuntivi
```

## Timing e Throttling

| Template | Profilo          |
| -------- | ---------------- |
| `T0`     | Molto lento      |
| `T1`     | Lento            |
| `T2`     | Ridotto impatto  |
| `T3`     | Default          |
| `T4`     | Più aggressivo   |
| `T5`     | Molto aggressivo |

```bash
nmap -T4 target
nmap --scan-delay 5s target
nmap --max-rate 100 target
nmap --min-rate 50 target
```

Timing più aggressivo non significa automaticamente migliore qualità: un aumento eccessivo della velocità può causare packet loss, timeout e maggiore visibilità nei sistemi di monitoraggio. I valori vanno adattati alla rete e al tipo di engagement, non applicati come default universali.

## Idle Scan

```bash
nmap --script ipidseq 192.168.1.0/24   # cerca host zombie candidati
nmap -sI zombie_ip:80 target_ip
```

L'Idle Scan non è una "scansione completamente anonima": può separare in determinati scenari l'origine apparente delle probe dal target, ma non garantisce anonimato assoluto.

## Nmap e Rilevamento

Una scansione può essere rilevata da firewall, IDS/IPS, NDR, EDR con visibilità di rete, log dei servizi e telemetria di rete. Timing, decoy e fragmentation possono modificare il profilo del traffico, ma non esiste un'opzione Nmap che garantisca "rilevamento zero".

## Nmap Output e Reporting

```bash
nmap -sV target -oN scan.nmap    # normal output
nmap -sV target -oX scan.xml     # XML, ideale per automazione/parsing
nmap -sV target -oG scan.gnmap   # grepable, comodo per grep/awk veloci
nmap -sV target -oA scan         # tutti e tre insieme
```

## Dove Salva Nmap i Risultati?

Nmap non salva automaticamente ogni scansione su file. Serve specificare esplicitamente `-oN`, `-oX`, `-oG` o `-oA`:

```bash
nmap -sV target -oA ./results/web_scan
```

## Riprendere una Scansione Interrotta

```bash
nmap --resume scan.nmap
```

## Workflow Nmap per un Penetration Test

### External Reconnaissance

```bash
nmap -F target
nmap -p- target
nmap -sC -sV -p <porte> target
```

### Internal Network Recon

```bash
sudo nmap -sn 10.0.0.0/24 -oG hosts.gnmap
nmap -p- -iL targets.txt -oA tcp_scan
```

### Active Directory Recon

```bash
nmap -p 53,88,135,139,389,445,464,636,3268,3269 --open 10.0.0.0/24
nmap -p 389 --script ldap-rootdse 10.0.0.0/24
```

Una combinazione di queste porte suggerisce la presenza di un Domain Controller — usa la tabella [Porte Principali](#porte-principali-cosa-fare-dopo) per il tool giusto su ciascuna.

### Web Reconnaissance

```text
Network discovery → 80/443/8080/8443 → service detection → HTTP NSE → enumerazione web
```

## Performance e Scansioni Massive

```bash
nmap -sn 10.0.0.0/16 -oG hosts.gnmap
grep "Up" hosts.gnmap | awk '{print $2}' > targets.txt
nmap --top-ports 1000 -iL targets.txt -oA service_scan
nmap -sC -sV -p <porte> -iL priority_targets.txt -oA detailed_scan
```

Separare discovery ed enumeration riduce il lavoro ripetitivo e destina le scansioni più costose solo agli host realmente interessanti.

## Nmap e myNmap

Durante CTF, lab e penetration test autorizzati, la sequenza full scan → service detection → OS detection → NSE → UDP → vulnerability check diventa ripetitiva. **myNmap** è il wrapper open source di Hackita che automatizza questo workflow mantenendo Nmap come motore:

```bash
git clone https://github.com/hack-ita/mynmap.git
cd mynmap
chmod +x mynmap
sudo cp mynmap /usr/local/bin/mynmap
```

```bash
sudo mynmap 10.10.10.10   # con privilegi: usa SYN scan (-sS)
mynmap 10.10.10.10        # senza sudo: usa connect scan (-sT)
```

In un'unica esecuzione copre discovery TCP completa, service/version detection con script NSE default, OS detection, controlli di vulnerabilità sulle porte critiche più comuni e una scansione UDP mirata sulle porte più rilevanti prima di quelle generiche — pensato per il compromesso velocità/copertura di CTF, HTB e Proving Grounds.

| Approccio     | Controllo | Automazione | Quando                                           |
| ------------- | --------- | ----------- | ------------------------------------------------ |
| Nmap manuale  | Massimo   | Bassa       | Scansione completamente personalizzata           |
| Script + Nmap | Alto      | Media       | Workflow ripetibili fatti in casa                |
| myNmap        | Alto      | Alta        | Prima panoramica rapida target→porte→servizi→NSE |

Repository: [github.com/hack-ita/mynmap](https://github.com/hack-ita/mynmap)

## Troubleshooting

```bash
nmap -Pn target                        # host down ma attivo -> ICMP filtrato
nmap -PS22,80,443 target               # probe su porte note
nmap -sT target                        # SYN scan non disponibile senza privilegi
sudo nmap -sU -p 53,67,68,123,161 target   # UDP lento: parti dalle porte rilevanti
sudo nmap -O -sV target                # OS detection poco precisa
```

**Porte `filtered`** — non significa che il servizio sia chiuso, significa che Nmap non ha ricevuto informazioni sufficienti per determinarne con certezza lo stato.

**`Operation not permitted`** — la tecnica richiede privilegi raw-packet: usa `sudo` o passa a `-sT`.

## FAQ

**Cos'è Nmap?**
Uno strumento open source per network discovery e security auditing: identifica host, porte, servizi, versioni software, sistemi operativi e informazioni aggiuntive tramite NSE.

**A cosa serve Nmap?**
Host discovery, port scanning, service/version detection, OS fingerprinting, enumeration e vulnerability detection tramite NSE.

**Come scansionare tutte le porte con Nmap?**
`nmap -p- target`, poi `nmap -sC -sV -p <porte> target` sulle porte trovate.

**Qual è la differenza tra `-sS` e `-sT`?**
`-sS` invia SYN e normalmente non completa il three-way handshake; `-sT` usa la `connect()` di sistema e completa la connessione. La differenza non si riduce a "stealth vs non-stealth": il traffico resta osservabile da log e monitoring.

**Posso usare Nmap senza essere rilevato?**
No. Timing, decoy e fragmentation modificano il traffico generato, ma non garantiscono invisibilità.

**Nmap può fare vulnerability scanning?**
Sì con `nmap --script vuln target`, ma non equivale a una piattaforma completa di vulnerability management.

**Nmap funziona su Windows?**
Sì, con installer ufficiale e Npcap per le funzionalità di rete.

**Dove salva Nmap i risultati?**
Non li salva automaticamente: serve specificare `-oN`, `-oX`, `-oG` o `-oA`.

**Quale formato è migliore per l'automazione?**
XML (`-oX`), per pipeline e parser dedicati.

**In che linguaggio è scritto Nmap?**
Il motore principale è in C/C++; il Nmap Scripting Engine (NSE) usa Lua per gli script; Zenmap, la GUI storica, era scritta in Python.

## Cheat Sheet Nmap

```bash
nmap -sn 192.168.1.0/24        # discovery
nmap -Pn target                 # skip host discovery
nmap -sL 192.168.1.0/24         # lista target
sudo nmap -sS target            # SYN scan
nmap -sT target                 # connect scan
sudo nmap -sU target            # UDP
sudo nmap -sA target            # ACK scan (mappa regole firewall)
sudo nmap -sF -sN -sX target    # FIN / Null / Xmas (evasion su target Unix-like)
nmap -p- target                 # tutte le porte TCP
nmap -p 22,80,443 target        # porte specifiche
nmap --top-ports 100 target
nmap -sV target                 # service detection
sudo nmap -O target             # OS detection
nmap -sC target                 # default NSE
nmap -sC -sV target
sudo nmap -A target             # aggressive
nmap --script vuln target
nmap -sV target -oA scan        # tutti i formati
nmap -sV target -oX scan.xml
nmap --resume scan.nmap
nmap -T4 target
```

## Risorse

* Nmap Official: [nmap.org](https://nmap.org/)
* Nmap Download: [nmap.org/download.html](https://nmap.org/download.html)
* Nmap Reference Guide: [nmap.org/book/man.html](https://nmap.org/book/man.html)
* NSE Documentation: [nmap.org/nsedoc](https://nmap.org/nsedoc/)
* myNmap — Hackita: [github.com/hack-ita/mynmap](https://github.com/hack-ita/mynmap)

> Utilizza Nmap esclusivamente su sistemi e reti per i quali disponi di autorizzazione. Le tecniche di scanning, enumeration ed evasion possono generare traffico, alert o impatti sui sistemi analizzati.
