---
title: 'Nmap Pentesting: Port Scanning, Network Enumeration e NSE'
slug: nmap
description: 'Nmap per penetration testing e network recon: host discovery, port scanning TCP/UDP, service detection, OS fingerprinting, NSE e workflow di enumeration.'
image: /Gemini_Generated_Image_8mre5n8mre5n8mre.webp
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

# Nmap: Scansione Porte, Network Recon e NSE

Nmap è uno dei principali strumenti open source per **network discovery, port scanning e security auditing**. Viene utilizzato per identificare host raggiungibili, porte esposte, servizi, versioni software, sistemi operativi e informazioni aggiuntive tramite il **Nmap Scripting Engine (NSE)**.

Nel penetration testing, però, Nmap non dovrebbe essere considerato semplicemente uno scanner di porte. Il suo valore sta soprattutto nella capacità di trasformare una superficie di rete sconosciuta in una sequenza di informazioni utili per le fasi successive:

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

Questa guida copre installazione, host discovery, TCP e UDP scanning, service detection, OS fingerprinting, NSE, enumeration per servizio, output, performance, troubleshooting, tecniche di evasion e automazione con **myNmap**.

> Esegui scansioni esclusivamente su sistemi, reti e infrastrutture per cui disponi di autorizzazione.

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

Un risultato Nmap non è necessariamente il finding finale. Spesso è il punto di partenza di un workflow:

```text
445/tcp open
    ↓
SMB identified
    ↓
SMB enumeration
    ↓
rpcclient / smbclient / enum4linux-ng / NetExec
```

Oppure:

```text
443/tcp open
    ↓
HTTPS identified
    ↓
HTTP enumeration
    ↓
Burp Suite / httpx / ffuf
```

L'obiettivo è passare da una semplice superficie esposta a una **mappa tecnica utilizzabile per la fase successiva dell'engagement**.

## Installazione e Setup

La versione di Nmap installata può essere verificata con `nmap --version`. Per scaricare la release corrente è consigliabile utilizzare la pagina ufficiale di download, evitando di hardcodare una versione specifica nel contenuto della guida.

### Linux — Debian e Ubuntu

Per installare Nmap dai repository della distribuzione:

```bash
sudo apt update
sudo apt install nmap -y
```

Verifica l'installazione:

```bash
nmap --version
```

La versione presente nel repository della distribuzione può essere diversa da quella distribuita più recentemente dal progetto Nmap.

### Kali Linux

Nmap è normalmente disponibile in Kali Linux.

Verifica la versione installata:

```bash
nmap --version
```

Per aggiornare il pacchetto:

```bash
sudo apt update
sudo apt install --only-upgrade nmap
```

### Windows

Nmap dispone di un installer ufficiale per Windows e utilizza Npcap per diverse funzionalità di packet capture e packet manipulation.

Dopo l'installazione:

```powershell
nmap --version
```

Esempio:

```powershell
nmap -sV 192.168.1.100
```

### macOS

Nmap è disponibile tramite i pacchetti ufficiali per macOS.

Verifica:

```bash
nmap --version
```

### Compilazione da sorgente

Per compilare Nmap dal codice sorgente, scarica il tarball della release desiderata dalla pagina ufficiale:

[https://nmap.org/download.html](https://nmap.org/download.html)

Dopo il download:

```bash
tar xvf nmap-<version>.tar.bz2
cd nmap-<version>
./configure
make
sudo make install
```

[https://nmap.org/download.html](https://nmap.org/download.html)

### Privilegi necessari

Non tutte le scansioni richiedono privilegi elevati. Le tecniche che inviano e ricevono raw packet, come la SYN scan, richiedono normalmente privilegi appropriati su Linux e Unix. La TCP connect scan può invece essere eseguita senza privilegi raw-packet equivalenti.

Esempio:

```bash
sudo nmap -sS target
```

Alternativa senza raw packet:

```bash
nmap -sT target
```

## Come funziona una scansione Nmap

Un modello mentale semplice è:

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

La sequenza può essere ridotta o ampliata in base all'obiettivo.

### Host Discovery

Domanda:

> Quali sistemi sono raggiungibili?

### Port Scanning

Domanda:

> Quali porte rispondono e in quale stato?

### Service Detection

Domanda:

> Quale servizio sta utilizzando la porta?

### Version Detection

Domanda:

> Quale implementazione o versione è stata identificata?

### OS Detection

Domanda:

> Quale sistema operativo è compatibile con il fingerprint osservato?

### NSE

Domanda:

> Quali informazioni aggiuntive posso raccogliere automaticamente?

### Enumeration

Domanda:

> Quale attività specifica ha senso eseguire dopo aver identificato il servizio?

## Sintassi Nmap

La sintassi generale è:

```bash
nmap [options] target
```

Esempio:

```bash
nmap -sV -p 22,80,443 192.168.1.100
```

`-sV` abilita la service/version detection, `-p` seleziona le porte e `192.168.1.100` è il target.

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

### Scansione di un singolo host

```bash
nmap 192.168.1.100
```

Il comando base esegue una scansione sulle porte TCP più comuni e restituisce gli stati che Nmap considera interessanti.

Esempio:

```text
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  open   https
```

### Scansione di un range

```bash
nmap 192.168.1.1-50
```

### Scansione di una subnet

```bash
nmap 192.168.1.0/24
```

### Target da file

```bash
nmap -iL targets.txt
```

### Elencare i target senza scansionarli

```bash
nmap -sL 192.168.1.0/24
```

`-sL` è utile quando vuoi verificare quali indirizzi appartengono a un range e come vengono risolti i nomi, senza eseguire il normale port scan.

## Host Discovery

Prima di eseguire una scansione completa della rete, è spesso utile identificare gli host che Nmap considera attivi.

### Ping Scan

```bash
nmap -sn 192.168.1.0/24
```

`-sn` esegue l'host discovery senza eseguire il normale port scanning.

A seconda del contesto e dei privilegi disponibili, Nmap può utilizzare più tipi di probe durante la fase di discovery.

### ARP Discovery in LAN

Su una rete Ethernet locale, ARP può essere particolarmente efficace:

```bash
sudo nmap -sn -PR 192.168.1.0/24
```

### ICMP e TCP Probe

È possibile combinare probe differenti:

```bash
sudo nmap -sn -PE -PS443 192.168.1.0/24
```

### `-Pn`: Skip Host Discovery

Quando i probe di discovery vengono filtrati, Nmap potrebbe considerare un host inattivo anche se è effettivamente raggiungibile.

Con:

```bash
nmap -Pn target
```

Nmap salta la fase di host discovery e tratta il target come attivo.

`-Pn` non è un bypass universale dei firewall: significa che Nmap non si basa sulla precedente fase di discovery per decidere se continuare la scansione.

Può essere utile quando ICMP o altri probe di discovery vengono filtrati, ma il target espone comunque servizi raggiungibili.

### Disabilitare il DNS lookup

Per evitare la risoluzione DNS durante una scansione:

```bash
nmap -n target
```

Può ridurre traffico DNS e accelerare alcuni workflow in cui la risoluzione dei nomi non è necessaria.

## Port Scanning

Nmap supporta più tecniche di port scanning. La scelta dipende dal protocollo, dai privilegi disponibili e dall'obiettivo della scansione.

### TCP SYN Scan

```bash
sudo nmap -sS target
```

La SYN scan invia una richiesta TCP SYN e interpreta la risposta senza completare normalmente il three-way handshake.

È una delle tecniche più utilizzate quando sono disponibili privilegi sufficienti per la gestione dei raw packet.

### TCP Connect Scan

```bash
nmap -sT target
```

La connect scan utilizza la normale `connect()` del sistema operativo e completa la connessione TCP.

È particolarmente utile quando non sono disponibili i privilegi necessari per una SYN scan.

### UDP Scan

```bash
sudo nmap -sU target
```

Le scansioni UDP sono generalmente più lente e hanno una semantica di risposta diversa da TCP. Per esempio, `open|filtered` può indicare che Nmap non è riuscito a distinguere in modo definitivo tra una porta aperta e una porta filtrata.

### Scansione di porte specifiche

```bash
nmap -p 22,80,443 target
```

Range:

```bash
nmap -p 1-1024 target
```

Range e porte miste:

```bash
nmap -p 22,80,443,8000-9000 target
```

### Tutte le porte TCP

```bash
nmap -p- target
```

`-p-` seleziona l'intero intervallo di porte TCP da 1 a 65535.

Un workflow efficace è separare la scoperta delle porte dalla successiva enumeration:

```bash
nmap -p- target
```

poi:

```bash
nmap -sC -sV -p 22,80,443,445 target
```

### Top ports

```bash
nmap --top-ports 100 target
```

Oppure:

```bash
nmap -F target
```

Una scansione rapida può essere usata come prima fotografia della superficie, seguita da una scansione completa e da una enumeration mirata.

## Stati delle porte Nmap

Gli stati riconosciuti da Nmap descrivono **come il port scanner vede una porta dal punto di osservazione corrente e con il tipo di scansione utilizzato**, non una proprietà assoluta della porta stessa.

| Stato        | Significato                                                                                           |                                                                               |
| ------------ | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `open`       | Un'applicazione sta accettando connessioni TCP, datagrammi UDP o associazioni SCTP                    |                                                                               |
| `closed`     | La porta è raggiungibile ma nessuna applicazione sta ascoltando                                       |                                                                               |
| `filtered`   | Un filtro impedisce a Nmap di determinare se la porta è open o closed                                 |                                                                               |
| `unfiltered` | La porta risponde ai probe, ma Nmap non riesce a stabilire se sia open o closed con quel tipo di scan |                                                                               |
| \`open       | filtered\`                                                                                            | Nmap non riesce a distinguere tra open e filtered                             |
| \`closed     | filtered\`                                                                                            | Nmap non riesce a distinguere tra closed e filtered in determinate condizioni |

Una porta `open` non significa automaticamente "vulnerabile". Significa che Nmap ha osservato un servizio raggiungibile e che esiste una superficie da identificare ed eventualmente enumerare.

La differenza tra `filtered` e `closed` è fondamentale: `closed` indica che la porta è raggiungibile ma non c'è un servizio in ascolto, mentre `filtered` indica che firewall o altri ostacoli impediscono a Nmap di determinarne con certezza lo stato.

## Service e Version Detection

Una porta aperta non identifica necessariamente il software che la gestisce.

Usa:

```bash
nmap -sV target
```

Esempio:

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.x
80/tcp   open  http    Apache httpd
443/tcp  open  https   nginx
445/tcp  open  microsoft-ds
```

Il percorso logico diventa:

```text
Port
 ↓
Protocol
 ↓
Service
 ↓
Product
 ↓
Version
```

### Version intensity

Per una detection più approfondita:

```bash
nmap -sV --version-intensity 5 target
```

Aumentare l'intensità non garantisce automaticamente un risultato migliore in ogni ambiente. La scelta deve tenere conto di latenza, stabilità della rete, numero di target e impatto operativo.

### `-sV` non implica vulnerabilità

Un risultato come:

```text
Apache httpd 2.4.x
```

non significa automaticamente che Apache sia vulnerabile.

La versione identificata da Nmap è un elemento di reconnaissance che può essere correlato a documentazione del vendor, advisory e vulnerability database, ma deve essere successivamente validato.

## OS Detection

```bash
sudo nmap -O target
```

Nmap utilizza fingerprint di rete per stimare il sistema operativo remoto.

Il risultato può contenere una o più ipotesi, ad esempio:

```text
OS details:
Linux 5.x
```

La precisione dipende dalle risposte ricevute, dalla qualità del fingerprint e dalla presenza di firewall, middlebox o sistemi che alterano le probe.

Una combinazione comune è:

```bash
sudo nmap -O -sV target
```

## Aggressive Scan

```bash
sudo nmap -A target
```

`-A` abilita un insieme di funzionalità avanzate che comprende:

* OS detection;
* version detection;
* default NSE scripts;
* traceroute.

Non è semplicemente una modalità "più potente": è una combinazione di più tecniche di detection e enumeration.

Quando vuoi controllare con precisione ciò che viene eseguito, è spesso preferibile scegliere esplicitamente le funzionalità:

```bash
nmap -sC -sV target
```

oppure:

```bash
sudo nmap -O -sV target
```

## Come leggere l'output di Nmap

Consideriamo:

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.x
80/tcp   open  http    Apache httpd
443/tcp  open  https   nginx
445/tcp  open  microsoft-ds
```

La lettura corretta è:

* `22/tcp`: SSH accessibile su TCP/22;
* `80/tcp`: servizio HTTP accessibile;
* `443/tcp`: servizio HTTPS accessibile;
* `445/tcp`: SMB esposto;
* `VERSION`: fingerprint del prodotto identificato da Nmap.

Da qui nasce la decision tree:

```text
22 → SSH enumeration
80 → HTTP enumeration
443 → HTTPS enumeration
445 → SMB enumeration
```

Il vero valore del risultato Nmap è quindi la trasformazione:

```text
scan
 ↓
interpretazione
 ↓
next step
```

## NSE: Nmap Scripting Engine

Il **Nmap Scripting Engine (NSE)** estende Nmap tramite script Lua per automatizzare attività di discovery, enumeration, service/version detection, vulnerability detection e, in alcuni casi, exploitation.

Per verificare gli script installati localmente:

```bash
ls /usr/share/nmap/scripts/
```

Per aggiornare il database locale:

```bash
sudo nmap --script-updatedb
```

Per cercare script relativi a SMB:

```bash
ls /usr/share/nmap/scripts/ | grep -i smb
```

Per visualizzare la documentazione di uno script:

```bash
nmap --script-help smb-enum-shares
```

### Default NSE

```bash
nmap -sC target
```

`-sC` esegue gli script della categoria `default`.

Una combinazione molto comune è:

```bash
nmap -sC -sV target
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

Gli script NSE non sono sandboxati. Prima di eseguire una categoria ampia o uno script sconosciuto è quindi importante comprenderne il comportamento e il possibile impatto.

### Servizio → script → obiettivo

La scelta dello script NSE è più utile quando parte dal servizio che hai già identificato:

| Servizio | Porte comuni        | Script iniziali                                           | Cosa cercare                                |
| -------: | ------------------- | --------------------------------------------------------- | ------------------------------------------- |
|      SMB | 139, 445            | `smb-enum-*`, `smb-vuln-*`                                | share, utenti, sessioni, vulnerabilità note |
|     HTTP | 80, 443, 8080, 8443 | `http-title`, `http-headers`, `http-methods`, `http-enum` | server, header, metodi, contenuti           |
|      SSH | 22                  | `ssh-auth-methods`                                        | metodi di autenticazione                    |
|     LDAP | 389, 636            | `ldap-rootdse`, `ldap-search`                             | naming context, directory information       |
|      DNS | 53                  | `dns-*`                                                   | discovery e verifiche DNS supportate        |
|    MySQL | 3306                | `mysql-info`                                              | fingerprint e informazioni sul servizio     |
|    MSSQL | 1433                | `ms-sql-*`                                                | informazioni e configurazione del servizio  |

Non tutti gli script funzionano allo stesso modo su ogni target: autenticazione, configurazione, versione del servizio e argomenti NSE possono cambiare il risultato.

### Vulnerability checks con NSE

```bash
nmap --script vuln target
```

La categoria `vuln` comprende script classificati per il rilevamento di specifiche vulnerabilità o condizioni insicure.

Non equivale a una piattaforma completa di vulnerability management: Nmap può eseguire security checks mirati tramite NSE, ma strumenti dedicati possono fornire inventario, correlazione, reporting e gestione delle vulnerabilità su scala più ampia.

## SMB Enumeration

Quando Nmap identifica:

```text
445/tcp open microsoft-ds
```

puoi passare a una enumeration specifica del servizio.

### Share enumeration

```bash
nmap -p 445 --script smb-enum-shares target
```

Lo script tenta di raccogliere informazioni sulle condivisioni SMB quando target, autenticazione e configurazione del servizio lo consentono.

### User enumeration

```bash
nmap -p 445 --script smb-enum-users target
```

Anche qui il risultato dipende dai permessi e dal comportamento del target.

### Session enumeration

```bash
nmap -p 445 --script smb-enum-sessions target
```

### Vulnerability checks

```bash
nmap -p 445 --script "smb-vuln*" target
```

Un workflow SMB tipico può diventare:

```text
445/tcp
 ↓
SMB detection
 ↓
NSE enumeration
 ↓
rpcclient / smbclient / enum4linux-ng / NetExec
```

Nmap fornisce discovery e prima enumeration; gli strumenti specializzati possono approfondire il servizio.

## LDAP e Active Directory Enumeration

Le porte LDAP più comuni sono:

```text
389/tcp
636/tcp
```

### RootDSE

```bash
nmap -p 389,636 --script ldap-rootdse target
```

### LDAP search

```bash
nmap -p 389 --script ldap-search target
```

Le query LDAP più avanzate possono richiedere credenziali, argomenti specifici o una configurazione del servizio che permetta determinate operazioni.

Un workflow iniziale può essere:

```text
389/636
 ↓
LDAP / LDAPS detection
 ↓
RootDSE
 ↓
Naming Context
 ↓
LDAP enumeration
```

Nmap può contribuire alla discovery iniziale di Active Directory, ma attività specifiche come Kerberoasting e AS-REP Roasting richiedono strumenti e workflow dedicati.

## Web Server Enumeration

Identifica le porte web più comuni:

```bash
nmap -p 80,443,8080,8443 --open -sV target
```

### HTTP fingerprinting

```bash
nmap -p 80,443 --script http-title,http-headers,http-methods target
```

### HTTP enumeration

```bash
nmap -p 80,443 --script http-enum target
```

### WAF detection

```bash
nmap -p 80,443 --script http-waf-detect,http-waf-fingerprint target
```

Workflow:

```text
80/443/8080/8443
 ↓
Service detection
 ↓
HTTP NSE
 ↓
Technology identification
 ↓
Burp Suite / httpx / ffuf
```

## SSH Enumeration

Service detection:

```bash
nmap -p 22 -sV target
```

Metodi di autenticazione:

```bash
nmap -p 22 --script ssh-auth-methods target
```

Workflow:

```text
22/tcp
 ↓
SSH
 ↓
Version
 ↓
Authentication methods
 ↓
SSH-specific enumeration
```

## DNS Enumeration

Discovery del servizio DNS:

```bash
nmap -p 53 --script dns-service-discovery target
```

Per un test autorizzato di zone transfer:

```bash
nmap -p 53 --script dns-zone-transfer \
  --script-args dns-zone-transfer.domain=example.com \
  ns.example.com
```

Nmap può contribuire alla reconnaissance DNS, ma per enumeration DNS completa è spesso opportuno affiancare strumenti dedicati.

## Database Discovery

### MySQL

```bash
nmap -p 3306 --script mysql-info target
```

### Microsoft SQL Server

```bash
nmap -p 1433 --script ms-sql-info target
```

### PostgreSQL

Per iniziare dalla detection del servizio:

```bash
nmap -p 5432 -sV target
```

Gli script NSE disponibili dipendono dalla versione installata. Per verificare quelli presenti localmente:

```bash
ls /usr/share/nmap/scripts/ | grep -Ei 'postgres|pgsql'
```

e:

```bash
nmap --script-help <script>
```

Separare discovery, enumeration e authentication testing evita di confondere attività con obiettivi differenti:

```text
database discovery
 ↓
service identification
 ↓
configuration enumeration
 ↓
authentication testing
```

## IoT e OT Discovery

Nmap dispone anche di script per protocolli specializzati.

### Modbus

```bash
nmap -p 502 --script modbus-discover target
```

### Siemens S7

```bash
nmap -p 102 --script s7-info target
```

### MQTT

```bash
nmap -p 1883,8883 --open target
```

In ambienti OT/ICS è importante considerare il possibile impatto operativo della scansione. Tecniche appropriate in una rete IT possono avere conseguenze diverse su sistemi industriali e dispositivi embedded.

## Firewall, IDS e Scan Evasion

Le opzioni di evasion di Nmap modificano il traffico, la struttura dei pacchetti o il comportamento temporale delle probe.

**Non costituiscono bypass universali di firewall, IDS o IPS e non garantiscono invisibilità.**

### Fragmentation

```bash
sudo nmap -f target
```

Più livelli di frammentazione:

```bash
sudo nmap -f -f target
```

### MTU custom

```bash
sudo nmap --mtu 24 target
```

### Decoy

```bash
sudo nmap -D RND:5 target
```

Con indirizzi specifici:

```bash
sudo nmap -D 192.168.1.50,192.168.1.51,ME,192.168.1.52 target
```

### Source Port

```bash
sudo nmap --source-port 53 target
```

oppure:

```bash
sudo nmap --source-port 80 target
```

Questa tecnica può modificare il comportamento di alcuni filtri configurati in modo errato, ma non deve essere considerata un firewall bypass generico.

### Bad Checksum

```bash
nmap --badsum target
```

Può essere utile per studiare il comportamento di firewall e dispositivi rispetto a pacchetti con checksum errato.

### Data Length

```bash
nmap --data-length 25 target
```

Aggiunge una quantità di dati casuali alle probe.

## Timing e Throttling

Nmap dispone dei timing template:

| Template | Profilo          |
| -------- | ---------------- |
| `T0`     | Molto lento      |
| `T1`     | Lento            |
| `T2`     | Ridotto impatto  |
| `T3`     | Default          |
| `T4`     | Più aggressivo   |
| `T5`     | Molto aggressivo |

Esempio:

```bash
nmap -T4 target
```

Timing più aggressivo non significa automaticamente migliore qualità. Un aumento eccessivo della velocità può causare packet loss, timeout, risultati meno affidabili e maggiore visibilità nei sistemi di monitoraggio.

### Scan delay

```bash
nmap --scan-delay 5s target
```

### Rate limiting

```bash
nmap --max-rate 100 target
```

oppure:

```bash
nmap --min-rate 50 target
```

I valori devono essere adattati alla rete e al tipo di engagement, non applicati come impostazioni universali.

## Idle Scan

L'Idle Scan utilizza un host intermedio compatibile come **zombie** per effettuare una scansione basata sul comportamento del traffico IP.

Esempio:

```bash
nmap -sI zombie_ip:80 target_ip
```

Un possibile metodo per studiare host con caratteristiche adatte è:

```bash
nmap --script ipidseq 192.168.1.0/24
```

L'Idle Scan non è una "scansione completamente anonima". Può separare in determinati scenari l'origine apparente delle probe dal target, ma non garantisce anonimato assoluto o assenza di tracce.

## Nmap e rilevamento

Una scansione Nmap può essere rilevata da:

* firewall;
* IDS/IPS;
* NDR;
* EDR con visibilità di rete;
* log dei servizi;
* sistemi di monitoring;
* telemetria di rete.

Timing, decoy, fragmentation e tecniche simili possono modificare il profilo del traffico, ma non esiste un'opzione Nmap che garantisca "rilevamento zero".

## Output e Reporting

Nmap supporta diversi formati di output.

### Normal output

```bash
nmap -sV target -oN scan.nmap
```

### XML

```bash
nmap -sV target -oX scan.xml
```

L'XML è particolarmente adatto per automazione e parsing da parte di altri programmi.

### Grepable output

```bash
nmap -sV target -oG scan.gnmap
```

Il formato grepable può essere comodo per operazioni veloci con `grep`, `awk`, `cut` e strumenti shell, ma per nuove pipeline strutturate l'XML è generalmente preferibile.

### Tutti i principali formati

```bash
nmap -sV target -oA scan
```

Genera:

```text
scan.nmap
scan.xml
scan.gnmap
```

## Dove salva Nmap i risultati?

Nmap non salva automaticamente ogni scansione su file.

Per salvare i risultati devi specificare una delle opzioni di output:

```text
-oN  Normal output
-oX  XML
-oG  Grepable output
-oA  Tutti i principali formati
```

Esempio:

```bash
nmap -sV target -oA ./results/web_scan
```

## Parsing XML

Per creare un output strutturato:

```bash
nmap -sV target -oX results.xml
```

Una pipeline tipica è:

```text
Nmap
 ↓
XML
 ↓
Parser
 ↓
Database / Dashboard / Automation
```

Questo è preferibile al parsing del testo terminale quando i risultati devono essere consumati da software.

## Riprendere una scansione interrotta

Per riprendere una scansione salvata in normal output:

```bash
nmap --resume scan.nmap
```

Nmap recupera dal file le informazioni necessarie per riprendere la scansione.

## Workflow Nmap per un Penetration Test

### External Reconnaissance

```text
Target
 ↓
Host / DNS discovery
 ↓
Top ports
 ↓
Full TCP scan
 ↓
Service / version detection
 ↓
NSE mirato
 ↓
Manual validation
```

Esempio:

```bash
nmap -F target
```

poi:

```bash
nmap -p- target
```

poi:

```bash
nmap -sC -sV -p <porte> target
```

### Internal Network Recon

```text
Subnet
 ↓
Live hosts
 ↓
Full port scan
 ↓
Service detection
 ↓
SMB / LDAP / DNS / HTTP
 ↓
Enumeration specifica
```

Discovery:

```bash
sudo nmap -sn 10.0.0.0/24 -oG hosts.gnmap
```

Full scan:

```bash
nmap -p- -iL targets.txt -oA tcp_scan
```

### Active Directory Recon

Una combinazione di servizi può suggerire la presenza di un Domain Controller:

```text
53
88
135
139
389
445
464
636
3268
3269
```

Scansione:

```bash
nmap -p 53,88,135,139,389,445,464,636,3268,3269 --open 10.0.0.0/24
```

LDAP:

```bash
nmap -p 389 --script ldap-rootdse 10.0.0.0/24
```

Il risultato orienta le fasi successive di Active Directory enumeration.

### Web Reconnaissance

```text
Network discovery
 ↓
80/443/8080/8443
 ↓
Service detection
 ↓
HTTP NSE
 ↓
Technology identification
 ↓
Web enumeration
```

## Performance e Scansioni Massive

Su reti ampie è spesso più efficace separare discovery e enumeration piuttosto che utilizzare sempre la scansione più aggressiva possibile.

### Discovery first

```bash
nmap -sn 10.0.0.0/16 -oG hosts.gnmap
```

Dopo aver isolato gli host attivi:

```bash
grep "Up" hosts.gnmap | awk '{print $2}' > targets.txt
```

Poi:

```bash
nmap --top-ports 1000 -iL targets.txt -oA service_scan
```

Infine, sui target prioritari:

```bash
nmap -sC -sV -p <porte> -iL priority_targets.txt -oA detailed_scan
```

Questo modello riduce il lavoro ripetitivo e consente di destinare le scansioni più costose agli host realmente interessanti.

## Nmap e myNmap

Durante CTF, lab e penetration test autorizzati, molte operazioni della reconnaissance possono diventare ripetitive:

```text
Full TCP scan
 ↓
Service detection
 ↓
OS detection
 ↓
NSE
 ↓
UDP
 ↓
Vulnerability checks
```

**myNmap** è un wrapper open source sviluppato da HACKITA per automatizzare diverse di queste operazioni e ridurre il lavoro manuale necessario per passare dal target ai primi risultati di enumeration.

Repository:

[https://github.com/hack-ita/mynmap](https://github.com/hack-ita/mynmap)

Il progetto combina in un workflow automatizzato diverse operazioni normalmente eseguite separatamente con Nmap, mantenendo Nmap come motore della scansione.

### Nmap manuale vs myNmap

|     Approccio | Controllo | Automazione | Utilizzo                               |
| ------------: | --------: | ----------- | -------------------------------------- |
|  Nmap manuale |   Massimo | Bassa       | Scansioni completamente personalizzate |
| Script + Nmap |      Alto | Media       | Workflow ripetibili                    |
|        myNmap |      Alto | Alta        | Enumeration automatizzata              |

Nmap rimane preferibile quando vuoi controllare direttamente ogni porta, probe, script e parametro di timing.

myNmap è invece orientato ai workflow in cui vuoi automatizzare attività ripetitive e arrivare rapidamente a una prima panoramica di:

```text
target
 ↓
porte
 ↓
servizi
 ↓
versioni
 ↓
NSE
 ↓
potenziali vulnerabilità
```

Repository ufficiale:

[https://github.com/hack-ita/mynmap](https://github.com/hack-ita/mynmap)

## Troubleshooting

### Host risulta down ma è attivo

```bash
nmap -Pn target
```

Oppure prova probe specifiche:

```bash
nmap -PS22,80,443 target
```

### SYN scan non disponibile

```bash
nmap -sT target
```

### UDP molto lento

Inizia dalle porte UDP più rilevanti invece di scansionare immediatamente tutto l'intervallo:

```bash
sudo nmap -sU -p 53,67,68,123,161 target
```

### OS Detection poco precisa

```bash
sudo nmap -O -sV target
```

La precisione dipende dal fingerprint osservato e dalle condizioni di rete.

### Porte `filtered`

Un risultato:

```text
443/tcp filtered https
```

non significa che HTTPS sia chiuso.

Significa che Nmap non ha ricevuto informazioni sufficienti per determinare con certezza lo stato della porta.

### `Operation not permitted`

Se una tecnica richiede privilegi raw-packet:

```bash
nmap -sS target
```

può fallire senza privilegi appropriati.

Su Linux puoi usare:

```bash
sudo nmap -sS target
```

Oppure una connect scan:

```bash
nmap -sT target
```

## FAQ

### Cos'è Nmap?

Nmap è uno strumento open source per network discovery e security auditing. Può identificare host, porte, servizi, versioni software, sistemi operativi e informazioni aggiuntive tramite NSE.

### A cosa serve Nmap?

Nmap viene utilizzato principalmente per host discovery, port scanning, service e version detection, OS fingerprinting, enumeration e vulnerability detection tramite NSE.

### Come scansionare tutte le porte con Nmap?

Usa:

```bash
nmap -p- target
```

Dopo aver individuato le porte interessanti puoi eseguire una scansione più approfondita:

```bash
nmap -sC -sV -p <porte> target
```

### Qual è la differenza tra `-sS` e `-sT`?

`-sS` utilizza una TCP SYN scan e normalmente non completa il normale three-way handshake.

`-sT` utilizza la normale `connect()` del sistema operativo e completa la connessione TCP.

La differenza non dovrebbe essere ridotta semplicemente a "stealth" e "non stealth": il traffico può essere osservato dai sistemi di logging e monitoraggio presenti nell'infrastruttura.

### Posso usare Nmap senza essere rilevato?

No. Una scansione può essere individuata da firewall, IDS/IPS, NDR e dai log dei servizi.

Timing, decoy, fragmentation e altre tecniche possono modificare il traffico generato, ma non garantiscono invisibilità.

### Nmap può fare vulnerability scanning?

Sì. NSE dispone di script per il vulnerability detection:

```bash
nmap --script vuln target
```

Questi controlli possono identificare specifiche condizioni vulnerabili, ma non equivalgono necessariamente a una piattaforma completa di vulnerability management.

### Nmap funziona su Windows?

Sì. Nmap dispone di un installer ufficiale per Windows e utilizza Npcap per diverse funzionalità di rete.

### Dove salva Nmap i risultati?

Nmap non salva automaticamente ogni scansione su file.

Puoi usare:

```bash
-oN
```

per normal output,

```bash
-oX
```

per XML,

```bash
-oG
```

per grepable output,

oppure:

```bash
-oA
```

per generare contemporaneamente i principali formati.

### Quale formato Nmap è migliore per l'automazione?

Per pipeline e programmi che devono processare i risultati, l'XML è generalmente il formato più adatto:

```bash
nmap -sV target -oX scan.xml
```

### Quante porte può scansionare Nmap?

Con:

```bash
nmap -p- target
```

puoi selezionare tutte le porte TCP da 1 a 65535. Le porte UDP vengono analizzate separatamente con `-sU`.

## Cheat Sheet Nmap

### Discovery

```bash
nmap -sn 192.168.1.0/24
```

### Skip host discovery

```bash
nmap -Pn target
```

### Lista target

```bash
nmap -sL 192.168.1.0/24
```

### SYN scan

```bash
sudo nmap -sS target
```

### TCP connect scan

```bash
nmap -sT target
```

### UDP

```bash
sudo nmap -sU target
```

### Tutte le porte TCP

```bash
nmap -p- target
```

### Porte specifiche

```bash
nmap -p 22,80,443 target
```

### Top ports

```bash
nmap --top-ports 100 target
```

### Service detection

```bash
nmap -sV target
```

### OS detection

```bash
sudo nmap -O target
```

### Default NSE

```bash
nmap -sC target
```

### Service + NSE

```bash
nmap -sC -sV target
```

### Aggressive scan

```bash
sudo nmap -A target
```

### Vulnerability checks

```bash
nmap --script vuln target
```

### Salvare tutti i principali formati

```bash
nmap -sV target -oA scan
```

### XML

```bash
nmap -sV target -oX scan.xml
```

### Riprendere una scansione

```bash
nmap --resume scan.nmap
```

### Timing

```bash
nmap -T4 target
```

## Risorse

* Nmap Official: [https://nmap.org/](https://nmap.org/)
* Nmap Download: [https://nmap.org/download.html](https://nmap.org/download.html)
* Nmap Reference Guide: [https://nmap.org/book/man.html](https://nmap.org/book/man.html)
* Nmap Network Scanning: [https://nmap.org/book/](https://nmap.org/book/)
* NSE Documentation: [https://nmap.org/nsedoc/](https://nmap.org/nsedoc/)
* Nmap GitHub: [https://github.com/nmap/nmap](https://github.com/nmap/nmap)
* HackTricks — Nmap Summary: [https://hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-network/nmap-summary-esp.html](https://hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-network/nmap-summary-esp.html)
* myNmap — HACKITA: [https://github.com/hack-ita/mynmap](https://github.com/hack-ita/mynmap)

> Utilizza Nmap esclusivamente su sistemi e reti per i quali disponi di autorizzazione. Le tecniche di scanning, enumeration ed evasion possono generare traffico, alert o impatti sui sistemi analizzati.
