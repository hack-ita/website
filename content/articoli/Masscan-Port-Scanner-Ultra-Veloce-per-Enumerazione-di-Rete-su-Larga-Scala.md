---
title: 'Masscan: Port Scanner Ultra-Veloce per Enumerazione di Rete su Larga Scala'
slug: masscan
description: Masscan è un port scanner ad altissima velocità capace di analizzare milioni di IP in pochi minuti. Guida pratica all’uso in fase di reconnaissance e mappatura infrastruttura durante un penetration test.
image: /Gemini_Generated_Image_bd3ranbd3ranbd3r.webp
draft: false
date: 2026-02-08T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - port-scanning
---

**Masscan** è un port scanner ad altissima velocità progettato per mappare superfici d’attacco estese in tempi estremamente ridotti. È in grado di trasmettere fino a **10 milioni di pacchetti al secondo**, consentendo la scansione di interi range /16, /12 o persino dell’intero spazio IPv4 in pochi minuti.

A differenza degli scanner tradizionali, utilizza uno stack TCP/IP asincrono proprietario, indipendente dal kernel del sistema operativo. Questo elimina i limiti di gestione delle connessioni e permette performance irraggiungibili con approcci convenzionali.

In un engagement di penetration testing o Red Team, Masscan copre la fase di **Reconnaissance (MITRE ATT\&CK T1046)** ed è il tool ideale per la mappatura iniziale di grandi infrastrutture, prima di passare a strumenti di enumerazione più approfondita come [Nmap](https://hackita.it/articoli/nmap).

In questa guida analizziamo calibrazione del rate, gestione del rumore, formati di output, integrazione con Nmap per service detection e scenari operativi reali su reti enterprise.

## Setup e Installazione

**Kali Linux (preinstallato):**

```bash
masscan --version
```

Output:

```
Masscan version 1.3.2
```

**Installazione da sorgente (versione più aggiornata):**

```bash
sudo apt install git gcc make libpcap-dev
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make -j$(nproc)
sudo make install
```

**Verifica post-installazione:**

```bash
masscan --version
```

**Requisiti:**

* Privilegi root (raw socket per invio pacchetti SYN)
* `libpcap` installata
* Interfaccia di rete configurata (Masscan la rileva automaticamente, ma puoi specificarla con `-e`)
* Banda sufficiente — una scansione a rate 10.000 genera circa 5 Mbps di traffico

***

## Uso Base

Scansione delle porte più comuni su una subnet /24:

```bash
sudo masscan 10.10.10.0/24 -p 21,22,80,443,445,3389,8080 --rate 1000
```

Output:

```
Discovered open port 22/tcp on 10.10.10.5
Discovered open port 80/tcp on 10.10.10.5
Discovered open port 443/tcp on 10.10.10.10
Discovered open port 445/tcp on 10.10.10.10
Discovered open port 3389/tcp on 10.10.10.20
Discovered open port 8080/tcp on 10.10.10.50
```

**Parametri chiave:**

* `10.10.10.0/24` → target (range CIDR)
* `-p` → porte (range con `-p 1-65535`, singole con virgola)
* `--rate 1000` → pacchetti al secondo (SYN packets/sec)
* `-oG output.gnmap` → output in formato grepable
* `-oJ output.json` → output JSON
* `-oX output.xml` → output XML (compatibile Nmap)
* `--banners` → tenta di catturare banner dai servizi

Scansione full port su singolo host:

```bash
sudo masscan 10.10.10.50 -p 0-65535 --rate 500
```

A rate 500 su un singolo host, la scansione completa richiede circa 2 minuti.

***

## Tecniche Operative

### Scansione di rete enterprise con rate calibrato

Su una rete /16 (65.536 host), scansiona le porte critiche:

```bash
sudo masscan 172.16.0.0/16 -p 22,80,443,445,1433,3306,3389,5432,5985,8080,8443 --rate 5000 -oJ results.json
```

A rate 5000 con 11 porte, la scansione termina in circa 2-3 minuti. L'output JSON è facilmente parsabile:

```bash
cat results.json | jq '.[] | select(.ports[0].port == 445)' | jq -r '.ip'
```

Restituisce tutti gli IP con porta 445 aperta — i tuoi target SMB.

### Scansione con esclusioni

Evita di scansionare host sensibili (stampanti, ICS, medical device):

```bash
sudo masscan 10.0.0.0/8 -p 80,443 --rate 10000 --excludefile exclude.txt
```

Il file `exclude.txt` contiene un IP o range per riga:

```
10.0.1.0/24
10.0.5.100
10.10.0.0/16
```

Essenziale in ambienti enterprise dove certi dispositivi non tollerano scansioni.

### Banner grabbing

Masscan può catturare banner dei servizi durante la scansione:

```bash
sudo masscan 10.10.10.0/24 -p 22,80,443 --banners --rate 500
```

Output:

```
Banner on port 22/tcp on 10.10.10.5: [ssh] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
Banner on port 80/tcp on 10.10.10.10: [http] HTTP/1.1 200 OK\x0d\x0aServer: Apache/2.4.52
Banner on port 443/tcp on 10.10.10.10: [ssl] TLS/1.2 cipher:0xc02f
```

Il banner grabbing rallenta la scansione (richiede completare il handshake TCP) ma fornisce informazioni preziose per la fase successiva.

### Output XML per import in Nmap

```bash
sudo masscan 10.10.10.0/24 -p 1-65535 --rate 1000 -oX masscan_output.xml
```

Questo file XML è compatibile con il formato Nmap e può essere importato in Metasploit:

```bash
msfconsole
msf6 > db_import masscan_output.xml
msf6 > hosts
msf6 > services
```

***

## Tecniche Avanzate

### Pipeline Masscan → Nmap

Masscan trova le porte aperte velocemente. Nmap fa service detection approfondita. Combina i due:

```bash
sudo masscan 172.16.0.0/24 -p 1-65535 --rate 1000 -oG masscan.gnmap
```

Estrai host e porte:

```bash
grep "open" masscan.gnmap | awk '{print $4}' | sort -u > live_hosts.txt
grep "open" masscan.gnmap | awk -F'/' '{print $1}' | awk '{print $NF}' | sort -un | tr '\n' ',' | sed 's/,$//' > ports.txt
```

Lancia Nmap solo su host e porte trovate:

```bash
nmap -sV -sC -iL live_hosts.txt -p $(cat ports.txt) -oA nmap_detailed
```

Hai ridotto la superficie di scansione Nmap da "tutto" a "solo ciò che è aperto". Tempo risparmiato: ore.

### Scansione UDP

Masscan supporta anche UDP (meno affidabile ma utile per SNMP, DNS, TFTP):

```bash
sudo masscan 10.10.10.0/24 -pU:53,161,500,1900 --rate 500
```

Il prefisso `U:` specifica porte UDP.

### Randomizzazione dell'ordine di scansione

Masscan randomizza già l'ordine di scansione per default (seed casuale). Per riproducibilità:

```bash
sudo masscan 10.10.10.0/24 -p 1-65535 --rate 1000 --seed 12345
```

Lo stesso seed produce lo stesso ordine di scansione. Utile per debug e per riprodurre risultati.

### Configurazione file per scansioni ricorrenti

Salva la configurazione in un file:

```bash
sudo masscan --echo > scan.conf
```

Modifica `scan.conf`:

```
rate = 5000
ports = 22,80,443,445,3389,5985,8080
output-format = json
output-filename = weekly_scan.json
range = 172.16.0.0/16
exclude-file = exclude.txt
```

Esegui:

```bash
sudo masscan -c scan.conf
```

Ideale per scansioni settimanali su perimetro enterprise.

***

## Scenari Pratici di Pentest

### Scenario 1: Mappatura perimetrale di una rete /16 — Primi 10 minuti dell'engagement

```bash
sudo masscan 172.16.0.0/16 -p 21,22,23,25,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,5985,8080,8443,9200 --rate 10000 -oJ perimeter.json
```

**Output atteso:** file JSON con centinaia/migliaia di entry. Il comando termina in \~3 minuti.

**Cosa fare se fallisce:**

* `FAIL: failed to detect router` → Masscan non trova il gateway. Specifica l'interfaccia: `--adapter-ip 10.10.14.22 -e eth0 --router-mac AA:BB:CC:DD:EE:FF`.
* Pochissimi risultati → Rate troppo alto per la rete. Riduci a `--rate 1000`. Switch e firewall possono droppare pacchetti con rate elevati.

**Timeline:** 3-5 minuti per la scansione. 30 minuti per analisi risultati.

### Scenario 2: Ricerca di servizi specifici — SQL Server in rete enterprise

```bash
sudo masscan 10.0.0.0/8 -p 1433,1434,3306,5432,27017 --rate 20000 -oG db_scan.gnmap
```

**Output atteso:**

```
Discovered open port 1433/tcp on 10.5.20.15
Discovered open port 3306/tcp on 10.12.0.50
Discovered open port 27017/tcp on 10.30.1.100
```

**Cosa fare se fallisce:**

* Range /8 enorme e rate 20000 genera molto traffico → Il team di rete nota l'anomalia. Riduci rate o frammenta: scansiona un /16 alla volta.
* Risultati incompleti → Pacchetti persi. Rilancia con `--retries 2` per inviare ogni pacchetto due volte.

**Timeline:** /8 su 5 porte a rate 20000: circa 15 minuti.

### Scenario 3: Scansione pre-engagement da esterno — Surface discovery

```bash
sudo masscan 203.0.113.0/24 -p 1-65535 --rate 500 --banners -oJ external.json
```

**Output atteso:** porte aperte con banner sui servizi esposti.

**Cosa fare se fallisce:**

* ISP o cloud provider rate-limit i SYN → Riduci rate a 100-200 pps. Le scansioni esterne richiedono pazienza.
* Nessun risultato → Verifica che non ci sia un firewall/NAT tra te e il target: `traceroute 203.0.113.1`.

**Timeline:** Full port scan su /24 a rate 500: circa 10 minuti.

***

## Toolchain Integration

Masscan è il primo anello della catena di recon. Trova velocemente cosa è aperto, poi passa il lavoro a tool specializzati.

**Flusso operativo:**

**Masscan (port discovery)** → Nmap (service detection) → [Gobuster](https://hackita.it/articoli/gobuster)/[Dirsearch](https://hackita.it/articoli/dirsearch) (web enum su porte HTTP trovate) → Exploit

**Passaggio dati concreto:**

```bash
# Masscan trova le porte
sudo masscan 172.16.0.0/24 -p 1-65535 --rate 1000 -oG scan.gnmap

# Estrai host con porta 80/443 per web enum
grep -E "80/open|443/open|8080/open" scan.gnmap | awk '{print $4}' | sort -u > web_targets.txt

# Lancia Gobuster su ogni target web
while read host; do
  gobuster dir -u http://$host -w /usr/share/seclists/Discovery/Web-Content/common.txt -o gobuster_$host.txt
done < web_targets.txt
```

| Criterio          | Masscan     | Nmap       | Zmap  | RustScan |
| ----------------- | ----------- | ---------- | ----- | -------- |
| Velocità          | ★★★★★       | ★★☆☆☆      | ★★★★★ | ★★★★☆    |
| Service detection | Solo banner | Completa   | No    | Via Nmap |
| Script engine     | No          | Sì (NSE)   | No    | No       |
| Accuracy          | ★★★☆☆       | ★★★★★      | ★★★☆☆ | ★★★★☆    |
| Configurabilità   | Alta        | Molto alta | Media | Media    |
| Uso RAM           | Basso       | Medio-alto | Basso | Basso    |

***

## Attack Chain Completa

**Obiettivo:** Compromissione di un database server in una rete enterprise mai testata.

**Fase 1 — Surface Discovery con Masscan (5 min)**

```bash
sudo masscan 10.0.0.0/16 -p 22,80,443,445,1433,3306,3389,5985,8080 --rate 10000 -oJ discovery.json
```

Mappa 65K host in 5 minuti. Trovi 347 host con porte aperte.

**Fase 2 — Service Detection con Nmap (30 min)**

```bash
nmap -sV -sC -iL live_hosts.txt -p 22,80,443,445,1433 -oA detailed
```

Identifichi un MSSQL Server su 10.5.20.15 con autenticazione SQL abilitata.

**Fase 3 — Initial Access (15 min)**

Bruteforce credenziali SQL con [CredNinja](https://hackita.it/articoli/credninja) o Hydra. Trovi `sa:Password1`.

**Fase 4 — Privilege Escalation (10 min)**

```bash
mssqlclient.py sa:Password1@10.5.20.15
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
# nt service\mssqlserver
```

Command execution via xp\_cmdshell.

**Fase 5 — Persistence (2 min)**

Scheduled task per callback ricorrente (cfr. articolo [Scheduled Task](https://hackita.it/articoli/scheduled-task)).

**Timeline totale:** \~62 minuti dal primo pacchetto alla persistenza.

***

## Detection & Evasion

### Cosa monitora il Blue Team

* Volume anomalo di pacchetti SYN da un singolo IP — IDS/IPS come Snort/Suricata triggerano alert su scan massivi
* Firewall logs con migliaia di connessioni verso porte diverse in pochi secondi
* NetFlow analysis che mostra fan-out anomalo (un IP contatta centinaia di IP in breve tempo)

### Log rilevanti

* Firewall → milioni di entry per SYN bloccati/permessi
* IDS (Snort/Suricata) → alert `ET SCAN` con threshold bassi
* Router/switch → SNMP trap per traffico anomalo

### Tecniche di evasion

1. **Rate basso:** `--rate 100` genera solo \~50 Kbps di traffico. Sotto la soglia di detection della maggior parte degli IDS. La scansione è più lenta ma invisibile.
2. **Scansione distribuita:** dividi il range tra più IP sorgente. Ciascuno scansiona un sottoinsieme a rate basso.
3. **Orari off-peak:** lancia la scansione di notte o durante il weekend quando il monitoring è ridotto e il traffico di base è più basso (il tuo traffico si nota meno).

### Nota

Masscan non ha funzionalità di cleanup — non lascia artefatti sul target. Il rischio è solo la detection della scansione stessa nei log di rete.

***

## Performance & Scaling

**Rate e banda:**

| Rate (pps) | Banda approx. | Tempo per /24 (65K porte) | Tempo per /16 (10 porte) |
| ---------- | ------------- | ------------------------- | ------------------------ |
| 100        | 50 Kbps       | \~3 ore                   | \~2 ore                  |
| 1.000      | 500 Kbps      | \~18 min                  | \~12 min                 |
| 10.000     | 5 Mbps        | \~2 min                   | \~1.5 min                |
| 100.000    | 50 Mbps       | \~12 sec                  | \~10 sec                 |

**Considerazioni:**

* Rate superiori a 10.000 possono saturare switch economici e causare packet loss
* Su connessioni remote (VPN, pivot), mantieni rate sotto 5.000 per evitare congestione
* Il parametro `--retries` (default 0) controlla il numero di ritrasmissioni SYN. Aumentalo a 1-2 per migliorare accuracy a rate elevati

**Consumo risorse:** Masscan usa \~50MB di RAM indipendentemente dal range scansionato. La CPU è il bottleneck solo a rate superiori a 1M pps.

***

## Tabelle Tecniche

### Command Reference

| Comando                    | Descrizione                   |
| -------------------------- | ----------------------------- |
| `masscan IP/CIDR -p PORTS` | Scansione base                |
| `--rate N`                 | Pacchetti al secondo          |
| `-oG file`                 | Output grepable               |
| `-oJ file`                 | Output JSON                   |
| `-oX file`                 | Output XML (Nmap compatible)  |
| `--banners`                | Banner grabbing               |
| `--excludefile file`       | Escludi host                  |
| `-e iface`                 | Specifica interfaccia di rete |
| `--retries N`              | Ritrasmissioni SYN            |
| `--seed N`                 | Seed per randomizzazione      |
| `-c file.conf`             | Usa file di configurazione    |
| `-pU:ports`                | Scansione UDP                 |

### Masscan vs Nmap vs RustScan

| Aspetto            | Masscan            | Nmap            | RustScan              |
| ------------------ | ------------------ | --------------- | --------------------- |
| Full port /24      | \~2 min            | \~25 min        | \~5 min               |
| Full port /16      | \~30 min           | Giorni          | Ore                   |
| Service detection  | Banner only        | Completa (NSE)  | Delega a Nmap         |
| OS fingerprint     | No                 | Sì              | No                    |
| Scripting          | No                 | NSE Lua scripts | No                    |
| Output format      | gnmap/json/xml     | Tutti           | Nmap-based            |
| Uso tipico pentest | Fase 1 (discovery) | Fase 2 (detail) | Alternativa a Masscan |

***

## Troubleshooting

| Problema                           | Causa                              | Fix                                            |
| ---------------------------------- | ---------------------------------- | ---------------------------------------------- |
| `FAIL: failed to detect router`    | Gateway non rilevato               | Specifica `--router-mac` e `-e interface`      |
| Pochi risultati vs Nmap            | Rate troppo alto, packet loss      | Riduci rate o aggiungi `--retries 1`           |
| `couldn't initialize adapter`      | Permessi insufficienti             | Esegui con `sudo`                              |
| Scansione non termina              | Range troppo grande con rate basso | Aumenta rate o riduci range                    |
| Risultati non corrispondono a Nmap | Falsi positivi/negativi SYN scan   | Usa `--banners` per conferma o valida con Nmap |
| Interfaccia errata selezionata     | Più interfacce di rete             | Specifica con `-e eth0`                        |

***

## FAQ

**Masscan è più preciso di Nmap?**
No. Masscan sacrifica accuracy per velocità. Può generare falsi positivi (porte chiuse riportate come aperte) e falsi negativi. Usa Nmap come verifica sui risultati di Masscan.

**Posso fare service detection con Masscan?**
Solo banner grabbing con `--banners`. Per service detection completa, passa i risultati a Nmap.

**Qual è il rate massimo sicuro per una rete enterprise?**
Dipende dall'infrastruttura. In linea generale: 1.000-5.000 pps su reti enterprise, 100-500 su reti legacy o con dispositivi sensibili.

**Masscan funziona attraverso VPN/pivot?**
Sì, ma il rate deve essere calibrato alla banda della VPN. Una VPN a 10 Mbps supporta circa 20.000 pps al massimo.

**Posso usare Masscan per scansioni UDP?**
Sì, con il prefisso `U:` sulle porte. L'affidabilità è inferiore alle scansioni TCP perché UDP non ha handshake di conferma.

***

## Cheat Sheet

| Azione                        | Comando                                                                     |
| ----------------------------- | --------------------------------------------------------------------------- |
| Scansione rapida /24          | `sudo masscan 10.10.10.0/24 -p 80,443,445 --rate 1000`                      |
| Full port singolo host        | `sudo masscan 10.10.10.50 -p 0-65535 --rate 500`                            |
| Scansione /16 con output JSON | `sudo masscan 172.16.0.0/16 -p 22,80,443,445 --rate 10000 -oJ results.json` |
| Banner grabbing               | `sudo masscan target -p 22,80 --banners --rate 500`                         |
| Con esclusioni                | `sudo masscan range -p ports --excludefile exclude.txt`                     |
| Scansione UDP                 | `sudo masscan target -pU:53,161 --rate 500`                                 |
| Da file config                | `sudo masscan -c scan.conf`                                                 |
| Output per Nmap/MSF           | `sudo masscan target -p ports -oX output.xml`                               |

***

**Disclaimer:** Masscan genera traffico di rete significativo. Usa esclusivamente in ambienti autorizzati con scope definito. Scansioni non autorizzate possono violare leggi nazionali e internazionali. Repository: [github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
