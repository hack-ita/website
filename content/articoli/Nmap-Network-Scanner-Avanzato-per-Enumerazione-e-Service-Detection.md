---
title: 'Nmap: Network Scanner Avanzato per Enumerazione e Service Detection'
slug: nmap
description: 'Nmap: Network Scanner Avanzato per Enumerazione e Service Detection'
image: /Gemini_Generated_Image_8mre5n8mre5n8mre.webp
draft: false
date: 2026-02-20T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - port-scanning
---

Nmap è lo strumento di riferimento per la ricognizione di rete nel penetration testing. In questa guida impari a usare nmap per identificare host attivi, porte aperte, servizi vulnerabili e configurazioni errate. Dalle scansioni base alle tecniche avanzate di evasion, trovi tutto quello che serve per integrare nmap nel tuo workflow di pentest.

## Installazione e Setup

### Linux (Debian/Ubuntu)

```bash
# Installazione da repository
sudo apt update && sudo apt install nmap -y

# Verifica versione
nmap --version
```

Output atteso:

```
Nmap version 7.94 ( https://nmap.org )
Platform: x86_64-pc-linux-gnu
```

### Kali Linux

Nmap è preinstallato. Aggiorna alla versione più recente:

```bash
sudo apt update && sudo apt upgrade nmap -y
```

### Compilazione da Sorgente

Per features sperimentali o versioni bleeding-edge:

```bash
wget https://nmap.org/dist/nmap-7.94.tar.bz2
tar xvf nmap-7.94.tar.bz2
cd nmap-7.94
./configure && make && sudo make install
```

### Requisiti

* Root/sudo per scansioni SYN e OS detection
* Minimo 512MB RAM (consigliati 2GB per scansioni massive)
* Connettività di rete verso i target

## Uso Base di Nmap

### Scansione Host Singolo

```bash
nmap 192.168.1.100
```

Output esempio:

```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.100
Host is up (0.0034s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

### Scansione Range e Subnet

```bash
# Range specifico
nmap 192.168.1.1-50

# Subnet intera
nmap 192.168.1.0/24

# Da file lista target
nmap -iL targets.txt
```

### Parametri Fondamentali

| Parametro | Funzione             | Esempio                    |
| --------- | -------------------- | -------------------------- |
| `-sS`     | SYN scan (stealth)   | `nmap -sS target`          |
| `-sT`     | TCP connect scan     | `nmap -sT target`          |
| `-sU`     | UDP scan             | `nmap -sU target`          |
| `-sV`     | Version detection    | `nmap -sV target`          |
| `-O`      | OS fingerprinting    | `nmap -O target`           |
| `-p`      | Porte specifiche     | `nmap -p 22,80,443 target` |
| `-p-`     | Tutte le 65535 porte | `nmap -p- target`          |
| `-A`      | Aggressive scan      | `nmap -A target`           |
| `-T[0-5]` | Timing template      | `nmap -T4 target`          |

## Tecniche di Scansione per Penetration Testing

### Host Discovery nella Rete Interna

Prima di tutto, identifica gli host attivi. Evita scansioni porte inutili:

```bash
# ARP discovery (più veloce in LAN)
nmap -sn -PR 192.168.1.0/24

# ICMP echo + TCP SYN su porta 443
nmap -sn -PE -PS443 192.168.1.0/24

# Discovery senza ping (bypass firewall)
nmap -Pn 192.168.1.0/24
```

Output host discovery:

```
Nmap scan report for 192.168.1.1
Host is up (0.0021s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Cisco Systems)

Nmap scan report for 192.168.1.100
Host is up (0.0035s latency).
MAC Address: 11:22:33:44:55:66 (Dell)
```

### Service Enumeration Aggressiva

Identifica versioni precise per cercare CVE:

```bash
# Version detection intensiva
nmap -sV --version-intensity 5 -p- 192.168.1.100

# Con script default
nmap -sC -sV -p 22,80,443,445,3389 192.168.1.100
```

### SMB Enumeration

Target prioritario in ogni pentest interno. Integra con [crackmapexec](https://hackita.it/articoli/crackmapexec) per exploitation:

```bash
# Enumera shares e utenti
nmap -p 445 --script smb-enum-shares,smb-enum-users 192.168.1.0/24

# Verifica vulnerabilità SMB
nmap -p 445 --script smb-vuln* 192.168.1.100

# Enumera sessioni attive
nmap -p 445 --script smb-enum-sessions --script-args smbusername=admin,smbpassword=pass 192.168.1.100

# Brute force SMB
nmap -p 445 --script smb-brute --script-args userdb=users.txt,passdb=pass.txt 192.168.1.100
```

Output vulnerabilità EternalBlue:

```
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
```

### LDAP e Active Directory Enumeration

Fondamentale per attacchi [Kerberoasting](https://hackita.it/articoli/kerberoasting) e AS-REP Roasting:

```bash
# LDAP enumeration base
nmap -p 389,636 --script ldap-search,ldap-rootdse target

# Cerca utenti con SPN (Kerberoastable)
nmap -p 389 --script ldap-search --script-args 'ldap.qfilter=(&(objectClass=user)(servicePrincipalName=*))' target

# Null session check
nmap -p 389 --script ldap-search --script-args 'ldap.username="",ldap.password=""' target
```

### Web Server Fingerprinting

```bash
# HTTP enumeration completa
nmap -p 80,443,8080,8443 --script http-enum,http-headers,http-methods 192.168.1.100

# Directory bruteforce leggero
nmap -p 80 --script http-enum --script-args http-enum.basepath='/api/' target
```

### Database Discovery

```bash
# MySQL
nmap -p 3306 --script mysql-info,mysql-enum 192.168.1.100

# MSSQL
nmap -p 1433 --script ms-sql-info,ms-sql-config 192.168.1.100

# PostgreSQL
nmap -p 5432 --script pgsql-brute 192.168.1.100
```

## Tecniche Avanzate di Evasion

### Firewall e IDS Bypass

Quando le scansioni standard vengono bloccate, usa queste tecniche per evadere i controlli:

```bash
# Fragmentazione pacchetti
nmap -f -sS 192.168.1.100

# Doppia frammentazione (8 byte fragments)
nmap -f -f -sS 192.168.1.100

# MTU custom (multipli di 8)
nmap --mtu 24 192.168.1.100

# Decoy scan (nascondi IP sorgente tra IP fake)
nmap -D RND:10 192.168.1.100

# Decoy con IP specifici
nmap -D 192.168.1.50,192.168.1.51,ME,192.168.1.52 target

# Source port spoofing (simula DNS/HTTP)
nmap --source-port 53 192.168.1.100
nmap --source-port 80 192.168.1.100

# Combina tecniche multiple
nmap -f --source-port 53 -D RND:5 -T2 192.168.1.100
```

### Bad Checksum e Data Length

Alcuni IDS non processano pacchetti malformati:

```bash
# Aggiungi dati random ai pacchetti
nmap --data-length 25 192.168.1.100

# Invia pacchetti con checksum errato (debug/testing)
nmap --badsum 192.168.1.100
```

### Timing e Throttling

Evita detection rallentando le scansioni:

```bash
# Paranoid (1 pacchetto ogni 5 minuti)
nmap -T0 192.168.1.100

# Sneaky (1 pacchetto ogni 15 secondi)
nmap -T1 192.168.1.100

# Custom timing granulare
nmap --scan-delay 5s --max-rate 10 192.168.1.100
```

| Template | Descrizione | Use Case              |
| -------- | ----------- | --------------------- |
| T0       | Paranoid    | IDS evasion critica   |
| T1       | Sneaky      | Pentest stealth       |
| T2       | Polite      | Network congestionati |
| T3       | Normal      | Default               |
| T4       | Aggressive  | CTF, lab              |
| T5       | Insane      | Solo lab isolati      |

### Idle Scan (Zombie Scan)

Scansione completamente anonima usando un host zombie:

```bash
# Trova zombie (IP ID incrementale)
nmap --script ipidseq 192.168.1.0/24

# Esegui idle scan
nmap -sI zombie_ip:80 target_ip
```

## Scenari Pratici di Penetration Test

### Scenario 1: Ricognizione Rete Corporate

Primo giorno di engagement interno. Obiettivo: mappare l'infrastruttura.

```bash
# Step 1: Host discovery veloce
nmap -sn -T4 10.0.0.0/16 -oG hosts_up.txt
grep "Up" hosts_up.txt | cut -d " " -f 2 > live_hosts.txt

# Step 2: Quick port scan top 100
nmap -F -iL live_hosts.txt -oA quick_scan

# Step 3: Full scan su host interessanti
nmap -sC -sV -p- -T4 -iL priority_targets.txt -oA full_scan
```

### Scenario 2: Identificazione Domain Controller

I DC sono target primari per [privilege escalation](https://hackita.it/articoli/privilege-escalation-windows):

```bash
# Cerca porte tipiche DC
nmap -p 53,88,135,139,389,445,464,636,3268,3269 10.0.0.0/24 --open

# Identifica DC con script
nmap -p 389 --script ldap-rootdse 10.0.0.0/24
```

Output Domain Controller:

```
| ldap-rootdse: 
|     domainFunctionality: 7
|     forestFunctionality: 7
|     domainControllerFunctionality: 7
|     rootDomainNamingContext: DC=corp,DC=local
```

### Scenario 3: Web Application Recon

Prima di lanciare [Burp Suite](https://hackita.it/articoli/burp-suite), identifica tutti i web server:

```bash
# Discovery web servers
nmap -p 80,443,8000,8080,8443,8888 --open -sV 192.168.1.0/24 -oG webservers.txt

# Identifica WAF
nmap -p 80,443 --script http-waf-detect,http-waf-fingerprint target

# Cerca vulnerabilità web note
nmap -p 80,443 --script http-vuln* target
```

### Scenario 4: IoT e OT Discovery

Ambienti industriali e IoT:

```bash
# Modbus (SCADA)
nmap -p 502 --script modbus-discover 192.168.1.0/24

# Siemens S7
nmap -p 102 --script s7-info 192.168.1.0/24

# MQTT
nmap -p 1883,8883 --script mqtt-subscribe 192.168.1.0/24
```

## NSE Scripts Essenziali

Nmap Scripting Engine trasforma nmap in vulnerability scanner completo. Con oltre 600 script disponibili, puoi automatizzare ricognizione, vulnerability assessment e exploitation leggera.

```bash
# Aggiorna script database
sudo nmap --script-updatedb

# Lista script disponibili
ls /usr/share/nmap/scripts/ | wc -l
# Output: 604

# Cerca script per keyword
ls /usr/share/nmap/scripts/ | grep -i "smb"

# Info dettagliate su uno script
nmap --script-help smb-vuln-ms17-010
```

### Script Categories

| Categoria   | Uso                       | Esempio              |
| ----------- | ------------------------- | -------------------- |
| `auth`      | Authentication bypass     | `--script auth`      |
| `brute`     | Credential bruteforce     | `--script brute`     |
| `vuln`      | Vulnerability detection   | `--script vuln`      |
| `exploit`   | Exploitation attiva       | `--script exploit`   |
| `discovery` | Network/service discovery | `--script discovery` |
| `safe`      | Non intrusivi             | `--script safe`      |
| `intrusive` | Potenzialmente pericolosi | `--script intrusive` |
| `malware`   | Malware detection         | `--script malware`   |

### Script Ad-Hoc per Target Specifici

```bash
# FTP anonymous login check
nmap -p 21 --script ftp-anon 192.168.1.0/24

# SSH authentication methods
nmap -p 22 --script ssh-auth-methods 192.168.1.100

# SSL/TLS vulnerabilities (Heartbleed, POODLE, etc)
nmap -p 443 --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection target

# DNS zone transfer attempt
nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=target.com ns.target.com
```

### Script Combinati per Engagement Completo

```bash
# Vulnerability assessment completo
nmap -sV --script "vuln and safe" -p- target -oA vuln_assessment

# Credential check
nmap --script "brute and not dos" -p 21,22,23,25,110,143,3306,5432 target
```

## Output e Reporting

### Formati Output

```bash
# Output multipli simultanei
nmap -sV -sC target -oA scan_results
# Genera: scan_results.nmap, scan_results.xml, scan_results.gnmap

# XML per parsing
nmap -sV target -oX results.xml

# Grepable per scripting
nmap -sV target -oG results.gnmap
```

### Parsing Risultati

```bash
# Estrai porte aperte da grepable
grep "open" results.gnmap | cut -d " " -f 2

# Converti XML in HTML report
xsltproc results.xml -o report.html
```

## Integrazione con Altri Tool

Nmap si integra con l'intero arsenal di pentest:

```bash
# Export per Metasploit
nmap -sV -oX scan.xml target
# In msfconsole: db_import scan.xml

# Genera target list per Nikto
nmap -p 80,443 --open -oG - 192.168.1.0/24 | grep "80/open" | cut -d " " -f 2 > web_targets.txt
nikto -h web_targets.txt

# Feed per Nuclei
nmap -p 80,443,8080 --open -oG - 192.168.1.0/24 | awk '/Up/{print $2}' | httpx | nuclei
```

## Performance e Ottimizzazione

### Scansioni Massive su Reti Enterprise

Per subnet /16 o superiori, ottimizza parallelismo e timing:

```bash
# Scansione veloce su rete grande
nmap -sS -T4 --min-hostgroup 256 --min-parallelism 100 10.0.0.0/16 -oA enterprise_scan

# Discovery first, then targeted scan
nmap -sn -T4 10.0.0.0/16 -oG alive.txt
grep "Up" alive.txt | cut -d " " -f 2 > targets.txt
nmap -sV -T4 -iL targets.txt --top-ports 1000 -oA service_scan
```

### Rate Limiting per Evitare Ban

```bash
# Max 100 pacchetti al secondo
nmap --max-rate 100 target

# Min 10 pacchetti (evita stall)
nmap --min-rate 10 target

# Combinato per scansioni controllate
nmap --min-rate 50 --max-rate 200 -T3 192.168.1.0/24
```

### Resume Scansioni Interrotte

```bash
# Salva progresso
nmap -sV -p- target -oA long_scan --resume long_scan.nmap

# Riprendi dopo interruzione
nmap --resume long_scan.nmap
```

## Troubleshooting

### Errore: "Operation not permitted"

```bash
# Problema: scansione senza privilegi
nmap -sS target
# Starting Nmap... Couldn't open a raw socket

# Fix: usa sudo
sudo nmap -sS target
```

### Scansioni Lente

```bash
# Problema: timeout su network congestionato
# Fix: aumenta parallelismo e riduci retry
nmap -T4 --min-parallelism 100 --max-retries 1 target
```

### Host Risulta Down ma è Attivo

```bash
# Problema: firewall blocca probe ICMP
# Fix: skip host discovery
nmap -Pn target

# Alternativa: probe su porte note aperte
nmap -PS22,80,443 target
```

### Output Vuoto su Porte Note

```bash
# Problema: firewall stateful blocca SYN scan
# Fix: usa TCP connect o ACK scan
nmap -sT target
nmap -sA target  # Mappa regole firewall
```

## FAQ

**Come scansiono tutte le porte velocemente?**

Usa `-p-` con timing aggressivo: `nmap -p- -T4 --min-rate 1000 target`. Su reti affidabili ottieni risultati in 2-3 minuti.

**Qual è la differenza tra -sS e -sT?**

`-sS` (SYN scan) non completa l'handshake TCP, è più veloce e meno loggato. `-sT` completa la connessione, funziona senza root ma lascia più tracce nei log.

**Posso usare nmap senza essere rilevato?**

Rilevamento zero è impossibile. Puoi ridurre le probabilità con: timing lento (`-T1`), decoy (`-D`), frammentazione (`-f`), idle scan (`-sI`).

**Come esporto i risultati per il report finale?**

Usa `-oA basename` per generare tutti i formati. L'XML può essere convertito in HTML con `xsltproc` o importato in [Dradis](https://hackita.it/articoli/dradis-reporting).

**Nmap può fare vulnerability scanning?**

Sì, con NSE scripts. `--script vuln` esegue tutti i check vulnerabilità. Per assessment completi, integra con OpenVAS o [Nessus](https://hackita.it/articoli/nessus).

**Quante porte posso scansionare per secondo?**

Dipende dalla rete. In LAN gigabit, 10.000+ porte/secondo sono realistiche con `-T5`. Su internet, 100-1000/secondo per evitare rate limiting.

**Come identifico il sistema operativo?**

`nmap -O target` con privilegi root. Per risultati migliori, aggiungi `-sV` e assicurati che almeno una porta sia aperta e una chiusa.

***

*Questo articolo è a scopo educativo per attività di penetration testing autorizzate. Esegui scansioni solo su sistemi per cui hai esplicita autorizzazione scritta.*

**Risorse**: [Nmap Official Docs](https://nmap.org/docs.html) | [NSE Script Database](https://nmap.org/nsedoc/) | [GitHub](https://github.com/nmap/nmap)
