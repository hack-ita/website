---
title: 'Recon-ng: Framework OSINT Modulare per Reconnaissance Avanzata'
slug: reconng
description: 'Recon-ng è un framework OSINT modulare con interfaccia stile Metasploit. Ideale per raccolta automatizzata di domini, email e asset esterni.'
image: /Gemini_Generated_Image_w57h06w57h06w57h.webp
draft: true
date: 2026-02-22T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - osint
---

Recon-ng automatizza la raccolta di intelligence open source attraverso un framework modulare simile a Metasploit, permettendo ai penetration tester di correlare dati da decine di sorgenti pubbliche in un unico database interrogabile. Sviluppato da Tim Tomes (@LaNMaSteR53) e attivo dal 2013, Recon-ng trasforma ore di ricerca manuale in workflow scriptabili e ripetibili, integrando API commerciali (Shodan, VirusTotal, FullContact) con scraper personalizzati per costruire profili target completi durante la fase iniziale di ogni assessment.

### Cosa imparerai

Questo articolo copre l'installazione e configurazione del marketplace di moduli, gestione workspace e database SQLite integrato, tecniche di pivoting tra entità (domini→host→contatti→credenziali), creazione di resource script per automazione, integrazione con altri tool OSINT come [maltego](https://hackita.it/articoli/maltego) e [spiderfoot](https://hackita.it/articoli/spiderfoot), best practices OPSEC per evitare detection durante raccolta passiva, e strategie di export per alimentare fasi successive dell'attack chain.

## Setup e Installazione

Recon-ng richiede Python 3.6+ ed è preinstallato su Kali Linux 2020.1+. La versione corrente è **v5.1.2** (ultima release stabile). Su sistemi Debian/Ubuntu:

```bash
sudo apt update && sudo apt install recon-ng
```

Su altre distribuzioni o per installazione da sorgente:

```bash
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng
pip3 install -r REQUIREMENTS
./recon-ng
```

Verifica funzionamento con primo avvio:

```bash
recon-ng --no-analytics
```

Output atteso:

```
    _/_/_/    _/_/_/_/    _/_/_/    _/_/_/    _/      _/            _/      _/    _/_/_/
   _/    _/  _/        _/        _/      _/  _/_/    _/            _/_/    _/  _/       
  _/_/_/    _/_/_/    _/        _/      _/  _/  _/  _/  _/_/_/_/  _/  _/  _/  _/  _/_/_/
 _/    _/  _/        _/        _/      _/  _/    _/_/            _/    _/_/  _/      _/ 
_/    _/  _/_/_/_/    _/_/_/    _/_/_/    _/      _/            _/      _/    _/_/_/    

                                          /\
                                         / \\ /\
    Sponsored by...               /\  /\/  \\V  \/\
                                 / \\/ // \\\\\ \\ \/\
                                // // BLACK HILLS \/ \\
                               www.blackhillsinfosec.com

                  ____   ____   ____   ____ _____ _  ____   ____  ____
                 |____] | ___/ |____| |       |   | |____| |____| |  |
                 |      |   \_ |    | |____   |   |_|    | |  |\ |__|

                     [recon-ng v5.1.2, Tim Tomes (@LaNMaSteR53)]

[*] No modules enabled/installed.

[recon-ng][default] >
```

Flag importanti:

* `--no-analytics`: disabilita invio telemetria a Google Analytics (obbligatorio in produzione)
* `--no-version`: salta check versione remota
* `--stealth`: combina tutti i flag --no-\* per massima privacy
* `-w <workspace>`: carica workspace specifico all'avvio
* `-r <file>`: esegue resource file all'avvio

## Uso Base

Il workflow di Recon-ng segue cinque fasi: creazione workspace, installazione moduli, configurazione opzioni/chiavi API, esecuzione moduli, analisi risultati.

### Gestione Workspace

```bash
[recon-ng][default] > workspaces create tesla_recon
[recon-ng][tesla_recon] > workspaces list
[recon-ng][tesla_recon] > workspaces select default
[recon-ng][default] > workspaces delete tesla_recon
```

Ogni workspace mantiene database SQLite isolato in `~/.recon-ng/workspaces/<nome>/data.db` con schema predefinito: domains, hosts, contacts, credentials, leaks, locations, netblocks, ports, profiles, repositories, vulnerabilities. Il comando `db schema` mostra struttura completa.

### Marketplace e Installazione Moduli

Dalla versione 5.0, i moduli non sono più bundled ma scaricabili da marketplace remoto:

```bash
[recon-ng][default] > marketplace search
[recon-ng][default] > marketplace search domains-
[recon-ng][default] > marketplace info recon/domains-hosts/hackertarget
[recon-ng][default] > marketplace install recon/domains-hosts/hackertarget
[recon-ng][default] > marketplace install all  # installa tutti i moduli
```

Output `marketplace search` mostra colonne:

* **Path**: categoria/source-target/nome
* **Version**: versione modulo
* **Status**: installed/not installed
* **Updated**: data ultimo update
* **D**: ha dipendenze Python aggiuntive
* **K**: richiede API key

Categorie principali:

* **recon/**: moduli OSINT (domains-hosts, hosts-hosts, contacts-profiles, etc.)
* **discovery/**: moduli per file disclosure e info leak
* **import/**: import dati da file esterni
* **reporting/**: export risultati (csv, html, json, xlsx, xml)
* **exploitation/**: moduli per test injection (xssed database)

### Comandi Fondamentali

```bash
modules search                    # elenca moduli installati
modules load recon/domains-hosts/bing_domain_web
info                             # mostra dettagli modulo caricato
options list                     # mostra parametri configurabili
options set SOURCE tesla.com
run                              # esegue modulo
back                             # esce dal contesto modulo
show domains                     # mostra table domains nel DB
show hosts                       # mostra table hosts
db query SELECT * FROM hosts WHERE ip_address LIKE '104.%'
```

Ogni modulo opera su una **source** (input) e produce **target** (output). Ad esempio, `recon/domains-hosts/hackertarget` prende domini come source e produce host come target. Il database si popola incrementalmente permettendo pivoting.

## Gestione API Keys

Molti moduli richiedono API key di servizi terzi. Sistema unificato di gestione:

```bash
keys list                        # mostra keys configurate
keys add bing_api <YOUR_KEY>
keys delete bing_api
```

API key essenziali per pentester (con link acquisizione):

| Servizio        | Nome Key            | Costo      | Moduli Abilitati         | Note                           |
| --------------- | ------------------- | ---------- | ------------------------ | ------------------------------ |
| **Shodan**      | shodan\_api         | $59/mo     | hosts-hosts/shodan\_\*   | Essenziale per IP intelligence |
| **Censys**      | censysio\_id/secret | Free tier  | hosts-hosts/censys\_\*   | Alternative Shodan             |
| **VirusTotal**  | virustotal\_api     | Free       | hosts-domains/virustotal | Rate limit 4 req/min           |
| **BuiltWith**   | builtwith\_api      | Free       | domains-hosts/builtwith  | Tech stack fingerprinting      |
| **FullContact** | fullcontact\_api    | Free tier  | contacts-profiles/\*     | Email→social enrichment        |
| **Hunter.io**   | hunterio\_api       | Free 50/mo | domains-contacts/hunter  | Email discovery                |
| **GitHub**      | github\_api         | Free       | profiles-repositories/\* | Code/leak hunting              |

Esempio configurazione Shodan:

```bash
[recon-ng][default] > keys add shodan_api xxxxxxxxxxxxxxxxxxxxxxxxxxx
[*] Key 'shodan_api' added.
[recon-ng][default] > modules load recon/hosts-hosts/shodan_hostname
[recon-ng][default][shodan_hostname] > options set SOURCE tesla.com
[recon-ng][default][shodan_hostname] > run
```

Senza API key, molti moduli falliscono silenziosamente o producono risultati parziali. Pianificare acquisizione chiavi prima di engagement.

## Tecniche Operative per Pentesting

### Scenario 1: Domain Reconnaissance Completo

Obiettivo: enumerare attack surface di `target.com` partendo da zero.

```bash
[recon-ng][default] > workspaces create target_enum
[recon-ng][target_enum] > db insert domains domain=target.com
[recon-ng][target_enum] > marketplace install recon/domains-hosts/bing_domain_web
[recon-ng][target_enum] > marketplace install recon/domains-hosts/hackertarget
[recon-ng][target_enum] > marketplace install recon/domains-hosts/shodan_hostname
[recon-ng][target_enum] > modules load recon/domains-hosts/bing_domain_web
[recon-ng][target_enum][bing_domain_web] > run
[*] URL: https://www.bing.com/search?q=domain%3Atarget.com
[*] dev.target.com
[*] api.target.com
[*] mail.target.com
-------
SUMMARY
-------
[*] 3 total (3 new) hosts found.
```

**Output atteso**: popolazione table `hosts` con subdomain trovati. Comando `show hosts` mostra:

```
  +------------------------------------------+
  | ip_address | host                       |
  +------------------------------------------+
  |            | dev.target.com             |
  |            | api.target.com             |
  |            | mail.target.com            |
  +------------------------------------------+
```

**Pivoting automatico**: moduli successivi usano automaticamente hosts trovati come SOURCE:

```bash
[recon-ng][target_enum] > modules load recon/hosts-hosts/resolve
[recon-ng][target_enum][resolve] > run
[*] dev.target.com => 203.0.113.45
[*] api.target.com => 203.0.113.46
[*] mail.target.com => 203.0.113.47
```

**Troubleshooting**: Se moduli non trovano SOURCE automaticamente, verificare con `options list` e settare manualmente. Alcuni moduli cercano in table specifica (es. domains vs hosts).

### Scenario 2: Email Harvesting e Social Footprinting

```bash
[recon-ng][target_enum] > marketplace install recon/domains-contacts/hunter
[recon-ng][target_enum] > marketplace install recon/domains-contacts/pgp_search
[recon-ng][target_enum] > modules load recon/domains-contacts/hunter
[recon-ng][target_enum][hunter] > options set SOURCE target.com
[recon-ng][target_enum][hunter] > run
[*] john.doe@target.com (John Doe)
[*] jane.smith@target.com (Jane Smith)
-------
SUMMARY
-------
[*] 2 total (2 new) contacts found.
```

Pivoting da email a profili social:

```bash
[recon-ng][target_enum] > marketplace install recon/contacts-profiles/fullcontact
[recon-ng][target_enum] > modules load recon/contacts-profiles/fullcontact
[recon-ng][target_enum][fullcontact] > run
[*] john.doe@target.com => https://linkedin.com/in/johndoe123
[*] john.doe@target.com => https://twitter.com/johndoe
```

**Cosa fare se fallisce**: Verificare API key valida con `keys list`. Hunter.io ha rate limit 50 query/mese su piano free — superato questo, modulo ritorna empty. Fallback: usare `pgp_search` (nessuna API richiesta) o Google dorks manuali.

### Scenario 3: Credential Leak Hunting

```bash
[recon-ng][target_enum] > marketplace install recon/domains-credentials/pwnedlist
[recon-ng][target_enum] > marketplace install recon/contacts-credentials/hibp_breach
[recon-ng][target_enum] > modules load recon/contacts-credentials/hibp_breach
[recon-ng][target_enum][hibp_breach] > run
[*] john.doe@target.com => LinkedIn breach (2012)
[*] jane.smith@target.com => Adobe breach (2013)
-------
SUMMARY
-------
[*] 2 total (2 new) credentials found.
```

Il modulo `hibp_breach` usa API HaveIBeenPwned gratuita ma rate-limited. Per credenziali complete (hash password), necessario accesso a database leak come Collection #1 (offline analysis).

**Timeline realistica**: Domain recon completo (500+ subdomains) = 15-30 minuti. Email harvesting (50-200 contatti) = 10-20 minuti. Leak checking (200 email) = 30-45 minuti con rate limits.

## Tecniche Avanzate

### Resource Scripts per Automazione

Resource file permette batch execution di comandi. Creare `recon_workflow.rc`:

```
workspaces create auto_target
db insert domains domain=target.com
marketplace install recon/domains-hosts/bing_domain_web
marketplace install recon/domains-hosts/hackertarget
marketplace install recon/hosts-hosts/resolve
marketplace install recon/domains-contacts/hunter
modules load recon/domains-hosts/bing_domain_web
run
modules load recon/domains-hosts/hackertarget
run
modules load recon/hosts-hosts/resolve
run
modules load recon/domains-contacts/hunter
run
show hosts
show contacts
exit
```

Esecuzione:

```bash
recon-ng -r recon_workflow.rc
```

Output viene stampato su stdout. Per logging:

```bash
recon-ng -r recon_workflow.rc | tee recon_output.txt
```

**Recording interattivo** per creare resource file:

```bash
[recon-ng][default] > script record myworkflow.rc
[recon-ng][default] > # esegui comandi normalmente
[recon-ng][default] > script stop
```

### Moduli Custom e Integrazione Python

Struttura base modulo Recon-ng (salvare in `~/.recon-ng/modules/recon/custom-module.py`):

```python
from recon.core.module import BaseModule

class Module(BaseModule):
    meta = {
        'name': 'Custom Subdomain Bruteforcer',
        'author': 'Your Name',
        'version': '1.0',
        'description': 'Brute force subdomains using custom wordlist',
        'required_keys': [],
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
        'options': (
            ('wordlist', '/path/to/wordlist.txt', True, 'path to subdomain wordlist'),
        ),
    }

    def module_run(self, domains):
        wordlist = open(self.options['wordlist']).read().splitlines()
        for domain in domains:
            for word in wordlist:
                subdomain = f"{word}.{domain}"
                # logic per check DNS resolution
                self.insert_hosts(host=subdomain, ip_address=resolved_ip)
```

Reload moduli dopo modifica:

```bash
[recon-ng][default] > modules reload
[recon-ng][default] > modules load recon/custom-module
```

### Multi-Stage Pivoting Completo

Chain completa domains→hosts→IPs→ports→vulnerabilities:

```bash
# Stage 1: Domain enumeration
modules load recon/domains-hosts/bing_domain_web
run
modules load recon/domains-hosts/certificate_transparency
run

# Stage 2: IP resolution e geolocation
modules load recon/hosts-hosts/resolve
run
modules load recon/hosts-hosts/ipinfodb
run

# Stage 3: Port scanning (se Shodan API disponibile)
modules load recon/hosts-ports/shodan_ip
run

# Stage 4: Tech stack fingerprinting
modules load recon/hosts-hosts/builtwith
run

# Stage 5: Vuln correlation
modules load recon/hosts-vulnerabilities/xssed
run
```

Ogni stage alimenta il successivo automaticamente tramite database condiviso. Query intermedia per verificare progressione:

```bash
db query SELECT COUNT(*) FROM hosts
db query SELECT host, ip_address FROM hosts WHERE ip_address IS NOT NULL
```

## Integrazione Toolchain

### Recon-ng → Nmap

Export host list per active scanning:

```bash
[recon-ng][target] > db query SELECT DISTINCT ip_address FROM hosts WHERE ip_address IS NOT NULL
# copia IP in file targets.txt
```

```bash
nmap -iL targets.txt -sV -sC -oA nmap_results
```

### Recon-ng → Maltego

Export database in formato Maltego-compatible:

```bash
[recon-ng][target] > modules load reporting/xml
[recon-ng][target][xml] > options set FILENAME target_maltego.xml
[recon-ng][target][xml] > run
```

Import XML in Maltego tramite Transform personalizzato o parsing manuale. Alternative: export CSV e import via Maltego CSV import.

### Recon-ng ← TheHarvester

TheHarvester produce output facilmente parsabile. Script Python per import:

```python
import json
import sqlite3

# Parse theHarvester JSON output
with open('harvester_output.json') as f:
    data = json.load(f)

# Connect to Recon-ng database
conn = sqlite3.connect('~/.recon-ng/workspaces/target/data.db')
cursor = conn.cursor()

# Insert emails
for email in data['emails']:
    cursor.execute("INSERT INTO contacts (email) VALUES (?)", (email,))

# Insert hosts
for host in data['hosts']:
    cursor.execute("INSERT INTO hosts (host) VALUES (?)", (host,))

conn.commit()
conn.close()
```

### Comparazione con Alternative

| Tool             | Modularità | Database         | API Integration | Learning Curve | Use Case Ideale                         |
| ---------------- | ---------- | ---------------- | --------------- | -------------- | --------------------------------------- |
| **Recon-ng**     | ★★★★★      | SQLite integrato | 30+ servizi     | Media          | Reconnaissance strutturato e ripetibile |
| **TheHarvester** | ★☆☆☆☆      | Nessuno          | 10+ servizi     | Bassa          | Quick email/subdomain enum              |
| **SpiderFoot**   | ★★★★☆      | Proprio          | 200+ servizi    | Media          | Automated scanning con GUI              |
| **Maltego**      | ★★★★★      | Graph-based      | 50+ transforms  | Alta           | Visual link analysis                    |
| **FOCA**         | ★★☆☆☆      | Nessuno          | Metadata only   | Bassa          | Document metadata extraction            |

**Quando usare Recon-ng vs alternative**: Scegliere Recon-ng quando serve correlazione dati cross-source, workflow ripetibili/scriptabili, storage persistente tra sessioni. Preferire TheHarvester per quick one-shot enumeration. Maltego per investigazioni visuali complesse. SpiderFoot per massima automation con minimal configuration.

## Attack Chain Completa: Recon → Initial Access

### Fase 1: Passive Reconnaissance (Recon-ng)

**Timeline**: Day 1, 4-6 ore

```bash
workspaces create corp_target
db insert domains domain=targetcorp.com
# Esegui full recon workflow
marketplace install all
# Domain/subdomain enumeration
modules load recon/domains-hosts/bing_domain_web
run
modules load recon/domains-hosts/certificate_transparency
run
# IP resolution
modules load recon/hosts-hosts/resolve
run
# Contact harvesting
modules load recon/domains-contacts/hunter
run
# Tech fingerprinting
modules load recon/hosts-hosts/builtwith
run
```

**Output**: 347 subdomains, 89 IP univoci, 52 email corporate, stack tecnologici (Apache/2.4, PHP/7.4, WordPress 5.9).

### Fase 2: Active Reconnaissance (Nmap + manual)

**Timeline**: Day 1-2, 2-3 ore

Export target da Recon-ng:

```bash
db query SELECT ip_address FROM hosts WHERE ip_address IS NOT NULL
# Risultato: 89 IP
```

```bash
nmap -iL targets.txt -p- -sV -sC --script vuln -oA full_scan
```

Identify vulnerable services: WordPress 5.9 (CVE-2022-21661), unpatched Apache, exposed Git directories su `dev.targetcorp.com/.git`.

### Fase 3: Initial Access (Exploitation)

**Timeline**: Day 2, 1-2 ore

Sfruttare `.git` exposure per source code disclosure:

```bash
wget -r http://dev.targetcorp.com/.git
git-dumper http://dev.targetcorp.com/.git targetcorp_source
```

Source code contiene credenziali database hardcoded in `config.php`. Accesso database → credential stuffing su `mail.targetcorp.com` (Microsoft 365) usando [https://hackita.it/articoli/crackmapexec](https://hackita.it/articoli/crackmapexec).

### Fase 4: Privilege Escalation (BloodHound + Mimikatz)

Dopo access iniziale, pivoting interno non coperto da Recon-ng ma da tool post-exploitation. Recon-ng rimane fondamentale per mappatura iniziale che guida tutti gli step successivi.

## Detection & Evasion OPSEC

### Blue Team Monitoring

Recon-ng è **tool passivo OSINT** — non genera traffico diretto verso target (eccetto moduli "discovery"). Tuttavia, alcuni indicatori rilevabili:

**Log Entries Target-Side**:

* Nessun log diretto su server target (moduli "recon")
* Possibili log su moduli "discovery" (es. `discovery/info_disclosure/interesting_files` che probes HTTP)
* Accessi ripetuti a Certificate Transparency logs da stesso IP (correlabile)

**Third-Party Service Logs**:

* Shodan query logs (associati ad API key)
* Hunter.io access logs
* FullContact query history

**Network-Level Detection**:

* Traffic patterns verso API endpoint specifici (api.shodan.io, api.hunter.io) con frequenza anomala
* User-Agent string default: `python-requests/X.X.X`
* Query patterns prevedibili (sequential subdomain probing via CT logs)

### Event ID e Telemetry

Recon-ng locale non genera Event ID Windows (tool Linux-based). Se eseguito da Windows via WSL:

* **Event ID 1**: Process Creation (wsl.exe → python3)
* **Event ID 3**: Network Connection (verso API endpoints)
* **Event ID 22**: DNS Query (shodan.io, hunter.io, etc.)

Su target Windows, moduli discovery generano:

* **Event ID 5145**: Network share accessed (se probing SMB)
* **IIS logs**: GET requests a path insoliti (/.git, /admin, etc.)

### Tecniche Evasion

**1. API Key Rotation**

Distribuire query su multiple API key per eludere rate limit e correlation:

```bash
keys add shodan_api_1 KEY1
keys add shodan_api_2 KEY2
# Script per alternare key tra run
```

**2. Request Throttling**

Modificare moduli per introdurre delay randomizzati:

```python
import time
import random

def module_run(self, hosts):
    for host in hosts:
        time.sleep(random.uniform(2, 5))  # 2-5 sec delay
        # processing logic
```

**3. User-Agent Spoofing**

Modificare default User-Agent nei moduli che fanno HTTP requests. Edit `~/.recon-ng/core/framework.py`:

```python
self.headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}
```

**4. Proxy Chaining**

Forzare tutto il traffico tramite Tor/VPN:

```bash
proxychains4 recon-ng
```

Configurare proxychains.conf:

```
[ProxyList]
socks5  127.0.0.1 9050
```

**5. Distributed Reconnaissance**

Eseguire Recon-ng da multiple VPS con API key differenti, poi mergiare database:

```bash
# VPS 1
recon-ng -w target
# esegui moduli batch 1

# VPS 2
recon-ng -w target
# esegui moduli batch 2

# Merge databases localmente
sqlite3 target_vps1.db ".dump hosts" > merge.sql
sqlite3 target_main.db < merge.sql
```

## Performance & Scaling

### Single Target vs Multi-Target

**Single target** (1 dominio):

* Full enumeration: 20-40 minuti
* 200-500 subdomain trovati in media
* 50-150 email
* Database size: 5-15 MB

**Multi-target** (50+ domini):

* Usare loop script bash:

```bash
#!/bin/bash
for domain in $(cat targets.txt); do
  recon-ng -C "workspaces create $domain; db insert domains domain=$domain; modules load recon/domains-hosts/bing_domain_web; run; exit"
done
```

* Timeline: 2-3 ore per 50 domain
* Attenzione a API rate limits globali

### Consumo Risorse

Recon-ng è estremamente lightweight:

* **RAM**: 50-100 MB durante esecuzione
* **CPU**: \<5% su hardware moderno
* **Disk**: \<50 MB per workspace completo
* **Network**: 10-50 KB/s (dipende da API chiamate)

Bottleneck principale: **rate limits API**, non performance tool.

### Ottimizzazione Pratica

**Parallelizzazione moduli non-dipendenti**:

```bash
# Esegui multiple istanze Recon-ng con workspace separati
recon-ng -w target_batch1 -C "modules load recon/domains-hosts/bing_domain_web; run; exit" &
recon-ng -w target_batch2 -C "modules load recon/domains-contacts/hunter; run; exit" &
wait
# Merge databases dopo completion
```

**Caching API responses** per evitare ripetute query:

Alcuni moduli implementano caching in `~/.recon-ng/cache/`. Verificare e pulire periodicamente:

```bash
ls -lh ~/.recon-ng/cache/
# delete cache vecchia
rm -rf ~/.recon-ng/cache/*
```

## Troubleshooting

### Errore: "No module installed"

**Causa**: Marketplace non sincronizzato o moduli non installati.

**Fix**:

```bash
marketplace refresh
marketplace install all
```

### Errore: "Invalid API key"

**Causa**: API key errata, scaduta, o rate limit superato.

**Fix**:

```bash
keys list  # verifica key presente
keys delete <service>_api
keys add <service>_api NEW_KEY
# Testa con singolo modulo
modules load recon/hosts-hosts/shodan_hostname
options set SOURCE test.com
run
```

### Moduli non trovano SOURCE

**Causa**: Table database vuota o nome colonna mismatch.

**Fix**:

```bash
show <table>  # verifica presenza dati
db insert <table> <column>=<value>
# Esempio:
db insert domains domain=test.com
```

### Database corrupted

**Causa**: Crash durante write o filesystem issue.

**Fix**:

```bash
# Backup e ricreazione
cp ~/.recon-ng/workspaces/target/data.db ~/.recon-ng/workspaces/target/data.db.backup
rm ~/.recon-ng/workspaces/target/data.db
# Recon-ng ricrea DB vuoto all'avvio
recon-ng -w target
```

### Performance lenta su large dataset

**Causa**: SQLite performance degrada con 10k+ records senza indici.

**Fix**:

```bash
# Aggiungi indici manualmente
sqlite3 ~/.recon-ng/workspaces/target/data.db
CREATE INDEX idx_hosts_domain ON hosts(host);
CREATE INDEX idx_contacts_email ON contacts(email);
.exit
```

## FAQ

**Q: Recon-ng è rilevabile dai sistemi di detection target?**

A: No per moduli "recon" (OSINT puro). Sì per moduli "discovery" che fanno active probing. Attenzione a moduli che interrogano direttamente target (es. `interesting_files`).

**Q: Posso usare Recon-ng senza API key?**

A: Sì, ma risultati limitati. Moduli senza simbolo "K" in `marketplace search` funzionano senza key. Per reconnaissance professionale, minimo Shodan + VirusTotal consigliati.

**Q: Come condividere workspace tra team member?**

A: Export database e import in workspace remoto:

```bash
# Team member 1
cp ~/.recon-ng/workspaces/target/data.db /shared/folder/

# Team member 2
mkdir ~/.recon-ng/workspaces/target
cp /shared/folder/data.db ~/.recon-ng/workspaces/target/
```

O usare export reporting (CSV/JSON) e re-import.

**Q: Differenza tra Recon-ng v4 e v5?**

A: Versione 5.x introduce marketplace separato (moduli non più bundled), refactoring options system, rimozione `use` command (ora `modules load`). Workflow fondamentalmente identico ma sintassi diversa.

**Q: Recon-ng supporta IPv6?**

A: Parziale. Alcuni moduli resolution supportano AAAA records. Coverage non completa come IPv4.

**Q: Posso integrare Recon-ng in CI/CD pipeline?**

A: Sì. Usare resource scripts + output parsing:

```bash
recon-ng -r workflow.rc > output.txt
python3 parse_output.py output.txt
```

**Q: Recon-ng loggа attività?**

A: No di default. Usare `spool` command per logging sessione:

```bash
spool start session.log
# esegui comandi
spool stop
```

## Cheat Sheet Finale

```bash
# Setup iniziale
recon-ng --no-analytics
workspaces create <name>

# Gestione moduli
marketplace search <keyword>
marketplace install <path>
marketplace install all
modules load <path>
modules reload

# Configurazione
options set SOURCE <value>
options set <param> <value>
keys add <service>_api <key>
goptions set TIMEOUT 30

# Database operations
db insert <table> <column>=<value>
show <table>
db query <SQL>
db schema
db delete <table> <rowid>

# Execution
run
back
info

# Reporting
modules load reporting/csv
options set FILENAME output.csv
run

# Automation
script record <file.rc>
script execute <file.rc>
recon-ng -r <file.rc>
spool start <logfile>

# Common workflows
# Domain enum
db insert domains domain=target.com
modules load recon/domains-hosts/bing_domain_web
run

# Email harvest
modules load recon/domains-contacts/hunter
run

# IP resolution
modules load recon/hosts-hosts/resolve
run

# Exit
exit
```

## Perché è rilevante oggi (2026)

Recon-ng mantiene valore in era di automation avanzata perchè unifica API disparate in singolo workflow consistente — capacità che tool moderni come SpiderFoot replicano ma con overhead maggiore. La modularità permette customizzazione granulare impossibile in GUI-based tool, fondamentale per OPSEC-conscious engagements dove ogni query API deve essere controllata. Database SQLite facilita correlation cross-source e historical tracking tra assessment ripetuti nel tempo. Integrazione Python nativa rende scripting extension naturale per team con pipeline DevSecOps. Footprint minimale (no dependencies Java/Node) mantiene Recon-ng deployment-friendly in ambienti restricted.

## Differenza rispetto ad alternative

| Caratteristica   | Recon-ng                       | SpiderFoot                           | Maltego                        |
| ---------------- | ------------------------------ | ------------------------------------ | ------------------------------ |
| **Modularità**   | Alta (100+ moduli)             | Media (200+ sources, meno granulari) | Alta (transform-based)         |
| **Database**     | SQLite integrato               | Proprio engine                       | Graph database                 |
| **Interfaccia**  | CLI only                       | GUI + API + CLI                      | GUI primaria                   |
| **API Coverage** | 30+ servizi                    | 200+ (molti passivi)                 | 50+ via transforms             |
| **Scripting**    | Python-native                  | Limitato (API REST)                  | JavaScript/Maltego API         |
| **OPSEC**        | Configurabile a livello modulo | Batch mode limitato                  | Request visible via transforms |

**Quando usare Recon-ng**: Workflow scriptabili, correlation multi-source, storage persistente tra sessioni, team già skillato su Python, budget API limitato (free tier sufficienti).

**Quando evitare**: Preferire visual correlation (→ Maltego), need GUI per stakeholder demos (→ SpiderFoot), time-critical one-shot enum (→ TheHarvester).

## Hardening / Mitigazione

Recon-ng è tool OSINT passivo — difesa non blocca tool ma riduce information leakage:

**Minimizzare footprint pubblico**:

* Rimuovere subdomains inattivi da DNS records
* Configurare Certificate Transparency opt-out (dove applicabile)
* Mascherare ownership info in WHOIS (privacy guard)
* Segregare staging/dev environment da internet pubblico

**Email harvesting prevention**:

* No email pubbliche su website (usare contact form)
* SPF/DKIM/DMARC correttamente configurati (riduce spoofing ma non harvesting)
* Monitorare leak tramite HaveIBeenPwned API aziendale

**API service restriction**:

* Blocc Shodan crawler a livello firewall (detectabile via User-Agent)
* Rate limiting su servizi pubblici per ridurre automated scraping
* CAPTCHA su endpoint sensibili

**Non mitigabile**:

* Public records (WHOIS, BGP, ASN data)
* Certificate Transparency logs (mandatorio per CA)
* Social media footprint (policy aziendale)

## OPSEC e Detection

**Rumorosità**: Bassa. Recon-ng fa primarily API calls a servizi terzi, non genera traffico diretto verso target.

**Event ID generabili**: Nessuno su target Windows (tool Linux). Su attacker machine:

* Linux: `/var/log/syslog` entries per process spawn
* Network logs: connessioni API endpoint (api.shodan.io, hunter.io)

**Riduzione visibilità**:

1. Eseguire da infrastructure non-attributable (VPS throwaway, Tor exit nodes)
2. Rate-limiting artificiale nelle API calls (editing moduli)
3. User-Agent rotation
4. Distribuzione query su multiple API accounts
5. Evitare moduli "discovery" su network monitored

**Cleanup**: Recon-ng non lascia artefatti su target. Cleanup locale:

```bash
# Rimozione workspace
workspaces delete <name>
# Rimozione cache API
rm -rf ~/.recon-ng/cache/*
# Rimozione config
rm -rf ~/.recon-ng/keys.db
```

***

**Disclaimer**: Recon-ng deve essere utilizzato esclusivamente su sistemi e domini per i quali si possiede autorizzazione esplicita scritta. L'uso non autorizzato di strumenti OSINT può violare policy aziendali, termini di servizio di API provider, e leggi sulla privacy (GDPR, CCPA). Repository ufficiale: [https://github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng)

Vuoi supportare HackIta? Visita [https://hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [https://hackita.it/servizi](https://hackita.it/servizi).
