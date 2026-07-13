---
title: 'Shodan: Guida a Dork, Query e Filtri Avanzati (2026)'
slug: shodan
description: 'Shodan: dork pratici per MongoDB, IoT, ICS e CVE, filtri avanzati, CLI, API, InternetDB e cheat sheet completo per reconnaissance passiva e pentest (2026).'
image: /shodan-search-engine-guide.webp
draft: false
date: 2026-02-25T00:00:00.000Z
categories:
  - networking
subcategories:
  - servizi
tags:
  - osint
---

# Shodan: guida al motore di ricerca per dispositivi e servizi esposti online

## Cos'è Shodan

Shodan è il motore di ricerca che indicizza dispositivi e servizi esposti su Internet, non pagine web. Scansiona continuamente l'intero spazio IPv4 pubblico (4.3 miliardi di indirizzi) raccogliendo banner, certificati, metadata e servizi esposti: porte [TCP](https://hackita.it/articoli/tcp)/[UDP](https://hackita.it/articoli/udp) aperte come webcam, router, server MongoDB, sistemi SCADA industriali, database senza autenticazione, pannelli di amministrazione esposti.

Il database contiene snapshot storici: vedi non solo lo stato attuale di un dispositivo, ma anche quando è apparso online e quali vulnerabilità sono state patchate (o ignorate). Utile per threat intelligence, attack surface monitoring, ricerca honeypot.

A differenza di scan attivi (nmap), Shodan è completamente passivo dal tuo punto di vista: interroghi un database già popolato, non tocchi il target. Per reconnaissance stealth, non ha eguali.

Shodan si colloca nella kill chain in **Passive Reconnaissance**, prima dell'active scanning, quando vuoi intelligence senza contatto diretto col target.

***

**Quando usarlo:** asset discovery esterno, ricerca CVE a scala internet, attack surface monitoring, reconnaissance passiva pre-engagement.

**Quando NON usarlo:** hai bisogno di dati in tempo reale (Shodan aggiorna ogni \~28-30 giorni, usa nmap), o serve deep analysis su certificati TLS (meglio Censys).

### Come funziona la scansione

Shodan usa crawler distribuiti che scansionano in modo continuo circa 1.500 porte su tutto lo spazio IPv4. Per ogni porta aperta, il crawler invia una richiesta minima al servizio (banner grabbing) e salva la risposta grezza: è quello il "banner". Non naviga siti, non segue link — si limita a bussare a ogni porta e registrare cosa risponde.

Protocolli coperti: HTTP/HTTPS, FTP, SSH, Telnet, SNMP, SMTP, IMAP, RTSP, Modbus, S7comm, e decine di altri, inclusi i principali protocolli industriali (ICS/SCADA).

I dati raccolti vengono poi indicizzati e resi ricercabili tramite i filtri. Il ciclo di scansione completo dell'intero IPv4 richiede circa 28-30 giorni, ma le porte più popolari (80, 443, 22) vengono ripassate più di frequente.

### Anatomia di un risultato Shodan

Ogni host restituito porta con sé diversi campi utili da saper leggere:

| **Campo**             | **Cosa contiene**                                                          |
| --------------------- | -------------------------------------------------------------------------- |
| `ip_str`              | Indirizzo IP pubblico                                                      |
| `port`                | Porta aperta trovata                                                       |
| `hostnames`           | Hostname associati via reverse DNS                                         |
| `org` / `isp`         | Proprietario del blocco IP / ISP                                           |
| `asn`                 | Numero di sistema autonomo                                                 |
| `location`            | Country/city/coordinate (approssimati, da IP geolocation)                  |
| `data`                | Il banner grezzo restituito dal servizio                                   |
| `product` / `version` | Software e versione rilevati (quando disponibili)                          |
| `vulns`               | CVE associate (verified = confermata, unverified = dedotta dalla versione) |
| `tags`                | Etichette Shodan (es. `honeypot`, `cloud`, `iot`)                          |
| `ssl`                 | Dettagli certificato, se il servizio usa TLS                               |
| `timestamp`           | Quando è stato osservato l'ultima volta                                    |

**Nota sulle `vulns`:** una vulnerabilità "unverified" è dedotta solo dalla versione del software — può generare falsi positivi (es. distro enterprise con patch backportate ma stesso numero di versione). Va sempre verificata.

***

## Setup e Accesso

### Piani e prezzi (verificati 2026)

```
FREE: query limitate, nessun filtro avanzato, max 100 risultati/query
MEMBERSHIP: $49 one-time (lifetime) — sblocca filtri, CLI, 100 query credit/mese
SMALL BUSINESS: da $359/mese — query credit alti, filtro "vuln"
CORPORATE: pricing custom — filtro "tag", monitoraggio esteso
```

**Nota:** il prezzo Membership cambia periodicamente (promo a $5-9 ricorrono ogni anno, tienile d'occhio). Verifica sempre su [account.shodan.io/billing](https://account.shodan.io/billing) prima di comprare.

### Shodan CLI installation

```bash
pip install shodan

# Initialize con API key
shodan init YOUR_API_KEY

# Verify
shodan info
```

**Output:**

```
Query credits available: 100
Scan credits available: 100
API key: *********************ABC123
```

### API key location

```
Web → Account → API Key
```

```bash
export SHODAN_API_KEY="abc123..."
```

```python
import shodan
api = shodan.Shodan("abc123...")
```

***

## Query di base

### Esempio: database MongoDB esposti

```
Search: "MongoDB Server Information" port:27017 -authentication
```

```
Total results: 47,832

IP: 203.0.113.50
Port: 27017
Organization: Amazon AWS
Location: United States, Virginia
Banner:
  MongoDB Server Information
  Version: 4.2.8
  databases: ["admin", "production_db", "user_data"]

[No authentication required]
```

🎓 **Nota:** decine di migliaia di MongoDB senza autenticazione. Cliccando sull'IP vedi dettagli completi e storico.

### Filtri principali

| **Filtro**  | **Esempio**            | **Risultato**            |
| ----------- | ---------------------- | ------------------------ |
| `port:`     | `port:22`              | Server SSH               |
| `country:`  | `country:IT`           | Dispositivi in Italia    |
| `city:`     | `city:Milan`           | Localizzati a Milano     |
| `org:`      | `org:"Google"`         | IP di proprietà Google   |
| `hostname:` | `hostname:example.com` | Dominio specifico        |
| `product:`  | `product:Apache`       | Server web Apache        |
| `version:`  | `version:2.4.41`       | Versione specifica       |
| `vuln:`     | `vuln:CVE-2014-0160`   | Vulnerabile a Heartbleed |
| `os:`       | `os:Windows`           | Sistemi Windows          |

```
apache port:443 country:US
→ Server Apache HTTPS negli USA

mongodb port:27017 -authentication city:London
→ MongoDB senza protezione a Londra
```

### Filtri avanzati

| **Filtro**                | **Esempio**                           | **Uso**                                                                              |
| ------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------ |
| `after:` / `before:`      | `after:"01/01/2026"`                  | Limita per data di scansione                                                         |
| `net:`                    | `net:192.168.1.0/24`                  | Cerca in un range/CIDR                                                               |
| `has_vuln:`               | `has_vuln:true`                       | Solo host con almeno una CVE associata                                               |
| `has_screenshot:`         | `has_screenshot:true`                 | Solo host con screenshot disponibile                                                 |
| `tag:`                    | `tag:honeypot`                        | Filtra per etichetta Shodan (piano avanzato)                                         |
| `ssl.cert.subject.cn:`    | `ssl.cert.subject.cn:"*.example.com"` | Subdomain enum via certificato SSL                                                   |
| `http.title:`             | `http.title:"Admin Panel"`            | Cerca nel titolo della pagina HTTP                                                   |
| `isp:`                    | `isp:"Fastweb"`                       | Filtra per ISP                                                                       |
| `http.favicon.hash:`      | `http.favicon.hash:-247388890`        | Trova applicazioni con lo stesso favicon (fingerprint app, molto usato in web recon) |
| `ssl.jarm:` / `ssl.ja3s:` | `ssl.jarm:"07d..."`                   | Fingerprinting TLS del server (identifica configurazioni/tool identici)              |
| `http.waf:`               | `http.waf:cloudflare`                 | Filtra per WAF rilevato (cloudflare, akamai, f5...)                                  |
| `http.component:`         | `http.component:wordpress`            | Filtra per tecnologia/CMS rilevata (wordpress, jquery, php...)                       |

### Faceting — vedere il quadro d'insieme

Prima di scendere nei singoli host, i facet aggregano i risultati e mostrano i pattern (porte più comuni, paesi, prodotti). Utile per non perdersi tra migliaia di risultati:

```bash
shodan stats --facets country apache
```

```
Top 10 Results for Facet: country
US    8,336,729
DE    4,512,172
CN    1,470,434
```

```bash
shodan stats --facets ssl.version net:78.13.0.0/16
```

Mostra la distribuzione delle versioni SSL/TLS in quel range — utile per individuare protocolli obsoleti (SSLv2/v3) da bonificare.

**Approccio consigliato:** prima `shodan count` per stimare la scala, poi `shodan stats --facets` per vedere i pattern, infine query mirata per i singoli host.

### Shodan CLI search

```bash
shodan search "apache country:IT"
```

```
203.0.113.10    Apache httpd 2.4.41    Italy
203.0.113.20    Apache httpd 2.4.38    Italy
203.0.113.30    Apache httpd 2.2.22    Italy [OBSOLETO!]
```

***

## GEO: leggere paese, città, ASN e cluster geografici

`country` e `city` filtrano per posizione dichiarata dal geolocation IP, che si basa su registrazione RIR — non sempre coincide con l'ubicazione fisica reale (specialmente per cloud provider).

`org` filtra per proprietario dell'IP block (es. "Amazon", "Fastweb") — utile ma un'azienda può avere infrastruttura sparsa su più org (CDN, cloud terzi). Quando `org` non basta, usa `asn:` per il numero di sistema autonomo esatto:

```
asn:AS16509
→ Tutti gli host nel blocco Amazon (ASN preciso)
```

**Mappare esposizioni in Italia:**

```
country:IT port:502
→ Dispositivi Modbus (industriali) esposti in Italia
```

**Shodan Maps** (funzione web) mostra i risultati su mappa geografica — utile per vedere cluster industriali o cloud concentrati in una regione (es. PLC Siemens concentrati in Germania e Italia).

**Quando usare cosa:**

* `country`/`city` → visione macro, primo filtro
* `org` → quando conosci il nome del cloud/hosting provider
* `asn` → quando `org` è ambiguo o l'azienda ha multipli ASN

***

## Tecniche operative

### Scenario 1 — Asset discovery per organizzazione

**Contesto:** pentest per un cliente. Serve mappare tutti gli asset esterni.

```
org:"Example Corp"
```

```
Total: 156 hosts

IP: 203.0.113.10
  Port 80: Apache httpd
  Port 443: Apache httpd (SSL cert: *.example.com)
  Port 22: OpenSSH 8.2

IP: 203.0.113.20
  Port 3306: MySQL 5.7.38
```

**Export:**

```bash
shodan search 'org:"Example Corp"' --fields ip_str,port,product --separator , > assets.csv
```

**Analisi:** 156 host trovati (il cliente dichiarava "\~50" = inventario incompleto). MySQL esposto su IP pubblico = priorità alta.

### Scenario 2 — Vulnerability hunting basato su CVE

```bash
shodan search vuln:CVE-2021-44228
```

```
Total results: 183,492 host potenzialmente vulnerabili

IP: 198.51.100.10
  Product: Apache Tomcat 9.0.50
  Port: 8080
  Vulnerability: CVE-2021-44228 (Log4Shell)
  Severity: CRITICAL (CVSS 10.0)
```

Per la verifica automatica delle CVE trovate, vedi [Nuclei](https://hackita.it/articoli/nuclei).

### Scenario 3 — Industrial Control Systems (ICS/SCADA)

```
"Siemens SIMATIC" port:102
```

```
Total: 2,847 Siemens PLC esposti

IP: 192.0.2.50
  Product: Siemens SIMATIC S7-1200
  Port: 102 (protocollo S7comm)
  Location: Italy, Milan
```

**Altre query ICS:**

```
port:502          # Modbus
port:47808         # BACnet (building automation)
"Allen-Bradley" port:44818   # Rockwell
scada country:US
```

***

## Tecniche avanzate

### Dorking

```
"Server: SQ-WEBCAM" -auth          # Webcam senza password
product:Redis -authentication       # Redis non protetto
port:9200 "cluster_name"            # Elasticsearch aperto
"default password" port:80          # Credenziali default
ssl.cert.subject.cn:"*.company.com" # Subdomain via certificato SSL
```

### Honeypot detection

```python
import shodan
api = shodan.Shodan(API_KEY)
result = api.host('target-ip')

if 'tags' in result and 'honeypot' in result['tags']:
    print("[!] Possibile honeypot")

honeypot_orgs = ['Censys', 'Shodan', 'ShadowServer', 'GreyNoise']
if result.get('org') in honeypot_orgs:
    print("[!] Organizzazione di ricerca")
```

### Integrazione con Metasploit

```bash
shodan search 'product:"ProFTPD" version:1.3.5' --fields ip_str > proftpd_targets.txt
```

```bash
msfconsole
use exploit/unix/ftp/proftpd_133c_backdoor
set RHOSTS file:/path/to/proftpd_targets.txt
run
```

### Monitoraggio via API

```python
import shodan, time

api = shodan.Shodan(API_KEY)
query = 'mongodb port:27017 country:IT -authentication'
last_count = 0

while True:
    results = api.search(query)
    current = results['total']
    if current > last_count:
        print(f"[!] {current - last_count} nuove esposizioni MongoDB")
    last_count = current
    time.sleep(3600)
```

### Scenario 4 — Cloud asset discovery (AWS/Azure/GCP)

**Contesto:** il cliente usa AWS ma non sa esattamente cosa è esposto.

```
org:"Amazon.com" ssl.cert.subject.cn:"*.client-company.com"
```

```
IP: 18.204.55.123 (AWS us-east-1)
  Port 443: nginx
  SSL cert: app.client-company.com

IP: 52.44.199.87 (AWS us-west-2)
  Port 22: OpenSSH 8.2
  Port 3000: Node.js API server
```

**Analisi:** Node.js su porta 3000 esposto = server di sviluppo in produzione? Deployment multi-regione (us-east + us-west).

**Azure:** `org:"Microsoft" hostname:*.azurewebsites.net`
**GCP:** `org:"Google" hostname:*.cloud.goog`

**Se non trovi nulla:**

1. Nome organizzazione diverso → prova per ASN: `asn:AS16509` (Amazon)
2. Troppi risultati → aggiungi specificità: `org:"Amazon" city:"Virginia" product:nginx`
3. Dati non aggiornati → Shodan aggiorna ogni \~30 giorni, valuta uno scan on-demand: `shodan scan submit <ip>`

Per la parte di sfruttamento successiva alla discovery (es. metadata cloud raggiungibili), vedi [SSRF e cloud metadata](https://hackita.it/articoli/ssrf).

***

## Toolchain: Shodan → Nmap → Exploitation

```bash
# 1. Shodan broad search
shodan search 'org:"Target Corp"' --fields ip_str > targets.txt

# 2. Nmap dettagliato
nmap -sV -sC -iL targets.txt -oA nmap_scan

# 3. Filtra servizi vulnerabili
grep "open" nmap_scan.gnmap | grep "3306" > mysql_targets.txt
```

**Estensione con Nuclei** (verifica automatica di CVE note su larga scala):

```bash
shodan search 'http.component:wordpress' --fields ip_str > wp_targets.txt
cat wp_targets.txt | nuclei -t cves/ -o nuclei_results.txt
```

Shodan trova i target per tecnologia, Nuclei verifica automaticamente le CVE note su quella tecnologia.

## Dalla scoperta su Shodan alla verifica di una misconfigurazione

Esempio di flusso completo, dalla query a Shodan alla conferma della vulnerabilità (in lab/pentest autorizzato).

**Fase 1 — Reconnaissance**

```bash
shodan search 'mongodb country:IT -authentication' --fields ip_str,port,product
```

```
203.0.113.75,27017,MongoDB 4.2.8
```

**Fase 2 — Verifica**

```bash
nc -zv 203.0.113.75 27017
# Connection successful

mongo 203.0.113.75:27017
```

```
> show dbs
admin           0.000GB
production_db   2.345GB
```

**Fase 3 — Enumerazione (solo per confermare l'impatto, mai oltre)**

```javascript
> db.customers.count()
45678
```

🎓 **CRITICAL:** un database di produzione raggiungibile senza autenticazione, da milioni di IP nel mondo, è la misconfigurazione più comune trovata via Shodan.

**Totale:** \~5 minuti da query Shodan a conferma della vulnerabilità. Senza Shodan, individuare questo host tra milioni di IP avrebbe richiesto giorni di scanning manuale.

Se vuoi approfondire come si sfrutta un MongoDB esposto una volta trovato, leggi [porta 27017 MongoDB](https://hackita.it/articoli/porta-27017-mongodb).

***

### Shodan CLI Commands

| **Comando**         | **Funzione**                    | **Esempio**                                         |
| ------------------- | ------------------------------- | --------------------------------------------------- |
| `shodan search`     | Cerca nel database              | `shodan search apache`                              |
| `shodan host`       | Lookup di un IP specifico       | `shodan host 8.8.8.8`                               |
| `shodan count`      | Conta i risultati               | `shodan count mongodb`                              |
| `shodan stats`      | Facet/statistiche aggregate     | `shodan stats --facets country apache`              |
| `shodan download`   | Salva risultati su file         | `shodan download results.json.gz apache`            |
| `shodan parse`      | Parsa risultati salvati         | `shodan parse --fields ip_str,port results.json.gz` |
| `shodan convert`    | Converte formato risultati      | `shodan convert results.json.gz csv`                |
| `shodan scan`       | Invia scan on-demand            | `shodan scan submit 1.2.3.4`                        |
| `shodan alert`      | Crea alert di monitoraggio      | `shodan alert create "MiaRete" 1.2.3.0/24`          |
| `shodan honeyscore` | Probabilità che sia un honeypot | `shodan honeyscore 1.2.3.4`                         |

***

## Performance e query su larga scala

**Rate limit:**

```
Free tier: 1 query/secondo
Membership/API a pagamento: nessun rate limit rigido
```

**Bulk export in Python:**

```python
import shodan
api = shodan.Shodan(API_KEY)

query = 'apache country:US'
page = 1
all_results = []

while True:
    try:
        results = api.search(query, page=page)
        all_results.extend(results['matches'])
        if page * 100 >= results['total']:
            break
        page += 1
    except shodan.APIError as e:
        print(f"Errore: {e}")
        break
```

**Limite:** ogni query credit consuma fino a 100 risultati. Con Membership hai 100 credit/mese = 10.000 risultati scaricabili.

***

## Troubleshooting

**Nessun risultato per un servizio che sai essere esposto**
Shodan non ha scansionato di recente, o il servizio è ora dietro firewall.

```bash
shodan scan submit <ip-target>
shodan scan list
```

Attendi 24-48h perché i risultati compaiano nel database.

**Errore API key**

```
APIError: Invalid API key
```

```bash
shodan init <api-key-corretta>
shodan info
```

**Query credit esauriti**

```
APIError: Query credits exhausted
```

```bash
shodan info   # controlla credit residui
```

Il reset è mensile per Membership e piani a pagamento.

***

## API — panoramica dei metodi principali

| **Metodo**             | **Funzione**                                      | **Consuma credit**                            |
| ---------------------- | ------------------------------------------------- | --------------------------------------------- |
| `/shodan/host/{ip}`    | Lookup completo di un IP                          | No                                            |
| `/shodan/host/search`  | Ricerca con filtri                                | Sì, se ci sono filtri o pagine oltre la prima |
| `/shodan/host/count`   | Solo conteggio risultati + facet, senza dati host | No                                            |
| `/shodan/scan`         | Richiede scan on-demand su un IP                  | Sì (scan credit)                              |
| `/dns/domain/{domain}` | Info DNS/subdomain su un dominio                  | Sì                                            |

```python
import shodan
api = shodan.Shodan(API_KEY)

# Ricerca (consuma query credit)
results = api.search('apache country:IT')

# Lookup singolo host (non consuma query credit)
host = api.host('8.8.8.8')

# Solo conteggio (non consuma query credit)
total = api.count('mongodb -authentication')
```

Regola pratica: usa `count` o `host` quando ti serve solo un numero o un lookup puntuale — risparmi i query credit per le ricerche con filtri.

### InternetDB — lookup rapido senza API key

Per un lookup veloce di un singolo IP, senza registrazione né API key, Shodan offre **InternetDB**: un endpoint gratuito che restituisce solo porte aperte, hostname, CVE e tag — niente banner completo.

```bash
curl https://internetdb.shodan.io/8.8.8.8
```

```json
{
  "ip": "8.8.8.8",
  "ports": [53, 443],
  "hostnames": ["dns.google"],
  "cpes": [],
  "vulns": [],
  "tags": []
}
```

**Quando usarlo:** script di massa che devono controllare rapidamente migliaia di IP senza gestire credit o autenticazione. **Limite:** aggiornato solo settimanalmente, e non ha i dettagli del banner — per quello serve l'API completa.

### Shodan Trends

Oltre alla ricerca puntuale, [trends.shodan.io](https://trends.shodan.io) mostra l'andamento storico di protocolli e prodotti nel tempo — utile per vedere, ad esempio, la crescita di MQTT (IoT) o il calo di Telnet su scala globale. Non supporta tutti i filtri della ricerca principale, ma è un buon modo per contestualizzare un dato puntuale in un trend più ampio.

***

## Limitazioni di Shodan

* **IPv6:** copertura parziale, la priorità resta lo spazio IPv4
* **NAT/VPN/Cloudflare:** Shodan vede l'IP esposto, non necessariamente l'host reale dietro un proxy o CDN
* **Host offline al momento della query:** i dati possono essere datati fino a \~30 giorni
* **Porte non scansionate:** copre \~1.500 porte, non tutte le 65.535 possibili — un servizio su porta non standard può sfuggire
* **Banner obsoleti:** un servizio patchato di recente potrebbe ancora mostrare la versione vecchia fino al prossimo giro di scansione
* **Falsi positivi sulle vulnerabilità:** le CVE "unverified" sono dedotte dalla versione, non confermate attivamente

***

## Best practice d'uso

1. Parti largo (`country`, `org`) poi restringi con filtri più specifici
2. Usa `shodan count` prima di lanciare ricerche pesanti, per stimare la scala
3. Verifica sempre con uno scan attivo (nmap) prima di trarre conclusioni operative — Shodan è un punto di partenza, non l'ultima parola
4. Non fidarti ciecamente del banner: può essere stato modificato, o il servizio patchato senza cambio versione
5. Affianca Censys quando serve analisi certificati/TLS più profonda

***

## Shodan vs Censys vs ZoomEye

| **Tool**    | **Focus**               | **Copertura** | **Punto di forza**             |
| ----------- | ----------------------- | ------------- | ------------------------------ |
| **Shodan**  | Servizi/porte           | IPv4 completo | IoT/ICS, storico               |
| **Censys**  | Certificati/TLS         | IPv4 completo | Analisi crittografica profonda |
| **ZoomEye** | Copertura Asia-Pacifico | Regionale     | Tracking C2/malware            |

**Usa Shodan quando:** serve info su servizi/porte, reconnaissance IoT/ICS, confronto storico.
**Usa Censys quando:** serve analisi certificati/TLS approfondita.
**Usa ZoomEye quando:** target/copertura è concentrata in area Asia-Pacifico.

**Nota:** Shodan trova cosa è esposto, ma non fa vulnerability assessment approfondito come uno scanner dedicato — serve poi uno scanner attivo per la verifica.

***

## Perché è rilevante oggi (2026)

L'attack surface continua ad espandersi: esplosione IoT (oltre 50 miliardi di dispositivi nel 2026), migrazione cloud, infrastrutture da remote work. Shodan resta l'unico tool con scansione globale continua a questa scala. I difensori lo usano per attack surface monitoring (cosa ho esposto per errore?). Gli attaccanti lo usano per identificare target prima della disclosure pubblica di una CVE. I team di threat intelligence correlano i dati Shodan con exploit database per difesa predittiva.

***

## OPSEC — cosa lascia visibile chi lo usa

**Rumorosità dal tuo lato:** zero, è query passiva al database. Ma Shodan stesso, quando scansiona internet, è rilevabile:

```
- Source IP nei range noti di Shodan (216.117.2.0/24)
- User-Agent: Shodan/1.0
- Pattern di scan sequenziale e prevedibile
```

Se invece usi la Scan API per uno scan on-demand, quello parte dal **tuo** IP — a quel punto sì che conta l'evasion (VPN/proxy diverso per scan, rate limiting, scan solo su porte specifiche).

Non c'è un Event ID locale da monitorare: la detection è lato network, via firewall log e IDS/SIEM sul traffico in ingresso.

***

## Detection & Evasion

**Cosa monitora il Blue Team:**

```
- Range IP di Shodan (216.117.2.0/24 e altri)
- User-Agent: "Shodan/1.0"
- Pattern di scansione prevedibili
```

```bash
# Bloccare Shodan a livello firewall
iptables -A INPUT -s 216.117.2.0/24 -j DROP
iptables -A INPUT -s 216.117.2.0/24 -j LOG --log-prefix "SHODAN_SCAN: "
```

**Nota:** le query al database sono passive. L'evasion si applica solo se usi la Scan API per scan custom (quello sì è active scanning dal tuo IP).

***

## Hardening — difendersi da Shodan

1. Esponi solo i servizi strettamente necessari
2. Blocca i range IP di Shodan via firewall
3. Nascondi versioni nei banner (`ServerTokens Prod` su Apache)
4. Mai servizi senza autenticazione su IP pubblico
5. Monitora te stesso: `shodan host <tuo-ip>` periodicamente
6. Servizi critici dietro VPN/bastion, mai esposti direttamente

```apache
# httpd.conf
ServerTokens Prod
ServerSignature Off
```

***

## FAQ

**Shodan è legale?**
Sì, interrogare il database è legale (informazione pubblica). Accedere a dispositivi trovati senza autorizzazione è illegale (CFAA, GDPR).

**Shodan aggiorna in tempo reale?**
No, il ciclo di scansione completo è \~28-30 giorni. Per dati in tempo reale serve uno scan attivo (nmap) o la Scan API a pagamento.

**Shodan serve per un pentest esterno?**
Sì, per la fase di asset discovery e reconnaissance passiva, prima dello scanning attivo.

**Shodan trova anche dispositivi in Italia?**
Sì, con `country:IT` — copre l'intero spazio IPv4 pubblico, Italia inclusa.

**Differenza tra Shodan e Censys?**
Shodan copre più ampiamente servizi/IoT con dati storici; Censys è più forte su certificati e analisi TLS.

**Posso rimuovere i miei IP da Shodan?**
Non esiste una procedura di rimozione ufficiale. Puoi solo bloccare i range IP di Shodan via firewall.

***

## Cheat sheet query

| **Scenario**             | **Query Shodan**                                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| MongoDB senza auth       | `mongodb port:27017 -authentication` — approfondisci su [porta 27017 MongoDB](https://hackita.it/articoli/porta-27017-mongodb) |
| Elasticsearch aperto     | `port:9200 "cluster_name"` — approfondisci su [porta 9200 Elasticsearch](https://hackita.it/articoli/porta-9200-elasticsearch) |
| Webcam esposte           | `"Server: SQ-WEBCAM"`                                                                                                          |
| RDP esposto              | `port:3389 country:US` — approfondisci su [porta 3389 RDP](https://hackita.it/articoli/porta-3389-rdp)                         |
| Log4Shell                | `vuln:CVE-2021-44228`                                                                                                          |
| ICS/SCADA                | `port:502` (Modbus) / `port:102` (Siemens)                                                                                     |
| SSH versione specifica   | `product:"OpenSSH" version:"7.4"`                                                                                              |
| WordPress esposti        | `http.component:wordpress`                                                                                                     |
| Jenkins esposti          | `"X-Jenkins"`                                                                                                                  |
| Grafana esposti          | `title:"Grafana"`                                                                                                              |
| Docker API esposta       | `port:2375 "Docker"`                                                                                                           |
| VPN endpoint             | `"OpenVPN" port:1194`                                                                                                          |
| NAS esposti              | `product:"Synology" OR product:"QNAP"`                                                                                         |
| phpMyAdmin esposto       | `title:"phpMyAdmin"`                                                                                                           |
| Server dietro Cloudflare | `http.waf:cloudflare`                                                                                                          |

***

## Disclaimer

Shodan è un search engine pubblico. Interrogare il database è legale. Accedere a dispositivi trovati senza autorizzazione è illegale (Computer Fraud and Abuse Act, GDPR per dati UE, equivalenti nazionali). Usa questa intelligence solo in penetration test autorizzati, inventario asset di tua proprietà, o ricerca con responsible disclosure.

**Sito:** [shodan.io](https://www.shodan.io)
**API Docs:** [developer.shodan.io/api](https://developer.shodan.io/api)
