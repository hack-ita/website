---
title: 'Httpx: HTTP Probing e Analisi Web su Larga Scala nel Penetration Testing'
slug: httpx
description: >-
  httpx è il tool di probing HTTP per filtrare host attivi, rilevare tecnologie,
  status code e screenshot in pipeline con subdomain enumeration.
image: /Gemini_Generated_Image_opsqi3opsqi3opsq.webp
draft: false
date: 2026-02-15T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - recon
---

Httpx è il coltellino svizzero del HTTP probing sviluppato da ProjectDiscovery. Quando hai una lista di migliaia di subdomain o IP e devi capire rapidamente quali rispondono su HTTP/HTTPS, quale status code restituiscono, che tecnologia usano e che titolo hanno — httpx è lo strumento che fa tutto questo in parallelo con velocità estrema.

Non è uno scanner di vulnerabilità né un directory bruteforcer. Httpx è il filtro che separa il rumore dai target reali nella tua pipeline di recon. Prende una lista grezza di host e restituisce una lista arricchita di informazioni utili per le fasi successive.

Kill chain: **Reconnaissance** (MITRE ATT\&CK T1595). Httpx è il connettore tra la fase di subdomain enumeration e il vulnerability scanning, garantendo che ogni tool successivo lavori solo su target effettivamente raggiungibili.

***

## 1️⃣ Setup e Installazione

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Alternativa:

```bash
sudo apt install httpx-toolkit
```

**Nota Kali:** il pacchetto potrebbe chiamarsi `httpx-toolkit` per evitare conflitto con il pacchetto Python `httpx`.

**Verifica:**

```bash
httpx -version
```

Output:

```
httpx v1.6.9
```

**Requisiti:**

* Go 1.21+ (per installazione da sorgente)
* Connettività di rete verso i target
* Nessun requisito sui target

***

## 2️⃣ Uso Base

Probe di una lista di host:

```bash
cat subdomains.txt | httpx -silent
```

Output:

```
https://www.target.com
http://mail.target.com
https://api.target.com
https://dev.target.com
http://staging.target.com:8080
```

Solo gli host che rispondono effettivamente su HTTP/HTTPS. I dead host sono filtrati.

**Parametri fondamentali:**

* `-silent` → output solo URL (no banner)
* `-status-code` → mostra status code
* `-title` → mostra page title
* `-tech-detect` → rileva tecnologie (Wappalyzer-based)
* `-content-length` → mostra dimensione risposta
* `-web-server` → mostra web server
* `-ip` → risolvi e mostra IP
* `-cdn` → rileva CDN
* `-o file` → output su file
* `-threads N` → thread paralleli

Probe completo con tutte le informazioni:

```bash
cat subdomains.txt | httpx -status-code -title -tech-detect -web-server -ip -cdn -content-length
```

Output:

```
https://www.target.com [200] [Welcome - Corp] [Nginx] [104.26.5.12] [cloudflare] [WordPress,PHP,jQuery] [15234]
http://mail.target.com [302] [Redirect] [Microsoft-IIS/10.0] [10.10.10.25] [] [Microsoft Exchange] [0]
https://dev.target.com [200] [Jenkins] [Jetty] [10.10.10.30] [] [Jenkins,Java] [8721]
```

Ogni riga è una miniera di informazioni per la fase successiva.

***

## 3️⃣ Tecniche Operative

### Filtraggio per status code

Solo target con pagine accessibili (200):

```bash
cat subs.txt | httpx -silent -mc 200
```

Solo redirect (301/302):

```bash
cat subs.txt | httpx -silent -mc 301,302 -follow-redirects
```

Escludi 404 e 403:

```bash
cat subs.txt | httpx -silent -fc 404,403
```

### Probe su porte specifiche

```bash
cat subs.txt | httpx -silent -ports 80,443,8080,8443,3000,9090
```

Httpx testa ogni host su tutte le porte specificate. Trova servizi web nascosti su porte non standard.

### Tech detection integrata

```bash
cat subs.txt | httpx -tech-detect -silent | grep -i wordpress
```

Filtra tutti i target WordPress dalla lista. Passa il risultato a [WPScan](https://hackita.it/articoli/wpscan) o [Nuclei](https://hackita.it/articoli/nuclei) con template WordPress.

### Screenshot capture

Httpx può catturare screenshot delle pagine:

```bash
cat subs.txt | httpx -screenshot -screenshot-timeout 15
```

Gli screenshot vengono salvati in `./output/screenshot/`. Utile per visual recon di centinaia di host.

### JSON output per parsing avanzato

```bash
cat subs.txt | httpx -json -o results.json
```

```bash
cat results.json | jq -r 'select(.status_code == 200) | .url'
```

***

## 4️⃣ Tecniche Avanzate

### Pipeline completa: subdomain → probe → vuln scan

```bash
subfinder -d target.com -silent | httpx -silent | nuclei -severity critical,high
```

Tre tool, una riga. Subdomain discovery → HTTP probe → vulnerability scan.

### Probe con header custom e autenticazione

```bash
cat subs.txt | httpx -H "Authorization: Bearer TOKEN" -H "X-Custom: value" -silent
```

### Favicon hash per fingerprinting

```bash
cat subs.txt | httpx -favicon -silent
```

Il favicon hash è un identificatore univoco per applicazioni web. Puoi cercare lo stesso hash su [Shodan](https://hackita.it/articoli/shodan) per trovare istanze simili.

### Match per contenuto

```bash
cat subs.txt | httpx -match-string "admin" -silent
```

Filtra solo host che contengono "admin" nel body della risposta.

### Probe massivo con rate limiting

```bash
cat massive_list.txt | httpx -silent -threads 100 -rate-limit 200 -timeout 5
```

100 thread paralleli con max 200 richieste/secondo. Bilanciamento tra velocità e gentilezza verso il target.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Filtrare subdomain live per scansione Nuclei

```bash
subfinder -d corp.com -silent | httpx -silent -o live.txt
nuclei -l live.txt -severity critical,high -o vulns.txt
```

**Output atteso:** `live.txt` con 50-300 URL attivi filtrati da migliaia di subdomain.

**Cosa fare se fallisce:**

* Pochissimi risultati → DNS wildcard attivo. Httpx mostra tutto come live. Filtra per content-length: `httpx -content-length` e identifica la size della wildcard page.
* Timeout → `httpx -timeout 10 -retries 2`.

**Timeline:** 1.000 subdomain → probe: 30-60 secondi.

### Scenario 2: Identificare Jenkins/Grafana/admin panel esposti

```bash
cat subs.txt | httpx -title -status-code -silent | grep -iE "jenkins|grafana|admin|kibana|dashboard"
```

**Output atteso:**

```
https://jenkins.corp.com [200] [Dashboard [Jenkins]]
http://grafana.corp.com:3000 [200] [Grafana]
https://admin.corp.com [200] [Admin Panel]
```

**Cosa fare se fallisce:**

* Title vuoto → SPA che carica il titolo via JS. Httpx non renderizza JS. Usa [Aquatone](https://hackita.it/articoli/aquatone) per screenshot.

**Timeline:** Istantaneo su lista preparata.

### Scenario 3: Mappatura completa di rete interna post-pivot

```bash
seq 1 254 | sed 's/^/172.16.0./' | httpx -silent -ports 80,443,8080,8443,3000,9090,9200 -status-code -title -tech-detect
```

**Output atteso:** lista di servizi web interni con tecnologie.

**Cosa fare se fallisce:**

* Nessun risultato → Firewall blocca i probe dal pivot host. Verifica connettività: `curl -sI http://172.16.0.1`.

**Timeline:** 254 host × 7 porte: 2-3 minuti.

***

## 6️⃣ Toolchain Integration

Httpx è il collante tra recon e exploitation.

**Flusso operativo:**

[Subfinder](https://hackita.it/articoli/subfinder)/[Amass](https://hackita.it/articoli/amass) (subdomain) → **Httpx (probe + tech)** → [Nuclei](https://hackita.it/articoli/nuclei)/[ZAP](https://hackita.it/articoli/zap) (vuln scan)

| Feature        | Httpx    | Httprobe | Curl    | Wget    |
| -------------- | -------- | -------- | ------- | ------- |
| Parallelismo   | ★★★★★    | ★★★★☆    | ★☆☆☆☆   | ★☆☆☆☆   |
| Tech detection | Sì       | No       | No      | No      |
| Screenshot     | Sì       | No       | No      | No      |
| CDN detection  | Sì       | No       | No      | No      |
| JSON output    | Sì       | No       | No      | No      |
| Favicon hash   | Sì       | No       | No      | No      |
| Filtering      | Avanzato | Base     | Manuale | Manuale |

***

## 7️⃣ Attack Chain Completa

**Obiettivo:** Da zero a RCE su un'applicazione interna esposta.

**Fase 1 — Subdomain Enumeration (10 min)**

```bash
subfinder -d corp.com -silent | sort -u > subs.txt
```

**Fase 2 — HTTP Probing (1 min)**

```bash
cat subs.txt | httpx -silent -status-code -title -tech-detect -o probed.txt
```

Trova `staging.corp.com` con Jenkins 2.319 (versione vulnerabile).

**Fase 3 — Vulnerability Scan (5 min)**

```bash
nuclei -u https://staging.corp.com -tags jenkins
```

Conferma CVE con RCE.

**Fase 4 — Exploitation (10 min)**

Exploit Jenkins → shell come `jenkins` user.

**Fase 5 — Post-exploitation (30 min)**

Credenziali nei job Jenkins → lateral movement.

**Timeline totale:** \~56 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* Burst di richieste HTTP da singolo IP verso molti subdomain
* Richieste verso porte non standard (8080, 3000, 9090)
* User-Agent `httpx` (default)

### Tecniche di evasion

1. **UA personalizzato:** `-H "User-Agent: Mozilla/5.0 ..."`
2. **Rate limiting:** `-rate-limit 10` per ridurre il rumore
3. **Probe su porte standard:** limita a 80/443 per fase iniziale

### Cleanup

Nessun artefatto sul target.

***

## 9️⃣ Performance & Scaling

**1.000 host:** 30-60 secondi con default settings.

**10.000 host:** 3-5 minuti con `-threads 200`.

**100.000 host:** 15-30 minuti. Httpx è progettato per scale massive.

**Consumo:** \~50-100MB RAM. Network è il bottleneck.

***

## 🔟 Tabelle Tecniche

### Flag Reference

| Flag                | Descrizione          |
| ------------------- | -------------------- |
| `-silent`           | Solo output URL      |
| `-status-code`      | Mostra status code   |
| `-title`            | Mostra page title    |
| `-tech-detect`      | Detection tecnologie |
| `-web-server`       | Server header        |
| `-ip`               | Risolvi IP           |
| `-cdn`              | Rileva CDN           |
| `-content-length`   | Size risposta        |
| `-screenshot`       | Cattura screenshot   |
| `-favicon`          | Hash favicon         |
| `-json`             | Output JSON          |
| `-mc codes`         | Match status code    |
| `-fc codes`         | Filter status code   |
| `-match-string str` | Match nel body       |
| `-ports p1,p2`      | Porte da testare     |
| `-threads N`        | Thread paralleli     |
| `-rate-limit N`     | Max req/sec          |
| `-follow-redirects` | Segui redirect       |

### Httpx vs alternative

| Aspetto            | Httpx     | Httprobe | Curl loop |
| ------------------ | --------- | -------- | --------- |
| Velocità (1K host) | \~40 sec  | \~60 sec | \~10 min  |
| Info raccolte      | 15+ campi | Solo URL | Manuale   |
| JSON output        | Nativo    | No       | Manuale   |
| Manutenzione       | Attiva    | Limitata | N/A       |

***

## 11️⃣ Troubleshooting

| Problema              | Causa                   | Fix                         |
| --------------------- | ----------------------- | --------------------------- |
| Troppi falsi positivi | DNS wildcard            | Filtra per content-length   |
| Timeout               | Target lenti            | `-timeout 15 -retries 2`    |
| `too many open files` | Ulimit basso            | `ulimit -n 10000`           |
| Tech detection vuota  | JS-rendered             | Usa Wappalyzer CLI          |
| Screenshot falliti    | Chromium non installato | Installa `chromium-browser` |

***

## 12️⃣ FAQ

**Httpx sostituisce httprobe?**
Sì. Httpx fa tutto ciò che fa httprobe e molto di più (tech detect, screenshot, filtering).

**Posso usare httpx per testare API?**
Sì. Usa `-match-string` per cercare risposte JSON e `-H` per header di autenticazione.

**Httpx funziona attraverso proxy?**
Sì: `-http-proxy http://127.0.0.1:8080`.

**Quanto è accurata la tech detection?**
Usa il database Wappalyzer. Buona per detection base, non precisa quanto WhatWeb a level 4 per le versioni.

**Httpx segue i redirect?**
Non di default. Usa `-follow-redirects` per seguirli.

***

## 13️⃣ Cheat Sheet

| Azione            | Comando                                                              |
| ----------------- | -------------------------------------------------------------------- |
| Probe base        | `cat subs.txt \| httpx -silent`                                      |
| Con info complete | `cat subs.txt \| httpx -status-code -title -tech-detect -web-server` |
| Solo status 200   | `cat subs.txt \| httpx -mc 200 -silent`                              |
| Multi-porta       | `cat subs.txt \| httpx -ports 80,443,8080,8443 -silent`              |
| Screenshot        | `cat subs.txt \| httpx -screenshot`                                  |
| JSON              | `cat subs.txt \| httpx -json -o results.json`                        |
| Pipeline completa | `subfinder -d domain \| httpx -silent \| nuclei`                     |
| Con rate limit    | `cat list.txt \| httpx -threads 50 -rate-limit 100`                  |
| Match string      | `cat subs.txt \| httpx -match-string "admin" -silent`                |

***

**Disclaimer:** Httpx è un tool open source di ProjectDiscovery per security assessment. L'uso su target senza autorizzazione è illegale. Repository: [github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
