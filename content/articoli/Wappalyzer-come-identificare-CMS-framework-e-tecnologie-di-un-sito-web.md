---
title: 'Wappalyzer: come identificare CMS, framework e tecnologie di un sito web'
slug: wappalyzer
description: >-
  Guida a Wappalyzer per rilevare CMS, framework, CDN, analytics e indizi di
  versione di un sito web, così da orientare reconnaissance, fingerprinting e
  scanning mirati nel pentest.
image: /wappalyzer.webp
draft: false
date: 2026-04-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - tech-fingerprinting
  - web-stack-enumeration
---

Wappalyzer rileva le tecnologie che alimentano un sito web — CMS, framework, CDN, analytics, hosting provider, linguaggi server-side, librerie JavaScript e molto altro. Originariamente noto come estensione browser, Wappalyzer è diventato uno strumento completo con CLI, API e integrazione DevOps.

Nel penetration testing lo usi nella primissima fase: conosci il target, capisci cosa gira, poi decidi come attaccare. Se WhatWeb è il bisturi per il fingerprinting da terminale, Wappalyzer è il radar passivo che lavora mentre navighi. La combinazione dei due dà una mappa tecnologica completa.

Kill chain: **Reconnaissance** (MITRE ATT\&CK T1592.004). L'articolo copre l'uso operativo dell'estensione, della CLI, le differenze con alternative e l'integrazione in pipeline di recon.

***

## 1️⃣ Setup e Installazione

### Estensione browser (uso manuale)

Disponibile per Chrome, Firefox ed Edge:

* Chrome: [Chrome Web Store](https://chrome.google.com/webstore/detail/wappalyzer)
* Firefox: [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/)

Dopo l'installazione, visita qualsiasi sito e clicca l'icona Wappalyzer nella toolbar per vedere le tecnologie rilevate.

### CLI (wappalyzer-cli via npm)

Per uso automatizzato e scripting:

```bash
npm install -g wappalyzer
```

**Verifica:**

```bash
wappalyzer --help
```

### Alternativa: wappalyzer-cli con Docker

```bash
docker pull AliasIO/wappalyzer
docker run --rm wappalyzer http://10.10.10.50
```

**Requisiti CLI:**

* Node.js 18+
* Chromium/Chrome (per rendering JavaScript)
* \~200MB di spazio disco

***

## 2️⃣ Uso Base

### Estensione browser

Naviga su `http://target.com`. L'icona Wappalyzer mostra un badge con il numero di tecnologie rilevate. Click per dettagli:

```
CMS:           WordPress 6.4.2
Server:        Nginx 1.24.0
Programming:   PHP 8.2
JavaScript:    jQuery 3.7.1, React 18.2
CDN:           Cloudflare
Analytics:     Google Analytics
```

### CLI

```bash
wappalyzer http://10.10.10.50
```

Output JSON:

```json
{
  "urls": { "http://10.10.10.50": { "status": 200 } },
  "technologies": [
    { "name": "Apache", "version": "2.4.52", "categories": ["Web servers"] },
    { "name": "WordPress", "version": "6.4.2", "categories": ["CMS"] },
    { "name": "PHP", "version": "8.1.2", "categories": ["Programming languages"] },
    { "name": "jQuery", "version": "3.6.0", "categories": ["JavaScript libraries"] }
  ]
}
```

**Parametri CLI chiave:**

* `--pretty` → output JSON formattato
* `--max-depth=N` → profondità di crawling
* `--max-urls=N` → massimo URL da analizzare
* `--max-wait=N` → timeout in ms
* `--recursive` → analizza link interni

***

## 3️⃣ Tecniche Operative

### Fingerprinting in massa via CLI

```bash
cat targets.txt | while read url; do
  echo "--- $url ---"
  wappalyzer "$url" --pretty 2>/dev/null | jq '.technologies[] | "\(.name) \(.version)"'
done
```

### Integrazione con httpx per target live

```bash
cat subdomains.txt | httpx -silent | while read url; do
  wappalyzer "$url" 2>/dev/null >> tech_report.json
done
```

### Rilevamento WAF e CDN

Wappalyzer identifica anche layer di protezione:

```
Security:      Cloudflare, AWS WAF
CDN:           CloudFront
Proxy:         Nginx
```

Informazioni critiche per decidere se serve evasion durante le fasi successive del pentest.

### Confronto con header analysis manuale

Quello che Wappalyzer automatizza, puoi verificarlo manualmente:

```bash
curl -sI http://10.10.10.50 | grep -iE "server|x-powered|x-generator"
```

Ma Wappalyzer analizza anche il body HTML, gli script caricati, i meta tag, i cookie e le classi CSS — informazioni non presenti negli header.

***

## 4️⃣ Tecniche Avanzate

### API Wappalyzer per automazione enterprise

Per integrazione in piattaforme di security:

```bash
curl "https://api.wappalyzer.com/v2/lookup/?urls=https://target.com" \
  -H "x-api-key: YOUR_API_KEY"
```

L'API restituisce dati storici sulla tecnologia del target, utile per tracciare cambiamenti nel tempo.

### Analisi JavaScript-rendered content

A differenza di [WhatWeb](https://hackita.it/articoli/whatweb), Wappalyzer CLI usa Chromium headless per renderizzare JavaScript. Questo significa che rileva:

* Single Page Applications (React, Vue, Angular)
* Widget dinamici caricati a runtime
* Librerie caricate via CDN post-rendering

### Custom fingerprint rules

Il database Wappalyzer è in formato JSON e può essere esteso:

```json
{
  "Custom App": {
    "cats": [1],
    "headers": { "X-Custom-Version": "(.+)" },
    "meta": { "generator": "CustomApp" },
    "js": { "CustomApp.version": "" }
  }
}
```

### Bypass protezioni anti-bot

Alcuni siti bloccano request automatiche:

```bash
wappalyzer http://target.com --max-wait=10000 --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

Aumenta il wait time e usa un User-Agent realistico.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Mapping tecnologico rapido durante OSINT

Apri il browser con l'estensione, visita il target. Wappalyzer mostra:

```
WordPress 6.2.1 | PHP 7.4 | Apache 2.4.41 | jQuery 3.5.1
```

**Azione successiva:** WordPress 6.2.1 + PHP 7.4 sono versioni con CVE note. Lancia [Nuclei](https://hackita.it/articoli/nuclei) con template WordPress.

**Cosa fare se fallisce:**

* Wappalyzer non rileva nulla → Il sito usa tecnologie proprietarie o offusca i fingerprint. Passa a WhatWeb con level 4.

**Timeline:** 2 secondi via browser.

### Scenario 2: Tech audit su 50 subdomain

```bash
cat subs.txt | httpx -silent | while read u; do
  echo "$u" >> report.txt
  wappalyzer "$u" --pretty 2>/dev/null | jq -r '.technologies[] | "  \(.name) \(.version // "N/A")"' >> report.txt
done
```

**Output atteso:** report con tecnologia per ogni subdomain.

**Cosa fare se fallisce:**

* Timeout su target lenti → `--max-wait=15000`.
* Chromium crash → Limita la memoria o usa Docker.

**Timeline:** 50 target: 5-10 minuti (dipende dal rendering JS).

### Scenario 3: Identificare target WordPress per campagna di mass exploitation

```bash
cat all_targets.txt | while read u; do
  result=$(wappalyzer "$u" 2>/dev/null | jq -r '.technologies[] | select(.name=="WordPress") | .version')
  if [ -n "$result" ]; then
    echo "$u|WordPress|$result" >> wordpress_targets.csv
  fi
done
```

**Cosa fare se fallisce:**

* Troppo lento → Parallelizza con `xargs -P 5`.

**Timeline:** 200 target: 20-30 minuti in sequenza, 5-8 in parallelo.

***

## 6️⃣ Toolchain Integration

Wappalyzer si inserisce nella fase iniziale di tech discovery.

**Flusso operativo:**

[Subfinder](https://hackita.it/articoli/subfinder)/Amass (subdomain) → Httpx (probe) → **Wappalyzer (tech ID)** → Nuclei/WPScan (vuln scan mirato)

**Passaggio dati:**

Il JSON output di Wappalyzer viene filtrato per selezionare target con tecnologie specifiche, poi passato ai vulnerability scanner appropriati.

| Feature           | Wappalyzer    | WhatWeb        | BuiltWith | Netcraft  |
| ----------------- | ------------- | -------------- | --------- | --------- |
| JS rendering      | Sì (Chromium) | No             | N/A       | N/A       |
| CLI               | Sì (npm)      | Sì (Ruby)      | No        | No        |
| Browser extension | Sì            | No             | Sì        | No        |
| API               | Sì (paid)     | No             | Sì (paid) | Sì        |
| Database size     | 1.500+        | 1.800+         | Vasto     | Limitato  |
| Stealth           | Medio         | Alto (level 1) | N/A       | N/A       |
| Costo             | Free/Paid     | Free           | Paid      | Free/Paid |

***

## 7️⃣ Attack Chain Completa

**Obiettivo:** Compromettere un e-commerce tramite CMS outdated trovato con Wappalyzer.

**Fase 1 — Subdomain enumeration (10 min)**

```bash
subfinder -d shop.com -silent | httpx -silent -o live.txt
```

**Fase 2 — Tech Fingerprinting (5 min)**

```bash
cat live.txt | while read u; do wappalyzer "$u" 2>/dev/null; done > tech.json
```

Trova: `staging.shop.com` → Magento 2.3.5 (versione vulnerabile).

**Fase 3 — Vulnerability Scan (5 min)**

Nuclei con template Magento. Trova admin panel esposto con default credentials.

**Fase 4 — Exploitation (15 min)**

Accesso admin Magento → template injection → RCE.

**Fase 5 — Post-exploitation (20 min)**

Credenziali database, dump clienti, lateral movement.

**Timeline totale:** \~55 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* Request da browser headless (Chromium automatizzato)
* Pattern di navigazione non umano (singola richiesta, nessun asset caricato)

### Tecniche di evasion

1. L'estensione browser è completamente passiva — analizza il traffico già in corso, nessuna richiesta extra.
2. La CLI con `--max-urls=1` genera traffico minimo.
3. User-Agent realistico per la CLI.

### Cleanup

Wappalyzer non lascia artefatti.

***

## 9️⃣ Performance & Scaling

**Browser extension:** istantaneo, nessun consumo aggiuntivo.

**CLI single target:** 5-15 secondi (Chromium rendering).

**CLI multi-target:** serializzato per default. Parallelizza con `xargs -P 5`.

**Consumo risorse CLI:** \~200-400MB per istanza Chromium. Limita le istanze parallele su macchine con poca RAM.

***

## 🔟 Tabelle Tecniche

### Categorie tecnologie rilevate

| Categoria  | Esempi                        | Utilità pentest          |
| ---------- | ----------------------------- | ------------------------ |
| CMS        | WordPress, Joomla, Drupal     | Exploit specifici        |
| Framework  | Laravel, Django, Spring       | Attack surface specifica |
| Web server | Apache, Nginx, IIS            | Version-based CVE        |
| CDN/WAF    | Cloudflare, Akamai, AWS WAF   | Evasion planning         |
| JavaScript | jQuery, React, Angular        | Client-side vuln         |
| Analytics  | GA, Matomo                    | Information disclosure   |
| E-commerce | Magento, WooCommerce, Shopify | Payment-related attacks  |

### CLI Flags Reference

| Flag               | Descrizione               |
| ------------------ | ------------------------- |
| `--pretty`         | JSON formattato           |
| `--max-depth=N`    | Profondità crawl          |
| `--max-urls=N`     | Max URL da analizzare     |
| `--max-wait=N`     | Timeout (ms)              |
| `--recursive`      | Crawling ricorsivo        |
| `--user-agent=str` | UA custom                 |
| `--probe`          | Solo test raggiungibilità |

***

## 11️⃣ Troubleshooting

| Problema                    | Causa                          | Fix                                       |
| --------------------------- | ------------------------------ | ----------------------------------------- |
| CLI non parte               | Chromium non trovato           | `npm install puppeteer` o installa Chrome |
| Nessuna tecnologia rilevata | Sito con offuscamento avanzato | Usa WhatWeb level 4 come complemento      |
| Timeout                     | Target lento                   | `--max-wait=15000`                        |
| Memory error                | Troppe istanze parallele       | Riduci parallelismo                       |
| API rate limited            | Troppi lookup                  | Usa intervalli tra le richieste           |

***

## 12️⃣ FAQ

**Wappalyzer è passivo o attivo?**
L'estensione browser è passiva (analizza traffico esistente). La CLI è attiva (invia richieste HTTP).

**Posso usare Wappalyzer senza browser?**
Sì, la CLI funziona standalone ma richiede Chromium installato per il rendering JS.

**Wappalyzer vs WhatWeb — quale scegliere?**
Usa WhatWeb per scansioni CLI pure senza dipendenze pesanti. Usa Wappalyzer quando hai bisogno di JS rendering o come complemento durante la navigazione manuale.

**L'API è gratuita?**
C'è un tier free limitato. Per uso professionale serve un piano paid.

**Wappalyzer rileva versioni precise?**
Quando possibile. La precisione dipende da come l'applicazione espone le informazioni di versione.

***

## 13️⃣ Cheat Sheet

| Azione         | Comando                                                     |
| -------------- | ----------------------------------------------------------- |
| Scan singolo   | `wappalyzer http://target --pretty`                         |
| Multi-target   | `cat targets.txt \| while read u; do wappalyzer "$u"; done` |
| JSON output    | `wappalyzer URL > results.json`                             |
| Timeout esteso | `wappalyzer URL --max-wait=15000`                           |
| UA custom      | `wappalyzer URL --user-agent="Mozilla/5.0..."`              |
| Solo probe     | `wappalyzer URL --probe`                                    |
| Browser        | Installa extension → naviga → click icona                   |

***

**Disclaimer:** Wappalyzer è un tool di fingerprinting per security assessment. L'identificazione di tecnologie su target senza autorizzazione può essere considerata ricognizione non autorizzata. Ottieni sempre permesso. Website: [wappalyzer.com](https://www.wappalyzer.com).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
