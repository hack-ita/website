---
title: 'OWASP ZAP: guida completa a proxy, spider, active scan e fuzzing'
slug: owasp-zap
description: >-
  Scopri come usare OWASP ZAP per intercettare traffico HTTP/HTTPS, mappare
  applicazioni web con spider e AJAX Spider, eseguire active scan, fuzzing e
  test autenticati, anche in CI/CD con Docker e API
image: /owasp-zap.webp
draft: false
date: 2026-04-02T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - zaproxy
  - web-vulnerability-scanning
---

OWASP ZAP (Zed Attack Proxy) è il proxy di intercettazione e scanner di vulnerabilità web più utilizzato nel mondo open source. A differenza di Burp Suite, è completamente gratuito — comprese le funzionalità di scanning automatico, fuzzing e spidering che in Burp richiedono la licenza Pro.

ZAP funziona come proxy tra il browser e il target: intercetta, analizza e modifica il traffico HTTP/HTTPS in tempo reale. Include un active scanner per trovare vulnerabilità automaticamente, uno spider per mappare l'applicazione e un fuzzer per testare input. Per chi opera in budget limitati o ha bisogno di uno strumento integrabile in pipeline CI/CD, ZAP è la scelta operativa.

Kill chain: **Vulnerability Assessment e Exploitation** (MITRE ATT\&CK T1190). L'articolo copre configurazione proxy, scansione automatizzata, scripting e integrazione nella pipeline offensiva.

***

## 1️⃣ Setup e Installazione

**Kali Linux:**

```bash
sudo apt install zaproxy
```

**Avvio:**

```bash
zaproxy &
```

**Docker (per headless/CI):**

```bash
docker pull ghcr.io/zaproxy/zaproxy:stable
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://target
```

**Versione attuale:** ZAP 2.15.0

**Requisiti:**

* Java 11+ (incluso nell'installer)
* \~500MB RAM minimo (1GB+ consigliato)
* Certificato CA di ZAP installato nel browser per intercettare HTTPS

**Setup proxy browser:**

Configura il browser per usare `127.0.0.1:8080` come proxy HTTP/HTTPS. Poi naviga su `https://zap` per scaricare e installare il certificato CA.

***

## 2️⃣ Uso Base

### Scansione automatica rapida

Dalla GUI: inserisci l'URL nel campo "URL to attack" e clicca "Attack". ZAP esegue spider + active scan.

**Da CLI (headless):**

```bash
zap-cli quick-scan -s all -r http://10.10.10.50
```

### Baseline scan (per CI/CD)

```bash
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://10.10.10.50 -r report.html
```

Output: report HTML con tutti i finding categorizzati per rischio.

### Spider per mappare l'applicazione

```bash
zap-cli spider http://10.10.10.50
```

Lo spider segue ogni link trovato nell'applicazione, costruendo una mappa completa di endpoint e parametri.

### Active scan

```bash
zap-cli active-scan http://10.10.10.50
```

Testa attivamente ogni endpoint trovato dallo spider per vulnerabilità: XSS, SQL injection, path traversal, CSRF e altre OWASP Top 10.

***

## 3️⃣ Tecniche Operative

### Intercettazione e modifica richieste

Con ZAP configurato come proxy e breakpoint attivi:

1. Imposta breakpoint su una richiesta specifica
2. Modifica parametri (es. cambia `user_id=1` in `user_id=2`)
3. Inoltra la richiesta modificata
4. Analizza la risposta per IDOR, privilege escalation, etc.

### Fuzzing di parametri

Seleziona un parametro nella request → tasto destro → "Fuzz":

* Seleziona il valore da fuzzare
* Scegli il payload (wordlist, numeri, caratteri speciali)
* Lancia il fuzzer
* Analizza le risposte per anomalie (size diversa, status code diverso, errori)

### Scanning autenticato

Per scansionare aree protette da login:

1. Naviga manualmente l'applicazione facendo login
2. ZAP cattura il cookie di sessione
3. Configura il "Context" con l'URL di login e le credenziali
4. Lo spider e l'active scan mantengono la sessione attiva

In alternativa, passa il cookie direttamente alla CLI:

```bash
zap-cli -p 8080 open-url "http://target/login"
zap-cli -p 8080 spider http://target/dashboard
zap-cli -p 8080 active-scan http://target/dashboard
```

### API REST di ZAP

ZAP espone un'API completa per automazione:

```bash
curl "http://localhost:8080/JSON/spider/action/scan/?url=http://target&apikey=YOUR_API_KEY"
```

L'API permette di controllare ogni funzionalità di ZAP programmaticamente.

***

## 4️⃣ Tecniche Avanzate

### Script ZAP per test custom

ZAP supporta script in JavaScript, Python (Jython) e Ruby:

```javascript
// Script per rilevare header di sicurezza mancanti
function scan(msg, id, name) {
    var headers = msg.getResponseHeader().toString();
    if (headers.indexOf("Content-Security-Policy") < 0) {
        alertHigh("Missing CSP Header", msg);
    }
}
```

### AJAX Spider per SPA

Applicazioni React/Angular/Vue richiedono l'AJAX Spider che usa un browser headless:

```bash
zap-cli ajax-spider http://10.10.10.50
```

Renderizza JavaScript e scopre endpoint invisibili allo spider tradizionale.

### Integration con Selenium

```python
from zapv2 import ZAPv2
zap = ZAPv2(apikey='API_KEY', proxies={'http': 'http://127.0.0.1:8080'})
zap.urlopen('http://target')
zap.spider.scan('http://target')
while int(zap.spider.status()) < 100:
    time.sleep(2)
zap.ascan.scan('http://target')
```

### Report personalizzato

```bash
zap-cli report -o report.html -f html
zap-cli report -o report.json -f json
zap-cli report -o report.xml -f xml
```

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Web app assessment completo — OWASP Top 10

```bash
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t http://10.10.10.50 -r full_report.html
```

**Output atteso:** report HTML con finding categorizzati (High, Medium, Low, Informational).

**Cosa fare se fallisce:**

* Scanner non trova nulla → L'app potrebbe richiedere autenticazione. Usa il context con credenziali.
* Timeout → Target lento. Configura timeout più elevati in ZAP options.

**Timeline:** Full scan su applicazione media (50-100 pagine): 15-30 minuti.

### Scenario 2: Test SQL injection specifico tramite fuzzing

Intercetta la richiesta con il parametro sospetto. Fuzz con payload SQLi:

```
' OR 1=1--
" OR "1"="1
'; DROP TABLE users--
UNION SELECT null,null,null--
```

**Output atteso:** risposte con size o status code diverso indicano SQL injection.

**Cosa fare se fallisce:**

* WAF blocca i payload → Prova encoding: URL encode, double encode, Unicode.
* Nessuna anomalia → Il parametro potrebbe non essere vulnerabile. Testa altri parametri.

**Timeline:** Fuzzing singolo parametro: 2-5 minuti.

### Scenario 3: Scanning CI/CD automatizzato

```bash
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://staging.corp.local \
  -r zap_report.html \
  -l WARN \
  -I
```

**Cosa fare se fallisce:**

* `-I` ignora warning e restituisce exit code 0 → Rimuovi per fail su qualsiasi finding.
* Container non raggiunge il target → Verifica networking Docker.

**Timeline:** Baseline scan: 3-5 minuti.

***

## 6️⃣ Toolchain Integration

ZAP si posiziona come scanner di vulnerabilità dopo la fase di discovery.

**Flusso operativo:**

[WhatWeb](https://hackita.it/articoli/whatweb)/Wappalyzer (tech ID) → [Dirsearch](https://hackita.it/articoli/dirsearch) (content discovery) → **ZAP (vuln scan + manual testing)** → Exploitation

| Feature               | ZAP           | Burp Suite Pro | Nikto    | Nuclei         |
| --------------------- | ------------- | -------------- | -------- | -------------- |
| Prezzo                | Free          | $449/anno      | Free     | Free           |
| Proxy intercettazione | Sì            | Sì             | No       | No             |
| Active scanner        | Sì            | Sì             | Limitato | Template-based |
| Fuzzer                | Sì            | Sì (Intruder)  | No       | No             |
| API                   | REST API      | REST API       | No       | CLI only       |
| CI/CD                 | Docker nativo | Enterprise     | Limitato | Ottimo         |
| AJAX Spider           | Sì            | Sì             | No       | No             |

***

## 7️⃣ Attack Chain Completa

**Obiettivo:** Trovare e sfruttare una SQL injection in un'applicazione enterprise.

**Fase 1 — Recon e Discovery (15 min)**

Dirsearch + WhatWeb identificano un'applicazione PHP con form di ricerca.

**Fase 2 — Spider e Active Scan (20 min)**

ZAP spider mappa l'applicazione. Active scan trova SQL injection nel parametro `search`.

**Fase 3 — Exploitation manuale (10 min)**

Usa ZAP per intercettare la richiesta, inietta payload SQLi manualmente. Conferma injection e estrai dati con `UNION SELECT`.

**Fase 4 — Data Exfiltration (10 min)**

Dump credenziali admin dal database via SQL injection. Per approfondire le tecniche di [SQL injection](https://hackita.it/articoli/sqlinjection), consulta la nostra guida dedicata.

**Fase 5 — Post-exploitation (20 min)**

Login come admin, upload web shell, shell sul server.

**Timeline totale:** \~75 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* Richieste con payload di attacco (SQLi, XSS) negli access log e WAF
* Volume di richieste anomalo dallo spider/scanner
* User-Agent ZAP (se non modificato)

### Log rilevanti

* WAF → ModSecurity CRS rules per SQLi, XSS, path traversal
* Web server → burst di richieste POST con payload anomali
* Application log → errori SQL, exception non gestite

### Tecniche di evasion

1. **Riduci velocità scanner:** nelle opzioni ZAP, imposta delay tra richieste (Options → Active Scan → Delay in ms).
2. **User-Agent custom:** cambia nelle opzioni di connessione.
3. **Scan selettivo:** scansiona solo endpoint specifici invece dell'intera applicazione.

### Cleanup

ZAP non lascia artefatti permanenti sul target.

***

## 9️⃣ Performance & Scaling

**Active scan singola app:** 15-30 minuti per applicazione media.

**AJAX Spider:** più lento (30-60 minuti) — usa browser headless per rendering JS.

**Consumo risorse:** 500MB-1GB RAM. Su app grandi, può arrivare a 2GB+.

**Ottimizzazione:** limita la profondità dello spider, escludi path statici (immagini, CSS, JS), focus su endpoint con parametri.

***

## 🔟 Tabelle Tecniche

### CLI Commands Reference

| Comando                         | Descrizione              |
| ------------------------------- | ------------------------ |
| `zap-cli quick-scan URL`        | Scansione rapida         |
| `zap-cli spider URL`            | Spider dell'applicazione |
| `zap-cli active-scan URL`       | Active scan              |
| `zap-cli ajax-spider URL`       | AJAX Spider (SPA)        |
| `zap-cli report -o file -f fmt` | Genera report            |
| `zap-cli alerts`                | Mostra alert trovati     |
| `zap-cli open-url URL`          | Apri URL in ZAP          |
| `zap-baseline.py -t URL`        | Baseline scan (Docker)   |
| `zap-full-scan.py -t URL`       | Full scan (Docker)       |

### Docker scan types

| Script             | Tipo    | Durata    | Uso                     |
| ------------------ | ------- | --------- | ----------------------- |
| `zap-baseline.py`  | Passivo | 3-5 min   | CI/CD, quick check      |
| `zap-full-scan.py` | Attivo  | 15-60 min | Assessment completo     |
| `zap-api-scan.py`  | API     | 5-15 min  | OpenAPI/Swagger testing |

***

## 11️⃣ Troubleshooting

| Problema                | Causa                         | Fix                                     |
| ----------------------- | ----------------------------- | --------------------------------------- |
| HTTPS non intercettato  | Certificato CA non installato | Naviga `https://zap` e installa il cert |
| Scanner lento           | App grande o rete lenta       | Limita scope e profondità spider        |
| Java heap error         | RAM insufficiente             | Aumenta `-Xmx` nelle opzioni JVM        |
| Spider non trova pagine | SPA con JavaScript            | Usa AJAX Spider                         |
| API non risponde        | API key mancante              | Configura API key in Options → API      |

***

## 12️⃣ FAQ

**ZAP sostituisce Burp Suite?**
Per molte operazioni sì. Burp Pro ha vantaggi in estensioni e usabilità, ma ZAP copre il 90% dei casi d'uso a costo zero.

**Posso usare ZAP headless in pipeline CI/CD?**
Sì. I Docker scan scripts (`zap-baseline.py`, `zap-full-scan.py`) sono progettati per questo.

**ZAP trova zero-day?**
Potenzialmente. L'active scanner testa pattern di attacco generici che possono rivelare vulnerabilità non ancora catalogate.

**Posso testare API REST con ZAP?**
Sì. Importa la specifica OpenAPI/Swagger e usa `zap-api-scan.py`.

**ZAP funziona via proxy per target interni?**
Sì. Configura il proxy upstream nelle opzioni di connessione di ZAP.

***

## 13️⃣ Cheat Sheet

| Azione               | Comando                                                                           |
| -------------------- | --------------------------------------------------------------------------------- |
| Baseline scan Docker | `docker run -t zaproxy/zaproxy:stable zap-baseline.py -t URL -r report.html`      |
| Full scan Docker     | `docker run -t zaproxy/zaproxy:stable zap-full-scan.py -t URL -r report.html`     |
| API scan             | `docker run -t zaproxy/zaproxy:stable zap-api-scan.py -t openapi.json -f openapi` |
| Spider CLI           | `zap-cli spider URL`                                                              |
| Active scan CLI      | `zap-cli active-scan URL`                                                         |
| AJAX Spider          | `zap-cli ajax-spider URL`                                                         |
| Report HTML          | `zap-cli report -o report.html -f html`                                           |

***

**Disclaimer:** OWASP ZAP è un progetto open source per security testing. Le scansioni attive possono causare instabilità sulle applicazioni target. Usa solo in ambienti autorizzati. Repository: [github.com/zaproxy/zaproxy](https://github.com/zaproxy/zaproxy).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
