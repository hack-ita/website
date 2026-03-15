---
title: 'WhatWeb: guida completa al web fingerprinting stealth e aggressivo'
slug: whatweb
description: 'Scopri come usare WhatWeb per identificare CMS, framework, web server, librerie JavaScript e tecnologie di un sito web, così da orientare reconnaissance, fingerprinting e vulnerability scanning mirato.'
image: /whatweb.webp
draft: true
date: 2026-04-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - web-fingerprinting
  - tech-discovery
---

Prima di attaccare un'applicazione web, devi sapere cosa c'è sotto. WhatWeb identifica tecnologie web — CMS, framework, librerie JavaScript, web server, sistemi operativi, device e molto altro. Riconosce oltre 1.800 plugin e può operare in modalità stealth con una singola richiesta HTTP o in modalità aggressiva con enumerazione completa.

L'output di WhatWeb alimenta direttamente la scelta dei tool successivi: se trovi WordPress, lanci WPScan; se trovi Apache 2.4.49, cerchi CVE-2021-41773; se trovi Tomcat, provi default credentials. È il primo anello della catena decisionale in un web pentest.

Nella kill chain si colloca nella fase di **Reconnaissance / Technology Discovery** (MITRE ATT\&CK T1592.004). Qui trovi configurazione, livelli di aggressività, scansione su larga scala e integrazione con gli scanner di vulnerabilità.

***

## 1️⃣ Setup e Installazione

Preinstallato su Kali Linux:

```bash
whatweb --version
```

Output:

```
WhatWeb version 0.5.5
```

**Installazione manuale:**

```bash
sudo apt install whatweb
```

**Da sorgente:**

```bash
git clone https://github.com/urbanadventurer/WhatWeb.git
cd WhatWeb
sudo make install
```

**Requisiti:**

* Ruby 2.x+
* Gem: `addressable`, `json`, `mongo` (opzionali per output avanzato)
* Nessun requisito sul target

***

## 2️⃣ Uso Base

```bash
whatweb http://10.10.10.50
```

Output:

```
http://10.10.10.50 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.10.50], JQuery[3.6.0], PHP[8.1.2], Title[Welcome], WordPress[6.4.2]
```

In una riga: server Apache 2.4.52 su Ubuntu, PHP 8.1.2, WordPress 6.4.2, jQuery 3.6.0.

**Livelli di aggressività:**

```bash
whatweb -a 1 http://10.10.10.50  # Stealth: 1 sola richiesta
whatweb -a 3 http://10.10.10.50  # Standard (default)
whatweb -a 4 http://10.10.10.50  # Aggressivo: richieste extra per ogni plugin
```

* **Level 1 (stealth):** una singola richiesta HTTP GET. Ideale quando la detection è un rischio.
* **Level 3 (default):** analisi approfondita degli header, del body e dei redirect.
* **Level 4 (aggressive):** richieste aggiuntive per confermare ogni match. Più rumoroso ma più preciso.

**Output verbose:**

```bash
whatweb -v http://10.10.10.50
```

Mostra ogni plugin matchato con il dettaglio del metodo di detection.

***

## 3️⃣ Tecniche Operative

### Scansione multi-target da file

```bash
whatweb -i targets.txt --log-json=results.json
```

L'output JSON è parsabile per automazione:

```bash
cat results.json | jq '.[] | select(.plugins.WordPress) | .target'
```

Estrae tutti i target che eseguono WordPress.

### Scansione di un intero range

```bash
whatweb 10.10.10.0/24 --no-errors -a 1
```

Scansiona tutto il range /24. Con `-a 1`, genera una sola richiesta per host — veloce e relativamente discreto.

### Identificazione versioni specifiche

```bash
whatweb -v http://10.10.10.50 | grep -i version
```

WhatWeb rileva versioni di:

* CMS (WordPress, Joomla, Drupal, Magento)
* Framework (Laravel, Django, Rails, Spring)
* Server (Apache, Nginx, IIS, Tomcat)
* Linguaggi (PHP, Python, Java, .NET)
* JavaScript libraries (jQuery, React, Angular)

### Scansione attraverso proxy

```bash
whatweb --proxy 127.0.0.1:8080 http://target.com
```

Utile per far passare il traffico attraverso Burp Suite o un tunnel SOCKS.

***

## 4️⃣ Tecniche Avanzate

### Plugin custom

WhatWeb supporta plugin Ruby custom per rilevare applicazioni proprietarie:

```ruby
Plugin.define do
name "Custom-App"
description "Custom enterprise application"
website "https://internal.corp"
matches [
  { :text => "X-Custom-App-Version" },
  { :regexp => /CustomApp\/([0-9.]+)/ },
]
end
```

### User-Agent rotation

```bash
whatweb --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://target.com
```

### Follow redirect con depth control

```bash
whatweb --max-redirects 5 http://target.com
```

Segue fino a 5 redirect, analizzando ogni hop.

### Output multiplo simultaneo

```bash
whatweb http://10.10.10.50 --log-json=out.json --log-xml=out.xml --log-verbose=out.txt
```

Genera report in 3 formati con un solo comando.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Fingerprinting stealth su target sensibile

```bash
whatweb -a 1 https://target.com --user-agent "Mozilla/5.0 (compatible; Googlebot/2.1)"
```

**Output atteso:**

```
https://target.com [200 OK] Nginx[1.18.0], PHP[7.4.33], WordPress[6.2.1]
```

**Cosa fare se fallisce:**

* WAF blocca la richiesta → Cambia User-Agent o usa un IP proxy residenziale.
* Redirect a login page → L'applicazione richiede autenticazione. Usa `--cookie` per passare una sessione valida.

**Timeline:** Meno di 1 secondo per target.

### Scenario 2: Technology mapping di un intero perimetro

```bash
whatweb -i live_hosts.txt --log-json=tech_map.json -a 3 --no-errors
```

**Output atteso:** JSON con tecnologie per ogni host.

**Cosa fare se fallisce:**

* Timeout su host lenti → `--open-timeout 10 --read-timeout 15`.
* Risultati parziali → Alcuni host potrebbero non rispondere. Filtra gli errori dal JSON con `jq`.

**Timeline:** 200 host a livello 3: 3-5 minuti.

### Scenario 3: Identificazione CMS per exploit targeting

```bash
whatweb -v http://10.10.10.50 | grep -iE "wordpress|joomla|drupal|magento"
```

**Output atteso:**

```
WordPress[6.4.2], WordPress-Theme[flavor], WordPress-Plugin[contact-form-7]
```

**Cosa fare se fallisce:**

* CMS non rilevato → Il CMS potrebbe essere personalizzato o il fingerprint nascosto. Controlla il sorgente HTML manualmente: `curl -s http://target | grep -i generator`.

**Timeline:** Istantaneo su singolo target.

***

## 6️⃣ Toolchain Integration

WhatWeb è il bridge tra network scanning e vulnerability scanning.

**Flusso operativo:**

[Nmap](https://hackita.it/articoli/nmap) (port scan) → **WhatWeb (tech fingerprint)** → [Nuclei](https://hackita.it/articoli/nuclei) (vuln scan mirato) → Exploitation

**Passaggio dati:**

```bash
# Nmap trova porte web
nmap -p 80,443 10.10.10.0/24 -oG web.gnmap
grep "open" web.gnmap | awk '{print $2}' > hosts.txt

# WhatWeb identifica tecnologie
whatweb -i hosts.txt --log-json=tech.json -a 3

# Filtra WordPress per scansione mirata
cat tech.json | jq -r '.[] | select(.plugins.WordPress) | .target' > wp_targets.txt

# Nuclei con template WordPress specifici
nuclei -l wp_targets.txt -tags wordpress
```

| Feature         | WhatWeb      | [Wappalyzer](https://hackita.it/articoli/wappalyzer) | BuiltWith | Netcraft  |
| --------------- | ------------ | ---------------------------------------------------- | --------- | --------- |
| CLI tool        | Sì           | Extension browser                                    | Web only  | Web only  |
| Plugin count    | 1.800+       | 1.500+                                               | Vasto     | Limitato  |
| Stealth mode    | Sì (level 1) | N/A                                                  | N/A       | N/A       |
| Scriptabilità   | Totale       | Limitata                                             | No        | No        |
| Prezzo          | Free         | Free/Paid                                            | Paid      | Free/Paid |
| Uso in pipeline | Nativo       | API only                                             | API only  | API only  |

***

## 7️⃣ Attack Chain Completa

**Obiettivo:** Trovare e sfruttare un CMS vulnerabile in una rete target.

**Fase 1 — Discovery (5 min)**

```bash
sudo masscan 192.168.1.0/24 -p 80,443,8080 --rate 1000 -oG ports.gnmap
```

**Fase 2 — Tech Fingerprinting con WhatWeb (3 min)**

```bash
whatweb -i web_hosts.txt --log-json=tech.json -a 3
```

Trova WordPress 6.2.1 su 192.168.1.25 e Joomla 4.2.7 su 192.168.1.30.

**Fase 3 — Vulnerability Scan (5 min)**

```bash
nuclei -u http://192.168.1.25 -tags wordpress -severity critical,high
```

Trova plugin vulnerabile con file upload non autenticato.

**Fase 4 — Exploitation (10 min)**

Upload di web shell via plugin vulnerabile. Shell come `www-data`.

**Fase 5 — Lateral Movement (25 min)**

Credenziali database nel `wp-config.php`. Password riusata per SSH su altro server. Approfondisci le tecniche di enumerazione della rete con strumenti come [Nmap](https://hackita.it/articoli/nmap) per identificare ulteriori vettori d'attacco.

**Timeline totale:** \~48 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* User-Agent `WhatWeb` nel default
* Richieste verso path di fingerprinting (es. `/wp-login.php`, `/administrator/`, `/readme.html`)
* Pattern singola richiesta seguita da parsing intensivo (level 1)

### Log rilevanti

* Web server access log → richieste verso path di fingerprinting
* WAF → detection di scanner basata su User-Agent

### Tecniche di evasion

1. **Level 1 + UA custom:** una sola richiesta con User-Agent legittimo. Praticamente invisibile.
2. **Via proxy:** passa il traffico attraverso un proxy residenziale.
3. **Timing:** scansiona durante orari di traffico elevato per confondersi.

### Cleanup

WhatWeb non lascia tracce sul target oltre le entry nei log del web server.

***

## 9️⃣ Performance & Scaling

**Single target:** Level 1 sotto 1 secondo. Level 4 circa 5-10 secondi.

**Multi-target:** WhatWeb gestisce liste di centinaia di host. Su 500 host a level 3: 10-15 minuti.

**Consumo risorse:** \~20-30MB di RAM. Rete è il bottleneck.

***

## 🔟 Tabelle Tecniche

### Command Reference

| Flag                | Descrizione                |
| ------------------- | -------------------------- |
| `-a N`              | Livello aggressività (1-4) |
| `-i file`           | Input da file              |
| `-v`                | Output verbose             |
| `--log-json=file`   | Output JSON                |
| `--log-xml=file`    | Output XML                 |
| `--proxy host:port` | Proxy HTTP                 |
| `--user-agent str`  | UA custom                  |
| `--cookie str`      | Cookie di sessione         |
| `--max-redirects N` | Max redirect               |
| `--no-errors`       | Sopprimi errori            |
| `--open-timeout N`  | Timeout connessione        |
| `--read-timeout N`  | Timeout lettura            |

### Livelli di aggressività

| Level | Richieste | Stealth | Accuracy | Uso                             |
| ----- | --------- | ------- | -------- | ------------------------------- |
| 1     | 1         | ★★★★★   | ★★★☆☆    | OSINT / target sensibile        |
| 3     | 5-10      | ★★★☆☆   | ★★★★☆    | Default / pentest standard      |
| 4     | 10-30+    | ★☆☆☆☆   | ★★★★★    | Lab / CTF / assessment completo |

***

## 11️⃣ Troubleshooting

| Problema                | Causa                    | Fix                                   |
| ----------------------- | ------------------------ | ------------------------------------- |
| Nessun output           | Target non raggiungibile | Verifica con `curl -I http://target`  |
| Plugin non riconosciuti | Database non aggiornato  | `whatweb --update` o `git pull`       |
| SSL error               | Certificato non valido   | WhatWeb ignora SSL errors di default  |
| Timeout                 | Server lento             | `--open-timeout 15 --read-timeout 20` |
| Output troppo verboso   | Level 4 su tanti host    | Usa level 1 o 3, filtra con `grep`    |

***

## 12️⃣ FAQ

**WhatWeb è meglio di Wappalyzer?**
Per pentest da CLI, sì. WhatWeb è scriptabile, ha livelli di aggressività e output strutturato. Wappalyzer è più comodo come estensione browser per analisi manuali.

**WhatWeb rileva WAF?**
Sì. Plugin dedicati rilevano Cloudflare, AWS WAF, ModSecurity e altri.

**Posso usare WhatWeb attraverso Tor?**
Sì: `whatweb --proxy 127.0.0.1:9050 http://target`. Usa il SOCKS proxy di Tor.

**Quanto è accurato il version detection?**
Al level 4, molto accurato. Al level 1, può mancare versioni specifiche — rileva il CMS ma non sempre la versione esatta.

**WhatWeb gestisce JavaScript-rendered content?**
No. Analizza solo HTML statico e header HTTP. Per contenuto renderizzato da JS, usa strumenti headless browser-based.

***

## 13️⃣ Cheat Sheet

| Azione       | Comando                                      |
| ------------ | -------------------------------------------- |
| Scan rapido  | `whatweb http://target`                      |
| Stealth      | `whatweb -a 1 http://target`                 |
| Aggressivo   | `whatweb -a 4 http://target`                 |
| Multi-target | `whatweb -i hosts.txt --log-json=out.json`   |
| Con proxy    | `whatweb --proxy 127.0.0.1:8080 URL`         |
| Range /24    | `whatweb 10.10.10.0/24 -a 1 --no-errors`     |
| Verbose      | `whatweb -v http://target`                   |
| UA custom    | `whatweb --user-agent "Mozilla/5.0 ..." URL` |
| JSON output  | `whatweb URL --log-json=results.json`        |

***

**Disclaimer:** WhatWeb è un tool di fingerprinting open source per security assessment autorizzati. Usalo solo su sistemi per cui hai permesso esplicito. Repository: [github.com/urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
