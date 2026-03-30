---
title: >-
  Subfinder: guida completa alla subdomain enumeration passiva con
  ProjectDiscovery
slug: subfinder
description: >-
  Scopri come usare Subfinder per trovare subdomain validi tramite fonti
  passive, velocizzare la reconnaissance web e costruire una pipeline di recon
  più efficace con il tool ProjectDiscovery ottimizzato per velocità e stealth.
image: /sub-finder.webp
draft: false
date: 2026-03-31T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - subdomain-enumeration
  - passive-recon
---

Subfinder è il tool di subdomain enumeration passiva più rapido dell'ecosistema ProjectDiscovery. Interroga oltre 30 data source — certificate transparency, motori di ricerca, API di threat intelligence — senza inviare una singola query DNS al target. In meno di 30 secondi restituisce centinaia di subdomain che altri strumenti richiederebbero minuti per trovare.

La velocità di Subfinder lo rende ideale come primo step nella pipeline di recon: lanci Subfinder, pipi l'output in [Httpx](https://hackita.it/articoli/httpx) per il probe, poi in [Nuclei](https://hackita.it/articoli/nuclei) per il vulnerability scanning — il tutto in una singola riga di comando.

Kill chain: **Reconnaissance passiva** (MITRE ATT\&CK T1590.002).

***

## 1️⃣ Setup e Installazione

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

O:

```bash
sudo apt install subfinder
```

**Verifica:**

```bash
subfinder -version
```

Output: `subfinder v2.6.7`

**Configurazione API key** (`~/.config/subfinder/provider-config.yaml`):

```yaml
shodan:
  - YOUR_KEY
virustotal:
  - YOUR_KEY
securitytrails:
  - YOUR_KEY
chaos:
  - YOUR_KEY
censys:
  - YOUR_KEY:YOUR_SECRET
```

Senza API: \~50% dei risultati. Con API: coverage massima.

***

## 2️⃣ Uso Base

```bash
subfinder -d target.com -silent
```

Output:

```
www.target.com
mail.target.com
api.target.com
dev.target.com
staging.target.com
vpn.target.com
jenkins.target.com
```

**Flag principali:**

* `-d domain` → dominio target
* `-dL file` → file con lista domini
* `-silent` → solo output subdomain
* `-o file` → output file
* `-json` → output JSON
* `-all` → usa tutte le fonti (più lento, più completo)
* `-t N` → thread
* `-timeout N` → timeout secondi
* `-rL file` → resolver list custom

***

## 3️⃣ Tecniche Operative

### Enumerazione multipla domini

```bash
subfinder -dL domains.txt -silent -o all_subs.txt
```

### Pipeline one-liner completa

```bash
subfinder -d target.com -silent | httpx -silent -status-code -title | nuclei -severity critical,high
```

### Output ricco per analisi

```bash
subfinder -d target.com -json -o results.json
cat results.json | jq -r '.host'
```

Il JSON include la fonte di discovery per ogni subdomain.

### Tutte le fonti (modalità exhaustive)

```bash
subfinder -d target.com -all -silent
```

Più lento ma interroga ogni singola fonte configurata.

***

## 4️⃣ Tecniche Avanzate

### Combinazione con Amass per maximum coverage

```bash
subfinder -d target.com -silent -o sf.txt
amass enum -passive -d target.com -o am.txt
cat sf.txt am.txt | sort -u > combined.txt
```

### Resolver custom per evitare rate limiting

```bash
subfinder -d target.com -rL resolvers.txt -silent
```

### Recursive enumeration

```bash
subfinder -d target.com -silent | while read sub; do
  subfinder -d "$sub" -silent
done | sort -u
```

Enumera subdomain di subdomain (es. trovi `dev.target.com`, poi cerchi `*.dev.target.com`).

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Quick recon pre-engagement

```bash
subfinder -d corp.com -silent | httpx -silent -status-code -title -tech-detect
```

**Output atteso:** lista subdomain live con tecnologie.

**Timeline:** 30-60 secondi totali.

### Scenario 2: Multi-domain assessment

```bash
echo -e "corp.com\ncorp.io\ncorp.dev" > domains.txt
subfinder -dL domains.txt -silent | sort -u | httpx -silent
```

**Timeline:** 1-2 minuti per tutti i domini.

### Scenario 3: Monitoraggio nuovi subdomain

```bash
subfinder -d target.com -silent > baseline.txt
# Dopo una settimana
subfinder -d target.com -silent > current.txt
comm -13 <(sort baseline.txt) <(sort current.txt)
```

**Output:** solo subdomain nuovi.

***

## 6️⃣ Toolchain Integration

**Flusso:**

**Subfinder** → [Httpx](https://hackita.it/articoli/httpx) → [Aquatone](https://hackita.it/articoli/aquatone) / [Nuclei](https://hackita.it/articoli/nuclei)

| Tool        | Velocità | Fonti | Bruteforce | Passivo |
| ----------- | -------- | ----- | ---------- | ------- |
| Subfinder   | ★★★★★    | 30+   | No         | Sì      |
| Amass       | ★★★☆☆    | 50+   | Sì         | Sì/No   |
| Assetfinder | ★★★★★    | 5+    | No         | Sì      |
| Sublist3r   | ★★★☆☆    | 10+   | No         | Sì      |

***

## 7️⃣ Attack Chain Completa

**Fase 1:** `subfinder -d corp.com -silent` → 300 subdomain (20 sec).

**Fase 2:** `httpx -silent` → 180 live (30 sec).

**Fase 3:** `nuclei -severity critical,high` → CVE su `jira.corp.com` (5 min).

**Fase 4:** Exploit Jira → shell → lateral movement (30 min).

**Timeline:** \~36 minuti.

***

## 8️⃣ Detection & Evasion

Subfinder è 100% passivo — nessun traffico verso il target. Zero detection.

***

## 9️⃣ Performance & Scaling

**Single domain:** 10-30 secondi. **100 domini:** 5-10 minuti. **Consumo:** \~30MB RAM.

***

## 🔟 Tabelle Tecniche

| Flag         | Descrizione       |
| ------------ | ----------------- |
| `-d domain`  | Dominio target    |
| `-dL file`   | File lista domini |
| `-silent`    | Solo subdomain    |
| `-o file`    | Output            |
| `-json`      | JSON output       |
| `-all`       | Tutte le fonti    |
| `-t N`       | Thread            |
| `-rL file`   | Resolver custom   |
| `-timeout N` | Timeout (sec)     |

***

## 11️⃣ Troubleshooting

| Problema        | Causa            | Fix                                |
| --------------- | ---------------- | ---------------------------------- |
| Pochi risultati | API key mancanti | Configura `provider-config.yaml`   |
| Errori API      | Rate limiting    | Usa `-t 5` per ridurre concorrenza |
| Timeout         | Fonte lenta      | `-timeout 30`                      |

***

## 12️⃣ FAQ

**Subfinder vs Amass?** Subfinder è più veloce per enum passivo. Amass è più completo con bruteforce e alterations.

**Serve connessione internet?** Sì, interroga API esterne.

**Posso usarlo offline?** No.

**Quante API key servono?** Minimo Shodan + VirusTotal. Ideale: 5-10 fonti.

***

## 13️⃣ Cheat Sheet

| Azione         | Comando                                          |
| -------------- | ------------------------------------------------ |
| Enum base      | `subfinder -d domain.com -silent`                |
| Multi-domain   | `subfinder -dL domains.txt -silent`              |
| Tutte le fonti | `subfinder -d domain -all -silent`               |
| JSON           | `subfinder -d domain -json -o out.json`          |
| Pipeline       | `subfinder -d domain \| httpx -silent \| nuclei` |

***

**Disclaimer:** Subfinder è un tool per recon passiva autorizzata. Repository: [github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
