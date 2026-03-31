---
title: 'Waybackurls: come trovare URL storici, endpoint nascosti e file sensibili'
slug: waybackurls
description: >-
  Scopri come usare Waybackurls per estrarre gli URL storici di un dominio dalla
  Wayback Machine, trovare path dimenticati, backup esposti e vecchi endpoint
  utili nella reconnaissance passiva.
image: /waybackurls.webp
draft: false
date: 2026-04-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - historical-urls
  - passive-recon
---

Waybackurls interroga la Wayback Machine di Internet Archive per recuperare tutti gli URL storicamente indicizzati per un dominio target. Pagine rimosse, endpoint API dismessi, file di configurazione esposti anni fa, path di admin dimenticati — tutto ciò che è stato visto almeno una volta dal crawler di Archive.org diventa accessibile.

Nel penetration testing è uno strumento di recon passiva devastante: non invii una singola richiesta al target, ma ottieni migliaia di URL che rivelano la struttura dell'applicazione nel tempo. Endpoint che oggi restituiscono 404 potrebbero ancora funzionare con path leggermente diversi, e file sensibili rimossi dal sito potrebbero essere ancora nella cache dell'archivio.

Kill chain: **Reconnaissance passiva** (MITRE ATT\&CK T1593.002). Questo articolo copre installazione, filtraggio dell'output, integrazione nella pipeline e tecniche per trovare vulnerabilità da URL storici.

***

## 1️⃣ Setup e Installazione

```bash
go install github.com/tomnomnom/waybackurls@latest
```

**Verifica:**

```bash
waybackurls -h
```

**Requisiti:**

* Go 1.17+
* Connettività verso `web.archive.org`
* Nessun requisito sul target (recon completamente passiva)

***

## 2️⃣ Uso Base

```bash
echo "target.com" | waybackurls
```

Output (parziale):

```
https://target.com/admin/login.php
https://target.com/api/v1/users
https://target.com/backup/db.sql
https://target.com/config.php.old
https://target.com/wp-content/uploads/2021/report.pdf
https://target.com/.env
https://target.com/test/phpinfo.php
```

Ogni URL è stato indicizzato almeno una volta dalla Wayback Machine.

**Con timestamp:**

```bash
echo "target.com" | waybackurls -dates
```

Output:

```
2021-03-15T10:23:45Z https://target.com/admin/login.php
2020-11-02T08:15:30Z https://target.com/backup/db.sql
2019-06-20T14:45:12Z https://target.com/.env
```

I timestamp mostrano quando l'URL è stato visto l'ultima volta.

**No subs (solo dominio principale):**

```bash
echo "target.com" | waybackurls -no-subs
```

Esclude URL di subdomain.

***

## 3️⃣ Tecniche Operative

### Filtrare per estensione — Trovare file sensibili

```bash
echo "target.com" | waybackurls | grep -iE "\.sql|\.bak|\.old|\.env|\.config|\.zip|\.tar|\.gz|\.log"
```

Output:

```
https://target.com/backup/site_2020.sql
https://target.com/config.php.bak
https://target.com/.env
https://target.com/logs/error.log
```

Ogni file è un potenziale data leak. Verifica se è ancora accessibile:

```bash
echo "target.com" | waybackurls | grep -iE "\.sql|\.bak|\.env" | httpx -silent -mc 200
```

### Trovare endpoint API

```bash
echo "target.com" | waybackurls | grep -iE "/api/|/v1/|/v2/|/graphql|/rest/"
```

Endpoint API storici che potrebbero essere ancora attivi o parzialmente funzionanti.

### Estrarre parametri per fuzzing

```bash
echo "target.com" | waybackurls | grep "?" | sort -u > params.txt
```

URL con parametri GET. Passali a strumenti come [Arjun](https://hackita.it/articoli/arjun) o sqlmap per testing di injection.

### Filtrare URL unici per path

```bash
echo "target.com" | waybackurls | sort -u | uro
```

`uro` (URL deduplication) rimuove URL simili mantenendo solo path unici. Riduce migliaia di URL a centinaia di path significativi.

***

## 4️⃣ Tecniche Avanzate

### Verificare URL storici dalla cache Wayback

Un file rimosso dal server potrebbe essere ancora nella cache:

```bash
curl "https://web.archive.org/web/2021/https://target.com/.env"
```

Se l'archivio ha una copia, ottieni il contenuto originale — credenziali, API key, configurazioni.

### Combinazione con gau per coverage massima

`gau` (Get All URLs) interroga più fonti oltre alla Wayback Machine (Common Crawl, URLScan, AlienVault OTX):

```bash
echo "target.com" | gau | sort -u > all_urls.txt
echo "target.com" | waybackurls | sort -u >> all_urls.txt
sort -u all_urls.txt -o all_urls.txt
```

### Pipeline per trovare XSS e SQLi potenziali

```bash
echo "target.com" | waybackurls | grep "=" | qsreplace "FUZZ" | sort -u > fuzz_targets.txt
```

`qsreplace` sostituisce tutti i valori dei parametri con "FUZZ". Ogni URL diventa un target per fuzzing automatico.

### Filtrare JavaScript per secret discovery

```bash
echo "target.com" | waybackurls | grep "\.js$" | sort -u > js_files.txt
cat js_files.txt | while read url; do
  curl -s "$url" | grep -iE "api_key|secret|token|password|aws_access"
done
```

File JS storici possono contenere API key hardcoded.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Trovare backup database esposti

```bash
echo "corp.com" | waybackurls | grep -iE "\.sql|\.db|dump" | httpx -silent -mc 200
```

**Output atteso:**

```
https://corp.com/backup/users_2020.sql
```

**Cosa fare se fallisce:**

* Tutti 404 → File rimossi. Controlla la Wayback Machine cache: `https://web.archive.org/web/*/corp.com/backup/*`.
* Nessun URL trovato → Dominio recente o non indicizzato. Prova con `gau` per fonti alternative.

**Timeline:** 10 secondi per estrazione, 30 secondi per verifica.

### Scenario 2: Scoprire endpoint API dismessi ma funzionanti

```bash
echo "api.target.com" | waybackurls | grep "/api/" | sort -u | httpx -silent -mc 200,401,403
```

**Output atteso:**

```
https://api.target.com/api/v1/users [200]
https://api.target.com/api/v2/admin [401]
https://api.target.com/api/internal/debug [200]
```

**Cosa fare se fallisce:**

* Tutti 404 → API completamente dismessa. Cerca path simili nelle versioni attuali.

**Timeline:** 15 secondi.

### Scenario 3: Estrarre secret da JavaScript storico

```bash
echo "target.com" | waybackurls | grep "\.js$" | sort -u | head -50 | while read url; do
  content=$(curl -s "https://web.archive.org/web/2023/$url")
  echo "$content" | grep -oiE "(api_key|secret|token|password)\s*[:=]\s*['\"][^'\"]+['\"]" && echo ">>> $url"
done
```

**Cosa fare se fallisce:**

* Wayback Machine rate limiting → Aggiungi `sleep 1` nel loop.

**Timeline:** 2-5 minuti per 50 file JS.

***

## 6️⃣ Toolchain Integration

Waybackurls alimenta la fase di discovery senza generare traffico verso il target.

**Flusso operativo:**

**Waybackurls (URL storico)** → [Httpx](https://hackita.it/articoli/httpx) (verifica live) → [Nuclei](https://hackita.it/articoli/nuclei) (vuln scan su endpoint trovati)

**Passaggio dati:**

```bash
echo "target.com" | waybackurls | sort -u | httpx -silent -mc 200 | nuclei -severity critical,high
```

| Tool        | Fonte dati                  | Passivo | Multi-source | Output   |
| ----------- | --------------------------- | ------- | ------------ | -------- |
| Waybackurls | Wayback Machine             | Sì      | No           | URL list |
| gau         | WBM + CommonCrawl + URLScan | Sì      | Sì           | URL list |
| katana      | Crawling attivo             | No      | N/A          | URL list |
| gospider    | Crawling attivo             | No      | N/A          | URL + JS |

***

## 7️⃣ Attack Chain Completa

**Obiettivo:** Compromettere un'applicazione tramite credenziali trovate in file storici.

**Fase 1 — URL Extraction (30 sec)**

```bash
echo "target.com" | waybackurls | sort -u > urls.txt
```

8.423 URL estratti.

**Fase 2 — Filtraggio file sensibili (10 sec)**

```bash
grep -iE "\.env|\.sql|config|backup" urls.txt | httpx -silent -mc 200
```

Trova `https://target.com/.env` ancora accessibile.

**Fase 3 — Credential Extraction (1 min)**

```bash
curl -s https://target.com/.env
```

Contiene `DB_PASSWORD=Pr0d_DB!2025` e `AWS_SECRET_ACCESS_KEY=...`.

**Fase 4 — Database Access (5 min)**

Connessione al database con le credenziali trovate. Dump utenti admin.

**Fase 5 — Admin Access e Shell (15 min)**

Login come admin → upload web shell → RCE.

**Timeline totale:** \~22 minuti. Zero traffico di scansione verso il target nella fase critica.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* Nulla. Waybackurls interroga solo Archive.org, non il target.

### Tecniche di evasion

* Waybackurls è 100% passivo. Non genera traffico verso il target.
* La verifica degli URL (con httpx/curl) genera traffico minimo e legittimo.

### Cleanup

Nessun artefatto. La fase di verifica lascia solo entry standard nei log del web server.

***

## 9️⃣ Performance & Scaling

**Single domain:** 5-30 secondi per l'estrazione, dipende da quanti URL ha Archive.org.

**Multi-domain:**

```bash
cat domains.txt | while read d; do echo "$d" | waybackurls; done | sort -u > all.txt
```

**Limiti:** Archive.org può rate-limitare richieste eccessive. Aggiungi delay per liste lunghe.

***

## 🔟 Tabelle Tecniche

### Flag Reference

| Flag            | Descrizione                         |
| --------------- | ----------------------------------- |
| `-dates`        | Mostra timestamp                    |
| `-no-subs`      | Escludi subdomain                   |
| `-get-versions` | Mostra tutte le versioni archiviate |

### Confronto tool per URL extraction

| Tool        | Fonte           | Passivo | Velocità | Coverage |
| ----------- | --------------- | ------- | -------- | -------- |
| waybackurls | Wayback Machine | Sì      | ★★★★☆    | ★★★★☆    |
| gau         | Multi-source    | Sì      | ★★★★★    | ★★★★★    |
| katana      | Crawling live   | No      | ★★★★☆    | ★★★☆☆    |
| hakrawler   | Crawling live   | No      | ★★★☆☆    | ★★★☆☆    |

***

## 11️⃣ Troubleshooting

| Problema             | Causa                           | Fix                                   |
| -------------------- | ------------------------------- | ------------------------------------- |
| Nessun output        | Dominio non indicizzato         | Prova con `gau` per fonti alternative |
| Troppi URL duplicati | Parametri diversi, path uguale  | Pipe in `sort -u` o `uro`             |
| Rate limiting        | Troppe richieste ad Archive.org | Aggiungi delay                        |
| Timeout              | Archive.org lento               | Riprova dopo qualche minuto           |

***

## 12️⃣ FAQ

**Waybackurls è legale?**
Sì. Interroga dati pubblici di Internet Archive. Non accede al target.

**I file trovati sono sempre ancora accessibili?**
No. Molti restituiscono 404. Filtra con `httpx -mc 200` per trovare quelli ancora live.

**Posso vedere il contenuto storico dei file?**
Sì, tramite la Wayback Machine: `https://web.archive.org/web/*/URL`.

**Waybackurls trova subdomain?**
Sì, a meno che non usi `-no-subs`.

**Quanto indietro nel tempo va?**
Dipende dal dominio. Archive.org ha dati dal 1996 per alcuni siti.

***

## 13️⃣ Cheat Sheet

| Azione                  | Comando                                                   |
| ----------------------- | --------------------------------------------------------- |
| Estrai URL              | `echo "domain.com" \| waybackurls`                        |
| Con timestamp           | `echo "domain.com" \| waybackurls -dates`                 |
| Solo dominio principale | `echo "domain.com" \| waybackurls -no-subs`               |
| Filtra file sensibili   | `waybackurls \| grep -iE "\.env\|\.sql\|\.bak"`           |
| Verifica live           | `waybackurls \| httpx -silent -mc 200`                    |
| Estrai parametri        | `waybackurls \| grep "?" \| sort -u`                      |
| Pipeline completa       | `echo "domain" \| waybackurls \| httpx -silent \| nuclei` |

***

**Disclaimer:** Waybackurls accede a dati pubblici di Internet Archive. L'uso delle informazioni trovate per accesso non autorizzato a sistemi è illegale. Repository: [github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
