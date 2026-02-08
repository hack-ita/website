---
title: 'Dirsearch: Directory e File Enumeration per Web Application Testing'
slug: dirsearch
description: >-
  Dirsearch è uno strumento per enumerare directory e file nascosti su
  applicazioni web tramite wordlist personalizzate. Guida pratica all’uso in
  fase di web reconnaissance durante un penetration test.
image: /Gemini_Generated_Image_sd9wawsd9wawsd9w.webp
draft: false
date: 2026-02-09T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - directory-enumeration
featured: true
---

Dirsearch è un directory bruteforcer scritto in Python che si distingue per una caratteristica fondamentale: la ricorsione automatica. Quando trova una directory, entra automaticamente e continua la scansione al suo interno, scendendo di livello senza intervento manuale. Su applicazioni web complesse con strutture di directory profonde, questo comportamento produce risultati che tool non ricorsivi come Gobuster non troverebbero mai in un singolo passaggio.

Il tool include wordlist integrate ottimizzate, gestione intelligente degli status code, supporto per estensioni multiple e output in formati diversi. È particolarmente efficace su CMS (WordPress, Joomla, Drupal) dove la struttura delle directory segue pattern prevedibili ma profondi.

Nella kill chain, ci troviamo nella fase di **Reconnaissance** (MITRE ATT\&CK T1595.003), specificamente nella content discovery su applicazioni web. L'articolo copre dalla configurazione iniziale fino a scenari reali su applicazioni enterprise, con confronto diretto con [Gobuster](https://hackita.it/articoli/gobuster) e integrazione nella pipeline offensiva.

***

## Setup e Installazione

**Installazione da pip:**

```bash
pip install dirsearch --break-system-packages
```

**Installazione da repository (consigliata per ultima versione):**

```bash
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
pip install -r requirements.txt --break-system-packages
```

**Verifica:**

```bash
python3 dirsearch.py --version
```

Output:

```
dirsearch v0.4.3
```

Se installato via pip:

```bash
dirsearch --version
```

**Requisiti:**

* Python 3.7+
* Moduli: `requests`, `urllib3`, `chardet`, `certifi`
* Wordlist incluse in `db/dicc.txt` (\~7.500 entry ottimizzate)

La wordlist integrata è un punto di forza: è curata specificamente per web enumeration e produce meno falsi positivi rispetto a wordlist generiche.

***

## Uso Base

Scansione con wordlist integrata:

```bash
dirsearch -u http://10.10.10.50
```

Output:

```
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25

Target: http://10.10.10.50

[14:23:01] Starting:
[14:23:02] 403 -  277B  - /.htaccess
[14:23:03] 301 -  313B  - /admin  ->  http://10.10.10.50/admin/
[14:23:05] 200 -  1.5KB - /admin/login.php
[14:23:08] 301 -  315B  - /backup  ->  http://10.10.10.50/backup/
[14:23:10] 200 -  482B  - /config.php.bak
[14:23:15] 301 -  316B  - /uploads  ->  http://10.10.10.50/uploads/
[14:23:20] 200 -  312B  - /.env
```

Nota: Dirsearch ha già provato estensioni comuni (`php, aspx, jsp, html, js`) automaticamente. Con Gobuster dovresti specificarle manualmente.

**Parametri fondamentali:**

* `-u URL` → target
* `-w wordlist` → wordlist custom (default: `db/dicc.txt`)
* `-e ext1,ext2` → estensioni aggiuntive
* `-t N` → thread (default 25)
* `-r` → ricorsione (attiva per default in alcune versioni)
* `-R N` → profondità massima ricorsione
* `--exclude-status=CODE` → escludi status code
* `-o file` → output su file

***

## Tecniche Operative

### Ricorsione automatica — Il vantaggio chiave

Abilita la ricorsione per esplorare ogni directory trovata:

```bash
dirsearch -u http://10.10.10.50 -r -R 3
```

* `-r` → attiva ricorsione
* `-R 3` → profondità massima 3 livelli

Output:

```
[14:30:01] 301 -  313B  - /admin  ->  /admin/
[14:30:05] 200 -  1.5KB - /admin/login.php
[14:30:06] 200 -  891B  - /admin/config/
[14:30:08] 200 -  312B  - /admin/config/database.yml
[14:30:12] 301 -  318B  - /admin/backups  ->  /admin/backups/
[14:30:15] 200 -  3.4MB - /admin/backups/db_dump.sql
```

Il percorso `/admin/backups/db_dump.sql` non sarebbe mai stato trovato da uno scanner non ricorsivo con una wordlist standard. Dirsearch ha trovato `/admin`, è entrato, ha trovato `/admin/backups/`, è entrato ancora e ha scoperto il dump.

### Scansione con estensioni mirate per tecnologia

Per un target PHP:

```bash
dirsearch -u http://10.10.10.50 -e php,phtml,inc,bak,old,txt,sql,zip,tar.gz
```

Per un target ASP.NET:

```bash
dirsearch -u http://10.10.10.50 -e aspx,asmx,ashx,config,bak,old,sql
```

Per un target Java:

```bash
dirsearch -u http://10.10.10.50 -e jsp,do,action,xml,properties,war,jar
```

### Gestione WAF e rate limiting

Dirsearch ha opzioni integrate per gestire applicazioni protette:

```bash
dirsearch -u http://target.com -t 5 --delay=0.5 --random-agent
```

* `--delay=0.5` → 500ms tra ogni richiesta
* `--random-agent` → User-Agent casuale da un database integrato ad ogni richiesta

### Esclusione risposte per dimensione

```bash
dirsearch -u http://10.10.10.50 --exclude-sizes=1523B
```

Filtra le risposte con dimensione esatta di 1523 bytes (la pagina 404 custom).

### Scansione tramite proxy

```bash
dirsearch -u http://target.com --proxy=socks5://127.0.0.1:1080
```

Integrazione diretta con tunnel SOCKS5 creati via SSH o [ProxyChains](https://hackita.it/articoli/proxychains).

***

## Tecniche Avanzate

### Wordlist multiple combinate

Dirsearch accetta più wordlist in sequenza:

```bash
dirsearch -u http://10.10.10.50 -w /usr/share/seclists/Discovery/Web-Content/common.txt,/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
```

Le entry vengono de-duplicate automaticamente.

### Prefisso e suffisso dinamici

Cerca pattern specifici come endpoint con versioning:

```bash
dirsearch -u http://10.10.10.50/api -w wordlist.txt --prefixes=v1/,v2/,v3/
```

Genera richieste tipo `/api/v1/users`, `/api/v2/users`, `/api/v3/users` per ogni entry nella wordlist.

Oppure suffissi:

```bash
dirsearch -u http://10.10.10.50 -w wordlist.txt --suffixes=/,~,.bak
```

Testa ogni path con `/`, `~` e `.bak` appesi.

### HTTP methods alternativi

Alcune risorse rispondono solo a metodi specifici:

```bash
dirsearch -u http://10.10.10.50/api -m PUT,DELETE,PATCH
```

Trova endpoint che accettano metodi pericolosi (PUT per upload, DELETE per cancellazione).

### Report in formato HTML

Per documentazione del pentest:

```bash
dirsearch -u http://10.10.10.50 --format=html -o report.html
```

Genera un report navigabile con tutti i finding, status code e dimensioni.

### Scansione multipla da file target

```bash
dirsearch -l targets.txt -e php,txt -r -R 2 -t 30 -o results.txt
```

* `-l targets.txt` → lista di URL target, uno per riga
* Scansiona ricorsivamente ogni target in sequenza

***

## Scenari Pratici di Pentest

### Scenario 1: WordPress — Trovare plugin vulnerabili e file residui

```bash
dirsearch -u http://10.10.10.50/wp-content/plugins/ -r -R 2 -e php,txt,bak,zip
```

**Output atteso:**

```
[14:45:01] 301 -  340B  - /wp-content/plugins/akismet/
[14:45:05] 200 -  2.1KB - /wp-content/plugins/akismet/readme.txt
[14:45:12] 301 -  345B  - /wp-content/plugins/custom-form/
[14:45:15] 200 -  521B  - /wp-content/plugins/custom-form/includes/upload.php
[14:45:20] 200 -  14KB  - /wp-content/plugins/custom-form/backup.zip
```

**Cosa fare se fallisce:**

* Nessun risultato → Il path `plugins` potrebbe essere diverso o l'accesso alla directory è bloccato. Prova `/wp-content/uploads/` o `/wp-includes/`.
* Timeout frequenti → Server lento. Riduci thread a 10 e aggiungi `--timeout=15`.

**Timeline:** Ricorsione su plugins con wordlist default: 3-5 minuti. Finding critici spesso nei primi 2 minuti.

### Scenario 2: Applicazione Java enterprise — Discovery di endpoint API

```bash
dirsearch -u https://app.corp.local:8443 -e jsp,do,action,json,xml -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -k -r -R 2 --exclude-status=401,403
```

**Output atteso:**

```
[15:00:01] 200 -    0B  - /api/
[15:00:05] 200 -  2.1KB - /api/swagger.json
[15:00:08] 200 -  891B  - /api/health
[15:00:12] 200 -  312B  - /actuator/env
[15:00:15] 200 -  4.2KB - /actuator/configprops
```

Un endpoint `/actuator/env` esposto su Spring Boot può contenere credenziali in chiaro.

**Cosa fare se fallisce:**

* HTTPS con cert non valido → Aggiungi `-k` (già presente nell'esempio).
* 429 Too Many Requests → Abilita `--delay=1` e `--retries=3`.

**Timeline:** 5-10 minuti con wordlist raft-medium.

### Scenario 3: Target con WAF Cloudflare — Evasion e scansione stealth

```bash
dirsearch -u https://target.com --random-agent --delay=1 -t 3 --exclude-status=403,503 -e php,html,txt -o cf_scan.txt
```

**Output atteso:** risultati filtrati senza le pagine bloccate da Cloudflare.

**Cosa fare se fallisce:**

* Cloudflare challenge page (503) su tutto → Stai venendo bloccato. Riduci ulteriormente rate (`--delay=3`). Considera di usare un browser headless per risolvere il challenge e poi passare i cookie a Dirsearch: `-H "Cookie: cf_clearance=..."`.
* IP bannato → Cambia IP sorgente. Usa una VPN o un proxy residenziale.

**Timeline:** 15-20 minuti per wordlist da 5K entry con delay 1 secondo.

***

## Toolchain Integration

Dirsearch opera dopo il port scanning e prima dell'exploitation web.

**Flusso tipico:**

[Masscan](https://hackita.it/articoli/masscan) (porte) → [Nmap](https://hackita.it/articoli/nmap) (service ID) → **Dirsearch (content discovery ricorsiva)** → [Burp Suite ](https://hackita.it/articoli/burp-suite)(analisi manuale) → Exploit

Dirsearch eccelle dove Gobuster si ferma: applicazioni con strutture profonde dove la ricorsione fa la differenza.

**Passaggio dati:**

```bash
# Nmap identifica web server
nmap -sV -p 80,443,8080 10.10.10.50

# Dirsearch scansiona ricorsivamente
dirsearch -u http://10.10.10.50 -r -R 3 -e php,txt,bak -o findings.txt

# I path trovati vengono analizzati con curl o Burp
grep "200" findings.txt | awk '{print $NF}' | while read path; do
  curl -s "http://10.10.10.50${path}" | head -20
done
```

| Criterio           | Dirsearch        | Gobuster | ffuf    | Feroxbuster |
| ------------------ | ---------------- | -------- | ------- | ----------- |
| Ricorsione nativa  | ★★★★★            | ☆☆☆☆☆    | ☆☆☆☆☆   | ★★★★★       |
| Velocità pura      | ★★★☆☆            | ★★★★★    | ★★★★★   | ★★★★☆       |
| Wordlist integrata | Sì (ottimizzata) | No       | No      | No          |
| Estensioni auto    | Sì               | No       | No      | Parziale    |
| Random User-Agent  | Integrato        | Manuale  | Manuale | Integrato   |
| Report HTML        | Sì               | No       | No      | No          |
| Prefissi/suffissi  | Sì               | No       | Sì      | No          |

***

## Attack Chain Completa

**Obiettivo:** Compromettere una webapp Joomla trovando file di configurazione esposti.

**Fase 1 — Recon (5 min)**

Nmap identifica porta 80 aperta con Joomla. Versione nel meta tag HTML.

**Fase 2 — Content Discovery con Dirsearch (10 min)**

```bash
dirsearch -u http://10.10.10.50 -r -R 3 -e php,txt,bak,sql,zip,xml -t 40
```

Trova `/administrator/`, `/configuration.php.bak`, `/tmp/`.

**Fase 3 — Credential Extraction (2 min)**

```bash
curl http://10.10.10.50/configuration.php.bak
```

Il backup della configurazione contiene credenziali MySQL in chiaro.

**Fase 4 — Admin Access (5 min)**

Le credenziali del database funzionano anche per il pannello admin Joomla. Login su `/administrator/`.

**Fase 5 — Web Shell via template editing (3 min)**

Dal pannello admin, editi un template PHP e inserisci una [Weevely3](https://hackita.it/articoli/weevely3) shell. Shell come `www-data`.

**Fase 6 — Post-exploitation (30 min)**

Enumerazione locale, privilege escalation, pivoting verso rete interna.

**Timeline totale:** \~55 minuti. La ricorsione di Dirsearch ha trovato il file `.bak` che ha sbloccato tutto.

***

## Detection & Evasion

### Cosa monitora il Blue Team

* Burst di richieste 404 sequenziali — signature classica di directory bruteforce
* User-Agent `python-requests` (default di Dirsearch se `--random-agent` non è abilitato)
* WAF rules specifiche per pattern di scansione (path con estensioni `.bak`, `.old`, `.sql`)

### Log rilevanti

* Web server access log → sequenze di 404 e 403 ravvicinate
* WAF → alert per scanning activity, blocked requests
* CDN logs (Cloudflare, Akamai) → spike di richieste da singolo IP

### Tecniche di evasion

1. **Random User-Agent per ogni richiesta:** `--random-agent` seleziona un UA diverso da un database di browser reali.
2. **Header custom per bypass WAF:** aggiungi header che emulano traffico interno:

```bash
dirsearch -u http://target.com -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 10.0.0.1"
```

1. **Scansione frammentata:** dividi la wordlist in blocchi e scansiona in sessioni separate con pause tra una e l'altra.

### Cleanup

Dirsearch non lascia tracce sul target. Le entry nei log del web server sono le uniche evidenze.

***

## Performance & Scaling

**Thread e velocità:** il default di 25 thread è equilibrato per la maggior parte dei target. Su server robusti, 50-80 thread accelerano significativamente. Su server fragili o protetti da WAF, scendi a 5-10.

**Impatto della ricorsione:** la ricorsione moltiplica il tempo di scansione. Su un sito con 10 directory di primo livello e ricorsione a 3 livelli, il tempo può crescere di 5-10x rispetto a una scansione piatta.

**Confronto tempi:**

| Modalità         | Wordlist default (\~7.5K) | Raft-medium (\~62K) |
| ---------------- | ------------------------- | ------------------- |
| Senza ricorsione | \~30 sec                  | \~4 min             |
| Ricorsione -R 2  | \~2-5 min                 | \~15-30 min         |
| Ricorsione -R 3  | \~5-15 min                | \~30-60 min         |

**Ottimizzazione:** se la ricorsione è troppo lenta, usa una wordlist piccola per la ricorsione e una grande per il primo livello:

```bash
dirsearch -u http://target -w large_wordlist.txt
# Poi ricorsione solo su directory interessanti
dirsearch -u http://target/admin -r -R 2 -w small_wordlist.txt
```

***

## Tabelle Tecniche

### Command Reference

| Flag                 | Descrizione                                           |
| -------------------- | ----------------------------------------------------- |
| `-u URL`             | URL target                                            |
| `-l file`            | Lista di URL target                                   |
| `-w wordlist`        | Wordlist custom                                       |
| `-e ext`             | Estensioni da cercare                                 |
| `-t N`               | Numero thread                                         |
| `-r`                 | Ricorsione attiva                                     |
| `-R N`               | Profondità ricorsione                                 |
| `--exclude-status=N` | Escludi status code                                   |
| `--exclude-sizes=NB` | Escludi per dimensione                                |
| `--random-agent`     | User-Agent casuale                                    |
| `--delay=N`          | Delay in secondi                                      |
| `--proxy=URL`        | Proxy SOCKS/HTTP                                      |
| `-H "header: value"` | Header custom                                         |
| `-m METHOD`          | HTTP method                                           |
| `--prefixes=p1,p2`   | Prefissi per wordlist                                 |
| `--suffixes=s1,s2`   | Suffissi per wordlist                                 |
| `-o file`            | Output su file                                        |
| `--format=FORMAT`    | Formato output (plain/json/xml/html)                  |
| `-k`                 | No SSL verify (Dirsearch usa `-b` in alcune versioni) |

### Dirsearch vs Gobuster — Confronto diretto

| Aspetto                | Dirsearch              | Gobuster              |
| ---------------------- | ---------------------- | --------------------- |
| Ricorsione             | Nativa, configurabile  | Non supportata        |
| Wordlist inclusa       | Sì (7.5K, ottimizzata) | No                    |
| Estensioni automatiche | Sì                     | No                    |
| Velocità raw           | 3/5                    | 5/5                   |
| Random User-Agent      | Built-in               | Manuale (-a)          |
| Modalità DNS           | No                     | Sì                    |
| Modalità vhost         | No                     | Sì                    |
| Report HTML            | Sì                     | No                    |
| Prefissi/suffissi      | Sì                     | No                    |
| Ideale per             | App complesse, CMS     | Scansioni veloci, DNS |

***

## Troubleshooting

| Problema                        | Causa                               | Fix                                                 |
| ------------------------------- | ----------------------------------- | --------------------------------------------------- |
| Troppi risultati falsi positivi | Custom 404 con status 200           | Usa `--exclude-sizes` per filtrare per dimensione   |
| Ricorsione infinita             | Target con redirect loop            | Limita con `-R 2` o `-R 3`                          |
| `ConnectionError` frequenti     | Server non regge il rate            | Riduci thread (`-t 10`) e aggiungi delay            |
| Nessun risultato                | Wordlist non adatta alla tecnologia | Cambia wordlist o aggiungi estensioni specifiche    |
| Output confuso                  | Mix di status code                  | Filtra con `--exclude-status=403,500,503`           |
| Proxy non funziona              | Formato errato                      | Formato corretto: `--proxy=socks5://127.0.0.1:1080` |

***

## FAQ

**Dirsearch è meglio di Gobuster?**
Per applicazioni con directory profonde (CMS, enterprise app), la ricorsione di Dirsearch è un vantaggio decisivo. Per scansioni veloci e piatte o DNS enumeration, Gobuster è più efficiente.

**La wordlist integrata è sufficiente?**
Per un primo passaggio sì. Per scansioni approfondite, combinala con SecLists: `-w db/dicc.txt,/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`.

**Come gestisco le custom 404 page?**
Fai prima una richiesta a un path inesistente: `curl -s http://target/xyz123abc | wc -c`. Poi usa `--exclude-sizes=SIZEB`.

**Posso scansionare API REST?**
Sì. Usa estensioni specifiche (`-e json,xml`) e la modalità con metodi HTTP alternativi (`-m GET,POST,PUT`). Aggiungi prefissi per versioning: `--prefixes=v1/,v2/`.

**Dirsearch funziona tramite proxy SOCKS?**
Sì: `--proxy=socks5://127.0.0.1:1080`. Supporta anche proxy HTTP e HTTPS.

**Qual è la differenza tra Dirsearch e Feroxbuster?**
Feroxbuster è scritto in Rust ed è più veloce. Entrambi supportano ricorsione. Dirsearch ha più opzioni di filtering e la wordlist integrata. Per scansioni massive dove la velocità è critica, Feroxbuster è preferibile.

***

## Cheat Sheet

| Azione               | Comando                                            |
| -------------------- | -------------------------------------------------- |
| Scan base            | `dirsearch -u http://target`                       |
| Con estensioni       | `dirsearch -u URL -e php,txt,bak,sql`              |
| Ricorsione livello 3 | `dirsearch -u URL -r -R 3`                         |
| Stealth mode         | `dirsearch -u URL --random-agent --delay=1 -t 5`   |
| Wordlist custom      | `dirsearch -u URL -w /path/to/wordlist.txt`        |
| Via proxy            | `dirsearch -u URL --proxy=socks5://127.0.0.1:1080` |
| Escludi status       | `dirsearch -u URL --exclude-status=403,500`        |
| Escludi size         | `dirsearch -u URL --exclude-sizes=1523B`           |
| Multi-target         | `dirsearch -l targets.txt -e php,txt`              |
| Report HTML          | `dirsearch -u URL --format=html -o report.html`    |
| Header custom        | `dirsearch -u URL -H "X-Forwarded-For: 127.0.0.1"` |
| HTTP methods         | `dirsearch -u URL -m GET,POST,PUT,DELETE`          |

***

**Disclaimer:** Dirsearch è uno strumento per security testing autorizzato. La scansione di applicazioni web senza permesso del proprietario è un reato. Assicurati di avere autorizzazione scritta prima di qualsiasi attività. Repository: [github.com/maurosoria/dirsearch](https://github.com/maurosoria/dirsearch).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
