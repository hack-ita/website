---
title: 'DirBuster su Kali: directory brute force con GUI e wordlist'
slug: dirbuster
description: 'Usa DirBuster su Kali per trovare directory e file nascosti: configurazione GUI e headless, wordlist, ricorsione, soft-404 e confronto con ffuf e feroxbuster.'
image: /dirbuster-directory-brute-force-web-enumeration.webp
draft: true
date: 2026-08-17T00:00:00.000Z
categories:
  - tools
subcategories:
  - risorse
tags:
  - 'directory brute force,'
  - soft-404
  - SecLists
  - web enumeration
---

# DirBuster: Guida al Directory Fuzzing, Wordlist, Ricorsione e File Discovery

Per trovare directory e file nascosti su un web server — `/admin`, `/backup.zip`, `/config.php.bak`, panel non linkati — il directory brute forcing è ancora uno dei passi obbligatori nella ricognizione web. **DirBuster** è il tool OWASP Java con GUI, con wordlist incluse e interfaccia visuale che mostra la struttura dell'applicazione man mano che scansiona. Slow rispetto ai tool moderni ma ancora utile quando vuoi ricorsione visuale o stai su un target lento che non sopporta thread aggressivi.

**Prerequisiti:** Java installato, wordlist [SecLists](https://hackita.it/articoli/wordlist/), nozioni base di HTTP (status code, header). Abbina [Burp Suite](https://hackita.it/articoli/burp-suite/) per ispezionare le request durante la scansione.

***

## Cos'è DirBuster?

DirBuster è uno strumento open source per il directory e file discovery su applicazioni web, scritto in Java e sviluppato originariamente nell'ambito OWASP. Usa wordlist per individuare directory, file e risorse non direttamente raggiungibili dai link dell'applicazione, con una GUI che mostra la struttura trovata man mano che procede.

## Come funziona DirBuster?

```text
Wordlist
   ↓
Ogni entry diventa una directory/file candidato
   ↓
HTTP Request al target
   ↓
HTTP Response
   ↓
Status / dimensione / contenuto della risposta
   ↓
Risorsa interessante o falso positivo
```

In pratica: DirBuster sostituisce progressivamente ogni nome della wordlist in coda all'URL target, manda la request e analizza la risposta. Con la ricorsione attiva, ripete lo stesso processo dentro ogni directory trovata.

## DirBuster è ancora utile nel 2026?

DirBuster non viene più mantenuto da anni, ma resta usabile. Per la maggior parte dei pentest moderni, ffuf e feroxbuster sono alternative più veloci e attivamente sviluppate. DirBuster rimane interessante soprattutto per la GUI — utile per mostrare la struttura ad albero a un cliente o quando lavori su un target lento che non regge thread aggressivi.

***

## DirBuster vs ffuf vs feroxbuster vs Gobuster

| Tool                                                        | Linguaggio | Velocità | GUI | Ricorsione   | Estensioni | Quando usarlo                                          |
| ----------------------------------------------------------- | ---------- | -------- | --- | ------------ | ---------- | ------------------------------------------------------ |
| **DirBuster**                                               | Java       | ★★ lenta | ✅   | ✅ visuale    | ✅          | Quando vuoi GUI, ricorsione visuale, target lenti      |
| **[ffuf](https://hackita.it/articoli/ffuf/)**               | Go         | ★★★★★    | ❌   | Manuale      | ✅          | Fuzzing generico, parametri, vhost — uso quotidiano    |
| **[feroxbuster](https://hackita.it/articoli/feroxbuster/)** | Rust       | ★★★★★    | ❌   | ✅ automatica | ✅          | Ricorsione aggressiva e veloce su target robusti       |
| **[gobuster](https://hackita.it/articoli/gobuster/)**       | Go         | ★★★★     | ❌   | ❌            | ✅          | DNS, vhost, S3 — semplicità e velocità                 |
| **[wfuzz](https://hackita.it/articoli/wfuzz/)**             | Python     | ★★★      | ❌   | Manuale      | ✅          | Fuzzing avanzato, header, cookie, parametri            |
| **[dirsearch](https://hackita.it/articoli/dirsearch/)**     | Python     | ★★★      | ❌   | ✅            | ✅          | Buon middle-ground, ricorsione, tecnologie auto-detect |
| **dirb**                                                    | C          | ★★       | ❌   | ✅            | ✅          | Legacy, semplice, usa wordlist proprie                 |

**DirBuster vs ffuf: quale scegliere?** Per velocità e uso quotidiano, ffuf. DirBuster ha senso solo se ti serve la GUI o vuoi vedere la ricorsione visualizzata in tempo reale.

**DirBuster vs feroxbuster: quale scegliere?** Feroxbuster gestisce meglio (e più velocemente) ricorsione e soft-404 in automatico. DirBuster resta preferibile su target molto lenti dove la velocità aggressiva di feroxbuster causa errori o rate limiting.

Per la maggior parte dei pentest usa ffuf o feroxbuster. Usa DirBuster quando: hai bisogno della GUI per mostrare risultati a un cliente, vuoi vedere la struttura ricorsiva visuale in tempo reale, o stai testando un target molto lento dove thread aggressivi causano errori.

***

## Installare DirBuster su Kali Linux

```bash
sudo apt install dirbuster -y

# Verifica
which dirbuster
```

> Su Kali può essere già presente di default a seconda dell'immagine/versione — verifica comunque con `which dirbuster` prima di assumerlo.

## Wordlist DirBuster: quale scegliere?

```bash
ls /usr/share/dirbuster/wordlists/
```

```text
/usr/share/dirbuster/wordlists/
├── directory-list-1.0.txt
├── directory-list-2.3-small.txt
├── directory-list-2.3-medium.txt        ← usa questa come default
├── directory-list-2.3-big.txt
├── directory-list-lowercase-2.3-small.txt
├── directory-list-lowercase-2.3-medium.txt
└── apache-user-enum-2.0.txt             (usernames via /~user/)
```

| Wordlist                        | Quando                                             |
| ------------------------------- | -------------------------------------------------- |
| `directory-list-1.0.txt`        | Quick check iniziale                               |
| `directory-list-2.3-medium.txt` | Assessment standard — il default da usare          |
| `directory-list-2.3-big.txt`    | Assessment approfondito, target che reggono carico |
| `common.txt` (SecLists)         | Quick win in meno di 30 secondi                    |

Per un primo controllo usa una wordlist piccola come `common.txt`. Per un assessment standard passa a `directory-list-2.3-medium.txt`; per una scansione più approfondita valuta una wordlist grande, tenendo conto del tempo e del carico che genera sul target.

> Il numero esatto di entry per wordlist varia a seconda della versione del pacchetto installato — verifica con `wc -l` sul file che stai usando invece di fidarti di un numero fisso.

***

## Come usare DirBuster in modalità GUI

```bash
# Avvia DirBuster (GUI Java)
dirbuster &
# oppure
java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar &
```

**Configurazione nella GUI:**

```
Target URL: http://target.com:80/
Work Method: GET
File Extension: php,html,txt,bak,zip,old
Wordlist: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
☑ Be Recursive
Number of Threads: 20
```

> Errore tipico: lasciare "Be Recursive" attivo con la wordlist da oltre un milione di entry su un target con molte directory. La scansione può durare ore. Disabilita la ricorsione nel primo run, poi vai manuale sulle directory trovate.

**Cosa leggi nell'output GUI:**

* **Response 200:** directory/file esiste e risponde — investigare
* **Response 301/302:** redirect — segui il redirect
* **Response 403:** esiste ma forbidden — possibile bypass
* **Response 404:** non esiste (ma attenzione ai soft-404, vedi sotto)

## Come usare DirBuster in modalità Headless

Per usarlo in pipeline o su server senza X11:

```bash
# Headless mode — output su file
java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar \
  -H \
  -u http://target.com/ \
  -l /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
  -e php,html,txt,bak \
  -t 20 \
  -r report.txt

# Opzioni principali:
# -H         headless (no GUI)
# -u URL     target
# -l FILE    wordlist
# -e EXT     estensioni (comma-separated)
# -t N       thread
# -r FILE    report output
# -s /       punto di partenza del path di scansione (default: /), NON una porta
# -R         disabilita la ricorsione — di default DirBuster È GIÀ ricorsivo
```

```text
Dir found: /admin/ - 200
Dir found: /backup/ - 200
File found: /config.php.bak - 200
File found: /admin/login.php - 200
Dir found: /admin/includes/ - 403
```

***

## Come trovare file di backup con DirBuster

Le estensioni sono fondamentali. Con solo la directory list non trovi i file. Aggiungi sempre estensioni basate sulla tecnologia del target.

### Estensioni PHP

```
php,php3,php4,php5,phtml,bak,old,txt,zip,tar.gz,conf
```

### Estensioni ASP.NET

```
asp,aspx,ashx,asmx,config,bak,old,txt,zip
```

### Estensioni Java

```
jsp,jspx,war,jar,xml,properties,bak,txt
```

### Backup e file di configurazione (qualsiasi target)

```
bak,old,txt,log,zip,tar,gz,sql,conf,cfg,ini,.env,backup
```

```bash
# Headless con estensioni aggressive
java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar \
  -H -u https://target.com/ \
  -l /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e php,bak,old,txt,zip,sql,.env,conf \
  -t 15 -r results.txt
```

> Un file `.env` esposto può contenere credenziali database, API key, token o altri segreti applicativi. Un file `.sql` può contenere dati o strutture del database e va trattato come potenzialmente sensibile. Un `.bak` è spesso una copia di un file di configurazione. Vale sempre la pena aggiungere queste estensioni.

***

## DirBuster e Soft-404: come evitare i falsi positivi

Un soft-404 si verifica quando un'applicazione restituisce una risposta apparentemente valida, spesso `200 OK`, anche per URL inesistenti. Durante il directory fuzzing questo produce centinaia o migliaia di falsi positivi — DirBuster mostra tutto come trovato, e diventa inutile senza correggerlo.

**Come identificarlo:**

```bash
# Prova a richiedere un path assurdo
curl -I http://target.com/qwerasdfzxcv1234567

# Se risponde 200 con lo stesso body di sempre → soft-404
# Guarda la lunghezza della risposta: se è uguale per tutti → soft-404
```

**Soluzione in DirBuster (GUI):**

1. Fai una request manuale a path inesistente
2. Nota la lunghezza della risposta (es: 1423 bytes)
3. In DirBuster: Options → Add a custom 404 response size
4. Inserisci 1423 — DirBuster esclude tutte le risposte di quella dimensione

**Con feroxbuster (alternativa più elegante):**

```bash
# feroxbuster gestisce soft-404 automaticamente
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt --auto-tune
```

***

## Come creare una wordlist personalizzata per DirBuster

Le wordlist generiche perdono i path specifici dell'applicazione. Per trovare i path reali estrai i link dal codice JavaScript, dalla sitemap e da altre fonti dell'applicazione stessa.

### Da JavaScript

```bash
pip install linkfinder

# Analizza un file JS
python3 linkfinder.py -i http://target.com/app.js -o cli

# Analizza tutti i JS linkati dalla homepage
python3 linkfinder.py -i http://target.com -d -o cli > js_paths.txt

# Filtra e crea wordlist
grep "/" js_paths.txt | sed 's|.*://[^/]*/||' | sort -u > custom_wordlist.txt
```

### Da sitemap.xml

```bash
curl -s http://target.com/sitemap.xml | grep -oP 'https?://[^<]+' | \
  sed "s|http://target.com/||" | sort -u >> custom_wordlist.txt
```

### Da robots.txt

```bash
curl -s http://target.com/robots.txt | grep -E "Disallow|Allow" | \
  awk '{print $2}' >> custom_wordlist.txt
```

### Uso della wordlist custom

```bash
java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar \
  -H -u http://target.com/ \
  -l custom_wordlist.txt \
  -e php,html -t 10 -r results.txt
```

Puoi arricchire ulteriormente la wordlist con gli endpoint scoperti manualmente navigando l'applicazione con [Burp Suite](https://hackita.it/articoli/burp-suite/) attivo come proxy.

***

## Come usare la ricorsione in DirBuster

La ricorsione permette a DirBuster di continuare la scansione dentro ogni directory individuata. È utile per mappare strutture profonde, ma può moltiplicare rapidamente il numero di richieste — e attenzione: **di default DirBuster è già ricorsivo**. Il flag `-R` non attiva la ricorsione, la **disattiva**.

**Strategia consigliata:**

1. Prima run con `-R` (ricorsione disattivata) — identifica solo le directory di primo livello
2. Seconda run senza `-R` (ricorsione di default attiva) solo sulle directory interessanti

```bash
# Run 1: niente ricorsione, solo primo livello
java -jar DirBuster-1.0-RC1.jar \
  -H -u http://target.com/ \
  -l directory-list-2.3-small.txt \
  -t 20 -r run1.txt \
  -R
# -R qui DISATTIVA la ricorsione di default

# Analizza risultati
grep "Dir found" run1.txt | grep -v "403"
# Output: /admin/, /api/, /backup/

# Run 2: ricorsiva (comportamento di default, niente -R) solo su /admin/
java -jar DirBuster-1.0-RC1.jar \
  -H -u http://target.com/admin/ \
  -l directory-list-2.3-medium.txt \
  -e php,html,txt -t 15 -r run2_admin.txt
# Nessun -R → resta ricorsivo di default
```

***

## Come usare DirBuster durante un Web Pentest

```text
1. QUICK WIN (2 minuti)
   └─ DirBuster (o ffuf) con common.txt
   └─ Estensioni: php,html,txt,bak
   └─ 20 thread, no ricorsione

2. STANDARD SCAN (10-30 minuti)
   └─ directory-list-2.3-medium.txt
   └─ Estensioni basate su tech stack rilevato
   └─ Controlla robots.txt e sitemap.xml prima

3. CUSTOM WORDLIST
   └─ Estrai URL da JS (linkfinder)
   └─ Estrai da sitemap/robots.txt
   └─ Merge + deduplica → wordlist specifica del target

4. RICORSIONE
   └─ Analizza directory di primo livello
   └─ Ricorsione manuale su /admin/, /api/, /backup/

5. ANALISI RISULTATI
   └─ 200: apri nel browser, analizza
   └─ 403: prova bypass (X-Forwarded-For, metodo PUT/POST, path encoding)
   └─ 301: segui redirect
   └─ Soft-404: escludi per dimensione risposta
```

***

## Troubleshooting

| Problema                  | Causa                                    | Soluzione                                                        |
| ------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| DirBuster non si avvia    | Java non installato o versione sbagliata | `java -version` → serve JRE ≥8: `sudo apt install default-jre`   |
| GUI non appare            | Display non impostato in SSH             | `export DISPLAY=:0` oppure usa modalità headless `-H`            |
| Tutto risponde 200        | Soft-404                                 | Prova path assurdo, nota dimensione risposta, escludi in Options |
| Crash su wordlist grandi  | Java heap troppo piccolo                 | Aumenta heap: `java -Xmx1024m -jar DirBuster.jar ...`            |
| Scansione lentissima      | Thread troppo bassi o wordlist enorme    | Aumenta `-t 30` oppure usa ffuf/feroxbuster                      |
| Troppi falsi positivi 403 | WAF o rate limiting                      | Riduci thread `-t 5`, aggiungi delay                             |
| SSL certificate error     | Certificato self-signed                  | Aggiungi eccezione Java oppure usa feroxbuster `--insecure`      |

***

## FAQ

**Cos'è DirBuster?**
Uno strumento open source Java, nato in ambito OWASP, per trovare directory e file nascosti su un web server tramite wordlist.

**DirBuster è ancora utile nel 2026?**
Sì, anche se non è più mantenuto. Per la maggior parte dei pentest ffuf e feroxbuster sono più veloci; DirBuster resta utile per la GUI e per target lenti che non reggono thread aggressivi.

**Qual è la migliore wordlist per DirBuster?**
`common.txt` per un primo check veloce, `directory-list-2.3-medium.txt` per un assessment standard, wordlist più grandi per un'analisi approfondita — sempre valutando tempo e carico sul target.

**DirBuster supporta HTTPS?**
Sì, basta usare `https://` nell'URL target. Con certificati self-signed può dare errore SSL — in quel caso conviene passare a feroxbuster con `--insecure`.

**Come evito i falsi positivi soft-404?**
Prova un path inesistente, nota la dimensione della risposta, ed escludila in DirBuster tramite Options → custom 404 response size.

**DirBuster vs ffuf: quale scegliere?**
Ffuf per velocità e uso quotidiano. DirBuster solo se ti serve la GUI o la visualizzazione ricorsiva in tempo reale.

**DirBuster vs feroxbuster: quale scegliere?**
Feroxbuster per ricorsione automatica e gestione soft-404 integrata. DirBuster su target molto lenti dove la velocità aggressiva causa errori.

**Come trovo file di backup con DirBuster?**
Aggiungi estensioni come `bak,old,sql,zip,tar.gz,.env,conf` alla scansione — sono i formati più comuni per backup e file di configurazione esposti per errore.

**Qual è la differenza tra DirBuster e dirb?**
DirBuster ha GUI, dirb è CLI puro scritto in C. Entrambi lenti rispetto agli standard attuali — per CLI moderno preferisci ffuf o feroxbuster.

***

## DirBuster Cheat Sheet

```text
=== AVVIO ===
GUI:        dirbuster
Headless:   java -jar DirBuster-1.0-RC1.jar -H -u URL -l WORDLIST -e EXT -t 20 -r report.txt

=== WORDLIST KALI INCLUSE ===
Quick:      /usr/share/dirbuster/wordlists/directory-list-1.0.txt
Standard:   /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
Aggressivo: /usr/share/dirbuster/wordlists/directory-list-2.3-big.txt
SecLists:   /usr/share/seclists/Discovery/Web-Content/common.txt

=== ESTENSIONI COMUNI ===
PHP:        php,php3,bak,old,txt,zip,conf
ASP.NET:    asp,aspx,ashx,config,bak,txt,zip
Java:       jsp,war,xml,properties,bak
Generiche:  bak,old,txt,log,zip,sql,conf,.env,backup

=== SOFT-404 FIX ===
Test:       curl -I http://target.com/aaaabbbbcccc1234
Fix GUI:    Options → custom 404 response size

=== CUSTOM WORDLIST ===
JS:         python3 linkfinder.py -i http://target.com -d -o cli > paths.txt
Sitemap:    curl -s http://target.com/sitemap.xml | grep -oP 'https?://[^<]+' | sed ...
Robots:     curl -s http://target.com/robots.txt | grep Disallow

=== ALTERNATIVA RAPIDA ===
ffuf:       ffuf -w common.txt -u http://target.com/FUZZ -e .php,.bak --hc 404
feroxbuster: feroxbuster -u http://target.com -w common.txt -x php,bak --auto-tune
gobuster:   gobuster dir -u http://target.com -w common.txt -x php,bak
```

***

**Guide correlate su hackita.it:**

* [wfuzz: Web Fuzzing Avanzato con Encoders e Multi-Position](https://hackita.it/articoli/wfuzz/)
* [Burp Suite: Intercettare e Analizzare Traffico HTTP](https://hackita.it/articoli/burp-suite/)
* [Wordlist e SecLists: Guida Operativa](https://hackita.it/articoli/wordlist/)
* [Attacchi alle Applicazioni Web](https://hackita.it/articoli/attacchi-applicazioni-web/)

## Riferimenti

* [OWASP DirBuster Project](https://owasp.org/www-project-dirbuster/)
* [SecLists – Discovery Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)
