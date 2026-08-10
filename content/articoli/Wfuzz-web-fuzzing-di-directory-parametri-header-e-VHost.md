---
title: 'Wfuzz: web fuzzing di directory, parametri, header e VHost'
slug: wfuzz
description: 'Wfuzz per il web fuzzing: comandi per directory e parametri, scoperta di VHost, header, cookie, filtri, SecLists, encoder e tecniche di WAF bypass.'
image: /wfuzz-web-fuzzing-directory-parameter.webp
draft: true
date: 2026-08-16T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - WAF bypass
  - directory fuzzing
  - Wfuzz
  - web fuzzing
---

# Wfuzz: Guida al Web Fuzzing, Parameter Fuzzing, Directory e Brute Force

**Wfuzz** è un web fuzzer Python che sostituisce la keyword `FUZZ` con ogni entry di una wordlist in qualsiasi parte di una request HTTP — URL, parametri GET/POST, header, cookie, body JSON. Mentre gobuster e feroxbuster sono ottimizzati per la directory brute force, wfuzz è **completamente generico**: puoi fuzzare qualsiasi campo, con più wordlist simultanee e con encoders integrati. Questo lo rende lo strumento giusto quando devi testare injection points, parametri nascosti, vhost o qualsiasi scenario non standard.

**Prerequisiti:** wordlist (installale con [SecLists](https://hackita.it/articoli/wordlist/)) e [Burp Suite](https://hackita.it/articoli/burp-suite/) come proxy per ispezionare le request.

***

## Cos'è Wfuzz?

Wfuzz è un web fuzzer open source scritto in Python che permette di sostituire una posizione `FUZZ` all'interno di una richiesta HTTP con i valori di una wordlist. Può essere usato su directory e file, parametri GET/POST, header, cookie, virtual host e in generale su qualsiasi punto di input HTTP raggiungibile in una request.

## Come funziona Wfuzz?

```text
Wordlist
   ↓
Ogni entry sostituisce FUZZ nella request
   ↓
Request inviata al target
   ↓
Response ricevuta
   ↓
Filtri (--hc, --sc, --hl, --hw, --hh, --hs, --ss)
   ↓
Risultati interessanti
```

In pratica: scrivi una request con `FUZZ` al posto del valore che vuoi testare, colleghi una wordlist, e wfuzz manda una request per ogni riga della wordlist. I filtri servono a scartare il rumore (le migliaia di risposte identiche/irrilevanti) e a far emergere solo ciò che conta.

***

## Wfuzz vs ffuf vs feroxbuster vs gobuster

Prima di iniziare: questi tool fanno cose simili, ma con punti di forza diversi. Scegli in base al task.

| Tool                                                        | Linguaggio | Velocità | Multi-fuzzing         | Encoders | Ricorsione         | Quando usarlo                                     |
| ----------------------------------------------------------- | ---------- | -------- | --------------------- | -------- | ------------------ | ------------------------------------------------- |
| **wfuzz**                                                   | Python     | ★★★      | ✅ FUZZ+FUZ2Z+FUZ3Z    | ✅ molti  | Manuale `-R`       | Massima flessibilità, parameter fuzzing, encoders |
| **[ffuf](https://hackita.it/articoli/ffuf/)**               | Go         | ★★★★★    | ✅ `-w w1:K1 -w w2:K2` | Base     | Auto `--recursion` | Directory fuzzing veloce, uso quotidiano          |
| **[feroxbuster](https://hackita.it/articoli/feroxbuster/)** | Rust       | ★★★★★    | ❌                     | ❌        | Auto, aggressiva   | Ricorsione profonda, massima velocità             |
| **[gobuster](https://hackita.it/articoli/gobuster/)**       | Go         | ★★★★     | ❌                     | ❌        | ❌                  | Semplicità, DNS subdomain, S3 bucket              |
| **[dirbuster](https://hackita.it/articoli/dirbuster/)**     | Java       | ★★       | ❌                     | ❌        | ✅ GUI              | Legacy, GUI per chi preferisce visual             |

**Wfuzz è migliore di ffuf?** No in assoluto: ffuf è generalmente preferibile per directory fuzzing veloce, mentre wfuzz è più interessante quando servono multi-position, parameter fuzzing, header/cookie fuzzing ed encoder — lì gli altri non arrivano.

**Wfuzz vs Burp Intruder?** Burp Intruder resta più comodo per fuzzing manuale, iterativo, dentro il flusso di Burp (con gestione di token/CSRF via macro). Wfuzz è più adatto quando vuoi automatizzare da riga di comando, integrarlo in script o lanciare scansioni massive senza passare dalla UI.

| Se devi...            | Usa             |
| --------------------- | --------------- |
| Directory veloce      | **ffuf**        |
| Parameter fuzzing     | **wfuzz**       |
| Multi-position        | **wfuzz**       |
| Encoder               | **wfuzz**       |
| Ricorsione aggressiva | **feroxbuster** |
| DNS/VHost semplice    | **gobuster**    |

***

## Installazione

Kali lo include già. Se manca:

```bash
sudo apt install wfuzz -y
# oppure
pip3 install wfuzz
```

Le wordlist di default stanno in `/usr/share/wfuzz/wordlist/`. Per fuzzing serio usa SecLists in `/usr/share/seclists/`.

***

## Sintassi base e filtri obbligatori

```bash
wfuzz [opzioni] -w WORDLIST URL_CON_FUZZ
```

**Le opzioni che userai sempre:**

| Flag               | Cosa fa                                            |
| ------------------ | -------------------------------------------------- |
| `-w wordlist`      | Specifica wordlist (ripeti per multi-position)     |
| `-c`               | Output colorato                                    |
| `-t N`             | Thread (default 10)                                |
| `--hc N`           | **Hide** risposte con status code N — usalo sempre |
| `--sc N`           | **Show** solo risposte con status code N           |
| `--hl N`           | Hide risposte con N linee                          |
| `--hw N`           | Hide risposte con N parole                         |
| `--hh N`           | Hide risposte con N caratteri esatti               |
| `--hs "stringa"`   | Hide risposte che contengono quella stringa        |
| `--ss "stringa"`   | Show solo risposte che contengono quella stringa   |
| `-d "data"`        | Body POST                                          |
| `-H "Header: val"` | Header HTTP custom                                 |
| `-b "cookie=val"`  | Cookie                                             |
| `-p proxy`         | Proxy (Burp Suite: `127.0.0.1:8080`)               |
| `-f file,formato`  | Salva output (json, csv, html)                     |

> Senza `--hc 404`, wfuzz stampa ogni risposta e l'output è inutilizzabile. È il primo filtro da aggiungere — sempre.Il comportamento esatto di alcuni flag (delay, ricorsione) può variare tra versioni di wfuzz. Verifica sempre `wfuzz -h` sulla tua versione prima di affidarti ciecamente a questi comandi in un engagement reale.

***

## Wfuzz per directory e file fuzzing

```bash
# Base — il punto di partenza su qualsiasi target
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  --hc 404 http://target.com/FUZZ
```

```text
ID    Response   Lines    Word    Chars    Payload
================================================================
00042:  C=200     12 L     45 W    512 Ch    "admin"
00137:  C=301      9 L     28 W    319 Ch    "backup"
00891:  C=403      7 L     22 W    285 Ch    "config"
```

`C=301` è redirect — seguilo con il browser. `C=403` esiste ma è forbidden — comunque interessante, spesso bypassabile.

```bash
# Fuzza con estensione specifica
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  --hc 404 http://target.com/FUZZ.php

# Fuzza path + estensione contemporaneamente (FUZZ + FUZ2Z)
wfuzz -c \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -w /usr/share/seclists/Fuzzing/Extensions/Web-Extensions.fuzz.txt \
  --hc 404 "http://target.com/FUZZ.FUZ2Z"

# Ricorsivo (depth 2) — dopo aver trovato /admin, entra dentro
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  --hc 404 -R 2 http://target.com/FUZZ/
```

**Wordlist consigliate per directory:**

| Wordlist                        | Entry   | Quando                  |
| ------------------------------- | ------- | ----------------------- |
| `common.txt`                    | 4.723   | Quick win iniziale      |
| `directory-list-2.3-medium.txt` | 220.000 | Assessment standard     |
| `directory-list-2.3-big.txt`    | 1.27M   | Assessment approfondito |
| `api/api-endpoints.txt`         | 13.000  | API REST                |

> Errore tipico: lanciare subito `directory-list-2.3-big.txt` su target in produzione. Inizia con `common.txt`, poi scala. Con 1.27 milioni di request a thread alti puoi triggerare rate limit o DoS accidentale.

***

## Wfuzz per parameter fuzzing GET e POST

Wfuzz eccelle qui dove ffuf e feroxbuster non arrivano facilmente: scoprire parametri nascosti e testare injection points su qualsiasi campo.

### GET parameter discovery

```bash
# Fuzza il nome del parametro — cosa accetta questa pagina?
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  --hh 0 "http://target.com/search.php?FUZZ=test"
```

```text
00234:  C=200    45 L    120 W   1823 Ch    "query"
00891:  C=200    12 L     34 W    412 Ch    "debug"
```

`--hh 0` nasconde risposte vuote (parametro ignorato dal server). Tutto il resto ha risposta diversa → parametro valido.

### IDOR e injection testing

```bash
# IDOR — testa accesso a risorse di altri utenti
wfuzz -c -z range,1-1000 --hc 404,403 \
  "http://target.com/api/user/FUZZ/profile"

# Testa injection SQL su parametro id (vedi la guida a SQL injection)
wfuzz -c -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt \
  --hs "not found" \
  "http://target.com/item.php?id=FUZZ"
```

### POST parameter fuzzing

```bash
# Login form — fuzza la password con username fisso
wfuzz -c -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  --hc 302 \
  -d "username=admin&password=FUZZ" \
  http://target.com/login.php
```

`--hc 302` nasconde i redirect di fallimento. Quando appare una risposta 200 → password trovata.

```bash
# Se il server risponde sempre 200 — filtra per testo di errore
wfuzz -c -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  --hs "Invalid credentials" \
  -d "username=admin&password=FUZZ" \
  http://target.com/login.php
```

### JSON parameter fuzzing

```bash
# API JSON POST
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"action":"FUZZ"}' \
  --hc 404,400 http://target.com/api/v1
```

> Errore tipico su API JSON: dimenticare `-H "Content-Type: application/json"`. Senza di esso quasi tutte le API rispondono 400, rendendo impossibile distinguere i risultati validi.

***

## Wfuzz per virtual host e subdomain discovery

Un singolo IP può ospitare decine di vhost — admin panel, staging, API interne — non raggiungibili dalla URL principale.

```bash
# Misura prima la dimensione della risposta di default
curl -s http://TARGET_IP/ | wc -c
# Output: 1423

# Virtual host discovery — nascondi baseline, mostra tutto il resto
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.target.com" \
  --hh 1423 http://TARGET_IP/
```

```text
00089:  C=200   312 L   1024 W   18432 Ch   "admin"
00234:  C=200    45 L    120 W    4821 Ch   "staging"
```

```bash
# Subdomain fuzzing (DNS)
wfuzz -c -Z \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  http://FUZZ.target.com/
```

`-Z` ignora connection error (subdomain che non esiste → timeout, non crash del fuzzer).

***

## Wfuzz per header e cookie fuzzing

```bash
# Fuzza X-Forwarded-For — bypass IP whitelist su admin panel
wfuzz -c -w /usr/share/seclists/Fuzzing/IP-addresses.txt \
  -H "X-Forwarded-For: FUZZ" \
  --sc 200 http://target.com/admin/

# Fuzza User-Agent — aggira blocchi anti-bot
wfuzz -c -w /usr/share/seclists/Fuzzing/User-Agents/UserAgents.fuzz.txt \
  -H "User-Agent: FUZZ" \
  --hc 403 http://target.com/

# Fuzza session cookie — IDOR su sessioni numeriche
wfuzz -c -z range,1-50000 \
  -b "sessionid=FUZZ" \
  --hc 302,401 http://target.com/dashboard/
```

### HTTP Basic Auth

```bash
# Brute force Basic Auth
wfuzz -c -w /usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt \
  --basic "admin:FUZZ" --hc 401 \
  http://target.com/protected/

# Fuzza anche username
wfuzz -c \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  --basic "FUZZ:FUZ2Z" --hc 401 \
  http://target.com/protected/
```

***

## Cosa sono FUZZ, FUZ2Z e FUZ3Z in Wfuzz?

`FUZZ` identifica la prima posizione di fuzzing, `FUZ2Z` la seconda e `FUZ3Z` la terza. Ogni posizione viene associata alla wordlist corrispondente in base all'ordine con cui passi i parametri `-w`: la prima `-w` alimenta `FUZZ`, la seconda `FUZ2Z`, e così via.

```bash
# Path + estensione
wfuzz -c \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -w /usr/share/seclists/Fuzzing/Extensions/Web-Extensions.fuzz.txt \
  --hc 404 "http://target.com/FUZZ.FUZ2Z"

# Username + password su login
wfuzz -c \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -d "user=FUZZ&pass=FUZ2Z" --hc 302 \
  http://target.com/login
```

> Il numero di request = `len(w1) × len(w2)`. Due wordlist da 5.000 entry → 25 milioni di request. Calcola prima, specialmente su target con rate limiting.

***

## Wfuzz Encoders: Encoding e Test dei Filtri WAF

Gli encoders trasformano il payload prima di inviarlo. Non garantiscono un bypass — servono a testare come l'applicazione (o un eventuale WAF davanti) normalizza e interpreta l'input codificato, cosa utile sia in offensive che in un'analisi difensiva della normalizzazione.

```bash
# Elenco encoder disponibili
wfuzz -e encoders
```

```text
  base64       – Encodes the given string as base64
  md5          – Returns the md5 hash of the string
  urlencode    – URL-encodes special characters
  html_escape  – HTML entity encoding
  hexlify      – Converts string to hex
  sha1         – Returns sha1 hash
```

```bash
# URL encoding (caratteri speciali nei payload SQLi)
wfuzz -c -z file,/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt,urlencode \
  --hs "error" "http://target.com/?id=FUZZ"

# Double URL encoding (test di normalizzazione a doppio layer)
wfuzz -c -z file,sqli.txt,urlencode-urlencode \
  "http://target.com/?id=FUZZ"

# Base64 (API che accettano parametri encodati)
wfuzz -c -z file,payloads.txt,base64 \
  -d "token=FUZZ" http://target.com/api/

# MD5 di ogni password (form che hashano lato server)
wfuzz -c -z file,passwords.txt,md5 \
  -d "hash=FUZZ" http://target.com/login
```

***

## Come filtrare i risultati di Wfuzz

Il filtering è fondamentale perché wfuzz può generare migliaia di risposte apparentemente valide. I filtri `--hc`, `--sc`, `--hl`, `--hw`, `--hh`, `--hs` e `--ss` servono a isolare le risposte interessanti dal rumore.

| Filtro          | Flag                            | Quando usarlo                              |
| --------------- | ------------------------------- | ------------------------------------------ |
| Per status code | `--hc 404,403` / `--sc 200,301` | Sempre — primo filtro                      |
| Per linee       | `--hl N`                        | Tutte le 404 hanno stesso numero di linee  |
| Per parole      | `--hw N`                        | Tutte le 404 hanno stesso numero di parole |
| Per caratteri   | `--hh N`                        | Nascondi risposte di esatta dimensione N   |
| Regex show      | `--ss "pattern"`                | Vuoi solo risposte contenenti una stringa  |
| Regex hide      | `--hs "error page"`             | Nascondi risposte con testo specifico      |
| Espressione     | `--filter "c==200 and l>10"`    | Filtro combinato avanzato                  |

```bash
# Filtro combinato: status 200 E più di 10 linee
wfuzz -c -w wordlist.txt \
  --filter "c==200 and l>10" http://target.com/FUZZ

# Salva output JSON per analisi successiva
wfuzz -c -w wordlist.txt --hc 404 \
  -f /tmp/results.json,json http://target.com/FUZZ
```

***

## Wfuzz con Burp Suite e rate limiting

```bash
# Passa tutto per Burp Suite (ispeziona ogni request)
wfuzz -c -w wordlist.txt --hc 404 \
  -p 127.0.0.1:8080 http://target.com/FUZZ

# Target lento o con rate limiting
wfuzz -c -w wordlist.txt --hc 404 \
  -t 5 -s 0.5 http://target.com/FUZZ
# -t 5: 5 thread (default 10)
# -s 0.5: delay tra request (verifica l'unità sulla tua versione)

# User-Agent legittimo + cookie sessione (fuzzing da autenticato)
wfuzz -c -w wordlist.txt --hc 302,403 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -H "Cookie: sessionid=abc123; PHPSESSID=xyz789" \
  http://target.com/FUZZ
```

***

## Quando usare Wfuzz

Wfuzz è particolarmente utile quando il punto di fuzzing non è limitato al path URL. Per directory discovery standard, strumenti come ffuf sono spesso più veloci; wfuzz diventa la scelta giusta quando devi controllare parametri, header, cookie, body o più posizioni contemporaneamente — è lì che la sua genericità paga.

***

## Come usare Wfuzz durante un Web Pentest

```text
1. DIRECTORY QUICK WIN
   └─ common.txt + --hc 404
   └─ File fuzzing con .php, .bak, .zip, .txt

2. APPROFONDIMENTO SU PATH TROVATI
   └─ medium.txt su /admin/, /api/, /backup/
   └─ Ricorsione -R 2

3. VHOST / SUBDOMAIN
   └─ Misura baseline → fuzza Host header con --hh N
   └─ DNS subdomain con -Z

4. PARAMETER DISCOVERY
   └─ burp-parameter-names.txt su endpoint trovati
   └─ IDOR range numerico su /api/user/FUZZ/

5. INJECTION TESTING
   └─ SQLi wordlist su parametri trovati (collega con guida SQL injection)
   └─ XSS payloads su input fields

6. AUTH BRUTEFORCE
   └─ Identifica risposta di errore → configura --hs o --hc
   └─ Lancia con 10k-most-common.txt

7. OUTPUT
   └─ -f risultati.json,json → analisi in Burp/Dradis
```

***

## Troubleshooting

| Problema                         | Causa                                | Soluzione                                             |
| -------------------------------- | ------------------------------------ | ----------------------------------------------------- |
| Output flood di risultati        | Manca `--hc 404`                     | Aggiungi sempre `--hc 404` come baseline              |
| Tutte risposte stessa dimensione | Server risponde uguale per ogni path | Usa `--hl` o `--hw` al posto di `--hc`                |
| IP bannato rapidamente           | Troppi thread / rate limit           | `-t 5 -s 0.5`                                         |
| HTTPS — certificato invalido     | SSL self-signed                      | Aggiungi `--no-check-certificate`                     |
| VHost non trova nulla            | Baseline non filtrata                | Misura con `curl -s http://IP/ \| wc -c` poi `--hh N` |
| Encoding sbagliato               | Caratteri speciali nella wordlist    | Encoder: `-z file,list.txt,urlencode`                 |
| Multi-position lentissimo        | Prodotto cartesiano enorme           | Riduci wordlist o accetta la durata                   |
| Wfuzz si blocca senza output     | Target non risponde                  | Riduci thread, aggiungi `--req-delay 5`               |

***

## FAQ

**Cos'è Wfuzz?**
Un web fuzzer open source in Python che sostituisce una posizione `FUZZ` in una richiesta HTTP con i valori di una wordlist.

**A cosa serve Wfuzz?**
A scoprire directory, file, parametri nascosti, vhost, e a testare header, cookie, form di login e injection points — praticamente qualsiasi campo di una request HTTP.

**Wfuzz o ffuf per directory fuzzing?**
Ffuf è notevolmente più veloce (Go vs Python) e ha output più pulito. Per directory standard usa ffuf. Wfuzz torna comodo quando hai bisogno di encoders, multi-position avanzato o fuzzing su header/cookie.

**Come si usa FUZZ in Wfuzz?**
Metti la keyword `FUZZ` nel punto della request che vuoi testare (URL, header, body, cookie) e colleghi una wordlist con `-w`. Wfuzz sostituisce `FUZZ` con ogni riga della wordlist, una request alla volta.

**Cosa sono FUZ2Z e FUZ3Z?**
Sono la seconda e terza posizione di fuzzing in un comando multi-position, ciascuna alimentata dalla rispettiva wordlist passata con `-w`, nell'ordine in cui la specifichi.

**Come filtro le risposte di Wfuzz?**
Con `--hc`/`--sc` per status code, `--hl`/`--hw`/`--hh` per linee/parole/caratteri, `--hs`/`--ss` per contenuto testuale, o `--filter` per espressioni combinate.

**Wfuzz supporta il fuzzing POST?**
Sì, con `-d "campo=FUZZ"` per body form-encoded o JSON.

**Wfuzz può fuzzare header e cookie?**
Sì, con `-H "Header: FUZZ"` per gli header e `-b "cookie=FUZZ"` per i cookie.

**Come faccio fuzzing su applicazione autenticata?**
Cattura il cookie di sessione post-login con [Burp Suite](https://hackita.it/articoli/burp-suite/), poi usalo con `-H "Cookie: session=abc123"` in ogni request.

**Come gestisco CSRF token?**
Wfuzz non gestisce CSRF dinamici. Per quello usa Burp Intruder con macro, oppure uno script Python con requests che estrae il token prima di ogni request.

**Qual è la wordlist migliore?**
`common.txt` per quick win, `directory-list-2.3-medium.txt` per assessment completo, `burp-parameter-names.txt` per parameter discovery. Tutte in [SecLists](https://hackita.it/articoli/wordlist/).

**Come salvo i risultati per il report?**
`-f output.json,json` per parsing automatizzato, `-f output.html,html` per leggibilità immediata. Il JSON è comodo per importare in tool di reporting come Dradis.

***

## Wfuzz Cheat Sheet

```text
=== DIRECTORY ===
Base:        wfuzz -c -w common.txt --hc 404 http://target/FUZZ
+Estensione: wfuzz -c -w common.txt --hc 404 http://target/FUZZ.php
Multi-ext:   wfuzz -c -w names.txt -w ext.txt --hc 404 "http://target/FUZZ.FUZ2Z"
Ricorsivo:   wfuzz -c -w medium.txt --hc 404 -R 2 http://target/FUZZ/

=== PARAMETER ===
GET nome:    wfuzz -c -w burp-params.txt --hh 0 "http://target/page?FUZZ=test"
GET valore:  wfuzz -c -z range,1-1000 --hc 404 "http://target/item?id=FUZZ"
POST:        wfuzz -c -w passwords.txt -d "user=admin&pass=FUZZ" --hc 302 http://target/login
JSON POST:   wfuzz -c -w endpoints.txt -H "Content-Type: application/json" -d '{"a":"FUZZ"}' --hc 400 http://target/api

=== VHOST / SUBDOMAIN ===
VHost:       wfuzz -c -w subdomains.txt -H "Host: FUZZ.target.com" --hh BASELINE http://IP/
Subdomain:   wfuzz -c -Z -w subdomains.txt http://FUZZ.target.com/

=== HEADER / COOKIE ===
Header:      wfuzz -c -w ips.txt -H "X-Forwarded-For: FUZZ" --sc 200 http://target/admin/
Cookie:      wfuzz -c -z range,1-50000 -b "session=FUZZ" --hc 302 http://target/dashboard/

=== AUTH ===
Basic:       wfuzz -c -w passwords.txt --basic admin:FUZZ --hc 401 http://target/protected/
Login:       wfuzz -c -w passwords.txt -d "u=admin&p=FUZZ" --hs "Invalid" http://target/login

=== MULTI-POSITION ===
Doppio:      wfuzz -c -w list1.txt -w list2.txt "http://target/FUZZ/FUZ2Z"
Login 2D:    wfuzz -c -w users.txt -w passwords.txt -d "u=FUZZ&p=FUZ2Z" --hc 302 http://target/login

=== ENCODERS ===
URL:         -z file,list.txt,urlencode
Double URL:  -z file,list.txt,urlencode-urlencode
Base64:      -z file,list.txt,base64
MD5:         -z file,list.txt,md5

=== FILTRI ===
--hc 404,403       Hide status code
--sc 200,301       Show solo status code
--hl N             Hide risposte con N linee
--hh N             Hide risposte con N caratteri
--hs "stringa"     Hide contenente stringa
--ss "stringa"     Show contenente stringa
--filter "c==200 and l>5"   Espressione combinata

=== PROXY / EVASION ===
Burp:        -p 127.0.0.1:8080
Delay:       -s 0.5
Thread:      -t 5 (default 10)
UA custom:   -H "User-Agent: Mozilla/5.0..."
Con cookie:  -H "Cookie: session=abc123"

=== OUTPUT ===
JSON:        -f output.json,json
HTML:        -f output.html,html
```

***

**Guide correlate su hackita.it:**

* [ffuf: Web Fuzzing Veloce in Go](https://hackita.it/articoli/ffuf/)
* [feroxbuster: Directory Fuzzing Ricorsivo](https://hackita.it/articoli/feroxbuster/)
* [gobuster: Directory, DNS e VHost Discovery](https://hackita.it/articoli/gobuster/)
* [Burp Suite: Intercettare e Modificare Richieste HTTP](https://hackita.it/articoli/burp-suite/)
* [SQL Injection: Guida Completa](https://hackita.it/articoli/sql-injection/)
* [Wordlist e SecLists: Guida Operativa](https://hackita.it/articoli/wordlist/)
* [Attacchi alle Applicazioni Web](https://hackita.it/articoli/attacchi-applicazioni-web/)

## Riferimenti

* [Wfuzz GitHub – xmendez/wfuzz](https://github.com/xmendez/wfuzz)
* [Wfuzz Docs](https://wfuzz.readthedocs.io/en/latest/)
