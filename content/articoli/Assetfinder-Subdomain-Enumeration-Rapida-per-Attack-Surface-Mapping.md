---
title: 'Assetfinder: Subdomain Enumeration Rapida per Attack Surface Mapping'
slug: assetfinder
description: >-
  Assetfinder è un tool OSINT per enumerare subdomain da fonti pubbliche durante
  la fase di reconnaissance. Ideale per mappare rapidamente la superficie
  d’attacco di un dominio in penetration test.
image: /Gemini_Generated_Image_czu74wczu74wczu7.webp
draft: false
date: 2026-02-10T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - subdomain-enumeration
  - osint
---

Le applicazioni web hanno spesso parametri non documentati — parametri di debug, flag admin, endpoint interni esposti per errore. Arjun li trova. Il tool testa migliaia di nomi di parametri comuni contro un endpoint HTTP e identifica quelli che producono una risposta diversa, indicando che il server li accetta e li elabora.

Un parametro nascosto come `?debug=true` o `?admin=1` può sbloccare funzionalità privilegiate, bypassare autenticazione o aprire vettori di injection inesplorati. Arjun è lo strumento che colma il gap tra la content discovery (directory bruteforce) e il vulnerability testing (injection).

Kill chain: **Reconnaissance / Discovery** (MITRE ATT\&CK T1595). L'articolo copre dalla scansione base al fuzzing avanzato su endpoint REST e form POST.

***

## 1️⃣ Setup e Installazione

```bash
pip install arjun --break-system-packages
```

**Da sorgente:**

```bash
git clone https://github.com/s0md3v/Arjun.git
cd Arjun
python3 setup.py install
```

**Verifica:**

```bash
arjun -h
```

Output: help con tutte le opzioni disponibili. Versione attuale: 2.2.6.

**Requisiti:**

* Python 3.6+
* Moduli: `requests`, `dicttoxml`
* Connettività HTTP verso il target

***

## 2️⃣ Uso Base

Scansione parametri GET:

```bash
arjun -u http://10.10.10.50/search
```

Output:

```
[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Performing parameter discovery
[+] Valid parameter found: query
[+] Valid parameter found: page
[+] Valid parameter found: debug
[+] Valid parameter found: lang
```

Arjun ha trovato 4 parametri accettati dall'endpoint `/search`. Il parametro `debug` è particolarmente interessante.

**Parametri chiave:**

* `-u URL` → target endpoint
* `-m GET/POST/JSON` → metodo HTTP (default GET)
* `-w wordlist` → wordlist custom
* `-t N` → thread
* `-o file` → output file (JSON)
* `--headers "H: V"` → header custom
* `-c N` → chunk size (parametri testati per richiesta)

Scansione POST:

```bash
arjun -u http://10.10.10.50/api/login -m POST
```

Scansione con body JSON:

```bash
arjun -u http://10.10.10.50/api/users -m JSON
```

***

## 3️⃣ Tecniche Operative

### Wordlist custom per applicazione specifica

La wordlist default di Arjun contiene \~25.000 nomi di parametri. Per target specifici, crea wordlist mirate:

```bash
arjun -u http://target/endpoint -w custom_params.txt
```

Genera una wordlist da [Waybackurls](https://hackita.it/articoli/waybackurls):

```bash
echo "target.com" | waybackurls | grep "?" | sed 's/.*?//' | tr '&' '\n' | cut -d= -f1 | sort -u > target_params.txt
arjun -u http://target/search -w target_params.txt
```

### Scansione con autenticazione

```bash
arjun -u http://target/dashboard --headers "Cookie: session=abc123; Authorization: Bearer token"
```

### Multi-URL da file

```bash
arjun -i urls.txt -o results.json
```

`urls.txt` contiene un endpoint per riga. L'output JSON è parsabile per automazione.

### Chunk size per evasion

Arjun testa parametri in blocchi. Ridurre il chunk size genera meno parametri per richiesta, rendendo il traffico meno sospetto:

```bash
arjun -u http://target/search -c 10
```

Default: 500 parametri per richiesta. Con `-c 10`, ogni richiesta testa solo 10 parametri.

***

## 4️⃣ Tecniche Avanzate

### Integrazione con Burp Suite

Arjun trova i parametri, Burp li testa per vulnerabilità:

```bash
arjun -u http://target/search --stable
```

Il flag `--stable` aumenta la precisione evitando falsi positivi. Usa i parametri trovati come input per Burp Intruder.

### Discovery su endpoint REST API

```bash
arjun -u http://target/api/v2/users -m JSON --headers "Content-Type: application/json"
```

Trova parametri JSON accettati dall'API. Risultato tipico:

```
[+] Valid parameter found: role
[+] Valid parameter found: admin
[+] Valid parameter found: id
```

Il parametro `role` o `admin` in un body JSON potrebbe permettere privilege escalation.

### Proxy support

```bash
arjun -u http://target/search --proxy http://127.0.0.1:8080
```

Passa il traffico attraverso Burp per catturare tutte le richieste.

### Rate limiting

```bash
arjun -u http://target/search -t 2 --delay 1
```

2 thread con 1 secondo di delay — lento ma stealth.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Trovare parametro debug su webapp

```bash
arjun -u http://10.10.10.50/index.php
```

**Output atteso:**

```
[+] Valid parameter found: debug
[+] Valid parameter found: page
[+] Valid parameter found: id
```

Verifica: `curl "http://10.10.10.50/index.php?debug=true"` — potrebbe mostrare stack trace, configurazione interna, path del filesystem.

**Cosa fare se fallisce:**

* Nessun parametro trovato → L'endpoint potrebbe non accettare parametri GET. Prova `-m POST`.
* Falsi positivi → Usa `--stable` per ridurre il noise.

**Timeline:** 2-3 minuti con wordlist default.

### Scenario 2: API REST — Trovare parametri per IDOR

```bash
arjun -u http://10.10.10.50/api/profile -m JSON --headers "Authorization: Bearer eyJ..."
```

**Output atteso:**

```
[+] Valid parameter found: user_id
[+] Valid parameter found: role
```

Testa IDOR: cambia `user_id` per accedere a profili altrui.

**Cosa fare se fallisce:**

* 401/403 su tutto → Token scaduto. Rinnova.
* Nessun parametro → API molto ristretta. Prova parametri da documentazione Swagger se disponibile.

**Timeline:** 1-2 minuti.

### Scenario 3: Form login — Trovare parametri di bypass

```bash
arjun -u http://10.10.10.50/login -m POST
```

**Output atteso:**

```
[+] Valid parameter found: username
[+] Valid parameter found: password
[+] Valid parameter found: remember
[+] Valid parameter found: redirect
[+] Valid parameter found: otp_bypass
```

`otp_bypass` potrebbe disabilitare 2FA.

**Cosa fare se fallisce:**

* CSRF protection blocca le richieste → Estrai il CSRF token e passalo via `--headers`.

**Timeline:** 2 minuti.

***

## 6️⃣ Toolchain Integration

**Flusso operativo:**

[Gobuster](https://hackita.it/articoli/gobuster) (endpoint discovery) → **Arjun (parameter discovery)** → [sqlmap](https://hackita.it/articoli/sqlmap) oppure [Burp](https://hackita.it/articoli/burp-suite) (vulnerability testing)

```bash
# Gobuster trova endpoint
gobuster dir -u http://target -w common.txt | grep "200" | awk '{print $1}' > endpoints.txt

# Arjun trova parametri per ogni endpoint
arjun -i endpoints.txt -o params.json

# sqlmap testa i parametri trovati
cat params.json | jq -r '.[] | .url + "?" + (.params | join("=test&")) + "=test"' | while read url; do
  sqlmap -u "$url" --batch --level 2
done
```

| Tool             | Scopo                | Metodo            | Output             |
| ---------------- | -------------------- | ----------------- | ------------------ |
| Arjun            | Parameter discovery  | Brute + heuristic | Parametri validi   |
| ParamSpider      | URL parameter mining | Passivo (archivi) | URL con parametri  |
| x8               | Parameter discovery  | Brute             | Parametri validi   |
| Burp Param Miner | Parameter discovery  | Extension Burp    | Parametri + header |

***

## 7️⃣ Attack Chain Completa

**Fase 1 — Content Discovery (5 min):** Gobuster trova `/api/admin`.

**Fase 2 — Parameter Discovery (3 min):**

```bash
arjun -u http://target/api/admin -m JSON --headers "Authorization: Bearer token"
```

Trova `role` come parametro accettato.

**Fase 3 — Exploitation (5 min):** Invia `{"role": "superadmin"}` → privilege escalation.

**Fase 4 — Post-exploitation (20 min):** Accesso admin completo → data exfiltration.

**Timeline totale:** \~33 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* Richieste con centinaia di parametri anomali in una singola request
* Burst di richieste verso lo stesso endpoint con parametri diversi

### Tecniche di evasion

1. **Chunk size basso:** `-c 10` riduce i parametri per richiesta.
2. **Delay:** `--delay 2` tra richieste.
3. **UA e header legittimi:** `--headers "User-Agent: Mozilla/5.0..."`.

***

## 9️⃣ Performance & Scaling

**Single endpoint:** 1-3 minuti con wordlist default (25K params).

**Multi-endpoint:** serializzato con `-i file`. 10 endpoint: 10-30 minuti.

**Ottimizzazione:** usa wordlist ridotte (5K) per primo passaggio, full solo su endpoint promettenti.

***

## 🔟 Tabelle Tecniche

| Flag               | Descrizione                            |
| ------------------ | -------------------------------------- |
| `-u URL`           | Target endpoint                        |
| `-m METHOD`        | GET/POST/JSON                          |
| `-w wordlist`      | Wordlist custom                        |
| `-t N`             | Thread                                 |
| `-c N`             | Chunk size                             |
| `-o file`          | Output JSON                            |
| `--headers "H: V"` | Header custom                          |
| `--proxy URL`      | Proxy HTTP                             |
| `--stable`         | Modalità stabile (meno falsi positivi) |
| `--delay N`        | Delay tra richieste (sec)              |
| `-i file`          | Input file multi-URL                   |

***

## 11️⃣ Troubleshooting

| Problema              | Causa                          | Fix                            |
| --------------------- | ------------------------------ | ------------------------------ |
| Troppi falsi positivi | Risposta instabile             | Usa `--stable`                 |
| Nessun parametro      | Endpoint non parametrizzato    | Prova altro metodo (`-m POST`) |
| Timeout               | Server lento                   | `-t 1 --delay 2`               |
| WAF blocca            | Richieste con troppi parametri | `-c 5` per chunk piccoli       |

***

## 12️⃣ FAQ

**Arjun trova parametri header?**
No nativamente. Per header discovery usa Burp Param Miner.

**Funziona su API GraphQL?**
Non direttamente. GraphQL ha un sistema di query diverso. Usa tool dedicati come `graphql-voyager`.

**La wordlist default è sufficiente?**
Per la maggior parte dei casi sì. Per target specifici, integra con parametri estratti da waybackurls.

**Posso usare Arjun via proxy SOCKS?**
Non direttamente. Usa `proxychains4 arjun -u target`.

***

## 13️⃣ Cheat Sheet

| Azione          | Comando                                        |
| --------------- | ---------------------------------------------- |
| Scan GET        | `arjun -u http://target/page`                  |
| Scan POST       | `arjun -u http://target/page -m POST`          |
| Scan JSON       | `arjun -u http://target/api -m JSON`           |
| Con auth        | `arjun -u URL --headers "Cookie: session=abc"` |
| Wordlist custom | `arjun -u URL -w params.txt`                   |
| Multi-URL       | `arjun -i endpoints.txt -o results.json`       |
| Stealth         | `arjun -u URL -c 10 --delay 1 -t 2`            |
| Via proxy       | `arjun -u URL --proxy http://127.0.0.1:8080`   |

***

**Disclaimer:** Arjun è un tool per security testing autorizzato. L'uso su applicazioni senza permesso è illegale. Repository: [github.com/s0md3v/Arjun](https://github.com/s0md3v/Arjun).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
