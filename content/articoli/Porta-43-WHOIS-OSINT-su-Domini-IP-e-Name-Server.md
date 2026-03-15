---
title: 'Porta 43 WHOIS: OSINT su Domini, IP e Name Server'
slug: porta-43-whois
description: 'La porta 43 WHOIS permette query passive su domini, IP e ASN per raccogliere registrar, name server, contatti e scadenze utili alla reconnaissance e all’OSINT.'
image: /porta-43-whois.webp
draft: true
date: 2026-04-11T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - osint
  - rdap
---

La porta 43 espone il **WHOIS protocol** — il servizio standard per interrogare database di registrazione domini, indirizzi IP e AS numbers. WHOIS (RFC 3912) opera come directory pubblica Internet, rispondendo con owner info, date registrazione/scadenza, name servers e contatti tecnici/amministrativi per qualsiasi dominio o blocco IP. In penetration testing e [OSINT](https://hackita.it/articoli/osint), la porta 43 è il **primo step reconnaissance passivo**: email addresses per [phishing](https://hackita.it/articoli/phishing), name servers per [DNS](https://hackita.it/articoli/dns) takeover, scadenze domini per domain hijacking, e organizational info per [social engineering](https://hackita.it/articoli/social-engineering). Ogni pentester inizia con WHOIS query prima di toccare il target — è intelligence gathering legale, passivo, non-invasivo.

WHOIS sopravvive identico dal 1982 perché è **infrastructure critica Internet**: ICANN impone registrar di operare WHOIS server, ARIN/RIPE/APNIC mantengono WHOIS per allocazioni IP/ASN, e nessun replacement esiste (RDAP è supplement, non sostituzione). Nel 2026, WHOIS è utilizzato daily da: security researchers, domain investors, legal teams, e brand protection services.

***

## Anatomia tecnica del protocollo WHOIS

WHOIS usa **TCP porta 43** con protocollo testuale plaintext estremamente semplice.

**Flow WHOIS query:**

1. **TCP Connect** — Client connette porta 43 del WHOIS server
2. **Query** — Client invia domain/IP/ASN seguito da `\r\n`
3. **Response** — Server restituisce record WHOIS (formato libero, non standardizzato)
4. **Connection Close** — Server chiude dopo invio response

**Esempio query manuale:**

```bash
telnet whois.verisign-grs.com 43
example.com
```

**Formato response (non standardizzato):**

```
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://www.iana.org/domains/example
Updated Date: 2024-08-14T07:01:31Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2025-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: signedDelegation
```

**WHOIS server hierarchy:**

```
Root WHOIS (IANA) → gTLD WHOIS (Verisign .com/.net) → Registrar WHOIS (GoDaddy/Namecheap)
                  → RIR WHOIS (ARIN/RIPE/APNIC) → IP block owner
```

**Campi critici per pentest:**

| Campo                  | Uso pentest                                           |
| ---------------------- | ----------------------------------------------------- |
| `Registrant Email`     | Phishing target, password reset attacks               |
| `Admin Email`          | Technical contact, social engineering                 |
| `Name Server`          | DNS infrastructure mapping, takeover opportunity      |
| `Registry Expiry Date` | Domain hijacking window (expired domains)             |
| `Registrar`            | Registrar-specific vulnerabilities (account takeover) |
| `Organization`         | Company name OSINT, subsidiary mapping                |
| `Creation Date`        | Domain age (new domains = suspicious)                 |

Le **misconfigurazioni comuni**: WHOIS privacy assente (real email/phone esposti), weak registrar account (same password everywhere), expired domains non rinnovati (takeover opportunity), e name servers third-party vulnerabili.

***

## Enumerazione base

```bash
whois example.com
```

```
Domain Name: EXAMPLE.COM
Registrar: RESERVED-Internet Assigned Numbers Authority
Registrant Organization: Internet Assigned Numbers Authority
Registrant Email: [email protected]
Admin Email: [email protected]
Tech Email: [email protected]
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Creation Date: 1995-08-14
Registry Expiry Date: 2025-08-13
Updated Date: 2024-08-14
DNSSEC: signedDelegation
```

**Query IP address:**

```bash
whois 8.8.8.8
```

```
NetRange: 8.0.0.0 - 8.255.255.255
CIDR: 8.0.0.0/8
NetName: LVLT-ORG-8-8
Organization: Level 3 Parent, LLC (LPL-141)
RegDate: 1992-12-01
Updated: 2012-02-24
```

**Query ASN:**

```bash
whois AS15169
```

```
aut-num: AS15169
as-name: GOOGLE
descr: Google LLC
country: US
org: ORG-GL71-RIPE
```

***

## Enumerazione avanzata: intelligence gathering

### Email harvesting per phishing

```bash
whois victim.com | grep -i email
```

```
Registrant Email: [email protected]
Admin Email: [email protected]
Tech Email: [email protected]
```

Emails per [phishing](https://hackita.it/articoli/phishing) campaigns, [password spraying](https://hackita.it/articoli/password-spraying), o breach correlation (HaveIBeenPwned).

### Name server enumeration

```bash
whois victim.com | grep -i "name server"
```

```
Name Server: NS1.VICTIM.COM
Name Server: NS2.VICTIM.COM
Name Server: NS3.CLOUDFLARE.COM
```

**Implicazioni:**

* `NS1.VICTIM.COM` self-hosted → target per [DNS](https://hackita.it/articoli/dns) exploits
* `NS3.CLOUDFLARE.COM` third-party → DNS zone transfer unlikely, but check

**DNS zone transfer attempt:**

```bash
dig @NS1.VICTIM.COM victim.com AXFR
```

### Registrar identification

```bash
whois victim.com | grep -i registrar
```

```
Registrar: GoDaddy.com, LLC
Registrar WHOIS Server: whois.godaddy.com
Registrar URL: https://www.godaddy.com
```

**Targeting registrar account takeover:**

* Check [password reset](https://hackita.it/articoli/account-takeover) flows
* Test for account enumeration
* Credential stuffing with leaked databases

### Subdomain discovery via historical WHOIS

```bash
# Tool: whoisxmlapi (paid) o SecurityTrails
curl "https://api.securitytrails.com/v1/history/victim.com/whois" -H "APIKEY: YOUR_KEY"
```

Historical WHOIS shows old name servers, old contacts, old IP addresses — useful for finding forgotten subdomains/infrastructure.

***

## Tecniche offensive

### 1. Email scraping per credential stuffing

```bash
# Mass WHOIS email harvest
for domain in $(cat domains.txt); do
  whois $domain | grep -Eio '\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,6}\b' | tr '[:upper:]' '[:lower:]'
done | sort -u > emails.txt
```

```bash
# Test su [HaveIBeenPwned](https://hackita.it/articoli/hibp)
for email in $(cat emails.txt); do
  curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$email" -H "hibp-api-key: KEY" | jq .
done
```

Emails leakate → credential stuffing su corporate login portals.

### 2. Domain expiration monitoring

```bash
whois target.com | grep -i "expiry"
```

```
Registry Expiry Date: 2026-03-15T00:00:00Z
```

**Attack window:** Se dominio scade e non viene rinnovato, acquistare il dominio → phishing campaigns usando dominio legittimo vittima.

**Monitoring script:**

```bash
#!/bin/bash
DOMAIN="target.com"
EXPIRY=$(whois $DOMAIN | grep -i "expiry" | awk '{print $NF}')
DAYS_LEFT=$(( ( $(date -d "$EXPIRY" +%s) - $(date +%s) ) / 86400 ))

if [ $DAYS_LEFT -lt 30 ]; then
  echo "[!] $DOMAIN expires in $DAYS_LEFT days!"
fi
```

### 3. Name server takeover

```bash
whois victim.com | grep -i "name server"
# NS1.VICTIM.COM → A record: 203.0.113.50

nslookup NS1.VICTIM.COM
# No response (NS down)
```

**Exploitation:** Se name server è down/abbandonato, registrare lo stesso hostname su provider terzo, controllare DNS resolution per `victim.com`.

### 4. Registrar account enumeration

```bash
# GoDaddy account enumeration (patched 2022, esempio storico)
curl -X POST https://www.godaddy.com/forsale/check -d "domain=victim.com"
# Response indica se dominio è su GoDaddy account specifico
```

Modern registrars hanno mitigato questo, ma old/small registrars potrebbero avere account enum vulnerabilities.

***

## Scenari pratici

### Scenario 1 — WHOIS → phishing campaign

**Contesto:** pentest esterno, zero knowledge su target.

```bash
# Fase 1: WHOIS query
whois victim.com
```

```
Registrant Email: [email protected]
Admin Email: [email protected]
Organization: Victim Corporation
```

```bash
# Fase 2: Organizational OSINT
whois victim.com | grep -i organization
# Victim Corporation

# LinkedIn scraping per employees
theHarvester -d victim.com -b linkedin
# Emails: [email protected], [email protected]
```

```bash
# Fase 3: Phishing email
cat << EOF > phishing.eml
From: [email protected]
To: [email protected]
Subject: Urgent: Domain Renewal Required

Your domain victim.com expires in 7 days. Click here to renew:
http://evil.attacker.com/renew
EOF
```

Vittima clicca → [credential harvest](https://hackita.it/articoli/credential-harvesting) → domain takeover.

### Scenario 2 — Expired domain hijacking

**Contesto:** competitor monitoring, domain acquisition.

```bash
# Monitor competitor domains
whois competitor.com | grep -i expiry
# Registry Expiry Date: 2026-02-01
```

```bash
# Setup daily cron check
0 0 * * * /usr/local/bin/check_expiry.sh competitor.com
```

**check\_expiry.sh:**

```bash
#!/bin/bash
EXPIRY=$(whois $1 | grep -i expiry | awk '{print $NF}')
if [ $(date -d "$EXPIRY" +%s) -lt $(date +%s) ]; then
  echo "[+] $1 EXPIRED! Attempting registration..."
  # Automated domain purchase via API (Namecheap/GoDaddy)
fi
```

**Post-acquisition:** Redirect `competitor.com` → `yoursite.com` to capture traffic.

### Scenario 3 — Name server intelligence

**Contesto:** infrastructure mapping pre-attack.

```bash
whois target.corp | grep -i "name server"
```

```
Name Server: NS1.TARGET.CORP
Name Server: NS2.TARGET.CORP
Name Server: NS-CLOUD-1.GOOGLEDOMAINS.COM
```

```bash
# Resolve name servers to IP
dig +short NS1.TARGET.CORP
# 198.51.100.10

# Check if self-hosted NS is vulnerable
[nmap](https://hackita.it/articoli/nmap) -sV -p 53 198.51.100.10
```

```
53/tcp open  domain  ISC BIND 9.9.5-3 (Ubuntu)
```

**Exploitation:** BIND 9.9.5 vulnerable a CVE-2015-5477 (TKEY DoS). Attack NS → DNS down → email/web services disrupted.

***

## Toolchain integration

**Pipeline OSINT/recon con WHOIS:**

```
RECONNAISSANCE
│
├─ whois <domain>                           → Registrant, admin emails
├─ whois <IP>                               → Netblock owner, organization
├─ whois <ASN>                              → AS owner, routing info
└─ Historical WHOIS (SecurityTrails)        → Old infrastructure

INTELLIGENCE GATHERING
│
├─ Email harvest → [HaveIBeenPwned](https://hackita.it/articoli/hibp) → breach check
├─ Name servers → [DNS](https://hackita.it/articoli/dns) enum → zone transfer
├─ Registrar ID → account takeover research
└─ Expiry dates → domain hijacking monitor

EXPLOITATION
│
├─ A) Expired domains → register → phishing infrastructure
├─ B) Leaked admin emails → [credential stuffing](https://hackita.it/articoli/credential-stuffing)
├─ C) Vulnerable NS → [DNS exploits](https://hackita.it/articoli/dns) → service disruption
└─ D) Organization info → [social engineering](https://hackita.it/articoli/social-engineering)

NEXT STEPS
│
└─ WHOIS data feeds [subdomain enumeration](https://hackita.it/articoli/subdomain-enum), [Google dorking](https://hackita.it/articoli/google-dorking), employee LinkedIn scraping
```

**Tabella comparativa domain info sources:**

| Source           | Info Type                         | Accuracy        | Cost     |
| ---------------- | --------------------------------- | --------------- | -------- |
| WHOIS (porta 43) | Registrant, emails, NS            | ✅ Authoritative | Free     |
| RDAP (HTTPS API) | Same as WHOIS + structured JSON   | ✅ Authoritative | Free     |
| DNS records      | IP, MX, TXT (SPF/DKIM)            | ✅ Real-time     | Free     |
| SecurityTrails   | Historical DNS, WHOIS, subdomains | ⚠️ Aggregated   | Paid     |
| Censys/Shodan    | IP→services, certificates         | ✅ Scan-based    | Freemium |

***

## Attack chain completa

**Scenario: WHOIS → social engineering → initial access**

```
[00:00] WHOIS QUERY
whois target.com

[00:02] EMAIL HARVEST
# admin@target.com, [email protected]

[00:05] BREACH CHECK
curl https://haveibeenpwned.com/api/v3/breachedaccount/admin@target.com
# Pwned in LinkedIn breach 2021

[00:10] LINKEDIN OSINT
theHarvester -d target.com -b linkedin
# Employees: John Doe (CEO), Jane Smith (IT Admin)

[00:15] SPEAR PHISHING
# Email to jane.smith: "IT Security: Password Reset Required"
# Payload: credential harvest page

[00:30] CREDENTIAL CAPTURE
# jane.smith:Password123!

[00:35] VPN ACCESS
openvpn --config target-vpn.ovpn --auth-user-pass creds.txt
# [+] VPN connected

[00:40] INTERNAL NETWORK
# Lateral movement via [crackmapexec](https://hackita.it/articoli/crackmapexec)
```

**Timeline:** 40 minuti da WHOIS a internal network access.

***

## Detection & evasion

### Lato Blue Team

WHOIS queries sono **pubbliche e legittime** — impossibile bloccare. Monitoring focus:

**IoC warning signs:**

* Massive WHOIS queries su domini corporate (domain scraping)
* WHOIS queries subito prima di phishing campaigns
* Unusual registrar account login attempts (enumeration)

**Defensive measures:**

```bash
# Enable WHOIS privacy (hides real emails)
# Registrar settings: Enable "Domain Privacy" or "WHOIS Guard"

# Monitor domain expiration
whois mycompany.com | grep -i expiry
# Set calendar reminder 90 days before

# Setup DMARC to prevent email spoofing
dig TXT _dmarc.mycompany.com
# "v=DMARC1; p=reject;"
```

### Lato Red Team: OPSEC

WHOIS è **100% passive** — no evasion needed. Best practices:

1. **Use `whois` command** invece di web interfaces (no browser fingerprinting)
2. **Tor for WHOIS** (opzionale, per anonimato):

```bash
proxychains whois target.com
```

1. **Rate limiting awareness:** Some WHOIS servers limit queries/IP (50-100/day). Rotate IPs se mass scanning.

***

## Performance & scaling

**Single query:**

```bash
time whois example.com
# real    0m0.450s
```

**Mass domain intelligence:**

```bash
# 1000 domains
for domain in $(cat domains.txt); do
  whois $domain >> whois_dump.txt
  sleep 1  # Rate limiting
done
```

**Parallel processing:**

```bash
cat domains.txt | parallel -j 10 "whois {} >> whois_dump.txt"
# 10 parallel queries, completes 1000 domains in ~2 minutes
```

**WHOIS rate limits:** Most servers allow 50-100 queries/day/IP. Enterprise APIs (WhoisXMLAPI, SecurityTrails) have 10k-100k/month limits.

***

## Tabelle tecniche

### Command reference

| Comando                         | Scopo                 | Note                            |
| ------------------------------- | --------------------- | ------------------------------- |
| `whois <domain>`                | Domain info           | Registrant, emails, NS, expiry  |
| `whois <IP>`                    | IP block owner        | Organization, netblock, country |
| `whois <ASN>`                   | AS info               | ISP, routing, BGP peers         |
| `whois -h <server> <query>`     | Specific WHOIS server | Bypass auto-routing             |
| `dig +short <domain> NS`        | Quick NS lookup       | Faster than full WHOIS          |
| `curl rdap.org/domain/<domain>` | RDAP query            | JSON output (modern WHOIS)      |

### WHOIS servers per TLD

| TLD             | WHOIS Server           |
| --------------- | ---------------------- |
| `.com` / `.net` | whois.verisign-grs.com |
| `.org`          | whois.pir.org          |
| `.io`           | whois.nic.io           |
| `.uk`           | whois.nic.uk           |
| `.de`           | whois.denic.de         |
| IP (ARIN)       | whois.arin.net         |
| IP (RIPE)       | whois.ripe.net         |
| IP (APNIC)      | whois.apnic.net        |

***

## Troubleshooting

| Errore                  | Causa                        | Fix                                     |
| ----------------------- | ---------------------------- | --------------------------------------- |
| `No match for domain`   | Domain non registrato o typo | Verifica spelling                       |
| `Connection timed out`  | WHOIS server down            | Prova server alternativo: `-h <server>` |
| `Rate limit exceeded`   | Troppi query da stesso IP    | Attendere o cambiare IP                 |
| `Redacted for privacy`  | WHOIS privacy enabled        | Info nascosta intenzionalmente          |
| Empty name server field | Domain parcheggiato          | No DNS attivo                           |

***

## FAQ

**WHOIS è legale per reconnaissance?**

Sì. WHOIS è **public information service** — query WHOIS non costituisce hacking. Tuttavia, usare WHOIS data per phishing/fraud è illegale.

**GDPR ha ucciso WHOIS?**

Parzialmente. GDPR (2018) ha forzato registrars europei a redact emails/phone personali. Corporate registrations mostrano ancora info, ma individuals hanno privacy di default.

**RDAP è il nuovo WHOIS?**

RDAP (Registration Data Access Protocol) è la versione moderna WHOIS con JSON output e autenticazione. Sta gradualmente sostituendo WHOIS, ma porta 43 WHOIS rimane standard de facto nel 2026.

**Posso fare WHOIS query via API?**

Sì. Servizi come WhoisXMLAPI, SecurityTrails, DomainTools offrono API REST. Utile per automation e bulk queries senza rate limits.

**Come trovo il WHOIS server corretto per un TLD?**

Il comando `whois` auto-route correttamente. Manualmente: IANA maintains list su [https://www.iana.org/domains/root/db](https://www.iana.org/domains/root/db)

**WHOIS rivela subdomain?**

No. WHOIS mostra solo domain registrato (example.com), non subdomains (mail.example.com). Per subdomains, usa [DNS enum](https://hackita.it/articoli/subdomain-enum) o certificate transparency logs.

***

## Cheat sheet finale

| Azione                | Comando                                              |
| --------------------- | ---------------------------------------------------- |
| Query domain          | `whois example.com`                                  |
| Query IP              | `whois 8.8.8.8`                                      |
| Query ASN             | `whois AS15169`                                      |
| Specific WHOIS server | `whois -h whois.verisign-grs.com example.com`        |
| Email harvest         | `whois domain.com \| grep -i email`                  |
| Name servers          | `whois domain.com \| grep -i "name server"`          |
| Expiry date           | `whois domain.com \| grep -i expiry`                 |
| Registrar             | `whois domain.com \| grep -i registrar`              |
| RDAP (modern WHOIS)   | `curl https://rdap.org/domain/example.com`           |
| Mass query            | `cat domains.txt \| parallel whois {} >> output.txt` |

***

## Perché WHOIS resta fondamentale nel 2026

WHOIS è **infrastruttura critica Internet** — ICANN policy requires public accessibility. Alternative (RDAP) exist ma WHOIS port 43 rimane universally supported. Nel pentest, WHOIS è step 0 di ogni engagement: domain expiry per timing attacks, email harvesting per phishing, name server mapping per [DNS attacks](https://hackita.it/articoli/dns), organization info per [social engineering](https://hackita.it/articoli/social-engineering). Tool automation (Recon-ng, Maltego, SpiderFoot) integrate WHOIS come primary data source.

## WHOIS vs RDAP

WHOIS (1982) è plaintext protocol porta 43. RDAP (2015) è RESTful API over HTTPS con JSON response. Differenze:

| Caratteristica       | WHOIS                    | RDAP                     |
| -------------------- | ------------------------ | ------------------------ |
| Protocol             | TCP porta 43             | HTTPS (443)              |
| Output format        | Plaintext (inconsistent) | JSON (structured)        |
| Authentication       | None                     | Optional OAuth           |
| Internationalization | Limited                  | Full Unicode             |
| Status               | Legacy ma universal      | Modern ma adoption lenta |

RDAP adoption è \~30% registrars nel 2026. WHOIS rimane default.

## Privacy protection post-GDPR

GDPR ha cambiato WHOIS drasticamente:

**Pre-GDPR (2017):**

```
Registrant Email: [email protected]
Registrant Phone: +39-02-1234567
```

**Post-GDPR (2018+):**

```
Registrant Email: REDACTED FOR PRIVACY
Registrant Phone: REDACTED FOR PRIVACY
```

**Workaround per pentesters:**

1. **Historical WHOIS** (pre-2018 data still available via SecurityTrails)
2. **Corporate domains** (businesses still publish contact info)
3. **Alternate sources** (DNS TXT records, SSL certificates)

## OPSEC: WHOIS in reconnaissance

WHOIS è **100% passive** — il target NON sa che stai facendo WHOIS query. È il **safest recon method** available. Best practices:

1. **Always start con WHOIS** prima di active scanning
2. **Document everything** — WHOIS data change nel tempo
3. **Check historical data** — old name servers = forgotten infrastructure

***

> **Disclaimer:** Tutti i comandi sono destinati all'uso in ambienti autorizzati. WHOIS data è public information, ma usarla per phishing/fraud è reato. L'autore e HackIta declinano responsabilità. RFC 3912: [https://www.rfc-editor.org/rfc/rfc3912.html](https://www.rfc-editor.org/rfc/rfc3912.html)

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
