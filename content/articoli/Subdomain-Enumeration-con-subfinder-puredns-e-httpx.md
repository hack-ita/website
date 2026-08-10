---
title: 'Subdomain Enumeration con subfinder, puredns e httpx'
slug: subdomain-enumeration
description: 'Pipeline di subdomain enumeration: recon passiva con subfinder, brute force con puredns, permutazioni Alterx, validazione httpx e subdomain takeover check.'
image: /subdomain-enumeration-passive-active-recon.webp
draft: true
date: 2026-08-18T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - subdomain enumeration
  - subfinder
  - puredns
  - massdns
  - Alterx
  - httpx
  - subdomain takeover
---

# Subdomain Enumeration: Guida Completa a Subfinder, Amass, Puredns e DNS Brute Force

Un target come `company.com` ha la homepage. Dietro ha `dev.company.com` senza autenticazione, `api-v2.company.com` con una versione vecchia del backend, `jenkins.company.com` accessibile da internet, e `cdn-old.company.com` che punta a un servizio cloud non più configurato correttamente e potenzialmente vulnerabile a subdomain takeover. Trovare queste risorse è subdomain enumeration — e la differenza tra trovarne 10 e trovarne 200 sta nella qualità della pipeline.

Questa guida costruisce la pipeline completa: da zero rumore (passive) a brute force accurato, permutazioni intelligenti e validazione live. Per la teoria DNS e i tool di basso livello (dig, dnsrecon, zone transfer) vedi [DNS](https://hackita.it/articoli/dns/).

**Prerequisiti:** una wordlist per il brute force DNS (es. SecLists), [DNS](https://hackita.it/articoli/dns/) per i concetti base.

***

## Cos'è la Subdomain Enumeration?

La subdomain enumeration è il processo di identificazione dei sottodomini associati a un dominio, come `dev.example.com`, `api.example.com` o `staging.example.com`. Durante un penetration test viene usata per ampliare la superficie di attacco e individuare applicazioni, API, ambienti di sviluppo e servizi esposti che non compaiono sul sito principale. Si esegue tramite tecniche passive, active, o più spesso una combinazione delle due.

## Passive vs Active Subdomain Enumeration

| Metodo  | Contatto DNS/target               | Esempi                              |
| ------- | --------------------------------- | ----------------------------------- |
| Passive | Nessun probing diretto del target | CT logs, API, database OSINT        |
| Active  | Query/probing DNS diretto         | Brute force, risoluzione            |
| Ibrido  | Entrambi                          | Passive → brute force → validazione |

La passive enumeration raccoglie informazioni già disponibili tramite fonti pubbliche, senza toccare direttamente l'infrastruttura del target. L'active enumeration invece genera o verifica nomi direttamente via DNS — più rumore, ma trova ciò che le fonti pubbliche non hanno mai indicizzato.

***

## La Pipeline di Subdomain Enumeration

La metodologia più efficace combina passive enumeration, DNS brute force, permutation scanning e validazione HTTP.

```text
1. PASSIVE    → subfinder, amass, assetfinder, crt.sh, chaos, GAU, GitHub
2. MERGE      → sort -u, dedup, filtraggio wildcard
3. ACTIVE     → puredns/massdns brute force + risoluzione
4. PERMUTAZIONI → alterx/gotator su sottodomini trovati
5. VALIDAZIONE  → httpx, subdomain takeover check
```

Ogni fase produce output che alimenta la successiva. Non saltare la fase passiva: permette spesso di ottenere una parte significativa della superficie senza effettuare brute force DNS.

***

## Migliori Tool per la Subdomain Enumeration

| Tool                                                        | Tipo             | Velocità | Cosa fa                                               |
| ----------------------------------------------------------- | ---------------- | -------- | ----------------------------------------------------- |
| **subfinder**                                               | Passive          | ★★★★★    | Interroga decine di fonti API, CT logs, DNS databases |
| **[amass](https://hackita.it/articoli/amass/)**             | Passive + Active | ★★       | OSINT approfondito, graph topology, molte fonti       |
| **[assetfinder](https://hackita.it/articoli/assetfinder/)** | Passive          | ★★★★★    | Leggero, quick win, fonti crt.sh + certspotter        |
| **chaos**                                                   | Passive          | ★★★★★    | Dataset ProjectDiscovery, aggiornato continuamente    |
| **gau**                                                     | Passive          | ★★★★     | Wayback Machine, Common Crawl, OTX per sottodomini    |
| **puredns**                                                 | Active           | ★★★★★    | Brute force accurato con wildcard detection nativa    |
| **massdns**                                                 | Active           | ★★★★★    | DNS resolver massivo, altissimo throughput            |
| **alterx**                                                  | Permutazioni     | ★★★★     | Genera varianti di sottodomini trovati                |
| **[httpx](https://hackita.it/articoli/httpx/)**             | Validazione      | ★★★★★    | Verifica quali rispondono HTTP, status + tech         |

| Obiettivo                  | Tool consigliato                 |
| -------------------------- | -------------------------------- |
| Passive enumeration veloce | Subfinder                        |
| OSINT approfondito         | Amass                            |
| Quick enumeration          | Assetfinder                      |
| DNS brute force            | Puredns                          |
| Mass DNS resolution        | Massdns                          |
| Permutazioni               | AlterX                           |
| HTTP validation            | httpx                            |
| Takeover detection         | Tool dedicati + verifica manuale |

***

## Passive Subdomain Enumeration – Zero Contatto col Target

### Come usare Subfinder per la Subdomain Enumeration

Subfinder è un tool di ProjectDiscovery pensato principalmente per la passive subdomain enumeration. Aggrega risultati da diverse fonti e produce una lista di sottodomini da passare alle fasi successive della pipeline.

```bash
# Installa
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# File di configurazione
nano ~/.config/subfinder/provider-config.yaml
```

```yaml
# provider-config.yaml — aggiungi le API key che hai
virustotal:
  - TUA_API_KEY_VIRUSTOTAL
securitytrails:
  - TUA_API_KEY_SECURITYTRAILS
shodan:
  - TUA_API_KEY_SHODAN
censys:
  - TUA_CENSYS_API_ID:TUA_CENSYS_SECRET
bevigil:
  - TUA_BEVIGIL_KEY
chaos:
  - TUA_CHAOS_KEY
# Fonti gratuite (no key):
# crt.sh, certspotter, dnsdumpster, alienvault, hackertarget...
```

Configurare più provider può aumentare significativamente la copertura, ma il numero di risultati varia in base al dominio e alle fonti effettivamente disponibili per quel target. Vale comunque la pena configurarle — la maggior parte offrono un piano gratuito sufficiente per un pentest.

```bash
# Scan base (senza API keys)
subfinder -d target.com -o subfinder.txt

# Scan con tutte le fonti configurate
subfinder -d target.com -all -o subfinder.txt

# Solo output pulito (nessun banner)
subfinder -d target.com -all -silent -o subfinder.txt

# Rate limiting (per non fare ban da API)
subfinder -d target.com -all -rate-limit 10 -delay 3 -o subfinder.txt

# Scan su più domini da file
subfinder -dL domains.txt -all -silent -o subfinder_all.txt
```

```text
dev.target.com
api.target.com
staging.target.com
mail.target.com
vpn.target.com
admin.target.com
jenkins.target.com
grafana.target.com
```

> `-all` attiva tutte le fonti configurate, non solo quelle senza key. Su target importanti usalo sempre: la differenza nei risultati rispetto al default può essere notevole, e varia da caso a caso.

### Assetfinder – Quick e Leggero

```bash
# Installa
go install github.com/tomnomnom/assetfinder@latest

# Uso base
assetfinder --subs-only target.com > assetfinder.txt

# Include anche domini correlati (stessa organizzazione)
assetfinder target.com > assetfinder_extended.txt
```

### Chaos – Dataset ProjectDiscovery

ProjectDiscovery mantiene un dataset aggiornato continuamente di sottodomini da bug bounty e scanning pubblico.

```bash
# Installa (richiede API key gratuita da chaos.projectdiscovery.io)
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Configura API key
export CHAOS_KEY="tua_api_key"

# Ricerca sottodomini
chaos -d target.com -o chaos.txt

# Output silenzioso
chaos -d target.com -silent > chaos.txt
```

### Come trovare sottodomini dagli archivi Web con GAU

GAU (GetAllUrls) estrae URL dalla Wayback Machine, Common Crawl e OTX — spesso contiene sottodomini legacy non più pubblicizzati ma ancora live.

```bash
# Installa
go install github.com/lc/gau/v2/cmd/gau@latest

# Estrai sottodomini da archivi web
gau --subs target.com | unfurl -u domains | sort -u > gau_subs.txt

# Solo sottodomini unici
gau --threads 5 --subs target.com | grep "\.target\.com" | \
  awk -F/ '{print $3}' | sort -u > gau.txt
```

### Certificate Transparency – crt.sh

```bash
# Query diretta (senza tool)
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | \
  grep -v "@" | \
  sort -u > crtsh.txt

# Versione con retry per grandi target
curl -s --retry 3 "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | sort -u > crtsh.txt
```

### Come trovare sottodomini esposti su GitHub

Gli sviluppatori spesso riferiscono sottodomini interni in codice, config file, README. GitHub conserva tutto.

```bash
# Dork manuali su github.com (nel browser)
site:github.com "target.com" ext:env
site:github.com "target.com" inurl:config
site:github.com "staging.target.com"
site:github.com "internal.target.com"
site:github.com "target.com" "api_key"

# Con trufflehog per scan automatico di repo pubblici
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh
trufflehog github --org=targetorg --only-verified | grep target.com
```

***

## Merge e Deduplicazione

```bash
# Combina tutti i risultati passivi in un unico file
cat subfinder.txt assetfinder.txt chaos.txt crtsh.txt gau.txt | \
  sort -u | \
  grep "\.target\.com$" | \
  grep -v "^*" > passive_all.txt

echo "[+] Passive total: $(wc -l < passive_all.txt) unique subdomains"
```

***

## DNS Brute Force con Puredns e Massdns

### Cos'è il DNS Brute Force?

Il DNS brute force consiste nel testare una wordlist di possibili nomi host contro un dominio — ad esempio `dev.example.com`, `api.example.com`, `staging.example.com` — verificando quali nomi risolvono realmente via DNS. Scopre sottodomini non presenti in nessuna fonte pubblica: ambienti interni, staging, versioni API vecchie. Richiede una buona wordlist e resolver DNS affidabili.

### Setup Resolver

I resolver pubblici vengono bannati rapidamente se mandi milioni di query. Usa una lista di resolver pubblici affidabili.

```bash
# Scarica lista resolver affidabili
curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
  -o resolvers.txt
wc -l resolvers.txt
```

### Puredns

puredns gestisce wildcard DNS nativamente — non ottieni falsi positivi anche se il dominio ha `*.target.com → 1.2.3.4`.

```bash
# Installa
go install github.com/d3mondev/puredns/v2@latest

# Brute force con wordlist
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  target.com \
  -r resolvers.txt \
  -w puredns_brute.txt

# Risolvi lista esistente (passivi trovati prima)
puredns resolve passive_all.txt -r resolvers.txt -w resolved_passive.txt

# Con rate limiting (gentile con i resolver)
puredns bruteforce wordlist.txt target.com \
  -r resolvers.txt \
  --rate-limit 500 \
  -w puredns.txt
```

```text
[+] Brute forcing target.com with 5000 words
[+] Using 1024 resolvers
[+] Wildcard detected: *.target.com → 1.2.3.4 (filtered)
[+] Found: dev.target.com
[+] Found: api-v2.target.com
[+] Found: jenkins.target.com
[+] Found: 47 unique subdomains
```

### Massdns

massdns è il resolver più veloce disponibile, con un throughput molto alto. Usalo con shuffledns per brute force massivo.

```bash
# Installa
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make
sudo mv bin/massdns /usr/local/bin/

# Genera lista di target da brute force
sed "s/$/\.target\.com/" /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  > brute_targets.txt

# Risolvi massivamente
massdns -r resolvers.txt -t A -o S -w massdns_out.txt brute_targets.txt

# Estrai solo quelli che risolvono
grep -oP '[\w\.-]+\.target\.com' massdns_out.txt | sort -u > massdns_found.txt
```

### Shuffledns – Wrapper Intelligente su Massdns

```bash
# Installa
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# Brute force con wildcard filtering automatico
shuffledns -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -r resolvers.txt \
  -o shuffledns.txt

# Risolvi lista esistente
shuffledns -d target.com \
  -list passive_all.txt \
  -r resolvers.txt \
  -o resolved.txt
```

### Puredns vs Massdns: quale usare?

Puredns è generalmente più pratico quando vuoi gestire automaticamente wildcard e validazione durante il brute force — copre l'intero workflow. Massdns è principalmente un resolver DNS ad alte prestazioni e richiede più gestione manuale (preprocessing della wordlist, filtraggio wildcard a parte). Per un pentest standard: puredns. Per volumi enormi dove serve throughput massimo: massdns, eventualmente tramite shuffledns.

***

## Subdomain Permutation Scanning

### Cos'è il Subdomain Permutation Scanning?

Il permutation scanning genera varianti di sottodomini già scoperti combinando prefissi, suffissi e pattern comuni — come `dev`, `staging`, `test`, `prod` e versioni numeriche. Hai trovato `api.target.com`? Il permutation scanning prova a generare e verificare `api-v2.target.com`, `api-staging.target.com`, `api-dev.target.com` e varianti simili.

### alterx – Permutazioni con Pattern

```bash
# Installa
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

# Genera permutazioni da lista di sottodomini
cat resolved.txt | alterx -o permutations.txt

# Con pattern custom
cat resolved.txt | alterx \
  -enrich \
  -pattern "{{sub}}-dev,{{sub}}-staging,{{sub}}-test,{{sub}}-prod,{{sub}}-v2" \
  -o permutations.txt

# Risolvi le permutazioni generate
puredns resolve permutations.txt -r resolvers.txt -w resolved_perms.txt

echo "[+] New from permutations: $(wc -l < resolved_perms.txt)"
```

```text
# Input: api.target.com
# Output alterx:
api-dev.target.com
api-staging.target.com
api-test.target.com
api-v2.target.com
api-prod.target.com
dev-api.target.com
staging-api.target.com
```

### gotator – Alternativa con Wordlist

```bash
# Installa
go install github.com/Josue87/gotator@latest

# Genera permutazioni con wordlist custom
gotator -sub passive_all.txt \
  -perm /usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt \
  -depth 1 -numbers 3 -md | \
  puredns resolve -r resolvers.txt > gotator_resolved.txt
```

***

## Come verificare quali sottodomini sono realmente attivi

Un sottodominio che risolve correttamente via DNS non implica necessariamente che esponga un servizio HTTP. Per questo la pipeline passa i risultati a httpx, che verifica HTTP/HTTPS e raccoglie status code, titolo e tecnologie rilevate — in pochi secondi su migliaia di host.

```bash
# Combina tutti i trovati
cat puredns_brute.txt resolved_passive.txt resolved_perms.txt | \
  sort -u > all_subdomains.txt

# Validazione HTTP/HTTPS
cat all_subdomains.txt | httpx \
  -status-code \
  -title \
  -tech-detect \
  -follow-redirects \
  -o live_hosts.txt

echo "[+] Live hosts: $(wc -l < live_hosts.txt)"
```

```text
https://dev.target.com [200] [Development Portal] [PHP, Symfony]
https://api-v2.target.com [401] [API Gateway] [nginx]
https://jenkins.target.com [200] [Jenkins - Dashboard] [Jenkins]
https://grafana.target.com [302] [] [Grafana]
https://admin.target.com [200] [Admin Panel] [Apache, WordPress]
```

**Focus immediato su:**

* `[200]` su path `admin`, `jenkins`, `grafana`, `kibana`, `dev` → accesso senza autenticazione
* `[401]` → esiste, prova credential stuffing con credenziali di default
* `[302]` → segui il redirect

***

## Cos'è un Subdomain Takeover?

Un subdomain takeover si verifica quando un sottodominio continua a puntare via DNS (tipicamente un CNAME) verso una risorsa di terze parti che non è più controllata dall'organizzazione — un bucket S3 cancellato, un'app su Heroku o Azure dismessa. In certe condizioni questo permette di rivendicare quella risorsa e servire contenuti sotto il sottodominio originale. Un CNAME verso un servizio esterno non è di per sé una prova di takeover — è un candidato da verificare.

### Trovare i candidati con dnsx

```bash
# Con dnsx — trova CNAME
cat all_subdomains.txt | dnsx -cname -resp -silent | \
  grep -E "s3\.amazonaws\.com|heroku\.com|github\.io|azurewebsites\.net|netlify\.app|vercel\.app" \
  > potential_takeover.txt
```

### Verifica con subjack

```bash
go install github.com/haccer/subjack@latest
curl -o fingerprints.json https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json

subjack -w all_subdomains.txt \
  -t 100 \
  -timeout 30 \
  -c fingerprints.json \
  -o takeover_results.txt

cat takeover_results.txt
# [Vulnerable] cdn-old.target.com → VULNERABLE (AWS S3)
```

Tratta ogni riga marcata "Vulnerable" come un **potenziale finding da verificare manualmente**, non come conferma automatica — i fingerprint possono generare falsi positivi, specialmente se non aggiornati.

***

## Come automatizzare la Subdomain Enumeration

La pipeline completa, in sequenza, può essere incapsulata in uno script:

```text
Passive → Dedup → DNS Resolution → Brute Force → Permutation → HTTP Validation → Takeover Check
```

```bash
#!/bin/bash
# Subdomain Enumeration Pipeline
# Uso: ./subenum.sh target.com

DOMAIN=$1
OUT="./recon/$DOMAIN"
RESOLVERS="$HOME/resolvers.txt"
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

[[ -z $DOMAIN ]] && echo "Usage: $0 <domain>" && exit 1
mkdir -p $OUT/{passive,active,perms,final}

echo "[*] Target: $DOMAIN"
echo "[*] Output: $OUT"

# ── FASE 1: PASSIVE ────────────────────────────────────────
echo "[1/5] Passive enumeration..."

subfinder -d $DOMAIN -all -silent -o $OUT/passive/subfinder.txt
assetfinder --subs-only $DOMAIN > $OUT/passive/assetfinder.txt 2>/dev/null
chaos -d $DOMAIN -silent -o $OUT/passive/chaos.txt 2>/dev/null
curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | grep -v "@" | \
  sort -u > $OUT/passive/crtsh.txt
gau --subs $DOMAIN 2>/dev/null | grep "\.$DOMAIN$" | sort -u > $OUT/passive/gau.txt

cat $OUT/passive/*.txt | sort -u | grep "\.$DOMAIN$" > $OUT/passive/all.txt
echo "[+] Passive: $(wc -l < $OUT/passive/all.txt) subdomains"

# ── FASE 2: RESOLVE PASSIVE ────────────────────────────────
echo "[2/5] Resolving passive results..."
puredns resolve $OUT/passive/all.txt -r $RESOLVERS -q \
  -w $OUT/active/resolved_passive.txt

# ── FASE 3: BRUTE FORCE ────────────────────────────────────
echo "[3/5] Active brute force..."
puredns bruteforce $WORDLIST $DOMAIN -r $RESOLVERS -q \
  -w $OUT/active/brute.txt

cat $OUT/active/*.txt | sort -u > $OUT/active/all.txt
echo "[+] Active: $(wc -l < $OUT/active/all.txt) subdomains"

# ── FASE 4: PERMUTAZIONI ───────────────────────────────────
echo "[4/5] Generating permutations..."
cat $OUT/active/all.txt | alterx -silent | \
  puredns resolve -r $RESOLVERS -q -w $OUT/perms/resolved.txt 2>/dev/null
echo "[+] Permutations: $(wc -l < $OUT/perms/resolved.txt 2>/dev/null || echo 0)"

# ── FASE 5: VALIDAZIONE ────────────────────────────────────
echo "[5/5] HTTP validation..."
cat $OUT/active/all.txt $OUT/perms/resolved.txt 2>/dev/null | sort -u | \
  httpx -status-code -title -tech-detect -silent \
  -o $OUT/final/live_hosts.txt

# ── TAKEOVER CHECK ─────────────────────────────────────────
cat $OUT/active/all.txt | dnsx -cname -resp -silent | \
  grep -E "s3\.amazonaws|heroku\.com|github\.io|azurewebsites|netlify|vercel" \
  > $OUT/final/potential_takeover.txt

echo ""
echo "═══ RISULTATI ═══"
echo "Subdomains trovati: $(cat $OUT/active/all.txt $OUT/perms/resolved.txt 2>/dev/null | sort -u | wc -l)"
echo "Live HTTP hosts:    $(wc -l < $OUT/final/live_hosts.txt)"
echo "Potenziali takeover: $(wc -l < $OUT/final/potential_takeover.txt)"
echo "Output:             $OUT/final/"
```

***

## Metodologia Consigliata

```text
1. PASSIVE PRIMA (sempre, zero rumore)
   └─ subfinder -all + assetfinder + crtsh + chaos
   └─ Merge e dedup

2. RISOLVI I PASSIVI
   └─ puredns resolve (filtra wildcard, verifica A record)

3. BRUTE FORCE ATTIVO
   └─ puredns bruteforce + wordlist 5k-20k
   └─ shuffledns come alternativa

4. PERMUTAZIONI (se engagement approfondito)
   └─ alterx su tutti i risolti
   └─ puredns resolve sulle permutazioni

5. VALIDA CON HTTPX
   └─ Status code + titolo + tech-detect
   └─ Focus su: admin, jenkins, grafana, dev, staging senza auth

6. TAKEOVER CHECK
   └─ dnsx -cname + grep cloud providers
   └─ subjack per check automatico, verifica manuale dei positivi
```

***

## Troubleshooting

| Problema                          | Causa                        | Soluzione                                                               |
| --------------------------------- | ---------------------------- | ----------------------------------------------------------------------- |
| Subfinder trova pochi risultati   | Nessuna API key configurata  | Configura API keys in `~/.config/subfinder/provider-config.yaml`        |
| puredns lentissimo                | Troppi resolver inaffidabili | Aggiorna resolvers.txt: scarica lista verificata                        |
| Falsi positivi a migliaia         | Wildcard DNS                 | puredns gestisce wildcard automaticamente — usa quello, non massdns raw |
| Chaos non funziona                | API key mancante             | Registra su chaos.projectdiscovery.io (gratuito)                        |
| alterx genera troppi risultati    | Pattern troppo ampio         | Limita con `-pattern` specifici o riduci wordlist                       |
| Subdomain takeover falsi positivi | Fingerprints non aggiornati  | Aggiorna fingerprints.json di subjack, verifica sempre a mano           |

***

## FAQ

**Cos'è la subdomain enumeration?**
Il processo di trovare tutti i sottodomini associati a un dominio target, per ampliare la superficie di attacco durante un pentest.

**Qual è il miglior tool per trovare sottodomini?**
Non ce n'è uno solo: subfinder per passive enumeration veloce, amass per OSINT approfondito, puredns per brute force accurato. La combinazione è più efficace del singolo tool.

**Subfinder o Amass: quale scegliere?**
Subfinder per velocità — risultati in decine di secondi. Amass per coverage più approfondita su target critici, a costo di run più lunghe. In pratica: parti con subfinder, aggiungi amass se l'engagement lo giustifica.

**Puredns o Massdns: quale usare?**
Puredns per accuracy e gestione automatica di wildcard e validazione. Massdns per throughput puro su volumi enormi, con più gestione manuale. Per un pentest standard: puredns.

**Qual è la differenza tra passive e active enumeration?**
La passive raccoglie dati già pubblici (CT logs, API, OSINT) senza toccare il target. L'active interroga direttamente il DNS del target (brute force, risoluzione), generando traffico osservabile.

**Come trovo sottodomini non indicizzati da nessuna fonte pubblica?**
Con il DNS brute force (puredns/massdns) e con le permutazioni (alterx/gotator) sui sottodomini già trovati.

**Come verifico se un sottodominio è davvero attivo?**
Con httpx: risolvere via DNS non basta, serve verificare che esponga effettivamente un servizio HTTP/HTTPS raggiungibile.

**Cos'è un subdomain takeover?**
Quando un sottodominio punta ancora, via DNS, a una risorsa di terze parti non più controllata dall'organizzazione — rendendola in certi casi rivendicabile da un attaccante.

***

## Cheat Sheet Finale

```text
=== PASSIVE ===
subfinder:    subfinder -d target.com -all -silent -o subs.txt
assetfinder:  assetfinder --subs-only target.com > asset.txt
chaos:        chaos -d target.com -silent > chaos.txt
crt.sh:       curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
GAU:          gau --subs target.com | grep "\.target\.com$" | sort -u
Merge:        cat *.txt | sort -u | grep "\.target\.com$" > all_passive.txt

=== ACTIVE BRUTE FORCE ===
puredns:      puredns bruteforce wordlist.txt target.com -r resolvers.txt -w out.txt
shuffledns:   shuffledns -d target.com -w wordlist.txt -r resolvers.txt -o out.txt
Resolvers:    curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o resolvers.txt

=== RISOLUZIONE ===
puredns:      puredns resolve passive.txt -r resolvers.txt -w resolved.txt
dnsx:         dnsx -l passive.txt -resp -o dnsx.txt

=== PERMUTAZIONI ===
alterx:       cat resolved.txt | alterx | puredns resolve -r resolvers.txt > perms.txt
gotator:      gotator -sub resolved.txt -perm prefixes.txt -depth 1 | puredns resolve -r resolvers.txt

=== VALIDAZIONE ===
httpx:        cat all.txt | httpx -status-code -title -tech-detect -o live.txt
Filter 200:   cat all.txt | httpx -mc 200 -silent

=== TAKEOVER ===
dnsx cname:   cat all.txt | dnsx -cname -resp | grep -E "s3|heroku|github\.io|azure|netlify|vercel"
subjack:      subjack -w all.txt -c fingerprints.json -o takeover.txt

=== API KEYS (subfinder) ===
Config:       ~/.config/subfinder/provider-config.yaml
Fonti key:    securitytrails, shodan, virustotal, censys, bevigil, chaos
```

***

**Guide correlate su hackita.it:**

* [DNS Enumeration: Zone Transfer, dnsrecon e Brute Force DNS](https://hackita.it/articoli/dns-enumeration/)
* [Wordlist e SecLists: Quale Lista DNS Usare](https://hackita.it/articoli/wordlist/)
* [Reconnaissance: OSINT e Raccolta Informazioni](https://hackita.it/articoli/reconnaissance/)
* [Linux Enumeration](https://hackita.it/articoli/linux-enumeration/)

## Riferimenti

* [ProjectDiscovery Tools – subfinder, dnsx, httpx, alterx](https://projectdiscovery.io/tools)
* [puredns – GitHub d3mondev](https://github.com/d3mondev/puredns)
