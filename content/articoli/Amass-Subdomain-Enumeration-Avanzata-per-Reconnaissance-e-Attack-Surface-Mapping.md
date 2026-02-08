---
title: 'Amass: Subdomain Enumeration Avanzata per Reconnaissance e Attack Surface Mapping'
slug: amass
description: 'Amass è uno strumento OSINT e active reconnaissance per enumerare subdomain, mappare asset esterni e analizzare relazioni DNS. Guida pratica all’uso in fase di attack surface discovery durante un penetration test.'
image: /Gemini_Generated_Image_4wvv9n4wvv9n4wvv.webp
draft: true
date: 2026-02-10T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - osint
---

OWASP Amass è il tool di subdomain enumeration più completo disponibile. Mentre strumenti come Subfinder interrogano API pubbliche, Amass combina DNS bruteforce, certificate transparency, web scraping, WHOIS e decine di data source per costruire una mappa completa degli asset di un dominio. Il risultato è una superficie d'attacco che altri tool non avrebbero mai trovato.

Amass opera in tre modalità: `enum` per enumerazione, `intel` per discovery di organizzazioni e ASN, `db` per gestione database locale dei risultati. La modalità `enum` è quella che usi nel 90% dei casi, con opzione passiva (solo API) o attiva (DNS bruteforce + zone transfer + alterazioni).

Kill chain: **Reconnaissance** (MITRE ATT\&CK T1590). L'articolo copre configurazione API, enumerazione attiva vs passiva, integrazione con altri tool di recon e gestione dei risultati.

***

## 1️⃣ Setup e Installazione

```bash
go install -v github.com/owasp-amass/amass/v4/...@master
```

Alternativa:

```bash
sudo apt install amass
```

**Verifica:**

```bash
amass -version
```

Output: `OWASP Amass v4.2.0`

**Configurazione API (fondamentale per risultati completi):**

Crea `~/.config/amass/config.yaml`:

```yaml
scope:
  domains:
    - target.com
datasources:
  - name: Shodan
    creds:
      account:
        apikey: YOUR_SHODAN_KEY
  - name: VirusTotal
    creds:
      account:
        apikey: YOUR_VT_KEY
  - name: SecurityTrails
    creds:
      account:
        apikey: YOUR_ST_KEY
```

Senza API key, Amass usa solo fonti gratuite e DNS. Con le key, la coverage aumenta del 200-300%.

***

## 2️⃣ Uso Base

**Enumerazione passiva:**

```bash
amass enum -passive -d target.com
```

Output:

```
mail.target.com
vpn.target.com
dev.target.com
staging.target.com
api.target.com
internal.target.com
jenkins.target.com
```

**Enumerazione attiva (con DNS bruteforce):**

```bash
amass enum -active -d target.com -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

L'opzione `-brute` aggiunge DNS bruteforce alle fonti passive. `-w` specifica la wordlist.

**Intel mode — Scoprire tutti i domini di un'organizzazione:**

```bash
amass intel -org "Target Corporation"
```

Restituisce ASN, range IP e domini associati all'organizzazione.

***

## 3️⃣ Tecniche Operative

### Enumerazione con output strutturato

```bash
amass enum -d target.com -o subs.txt -json results.json
```

Il JSON contiene dettagli per ogni subdomain: IP, fonte di discovery, record DNS.

### DNS zone transfer check

```bash
amass enum -active -d target.com
```

La modalità attiva tenta zone transfer automaticamente. Se il DNS è misconfigured, ottieni l'intera zona DNS.

### ASN discovery e IP range mapping

```bash
amass intel -asn 12345
```

Trova tutti i domini hostati nell'ASN specificato. Utile per mappare l'intera infrastruttura di un'organizzazione.

### Esclusione subdomain noti

```bash
amass enum -d target.com -bl known_subs.txt
```

Esclude subdomain già noti per concentrarsi su nuove scoperte.

***

## 4️⃣ Tecniche Avanzate

### Combinazione con Subfinder per maximum coverage

```bash
amass enum -passive -d target.com -o amass_results.txt
subfinder -d target.com -silent -o subfinder_results.txt
cat amass_results.txt subfinder_results.txt | sort -u > all_subs.txt
```

Amass e [Subfinder](https://hackita.it/articoli/subfinder) usano fonti parzialmente diverse. La combinazione massimizza la coverage.

### Alterations per trovare varianti

```bash
amass enum -d target.com -active -alts
```

L'opzione `-alts` genera varianti dei subdomain trovati (es. da `dev.target.com` prova `dev1`, `dev2`, `dev-staging`, etc.).

### Tracking nel tempo

```bash
amass track -d target.com
```

Confronta i risultati attuali con quelli precedenti nel database locale, mostrando nuovi subdomain e quelli rimossi.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Mappatura perimetrale completa

```bash
amass enum -active -d corp.com -brute -alts -o full_enum.txt
```

**Output atteso:** 200-500+ subdomain con DNS bruteforce e alterazioni.

**Cosa fare se fallisce:**

* Pochi risultati → Configura API key nel `config.yaml`.
* DNS bruteforce bloccato → Il DNS resolver limita le query. Usa resolver custom: `-r 8.8.8.8,1.1.1.1`.

**Timeline:** Passiva: 2-5 minuti. Attiva con brute: 15-30 minuti.

### Scenario 2: Scoprire shadow IT

```bash
amass intel -org "Target Corp" -whois -d target.com
```

**Trova domini non ufficiali registrati dall'organizzazione — shadow IT.**

**Timeline:** 5-10 minuti.

### Scenario 3: Monitoring continuo

```bash
amass enum -passive -d target.com
amass track -d target.com
```

**Confronta risultati per trovare nuovi asset esposti.**

**Timeline:** Setup 5 minuti, poi automatizzabile.

***

## 6️⃣ Toolchain Integration

**Flusso:**

**Amass (subdomain enum)** → [Httpx](https://hackita.it/articoli/httpx) (probe) → [Aquatone](https://hackita.it/articoli/aquatone) (visual recon) → [Nuclei](https://hackita.it/articoli/nuclei) (vuln scan)

| Tool        | Fonti | Bruteforce | Alterations | API support | Velocità |
| ----------- | ----- | ---------- | ----------- | ----------- | -------- |
| Amass       | 50+   | Sì         | Sì          | 30+ API     | ★★★☆☆    |
| Subfinder   | 30+   | No         | No          | 20+ API     | ★★★★★    |
| Assetfinder | 5+    | No         | No          | Limitato    | ★★★★★    |
| Sublist3r   | 10+   | No         | No          | Limitato    | ★★★☆☆    |

***

## 7️⃣ Attack Chain Completa

**Fase 1 — Asset Discovery (15 min):** Amass enum attivo → 450 subdomain.

**Fase 2 — HTTP probe (1 min):** Httpx filtra 200 live.

**Fase 3 — Visual recon (5 min):** Aquatone screenshot. Trovi `old-admin.corp.com` con pannello senza 2FA.

**Fase 4 — Exploitation (10 min):** Credential stuffing con credenziali leaked. Accesso admin.

**Fase 5 — Post-exploitation (30 min):** API admin → RCE → lateral movement.

**Timeline:** \~61 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* Burst di query DNS (modalità attiva/brute)
* Query verso record TXT/AXFR anomali

### Tecniche di evasion

1. **Solo passivo:** `-passive` non genera traffico verso il target.
2. **Resolver custom:** usa resolver pubblici per non colpire il DNS aziendale.
3. **Rate limiting:** `-max-dns-queries 100` limita le query/sec.

***

## 9️⃣ Performance & Scaling

**Passivo:** 2-5 minuti per dominio. **Attivo con brute (5K wordlist):** 15-30 minuti. **Con alterations:** 30-60 minuti.

**Consumo:** 100-500MB RAM a seconda delle fonti e del bruteforce.

***

## 🔟 Tabelle Tecniche

| Flag                | Descrizione                  |
| ------------------- | ---------------------------- |
| `enum -passive`     | Solo fonti passive           |
| `enum -active`      | Passive + DNS active         |
| `-brute`            | DNS bruteforce               |
| `-alts`             | Generazione alterazioni      |
| `-d domain`         | Dominio target               |
| `-w wordlist`       | Wordlist per brute           |
| `-o file`           | Output file                  |
| `-json file`        | Output JSON                  |
| `-r resolvers`      | DNS resolver custom          |
| `intel -org "name"` | Discovery per organizzazione |
| `track -d domain`   | Tracking cambiamenti         |

***

## 11️⃣ Troubleshooting

| Problema               | Causa             | Fix                              |
| ---------------------- | ----------------- | -------------------------------- |
| Pochi risultati        | API key mancanti  | Configura `config.yaml`          |
| DNS brute lento        | Resolver lento    | Usa `-r 8.8.8.8,1.1.1.1`         |
| Crash su domini grandi | RAM insufficiente | Aumenta memoria o usa `-passive` |
| Errori API             | Rate limiting     | Aggiungi delay nelle config      |

***

## 12️⃣ FAQ

**Amass vs Subfinder?**
Amass è più completo (bruteforce, alterations, intel). Subfinder è più veloce per enumerazione passiva pura. Usali entrambi.

**Serve un database locale?**
Amass salva i risultati automaticamente in un graph database. Utile per tracking nel tempo.

**Amass rileva wildcard DNS?**
Sì, automaticamente nella modalità attiva.

**Quante API key servono?**
Più ne configuri, meglio è. Minimo: Shodan, VirusTotal, SecurityTrails.

***

## 13️⃣ Cheat Sheet

| Azione          | Comando                                                    |
| --------------- | ---------------------------------------------------------- |
| Enum passivo    | `amass enum -passive -d domain.com`                        |
| Enum attivo     | `amass enum -active -d domain.com -brute`                  |
| Con alterations | `amass enum -active -d domain -brute -alts`                |
| Intel org       | `amass intel -org "Company Name"`                          |
| Intel ASN       | `amass intel -asn 12345`                                   |
| Tracking        | `amass track -d domain.com`                                |
| Output JSON     | `amass enum -d domain -json results.json`                  |
| Pipeline        | `amass enum -passive -d domain \| httpx -silent \| nuclei` |

***

**Disclaimer:** OWASP Amass è un progetto open source per security assessment. L'enumerazione attiva genera traffico DNS verso i nameserver del target. Usa con autorizzazione. Repository: [github.com/owasp-amass/amass](https://github.com/owasp-amass/amass).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
