---
title: 'TheHarvester: SEGRETI per OSINT, Email & Sottodomini (2026)'
slug: theharvester
description: 'Scopri come usare TheHarvester per raccogliere email e sottodomini: installazione, recon, sorgenti OSINT, API key, output JSON/XML e troubleshooting verificato.'
image: /theharvester-osint-email-sottodomini.webp
draft: false
date: 2026-02-08T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - theHarvester
  - OSINT
  - Email Harvesting
  - Subdomain Enumeration
  - Reconnaissance
---

# TheHarvester: come raccogliere email e sottodomini in un test autorizzato

TheHarvester è uno strumento da riga di comando che interroga fonti OSINT pubbliche (certificate transparency, motori di ricerca, archivi DNS, servizi di threat intelligence) per raccogliere **sottodomini, host, IP ed email** legati a un dominio. È uno dei primi comandi che si lanciano nella fase di reconnaissance, perché non richiede configurazione e restituisce una prima mappa dell'esposizione pubblica in pochi minuti.

> **Risposta rapida:** TheHarvester è uno strumento OSINT in Python che, dato un dominio, interroga decine di sorgenti pubbliche e restituisce sottodomini, IP ed email. In un pentest serve a costruire la superficie d'attacco iniziale prima di scansioni attive come [Nmap](/articoli/nmap/). Non verifica che un'email esista e non dimostra che un host sia in scope: raccoglie, non valida.

## Cos'è TheHarvester e cosa non fa

TheHarvester nasce come raccoglitore di email e sottodomini e nel tempo è diventato un aggregatore: ogni sorgente è un modulo che restituisce un tipo di dato diverso. Il tool unisce i risultati, li deduplica e può salvarli in file.

| Cosa fa                                                     | Cosa NON fa                                                     |
| ----------------------------------------------------------- | --------------------------------------------------------------- |
| Raccoglie sottodomini e host da sorgenti pubbliche          | Non scansiona le porte (per quello c'è [Nmap](/articoli/nmap/)) |
| Raccoglie email che compaiono in fonti indicizzate          | Non verifica che la casella esista                              |
| Può risolvere i nomi in IP e provare un DNS brute force     | Non garantisce completezza: trova ciò che le fonti conoscono    |
| Salva in XML e JSON                                         | Non produce HTML (vecchie guide dicono il contrario)            |
| Può fare screenshot e controllo takeover (attività dirette) | Non decide cosa è in scope: lo decide il contratto del test     |

Un punto da fissare subito: **un risultato di TheHarvester è un'ipotesi, non una prova**. Un sottodominio può essere dismesso, un'email può essere vecchia, un host può appartenere a un terzo. Prima di toccarlo con tool attivi va confrontato con il perimetro autorizzato.

## Passivo o attivo? Dipende dall'opzione

La domanda "TheHarvester è passivo?" non ha una risposta unica. Cambia a seconda di cosa lanci.

| Attività                                       | Chi contatta                              | Chi può vederla                                                               |
| ---------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------- |
| `-b crtsh`, `-b otx`, `-b urlscan`… (sorgenti) | Il provider della sorgente                | Il provider (il tuo IP e, se usata, la tua API key). Il target non vede nulla |
| `-b` con chiave (Shodan, Hunter…)              | Il provider                               | L'account associato alla chiave conserva lo storico                           |
| `-r` risoluzione DNS                           | I resolver DNS                            | Chi gestisce i resolver; i nameserver del target possono vedere le query      |
| `-c` DNS brute force                           | I resolver, poi i nameserver autoritativi | Il target può vedere un picco di query per nomi inesistenti                   |
| `-t` controllo takeover                        | I sottodomini trovati (HTTP/DNS)          | Il target                                                                     |
| `--screenshot DIR`                             | I sottodomini trovati, con un browser     | Il target (log web)                                                           |
| `-a` scansione endpoint API                    | Il target                                 | Il target                                                                     |

Regola pratica: finché usi solo `-b`, il target non riceve traffico da te. Nel momento in cui aggiungi risoluzione, brute force, takeover, screenshot o api-scan, stai facendo reconnaissance **attiva**, e deve essere dentro l'autorizzazione scritta. Per il quadro generale della fase iniziale vedi [reconnaissance](/articoli/reconnaissance/).

## Come ho verificato questa guida

Questa guida è costruita sul codice della release **4.11.1** (3 giugno 2026), installata e controllata riga per riga: opzioni, sorgenti, formato dei file di output e configurazione delle API key. Molte guide in giro (e anche la nostra versione precedente di questo articolo) descrivono comandi di versioni vecchie che oggi non funzionano più: qui trovi solo ciò che ho verificato.

**Nota di metodo.** Riferimento: tag `4.11.1` del repository ufficiale ([github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)), controllato il 13 ottobre 2026. Sul ramo di sviluppo esiste già una 5.0.0 non rilasciata (richiede Python 3.14, cambia nomi di opzioni e output): se la installi dal ramo `dev` i comandi di questa guida possono differire. Usa sempre `theHarvester -h` per confrontare.

## Installazione e verifica

TheHarvester 4.11.1 richiede **Python 3.12 o superiore**.

**Kali Linux** ([Kali Linux](/articoli/kali-linux/)) include il pacchetto:

```bash
sudo apt update && sudo apt install theharvester
theHarvester -h
```

La versione che ottieni da `apt` dipende dal repository di Kali e può essere più vecchia dell'ultima release: controlla il banner che compare a ogni avvio (`theHarvester 4.11.1` nel mio test).

**Da sorgente**, come indicato nel README del repository:

```bash
git clone https://github.com/laramies/theHarvester
cd theHarvester
git checkout 4.11.1        # stable tag; without checkout you get the dev branch
uv sync
uv run theHarvester -h
```

Se non usi `uv`, funziona anche un virtualenv classico:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e .
theHarvester -h
```

Due note su cosa **non** ho verificato: l'installazione nativa su Windows e su macOS. Se lavori da Windows, usa una VM o WSL con Kali; per qualsiasi altra strada fai riferimento al README ufficiale.

Alla prima esecuzione il tool crea `~/.theHarvester/proxies.yaml`. Il file con le API key invece non viene creato da solo: lo vediamo più avanti.

## Sintassi e opzioni (4.11.1)

La forma base è:

```bash
theHarvester -d <dominio> -b <sorgenti> [opzioni]
```

Queste sono le opzioni presenti nell'help della 4.11.1:

| Opzione             | Significato                                                          |
| ------------------- | -------------------------------------------------------------------- |
| `-d, --domain`      | Dominio (o nome azienda) da cercare. Obbligatorio                    |
| `-b, --source`      | Sorgenti separate da virgola, oppure `all`                           |
| `-l, --limit`       | Limite di risultati per sorgente (default 500)                       |
| `-S, --start`       | Parte dal risultato numero X (default 0)                             |
| `-f, --filename`    | Salva `NOME.xml` e `NOME.json`                                       |
| `-r, --dns-resolve` | Risolve i sottodomini in IP, con resolver in lista o passati a mano  |
| `-n, --dns-lookup`  | Abilita il lookup DNS                                                |
| `-c, --dns-brute`   | DNS brute force sul dominio                                          |
| `-t, --take-over`   | Controlla possibili takeover                                         |
| `-s, --shodan`      | Interroga Shodan per gli host scoperti (serve chiave)                |
| `--screenshot DIR`  | Screenshot degli host risolti nella cartella indicata                |
| `-a, --api-scan`    | Cerca endpoint API                                                   |
| `-w, --wordlist`    | Wordlist per `--api-scan` (non per il DNS)                           |
| `-p, --proxies`     | Usa i proxy definiti in `proxies.yaml`                               |
| `-e, --dns-server`  | Presente nell'help, ma nel codice 4.11.1 l'argomento non viene usato |
| `-q, --quiet`       | Sopprime gli avvisi sulle API key mancanti                           |

Tre cose che le guide vecchie sbagliano e che conviene sapere:

1. **`-w` non è la wordlist del DNS brute force.** Serve solo con `-a` per gli endpoint API. Il brute force `-c` usa una lista interna (`dns-names.txt`, circa 5.000 nomi) e non offre un'opzione per sostituirla.
2. **`--virtual-host` non esiste** nella 4.11.1. Per cercare virtual host usa tool dedicati come [ffuf](/articoli/ffuf/) o [Gobuster](/articoli/gobuster/).
3. **`--dns-server` non esiste** e `-e` non fa nulla di utile in questa versione. Per scegliere i resolver si usa `-r` (vedi più avanti).

## Le sorgenti: cosa puoi passare a `-b`

L'elenco ufficiale della 4.11.1 (copiato dall'help, in ordine alfabetico):

```
baidu, bevigil, bitbucket, brave, bufferoverun, builtwith, censys,
certspotter, chaos, commoncrawl, criminalip, crtsh, dehashed, dnsdumpster,
duckduckgo, dymo, fofa, fullhunt, github-code, gitlab, hackertarget,
haveibeenpwned, hudsonrock, hunter, hunterhow, intelx, leakix, leaklookup,
mojeek, netlas, onyphe, otx, pentesttools, projectdiscovery, rapiddns,
robtex, rocketreach, securityscorecard, securityTrails, sherlockeye, shodan,
shodanInternetDB, subdomaincenter, subdomainfinderc99, thc, threatcrowd,
tomba, urlscan, venacus, virustotal, waybackarchive, whoisxml, windvane,
yahoo, zoomeye
```

Se stai seguendo un tutorial che usa `-b google`, `-b bing`, `-b linkedin`, `-b pgp`, `-b twitter` o `-b sublist3r`: **quei nomi non sono più nell'elenco**. Non è un errore tuo, il tool è cambiato.

Dal codice della 4.11.1, queste sorgenti **non leggono nessuna API key** e puoi usarle subito: `crtsh`, `certspotter`, `otx`, `rapiddns`, `robtex`, `threatcrowd`, `thc`, `urlscan`, `waybackarchive`, `commoncrawl`, `subdomaincenter`, `subdomainfinderc99`, `hudsonrock`, `gitlab`, `baidu`, `yahoo`, `shodanInternetDB`. Il provider può comunque applicare limiti o bloccare le richieste, perché "senza chiave" non significa "sempre disponibile".

Sorgenti come `shodan`, `hunter`, `securityTrails`, `virustotal`, `censys`, `github-code`, `intelx`, `zoomeye` o `fullhunt` danno risultati solo con una chiave configurata.

`-b all` seleziona tutte le sorgenti supportate. Le sorgenti per cui manca la chiave non producono risultati (e il tool avvisa, a meno che tu non usi `-q`): `all` non vuol dire "tutto ciò che il target espone", vuol dire "tutte le sorgenti che riesco a interrogare con le credenziali che ho".

### Esempio minimo

```bash
theHarvester -d example.org -b crtsh,otx,rapiddns -l 200
```

Quello che conta nell'output è la struttura: il banner con la versione, la riga `Target:`, una riga `Searching ...` per ogni sorgente e infine le sezioni IP, email e host. Se una sezione è vuota il tool lo dice (`No hosts found.`). Un risultato vuoto può voler dire che il dominio non ha tracce pubbliche, ma anche che la sorgente era irraggiungibile o limitata: non sono la stessa cosa.

## Configurare le API key

TheHarvester cerca il file `api-keys.yaml` in questo ordine: `~/.theHarvester/`, `/etc/theHarvester/`, `/usr/local/etc/theHarvester/`. Il template è incluso nel pacchetto (`theHarvester/data/api-keys.yaml`): copialo nella tua home e compila solo ciò che usi.

```bash
mkdir -p ~/.theHarvester
cp theHarvester/data/api-keys.yaml ~/.theHarvester/api-keys.yaml
chmod 600 ~/.theHarvester/api-keys.yaml
```

```yaml
apikeys:
  shodan:
    key: YOUR_KEY
  hunter:
    key: YOUR_KEY
  securityTrails:
    key: YOUR_KEY
  virustotal:
    key: YOUR_KEY
  github:
    key: YOUR_TOKEN
  censys:
    id: YOUR_ID
    secret: YOUR_SECRET
```

Attenzione ai nomi dei campi: sono quelli del template, e alcuni hanno le maiuscole (`securityTrails`, `pentestTools`, `projectDiscovery`). `censys` usa `id` e `secret`, `fofa` usa `key` ed `email`, `tomba` usa `key` e `secret`. Se sbagli il nome, la sorgente risulta come "senza chiave".

Buone pratiche: una chiave dedicata per ogni engagement, permessi `600` sul file, chiave revocata a fine incarico. Non ho riportato prezzi e quote dei provider: cambiano spesso, controllali sul sito di ciascun servizio prima di pianificare.

## Salvare e leggere i risultati

Con `-f NOME` TheHarvester scrive **due** file: `NOME.xml` e `NOME.json`. Niente HTML.

```bash
theHarvester -d example.org -b crtsh,otx,rapiddns -l 200 -f scan_example
ls scan_example.*
# scan_example.json  scan_example.xml
```

**Trappola del punto.** Il tool toglie l'ultima estensione dal nome che gli passi. Se scrivi `-f example.org`, ottieni `example.json` ed `example.xml`, perché `.org` viene trattato come estensione. Usa nomi senza punti (`scan_example`, `client01`).

### Struttura del JSON

Il JSON contiene sempre `cmd` (la riga di comando usata) e `shodan`, più `hosts`. Le altre chiavi compaiono **solo se hanno contenuto**: `emails`, `ips`, `vhosts`, `interesting_urls`, `asns`, `people`, `takeover_results` e poche altre. Gli host possono essere nel formato `host` oppure `host:ip`, a seconda di come sono stati ottenuti.

Esempio di struttura (dati inventati su dominio e IP riservati per documentazione, costruiti seguendo il codice):

```json
{
  "cmd": "-d example.org -b crtsh,otx -f scan",
  "emails": ["admin@example.org", "m.rossi@example.org", "info@example.org"],
  "hosts": ["www.example.org", "vpn.example.org:203.0.113.10", "dev.example.org:203.0.113.11"],
  "ips": ["203.0.113.10", "203.0.113.11"],
  "shodan": []
}
```

Estrazioni rapide con `jq`, testate sul file qui sopra:

```bash
# hostnames only, no IPs, deduplicated
jq -r '.hosts[] | split(":")[0]' scan.json | sort -u

# emails only
jq -r '.emails[]' scan.json | sort -u

# hosts with IP as CSV (resolved ones only)
jq -r '.hosts[] | select(contains(":")) | split(":") | "\(.[0]),\(.[1])"' scan.json
```

Dato che `emails` può non esistere, se un parser deve funzionare sempre usa `.emails[]?` in `jq` o `.get("emails", [])` in Python.

## Workflow 1: sottodomini passivi

Obiettivo: ottenere una lista di sottodomini candidati senza toccare il target.

```bash
theHarvester -d example.org -b crtsh,certspotter,otx,rapiddns,urlscan,waybackarchive -l 500 -f subs_example
jq -r '.hosts[] | split(":")[0]' subs_example.json | sort -u > candidate_subs.txt
wc -l candidate_subs.txt
```

I risultati vanno **normalizzati**: i sottodomini wildcard (`*.example.org`), i nomi in maiuscolo e i duplicati sono frequenti nei dati di certificate transparency. Un passaggio utile è unire il risultato con quello di altri tool (vedi [Subfinder](/articoli/subfinder/) e [Amass](/articoli/amass/)) e poi verificare quali nomi rispondono davvero con [httpx](/articoli/httpx/):

```bash
cat candidate_subs.txt subs_amass.txt | tr 'A-Z' 'a-z' | sort -u > merged_subs.txt
httpx -l merged_subs.txt -title -status-code -o alive.txt
```

**Solo a questo punto**, e solo sugli host confermati in scope, ha senso passare a scansioni attive. Per l'approccio generale sulla ricerca di sottodomini vedi [subdomain enumeration](/articoli/subdomain-enumeration/); per il DNS di base vedi [DNS](/articoli/dns/).

## Workflow 2: email e persone

Le email compaiono nei risultati quando una sorgente le ha indicizzate (repository pubblici, breach database, servizi di intelligence). Le sorgenti più utili richiedono chiavi (`hunter`, `github-code`, `haveibeenpwned`, `intelx`).

```bash
theHarvester -d example.org -b hunter,github-code,hudsonrock -l 300 -f mail_example
jq -r '.emails[]?' mail_example.json | tr 'A-Z' 'a-z' | sort -u > emails_raw.txt
```

Poi si separano gli indirizzi **generici** (`info@`, `support@`, `admin@`) da quelli **nominali**, e si prova a dedurre il formato aziendale. Ecco uno script che fa solo questo, senza validare nulla (testato su un JSON di esempio):

```python
#!/usr/bin/env python3
import json, re, sys
from collections import Counter

GENERIC = {"info", "support", "admin", "contact", "sales", "noreply", "no-reply", "postmaster", "abuse"}

def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def split_host(entry):
    host, _, ip = entry.partition(":")
    return host.lower(), ip

def guess_pattern(local):
    if re.fullmatch(r"[a-z]\.[a-z]+", local):
        return "f.last"
    if re.fullmatch(r"[a-z]{2,}\.[a-z]{2,}", local):
        return "first.last"
    if re.fullmatch(r"[a-z]\.?[a-z]{2,}", local):
        return "flast"
    if re.fullmatch(r"[a-z]+_[a-z]+", local):
        return "first_last"
    return "other"

def main(path):
    data = load(path)
    emails = sorted({e.lower() for e in data.get("emails", [])})
    hosts = sorted({split_host(h) for h in data.get("hosts", [])})
    nominal = [e for e in emails if e.split("@")[0] not in GENERIC]
    print(f"total emails: {len(emails)} | named: {len(nominal)}")
    print(f"hosts: {len(hosts)} | with IP: {sum(1 for _, ip in hosts if ip)}")
    patterns = Counter(guess_pattern(e.split("@")[0]) for e in nominal)
    for p, n in patterns.most_common():
        print(f"pattern {p}: {n}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: parse_harvest.py file.json")
    main(sys.argv[1])
```

Nota: l'ordine dei controlli conta. Se metti `first.last` prima di `f.last`, un indirizzo come `m.rossi` viene classificato nel pattern sbagliato (è un errore comune in script di questo tipo).

### Raccogliere non è validare

Questo è il punto che più spesso viene confuso nei report:

| Livello                            | Cosa sai                             | Cosa NON sai                                              |
| ---------------------------------- | ------------------------------------ | --------------------------------------------------------- |
| **Trovata** da una sorgente        | L'indirizzo è comparso pubblicamente | Se è ancora attivo                                        |
| **Sintassi corretta** (regex)      | Ha un formato valido                 | Se la casella esiste                                      |
| **Dedotta** dal pattern aziendale  | È plausibile                         | Se esiste davvero                                         |
| **Verificata** (es. risposta SMTP) | Il server ha accettato o rifiutato   | Quasi mai affidabile: molti server rispondono sempre "ok" |

La verifica SMTP (`VRFY`, `RCPT TO`) è spesso disabilitata o neutralizzata; trovi i dettagli in [porta 25 SMTP](/articoli/porta-25-smtp/). Nel report scrivi sempre quale livello hai raggiunto. Gli elenchi di email e nomi sono dati personali: raccoglili solo se il contratto lo prevede (per esempio per un test di [social engineering](/articoli/social-engineering/) o [phishing](/articoli/phishing/) autorizzato) e conservali con le tutele del caso.

## Workflow 3: risoluzione DNS, brute force, takeover, screenshot

Queste sono le opzioni **attive**. Usale solo con autorizzazione scritta.

**Risoluzione (`-r`).** Prende i sottodomini trovati e li risolve in IP:

```bash
theHarvester -d example.org -b crtsh,otx -r -f resolved_example
```

Se la risoluzione non funziona o è lenta, prova a passare tu i resolver (l'opzione accetta una lista); nel codice 4.11.1 esiste anche un file interno `resolvers.txt` con resolver pubblici di default.

**DNS brute force (`-c`).** Prova nomi da una lista interna di circa 5.000 voci:

```bash
theHarvester -d example.org -c -f brute_example
```

Due avvertenze. Primo: non puoi cambiare la lista, quindi per un brute force serio con wordlist tue (vedi [wordlist](/articoli/wordlist/)) usa tool pensati per questo. Secondo: se il dominio ha un **DNS wildcard**, ogni nome inesistente risponde con un IP e il brute force produce falsi positivi in massa. Controllalo prima:

```bash
dig +short this-name-does-not-exist-91827.example.org
```

Se risponde con un IP, il wildcard è attivo e un host trovato col brute force va confermato in un altro modo (per esempio confrontando la risposta con quella del nome inventato).

**Takeover (`-t`).** Segnala sottodomini che puntano a servizi non più attivi. Il risultato è un indizio da verificare a mano: vedi [subdomain takeover](/articoli/subdomain-takeover/).

**Screenshot (`--screenshot DIR`).** Richiede Playwright con Chromium installato (il pacchetto dipende da `playwright`; se manca il browser, installalo con `playwright install chromium`):

```bash
theHarvester -d example.org -b crtsh -r --screenshot ./shots
```

Ogni host raggiunto riceve una richiesta diretta dal browser: è traffico verso il target.

**Shodan (`-s`).** Con chiave configurata, interroga Shodan sugli host scoperti. Per usare Shodan in modo più mirato leggi [Shodan](/articoli/shodan/).

**API scan (`-a -w list.txt`).** Controlla percorsi API comuni sugli host. È un'attività diretta, con richieste verso il target.

## Pipeline: un solo script affidabile

Un solo script, ripulito: input da file con controllo di righe vuote e commenti, variabili tra virgolette, pausa tra i domini, output con nomi coerenti.

```bash
#!/usr/bin/env bash
# batch_harvest.sh - usage: ./batch_harvest.sh domains.txt
set -euo pipefail

DOMAINS_FILE="${1:?usage: $0 domains.txt}"
OUT_DIR="./harvest_$(date +%Y%m%d)"
SOURCES="crtsh,certspotter,otx,rapiddns,urlscan,waybackarchive"
mkdir -p "$OUT_DIR"

while IFS= read -r domain; do
    # skip empty lines and comments
    [[ -z "$domain" || "$domain" == \#* ]] && continue

    base="$OUT_DIR/${domain//./_}"   # no dots in the file name
    echo "[*] $domain"
    theHarvester -d "$domain" -b "$SOURCES" -l 500 -f "$base" || echo "[!] error on $domain"

    if [[ -f "$base.json" ]]; then
        jq -r '.hosts[]? | split(":")[0]' "$base.json" | sort -u > "$base.subs.txt"
        jq -r '.emails[]?' "$base.json" | sort -u > "$base.emails.txt"
    fi
    sleep 5
done < "$DOMAINS_FILE"

echo "[+] done: $OUT_DIR"
```

`domains.txt` contiene un dominio per riga, e **solo domini del perimetro autorizzato**. Il nome del file di output sostituisce i punti con underscore proprio per evitare la trappola dell'estensione vista prima.

Per confrontare due esecuzioni nel tempo (nuovi sottodomini comparsi) basta `comm`:

```bash
comm -13 <(sort old.txt) <(sort new.txt) > nuovi_sottodomains.txt
```

Per costruire pipeline più grandi (TheHarvester → Amass → httpx → scansione) vedi [OSINT pipeline building](/articoli/osint-pipeline-building/).

## Cosa cambia nel ramo 5.0.0 (non ancora rilasciato)

Il ramo di sviluppo del repository (versione `5.0.0`, controllato il 13 ottobre 2026) sta ridisegnando parecchie cose. Non è una release, quindi **non usarlo come riferimento per un incarico** senza controllare il suo help, ma conviene sapere cosa arriva perché alcuni comandi di questa guida cambieranno:

| Novità nel ramo dev                                                                                       | Differenza rispetto alla 4.11.1            |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| Python **3.14** come minimo                                                                               | La 4.11.1 gira con 3.12+                   |
| `-b` accetta anche categorie (`subdomains`, `emails`, `ips`, `asns`, `urls`, `people`, `breaches`, `all`) | Nella 4.11.1 solo nomi di sorgente e `all` |
| `--vhost`, `--vhost-endpoint`, `--vhost-candidate` per i virtual host                                     | Nella 4.11.1 non esistono                  |
| `--dns-resolvers`, `--dns-recursive-depth` e altri limiti DNS                                             | Nella 4.11.1 solo `-r`, `-n`, `-c`         |
| `-j` per il numero di sorgenti in parallelo, `--no-hosts`                                                 | Assenti nella 4.11.1                       |
| `-f NOME` scrive `NOME.json`, `NOME.xml` e `NOME.jsonl`                                                   | La 4.11.1 scrive solo JSON e XML           |
| Interfaccia web locale (HarvestView) e API REST                                                           | Non presenti nella 4.11.1                  |

Il consiglio operativo è semplice: scrivi nel report la versione esatta usata, e se aggiorni, rilancia `theHarvester -h` prima di riusare script vecchi.

## Come metterlo nel report

Un risultato di TheHarvester diventa un finding solo se lo colleghi a un rischio. Esempi di righe credibili:

| Evidenza                                                                          | Come descriverla                                                     | Livello di certezza             |
| --------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------- |
| Sottodominio `dev.example.org` trovato in certificate transparency e che risponde | Ambiente di sviluppo esposto pubblicamente: va verificato cosa serve | Alto (risolve e risponde)       |
| Sottodominio nei log ma non risolve                                               | Nome storico, nessun servizio raggiungibile oggi                     | Basso (informativo)             |
| Pattern `f.last` dedotto da 6 indirizzi nominali                                  | Formato email probabile, utile per un test di phishing autorizzato   | Medio (dedotto, non verificato) |
| Record che punta a un servizio dismesso (`-t`)                                    | Possibile subdomain takeover, da dimostrare in sicurezza             | Da confermare a mano            |
| Email personale dentro un repository pubblico                                     | Esposizione di dato personale, da segnalare al cliente               | Alto (fonte citabile)           |

Per ogni riga indica sorgente, data e comando usato: chi legge deve poter ripetere la raccolta.

## TheHarvester, Amass, Subfinder, Recon-ng, SpiderFoot: quando usare cosa

Un confronto unico, basato sull'obiettivo e non su punteggi:

| Strumento                           | Cosa lo distingue                                                    | Quando lo scegli                                    |
| ----------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------- |
| **TheHarvester**                    | Aggregatore leggero: sottodomini, email, IP, nomi, da molte sorgenti | Primo giro veloce e raccolta di email               |
| [Subfinder](/articoli/subfinder/)   | Solo sottodomini passivi, pensato per l'automazione                  | Enumerazione rapida di sottodomini in pipeline      |
| [Amass](/articoli/amass/)           | Mappatura DNS approfondita, anche con tecniche attive                | Quando la completezza dei sottodomini è la priorità |
| [Recon-ng](/articoli/reconng/)      | Framework con database persistente e moduli                          | Indagini lunghe, dati da correlare nel tempo        |
| [SpiderFoot](/articoli/spiderfoot/) | Automazione con interfaccia web e correlazione                       | Raccolta ampia con meno scripting                   |
| [Maltego](/articoli/maltego/)       | Analisi a grafo delle relazioni                                      | Mappare relazioni tra entità                        |

Non esiste "il migliore": le sorgenti coperte si sovrappongono solo in parte, quindi in un incarico serio si incrociano più strumenti. Il panorama generale è in [reconnaissance](/articoli/reconnaissance/).

## Cosa vede chi si difende

Se sei dall'altra parte, ecco cosa lascia TheHarvester:

* **Con le sorgenti passive** il tuo dominio non riceve nulla: i dati sono già pubblici. Non c'è nessun log da guardare sul tuo server.
* **Certificate transparency**: ogni certificato emesso per un sottodominio compare nei log pubblici. Se non vuoi che un nome interno finisca in `crtsh`, non richiedere un certificato pubblico per quel nome.
* **Brute force DNS e risoluzione**: i nameserver autoritativi possono registrare un picco di query per nomi inesistenti. È il segnale più utile da monitorare.
* **Screenshot, takeover, api-scan**: arrivano come normali richieste web; guarda User-Agent e raffiche di richieste su percorsi insoliti nei log.

Riduzione dell'esposizione (non elimina i dati già raccolti da terzi):

* niente email personali stampate nelle pagine pubbliche: usa moduli di contatto e alias di ruolo;
* dismetti dal DNS pubblico i sottodomini non più usati ed elimina i record che puntano a servizi disattivati (è la causa dei takeover);
* tieni i nomi interni fuori dai certificati pubblici;
* monitora i log di certificate transparency per il tuo dominio, così sai prima cosa vedono gli altri.

## Troubleshooting

| Sintomo                                              | Causa probabile                                          | Cosa fare                                                                           |
| ---------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `No hosts found` / `No emails found`                 | Pochi dati pubblici, sorgente limitata o irraggiungibile | Prova una sorgente alla volta e confronta; verifica che il dominio sia scritto bene |
| Avvisi su API key mancanti                           | Sorgenti con chiave senza chiave configurata             | Compila `~/.theHarvester/api-keys.yaml` oppure usa `-q` e solo sorgenti gratuite    |
| Una sorgente con chiave non restituisce nulla        | Nome del campo sbagliato (maiuscole) o quota esaurita    | Confronta con il template; controlla l'account del provider                         |
| Il file di output ha un nome strano (`example.json`) | Hai usato `-f example.org`                               | Nome senza punti: `-f example_org`                                                  |
| Cerchi `results.html` e non esiste                   | La 4.11.1 non genera HTML                                | Leggi `.json` o `.xml`                                                              |
| `unrecognized arguments: --virtual-host`             | Opzione inesistente nella 4.11.1                         | Usa ffuf/gobuster per i virtual host                                                |
| `invalid choice` su `-b google`                      | Sorgente rimossa                                         | Usa i nomi dell'elenco sopra                                                        |
| Errore nello screenshot                              | Playwright o Chromium non installati                     | `playwright install chromium`                                                       |
| Brute force pieno di host "validi"                   | DNS wildcard                                             | Controlla con un nome inventato prima di fidarti                                    |
| Errore all'installazione da sorgente                 | Python troppo vecchio                                    | Serve 3.12+ per la 4.11.1 (3.14 per il ramo dev)                                    |

## FAQ

**TheHarvester è legale?**
Interrogare fonti pubbliche non è di per sé vietato, ma la liceità dipende da cosa raccogli e perché. Email e nomi sono dati personali e il loro trattamento può rientrare nel GDPR. Usalo su domini per cui hai un incarico scritto, e per il resto verifica le condizioni d'uso dei provider. Non è un parere legale.

**TheHarvester è passivo o attivo?**
Dipende dall'opzione: con le sole sorgenti (`-b`) il target non vede nulla; con `-r`, `-c`, `-t`, `--screenshot` e `-a` generi traffico verso sistemi del target o verso i suoi DNS.

**Posso usare `-b google` o `-b linkedin`?**
Non nella 4.11.1: quei nomi non sono più nell'elenco ufficiale delle sorgenti.

**TheHarvester verifica che le email esistano?**
No. Raccoglie ciò che le fonti hanno indicizzato. Una regex controlla solo il formato e la verifica SMTP è poco affidabile.

**Quanto ci mette a girare?**
Dipende da sorgenti, limiti dei provider, rete e chiavi. Non ti do un numero perché non sarebbe riproducibile: misura sul tuo caso con `time theHarvester ...` e annota il risultato nel report.

**Come cambio la wordlist del DNS brute force?**
Nella 4.11.1 non puoi: `-c` usa la lista interna. Per una lista tua usa un altro strumento di brute force DNS.

**Come integro l'output con altri tool?**
Passa dal JSON (`-f`) e normalizza con `jq` o Python. Evita di scrivere direttamente nei database interni di altri tool (per esempio Recon-ng): usa i loro meccanismi di import documentati.

## Checklist rapida

* ☐ Ambito e autorizzazione scritti prima di iniziare
* ☐ Versione verificata dal banner (`4.11.1` o quella che usi davvero)
* ☐ Solo sorgenti dell'elenco ufficiale della tua versione
* ☐ API key in `~/.theHarvester/api-keys.yaml` con permessi `600`
* ☐ `-f` con nome senza punti; letti `.json` e `.xml`, non HTML
* ☐ Sottodomini normalizzati, deduplicati e confrontati con lo scope
* ☐ Email distinte in generiche, nominali, dedotte e verificate
* ☐ Opzioni attive (`-r`, `-c`, `-t`, `--screenshot`, `-a`) usate solo dove autorizzate
* ☐ Controllo wildcard DNS prima di fidarti del brute force
* ☐ Chiavi API revocate a fine incarico

Usa questo strumento solo su domini e sistemi per cui hai un'autorizzazione scritta, in laboratori o programmi dove è consentito. La responsabilità di un uso improprio è tua.
