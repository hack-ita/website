---
title: 'Maltego OSINT: Reconnaissance, Transform e Graph Analysis'
slug: maltego
description: 'Scopri cos''è Maltego per OSINT e reconnaissance: usa Entity, Transform, pivot e graph analysis per correlare domini, IP, email, persone e infrastruttura.'
image: /maltego-osint-visual-analysis.webp
draft: false
date: 2026-02-08T00:00:00.000Z
lastmod: 2026-09-14T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - osint
  - threat-intelligence
  - Graph Analysis
  - Digital Footprinting
  - Attack Surface Discovery
---

# Maltego: OSINT, Reconnaissance e Graph Analysis

Maltego collega dati provenienti da fonti diverse — DNS, WHOIS, certificati, breach database, social media, API commerciali — attraverso un sistema di **entity** e **transform**, e li visualizza come grafo di relazioni. Non è principalmente un tool di raccolta dati: è un ambiente per correlare e visualizzare dati che altri tool (come [TheHarvester](https://hackita.it/articoli/theharvester/) o [Recon-ng](https://hackita.it/articoli/reconng/)) raccolgono più velocemente in forma grezza. Il valore di Maltego emerge quando devi collegare quei dati tra loro — dominio → IP → ASN → organizzazione — e vedere relazioni che in un elenco testuale restano invisibili.

## Maltego in 30 Secondi

```text
Entity iniziale (es. domain.com)
        |
   Transform (DNS / WHOIS / certificati / breach / social)
        |
  Nuova entity scoperta
        |
     Pivot (usa la nuova entity come punto di partenza)
        |
   Correlazione nel grafo
        |
  Validazione (Nmap, Shodan, verifica manuale — mai il solo grafo)
        |
      Finding
```

## Concetti Fondamentali

| Concetto     | Cosa significa                                              | Esempio                                 |
| ------------ | ----------------------------------------------------------- | --------------------------------------- |
| Entity       | Un oggetto rappresentato nel grafo                          | `example.com`, un IP, un'email          |
| Transform    | Un'operazione che parte da un'entity e ne genera altre      | Domain → DNS Name                       |
| Relationship | Il collegamento visualizzato tra due entity                 | Domain → IPv4                           |
| Pivot        | Usare un'entity appena trovata come nuovo punto di partenza | IP → Netblock → altri IP                |
| Machine      | Una sequenza di transform preconfigurata                    | Domain → footprint completo in un click |

**Pivot** è il concetto che rende Maltego diverso da una semplice query: ogni salto aumenta la superficie informativa raccolta, ma aumenta anche il rischio di introdurre risultati non correlati o falsi positivi — un pivot non validato può portarti fuori strada tanto quanto uno buono ti porta a un finding reale.

## Setup e Installazione

Richiede Java 11+ e un account Paterva/Maltego.

```bash
# Linux
wget https://downloads.maltego.com/maltego-v4/linux/Maltego.v4.8.0.deb
sudo dpkg -i Maltego.v4.8.0.deb
```

Su macOS e Windows: download da maltego.com, installer grafico standard.

| Edition   | Limiti indicativi                                    | Uso commerciale    |
| --------- | ---------------------------------------------------- | ------------------ |
| Community | Transform per run limitati, dimensione grafo ridotta | No, solo personale |
| Classic   | Transform illimitati, grafo più grande               | Sì                 |
| XL        | Nessun limite pratico, grafo illimitato              | Sì                 |

I limiti esatti e i prezzi cambiano nel tempo — verifica sempre il piano corrente sul sito ufficiale prima di decidere, non fidarti di cifre trovate in guide vecchie (comprese quelle di Hackita).

Dopo l'installazione, dal Transform Hub installi i pacchetti che ti servono (Shodan, VirusTotal, Have I Been Pwned, e altri, alcuni richiedono API key propria). Verifica funzionamento: trascina un'entity Domain, imposta `example.com`, esegui "To DNS Name - NS" e controlla che tornino nameserver reali.

## Workflow 1: Domain Investigation

**Obiettivo:** mappare l'infrastruttura esposta di un dominio target.

**Input:** entity Domain, valore `targetcorp.com`.

**Transform:** esegui i transform DNS/WHOIS/netblock disponibili sull'entity.

**Output tipico:**

```text
[targetcorp.com]
    +-- [DNS Name: www.targetcorp.com]
    +-- [DNS Name: mail.targetcorp.com]
    +-- [MX Record: mail.targetcorp.com]
    +-- [NS Record: ns1.targetcorp.com]
    +-- [IPv4: 203.0.113.1]
    +-- [Netblock: 203.0.113.0/24]
```

**Interpretazione:** ogni relazione qui è "il transform ha trovato questo dato", non "questo dato è confermato attivo". Un NS record vecchio o un IP non più in uso possono comparire lo stesso.

**Pivot:** dall'IP, prova un transform verso Shodan per vedere porte e servizi esposti.

**Validazione:** conferma con una query diretta — l'IP risponde davvero, il servizio indicato è ancora in ascolto:

```bash
nmap -sV -p- 203.0.113.1
```

**Rilevanza offensiva:** questo primo giro ti dà la lista grezza di asset da prioritizzare, non ancora target validati.

## Workflow 2: Email → Person

**Obiettivo:** costruire un profilo a partire da un indirizzo email aziendale.

```text
[john.doe@targetcorp.com]
    +-- [Person: John Doe]
        +-- [Profilo social pubblico]
        +-- [Possibile breach exposure]
```

**Interpretazione corretta della catena breach:** trovare un'email in un breach database significa che **quell'account è comparso in un dataset esposto**, non che hai una password in chiaro utilizzabile. La catena corretta da tenere a mente è:

```text
Email
  |
Breach exposure (fonte, data)
  |
Servizio coinvolto nel breach
  |
Metadata della credenziale (hash, formato, se disponibile)
  |
Ipotesi di password reuse — da VALIDARE, mai da assumere
```

Se il dataset include un hash, va craccato offline con [hashcat](https://hackita.it/articoli/hashcat/) prima di poter anche solo ipotizzare un riutilizzo; se include solo l'email, hai un indizio di esposizione, non una credenziale. Maltego ti dà la correlazione, non la prova.

**Pivot:** dal profilo LinkedIn trovato, un transform verso "Company from LinkedIn" ti dà lo storico datore di lavoro — utile per costruire pattern di username aziendali.

## Workflow 3: IP → Infrastructure Mapping

```text
1. IPv4: 203.0.113.50
2. Transform: To Netblock → 203.0.113.0/24
3. Transform: To All IPs in block → fino a 256 IP
4. Transform: To Websites → siti ospitati per IP
```

**Filtro rumore:** dopo un pivot così ampio, filtra le entity senza relazioni (`Select → Filter → Remove entities without edges`) per tenere solo IP con siti attivi.

**Co-hosting:** da un sito trovato, "To Domains on same IP" rivela virtual host co-locati sullo stesso server — utile per scoprire domini collegati che non erano nello scope iniziale ma condividono infrastruttura.

## Attack Surface Discovery

Non è una funzione builtin isolata, è il modo in cui incateni i workflow sopra con un obiettivo preciso:

```text
Domain
  |
Subdomain enumeration
  |
DNS resolution
  |
IP
  |
ASN / Netblock
  |
Servizi esposti (via Shodan o Nmap)
  |
Asset prioritizzati
```

Maltego non sostituisce Nmap: Maltego correla intelligence passiva, Nmap valida attivamente cosa gira davvero su una porta. Usali in sequenza, non uno al posto dell'altro.

### Forgotten Asset Discovery

Un pivot particolarmente utile in un assessment: enumerare i sottodomini e cercare pattern che tradiscono ambienti dimenticati.

```text
target.com
  |
subdomain enumeration
  |
old.target.com / dev.target.com / staging.target.com / vpn.target.com
  |
DNS resolution di ciascuno
  |
verifica servizio attivo
```

Sono spesso i target più preziosi in un engagement proprio perché nessuno li patcha più: pannelli admin dimenticati, VPN gateway, ambienti di staging con credenziali di default.

### Certificate Transparency come Fonte di Subdomain

```text
Domain
  |
Certificato TLS emesso
  |
Subject Alternative Names (SAN)
  |
Nuovi subdomain non trovati via DNS enumeration classica
  |
IP / servizio
```

I log di Certificate Transparency sono pubblici per policy dei CA — qualunque certificato emesso per un subdomain finisce lì, anche se quel subdomain non è mai stato pubblicizzato altrove.

## Employee → Infrastructure Pivot

```text
Company
  |
Employee (LinkedIn/social)
  |
Corporate email (formato dedotto o trovato)
  |
Pattern username
  |
Verifica su infrastruttura pubblica (VPN, webmail, portali)
```

Utile per costruire una lista di username plausibili prima di una fase di password spraying autorizzata — la lista resta un'ipotesi da validare, non un elenco di account confermati.

## Toolchain: Maltego + Altri Strumenti

**Maltego → Nmap.** L'OSINT ti dà `dominio → IP → host prioritario`; Nmap verifica `IP → porte → servizi → versioni`. Sono fasi diverse, non intercambiabili.

**Maltego → Shodan.** Transform diretto da IP a Shodan per porte, banner e tecnologie note senza scansionare tu stesso l'host.

**Maltego → TheHarvester / Recon-ng / SpiderFoot.** Questi tool sono spesso più veloci per la raccolta grezza iniziale; puoi importare il loro output in Maltego per la fase di correlazione visuale:

```python
# Esempio: da output TheHarvester (JSON) a CSV importabile in Maltego
import json

with open('harvest.json') as f:
    data = json.load(f)

with open('maltego_import.csv', 'w') as out:
    out.write("entity.type,entity.value\n")
    for email in data.get('emails', []):
        out.write(f"maltego.EmailAddress,{email}\n")
    for host in data.get('hosts', []):
        out.write(f"maltego.Domain,{host.split(':')[0]}\n")
```

Poi in Maltego: `File → Import → Entities from CSV`.

## Custom Transform in Python

Per data source non coperti dal Transform Hub — un database interno, un'API proprietaria — puoi scrivere un transform locale:

```python
#!/usr/bin/env python3
from maltego_trx.entities import IPAddress
from maltego_trx.transform import DiscoverableTransform

class DomainToIP(DiscoverableTransform):
    """Domain -> IP via query a un DB interno"""

    @classmethod
    def create_entities(cls, request, response):
        domain = request.Value
        ips = query_internal_db(domain)
        for ip in ips:
            response.addEntity(IPAddress, ip)
        return response

def query_internal_db(domain):
    # sostituisci con la query reale al tuo datastore
    return ["203.0.113.1", "203.0.113.2"]
```

```bash
pip install maltego-trx
python transform.py --register
```

Poi registri il transform in `Transforms → New Local Transform`, indicando entity di input/output e comando da eseguire.

Per un transform basato su API HTTP esterna, lo schema è identico ma la query interna diventa una `requests.get(...)`: gestisci sempre errori (mai far crashare il transform, restituisci una response vuota), rate limiting e caching per evitare query duplicate sulla stessa entity.

## Machine vs Transform Manuali

Le **Machine** incatenano più transform in un'unica esecuzione (es. da un dominio a un footprint completo in pochi minuti). Comode per un primo giro rapido, ma il set esatto di transform eseguiti e i tempi dipendono dalla versione installata e dai transform disponibili nel tuo Transform Hub — non assumere che una Machine con lo stesso nome faccia esattamente le stesse query in ogni installazione.

Per un lavoro mirato (un dominio specifico, un filtro preciso), eseguire i transform uno alla volta ti dà più controllo su cosa stai davvero interrogando e quanto rumore stai generando verso le API di terze parti.

## Validare un Risultato Prima di Trattarlo come Finding

Correlazione non è prova. Prima di riportare qualcosa come finding, verifica:

1. **Source** — quale transform/provider ha generato il dato.
2. **Timestamp** — quanto è recente l'informazione (un DNS record di 3 anni fa può non valere più).
3. **Second source** — un'altra fonte indipendente conferma lo stesso dato?
4. **Manual validation** — hai verificato attivamente (Nmap, connessione diretta) quando applicabile e autorizzato?

```text
Maltego: example.com -> IP 203.0.113.10
Shodan:  porta 443 aperta su quell'IP
DNS:     hostname coerente
Cert. Transparency: certificato valido per lo stesso dominio
```

Quattro fonti indipendenti che convergono sono un finding solido. Una singola relazione nel grafo, da sola, è un'ipotesi.

## Graph Layout e Filtro

Layout disponibili: Organic (default, force-directed, buono sotto le poche centinaia di nodi), Hierarchical (per catene/timeline), Circular (per analisi hub-and-spoke), Block (per output da presentazione).

```text
Edit → Select → By Type → filtra per tipo di entity
Filter Tab → condizioni su proprietà (es. IP che inizia con un prefisso specifico)
Right-click → Hide Selection → nascondi rumore senza cancellare
```

## Performance e Scala

Su grafi grandi (migliaia di entity), le prestazioni degradano — quanto esattamente dipende da versione, hardware e piano, quindi evita di fidarti di numeri precisi trovati altrove senza verificarli sulla tua installazione. Strategie pratiche indipendenti dalla versione:

* dividi un'investigazione ampia in più file di grafo invece di un unico grafo enorme;
* rimuovi periodicamente entity senza relazioni;
* preferisci transform locali a chiamate API quando possibile, sono più veloci e non consumano quota.

Se l'interfaccia rallenta pesantemente, aumenta l'heap Java nello script di avvio (`-Xmx` nel file di configurazione) — il valore giusto dipende dalla RAM disponibile sulla tua macchina, non esiste un numero universale corretto.

## OPSEC: Cosa Vede Realmente il Target

Distingui sempre tra due categorie di transform:

**Passive (la maggioranza)** — interrogano fonti terze (WHOIS, DNS pubblico, Certificate Transparency, breach database, API commerciali). Il target normalmente non riceve traffico diretto da te; il *provider* della fonte, però, registra la tua query: account, API key, timestamp, IP sorgente usato per interrogarlo.

**Active** — alcuni transform (in particolare quelli che fanno screenshot o verifiche dirette su un servizio) generano traffico che arriva davvero al target. Verifica sempre cosa fa uno specifico transform prima di assumere che sia "solo OSINT passivo" — non esiste una regola valida per tutti i transform indistintamente.

Pratiche utili in un engagement autorizzato:

* account/API key separati per cliente, revocati a fine assessment;
* se serve, instrada le query tramite proxy;
* preferisci i transform locali quando la fonte lo permette, per ridurre la dipendenza da servizi terzi che loggano ogni interrogazione.

```bash
# cleanup post-engagement
rm -rf ~/.maltego/graphs/*
rm -rf ~/.maltego/cache/*
# revoca le API key configurate per quel cliente
```

## Troubleshooting

**"Transform returned 0 results"** — verifica prima l'API key nel Transform Manager (`Test`), poi la quota residua sul dashboard del provider, poi la connettività/proxy.

**`OutOfMemoryError: Java heap space`** — aumenta `-Xmx` nello script di avvio in base alla RAM disponibile.

**UI lenta su grafi grandi** — filtra entity orfane, chiudi pannelli non necessari, disabilita animazioni nelle preferenze, o dividi il grafo.

**Transform Hub non si installa** — scarica il pacchetto `.mtz` manualmente e importalo via `Transforms → Import Configuration`.

## Maltego vs Alternative

| Tool                                                      | Punto di forza                   | Limite                                    | Uso tipico                                      |
| --------------------------------------------------------- | -------------------------------- | ----------------------------------------- | ----------------------------------------------- |
| Maltego                                                   | Correlazione visuale multi-hop   | Dipende da transform/provider configurati | OSINT + attack surface, presentazione risultati |
| [Recon-ng](https://hackita.it/articoli/reconng/)          | Workflow CLI scriptabile         | Nessuna visualizzazione grafica nativa    | Recon automatizzato/ripetibile                  |
| [SpiderFoot](https://hackita.it/articoli/spiderfoot/)     | Automazione molto ampia, GUI web | Genera più rumore, meno controllo fine    | Broad OSINT, monitoraggio continuo              |
| [TheHarvester](https://hackita.it/articoli/theharvester/) | Velocissimo per email/subdomain  | Scope volutamente ristretto               | Primo giro rapido di recon                      |
| Gephi                                                     | Analisi di grafo pura            | Non raccoglie dati OSINT da solo          | Analisi su dataset già estratti                 |

Non sono necessariamente in competizione: un workflow comune è raccolta rapida con TheHarvester/Recon-ng, poi correlazione visuale in Maltego, poi validazione attiva con Nmap/Shodan sui candidati emersi.

## Hardening: Ridurre la Propria Esposizione OSINT

* minimizza le informazioni aziendali pubbliche non necessarie (filing, job posting con dettagli tecnici);
* monitora periodicamente i log di Certificate Transparency per il tuo dominio: ogni certificato emesso è pubblico comunque tu lo voglia o no;
* rimuovi subdomain dimenticati invece di lasciarli risolvere silenziosamente;
* privacy guard su WHOIS dove disponibile;
* monitoraggio breach (es. Have I Been Pwned) per gli indirizzi aziendali principali;
* formazione dei dipendenti su cosa pubblicano su LinkedIn/social a livello di dettaglio tecnico interno.

Quello che non puoi mitigare: dati storici già indicizzati (Archive.org, cache), filing regolatori pubblici, documenti di tribunale, breach già avvenuti e pubblicati.

## Cheat Sheet

```text
# ENTITY
Trascina dalla palette -> canvas
Doppio click -> modifica valore
Click destro -> Run Transform -> seleziona

# TRANSFORM
Click destro -> All Transforms (esegue tutti gli applicabili)
Click destro -> Run Machine -> workflow preconfigurato

# LAYOUT
View -> Layout -> Organic / Hierarchical / Circular / Block

# FILTRO
Edit -> Select -> By Type
Filter Tab -> condizioni su proprietà
Click destro -> Hide Selection

# EXPORT
File -> Save Graph -> .mtgx
File -> Export -> PDF / GEXF / GraphML / CSV
File -> Import -> Entities from CSV

# SVILUPPO TRANSFORM
pip install maltego-trx
class extends DiscoverableTransform
Transforms -> New Local Transform
```

## FAQ

**Cos'è Maltego?**
Una piattaforma di OSINT e graph analysis che collega entity da fonti diverse tramite transform, visualizzando le relazioni scoperte come grafo.

**Maltego fa port scanning?**
Non è il suo scopo principale. Alcuni transform di terze parti (es. Shodan) restituiscono dati già raccolti da scan altrui; per una validazione attiva diretta usa uno strumento dedicato come Nmap.

**Maltego è passivo?**
Dipende dal transform specifico. La maggior parte lo è (interroga fonti terze), ma alcuni generano traffico diretto verso il target — verifica sempre il comportamento del singolo transform prima di darlo per scontato.

**Qual è la differenza tra Entity e Transform?**
L'entity è l'oggetto (un dominio, un IP, un'email); il transform è l'operazione che, partendo da quell'entity, ne trova di nuove correlate.

**Trovare un'email in un breach dà accesso a una password?**
No. Dà un'indicazione di esposizione, non una credenziale utilizzabile. Serve verificare cosa contiene davvero il dataset (email soltanto, hash, o altro) prima di ipotizzare qualsiasi riutilizzo.

**Maltego è utile in un penetration test?**
Sì, soprattutto nella fase di reconnaissance passiva e mappatura dell'attack surface — ma resta un tool di intelligence e correlazione, non di exploitation: la validazione attiva richiede altri strumenti.

***

**Uso consentito solo su target per cui hai autorizzazione scritta esplicita.** L'uso per investigazioni non autorizzate può violare normative sulla privacy (GDPR incluso) e i termini di servizio dei provider di dati integrati. L'uso commerciale richiede licenza Classic o XL — verifica i termini aggiornati sul sito ufficiale di Maltego.
