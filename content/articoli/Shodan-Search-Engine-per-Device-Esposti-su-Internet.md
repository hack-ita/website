---
title: 'Shodan: Cos’È e Come Si Usa, filtri, API Python e OSINT'
slug: shodan
description: 'Shodan Search per IP e servizi esposti, Shodan OSINT, Shodan Camera e Shodan API Python: filtri, query, dorks ed esempi per analizzare dispositivi connessi.'
image: /shodan-search-engine-guide.webp
draft: false
date: 2026-02-25T00:00:00.000Z
categories:
  - networking
subcategories:
  - servizi
tags:
  - Shodan
  - OSINT
  - Cybersecurity
  - Network Reconnaissance
  - Internet of Things (IoT)
---

# Shodan: guida completa a ricerca, filtri, API Python, OSINT e difesa

Shodan è il motore di ricerca dei dispositivi collegati a Internet: server, router, telecamere, stampanti, database, impianti industriali. Google cerca pagine web, Shodan cerca **servizi esposti**. Per questo viene chiamato il motore di ricerca per hacker, ma lo usano ogni giorno anche i team di sicurezza per sapere cosa è visibile della propria azienda.

Questo tutorial su Shodan spiega cos'è Shodan e come funziona, come usare Shodan (registrazione, versione gratuita, filtri e query), la ricerca per IP, l'OSINT con Shodan, la ricerca di telecamere IP e dispositivi IoT (Internet of Things) dal punto di vista della difesa, la Shodan API con la API key e Python, la CLI, il confronto con Censys e ZoomEye, e come proteggere i tuoi sistemi.

***

## Cos'è Shodan e come funziona

Shodan (shodan.io) scansiona tutto lo spazio IPv4 e le porte più comuni, si collega ai servizi che trova e salva la loro risposta. Questa risposta si chiama `banner`. Il significato di `banner` è: il testo che un servizio manda quando ti connetti (nome del software, versione, intestazioni).

Un risultato di Shodan contiene di solito:

| Campo                    | Cosa dice                                         |
| ------------------------ | ------------------------------------------------- |
| IP e porta               | Dove risponde il servizio                         |
| `banner`                 | La risposta grezza del servizio                   |
| Prodotto e versione      | Per esempio `nginx 1.18.0` o `OpenSSH 8.9`        |
| Organizzazione, ASN, ISP | Chi possiede quell'IP                             |
| Paese e città            | Posizione stimata                                 |
| Hostname e dominio       | Nomi DNS associati                                |
| Certificato TLS          | Soggetto, emittente, scadenza                     |
| Vulnerabilità (`vuln`)   | CVE associati alla versione trovata               |
| Data                     | Quando Shodan ha visto il servizio l'ultima volta |

Shodan è un motore di ricerca di cyber security perché risponde a una domanda semplice: "cosa vede un attaccante di me da Internet, senza toccarmi?". Cercare su Shodan non invia nessun pacchetto al bersaglio: leggi dati che Shodan ha già raccolto.

**Attenzione alla data.** Un risultato può essere vecchio di giorni o settimane. Se Shodan dice che una porta è aperta, verifica sempre con una scansione tua (su sistemi tuoi o autorizzati) prima di scriverlo in un report.

***

## Shodan.io: account, versione gratuita e piani

Ti serve un account su shodan.io. Con l'account gratuito puoi cercare e usare l'API, ma con limiti: la ricerca con filtri e le pagine oltre la prima consumano i query credits, che si rinnovano ogni mese. Il significato di `query credits` è: i crediti che si consumano a ogni ricerca con filtri o a ogni pagina di risultati oltre la prima.

| Piano                                                                | Per chi                     | Note                                                                         |
| -------------------------------------------------------------------- | --------------------------- | ---------------------------------------------------------------------------- |
| Gratuito                                                             | Prime prove                 | Pochi risultati, funzioni limitate, API con limite di 1 richiesta al secondo |
| Membership (pagamento unico, circa 49 dollari quando ho controllato) | Studenti, pentester singoli | 100 query credits e 100 scan credits al mese, 16 IP monitorati               |
| Freelancer, Small Business, Corporate                                | Team e aziende              | Più crediti, più IP monitorati, più filtri                                   |
| Enterprise                                                           | Grandi aziende              | Dati in blocco e firehose                                                    |

I prezzi cambiano: controllali sulla pagina ufficiale dei piani. Con una email universitaria Shodan offre un upgrade accademico gratuito. Alcuni filtri, come `vuln` e `tag`, dipendono dal piano: se una ricerca non restituisce nulla, il piano può essere il motivo e la sintassi può essere giusta.

***

## Come usare Shodan: la ricerca di base

La sintassi è semplice:

* Una parola da sola cerca nel `banner`. `Moxa Nport` trova i dispositivi Moxa Nport.
* Un filtro ha la forma `filtro:valore`, **senza spazi** dopo i due punti.
* Un valore con spazi va tra virgolette: `org:"Acme Corporation"`.
* Più filtri si combinano separandoli con uno spazio: sono tutti in AND.
* Il meno davanti a un filtro lo esclude: `-country:US`.

Un primo esempio sul tuo mondo: il database MongoDB esposto in Italia.

```text
product:MongoDB country:IT
```

Per vedere solo quanti sono, senza aprire i risultati, usa il conteggio (lo stesso numero lo trovi in alto nella pagina dei risultati):

```bash
shodan count product:MongoDB country:IT
```

Una buona abitudine è partire sempre da un conteggio e restringere la ricerca finché il numero è gestibile.

***

## Shodan Search: filtri, dorks e query avanzate

Questi sono i filtri che usi di continuo. Gli esempi sono la base di qualunque query Shodan e dei cosiddetti `dork`. Il significato di `dork` è: una ricerca costruita con filtri precisi per trovare un tipo specifico di sistema.

| Filtro                 | Esempio                            | Cosa trova                                        |
| ---------------------- | ---------------------------------- | ------------------------------------------------- |
| `port:`                | `port:3389`                        | Servizi su una porta                              |
| `net:`                 | `net:203.0.113.0/24`               | Tutto ciò che sta in un blocco di IP              |
| `hostname:`            | `hostname:acme.example`            | Host con quel nome                                |
| `org:`                 | `org:"Acme Corporation"`           | IP di un'organizzazione                           |
| `asn:`                 | `asn:AS15169`                      | Un sistema autonomo                               |
| `country:`             | `country:IT`                       | Paese (codice a due lettere)                      |
| `city:`                | `city:Napoli`                      | Città                                             |
| `product:`             | `product:nginx`                    | Software riconosciuto                             |
| `version:`             | `product:nginx version:1.18.0`     | Versione precisa                                  |
| `os:`                  | `os:"Windows Server 2012"`         | Sistema operativo stimato                         |
| `http.title:`          | `http.title:"Index of /"`          | Titolo della pagina web                           |
| `http.html:`           | `http.html:"admin login"`          | Testo nel corpo della pagina                      |
| `http.favicon.hash:`   | `http.favicon.hash:-1234567890`    | Tutti i siti con la stessa icona                  |
| `http.component:`      | `http.component:wordpress`         | Tecnologia web rilevata                           |
| `ssl:`                 | `ssl:acme.example`                 | Testo nel certificato TLS                         |
| `ssl.cert.subject.cn:` | `ssl.cert.subject.cn:acme.example` | Nome comune del certificato                       |
| `has_ssl:`             | `has_ssl:true`                     | Solo servizi con TLS                              |
| `has_screenshot:`      | `has_screenshot:true`              | Shodan ha catturato un'immagine                   |
| `vuln:`                | `vuln:CVE-2021-44228`              | Host associati a un CVE (dipende dal piano)       |
| `tag:`                 | `tag:ics`                          | Categoria assegnata da Shodan (dipende dal piano) |
| `before:` / `after:`   | `after:01/10/2026`                 | Filtra per data della scansione                   |

Il valore dell'hash della favicon (`http.favicon.hash`) è un numero che si calcola dall'icona del sito. Serve a trovare tutti i server che usano lo stesso pannello, anche con IP e domini diversi. Per questo è molto usato nella ricerca di infrastruttura.

### Query Shodan per porta e servizio

Servizi spesso lasciati esposti per errore. Per ogni riga, il numero ti dice quanto è diffusa l'esposizione:

| Cosa cerchi                           | Query                                          |
| ------------------------------------- | ---------------------------------------------- |
| RDP esposto in un blocco di IP        | `port:3389 net:203.0.113.0/24`                 |
| SSH su una porta insolita             | `product:OpenSSH -port:22`                     |
| Database MongoDB senza autenticazione | `product:MongoDB "mongodb server information"` |
| Elasticsearch aperto                  | `product:Elasticsearch port:9200`              |
| Directory listing                     | `http.title:"Index of /"`                      |
| Pannelli di login                     | `http.title:"login"`                           |
| Server con una versione vecchia       | `product:Apache version:2.4.49`                |
| Protocolli industriali                | `port:502` (Modbus)                            |

Le stesse ricerche, in versione approfondita, le trovi negli articoli su [RDP](https://hackita.it/articoli/porta-3389-rdp/), [MongoDB](https://hackita.it/articoli/porta-27017-mongodb/) ed [Elasticsearch](https://hackita.it/articoli/porta-9200-elasticsearch/).

### Shodan query examples: filtri combinati, esclusioni e CIDR

Esempi pratici di Shodan search, da usare sul tuo perimetro o su sistemi autorizzati. Mostrano come si combinano i filtri.

| Obiettivo                                    | Query                                    |
| -------------------------------------------- | ---------------------------------------- |
| Tutti i servizi di un blocco di IP           | `net:203.0.113.0/24`                     |
| Solo i web server del blocco, esclusa la 443 | `net:203.0.113.0/24 port:80 -port:443`   |
| Un'organizzazione, escluso un paese          | `org:"Acme Corporation" -country:US`     |
| Un prodotto in una città                     | `product:nginx city:Napoli`              |
| Una versione precisa di un software          | `product:Apache version:2.4.49`          |
| Siti con la stessa icona                     | `http.favicon.hash:-1234567890`          |
| Pannelli con un certo titolo, solo con TLS   | `http.title:"dashboard" has_ssl:true`    |
| Servizi scansionati dopo una data            | `net:203.0.113.0/24 after:01/10/2026`    |
| Host con un CVE (dipende dal piano)          | `net:203.0.113.0/24 vuln:CVE-2021-44228` |
| Un hostname e i suoi sottodomini             | `hostname:acme.example`                  |

Le regole da ricordare: i filtri si uniscono con lo spazio (AND), il meno esclude, le virgolette servono ai valori con spazi e il CIDR (`/24`) restringe la ricerca a un blocco di IP. Parti da un `shodan count`, poi aggiungi filtri finché il numero è gestibile.

### Shodan IP Search: come cercare un indirizzo IP

Per la ricerca per IP (Shodan search IP, ricerca di un indirizzo) hai tre modi:

```bash
# Everything Shodan knows about one IP
shodan host 203.0.113.10

# Same, with the history of past scans
shodan host --history 203.0.113.10
```

La ricerca per IP si chiama anche host lookup. Nel sito basta incollare l'IP nella barra di ricerca, oppure aprire `https://www.shodan.io/host/8.8.8.8`. Per un'intera rete usi `net:`; per un dominio, `hostname:` o il comando `shodan domain`.

### Shodan InternetDB: ricerca IP gratuita senza API key

InternetDB è un servizio gratuito di Shodan che restituisce, per un IP, un riassunto: porte aperte, hostname, tag, CPE (software riconosciuto) e CVE associati. Non serve account né API key. Non ha il `banner` completo, ma per un controllo rapido su molti IP è comodo.

```bash
curl -s https://internetdb.shodan.io/8.8.8.8
```

Per controllare una lista di tuoi IP da script:

```python
import time
import requests

for ip in ["8.8.8.8", "1.1.1.1"]:
    data = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10).json()
    print(ip, "ports:", data.get("ports", []), "vulns:", data.get("vulns", []))
    time.sleep(1)
```

***

## Shodan OSINT e reconnaissance

Nell'OSINT con Shodan l'obiettivo è la mappa dell'esposizione di un'organizzazione senza mandare un solo pacchetto. È la fase di reconnaissance e footprinting di un pentest.

Il percorso tipico, passo dopo passo:

1. **Trovi i blocchi di IP** dell'azienda (WHOIS, ASN, `org:`).
2. **Elenchi i servizi esposti** con `net:` o `org:`.
3. **Guardi le statistiche** per paese, porta e prodotto.
4. **Cerchi versioni vulnerabili** con `product:`, `version:` e `vuln:`.
5. **Verifichi** i candidati con una scansione tua, solo se autorizzato.

Le statistiche si chiamano `facets`. Il significato di `facets` è: il riepilogo dei risultati raggruppato per un campo (porta, paese, prodotto).

```bash
shodan stats --facets port,country,product net:203.0.113.0/24
```

Comandi per lavorare sui domini e sul perimetro:

```bash
# DNS records and subdomains known to Shodan
shodan domain example.com

# Same, plus host details for every IP found
shodan domain --details example.com

# Honeypot likelihood of an IP (0.0 to 1.0)
shodan honeyscore 203.0.113.10
```

Shodan non sostituisce gli strumenti di enumerazione: li affianca. Per i sottodomini e la mappa esterna ci sono [Amass](https://hackita.it/articoli/amass/), [Nmap](https://hackita.it/articoli/nmap/) per la verifica attiva e [Nuclei](https://hackita.it/articoli/nuclei/) per controllare le vulnerabilità sui candidati trovati. L'ordine corretto è sempre: Shodan per scoprire, Nmap per confermare, Nuclei o test manuali per verificare.

***

## Shodan Camera Search: ricerca di telecamere IP e webcam

Le ricerche "Shodan camera", "IP camera" e "webcam search" sono tra le più cercate, perché le telecamere sono tra i dispositivi più esposti. Una telecamera su Internet con password di fabbrica o senza password mostra le immagini a chiunque.

Quello che devi sapere:

* Le telecamere vengono trovate dal `banner` (modello, produttore, protocollo come RTSP, porta 554) e a volte da uno screenshot catturato da Shodan.
* Guardare un flusso video o provare le password di una telecamera che non è tua è accesso abusivo a un sistema informatico. Il fatto che sia "aperta" non lo rende lecito.
* Per te la ricerca serve a controllare **le tue** telecamere.

Controllo delle tue telecamere e degli apparati sul tuo perimetro:

```bash
# How many RTSP services are visible in your IP range
shodan count port:554 net:203.0.113.0/24

# List them with IP, port and product
shodan search --fields ip_str,port,product port:554 net:203.0.113.0/24

# Visible web interfaces with a screenshot in your range
shodan count has_screenshot:true net:203.0.113.0/24
```

Se il conteggio non è zero, ogni risultato è una telecamera o un registratore da mettere dietro VPN o firewall. Il protocollo RTSP si approfondisce in [porta 554 RTSP](https://hackita.it/articoli/porta-554-rtsp/).

Anche per altri dispositivi IoT e impianti industriali il principio è lo stesso: la ricerca serve a misurare l'esposizione, non ad entrare.

***

## Shodan API: API key, CLI e Python

La Shodan API ti permette di fare le stesse ricerche da uno script. Ogni account ha una API key, che trovi in "My Account" su shodan.io. Per ottenere la API key serve solo registrarsi. La API key è personale: non pubblicarla mai su GitHub.

**Installazione della CLI e della libreria Python:**

```bash
python3 -m venv shodan-env
source shodan-env/bin/activate
pip install shodan
shodan init "$SHODAN_API_KEY"
shodan info
```

`shodan init` salva la chiave. `shodan info` mostra i crediti rimasti.

**Comandi della CLI:**

| Comando                                          | Cosa fa                                  |
| ------------------------------------------------ | ---------------------------------------- |
| `shodan search "query"`                          | Cerca e stampa i risultati               |
| `shodan search --fields ip_str,port,org "query"` | Stampa solo i campi scelti               |
| `shodan count "query"`                           | Conta i risultati                        |
| `shodan stats --facets port,country "query"`     | Statistiche per campo                    |
| `shodan host IP`                                 | Informazioni su un IP                    |
| `shodan download file "query"`                   | Scarica i risultati in un file compresso |
| `shodan parse --fields ip_str,port file.json.gz` | Legge un file scaricato                  |
| `shodan convert file.json.gz csv`                | Converte in CSV                          |
| `shodan domain example.com`                      | DNS e sottodomini                        |
| `shodan myip`                                    | Il tuo IP pubblico                       |
| `shodan honeyscore IP`                           | Probabilità di honeypot                  |
| `shodan alert create nome rete`                  | Crea un avviso su una rete               |
| `shodan scan submit IP`                          | Chiede a Shodan di scansionare (attivo)  |
| `shodan trends`                                  | Dati storici                             |

Il `parse` lavora in locale sul file scaricato e non consuma crediti. Questo flusso è il più comodo: scarichi una volta, poi filtri quante volte vuoi.

```bash
shodan download acme-exposure product:nginx net:203.0.113.0/24
shodan parse --fields ip_str,port,org acme-exposure.json.gz
shodan parse --fields ip_str,port -f port:443 acme-exposure.json.gz
shodan convert acme-exposure.json.gz csv
```

### Shodan API Python: esempi pratici di ricerca

La chiave la leggi da una variabile d'ambiente (`export SHODAN_API_KEY=...`), non la scrivi nel codice.

```python
import os
import shodan

api = shodan.Shodan(os.environ["SHODAN_API_KEY"])

try:
    # Search with a filter: nginx servers in a network block
    results = api.search("product:nginx net:203.0.113.0/24")
    print("Total results:", results["total"])

    for match in results["matches"]:
        print(match["ip_str"], match["port"], match.get("org", "-"))

except shodan.APIError as error:
    print("Shodan error:", error)
```

**Informazioni su un singolo host (host lookup):**

```python
import os
import shodan

api = shodan.Shodan(os.environ["SHODAN_API_KEY"])

try:
    host = api.host("8.8.8.8")
    print("Organization:", host.get("org", "n/a"))
    print("Open ports:", host["ports"])
    for service in host["data"]:
        print(service["port"], service.get("product", "unknown"))
except shodan.APIError as error:
    print("Shodan error:", error)
```

**Scorrere tutti i risultati con il cursore** (consuma un credito ogni 100 risultati):

```python
import os
import shodan

api = shodan.Shodan(os.environ["SHODAN_API_KEY"])

for banner in api.search_cursor("port:554 net:203.0.113.0/24"):
    print(banner["ip_str"], banner["port"], banner.get("product", "unknown"))
```

**Cercare exploit pubblici per un software (Shodan exploit search)** (l'API degli exploit è separata dalla ricerca dei dispositivi):

```python
import os
import shodan

api = shodan.Shodan(os.environ["SHODAN_API_KEY"])

exploits = api.exploits.search("apache 2.4.49")
print("Exploits found:", exploits["total"])
```

**Streaming API:** le API di Shodan sono tre: REST (le ricerche viste sopra), Streaming e Trends. Lo Streaming ti manda i `banner` in tempo reale mentre Shodan li raccoglie. Serve un piano che lo includa.

```python
import os
import shodan

api = shodan.Shodan(os.environ["SHODAN_API_KEY"])

# Prints every new banner Shodan collects for these ports, stop with Ctrl+C
for banner in api.stream.ports([3389, 5900]):
    print(banner["ip_str"], banner["port"])
```

Con l'API gratuita il limite è una richiesta al secondo: se fai cicli, metti `time.sleep(1)` tra una chiamata e l'altra.

***

## Shodan nella catena di un pentest

Il flusso completo, da Shodan all'exploitation, in un incarico autorizzato:

| Fase          | Strumento                                                   | Cosa fai                                                                  |
| ------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------- |
| Scoperta      | Shodan, Amass                                               | Trovi IP, domini, servizi esposti                                         |
| Conferma      | [Nmap](https://hackita.it/articoli/nmap/)                   | Verifichi che porte e versioni siano ancora quelle                        |
| Vulnerabilità | [Nuclei](https://hackita.it/articoli/nuclei/), test manuali | Controlli i candidati                                                     |
| Sfruttamento  | Metasploit, exploit manuali                                 | Solo se previsto dal contratto                                            |
| Report        |                                                             | Lo screenshot di Shodan è una prova di esposizione, non di compromissione |

Esempio di conferma con Nmap sui risultati di Shodan, salvati in un file:

```bash
shodan parse --fields ip_str acme-exposure.json.gz | sort -u > targets.txt
nmap -sV -sC -iL targets.txt -oA nmap_scan
```

Questa scansione è attiva: falla solo su IP che ti appartengono o per cui hai un'autorizzazione scritta.

***

## Shodan vs Censys, ZoomEye e FOFA: alternative a confronto

| Motore  | Punto di forza                                                             | Limite                                              |
| ------- | -------------------------------------------------------------------------- | --------------------------------------------------- |
| Shodan  | Interfaccia semplice, filtri, API, CLI, ottimo per IoT e servizi           | Molti filtri dipendono dal piano                    |
| Censys  | Dati sui certificati TLS e sulle configurazioni, buon per asset management | Sintassi di query diversa                           |
| ZoomEye | Copertura forte su Asia e Cina                                             | Meno usato in Occidente                             |
| FOFA    | Simile a ZoomEye, molto diffuso in Cina                                    | Interfaccia e documentazione meno curate in inglese |
| Google  | Pagine web, non servizi                                                    | Non vede porte e `banner`                           |

Per un confronto vero tra Shodan e Censys conviene lanciare la stessa query su entrambi: le differenze nei risultati (date, porte, versioni) ti dicono quale dei due vede meglio il tuo perimetro. In un lavoro serio si usano insieme.

***

## Limiti di Shodan e errori da evitare

| Limite                                        | Conseguenza                                                                                                                                                                                    |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| I dati sono vecchi                            | Un servizio chiuso ieri può comparire ancora                                                                                                                                                   |
| Non vede tutte le porte                       | Una porta rara può non essere mai scansionata                                                                                                                                                  |
| Il CVE nel risultato è dedotto dalla versione | Può essere un falso positivo (versione corretta con patch del distributore)                                                                                                                    |
| Gli `honeypot` sembrano sistemi veri          | Il significato di `honeypot` è: un sistema esca fatto apposta per attirare e registrare gli attaccanti. Un host con troppi servizi strani e vulnerabili va controllato con `shodan honeyscore` |
| Non vede dietro firewall e VPN                | Mostra solo ciò che è raggiungibile da Internet                                                                                                                                                |
| Account gratuito con pochi risultati          | Per analisi grandi servono crediti                                                                                                                                                             |

Errori comuni nelle query: spazi dopo i due punti (`port: 22` non funziona), virgolette dimenticate sui valori con spazi, filtri a pagamento che sembrano "non trovare nulla".

***

## Aspetti legali: Shodan è legale?

Cercare su Shodan è legale: stai leggendo un indice pubblico, e il bersaglio non riceve niente. Diventa un problema quando passi all'azione:

* **Ricerca passiva** su Shodan: lecita.
* **`shodan scan`**, cioè chiedere a Shodan di scansionare un IP: è reconnaissance attiva. Fallo solo su IP tuoi o autorizzati.
* **Connettersi** a un servizio trovato, aprire un pannello, provare password, vedere un flusso video: è accesso a un sistema informatico altrui. Senza autorizzazione è reato in Italia (art. 615-ter del Codice penale) e in quasi tutti i Paesi.
* Se trovi un'esposizione che non è tua: non toccare i dati, segnalala al proprietario o a un CERT e dai tempo per correggere.

Questa non è una consulenza legale.

***

## Come difendersi da Shodan

Il modo migliore per non finire nei risultati è non esporre il servizio. Nell'ordine:

**1. Conosci cosa vede Shodan di te.** Controlla ogni settimana il tuo perimetro:

```bash
shodan count net:203.0.113.0/24
shodan stats --facets port,product net:203.0.113.0/24
shodan host 203.0.113.10
```

**2. Shodan Monitor e alerts.** Shodan Monitor (monitor.shodan.io) controlla i tuoi IP e ti manda una notifica quando compare un nuovo servizio, una porta aperta o una vulnerabilità. Da terminale crei un avviso (alert) su una rete:

```bash
shodan alert create "Office network" 203.0.113.0/24
shodan alert list
```

**3. Chiudi ciò che non serve su Internet.** RDP, SSH, database, pannelli di amministrazione e telecamere non devono essere raggiungibili da tutta Internet. Mettili dietro una VPN. Un esempio di regola base su Linux per tenere SSH solo dalla rete interna:

```bash
sudo iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
```

**4. Cambia le credenziali di fabbrica** di telecamere, router e dispositivi IoT, e disattiva UPnP sul router. Aggiorna il firmware.

**5. Non fidarti del "bloccare Shodan".** Bloccare gli IP dei suoi scanner non ti protegge: gli attaccanti usano scanner propri, Censys e altri motori. Un servizio esposto resta esposto.

**6. Togli le informazioni inutili dai `banner`.** Nascondi la versione del server web e dei servizi (per esempio `ServerTokens Prod` in Apache o `server_tokens off;` in nginx). Non sostituisce le patch, ma toglie dati gratis a chi fa reconnaissance.

**7. Applica le patch.** Se Shodan associa un CVE alla tua versione, un attaccante lo vede in dieci secondi.

**8. Cerca l'esposizione prima degli altri.** Fai ripetere la scansione con Nmap sul tuo perimetro e confrontala con Shodan: le differenze sono servizi che non sapevi di avere.

**Per controllare un avviso da Python:**

```python
import os
import shodan

api = shodan.Shodan(os.environ["SHODAN_API_KEY"])

for alert in api.alerts():
    print(alert["name"], alert["filters"]["ip"])
```

**Cosa monitorare:** nuove porte aperte su IP pubblici, servizi con `banner` che rivelano versioni, certificati TLS di domini che non riconosci, nuovi host nel tuo blocco di IP. Gli avvisi di Shodan, uniti ai log del firewall, bastano per accorgertene presto.

Usa le tecniche di questo articolo solo su sistemi tuoi o per cui hai un'autorizzazione scritta.

***

## FAQ

**Cos'è Shodan?** È un motore di ricerca che indicizza dispositivi e servizi collegati a Internet (server, router, telecamere, database) invece delle pagine web.

**Come funziona Shodan?** Scansiona gli indirizzi IP e le porte, si collega ai servizi, salva la loro risposta (il `banner`) e la rende ricercabile con parole e filtri.

**Shodan è legale?** Cercare nei suoi dati è legale. Connettersi ai sistemi trovati, o scansionarli, senza autorizzazione no.

**Shodan è gratis?** Esiste un account gratuito con funzioni e risultati limitati. Per più crediti e filtri serve la Membership o un piano superiore. Con email universitaria c'è un upgrade accademico gratuito.

**Come si usa Shodan per cercare un IP?** Incolli l'IP nella barra di ricerca o usi `shodan host IP` da terminale. Per una rete intera si usa `net:`.

**Come trovo la mia API key?** La trovi in "My Account" su shodan.io dopo la registrazione. Si inizializza la CLI con `shodan init` seguito dalla chiave.

**Posso usare Shodan con Python?** Sì, con la libreria ufficiale: `pip install shodan`, poi `shodan.Shodan(chiave)` con i metodi `search()`, `host()` e `search_cursor()`.

**Cosa si può trovare con Shodan?** Server web e database esposti, pannelli di amministrazione, telecamere, stampanti, router, dispositivi industriali e IoT, certificati TLS, versioni di software.

**Shodan trova dispositivi vulnerabili?** Mostra le versioni dei servizi e i CVE associati. Il CVE è dedotto dalla versione e va confermato: può essere un falso positivo.

**Qual è la differenza tra Shodan e Censys?** Shodan è più orientato a dispositivi e servizi, con filtri e API molto usati. Censys è forte sui certificati e sulle configurazioni. I risultati si completano a vicenda.

**Posso bloccare Shodan?** Non serve: bloccare i suoi IP non ferma gli altri scanner. L'unica difesa vera è non esporre servizi inutili e tenere tutto aggiornato.

**Shodan è sicuro da usare?** Sì, la ricerca è passiva. Il rischio è tuo se poi ti colleghi a sistemi altrui senza permesso.
