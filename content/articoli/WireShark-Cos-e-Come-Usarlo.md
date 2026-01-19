---
title: WireShark Cos'è e Come Usarlo
description: >-
  Guida pratica a Wireshark per analizzare PCAP/PCAPNG in laboratorio (solo
  scenari autorizzati). Differenza tra capture filter e display filter, filtri
  essenziali da copiare, Follow TCP Stream, Export Objects, decrittazione TLS
  con Key Log File, profili e color rules, confronto con tcpdump/tshark e
  playbook operativo per trovare la pista giusta in pochi minuti.
image: /WIRESHARK.webp
draft: false
date: 2026-01-20T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - Wireshark
---

# Wireshark: guida pratica per analisi PCAP in lab

Wireshark è il tool che apri quando vuoi smettere di “andare a intuito” e capire cosa succede davvero sulla rete. Ti aiuta a leggere e ricostruire in modo chiaro protocolli come TCP/IP, DNS, HTTP, SMB e LDAP, senza dover interpretare a caso segnali e comportamenti. Nella pratica, le funzionalità che fanno davvero la differenza sono i **filtri**, il **Follow Stream** e l’export (oggetti/chiavi) quando serve.

Useremo solo scenari **ethical/lab** (HTB, Proving Grounds, VM locali, reti autorizzate), seguendo sempre lo stesso flusso: cattura → filtro → evidenza → conclusione.

***

## Come ragiona Wireshark

**Wireshark non “hacker-a” nulla: legge pacchetti e li ricostruisce nei protocolli corretti, così capisci chi parla con chi e cosa si scambiano.**
**Se sai filtrare e seguire gli stream, hai già l’80% della potenza.**

Puoi lavorare su capture live o su file **PCAP/PCAPNG**. PCAPNG è il formato moderno e in genere conserva più metadati, il che torna utile quando devi contestualizzare traffico, interfacce e dettagli della cattura.

***

## Capture filter vs Display filter

**Wireshark ha due linguaggi di filtro: capture filter (prima, mentre catturi) e display filter (dopo, mentre analizzi).**
**Quando puoi, filtra in cattura per ridurre rumore; poi affina in display filter per trovare la pista giusta.**

* **Capture filter**: sintassi libpcap/BPF (stessa di tcpdump).
* **Display filter**: sintassi Wireshark (molto più ricca, con tantissimi campi e condizioni).

Esempi display filter “da skiddie” (bar in alto):

```text
dns
http.request
ip.addr == 10.10.20.5
tcp.port == 445
```

***

## Display filters che vincono i lab

**Il display filter giusto ti porta dal caos a “ecco la request/errore/credenziale” in pochi secondi.**
**Impara 10 filtri, non 1000: e applicali sempre.**

Base (copiabili):

```text
# DNS query
dns.qry.name contains "lab.local"

# HTTP request e solo POST
http.request && http.request.method == "POST"

# Errori server (se c'è HTTP)
http.response.code >= 400

# SMB e NTLM (se presente)
smb || ntlmssp

# TLS handshake (utile per capire SNI/cert)
tls.handshake
```

Per la sintassi e la logica dei filtri: User’s Guide + wiki DisplayFilters.

Tip da senior: quando trovi un pacchetto interessante, fai click destro su un campo → “Apply as Filter”. È il modo più veloce per non sbagliare la sintassi, perché parti direttamente dal campo reale che Wireshark sta mostrando (approccio “field-based filtering”).

***

## Follow TCP Stream: il tasto “fammi vedere la conversazione”

**Follow Stream isola una conversazione e applica un display filter per mostrarti solo quel flusso.**
**Quando cerchi login, cookie, path e payload, Follow TCP Stream è spesso più veloce di mille filtri.**

Wireshark spiega che seguire uno stream applica un display filter che seleziona i pacchetti dello stream corrente. In pratica: trovi un pacchetto HTTP/SMTP/qualsiasi cosa → Follow → leggi request/response ricostruite.

Mini-uso da lab:

1. filtra `http.request`
2. click su una request interessante
3. Follow TCP Stream
4. leggi e capisci “client → server” e “server → client” (e poi torni indietro se serve)

***

## Export Objects: estrarre file da una capture

**Se il traffico contiene oggetti (es. file via HTTP), Wireshark può ricostruirli ed esportarli su disco.**
**In incident/lab è utile per estrarre “cosa è stato scaricato” senza reinventarti parsing a mano.**

La User’s Guide dice che “Export Objects” scansiona gli stream del protocollo scelto e ti permette di salvare oggetti (HTML, immagini, eseguibili, ecc.) trasferiti, ad esempio, via HTTP.

Regola etica: se estrai eseguibili o file sospetti, analizzali solo in sandbox/lab isolato.

***

## TLS/HTTPS: decrittare in lab con Key Log File

**Wireshark può decrittare TLS se gli dai le session keys tramite “(Pre)-Master-Secret log filename” (key log file).**
**Questa cosa funziona bene per traffico del TUO browser/app in lab; non è “magia” su traffico di terzi.**

Wireshark documenta l’uso del Key Log File (master secrets) per TLS decryption e fornisce una guida step-by-step (Chrome/Firefox). Mitmproxy doc e altri vendor mostrano dove impostare il file in Wireshark: Preferences → Protocols → TLS → (Pre)-Master-Secret log filename.

### Procedura super semplice (solo lab / traffico tuo)

1. imposti sul client (es. browser) la variabile `SSLKEYLOGFILE` verso un file (vuoto ok)
2. catturi traffico
3. in Wireshark punti a quel file nelle preferenze TLS
4. ora puoi vedere HTTP “dentro” TLS quando possibile

Nota pratica: se un’app fa pinning o usa canali non compatibili con key logging, potresti non riuscire a decrittare. (È normale.)

***

## Profili e colorizzazione: rendere Wireshark “tuo”

**I profili ti permettono di avere setup diversi (es. “OSCP lab”, “Incident”, “AD/SMB”) senza distruggere le preferenze ogni volta.**
**La colorizzazione usa la stessa sintassi dei display filter: evidenzia subito pacchetti che contano.**

Wireshark supporta Configuration Profiles (Edit → Configuration Profiles) per più set di preferenze/config. E per i colori: puoi colorare pacchetti secondo un display filter, con esempi disponibili anche nella wiki.

***

## Wireshark vs tcpdump vs tshark: chi fa cosa

**tcpdump è perfetto per catturare veloce; Wireshark è perfetto per analizzare “da umano”; tshark è perfetto per automation/export.**
**Workflow reale da lab: cattura con tcpdump/dumpcap → apri in Wireshark → se serve, esporta con tshark.**

La User’s Guide elenca tool correlati (tshark, tcpdump, dumpcap, capinfos, editcap, mergecap).

Esempi utili (CLI “amici” di Wireshark):

```bash
# Info rapide su una capture (dimensione, pacchetti, durata, ecc.)
capinfos lab.pcapng

# Taglia/converti capture (ripulisci e riduci)
editcap -c 10000 lab.pcapng small.pcapng

# Unisci più capture in una
mergecap -w merged.pcapng a.pcapng b.pcapng
```

***

## Mini-playbook operativo (step-by-step): “trova la pista giusta in 10 minuti”

**Questo playbook è quello che uso quando ho una VM che “fa cose” e devo capire velocemente protocollo, endpoint e contenuto utile.**
**È ripetibile: se lo segui sempre, smetti di perderti nei dettagli.**

**Step 1 — Parti largo (macro)**

* apri la capture e prova filtri grossi: `dns`, `http`, `smb`, `ldap`, `tls.handshake`

**Step 2 — Stringi su IP/porta**

* filtra: `ip.addr == 10.10.20.5` oppure `tcp.port == 445`

**Step 3 — Isola il flusso**

* trova un pacchetto “buono” e fai Follow TCP Stream

**Step 4 — Estrai evidenze**

* se è web e ci sono oggetti: Export Objects (HTTP)
* se è HTTPS del tuo lab: prepara key log file e decritta TLS

**Step 5 — Post-ex / next move (lab)**

* quello che hai trovato guida i tool: se vedi LDAP/SMB, fai enum mirata; se vedi endpoint HTTP, passi a Burp/mitmproxy per manipolare request (sempre autorizzato).

***

## Checklist pratica (lab / esami)

**Se spunti questa lista, Wireshark diventa uno strumento “che ti risolve problemi” e non un videogioco pieno di finestre.**
**Obiettivo: meno pacchetti a schermo, più conclusioni.**

* Ho capito se mi serve capture filter (BPF) o display filter.
* So usare filtri base: `dns`, `http.request`, `ip.addr == X`.
* Quando trovo qualcosa, uso Follow TCP Stream per isolare.
* So creare un profilo “Lab” separato (config profiles).
* Se è HTTPS in lab, so dove impostare il key log file in TLS preferences.
* Se devo estrarre file HTTP, so usare Export Objects.

***

## Promemoria 80/20

| Obiettivo             | Azione pratica             | Comando/Strumento       |
| --------------------- | -------------------------- | ----------------------- |
| Ridurre rumore        | usa display filter “macro” | `dns` / `http.request`  |
| Focalizzare su host   | filtra per IP              | `ip.addr == 10.10.20.5` |
| Isolare conversazione | Follow TCP Stream          | Follow Stream           |
| Estrarre file web     | Export Objects (HTTP)      | Exporting Data          |
| Decrittare TLS in lab | key log file + TLS prefs   | TLS wiki / TLS prefs    |
| Gestire setup diversi | profili separati           | Configuration Profiles  |
| Preparare capture     | unisci/ritaglia            | `mergecap` / `editcap`  |

***

## Concetti controintuitivi (minimo 3)

**Queste sono le trappole che vedo sempre: se le capisci, fai analysis più veloce e più pulita.**
**Wireshark non è “apri e guardi”: è “filtra e isola”.**

1. **“Ho catturato tutto, posso filtrare dopo” (sì, ma ti sei complicato la vita)**
   Display filter funziona dopo, ma se hai catturato troppo rumore, ti perdi. Quando puoi, usa capture filter (BPF) già in cattura.
2. **“Follow Stream mi mostra solo quel flusso e basta” (sì, perché applica un filtro)**
   Wireshark dice che Follow Stream applica un display filter per selezionare i pacchetti dello stream. Se ti “sparisce tutto”, è quello il motivo.
3. **“HTTPS = non si può vedere niente” (falso in lab)**
   Se hai il key log file (master secrets) del tuo client, Wireshark può decrittare TLS e farti vedere il contenuto.
4. **“Colori = estetica” (no, è tempo risparmiato)**
   La colorizzazione evidenzia pacchetti che ti interessano e usa la stessa sintassi dei display filter.

***

## FAQ su Wireshark

### Wireshark è uguale a tcpdump?

No: tcpdump è più “cattura e stampa”, Wireshark è “analisi visuale” con dissezione ricca, stream, export e statistiche. (Sono strumenti complementari.)

### Qual è la differenza tra capture filter e display filter?

Capture filter limita cosa catturi (libpcap/BPF). Display filter limita cosa vedi/analizzi dopo (sintassi Wireshark).

### Come trovo una singola request HTTP in mezzo a tutto?

Parti con `http.request`, poi stringi con IP/host/URI e se serve usa Follow TCP Stream.

### Posso estrarre file scaricati via HTTP da un PCAP?

Sì: Export Objects (HTTP) ricostruisce e ti fa salvare oggetti trasferiti via HTTP.

### Posso decrittare HTTPS con Wireshark?

In lab sì, se hai un key log file con i (pre)-master secrets del client e lo imposti nelle preferenze TLS.

### A cosa servono i profili?

A mantenere set diversi di preferenze/configurazioni (es. un profilo “OSCP lab” e uno “Incident”).

***

## Supporta HackITA

Se questa guida ti è stata utile e vuoi supportare il progetto, trovi la pagina **Supporta** sul sito: anche un contributo piccolo ci aiuta a pubblicare più contenuti pratici, lab-oriented e aggiornati.

Se invece sei in difficoltà e vuoi accelerare sul serio, offriamo **formazione 1:1** (hacking etico, cybersecurity, networking, preparazione lab/CTF e metodo di analisi). E se hai un’azienda o un progetto e ti serve una mano concreta, possiamo anche valutare **lavori/consulenze** su attività di sicurezza e assessment (sempre in contesti autorizzati e concordati).

***
