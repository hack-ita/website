---
title: 'Thomson Reuters: violati SSN e fascicoli sigillati'
slug: thomson-reuters-ctrack-data-breach-tribunali
description: 'Thomson Reuters: violata la piattaforma C-Track dei tribunali USA e Canada. Esposti SSN, dati sanitari e fascicoli giudiziari sigillati in 24 corti.'
image: /thomson-reuters-c-track-data-breach-usa-canada.webp
draft: false
date: 2026-09-11T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - data-breach
  - thomson-reuters
  - terze-parti
  - fascicoli-sigillati
  - tribunali-usa-canada
---

# Thomson Reuters, violati i dati dei tribunali USA e Canada: SSN e fascicoli sigillati esposti

Thomson Reuters ha confermato che una parte non autorizzata ha avuto accesso ai server della piattaforma **C-Track**, il software di gestione dei fascicoli giudiziari usato da decine di tribunali negli Stati Uniti e in Canada, gestito dalla controllata **West Publishing**. L'azienda ha reso pubblico l'incidente il 2-3 settembre 2026, ma le indagini interne collocano l'accesso non autorizzato già a **marzo 2026**, scoperto solo il **30 giugno 2026** — circa 92 giorni di accesso non rilevato. Tra i dati potenzialmente esposti ci sono nomi, numeri di previdenza sociale (SSN), numeri di patente, informazioni sanitarie, date di nascita e, in alcuni tribunali, **fascicoli riservati, redatti o sigillati**. Al momento nessun gruppo ransomware o APT ha rivendicato l'attacco e Thomson Reuters non ha reso pubblico né il vettore d'accesso iniziale né l'identità del responsabile.

## Cosa è successo, in parole semplici

C-Track è il software con cui molti tribunali statunitensi e canadesi gestiscono i propri fascicoli: udienze, atti, documenti processuali, a volte anche informazioni riservate o secretate da un giudice. Non è un sistema informatico del tribunale in senso stretto, ma un servizio fornito da un'azienda esterna — Thomson Reuters, tramite West Publishing — a cui i tribunali si appoggiano.

Secondo quanto comunicato da Thomson Reuters, qualcuno è riuscito ad accedere senza autorizzazione a una parte di questi dati. L'azienda parla di un "sottoinsieme di fascicoli giudiziari" potenzialmente coinvolto, che in alcuni casi conterrebbe dati personali diretti: nome, cognome, SSN (l'equivalente americano del nostro codice fiscale, ma usato anche per aprire conti bancari e richiedere credito), numero di patente, data di nascita, informazioni mediche e assicurative sanitarie. Per alcuni tribunali sono coinvolti anche documenti "confidenziali, redatti o sigillati" — cioè fascicoli che un giudice aveva deciso di non rendere pubblici, ad esempio per proteggere vittime, minori o informazioni sensibili di un procedimento.

In totale risultano coinvolte **almeno 24 organizzazioni giudiziarie** in 11-12 stati americani (tra cui Alabama, Kentucky, Montana, Nevada, New Hampshire, North Dakota, Ohio, Pennsylvania, South Carolina, Tennessee, Wyoming, più l'Oregon confermato successivamente), le Isole Vergini americane, e tre tribunali dell'Ontario, in Canada (la Court of Appeal for Ontario, l'Ontario Superior Court of Justice e l'Ontario Court of Justice). A queste si aggiunge un caso particolare: il **Minnesota**, che non compare nella notifica ufficiale pubblicata da Thomson Reuters/West Publishing, ma i cui tribunali hanno confermato in autonomia di essere coinvolti (vedi sezione valutazione editoriale).

Non tutti i tribunali sono colpiti allo stesso modo: il New Hampshire, ad esempio, ha dichiarato che nel suo caso sono stati esposti solo nomi e indirizzi legati a fascicoli tra il 2002 e il 2015, senza SSN o dati sanitari; l'Ohio ha invece segnalato che è stata raggiunta la piattaforma di produzione (i dati "vivi", non solo copie di backup). In Alabama, invece, è emerso un dettaglio particolare: i dati coinvolti erano una **copia di backup** che i tribunali non sapevano nemmeno esistesse (vedi sotto).

Chi rischia di essere coinvolto sono soprattutto persone che, anche indirettamente, sono comparse in un procedimento giudiziario in uno di questi stati o in Ontario negli ultimi anni: parti in causa, testimoni, o semplicemente cittadini citati in un atto. Non è richiesta alcuna azione immediata obbligatoria, ma chi ha ricevuto o riceve una notifica da Thomson Reuters dovrebbe attivare il monitoraggio del credito offerto gratuitamente dall'azienda e prestare attenzione a tentativi di [phishing](https://hackita.it/articoli/phishing/) o furto d'identità nei mesi successivi — dati come SSN, data di nascita e informazioni sanitarie sono esattamente il tipo di materiale che rende più credibile un attacco mirato.

## Valutazione editoriale: cosa ha funzionato e cosa no

Sul fronte della trasparenza, la tempistica lascia perplessi: l'accesso non autorizzato risale a marzo 2026, ma è stato scoperto solo a fine giugno — tre mesi dopo. Da lì, le prime notifiche ufficiali (a Montana e Ontario) sono arrivate il 23 luglio, quasi un mese dopo la scoperta, e la comunicazione pubblica è arrivata solo a inizio settembre: in totale, tra intrusione e divulgazione pubblica sono passati circa cinque-sei mesi. È un intervallo lungo per un incidente che coinvolge dati potenzialmente molto sensibili, come SSN e fascicoli sigillati.

Il caso più critico riguarda però la **completezza della disclosure**. Il Minnesota non compare nella notifica ufficiale di West Publishing, ma il sistema giudiziario dello stato ha comunicato autonomamente di essere coinvolto: ha **tagliato l'accesso di Thomson Reuters** ai propri sistemi, avviato un audit degli account, forzato il reset password per tutti gli utenti del sistema di gestione fascicoli d'appello e aperto un'indagine indipendente. La Chief Justice della Corte Suprema del Minnesota, Natalie Hudson, si è detta "profondamente turbata" per l'impatto sugli utenti dei tribunali. Il fatto che uno stato coinvolto sia assente dalla comunicazione ufficiale dell'azienda — senza che Thomson Reuters abbia mai spiegato pubblicamente questa omissione — è un problema di trasparenza serio, non un dettaglio marginale.

Ancora più rivelatore è il caso dell'**Alabama**: West Publishing ha comunicato ai tribunali dello stato che una copia dei loro dati d'appello era conservata "in un file di backup all'interno dell'ambiente cloud dell'azienda". La Chief Justice dell'Alabama, Sarah Stewart, ha dichiarato che i propri tribunali "non avevano richiesto né erano a conoscenza" di quel backup. In altre parole: Thomson Reuters conservava dati che i suoi stessi clienti non sapevano fossero ancora lì — un problema di governance dei dati, non solo di sicurezza perimetrale.

Le reazioni dei tribunali coinvolti sono state in diversi casi molto dure. L'Oregon, tramite la Chief Justice Meagan Flynn, ha definito l'incidente "inaccettabile" chiedendo piena responsabilità da parte di Thomson Reuters. Il North Dakota ha confermato l'apertura di un'indagine penale attiva. E la Corte Suprema dell'Ohio ha dichiarato di **non aver ancora ricevuto dettagli completi** sulle "misure di sicurezza aggiuntive" che Thomson Reuters dice di aver implementato dopo l'incidente — il che significa che anche la rassicurazione pubblica dell'azienda sul rimedio applicato non risulta verificata dai suoi stessi clienti istituzionali.

Va anche notato come Thomson Reuters abbia insistito nel comunicato sul fatto che la violazione sia avvenuta "all'interno del proprio ambiente cloud" e non nei sistemi informatici dei tribunali stessi — una distinzione tecnicamente corretta, ma che rischia di apparire come un modo per allontanare la responsabilità dall'azienda, quando in pratica i dati compromessi appartenevano proprio ai tribunali e alle persone coinvolte nei loro procedimenti. È un caso da manuale di rischio di terze parti: i tribunali non hanno subito una violazione dei propri sistemi, ma la violazione di un fornitore a cui avevano affidato dati sensibili.

Sul lato positivo, Thomson Reuters ha messo a disposizione delle persone coinvolte 12 mesi di monitoraggio del credito e protezione dal furto d'identità gratuiti (Experian IdentityWorks negli Stati Uniti, con iscrizione aperta fino al 31 dicembre 2026 tramite un codice pubblicato nella notifica, e una hotline dedicata; TransUnion myTrueIdentity in Canada, con un call center attivo dal 4 settembre), oltre a pagine di notifica ufficiali dedicate (separate per Stati Uniti e Canada) dove chiunque può verificare se è stato coinvolto. Diversi tribunali, come quello del New Hampshire e quelli dell'Ontario, hanno inoltre pubblicato comunicati propri con dettagli specifici sul proprio caso, un livello di trasparenza che va oltre il minimo richiesto.

Resta un punto critico particolare rispetto ai data breach più comuni: un numero di carta di credito si può cambiare, un SSN più difficilmente, ma un fascicolo giudiziario sigillato, una volta esposto, non si può "resettare" in alcun modo. È un tipo di danno permanente che va oltre il classico rischio di frode finanziaria.

## Analisi tecnica

### Vettore d'attacco

Non è stato reso pubblico. Thomson Reuters non ha comunicato come l'attaccante abbia ottenuto l'accesso iniziale, né chi sia il responsabile, né quanti dati esattamente siano stati sottratti. Non risultano, dalle fonti disponibili, exploit, credenziali rubate o campagne di phishing menzionate esplicitamente in relazione a questo incidente: qualsiasi ipotesi in tal senso sarebbe speculazione, non un fatto confermato.

### Timeline

* **Marzo 2026** — secondo l'indagine interna di Thomson Reuters, un soggetto non autorizzato ottiene accesso ai file di C-Track.
* **30 giugno 2026** — l'azienda scopre l'intrusione e avvia le indagini con esperti di cybersecurity esterni e le forze dell'ordine. Da questo momento all'accesso iniziale sono passati circa 92 giorni non rilevati.
* **23 luglio 2026** — prime notifiche ufficiali ad alcune giurisdizioni coinvolte, tra cui Montana e i tribunali dell'Ontario.
* **Metà agosto 2026** — il New Hampshire riceve i file effettivamente compromessi per una revisione indipendente.
* **2-3 settembre 2026** — divulgazione pubblica dell'incidente da parte di Thomson Reuters e dei tribunali coinvolti.
* **9 settembre 2026** — la Corte Suprema del New Hampshire pubblica un aggiornamento specifico: confermati nomi e indirizzi legati a fascicoli tra il 2002 e il 2015, nessuna evidenza di SSN o dati sensibili esposti per il proprio caso.

### Gruppo responsabile

Non attribuito. Nessun gruppo ransomware o APT ha rivendicato pubblicamente l'attacco al momento della stesura di questo articolo, e non risultano fonti affidabili che colleghino l'incidente a un attore noto. Va trattato come un accesso non autorizzato di origine non identificata, non come un attacco ransomware o una campagna APT accertata.

### IOC / TTP

Non disponibili pubblicamente. Nessuna fonte consultata ha pubblicato indicatori di compromissione (IP, domini, hash) o tecniche MITRE ATT\&CK specifiche relative a questo incidente.

### Impatto tecnico

I dati potenzialmente esposti includono nomi, SSN, numeri di patente, informazioni sanitarie, date di nascita, informazioni assicurative sanitarie e, per alcuni tribunali, documenti giudiziari riservati, redatti o sigillati. L'impatto varia sensibilmente da giurisdizione a giurisdizione: il New Hampshire riporta solo nomi e indirizzi per fascicoli 2002-2015, mentre altri tribunali — come l'Ohio, dove risulta coinvolta la piattaforma di produzione e non solo copie di backup — riportano categorie di dati più sensibili. In Alabama, al contrario, i dati coinvolti erano specificamente una copia di backup che i tribunali stessi non sapevano fosse conservata da Thomson Reuters. Thomson Reuters ha dichiarato che non risultano compromessi i sistemi usati per elaborare transazioni finanziarie, e che non ci sono al momento evidenze di frode o uso improprio dei dati.

### Risposta dell'organizzazione

Thomson Reuters ha avviato un'indagine con esperti di cybersecurity esterni e le forze dell'ordine, ha notificato progressivamente le giurisdizioni coinvolte tra luglio e settembre 2026, ha attivato pagine di notifica dedicate (ctracknotification.com per gli Stati Uniti e ctracknotification.ca per il Canada) e offre 12 mesi di monitoraggio del credito e protezione dal furto d'identità alle persone interessate — Experian IdentityWorks negli USA (iscrizione entro il 31 dicembre 2026) e TransUnion myTrueIdentity in Canada. L'azienda dichiara che la piattaforma C-Track "rimane pienamente operativa" e che sono state implementate "misure di sicurezza aggiuntive riviste e approvate da esperti esterni" — affermazione che, secondo quanto dichiarato dalla Corte Suprema dell'Ohio, non è ancora stata accompagnata da dettagli completi verso i tribunali clienti. Diversi tribunali coinvolti — tra cui quelli dell'Ontario, del New Hampshire e il Minnesota (quest'ultimo in autonomia, non tramite la notifica ufficiale) — hanno pubblicato comunicati pubblici indipendenti con dettagli specifici sul proprio caso, in alcuni casi con toni molto più critici di quelli usati da Thomson Reuters stessa.

## Domande frequenti

**Cos'è successo a Thomson Reuters?**
Un soggetto non autorizzato ha avuto accesso ai server di C-Track, il software di gestione dei fascicoli giudiziari fornito da West Publishing (controllata di Thomson Reuters) a diversi tribunali di Stati Uniti e Canada.

**Quando è avvenuto l'attacco?**
L'accesso non autorizzato risale, secondo l'indagine interna, a marzo 2026. È stato scoperto il 30 giugno 2026 (circa 92 giorni dopo) e reso pubblico il 2-3 settembre 2026.

**Quanti tribunali sono coinvolti?**
Almeno 24 organizzazioni giudiziarie in 11-12 stati americani (tra cui Alabama, Kentucky, Montana, Nevada, New Hampshire, North Dakota, Ohio, Oregon, Pennsylvania, South Carolina, Tennessee, Wyoming), le Isole Vergini americane e tre tribunali dell'Ontario, in Canada. Il Minnesota risulta coinvolto ma non compare nella notifica ufficiale dell'azienda.

**Quali dati sono stati esposti?**
A seconda del tribunale: nomi, numeri di previdenza sociale (SSN), numeri di patente, informazioni sanitarie, date di nascita, informazioni assicurative sanitarie e, in alcuni casi, documenti giudiziari sigillati o riservati. Non tutti i tribunali hanno gli stessi dati coinvolti.

**L'attacco è stato confermato?**
Sì, è stato confermato direttamente da Thomson Reuters e dai singoli tribunali coinvolti, non si tratta di una semplice rivendicazione.

**Chi ha rivendicato l'attacco?**
Nessuno. Non risultano rivendicazioni da parte di gruppi ransomware o APT, e Thomson Reuters non ha reso pubblica l'identità del responsabile.

**I miei dati sono a rischio?**
Solo se sei stato coinvolto in un procedimento giudiziario in uno dei tribunali interessati negli anni coperti dalla violazione. Thomson Reuters e i singoli tribunali stanno notificando direttamente le persone interessate.

**Come posso proteggermi?**
Se ricevi una notifica da Thomson Reuters o da un tribunale coinvolto, attiva il servizio gratuito di monitoraggio del credito offerto (Experian IdentityWorks negli USA, TransUnion myTrueIdentity in Canada, 12 mesi) e presta attenzione a email o chiamate sospette che potrebbero sfruttare i tuoi dati per tentativi di phishing o furto d'identità.

## Fonti

* [Thomson Reuters – pagina di notifica ufficiale (USA)](https://www.ctracknotification.com/)
* [Ontario Courts – comunicato ufficiale sulla cybersecurity](https://www.ontariocourts.ca/en/public-statement-cybersecurity.htm)
* [TechTimes – Sealed Court Records Breached When Thomson Reuters Lost Control of Its Cloud](https://www.techtimes.com/articles/326594/20260904/sealed-court-records-breached-when-thomson-reuters-lost-control-its-cloud.htm)
* [The Hacker News – Thomson Reuters Court Software Breach May Have Exposed SSNs and Sealed Data](https://thehackernews.com/2026/09/thomson-reuters-court-software-breach.html)
