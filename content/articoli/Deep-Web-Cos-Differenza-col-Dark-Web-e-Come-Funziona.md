---
title: 'Deep Web: Cos''è, Differenza col Dark Web e Come Funziona'
slug: deep-web
description: 'Deep web spiegato semplice: cos''è, come entrarci e come funziona, esempi, differenze con surface web e dark web, se serve Tor e se è legale navigarci.'
image: /dark-web-cose-come-funziona-rete-tor.webp
draft: true
date: 2026-10-07T23:18:15.769Z
lastmod: 2026-10-07T23:16:04.558Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Dark Web
  - Tor
  - Deep Web
  - Privacy
  - Cybersecurity
---

# Dark Web: Cosa Si Trova, Come Funziona, Come Entrare e Quali Rischi Presenta

Il **deep web** è la parte di Internet non indicizzata dai motori di ricerca: email, conti bancari online, cartelle cliniche digitali, database aziendali, aree riservate di un sito. Non serve nessuno strumento speciale per raggiungerlo: lo usi ogni giorno, semplicemente facendo login da qualche parte. È una cosa diversa dal **dark web**, la porzione nascosta e accessibile solo con software specifici come Tor, con cui viene costantemente confuso.

Capire la differenza non è un dettaglio tecnico: è la base per orientarsi in un argomento pieno di titoli sensazionalistici e poche informazioni corrette.

## Deep web cos'è: la parte sommersa, non quella nascosta

Immagina Internet come un iceberg. La punta visibile sopra l'acqua è il **surface web**: tutto ciò che Google, Bing e gli altri motori di ricerca possono indicizzare e mostrare nei risultati. È una frazione minima del totale, stimata in meno del 10%.

Sotto la superficie c'è il **deep web**: pagine che esistono, ma che non vengono indicizzate perché richiedono un login, sono generate dinamicamente, sono dietro un paywall, o semplicemente nessuno le ha linkate pubblicamente. È molto più ampio del surface web indicizzato dai motori di ricerca: non esiste però una percentuale precisa e universalmente accettata delle sue dimensioni, nonostante circolino da anni stime (come il celebre "90%") che risalgono a studi di oltre vent'anni fa e che oggi non sono verificabili in modo affidabile.

Il deep web include cose del tutto ordinarie:

* la tua casella di posta elettronica;
* l'home banking;
* la tua cartella clinica su un portale sanitario;
* i documenti su Google Drive o Dropbox condivisi privatamente;
* il pannello di amministrazione di un sito;
* gli archivi di una biblioteca universitaria accessibili solo agli iscritti;
* le intranet aziendali.

Nulla di tutto questo è nascosto in senso sinistro: è semplicemente privato o non pensato per essere trovato da un motore di ricerca.

## Perché un contenuto finisce nel deep web

Una pagina resta fuori dall'indice di un motore di ricerca per motivi molto pratici, non per "segretezza":

* **richiede un login** (email, home banking, intranet);
* è **generata dinamicamente**, per esempio il risultato di una ricerca interna o di una query a un database, e non esiste come URL fissa da indicizzare;
* è dietro un **paywall**;
* **nessuno l'ha mai linkata** pubblicamente, quindi i motori non l'hanno mai trovata;
* il sito stesso chiede esplicitamente di non indicizzarla (direttiva `noindex`, blocco in `robots.txt`).

Un punto spesso frainteso: **"non indicizzato" non significa "protetto"**. Una pagina con `noindex` o mai linkata pubblicamente può comunque essere perfettamente accessibile a chiunque ne conosca l'URL esatto: l'assenza da Google non è una misura di sicurezza, è solo assenza dai risultati di ricerca.

## Surface web, deep web e dark web: le differenze

Questa è la distinzione più importante dell'intero argomento, e i media spesso la ignorano per titoli più accattivanti.

|                    | **Surface Web**                                      | **Deep Web**                                           | **Dark Web**                                                 |
| ------------------ | ---------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------ |
| **Cos'è**          | Contenuto pubblico indicizzato dai motori di ricerca | Contenuto online non indicizzato                       | Una piccola parte del deep web, intenzionalmente nascosta    |
| **Come si accede** | Browser normale, nessun requisito                    | Browser normale, serve solo un login o un link diretto | Software specifico come **Tor**, non basta un browser comune |
| **Serve login**    | In genere no                                         | Spesso sì                                              | Dipende dal sito                                             |
| **Esempio**        | Un sito pubblico qualsiasi                           | La tua casella email, l'home banking                   | Un servizio .onion                                           |
| **Natura**         | Pubblico per definizione                             | In gran parte attività quotidiane legittime            | Mix di anonimato legittimo e attività illegali               |

In una frase: **il dark web è un sottoinsieme del deep web**, non il suo sinonimo. Tutto il dark web è deep web, ma quasi tutto il deep web non ha nulla a che fare col dark web. Per un approfondimento specifico sul tema, abbiamo una guida dedicata al [dark web](https://hackita.it/articoli/dark-web/).

## Serve Tor per accedere al deep web?

No. Questo è uno dei fraintendimenti più comuni. Il deep web, nella sua quasi totalità, si raggiunge con un browser qualunque: basta fare login sulla propria email o sull'home banking. **Tor serve solo per il dark web**, la piccola parte del deep web intenzionalmente nascosta e raggiungibile solo tramite indirizzi `.onion`.

## Dark web e Onion Services: qual è la differenza con Tor

Tor è una rete e un insieme di strumenti per la privacy, usata ogni giorno soprattutto per navigare in modo anonimo sul web "normale": la gran parte del traffico Tor non è diretta verso siti nascosti. Gli **Onion Services**, identificati da indirizzi che terminano in **.onion**, sono la parte di Tor pensata per ospitare siti raggiungibili solo attraverso quella rete, con proprietà aggiuntive di autenticazione e cifratura end-to-end tra client e servizio: è questa la parte comunemente chiamata "dark web". Tor Browser, basato su Firefox, è lo strumento più diffuso per navigare sia il web normale in anonimato sia gli Onion Services, disponibile gratuitamente per Windows, macOS, Linux e Android.

**Usare Tor non è illegale**: è un software scaricabile liberamente, impiegato ogni giorno da giornalisti, attivisti, persone che vivono sotto regimi censori e semplici utenti che vogliono più privacy.

Il dark web vero e proprio, i suoi marketplace, i rischi concreti di navigarci e la sua legalità li trattiamo in modo approfondito nella guida dedicata al [dark web](https://hackita.it/articoli/dark-web/): qui basta ricordare che è **una parte del deep web**, non il suo sinonimo, e che la liceità dipende sempre da cosa si fa una volta dentro, non dall'accesso in sé.

## Deep web, dark web e dati rubati

Una precisazione importante: **"deep web" non è sinonimo di "mercato criminale"**. La stragrande maggioranza del deep web è fatta di email, home banking e aree riservate del tutto legittime. È nella parte criminale del dark web, non nel deep web in generale, che circolano credenziali, numeri di carte e identità rubate provenienti da [data breach](https://hackita.it/articoli/data-breach/), spesso in vendita su forum e marketplace a poche ore da una violazione. Per questo esistono servizi di **dark web monitoring**: strumenti che cercano automaticamente le credenziali di un'azienda o di una persona in questi mercati, per avvisare prima che vengano sfruttate.

A livello personale, un primo controllo gratuito e alla portata di tutti è verificare se la propria email compare in violazioni note tramite servizi come Have I Been Pwned, che non richiede di accedere al dark web per funzionare.

## Domande frequenti sul deep web

### Cos'è il deep web?

La parte di Internet non indicizzata dai motori di ricerca: email, home banking, aree riservate, database. Si accede con un browser normale, serve solo un login o un link diretto.

### Qual è la differenza tra deep web e dark web?

Il dark web è una piccola parte del deep web, intenzionalmente nascosta e accessibile solo con software come Tor. Il deep web, molto più grande, comprende contenuti privati ordinari come la tua email.

### Il deep web è illegale?

No. La quasi totalità del deep web è fatta di contenuti privati e legittimi che usi ogni giorno, come l'home banking o la posta elettronica.

### È legale usare Tor?

Sì. Tor è un software gratuito e legale da scaricare, installare e usare. È impiegato da giornalisti, attivisti e semplici utenti per la privacy, oltre che per accedere al dark web.

### È legale entrare nel dark web?

Sì, accedervi non è reato. Diventa un problema ciò che si fa una volta dentro: comprare sostanze illegali o dati rubati resta reato, indipendentemente dal canale usato.

### Cosa si trova nel dark web?

Un mix di marketplace illegali, forum, mercati di dati rubati, ma anche siti legittimi come le versioni .onion di testate giornalistiche internazionali per lettori sotto censura.

### Come faccio a sapere se i miei dati sono nel dark web?

Puoi usare servizi come Have I Been Pwned per controllare se la tua email compare in violazioni di dati note, senza bisogno di accedere al dark web.

### Il deep web è più grande del surface web?

Il deep web comprende una quantità molto ampia di contenuti non indicizzati, ma non esiste una percentuale precisa e universalmente accettata delle sue dimensioni rispetto al surface web: le stime che circolano online risalgono a studi di oltre vent'anni fa.

### Serve Tor per accedere al deep web?

No. Il deep web si raggiunge con un browser normale: basta fare login su un servizio privato come la tua email. Tor serve solo per il dark web, la sua parte nascosta.
