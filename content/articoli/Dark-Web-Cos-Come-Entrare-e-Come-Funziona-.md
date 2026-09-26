---
title: 'Dark Web: Cos’è, Come Entrare e Come Funziona '
slug: dark-web
description: 'Cos''è il dark web, la differenza con deep web e Tor, l''economia criminale che ci circola davvero e cosa c''è di vero nelle leggende come le Red Room.'
image: /dark-web-cose-come-funziona.webp
draft: true
date: 2026-09-27T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - dark web
  - deep web
  - tor
  - onion
  - black hat
---

# Dark Web: Deep Web, Legalità e Sicurezza

Il dark web comprende servizi e contenuti ospitati su reti progettate per non essere direttamente raggiungibili dal web tradizionale — come i servizi .onion della rete Tor — e accessibili solo con software specifici. Non è di per sé un covo di criminali né semplicemente "la parte pericolosa di internet": è un livello di rete con proprietà tecniche precise — anonimato per chi pubblica e per chi naviga — che può essere usato per proteggere un giornalista quanto per vendere dati rubati. È l'uso che se ne fa a determinare la legalità, non l'accesso in sé.

**In breve:**

* **Deep web** — tutto ciò che i motori di ricerca non indicizzano (email, intranet, database): per lo più legale e quotidiano
* **Dark web** — la porzione del deep web accessibile solo con software dedicati, progettata per l'anonimato
* **Darknet** — a rigore, la rete overlay (Tor è la più diffusa) su cui il dark web gira; nel linguaggio comune i due termini vengono però usati come sinonimi
* **Tor** — la rete di anonimizzazione più usata per raggiungerlo, tramite l'onion routing
* **.onion** — l'indirizzo dei siti raggiungibili solo dentro la rete Tor
* **Legalità** — usare Tor e accedere al dark web non è reato; lo sono le attività illecite eventualmente svolte lì dentro

## Surface Web, Deep Web e Dark Web: le Differenze

I due termini "deep web" e "dark web" vengono usati come sinonimi quasi ovunque, ma descrivono livelli diversi di uno stesso schema a tre strati.

| Livello     | Cosa comprende                                                                                                                                                                             | Come si accede                                    |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------- |
| Surface web | Le pagine indicizzate da Google e dagli altri motori di ricerca — quello che navighi ogni giorno                                                                                           | Browser normale                                   |
| Deep web    | Tutto ciò che NON è indicizzato: la tua casella email, l'home banking, le cartelle cliniche online, un database aziendale interno, un articolo dietro paywall                              | Accesso diretto o login, nessun software speciale |
| Dark web    | Una porzione specifica e molto più piccola del deep web, progettata apposta per restare irraggiungibile senza un software dedicato e per garantire anonimato a chi pubblica e a chi visita | Software specifico come Tor Browser               |

Il deep web è, nella stragrande maggioranza dei casi, contenuto perfettamente legale e quotidiano, semplicemente non pubblico — la tua webmail non è "dark web" solo perché Google non la indicizza. Ogni dark web è deep web, ma il deep web è quasi interamente qualcos'altro.

## Come Funziona: Tor e l'Onion Routing

Il modo più comune per raggiungere il dark web è **Tor** (The Onion Router), una rete di anonimizzazione nata da un progetto della Marina degli Stati Uniti e oggi mantenuta dal Tor Project, un'organizzazione no profit. Il meccanismo che le dà il nome è l'**onion routing**: il traffico viene avvolto in più livelli di cifratura, uno per ogni nodo che attraverserà. Per un normale sito internet, il circuito passa attraverso tre relay — un nodo di ingresso, uno intermedio e un nodo di uscita che si affaccia sul resto della rete. Ogni nodo toglie un livello di cifratura e conosce solo il passo prima e quello dopo di sé, mai l'intero percorso.

Per i servizi .onion il meccanismo cambia: sia il client sia il servizio costruiscono ciascuno il proprio circuito di tre relay verso un **punto di rendezvous** scelto a caso, per un totale di circa sei hop — e non esiste un nodo di uscita, perché la connessione non lascia mai la rete Tor. È il motivo per cui gli onion service restano protetti anche dal lato di chi li pubblica, non solo di chi li visita.

Tor **non garantisce un anonimato perfetto**: proteggere davvero l'identità richiede di non fare login con account personali, non inserire dati identificativi nei form, non installare plugin o estensioni nel browser (possono bypassare le protezioni) e non usare servizi come i torrent attraverso la rete, che espongono comunque l'indirizzo IP reale.

I siti raggiungibili solo dentro questa rete usano indirizzi che terminano in **.onion** invece che in .com o .it — stringhe generate dalla chiave crittografica del servizio stesso, non registrate presso un'autorità come i domini normali. Non fanno parte del normale sistema DNS: un browser tradizionale non sa nemmeno come risolverli, e sono raggiungibili solo passando attraverso la rete Tor.

## Come Accedere al Dark Web in Sicurezza

Il modo standard per entrarci è scaricare **[Tor Browser](https://www.torproject.org/)** dal sito ufficiale del Tor Project — l'unica fonte da cui scaricarlo, perché copie modificate distribuite altrove sono un vettore comune di malware. L'installazione è identica a quella di un browser qualsiasi; una volta aperto, instrada automaticamente tutto il traffico attraverso la rete Tor e permette di visitare sia i normali siti .com/.it (in forma anonima) sia i siti .onion. Su iPhone il Tor Project non pubblica un'app ufficiale: l'alternativa che consiglia è **Onion Browser**, sviluppata da terzi ma esplicitamente supportata dal progetto Tor per iOS.

Poche regole pratiche riducono la maggior parte dei rischi concreti:

* **Non scaricare file** da siti .onion sconosciuti: è il vettore di infezione più comune in assoluto in questo contesto.
* **Non usare le tue credenziali reali** o effettuare login su account personali mentre navighi sul dark web.
* **Non installare plugin o estensioni** nel Tor Browser: possono compromettere l'anonimato che la rete garantisce di base.
* **Non fidarti di ciò che leggi**: l'assenza di qualsiasi controllo su chi pubblica rende il dark web un terreno fertile per truffe, ancora più che per contenuti illegali veri e propri.

Sulla VPN un chiarimento che smentisce un consiglio molto diffuso online: il Tor Project stesso **sconsiglia** di abbinare una VPN a Tor a meno di sapere esattamente come configurare entrambe, perché una combinazione fatta male può ridurre l'anonimato invece di aumentarlo. Per la navigazione normale con Tor Browser, usarlo da solo è già la configurazione pensata per essere sicura di default.

### Tor vs VPN: Non Sono la Stessa Cosa

|                                 | Tor                                        | VPN                                        |
| ------------------------------- | ------------------------------------------ | ------------------------------------------ |
| Instrada il traffico attraverso | Tre (o più) relay indipendenti             | Un singolo server del provider             |
| Accede ai siti .onion           | Sì                                         | No                                         |
| Chi deve fidarsi di chi         | Nessun nodo singolo vede l'intero percorso | Il provider VPN vede tutto il tuo traffico |
| Velocità                        | Più lenta                                  | Generalmente più veloce                    |
| Obiettivo principale            | Anonimato e resistenza alla censura        | Privacy della connessione verso il tuo ISP |

Una VPN nasconde il tuo traffico al tuo provider internet ma il provider VPN stesso può vederlo; Tor distribuisce la fiducia su più nodi indipendenti ma è più lento e, da solo, non nasconde al tuo ISP il fatto che stai usando Tor. Sono strumenti con obiettivi diversi, non uno sostituto dell'altro.

### Livelli di Sicurezza Aggiuntivi

Tor Browser ha uno slider di sicurezza integrato (Impostazioni → Privacy e sicurezza → Livello di sicurezza) che al livello più alto disattiva JavaScript su tutti i siti: riduce parecchio la superficie d'attacco per exploit del browser, al costo di rompere alcune funzionalità interattive delle pagine. Chi ha esigenze di anonimato più elevate spesso va oltre il solo Tor Browser: **Whonix** instrada tutto il traffico di sistema (non solo del browser) attraverso Tor usando due macchine virtuali separate, così che anche un'applicazione compromessa non riesca a rivelare l'indirizzo IP reale bypassando Tor per errore. Per un uso più occasionale, **Tails** — un sistema operativo live avviabile da chiavetta USB che non lascia traccia sul computer usato — è l'alternativa più diffusa.

## Cosa Sono i Siti .onion

Un indirizzo .onion è generato automaticamente dalla chiave pubblica del servizio quando viene creato: è per questo che appare come una stringa casuale di caratteri (nella versione attuale del protocollo, 56 caratteri) invece che come un nome scelto liberamente. Questo design elimina la necessità di un'autorità centrale che assegni gli indirizzi — chiunque può creare un servizio .onion senza registrarlo da nessuna parte — ma ha una conseguenza diretta sul modo in cui si trovano questi siti: non esiste un registro pubblico consultabile, e un indirizzo va condiviso direttamente o trovato tramite un motore di ricerca dedicato.

## Come Trovare Siti .onion

Non esiste un registro pubblico consultabile degli indirizzi .onion, quindi il modo in cui si trovano varia. Il metodo più affidabile è la fonte diretta: molti servizi pubblicano il proprio indirizzo .onion sul sito ufficiale in chiaro, oppure lo segnalano tramite **Onion-Location**, un'intestazione che Tor Browser riconosce automaticamente e che offre di reindirizzarti alla versione .onion di un sito quando la visiti dal web normale.

**I motori di ricerca del dark web.** In alternativa esistono motori di ricerca dedicati che effettuano il proprio crawling all'interno della rete Tor — **Ahmia** è tra i più noti perché applica filtri espliciti contro contenuti come materiale pedopornografico, una scelta di design che non tutti i motori del dark web condividono. Il limite strutturale resta lo stesso di sempre: un motore può indicizzare solo ciò che riesce a raggiungere seguendo link noti, e molti servizi .onion restano irraggiungibili proprio perché progettati per non esserlo.

Un altro nome che ricorre spesso è **The Hidden Wiki**, una delle directory .onion più note e longeve della storia del dark web. A differenza di Ahmia, però, non applica alcun filtro: mescola senza distinzione link a servizi legittimi e link a contenuti illegali, ed è stata più volte clonata da versioni fasulle pensate per rubare dati a chi le visita. Proprio per questo non è un punto di partenza consigliabile — un motore filtrato o la fonte diretta di un servizio restano scelte più sicure.

## Cosa si Trova nel Dark Web

Il contenuto si divide grosso modo in due categorie, e la seconda occupa molto più spazio mediatico della prima nonostante non sia necessariamente la più diffusa:

**Uso legittimo.** Piattaforme di whistleblowing come SecureDrop, usate da testate come il New York Times e il Guardian per ricevere documenti da fonti anonime in sicurezza, e **GlobaLeaks**, framework simile usato anche in ambito anticorruzione; **OnionShare**, tool open source per condividere file in modo anonimo attraverso la rete Tor senza passare da un server terzo; specchi .onion di siti che vuoi restino raggiungibili anche sotto censura — BBC News, ProPublica e persino Facebook mantengono un proprio servizio .onion per questo motivo; forum di attivisti, dissidenti politici e giornalisti che operano sotto regimi che limitano la rete Tor stessa (Cina, Russia, Iran, Turchia). Una curiosità tecnica poco nota: non tutti i siti .onion sono pubblici allo stesso modo — un servizio può richiedere una chiave di autenticazione oltre al semplice indirizzo, restando invisibile e inaccessibile a chiunque non l'abbia ricevuta direttamente da chi lo gestisce.

**Uso illecito.** Mercati che vendono dati rubati, credenziali compromesse (spesso il punto di arrivo di una campagna di [phishing](https://hackita.it/articoli/phishing/) riuscita), [malware](https://hackita.it/articoli/malware/) pronto all'uso, droghe, armi e beni contraffatti; forum di [black hat](https://hackita.it/articoli/white-hat-black-hat-grey-hat/) dove si comprano e vendono exploit e accessi compromessi. I marketplace di questo tipo diventati più noti al grande pubblico — Silk Road e AlphaBay su tutti — sono stati smantellati da operazioni di polizia internazionali, con i gestori arrestati e i fondi sequestrati; Dream Market ha invece cessato le attività nel 2019 in circostanze meno chiare. Nessuno di questi esiste più, ed è la norma più che l'eccezione: un mercato che vende beni illegali online prima o poi finisce sotto indagine, chiuso o svuotato da chi lo gestiva. Questo articolo non nomina né linka alcun marketplace attualmente attivo. E ai margini più oscuri, materiale che le forze dell'ordine di tutto il mondo perseguono attivamente, incluso lo sfruttamento minorile. Su quest'ultimo punto non c'è nulla da spiegare oltre al fatto che esiste come priorità di contrasto internazionale: non è materiale su cui questo articolo entra nel merito in alcun modo.

## L'Economia Sommersa: Non Solo Droga

L'immagine di mercati che vendono soltanto sostanze illegali è ormai riduttiva. Una parte consistente del cybercrime moderno ruota attorno ad accessi e dati, non a beni fisici — e capire come funziona aiuta a capire perché certi attacchi avvengono a catena invece che come opera isolata di un singolo criminale.

| Cosa si scambia              | Cosa significa                                                                                                                                                                                                 |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Credenziali e session cookie | Username, password e token di sessione rubati tramite malware, phishing o data breach — un cookie di sessione valido permette di riutilizzare un accesso già autenticato senza nemmeno conoscere la password   |
| Initial access               | Un accesso già ottenuto a una rete aziendale (VPN, RDP, account privilegiato), venduto da chi lo ha compromesso a chi lo sfrutterà in un secondo momento — chi entra e chi attacca sono spesso persone diverse |
| Exploit e vulnerabilità      | Codice o informazioni per sfruttare falle non ancora corrette (0-day) o già note (n-day); il valore varia molto in base alla gravità e alla diffusione del software colpito                                    |
| Leak site da ransomware      | Pagine .onion dove un gruppo pubblica, o minaccia di pubblicare, dati rubati a un'azienda che si è rifiutata di pagare — il modello noto come doppia estorsione                                                |

Questa separazione dei ruoli — chi ottiene l'accesso, chi lo compra, chi conduce l'attacco, chi gestisce l'estorsione — è uno degli aspetti più concreti di come funziona davvero il cybercrime organizzato oggi: una filiera con specializzazioni diverse, non il lavoro di un singolo hacker isolato in una stanza buia.

## Il Mito dell'Anonimato Totale: Due Cose che Quasi Nessuno Sa

Due convinzioni molto diffuse sul dark web sono, nella pratica, sbagliate — e capirle è probabilmente la parte più istruttiva di questo articolo.

**Pagare in Bitcoin non significa essere anonimi.** Ogni transazione resta registrata per sempre, in chiaro, sulla blockchain pubblica: chiunque può consultarla. Società di analisi forense specializzate collaborano di routine con le forze dell'ordine per ricostruire il flusso di fondi tra wallet, e il punto debole arriva quasi sempre quando qualcuno converte le criptovalute in euro o dollari su un exchange regolamentato, che per legge deve identificare i propri utenti. Diversi casi giudiziari di rilievo — Silk Road compreso — sono stati risolti seguendo il denaro sulla blockchain, non violando Tor.

**Un marketplace che funziona normalmente non è garanzia di nulla.** Il caso più clamoroso è quello di Hansa Market: quando la polizia olandese ne prese il controllo nel giugno 2017, non lo chiuse — lo tenne operativo sotto copertura per circa un mese, proprio mentre migliaia di utenti dell'appena chiuso AlphaBay (chiusura coordinata sotto il nome Operation Bayonet) vi si riversavano credendolo un rifugio sicuro. In quelle settimane la polizia olandese registrò le password in chiaro, intercettò gli ordini prima che i messaggi venissero cifrati con PGP e raccolse oltre 10.000 indirizzi di consegna reali, poi condivisi con Europol. Un sito che accetta il login e processa un ordine normalmente può comunque essere gestito, in quel momento, da chi sta già indagando su chi lo usa.

## Leggende del Dark Web: Cosa è Vero e Cosa no

Intorno al dark web circolano da anni storie che ne hanno costruito la fama sinistra, ma che reggono male a un controllo dei fatti.

**Le "Red Room".** La leggenda più diffusa parla di siti nascosti dove sarebbe possibile assistere in diretta a violenze estreme pagando in criptovaluta. Nonostante decine di racconti online, non esistono prove pubbliche affidabili che una Red Room di questo tipo abbia mai funzionato davvero come descritto: la maggior parte dei casi documentati si è rivelata una truffa, in cui alla vittima viene chiesto un pagamento per uno streaming che poi non esiste, seguito da ulteriori richieste di denaro.

**Sicari a pagamento.** Diversi siti .onion nel tempo hanno dichiarato di offrire omicidi su commissione. Le indagini che li hanno seguiti non hanno mai documentato un caso in cui un omicidio sia stato effettivamente compiuto tramite uno di questi servizi: quasi tutti si sono rivelati raggiri per estorcere denaro a chi ci credeva, e in alcuni casi chi ha tentato di commissionarli è finito comunque sotto processo per il solo tentativo.

**I "livelli segreti" di internet.** Una storia molto popolare su forum e video descrive il web come diviso in livelli sempre più nascosti e pericolosi. Non corrisponde a nessuna struttura tecnica reale — internet non è organizzato a livelli — ed è nata come pura creepypasta, la stessa categoria di leggenda urbana di internet a cui appartengono le Red Room.

Il filo conduttore è sempre lo stesso: paura e curiosità sono l'esca perfetta per una truffa. Chi entra nel dark web aspettandosi il peggio scopre spesso che il rischio reale è molto più banale — essere raggirato, infettato o identificato — non le storie horror che circolano online.

## Il Dark Web è Illegale?

No — e vale la pena essere chiari su questo, perché è il punto più frainteso dell'intero argomento. Usare Tor e accedere al dark web non costituisce reato in Italia né nella maggior parte dei paesi del mondo, con l'eccezione di stati come Cina, Russia, Iran e Turchia, dove è la rete Tor stessa a essere limitata o vietata. Quello che resta illecito sono le attività specifiche eventualmente compiute una volta dentro: acquistare beni o servizi illegali, accedere o diffondere contenuti proibiti, commettere frodi o accessi abusivi a sistemi informatici — esattamente gli stessi reati che restano tali sul resto di internet, non regole nuove create dal contesto. "Ho trovato questo per caso" non è una difesa legale valida se, una volta trovato contenuto illegale, lo si scarica, conserva o ridistribuisce consapevolmente.

## FAQ

**Cos'è il dark web?** È la porzione di internet raggiungibile solo con software specifici come Tor, progettata per garantire anonimato sia a chi pubblica sia a chi naviga — una piccola parte del più ampio deep web (tutto ciò che i motori di ricerca non indicizzano).

**Qual è la differenza tra deep web e dark web?** Il deep web è tutto il contenuto non indicizzato da Google (email, database, intranet aziendali) ed è per la maggior parte assolutamente legale e quotidiano. Il dark web è una sua sottoparte specifica, accessibile solo con Tor o software simili e progettata per l'anonimato avanzato.

**Come si accede al dark web?** Scaricando Tor Browser dal sito ufficiale del Tor Project — l'unica fonte sicura — e navigando come con un browser normale verso indirizzi .onion.

**Usare Tor è legale in Italia?** Sì, con la stessa base giuridica di qualsiasi altro software: l'uso di Tor non rende di per sé illegale un'attività, quello che può diventare reato è il comportamento specifico tenuto, non lo strumento usato per tenerlo.

**Cosa si trova davvero nel dark web?** Un mix di servizi legittimi per privacy e libertà d'informazione (whistleblowing, specchi di testate censurate altrove) e mercati o forum dedicati ad attività illegali — la percezione mediatica enfatizza la seconda categoria più di quanto rifletta l'uso reale della rete.

**È pericoloso navigare nel dark web?** Il rischio principale non è legale ma pratico: malware distribuito tramite download, truffe su marketplace senza alcuna garanzia, e l'assenza totale di moderazione o controllo qualità su qualsiasi contenuto trovato.

**Serve una VPN per entrare nel dark web?** No, non è necessaria: Tor Browser da solo è già pensato per essere sicuro di default, e lo stesso Tor Project sconsiglia di abbinare una VPN a meno di saperla configurare correttamente insieme a Tor.

**Tor nasconde completamente l'identità?** No. Riduce moltissimo la tracciabilità del traffico, ma un login con account personali, dati inseriti in un form o un plugin del browser possono comunque identificarti — l'anonimato dipende anche dal comportamento, non solo dallo strumento.

**Si può usare Tor senza entrare nel dark web?** Sì. La maggior parte di chi usa Tor Browser lo fa per navigare in modo anonimo sul web normale, senza mai visitare un sito .onion — Tor e dark web non sono sinonimi.

**Google indicizza il dark web?** No. I siti .onion non fanno parte del sistema DNS tradizionale e non sono raggiungibili dai crawler dei motori di ricerca standard: servono motori dedicati che effettuano il proprio crawling dentro la rete Tor.

**Le Red Room esistono davvero?** Non ci sono prove pubbliche affidabili che dimostrino l'esistenza di una Red Room funzionante come la descrive la leggenda. La maggior parte dei casi documentati riconducibili a questo nome si è rivelata una truffa a scopo di estorsione.

**Qual è la differenza tra Tor e dark web?** Tor è il software e la rete usati per raggiungere il dark web in modo anonimo; il dark web è l'insieme dei contenuti e servizi raggiungibili tramite quella rete. Si può usare Tor senza mai toccare il dark web, ma non si può accedere al dark web senza un software come Tor.
