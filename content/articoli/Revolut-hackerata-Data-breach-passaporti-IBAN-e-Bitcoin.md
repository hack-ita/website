---
title: 'Revolut hackerata? Data breach: passaporti, IBAN e Bitcoin'
slug: revolut-data-breach-richiesta-governativa-falsa
description: 'Revolut conferma un data breach: finta richiesta governativa, passaporti e cronologie Bitcoin esposti. Dati pubblicati online, richiesti 10.000 BTC di riscatto.'
image: /revolut-data-breach-hackerata-passaporti-bitcoin.webp
draft: false
date: 2026-09-15T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - tecniche
tags:
  - Revolut
  - Data Breach
  - Social Engineering
  - Bitcoin
featured: true
---

# Revolut, data breach dopo una falsa richiesta governativa: passaporti e cronologie Bitcoin esposti

**Revolut ha confermato il 12 settembre 2026 un data breach che ha coinvolto un numero “molto limitato” di clienti.** Non si è trattato di un attacco diretto ai sistemi dell'azienda: gli aggressori hanno sfruttato una **falsa richiesta governativa**, utilizzando un indirizzo email legittimo di un'agenzia pubblica per convincere Revolut a consegnare dati sensibili.

Tra le informazioni ottenute attraverso la frode figurano **copie di passaporti e patenti, selfie utilizzati per la verifica dell'identità, estratti conto, IBAN e cronologie delle transazioni, comprese quelle in Bitcoin**. Dal 13 settembre, parte del materiale è stata pubblicata online dagli stessi attaccanti, che hanno minacciato nuove pubblicazioni quotidiane.

Gli aggressori avrebbero inoltre richiesto un **riscatto di 10.000 Bitcoin**, pari a circa 780 milioni di dollari al momento delle prime segnalazioni, ma l'importo non è stato confermato da Revolut né da fonti indipendenti. **Al momento non è stato identificato alcun gruppo ransomware o APT come responsabile dell'attacco.**
.

## Incidente in breve

| Campo                                 | Dettaglio                                                                                                                                                                                                 |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Organizzazione colpita                | Revolut                                                                                                                                                                                                   |
| Piattaforma/processo coinvolto        | Processo interno di risposta alle richieste dati di autorità governative ("Emergency Data Request")                                                                                                       |
| Data accesso non autorizzato          | Non applicabile in senso classico: nessuna intrusione nei sistemi Revolut. Data esatta dell'invio/soddisfacimento della richiesta fraudolenta non nota (precedente all'11 settembre 2026)                 |
| Data scoperta                         | 11 settembre 2026 (blocco dell'indirizzo email fraudolento da parte di Revolut)                                                                                                                           |
| Data divulgazione pubblica            | Notifiche ai clienti l'11 settembre 2026 (21:59 UTC); resa pubblica il 12 settembre da Mark Karpelès e ZachXBT, confermata da Revolut a TechCrunch lo stesso giorno                                       |
| Organizzazioni/persone coinvolte      | Numero non divulgato, descritto da Revolut come "molto limitato"; secondo l'investigatore ZachXBT si tratterebbe soprattutto di utenti ad alto patrimonio legati al mondo crypto                          |
| Tipo di dati coinvolti                | Nome, data di nascita, occupazione, indirizzo, email, telefono, copie di documenti d'identità, selfie di verifica, estratti conto, IBAN, cronologia di prelievi e transazioni (incluse quelle in Bitcoin) |
| Dati effettivamente pubblicati online | Solo una parte del materiale ottenuto: documenti d'identità e selfie attribuiti ad alcune persone identificate pubblicamente, a partire dal 13 settembre 2026                                             |
| Gruppo responsabile                   | Rivendicato da un soggetto che si fa chiamare "IAmNotAVillain" (rivendicazione del 14 settembre 2026, non confermata indipendentemente né da Revolut)                                                     |
| Rivendicazione                        | Sì — pubblicazione parziale dei dati e richiesta di riscatto (10.000 BTC), non confermata ufficialmente da Revolut                                                                                        |
| IOC pubblici                          | No                                                                                                                                                                                                        |

## Rigore sui termini: tre cose diverse, non sinonimi

Vale la pena chiarire subito tre distinzioni che nel racconto della vicenda vengono spesso appiattite.

La prima riguarda **come sono usciti i dati**: qui non c'è stato un accesso non autorizzato ai sistemi di Revolut. L'azienda ha dichiarato che "i sistemi Revolut e i fondi dei clienti non sono stati compromessi". I dati non sono stati sottratti con un attacco informatico ai server: sono stati **consegnati** dal personale di Revolut a un soggetto che si è finto un'autorità legittima, nel rispetto (apparente) di una procedura normale. È una distinzione tecnica importante, ma che — come ha notato un giornalista che ha seguito la vicenda — "non elimina il problema di responsabilità di chi ha in mano quei dati": per i clienti coinvolti il risultato pratico, cioè l'esposizione di documenti d'identità e dati finanziari a un soggetto non autorizzato, è lo stesso di un data breach tradizionale.

La seconda distinzione è tra **dati esposti** e **dati pubblicati**. "Esposti" indica l'insieme dei dati che Revolut ha consegnato rispondendo alla richiesta fraudolenta — l'intero pacchetto descritto sopra. "Pubblicati" indica invece solo quella parte di quei dati che gli attaccanti hanno effettivamente diffuso online, su X e Telegram, a partire dal 13 settembre. Le fonti disponibili non affermano che l'intero pacchetto di dati consegnato sia stato reso pubblico: al momento risultano pubblicati documenti d'identità e selfie relativi ad alcune persone identificabili, non necessariamily l'intero set di dati di tutti i clienti coinvolti.

La terza distinzione, meno immediata ma centrale per capire l'incidente, è tra **autenticazione** e **autorizzazione**. L'indirizzo email usato per la richiesta era autentico: apparteneva davvero a un'agenzia governativa, quindi ha superato qualunque controllo basato sul "chi sta scrivendo". Ma il fatto che il mittente fosse autentico non significa che quella specifica richiesta fosse autorizzata da chi di dovere all'interno dell'agenzia: potrebbe trattarsi di un account compromesso e usato senza che l'agenzia ne fosse a conoscenza. Autenticazione (l'indirizzo è reale) e autorizzazione (chi lo controlla in quel momento ha davvero il diritto di fare questa richiesta) sono due cose diverse, ed è proprio la seconda verifica che, stando alle fonti disponibili, sembra essere mancata.

## Cosa è successo, spiegato semplicemente

Revolut, una delle fintech più diffuse al mondo con oltre 80 milioni di utenti (anche in Italia è tra le app bancarie e di pagamento più usate), riceve regolarmente richieste di dati da parte di autorità governative e forze dell'ordine — è una prassi normale per qualsiasi banca o istituto finanziario, spesso legata a indagini o emergenze che richiedono risposte rapide.

Il problema è che qualcuno ha ottenuto l'uso di una casella email reale di un'agenzia governativa (Revolut non ha specificato quale, né il paese di provenienza) e l'ha usata per inviare una richiesta di dati che appariva del tutto legittima, proveniente da un dominio autentico. Revolut ha risposto fornendo le informazioni richieste, "nella ragionevole convinzione che si trattasse di una richiesta governativa autentica". Solo in un secondo momento l'azienda ha individuato l'anomalia, bloccato l'indirizzo e avvisato l'agenzia coinvolta, le forze dell'ordine, le autorità di protezione dati e i regolatori finanziari.

Secondo il sito The Record, il dominio email compromesso apparterrebbe a un'agenzia governativa italiana: un dettaglio non confermato pubblicamente da Revolut e non ripreso da altre fonti verificate, quindi da trattare con cautela.

Tra i clienti coinvolti risultano, secondo dati emersi pubblicamente, l'ex CEO di Mt. Gox Mark Karpelès, l'imprenditore crypto Marc Zeller, il tennista Alexander Shevchenko e Felix Römer, amministratore delegato del casinò online in criptovalute Gamdom — un elemento che rafforza l'ipotesi di un bersaglio selezionato tra utenti ad alto patrimonio, in particolare nel settore crypto.

### Come verificare se si è coinvolti

Al momento non risulta pubblicato alcun elenco ufficiale o verificabile delle persone coinvolte: le uniche identità note sono emerse perché alcuni interessati (come Karpelès) hanno reso pubblica di propria iniziativa la notifica ricevuta, o perché i loro documenti sono comparsi tra il materiale diffuso dagli attaccanti. Chi è stato effettivamente coinvolto dovrebbe aver ricevuto (o dovrebbe ricevere) una comunicazione diretta da Revolut, via email, con l'indicazione di quali dati specifici sono stati esposti nel proprio caso.

Per questo motivo, qualunque messaggio relativo alla vicenda — anche uno che sembra citare dati reali del proprio conto — va verificato esclusivamente attraverso i canali ufficiali Revolut (app o sito, senza passare da link o numeri indicati nel messaggio stesso). Non esiste un modo per "controllare" autonomamente se si è tra le persone coinvolte al di fuori di una comunicazione diretta dell'azienda.

### Perché questa combinazione di dati è pericolosa

Presi singolarmente, molti dei dati coinvolti (un indirizzo, un numero di telefono) hanno un valore limitato. Il problema è la combinazione: documento d'identità, selfie di verifica, dati anagrafici, IBAN, movimenti finanziari, transazioni in criptovalute e recapiti, tutti insieme e riferiti alla stessa persona, costituiscono quello che un esperto di sicurezza ha definito "un kit completo per il furto d'identità". Con questo set di informazioni un attaccante ha, in un colpo solo, sia i mezzi per dimostrare falsamente di "essere" la vittima presso terzi, sia la conoscenza dettagliata della sua situazione finanziaria reale per rendere credibile qualunque approccio successivo.

Concretamente, questa combinazione di dati si presta a: **impersonificazione** della vittima presso altri servizi finanziari o presso Revolut stessa; **phishing personalizzato**, con messaggi che citano correttamente saldo, transazioni o beneficiari reali per apparire legittimi; **vishing** (truffe telefoniche) in cui chi chiama dimostra di "conoscere" già il conto della vittima; **tentativi di recupero account** basati sui documenti d'identità rubati; **frodi finanziarie** come richieste di credito o apertura di conti a nome della vittima; e, per i clienti legati al mondo crypto, un **targeting specifico** verso chi ha cronologie di transazioni in Bitcoin visibili, un profilo particolarmente interessante per chi cerca patrimoni in criptovalute da colpire con truffe mirate.

### Cosa fare se si teme di essere coinvolti

Chi ha ricevuto (o teme di dover ricevere) una notifica da Revolut dovrebbe: verificare i movimenti sul conto, le carte attive, i beneficiari salvati e i dispositivi collegati direttamente dall'app o dal sito ufficiale, senza usare link o numeri di telefono ricevuti via email/SMS/WhatsApp che si presentano come "assistenza sicurezza Revolut"; diffidare di chiunque contatti telefonicamente citando i dati esposti nella truffa, anche se sembra a conoscenza di dettagli reali del proprio conto; monitorare eventuali richieste di credito o apertura di conti non richieste, ad esempio tramite il proprio report creditizio.

## Valutazione editoriale: cosa ha fatto Revolut, cosa resta poco chiaro

Sul fronte della risposta immediata, le fonti descrivono un comportamento in linea con le buone pratiche: Revolut ha rilevato l'anomalia, bloccato l'indirizzo email fraudolento, notificato tempestivamente le autorità competenti (l'agenzia coinvolta, le forze dell'ordine, i garanti privacy, i regolatori finanziari) e contattato individualmente i clienti interessati specificando quali dati li riguardavano — un livello di trasparenza verso gli utenti coinvolti superiore alla semplice comunicazione generica.

Restano però almeno due punti poco chiari nella comunicazione pubblica dell'azienda. Il primo è la scelta di non rivelare quale agenzia governativa (né quale paese) sia stata impersonata: una reticenza comprensibile per motivi di indagine in corso, ma che lascia i clienti senza un quadro completo di cosa sia effettivamente accaduto. Il secondo è il numero delle persone coinvolte, descritto solo come "molto limitato" senza alcuna cifra: una definizione che, alla luce della quantità di dati per singolo utente (documenti, selfie, dati finanziari e di transazione), lascia margini di interpretazione molto ampi.

Un giornalista che ha seguito la vicenda ha inquadrato bene il problema di fondo: gli istituti finanziari sono addestrati a fidarsi delle richieste che arrivano da indirizzi email governativi autentici, e questa fiducia — non un difetto tecnico dei sistemi Revolut — è ciò che è stato sfruttato. È un'osservazione corretta, ma non elimina un punto: come chiarito sopra, un indirizzo autentico non equivale a una richiesta autorizzata. Le fonti non riportano se Revolut disponesse, prima dell'incidente, di controlli aggiuntivi per le richieste governative "urgenti", né se ne siano stati introdotti dopo. Alcune misure che, in generale, riducono il rischio di questo tipo di frode e che le fonti non confermano essere già in uso da Revolut includono: la verifica della richiesta tramite un secondo canale indipendente (ad esempio contattando l'agenzia ai recapiti ufficiali pubblicati, non a quelli citati nella richiesta stessa); una validazione più rigorosa dell'identità e dell'autorità di chi invia la richiesta; l'escalation interna obbligatoria per richieste che coinvolgono dati particolarmente sensibili o un numero elevato di persone; il logging e l'audit sistematico delle richieste EDR ricevute ed evase; e la limitazione dei dati restituiti al minimo strettamente necessario a soddisfare la richiesta, invece di un pacchetto completo per ogni persona coinvolta.

## Analisi tecnica

### Vettore d'attacco

Il vettore confermato dalle fonti è una frode nota come **"richiesta di dati in emergenza" (Emergency Data Request, EDR) fraudolenta**. La catena, per come è ricostruibile dalle fonti disponibili, è questa: un account o una casella email appartenente a un'agenzia governativa finisce nelle mani di un soggetto non autorizzato (le fonti non specificano se per compromissione diretta dell'account, furto di credenziali o altro accesso non autorizzato al dominio); da quell'indirizzo autentico viene inviata a Revolut una richiesta di dati formulata come urgente; Revolut la valuta e, non disponendo di (o non applicando) una verifica indipendente dell'autorizzazione della richiesta, la soddisfa; solo in seguito l'anomalia viene individuata e l'indirizzo bloccato. Il punto debole non è tecnico in senso stretto — non ci sono exploit, malware o vulnerabilità software coinvolte — ma di processo: manca un secondo controllo che distingua un mittente autentico da una richiesta effettivamente autorizzata.

Questa tecnica non è nuova: nel 2021-2022 il gruppo LAPSUS$ ottenne dati sensibili da Apple, Meta e Discord usando lo stesso schema, sfruttando account di forze dell'ordine compromessi per inviare richieste di emergenza che le aziende soddisfacevano senza verifica indipendente. Nel novembre 2024 l'FBI ha pubblicato un avviso pubblico specifico sul crescente mercato criminale di accessi a caselle email governative compromesse, proprio a scopo di richieste EDR fraudolente — un contesto che rende l'incidente Revolut tutt'altro che isolato nel panorama delle minacce note. Ne avevamo già parlato in generale nel nostro approfondimento sui [vettori di phishing e social engineering usati nel red teaming](https://hackita.it/articoli/phishing/), tecnica concettualmente vicina a questo tipo di impersonificazione, anche se qui il bersaglio non è un dipendente preso di mira con un'email di phishing, ma direttamente il processo aziendale con cui l'azienda decide a chi consegnare dati sensibili.

Il motivo per cui questo vettore è particolarmente efficace contro aziende come Revolut è strutturale: una fintech con decine di milioni di utenti gestisce, per ciascun cliente, esattamente il tipo di dati (identità, documenti, cronologia finanziaria) che le autorità richiedono legittimamente nell'ambito di indagini — ed è quindi organizzata per rispondere a queste richieste in tempi rapidi, spesso proprio perché "emergenza" implica urgenza. La stessa caratteristica che rende il processo utile alle forze dell'ordine legittime (velocità di risposta, fiducia nel mittente istituzionale) è quella che un attaccante sfrutta: più l'azienda gestisce dati sensibili su larga scala e più è pressata a rispondere in fretta, più il vettore diventa redditizio per chi riesce a impersonare un'autorità.

### Causa iniziale e fase di divulgazione: due momenti distinti

Come nella [cyber kill chain](https://hackita.it/articoli/killchain/), è utile tenere separati due eventi che nel racconto della vicenda tendono a mescolarsi. La **causa iniziale** dell'incidente è la richiesta fraudolenta e la sua accettazione da parte di Revolut: è qui che i dati sono usciti dal perimetro dell'azienda, in un momento non precisato prima dell'11 settembre 2026. La **fase di divulgazione**, iniziata il 13 settembre, è invece una fase successiva e distinta: gli attaccanti, già in possesso dei dati, hanno scelto di pubblicarne una parte online come leva di estorsione. Sono due fasi con dinamiche diverse — la prima è un problema di verifica dei processi aziendali, la seconda è una tattica di pressione post-incidente — ed è la seconda, non la prima, a determinare quali dati specifici diventano effettivamente visibili pubblicamente.

### Timeline

* **Prima dell'11 settembre 2026**: la richiesta fraudolenta viene inviata e soddisfatta da Revolut. Data esatta non nota — il "dwell time" (tempo tra la consegna dei dati e la sua scoperta) non è calcolabile con le informazioni pubblicamente disponibili.
* **11 settembre 2026**: Revolut individua l'anomalia, blocca l'indirizzo email fraudolento e, alle 21:59 UTC, inizia a notificare individualmente i clienti coinvolti.
* **12 settembre 2026**: Mark Karpelès e l'investigatore ZachXBT rendono pubblica la notifica ricevuta; Revolut conferma la vicenda a TechCrunch, descrivendola come una truffa di impersonificazione e precisando che sistemi e fondi non sono stati compromessi. In questa fase gli attaccanti non hanno ancora pubblicato materiale: si tratta di notifiche dell'azienda, non di una rivendicazione da parte di chi ha ottenuto i dati.
* **13 settembre 2026**: gli attaccanti iniziano a pubblicare online, su X e Telegram, parte del materiale ottenuto — in particolare documenti e selfie attribuiti al tennista Alexander Shevchenko e a Felix Römer (CEO di Gamdom). Le fonti disponibili non specificano se un soggetto terzo abbia verificato in modo indipendente l'autenticità di questi documenti oltre alla loro provenienza dichiarata dagli attaccanti stessi e al riconoscimento pubblico da parte di alcune delle persone coinvolte.
* **14 settembre 2026**: emergono report su una richiesta di riscatto da 10.000 BTC (circa 780 milioni di dollari) per interrompere ulteriori pubblicazioni; gli attaccanti minacciano nuovi rilasci quotidiani di dati. Né l'importo né l'autenticità della richiesta di riscatto sono stati confermati da Revolut o da fonti indipendenti.
* **14 settembre 2026, ore 22:23**: un soggetto che si fa chiamare "IAmNotAVillain" rivendica, tramite un account X specializzato in sicurezza informatica, di aver compromesso da sei mesi sistemi di più dipartimenti delle forze dell'ordine italiane e di averli usati per costruire la richiesta fraudolenta a Revolut, sottraendo inoltre 147 GB di documenti interni, calendari e comunicazioni. Si tratta di una rivendicazione non confermata: nessuna fonte indipendente né alcuna autorità italiana (Polizia di Stato, Carabinieri, Guardia di Finanza) l'ha finora verificata.

### Gruppo responsabile

Fino al 14 settembre nessuna fonte affidabile aveva attribuito l'attacco a un gruppo APT o ransomware noto. In serata è comparsa una rivendicazione da parte di un soggetto che si fa chiamare "IAmNotAVillain", che sostiene di aver avuto accesso per sei mesi a sistemi di più dipartimenti delle forze dell'ordine italiane — da cui sarebbe stata costruita la richiesta fraudolenta inviata a Revolut — e di aver sottratto separatamente 147 GB di documenti interni, calendari e comunicazioni a quegli stessi enti. La rivendicazione è circolata tramite un account X di settore e non è stata confermata né da Revolut né da autorità italiane: va trattata come non verificata, non come un fatto accertato.

### IOC / TTP

Le fonti consultate non hanno pubblicato indicatori di compromissione (IOC) tecnici verificabili (indirizzi email specifici, domini, hash). Sul piano delle tecniche osservabili (TTP), l'incidente si può scomporre così: compromissione o abuso non autorizzato di un account/dominio email governativo per ottenere un mittente autentico; impersonificazione di un'autorità legittima nei confronti del personale Revolut incaricato di gestire le richieste; sfruttamento della fiducia riposta in un canale di comunicazione ritenuto affidabile ("abuse of a trusted communication channel"), senza alcun exploit tecnico contro Revolut; social engineering rivolto a un processo aziendale anziché a un singolo dipendente tramite email di phishing; divulgazione di dati (data disclosure) da parte della vittima stessa, non esfiltrazione attiva da un sistema compromesso; e, nella fase successiva, estorsione tramite pubblicazione progressiva dei dati, uno schema "extortion-only" senza cifratura di sistemi, sempre più comune nelle campagne che puntano sui dati piuttosto che sul ransomware classico.

### Impatto tecnico

Non essendoci stata intrusione nei sistemi, l'impatto si misura nella sensibilità e nell'ampiezza dei dati coinvolti per ciascun cliente interessato: documento d'identità, selfie di verifica, dati di contatto e informazioni finanziarie (estratti conto, IBAN, cronologia di prelievi e transazioni, incluse quelle in Bitcoin). Le fonti non specificano se per ogni cliente coinvolto sia stato consegnato l'intero set di dati elencato o un sottoinsieme diverso caso per caso. Revolut non ha fornito una cifra sul numero di persone coinvolte; le informazioni pubbliche indicano un gruppo ristretto ma con un profilo patrimoniale elevato. Dalle fonti disponibili non risultano movimenti laterali, escalation di privilegi o accesso a sistemi interni di Revolut: l'incidente, per quanto è dato sapere, si è generato nello scambio di una richiesta e di una risposta via email, senza che questo escluda passaggi intermedi non documentati dalle fonti consultate.

### Risposta dell'organizzazione

Revolut ha dichiarato di aver bloccato immediatamente l'indirizzo email fraudolento, avvisato l'agenzia governativa coinvolta, le forze dell'ordine, le autorità di protezione dati e i regolatori finanziari, e di aver contattato direttamente via email i clienti coinvolti indicando quali categorie di dati fossero state esposte nel loro caso specifico. Le fonti non riportano l'offerta di servizi concreti come il monitoraggio del credito o dell'identità ai clienti coinvolti, né dettagli su eventuali modifiche alla procedura interna di verifica delle richieste governative introdotte dopo l'incidente.

## Cosa sappiamo e cosa non sappiamo

**Confermato:**

* Revolut ha subito una truffa di impersonificazione di un'agenzia governativa che ha portato alla consegna di dati di un numero limitato di clienti.
* I sistemi Revolut e i fondi dei clienti non sono stati compromessi, secondo l'azienda.
* Tra i dati consegnati per effetto della frode ci sono documenti d'identità, selfie, dati finanziari e cronologie di transazioni, incluse quelle in Bitcoin.
* Gli attaccanti hanno iniziato a pubblicare online una parte di quei dati, su X e Telegram, a partire dal 13 settembre 2026.
* Non è la prima violazione per Revolut: nel 2022 un attacco aveva coinvolto i dati di 50.150 clienti.

**Non confermato:**

* Quale agenzia governativa e quale paese siano stati impersonati (l'ipotesi di un dominio italiano riportata da una singola fonte non è confermata da Revolut né da altre fonti).
* Il numero esatto di clienti coinvolti e se tutti abbiano ricevuto lo stesso set di dati esposti.
* Se il materiale finora pubblicato online rappresenti l'intero pacchetto di dati consegnato o solo una parte selezionata dagli attaccanti a scopo dimostrativo.
* L'autenticità e l'importo esatto della richiesta di riscatto (10.000 BTC).
* L'identità o l'appartenenza degli attaccanti a un gruppo specifico: la rivendicazione a nome "IAmNotAVillain" e la presunta compromissione, per sei mesi, di sistemi delle forze dell'ordine italiane non sono confermate in modo indipendente.
* Se la richiesta fraudolenta sia stata inviata da un account governativo compromesso o tramite altre modalità di accesso al dominio.

## FAQ

**I sistemi di Revolut sono stati violati con un attacco informatico?**
No. Revolut ha dichiarato che i propri sistemi e i fondi dei clienti non sono stati compromessi. I dati sono stati consegnati dal personale Revolut a un soggetto che si è finto un'autorità governativa legittima, non sottratti con un'intrusione informatica.

**Qual è la differenza tra i dati "esposti" e i dati "pubblicati"?**
"Esposti" è l'insieme dei dati che Revolut ha consegnato rispondendo alla richiesta fraudolenta. "Pubblicati" è solo la parte di quei dati che gli attaccanti hanno effettivamente diffuso online finora. Le fonti non confermano che tutto ciò che è stato esposto sia stato anche pubblicato.

**Quali dati sono stati esposti esattamente?**
Nome, data di nascita, occupazione, indirizzo, email, telefono, copie di documenti d'identità (passaporto o patente), selfie di verifica, estratti conto, IBAN e cronologia di prelievi e transazioni, incluse quelle in Bitcoin.

**Quanti clienti sono coinvolti?**
Revolut non ha fornito una cifra, parlando solo di un numero "molto limitato". Alcuni ricercatori suggeriscono che il bersaglio principale fossero utenti ad alto patrimonio legati al mondo crypto, ma non è una conferma ufficiale.

**Esiste un elenco pubblico delle persone coinvolte, o posso controllare se ci sono anche io?**
No, non esiste un elenco pubblico verificabile. Le identità note sono emerse solo perché alcune persone coinvolte hanno reso pubblica la notifica ricevuta, o perché i loro dati sono comparsi tra il materiale diffuso online. L'unico modo per sapere se si è coinvolti è una comunicazione diretta da parte di Revolut tramite i propri canali ufficiali.

**Come hanno fatto gli attaccanti a ottenere i dati senza violare i sistemi?**
Hanno usato una casella email realmente appartenente a un'agenzia governativa per inviare una richiesta di dati "urgente" che Revolut ha ritenuto autentica e a cui ha risposto. È una tecnica nota come frode delle "richieste di dati in emergenza" (EDR), già usata in passato da altri attori contro Apple, Meta e Discord.

**È stato pagato un riscatto?**
Non risulta confermato. Circolano notizie di una richiesta di 10.000 BTC (circa 780 milioni di dollari) per fermare ulteriori pubblicazioni di dati, ma né Revolut né fonti indipendenti hanno confermato l'importo o l'eventuale pagamento.

**Chi ha effettuato l'attacco?**
Il 14 settembre un soggetto che si fa chiamare "IAmNotAVillain" ha rivendicato l'attacco, sostenendo di aver usato per sei mesi accessi a sistemi delle forze dell'ordine italiane per costruire la richiesta fraudolenta. È una rivendicazione, non una conferma: nessuna fonte indipendente o autorità italiana l'ha verificata.

**Cosa devo fare se ho ricevuto una notifica da Revolut, o se qualcuno mi contatta citando questa vicenda?**
Verifica movimenti, carte, beneficiari e dispositivi collegati solo tramite l'app o il sito ufficiale Revolut, ignora link o numeri ricevuti via email/SMS/WhatsApp legati alla vicenda, e diffida di chiamate che citano i tuoi dati esposti per sembrare più credibili: qualunque comunicazione ufficiale sull'incidente va verificata solo attraverso i canali Revolut, mai rispondendo a chi ti ha contattato per primo.

## Conclusione

L'aspetto più significativo di questo incidente non è tecnico: nessun server è stato violato, nessun exploit è stato usato, nessuna vulnerabilità software è stata sfruttata. Per ottenere documenti d'identità, selfie e cronologie finanziarie di clienti di una fintech con oltre 80 milioni di utenti non è servito compromettere l'infrastruttura di Revolut — è bastato compromettere il meccanismo con cui l'azienda decide a chi consegnare quei dati quando qualcuno, apparentemente in modo legittimo, li richiede. È lo stesso schema già visto contro Apple, Meta e Discord anni fa, ed è la controprova che, in molte organizzazioni che gestiscono dati sensibili su larga scala, il punto più debole non è sempre il firewall o il codice: è spesso il processo umano che decide, sotto pressione di un'"emergenza", a chi aprire la porta.

## Fonti

* [Revolut discloses data breach exposing financial info, passports – BleepingComputer](https://www.bleepingcomputer.com/news/security/revolut-discloses-data-breach-exposing-financial-info-passports/)
* [Revolut confirms customer data breach through fake government requests – TechCrunch](https://techcrunch.com/2026/09/12/revolut-confirms-customer-data-breach-through-fake-government-requests/)
* [Revolut handed customer data to fraudsters using government email account – The Record (Recorded Future News)](https://therecord.media/revolut-scam-crypto-impersonation)
* [Revolut, dati esposti dopo una falsa richiesta governativa: il limite della fiducia digitale – Cyber Security 360](https://www.cybersecurity360.it/news/revolut-dati-esposti-dopo-una-falsa-richiesta-governativa-il-limite-della-fiducia-digitale/)
* [Caso Revolut, gli hacker rilanciano: "Compromessi anche sistemi delle forze dell'ordine italiane" – Everyeye Tech](https://tech.everyeye.it/notizie/caso-revolut-hacker-rilanciano-171-compromessi-sistemi-forze-ordine-italiane-187-900328.html)
