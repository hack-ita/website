---
title: 'Smishing: Cos''è, Tecniche e Come Difendersi dagli SMS Truffa'
slug: smishing
description: 'Smishing: cos''è il phishing via SMS, come funziona, i principali scam e attacchi in Italia, il rischio malware Android e come riconoscere e fermare le truffe.'
image: /smishing-sms-phishing-truffa-telefonica.webp
draft: true
date: 2026-10-19T23:49:22.424Z
lastmod: 2026-10-19T23:52:09.056Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Smishing
  - SMS Phishing
  - Phishing via SMS
  - Truffe SMS
  - Mobile Security
---

# Smishing: Come Funziona il Phishing via SMS

Lo **smishing** (*SMS phishing*, phishing via SMS) è una truffa o anche detto scam, in cui l'attaccante invia un messaggio di testo che sembra provenire da una banca, un corriere, un ente pubblico o un servizio di pagamento, per spingere la vittima a cliccare un link malevolo, chiamare un numero o rivelare dati sensibili. È la versione via SMS del [phishing](https://hackita.it/articoli/phishing/), e in Italia è ormai il **secondo canale di truffa digitale** dopo l'email.

Secondo i dati di Polizia Postale e associazioni dei consumatori, le email di phishing rappresentano circa il **38,1%** delle truffe segnalate, seguite dagli SMS fraudolenti con circa il **28,4%**. Il Cert-AgID, nel suo report 2025 sulle campagne malevole in Italia, ha registrato **3.620 campagne** in un anno, con un aumento di circa il **55%** degli attacchi diretti a dispositivi Android, spesso innescati proprio da un link ricevuto via SMS.

## Smishing significato: perché funziona così bene

Il termine nasce dall'unione di *SMS* e *phishing*. Funziona meglio di molte email per motivi molto concreti:

* **tasso di apertura altissimo**: gli SMS vengono letti quasi sempre e in pochi minuti, a differenza delle email che possono restare ignorate;
* **percezione di urgenza e ufficialità**: un messaggio breve, diretto, che arriva sullo smartphone personale sembra più "istituzionale" di un'email;
* **schermo piccolo**: su mobile è più difficile notare un URL sospetto o un mittente anomalo;
* **spoofing del mittente**: il nome che appare come mittente può essere falsificato e inserirsi nello stesso thread degli SMS legittimi già ricevuti dalla banca o dal corriere. Va precisato che **smishing e spoofing non sono sinonimi**: lo spoofing è la tecnica di falsificazione del mittente, spesso usata per rendere più credibile un attacco di smishing, ma non ne è l'unica forma.

## Come funziona un attacco di smishing

Lo schema tipico è semplice e diretto:

1. **Il messaggio arriva**: finge di essere banca, corriere, Agenzia delle Entrate, INPS o un circuito di pagamento.
2. **Il pretesto crea urgenza**: un pacco bloccato, un pagamento sospetto, un conto da verificare, una multa da pagare.
3. **Il link porta a un sito clone**: graficamente identico all'originale, con un dominio simile ma diverso (per esempio `poste-italiane.cc` invece di `poste.it`).
4. **La vittima inserisce dati**: credenziali, numero di carta, codice OTP, convinta di risolvere il problema indicato.
5. **I dati vengono sfruttati**: per accessi non autorizzati, pagamenti, o rivenduti.

Una variante diffusa è la richiesta di una piccola somma, spesso tra **1 e 3 euro**, per "sbloccare" una spedizione: un importo volutamente basso per non insospettire, ma che in realtà serve solo a far inserire i dati della carta di pagamento su un sito fraudolento.

## I tipi di smishing più diffusi in Italia

| Tipo                            | Come si presenta                                                                                                                                                                                        |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Pacco in giacenza**           | SMS a nome di Poste, GLS, BRT, DHL o Amazon: una consegna bloccata, un indirizzo incompleto, una tassa di sdoganamento da pagare                                                                        |
| **Falso avviso bancario**       | Un pagamento sospetto o un accesso anomalo al conto, con invito a "verificare" cliccando un link                                                                                                        |
| **Falso circuito di pagamento** | SMS a nome di Nexi o altri circuiti, che segnala un addebito sospetto e chiede di richiamare un numero con urgenza                                                                                      |
| **Falso ente pubblico**         | Agenzia delle Entrate, INPS o Comune, con richiesta di rimborso o pagamento di una presunta sanzione                                                                                                    |
| **Codice di autorizzazione**    | Il messaggio chiede di inserire un codice ricevuto via SMS su un sito falso, spesso come primo passo di un attacco che prosegue poi con una chiamata di [vishing](https://hackita.it/articoli/vishing/) |

Un caso reale: nel 2026 una campagna a tema **Nexi** ha colpito diversi utenti italiani con un SMS che segnalava un pagamento sospetto di importo elevato, invitando a chiamare un numero per "bloccare" l'operazione, un primo passo tipico verso una truffa più articolata condotta poi per telefono.

## Come riconoscere un SMS truffa

| Segnale                                        | Perché deve insospettire                                                                       |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Link con dominio simile ma diverso**         | `poste-italiane.cc`, `dhl-spedizioni.online` invece dei domini ufficiali `poste.it`, `dhl.com` |
| **Richiesta di un pagamento minimo**           | Cifre piccole (1-3 euro) per non destare sospetti, tipiche delle truffe sui pacchi             |
| **Urgenza estrema**                            | "Entro 24 ore", "azione immediata richiesta": la pressione temporale è una tecnica classica    |
| **Mittente che sembra "ufficiale"**            | Il nome del mittente può essere falsificato e comparire nello stesso thread di SMS legittimi   |
| **Richiesta di un codice OTP**                 | Nessun ente reale chiede di inserire un codice di sicurezza per "sbloccare" qualcosa           |
| **Errori di battitura o formattazione strana** | Non sempre presenti, ma restano un segnale valido quando ci sono                               |

## Cosa fare se ricevi un SMS sospetto

1. **Non cliccare il link**, nemmeno per curiosità o per "controllare".
2. **Verifica in autonomia**: apri l'app ufficiale del corriere o della banca, oppure digita a mano l'indirizzo del sito ufficiale. Se hai davvero un pacco in arrivo, il tracking sarà visibile lì.
3. **Non richiamare il numero indicato** nell'SMS: cerca tu il numero ufficiale sul sito dell'ente.
4. **Segnala il messaggio** tramite gli strumenti anti-spam messi a disposizione dal tuo operatore telefonico, e quando disponibile usa il canale di inoltro dedicato che l'operatore indica per questo tipo di segnalazioni.
5. **Se hai già cliccato o inserito dati**, cambia subito le password coinvolte, contatta la banca per bloccare carta e conto, e valuta una denuncia alla Polizia Postale.

### Ho cliccato un link di smishing: cosa fare, caso per caso

La risposta giusta dipende da cosa hai fatto dopo aver cliccato:

* **Hai solo aperto la pagina, senza inserire nulla**: chiudila e basta. Non installare nulla che ti venga proposto.
* **Hai inserito una password**: cambiala subito su quel servizio e su ogni altro dove la riutilizzavi.
* **Hai inserito i dati di una carta**: contatta immediatamente la banca per bloccarla.
* **Hai installato un file APK**: disconnetti il dispositivo da Wi-Fi e dati mobili, disinstalla l'app se riesci ad accedere alle impostazioni, e valuta un ripristino alle impostazioni di fabbrica se il telefono mostra comportamenti anomali.

## Smishing e sicurezza aziendale

Lo smishing non colpisce solo i privati: è spesso il primo passo di un attacco più ampio contro un'azienda, soprattutto quando il bersaglio è un dipendente con accesso a sistemi aziendali. Un SMS che sembra provenire dall'IT interno, con un link a una falsa pagina di login, può bastare a sottrarre credenziali aziendali vere, con conseguenze ben più gravi di una singola truffa da pochi euro: nel peggiore dei casi, l'accesso a sistemi interni e un vero e proprio [data breach](https://hackita.it/articoli/data-breach/).

Per questo, nella formazione aziendale contro il [phishing](https://hackita.it/articoli/phishing/), è sempre più comune includere anche simulazioni di smishing, non solo di email, perché i dipendenti tendono a fidarsi più facilmente di un messaggio sul telefono personale che di un'email sul computer di lavoro.

## Smishing, phishing e vishing: le differenze

|                                                     | Canale          | Esempio tipico                                        |
| --------------------------------------------------- | --------------- | ----------------------------------------------------- |
| **Phishing**                                        | Email           | Falsa fattura o avviso di sicurezza con link malevolo |
| **Smishing**                                        | SMS             | Falso avviso di consegna o blocco conto con link      |
| **[Vishing](https://hackita.it/articoli/vishing/)** | Chiamata vocale | Finto operatore bancario che chiede un OTP            |

Gli attacchi spesso combinano i canali in sequenza: un SMS che chiede di richiamare un numero, seguito da una telefonata di un finto operatore che porta avanti la truffa. Riconoscere un solo canale non basta: bisogna restare diffidenti verso tutta la catena di contatto, non solo verso il primo messaggio.

## Domande frequenti sullo smishing

### Cos'è lo smishing?

Una truffa che usa messaggi SMS per spingere la vittima a cliccare un link malevolo, chiamare un numero o rivelare dati sensibili, fingendosi una banca, un corriere o un ente pubblico.

### Perché lo smishing funziona meglio del phishing via email?

Gli SMS vengono letti quasi sempre e in tempi rapidi, danno una sensazione di maggiore ufficialità e, su schermo piccolo, è più difficile notare un link sospetto.

### Come riconosco un SMS truffa sul pacco in giacenza?

Controlla il dominio del link: se non corrisponde esattamente al sito ufficiale del corriere, è una truffa. Nessun corriere chiede pagamenti via SMS con link per sbloccare una consegna.

### Cosa devo fare se ricevo un SMS sospetto?

Non cliccare il link, verifica in autonomia tramite l'app o il sito ufficiale, e inoltra l'SMS al 7726 per segnalarlo.

### Ho già cliccato un link di smishing, cosa faccio?

Se hai inserito dati, cambia subito le password coinvolte, contatta la banca per bloccare carta e conto, e valuta una denuncia alla Polizia Postale.

### Qual è la differenza tra smishing e vishing?

Lo smishing arriva via SMS, il vishing tramite una chiamata vocale. Spesso vengono combinati: un SMS che invita a richiamare un numero, seguito da una telefonata con un finto operatore.

### Lo smishing può colpire anche le aziende?

Sì, spesso prendendo di mira dipendenti con accesso a sistemi aziendali, con SMS che imitano comunicazioni interne per rubare credenziali vere.

### Uno smishing può installare un virus sul telefono?

Sì. È un vettore in forte crescita secondo il CERT-AgID: il link porta spesso al download di un file APK malevolo, specialmente su Android, che può rubare credenziali o intercettare i codici OTP ricevuti via SMS.

### Il mittente di un SMS può essere falsificato?

Sì, tramite tecniche di spoofing: un SMS fraudolento può mostrare lo stesso nome mittente della tua banca e comparire nello stesso thread degli SMS legittimi già ricevuti.
