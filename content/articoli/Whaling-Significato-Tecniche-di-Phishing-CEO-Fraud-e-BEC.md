---
title: 'Whaling: Significato, Tecniche di Phishing, CEO Fraud e BEC'
slug: whaling
description: 'Whaling: cos''è, come funziona un attacco ai dirigenti, differenze con spear phishing e BEC, casi reali di deepfake e difesa della cybersecurity aziendale.'
image: /whaling-phishing-dirigenti-ceo-frode-aziendale.webp
draft: true
date: 2026-10-22T00:07:59.645Z
lastmod: 2026-10-22T00:08:01.032Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Whaling
  - CEO Fraud
  - Spear Phishing
  - Business Email Compromise
  - Social Engineering
---

# Whaling: Cos'è l'Attacco ai Dirigenti e Come Funziona

Il **whaling** è una forma di [spear phishing](/articoli/spear-phishing/) rivolta specificamente a dirigenti, CEO, CFO e membri del consiglio di amministrazione: le "balene" (*whales*) da cui prende il nome, bersagli di alto valore per via dell'autorità e dell'accesso che hanno all'interno di un'organizzazione. Funziona in due direzioni: un dirigente può essere il **bersaglio diretto** di un messaggio ingannevole, oppure un attaccante può **impersonare** quel dirigente per dare ordini a chi lavora sotto la sua autorità, tipicamente al reparto finanziario.

Con l'arrivo di cloni vocali e video deepfake, il whaling è passato dalla semplice email contraffatta a videochiamate che imitano in tempo reale l'aspetto e la voce di un dirigente reale, con perdite che in alcuni casi hanno superato le decine di milioni di dollari in un solo episodio.

## Whaling: le due direzioni dell'attacco

Un punto spesso frainteso: non ogni attacco che coinvolge un dirigente è whaling. La definizione più rigorosa distingue:

| Direzione                                  | Cosa succede                                                                                                                                                |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Il dirigente come bersaglio**            | L'attaccante inganna direttamente il CEO o un altro dirigente, per esempio con una pagina di raccolta credenziali su misura o una richiesta legale fittizia |
| **Il dirigente come identità impersonata** | L'attaccante finge di essere il dirigente per convincere qualcun altro (tipicamente la finanza) a eseguire un pagamento o concedere un accesso              |

Solo il primo caso rientra nella definizione più stretta di whaling; il secondo, pur essendo strettamente collegato e spesso trattato insieme, è più propriamente una forma di [Business Email Compromise](/articoli/business-email-compromise/) basata sull'impersonificazione di un dirigente. Nella pratica, i due schemi vengono spesso discussi insieme perché condividono la stessa logica: sfruttare l'autorità di una figura di vertice.

## Come funziona un attacco di whaling

1. **Ricognizione approfondita**: l'attaccante studia il bersaglio tramite LinkedIn, dichiarazioni pubbliche, interviste, il sito aziendale e, quando disponibili, registrazioni audio o video pubbliche (conferenze, earning call, interviste).
2. **Scelta del momento**: spesso l'attacco viene sincronizzato con eventi reali: un cambio di CEO, un'acquisizione in corso, un viaggio di lavoro del dirigente, un periodo di maggiore attività (chiusura trimestre).
3. **Costruzione del pretesto**: una richiesta che sfrutta l'autorità del dirigente coinvolto, spesso con elementi di riservatezza e urgenza.
4. **Canale**: può essere una semplice email, ma sempre più spesso un messaggio WhatsApp, una chiamata vocale clonata o una videochiamata con deepfake.
5. **Esecuzione**: la vittima, convinta di rispondere a un'istruzione legittima, autorizza un bonifico, un accesso o la condivisione di informazioni sensibili.

Un fattore psicologico chiave è il cosiddetto ***authority bias***, il bias dell'autorità: una richiesta percepita come proveniente da qualcuno con potere decisionale superiore tende a ricevere meno verifiche e più obbedienza automatica, anche quando qualcosa nel messaggio dovrebbe insospettire.

## Whaling con l'intelligenza artificiale: dalla voce al video

Il whaling si è evoluto rapidamente negli ultimi anni: dall'email contraffatta (la forma classica, pre-2020), ai cloni vocali telefonici, fino alle **videochiamate interamente deepfake** degli ultimi anni.

Il caso più noto e meglio documentato è quello dell'azienda di ingegneria **Arup**: un dipendente dell'ufficio di Hong Kong ha partecipato a una videoconferenza in cui ogni altro partecipante, compresi i dirigenti senior, era un'identità digitalmente clonata, con immagini e voci generate artificialmente per impersonare persone reali. Convinto di parlare con i suoi reali superiori, il dipendente ha effettuato **15 bonifici verso cinque conti**, per una perdita complessiva di circa **25 milioni di dollari** (circa 200 milioni di dollari di Hong Kong). Arup ha confermato che i propri sistemi interni non erano stati compromessi: l'attacco si è basato interamente sull'inganno multimediale, non su un'intrusione tecnica. Il caso, riportato dal Financial Times, è diventato un punto di riferimento per descrivere l'evoluzione del whaling verso attacchi multicanale.

Un altro caso noto, sventato prima che causasse danni, ha coinvolto un tentativo di clonazione vocale del CEO di **Ferrari** su WhatsApp, accento del sud Italia incluso, per pressare un dirigente su una presunta acquisizione riservata: il tentativo è fallito quando il dirigente ha chiesto, come verifica, quale libro il CEO gli avesse consigliato pochi giorni prima, domanda a cui l'attaccante non ha saputo rispondere.

## Whaling prima dell'IA: il caso Mattel

Il whaling non è un fenomeno nato con i deepfake. Nel 2015, poco dopo la nomina di un nuovo CEO in **Mattel**, un dirigente finanziario ha ricevuto un'email che sembrava provenire proprio dal nuovo amministratore delegato, con la richiesta di autorizzare un pagamento da **3 milioni di dollari** verso un conto in Cina. Il messaggio arrivava in un momento di transizione interna, quando le procedure erano meno consolidate, e rispecchiava da vicino il normale flusso di approvazione dell'azienda. Nessun malware, nessuna vulnerabilità tecnica: solo tempismo, conoscenza dei processi interni e impersonificazione credibile. In questo caso, a differenza di molti altri, l'azienda riuscì poi a recuperare il denaro grazie a una rapida collaborazione tra banche e autorità.

## Esempi delle tattiche più comuni di whaling

| Tattica                               | Come si presenta                                                                                                                 |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **Ordine di bonifico del CEO**        | Un'email o un messaggio che sembra del CEO, con richiesta di un pagamento urgente e riservato                                    |
| **Acquisizione riservata**            | Un finto consulente legale o un finto CEO coinvolge il bersaglio in un'operazione "segreta" che richiede un bonifico             |
| **Richiesta di dati fiscali/payroll** | Un messaggio, apparentemente dalle risorse umane o dal CEO, chiede moduli fiscali o buste paga dei dipendenti                    |
| **Chiamata o video con voce clonata** | Una richiesta di approvazione urgente arriva tramite una chiamata o videochiamata che imita voce e aspetto di un dirigente reale |
| **Furto di credenziali su misura**    | Una pagina di login contraffatta, costruita specificamente per imitare strumenti usati dal dirigente bersaglio                   |
| **Falso supporto IT**                 | Una richiesta di accesso o reset credenziali rivolta all'help desk, sfruttando l'autorità percepita del dirigente impersonato    |

Vale la pena notare che non tutti i tentativi di whaling puntano al denaro: alcuni cercano solo credenziali o accessi, da sfruttare in un secondo momento.

## Perché il whaling è particolarmente redditizio

* **Autorità massima**: un ordine che sembra venire dal CEO raramente viene messo in discussione da chi lo riceve.
* **Accesso privilegiato**: un dirigente compromesso o impersonato può sbloccare pagamenti di importo molto più alto rispetto a un dipendente qualunque.
* **Superficie pubblica ampia**: i dirigenti hanno spesso una forte presenza pubblica (interviste, conferenze, social), che fornisce agli attaccanti abbondante materiale per la ricognizione e, oggi, anche per clonare voce e aspetto.
* **Canali meno monitorati**: WhatsApp, SMS e chiamate personali spesso sfuggono ai controlli di sicurezza aziendali pensati solo per la posta elettronica.

## Come riconoscere un tentativo di whaling

| Segnale                                                | Perché deve insospettire                                                                                   |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| **Richiesta di massima riservatezza**                  | Un'operazione finanziaria legittima raramente richiede di non parlarne con nessuno                         |
| **Urgenza abbinata all'assenza del dirigente reale**   | "Sono in viaggio, non posso essere chiamato" è una scusa ricorrente per impedire la verifica               |
| **Canale insolito**                                    | Un ordine importante che arriva solo via WhatsApp o chat, mai confermato su un canale aziendale verificato |
| **Bypass delle procedure normali**                     | "Fallo solo questa volta, te lo confermo dopo"                                                             |
| **Richiesta impossibile da verificare in tempo reale** | Una videochiamata che si interrompe stranamente non appena si fanno domande personali di controllo         |

## Come proteggersi dal whaling

* **Procedura di verifica indipendente**: qualsiasi richiesta finanziaria rilevante va confermata su un canale diverso da quello con cui è arrivata, chiamando un numero noto in anticipo, non quello fornito nel messaggio.
* **Domanda di controllo concordata**: per i dirigenti più esposti, stabilire in anticipo una domanda o un codice che solo loro conoscono, utile proprio contro i cloni vocali e video.
* **Doppia approvazione per pagamenti rilevanti**: nessuna autorizzazione unica, specialmente se la richiesta arriva "dall'alto" con fretta.
* **Formazione specifica per i dirigenti**: non la formazione anti-phishing generica rivolta a tutti i dipendenti, ma scenari costruiti sui canali e le situazioni reali che un dirigente incontra (WhatsApp, videochiamate, richieste di acquisizioni riservate).
* **Limitare l'esposizione pubblica non necessaria**: ogni intervista, conferenza o video pubblico di un dirigente è materiale utilizzabile per clonare voce e aspetto.
* **Monitoraggio di domini e profili simili**: registrare o sorvegliare varianti del dominio aziendale e profili social che impersonano i vertici dell'azienda.

## Domande frequenti sul whaling

### Cos'è il whaling?

Una forma di spear phishing rivolta specificamente a dirigenti e membri del consiglio di amministrazione, che può coinvolgerli come bersaglio diretto o come identità impersonata verso altri dipendenti.

### Qual è la differenza tra whaling e spear phishing?

Il whaling è un sottoinsieme dello spear phishing: stessa tecnica di phishing mirato, ma specificamente rivolta a figure di altissimo livello in un'organizzazione.

### Qual è la differenza tra whaling e BEC?

Quando un attaccante impersona un dirigente per ordinare un pagamento a terzi, lo schema è più propriamente una forma di Business Email Compromise basata sull'impersonificazione esecutiva; i due termini vengono spesso trattati insieme perché condividono la stessa logica.

### Il whaling richiede sempre strumenti sofisticati come i deepfake?

No. Il caso Mattel del 2015, da 3 milioni di dollari, ha usato solo tempismo, conoscenza dei processi interni e impersonificazione via email, senza malware né strumenti avanzati.

### Quanto può costare un attacco di whaling?

Le perdite documentate vanno da poche centinaia di migliaia a decine di milioni di dollari in un singolo episodio, come nel caso Arup (circa 25 milioni di dollari).

### Come ci si difende da un CEO deepfake in videochiamata?

Con una verifica indipendente su un canale diverso e, per i casi più delicati, una domanda di controllo concordata in anticipo che solo il dirigente reale può conoscere.

### Il whaling è una forma di spear phishing?

Sì. Il whaling è generalmente considerato un sottotipo di spear phishing in cui il bersaglio è specificamente una persona di alto profilo, come un CEO o un altro dirigente.

### Come verifico che un messaggio o una chiamata del CEO sia autentica?

Non affidarti solo all'indirizzo email, al numero di telefono, alla voce o al video: per richieste finanziarie o riservate usa sempre un secondo canale già noto in anticipo e una procedura di approvazione indipendente.

### I dirigenti sono consapevoli di essere bersagli ad alto rischio?

Spesso meno di quanto dovrebbero: la formazione sulla sicurezza è ancora troppo spesso generica e rivolta a tutti i dipendenti allo stesso modo, invece di affrontare gli scenari specifici che un dirigente incontra.

### Il whaling usa solo l'email come canale?

No. Le campagne più recenti combinano email, SMS, WhatsApp, chiamate vocali e videochiamate, spesso in sequenza nello stesso attacco.
