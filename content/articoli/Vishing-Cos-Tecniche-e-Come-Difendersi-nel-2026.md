---
title: 'Vishing: Cos''è, Tecniche e Come Difendersi nel 2026'
slug: vishing
description: 'Vishing e phishing telefonico: scopri tecniche, spoofing e voice cloning con IA, come gli attaccanti manipolano le vittime e come riconoscere una truffa.'
image: /vishing-phishing-vocale-chiamate-truffa.webp
draft: true
date: 2026-10-15T23:45:56.054Z
lastmod: 2026-10-15T23:46:16.564Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Vishing
  - Voice Phishing
  - Spoofing Telefonico
  - Phishing Telefonico
  - Social Engineering
---

# Vishing: Come Funziona il Phishing Telefonico

Il **vishing** (*voice phishing*, phishing vocale) è una truffa in cui l'attaccante telefona alla vittima fingendosi una banca, un corriere, un ente pubblico o un collega, per convincerla a rivelare dati sensibili, leggere un codice OTP o autorizzare un bonifico. È la versione "a voce" del [phishing](/articoli/phishing/), e con l'arrivo dei cloni vocali basati su intelligenza artificiale è diventata più credibile ed efficace che mai.

In Italia il fenomeno è tutt'altro che marginale: nel 2025 la Polizia Postale ha gestito oltre **27.000 casi** di cybercrime economico-finanziario, e **AGCOM ha bloccato 43 milioni di chiamate** con numeri contraffatti nello stesso anno.

## Vishing significato: perché si chiama così

Il termine nasce dall'unione di *voice* e *phishing*: come il phishing via email o SMS ([smishing](/articoli/smishing/)), il vishing punta a ingannare la vittima per farle compiere un'azione dannosa, ma usa il canale telefonico. La voce umana, in tempo reale, con la possibilità di rispondere a domande e mostrare "sicurezza", è da sempre uno dei vettori più efficaci di social engineering: una persona può fidarsi più facilmente di chi sembra parlarle davvero. Un esempio attuale di quanto queste tecniche continuino a essere utilizzate nel 2026 è la **truffa Vodafone dei falsi punti Gold Starter**, una campagna di smishing che sfrutta il nome del brand per spingere la vittima verso un sito fraudolento e raccogliere dati personali e della carta: [leggi l'analisi della truffa Vodafone su HackITA](/articoli/vodafone-7415-punti-truffa/).

## Come funziona un attacco di vishing

Lo schema tipico segue alcuni passaggi ricorrenti:

1. **Pretesto**: l'attaccante si presenta come un soggetto autorevole, spesso la banca, le Poste, un corriere o persino la Polizia Postale.
2. **Urgenza**: comunica un problema che richiede azione immediata: un'operazione sospetta, un blocco del conto, una consegna in sospeso.
3. **Richiesta**: chiede di confermare dati, leggere ad alta voce un codice ricevuto via SMS, o installare un'app di assistenza remota.
4. **Sfruttamento**: usa quei dati per autorizzare un bonifico, un pagamento, o un accesso non autorizzato.

Una precisazione importante: **vishing e spoofing non sono sinonimi**. Il vishing è la tecnica di social engineering veicolata dalla voce; lo spoofing è la falsificazione tecnica del numero chiamante, spesso usata *all'interno* di una campagna di vishing per renderla più credibile, ma esiste anche da solo (per esempio nel telemarketing aggressivo).

Una variante diffusa in Italia è la **truffa del codice**: il truffatore, avendo già i dati della carta (numero, scadenza, CVV, spesso ottenuti altrove), inizia un pagamento online e chiede alla vittima di leggere ad alta voce il codice OTP ricevuto via SMS "per annullare l'operazione sospetta". In realtà quella lettura **autorizza** la transazione.

### Spoofing del numero: perché sembra davvero la tua banca

Molti attacchi usano lo **spoofing del Caller ID**: il numero che appare sul telefono è contraffatto e mostra lo stesso numero della banca vera, a volte persino inserendosi nello storico degli SMS legittimi già ricevuti. L'Arbitro Bancario Finanziario ha più volte qualificato questa tecnica come "vishing caller ID", riconoscendola come un fattore che rende la truffa particolarmente insidiosa anche nelle valutazioni di responsabilità tra banca e cliente. Dopo il regolamento AGCOM del 19 agosto 2025 sulle chiamate estere con CLI fisso falsificato, dal 19 novembre 2025 è scattato anche il filtro sulle numerazioni mobili italiane contraffatte: un segnale di quanto il fenomeno fosse diffuso.

### Vishing e OTP: come funziona la truffa del codice

Il Garante Privacy segnala tra le informazioni più cercate dai truffatori proprio i **dati bancari, della carta di pagamento e i codici OTP**. Lo schema più comune, descritto più sopra come "truffa del codice", sfrutta il fatto che la vittima considera l'OTP un'informazione innocua da "confermare", quando in realtà leggerlo ad alta voce equivale a firmare un'operazione. **Una richiesta telefonica di comunicare un OTP o un codice di sicurezza va sempre considerata un forte segnale di frode**: non va letto né digitato, e l'eventuale operazione va verificata tramite un canale ufficiale.

## Vishing con l'intelligenza artificiale: i cloni vocali

La novità degli ultimi anni è la **clonazione vocale**: con pochi secondi di audio pubblico (una diretta, un video, una nota vocale) è possibile generare una voce sintetica che imita in modo convincente quella di una persona reale, spesso un dirigente aziendale o un familiare.

Alcuni dati recenti danno la misura del fenomeno:

| Dato                                                                                                             | Valore                                                                                   |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Adulti che, secondo un'indagine McAfee, hanno già incontrato o conosciuto chi ha subito una truffa vocale con IA | circa 1 su 4                                                                             |
| Audio necessario per generare un clone vocale sperimentale                                                       | pochi secondi; per un risultato di qualità professionale servono in genere alcuni minuti |

Un caso recente che mostra bene il rischio per le aziende: nell'aprile 2026 il gruppo **ShinyHunters** ha usato una tecnica di vishing per ottenere l'accesso all'account Microsoft Entra di un dipendente di **Charter Communications**, usandolo poi per sottrarre circa **4,9 milioni di record**. Il punto debole non è stata una vulnerabilità tecnica, ma una telefonata convincente. Vale la pena notare che la statistica McAfee citata sopra risale al 2023: è un dato più vecchio, ma resta un'evidenza utile di quanto il fenomeno fosse già diffuso prima dell'ultima ondata di strumenti di voice cloning ancora più accessibili.

Il messaggio pratico è semplice: **una voce familiare al telefono non è più una prova d'identità sufficiente**, né per le persone né per le aziende.

## Vishing contro le aziende: l'help desk come bersaglio

Un bersaglio sempre più comune è l'**help desk IT**: l'attaccante chiama fingendosi un dipendente che ha perso l'accesso al proprio account e chiede un reset della password o della MFA. Se chi risponde non verifica l'identità con una procedura rigorosa, l'attaccante ottiene un accesso legittimo senza sfruttare nessuna vulnerabilità tecnica. Per questo, nei report di settore, il vishing mirato (*vishing interattivo*) risulta tra i vettori di accesso iniziale in forte crescita nelle intrusioni aziendali reali, secondo dati Mandiant.

Secondo il Verizon Data Breach Investigations Report 2026, il *pretexting* (manipolazione sincrona via voce o chat) rappresenta circa il **6% degli accessi iniziali** registrati, contro il 16% del phishing asincrono via email; il fattore umano, in generale, è presente in circa il **62%** dei breach confermati analizzati dal report.

## Come riconoscere una chiamata di vishing

| Segnale                                                 | Perché deve insospettire                                                                   |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| **Urgenza estrema**                                     | "Devi agire ora" è una pressione psicologica classica, non una prassi bancaria             |
| **Richiesta di codici o OTP**                           | Nessun operatore reale chiede di leggere un codice ricevuto via SMS                        |
| **Richiesta di installare un'app di assistenza remota** | Dà accesso completo al dispositivo a uno sconosciuto                                       |
| **Il numero sembra quello giusto**                      | Il Caller ID può essere falsificato: non è una prova                                       |
| **Chi chiama "sa già" molti tuoi dati**                 | Informazioni raccolte da data breach precedenti o dai social, usate per sembrare credibile |
| **Richiesta di una risposta "sì" registrata**           | La cosiddetta *truffa del sì*, usata per autorizzare servizi o contratti                   |

## Cosa fare se ricevi una chiamata sospetta

1. **Non dare mai dati sensibili al telefono**: codici, password, OTP, dati della carta — anche se chi chiama sembra già conoscere molti tuoi dati.
2. **Riaggancia e richiama tu** un numero ufficiale, trovato sul sito della banca o sul retro della carta, mai un numero fornito da chi ti ha chiamato.
3. **Non installare app** suggerite durante la chiamata.
4. **Se hai già fornito dati o letto un codice**, contatta subito la banca per bloccare carta e conto, cambia le password coinvolte e sporgi denuncia alla Polizia Postale, anche online tramite il Commissariato di PS.
5. **Segnala il numero** se possibile, anche se con lo spoofing il numero mostrato spesso non è quello reale del truffatore.

## Come proteggersi dal vishing: aziende e privati

**Per i privati:**

* considera ogni chiamata non richiesta su temi finanziari come potenzialmente sospetta, anche se il numero sembra corretto;
* stabilisci con familiari stretti una "parola di sicurezza" da usare in caso di richieste urgenti di denaro per telefono, utile anche contro i cloni vocali;
* attiva l'[autenticazione a più fattori](/articoli/mfa/) ovunque possibile: una password ottenuta al telefono da sola non basta a superarla, a patto di non leggere a voce anche il secondo codice.

**Per le aziende:**

* definisci procedure di **verifica dell'identità** per l'help desk che non si basino solo sulla voce (domande di sicurezza predefinite, verifica tramite canale secondario);
* forma il personale con **simulazioni di vishing**, non solo con corsi teorici: i programmi di simulazione risultano più efficaci nel cambiare comportamenti reali rispetto alla sola formazione passiva;
* per operazioni finanziarie critiche, richiedi **conferma su un canale diverso** dalla chiamata stessa (per esempio un messaggio su un sistema aziendale verificato, non una richiamata allo stesso numero).

## Vishing, phishing e smishing: le differenze

|              | Canale          | Esempio tipico                                        |
| ------------ | --------------- | ----------------------------------------------------- |
| **Phishing** | Email           | Falsa fattura o avviso di sicurezza con link malevolo |
| **Smishing** | SMS             | Falso avviso di consegna o blocco conto con link      |
| **Vishing**  | Chiamata vocale | Finto operatore bancario che chiede un OTP            |

Spesso gli attacchi combinano i canali: un SMS che chiede di richiamare un numero, seguito da una telefonata con un finto operatore, o viceversa un'email seguita da una chiamata di conferma. Il vishing usa soprattutto la voce, ma può far parte di una catena che combina telefono, SMS ed email: riconoscere un solo canale non basta, la diffidenza va applicata a tutta la sequenza.

## Domande frequenti sul vishing

### Cos'è il vishing?

Una truffa telefonica in cui l'attaccante si finge un ente affidabile (banca, corriere, assistenza) per ottenere dati sensibili, codici o autorizzare operazioni finanziarie.

### Qual è la differenza tra vishing e phishing?

Il phishing avviene via email, il vishing per telefono. Lo smishing è la variante via SMS. L'obiettivo e le tecniche psicologiche sono simili, cambia il canale.

### Vishing e spoofing sono la stessa cosa?

No. Il vishing è la truffa basata sulla manipolazione psicologica via voce; lo spoofing è la falsificazione tecnica del numero chiamante, spesso usata per rendere più credibile un attacco di vishing ma presente anche da sola, per esempio nel telemarketing aggressivo.

### Come faccio a sapere se una chiamata della banca è vera?

Riaggancia e richiama tu un numero ufficiale trovato sul sito della banca o sulla carta. Una richiesta di comunicare un OTP o un codice di sicurezza al telefono va sempre considerata un segnale di frode.

### Il numero che appare sul telefono può essere falso?

Sì. Con lo spoofing del Caller ID un truffatore può far apparire il numero reale della tua banca, anche inserendosi nello storico degli SMS legittimi.

### L'intelligenza artificiale ha reso il vishing più pericoloso?

Sì. Con pochi secondi di audio pubblico è possibile clonare una voce in modo credibile, rendendo più difficile distinguere una chiamata vera da una falsa, anche quando sembra la voce di una persona conosciuta.

### Cosa devo fare se ho già dato dati sensibili per telefono?

Contatta subito la tua banca per bloccare carta e conto, cambia le password coinvolte e sporgi denuncia alla Polizia Postale.

### Le aziende possono essere colpite dal vishing?

Sì, spesso tramite l'help desk IT, con l'attaccante che si finge un dipendente per ottenere il reset di una password o della MFA, senza sfruttare nessuna vulnerabilità tecnica.

### Esiste una difesa efficace contro i cloni vocali?

Non fidarsi della sola voce come prova d'identità: serve una verifica su un canale diverso (richiamata a un numero noto, domanda di sicurezza concordata) prima di agire su richieste urgenti di denaro o dati.
