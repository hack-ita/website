---
title: 'Business Email Compromise (BEC): Truffe, Tecniche e Difesa'
slug: business-email-compromise
description: 'BEC spiegato semplice: cos''è la truffa del CEO, come funziona un attacco Business Email Compromise, un caso reale e come proteggere la tua azienda.'
image: /business-email-compromise-bec-frode-email-aziendale.webp
draft: true
date: 2026-10-20T23:54:59.051Z
lastmod: 2026-10-20T23:55:31.830Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Business Email Compromise
  - BEC
  - CEO Fraud
  - Email Account Compromise
  - Invoice Fraud
---

# Business Email Compromise: Come Funziona la Frode Aziendale

Il **Business Email Compromise** (**BEC**), in italiano conosciuto anche come **truffa del CEO**, è un attacco mirato in cui i criminali compromettono o falsificano un indirizzo email aziendale per convincere un dipendente a fare un bonifico, cambiare le coordinate bancarie di un fornitore o inviare dati riservati. Non c'è malware, non c'è un link da cliccare: c'è solo un'email ben scritta, al momento giusto, verso la persona giusta.

È una delle truffe informatiche più redditizie al mondo. Secondo l'FBI, nel suo report 2025 pubblicato ad aprile 2026, l'Internet Crime Complaint Center ha ricevuto **24.768 denunce di BEC**, per oltre **3 miliardi di dollari** di perdite dichiarate, in crescita rispetto ai 2,77 miliardi del 2024. Tra il 2013 e il 2023 le perdite cumulate stimate superano i **55 miliardi di dollari**.

## BEC significato: perché non è il solito phishing

Il BEC è una forma di [phishing](https://hackita.it/articoli/phishing/) mirato (*spear phishing*), ma con una differenza cruciale: **le email BEC quasi mai contengono allegati infetti o link malevoli**, gli elementi che i filtri antispam sono addestrati a riconoscere. Sono messaggi puliti, scritti bene, spesso costruiti dopo settimane di osservazione dell'azienda bersaglio: organigramma, stile di comunicazione, gerarchie interne, abitudini operative, perfino il linguaggio tipico del CEO o del responsabile amministrativo.

Per questo il BEC bypassa i controlli tecnici tradizionali: non sfrutta una vulnerabilità del software, sfrutta la **fiducia** tra le persone.

## Come funziona un attacco BEC, passo per passo

1. **Ricognizione**: l'attaccante studia l'azienda tramite social network (LinkedIn in primis), sito web, comunicati stampa e, se possibile, email già compromesse.
2. **Accesso o impersonificazione**: o compromette davvero un account email (tramite phishing, credenziali rubate o un [data breach](https://hackita.it/articoli/data-breach/) precedente), oppure crea un dominio e un indirizzo molto simili a quello reale (per esempio `azienda-spa.com` invece di `aziendaspa.com`).
3. **Osservazione silenziosa**: se ha accesso reale alla casella, spesso monitora per settimane le conversazioni, aspettando il momento giusto, come una trattativa commerciale in corso.
4. **Il colpo**: invia (o inserisce in una conversazione reale) un messaggio che richiede un bonifico urgente, un cambio di IBAN per un pagamento già previsto, o dati riservati.
5. **Pressione psicologica**: urgenza, riservatezza ("non parlarne con nessun altro"), autorità (il messaggio sembra venire dal capo o da un partner fidato).
6. **Incasso**: il denaro finisce su un conto controllato dai criminali, spesso smistato rapidamente su altri conti per renderne difficile il recupero.

## Le varianti più comuni di BEC

| Tipo                                         | Come funziona                                                                                                                                                 |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Frode del CEO**                            | Un'email che sembra del CEO o di un dirigente chiede un bonifico urgente e riservato, spesso mentre "è in riunione e non può essere chiamato"                 |
| **Fattura falsa / fornitore compromesso**    | L'attaccante si spaccia per un fornitore reale e comunica un cambio di IBAN per i pagamenti futuri                                                            |
| **Attacco all'avvocato**                     | Un finto legale, coinvolto in un'operazione riservata (acquisizione, contratto), chiede un bonifico urgente per "chiudere l'affare"                           |
| **Furto di dati dei dipendenti**             | L'email, apparentemente del CEO o delle risorse umane, chiede l'invio di dati fiscali o buste paga dei dipendenti                                             |
| **Compromissione reale della casella (EAC)** | La variante più pericolosa: l'attaccante ha davvero accesso all'email e si inserisce in una trattativa autentica, sostituendo l'IBAN al momento del pagamento |

## Un caso reale: la truffa del travertino

Un caso che mostra bene il meccanismo ha coinvolto un'azienda italiana e una statunitense, impegnate in una fornitura di materiali in pietra per un progetto da circa 1,4 milioni di dollari. I criminali erano riusciti a prendere il controllo della casella email della società italiana, osservando le comunicazioni e le transazioni in corso. Al momento del pagamento, l'azienda americana ha versato circa **700.000 dollari** su un IBAN sostituito dai truffatori, convinta di pagare il proprio partner reale. Solo la collaborazione tra la polizia italiana e i Secret Service statunitensi ha permesso di recuperare parte dei fondi.

Il dettaglio da notare: nessun link, nessun allegato sospetto. Solo una conversazione commerciale reale, dirottata al momento giusto.

## Perché il BEC funziona così bene

* **Bypassa i filtri tecnici**: niente malware da rilevare, niente URL sospetti da bloccare.
* **Sfrutta l'autorità**: un dipendente raramente mette in discussione una richiesta che sembra venire dal proprio capo.
* **Sfrutta l'urgenza**: "serve entro oggi" spinge a saltare i controlli abituali.
* **Sfrutta la riservatezza**: "non parlarne con altri" isola la vittima dal confronto con i colleghi, che spesso farebbe emergere l'anomalia.
* **È mirato, non di massa**: a differenza dello spam, ogni messaggio è costruito su misura per l'azienda e la persona bersaglio.

## Segnali d'allarme di un'email BEC

| Segnale                                      | Perché deve insospettire                                                          |
| -------------------------------------------- | --------------------------------------------------------------------------------- |
| **Richiesta urgente di bonifico**            | Specialmente se fuori dalle normali procedure aziendali                           |
| **Invito alla riservatezza**                 | "Non dirlo a nessuno" non è una prassi legittima per un pagamento                 |
| **Cambio improvviso di coordinate bancarie** | Un fornitore reale non cambia IBAN via email senza una verifica indipendente      |
| **Dominio simile ma diverso**                | Controllare sempre l'indirizzo esatto del mittente, non solo il nome visualizzato |
| **Il mittente "non può essere chiamato"**    | Una scusa comune per impedire la verifica telefonica                              |
| **Richiesta insolita per quel ruolo**        | Un CEO che chiede dati fiscali di un singolo dipendente è un pattern atipico      |

## Come proteggersi dal BEC: aziende

* **Verifica su un canale diverso**: qualsiasi richiesta di bonifico o cambio IBAN va confermata telefonicamente, chiamando un numero noto in anticipo, mai quello indicato nell'email sospetta.
* **Procedure a doppia approvazione**: nessun pagamento rilevante autorizzato da una sola persona su richiesta via email.
* **Autenticazione email**: implementare SPF, DKIM e DMARC per ridurre lo spoofing del dominio aziendale.
* **MFA ovunque**: soprattutto sugli account email dei dirigenti e dell'amministrazione, bersagli principali.
* **Formazione mirata**: non la solita formazione anti-phishing generica, ma scenari specifici su richieste finanziarie urgenti e riservate.
* **Monitoraggio dei domini simili**: registrare o monitorare varianti del proprio dominio aziendale che potrebbero essere usate per impersonificazioni.
* **Controlla regole di inoltro e app OAuth**: se un account è stato davvero compromesso, l'attaccante può creare regole di posta nascoste o sfruttare applicazioni autorizzate per mantenere visibilità sulle comunicazioni anche dopo un cambio password. Vale la pena controllarle periodicamente sugli account più esposti.
* **Cultura dell'errore sicuro**: i dipendenti devono sentirsi liberi di fare una domanda in più o di rifiutare un pagamento sospetto senza timore di ritorsioni, anche se la richiesta sembra venire dall'alto.

## Cosa fare se sei stato vittima di un BEC

1. **Contatta subito la banca**, chiedendo di contattare a sua volta l'istituto che ha ricevuto il trasferimento: un bonifico fraudolento può talvolta essere bloccato o recuperato se segnalato entro poche ore.
2. **Denuncia alla Polizia Postale**: la collaborazione internazionale tra forze dell'ordine ha già permesso il recupero di fondi in casi simili.
3. **Cambia le credenziali** di tutti gli account email coinvolti e attiva l'MFA se non era già attiva.
4. **Verifica l'estensione della compromissione**: se un account è stato davvero violato, controlla regole di inoltro nascoste nella posta, spesso usate dagli attaccanti per monitorare le conversazioni senza farsi notare.
5. **Avvisa i partner commerciali** coinvolti nella conversazione compromessa: potrebbero essere il prossimo bersaglio con lo stesso schema.

## BEC e intelligenza artificiale

Il BEC si sta evolvendo con l'IA generativa: email sempre più naturali, senza gli errori grammaticali che un tempo erano un segnale rivelatore, e in alcuni casi persino deepfake vocali o video per rafforzare la credibilità di una richiesta urgente (una tecnica che si sovrappone al [vishing](https://hackita.it/articoli/vishing/)). L'FBI ha già attribuito oltre **30 milioni di dollari** di perdite BEC del 2025 a schemi con una componente IA confermata. La difesa non cambia nella sostanza: nessuna richiesta finanziaria urgente va autorizzata senza una verifica indipendente, qualunque sia il mezzo con cui arriva.

## Domande frequenti sul Business Email Compromise

### Cos'è il Business Email Compromise?

Un attacco mirato in cui i criminali compromettono o falsificano un'email aziendale per convincere qualcuno a fare un bonifico, cambiare coordinate bancarie o inviare dati riservati.

### Qual è la differenza tra BEC e phishing?

Il BEC è una forma di phishing molto mirata (spear phishing) che quasi mai usa link o allegati malevoli: si basa su un'email convincente e sul contesto, non su un file da aprire.

### Cos'è la truffa del CEO?

È la variante più nota di BEC: un'email che sembra provenire dal CEO o da un dirigente chiede un bonifico urgente e riservato a un dipendente.

### Come riconosco un'email BEC?

Richiesta urgente e riservata di bonifico o cambio IBAN, mittente che "non può essere chiamato", dominio simile ma diverso da quello reale, richieste insolite per quel ruolo.

### Come si verifica se una richiesta di pagamento è legittima?

Chiamando un numero di telefono noto in anticipo, mai quello indicato nell'email sospetta, e seguendo sempre una procedura di doppia approvazione per i bonifici rilevanti.

### Quanto costano le truffe BEC alle aziende?

Secondo l'FBI, solo nel 2025 le perdite dichiarate negli Stati Uniti hanno superato i 3 miliardi di dollari, su quasi 25.000 denunce.

### Cosa fare se ho già fatto un bonifico per una truffa BEC?

Contatta subito la banca per tentare il blocco o il recupero dei fondi, denuncia alla Polizia Postale e cambia le credenziali degli account email coinvolti.

### L'intelligenza artificiale ha peggiorato il rischio BEC?

Sì. Rende le email più naturali e convincenti e può aggiungere deepfake vocali o video a supporto della richiesta, ma la difesa resta la stessa: verificare sempre su un canale indipendente.
