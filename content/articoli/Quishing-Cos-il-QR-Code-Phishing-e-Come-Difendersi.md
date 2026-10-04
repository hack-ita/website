---
title: 'Quishing: Cos''è il QR Code Phishing e Come Difendersi'
slug: quishing
description: 'Quishing: significato e cos''è l''attacco di phishing con QR code, come funziona, dove compare, come riconoscere un codice falso e verificarlo prima di aprirlo.'
image: /quishing-qr-code-phishing-cybersecurity.webp
draft: true
date: 2026-10-23T00:13:02.274Z
lastmod: 2026-10-23T00:13:08.184Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Quishing
  - Quishing
  - Phishing
  - Cybersecurity
  - Sicurezza Informatica
---

# Quishing: Funzionamento e Come Evitare l'Attacco

Il **quishing** è una forma di [phishing](https://hackita.it/articoli/phishing/) che usa un QR code per nascondere un URL malevolo, portando la vittima verso una pagina falsa, un download dannoso o un servizio fraudolento. Il termine nasce dall'unione di *QR* e *phishing*.

Microsoft ha rilevato oltre **145 milioni di attacchi QR-code phishing** tra luglio 2025 e giugno 2026 tramite Microsoft Defender for Office 365: nel primo trimestre del 2026 il volume mensile è salito da 7,6 a 18,7 milioni di tentativi (+146%), per poi scendere a circa 8,3 milioni a giugno, un andamento che mostra un fenomeno in forte crescita ma altalenante, non una linea solo ascendente. Secondo l'ESET Threat Report sul primo semestre 2026, i QR code malevoli comparivano in circa l'**11%** delle email di phishing rilevate nel periodo analizzato.

Quello che rende il quishing particolarmente insidioso non è una tecnica sofisticata, ma un difetto strutturale del QR code stesso: **un codice QR nasconde la destinazione finché non viene scansionato**.

## Quishing significato: perché un QR code è pericoloso

Un link scritto per esteso si può leggere prima di cliccarlo: un occhio attento nota un dominio sospetto. Un codice QR, invece, è illeggibile a occhio nudo: il contenuto si rivela solo dopo la scansione, quando ormai il telefono ha già aperto il browser verso quell'indirizzo. Questo bypassa due difese molto comuni:

* **l'abitudine a controllare l'URL** prima di cliccare, che semplicemente non si applica a un QR code;
* **i filtri antispam aziendali**, pensati per analizzare testo e link nelle email, spesso meno efficaci su un'immagine che contiene un codice.

A questo si aggiunge un fattore psicologico: un QR code su un parchimetro, un menu di un ristorante o un poster non genera lo stesso istinto di cautela di un link sospetto in un'email.

Un punto spesso frainteso: **il quishing non è un canale a sé stante** come lo sono SMS o chiamata vocale. È una tecnica che può viaggiare su più canali — email, SMS, documenti PDF, stampa fisica — accomunati dal fatto che il link è nascosto dentro un'immagine invece che scritto in chiaro.

## Come funziona un attacco di quishing

1. **Creazione del codice malevolo**: l'attaccante genera un QR code che punta a un sito di phishing o a un file malevolo.
2. **Distribuzione**: il codice viene diffuso tramite email (spesso in allegati PDF, per eludere i filtri testuali), oppure stampato su adesivi fisici.
3. **Scansione**: la vittima inquadra il codice con lo smartphone, spesso per un'azione che percepisce come innocua: pagare un parcheggio, vedere un menu, accedere a un Wi-Fi.
4. **Reindirizzamento**: il telefono apre una pagina che imita un sito legittimo (un portale di pagamento, una pagina di login aziendale). Molte fotocamere e app di scansione mostrano comunque un'anteprima dell'URL prima di aprirlo: è il controllo più semplice e spesso trascurato.
5. **Furto dei dati**: la vittima inserisce credenziali o dati della carta, convinta di completare un'operazione reale.

## Dove compaiono i QR code malevoli

| Contesto                             | Come si presenta                                                                                       |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| **Parchimetri e pagamenti stradali** | Un adesivo con QR falso incollato sopra quello ufficiale del Comune                                    |
| **Email aziendali**                  | Un QR code in un PDF che finge di essere una busta paga, un documento HR o una fattura da "verificare" |
| **Ristoranti e locali**              | Un adesivo falso sovrapposto al QR del menu digitale                                                   |
| **Poster ed eventi pubblici**        | Codici per "maggiori informazioni" o "registrazione", sostituiti con uno malevolo                      |
| **Pacchi e consegne**                | Un codice per "tracciare la spedizione" che porta a un sito di phishing                                |
| **SMS e WhatsApp**                   | Un messaggio che invita a scansionare un QR per "verificare l'account"                                 |

Un caso reale: nel 2025 il Dipartimento dei Trasporti di New York ha emesso un avviso ufficiale dopo la comparsa di adesivi QR fraudolenti sui parchimetri di Manhattan, scoperti grazie alla segnalazione di un automobilista. L'ispezione sistematica che ne è seguita ha portato all'individuazione e rimozione di **64 adesivi QR contraffatti**, e nell'ottobre 2026 un uomo è stato incriminato con 11 capi d'accusa per aver orchestrato lo schema, che indirizzava gli automobilisti verso un sito fraudolento costruito per raccogliere i dati delle carte di pagamento invece di processare il pagamento del parcheggio.

## Quishing nelle email aziendali

Una tendenza in crescita è l'uso del quishing contro le aziende: un'email che sembra provenire dalle risorse umane, dall'amministrazione o da un fornitore, con un QR code al posto di un link testuale. Secondo le analisi di Microsoft, nei primi mesi del 2026 i **PDF sono stati il vettore principale** di queste campagne (fino al 70% dei casi a marzo), prima che aumentasse anche la quota di documenti Word. Il QR può ridurre l'efficacia dei controlli che analizzano direttamente il testo e gli URL in chiaro di un'email, soprattutto quando il codice è dentro un'immagine o un allegato: non significa che ogni filtro lo ignori, ma è un punto cieco reale per molti sistemi pensati per il testo.

Il problema si aggrava perché il clic avviene spesso su uno **smartphone personale, non gestito dall'azienda**: la mail originale transita nei sistemi di sicurezza aziendali, ma la scansione del QR e l'apertura del sito malevolo avvengono fuori da quel perimetro (reti, VPN, filtri sul traffico web), rendendo l'attacco più difficile da intercettare. Alcuni casi documentati combinano il quishing con tecniche da [Business Email Compromise](https://hackita.it/articoli/business-email-compromise/), impersonando un dirigente o un responsabile HR per aumentare la pressione a scansionare in fretta.

## Come riconoscere un QR code malevolo

| Segnale                                            | Perché deve insospettire                                                                                                          |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Adesivo sovrapposto**                            | Bordi visibili, colla, un adesivo leggermente storto su un codice che dovrebbe essere stampato                                    |
| **QR in un contesto insolito**                     | Un codice dove normalmente non ce n'è uno, o in un'email che normalmente non ne contiene                                          |
| **Urgenza nel messaggio che accompagna il codice** | "Scansiona subito per verificare l'account" è un classico schema di pressione                                                     |
| **Richiesta di dati dopo la scansione**            | Un vero pagamento di un parcheggio comunale raramente chiede subito dati sensibili della carta su una pagina dall'aspetto anomalo |
| **URL dopo la scansione diverso dall'atteso**      | Prima di procedere, molte fotocamere e app mostrano l'anteprima del link: controllarla è il passo più semplice ed efficace        |

Un errore comune: pensare che un sito con **HTTPS attivo sia automaticamente sicuro**. HTTPS cifra la connessione, ma non garantisce che il sito appartenga davvero all'organizzazione che dice di rappresentare: anche una pagina di phishing può avere un certificato valido e il lucchetto nella barra degli indirizzi.

### Decodificare un QR code senza scansionarlo con il telefono

Un modo per analizzare un QR code sospetto, ricevuto per esempio come immagine in un'email, senza rischiare di aprire il link su un dispositivo reale, è decodificarlo da terminale. Su Linux, con `zbar-tools` installato:

```bash
zbarimg sospetto.png
```

Il comando restituisce il testo codificato (nella maggior parte dei casi un URL) senza mai effettuare una richiesta di rete verso quell'indirizzo. Da lì si può ispezionare il dominio con calma, per esempio controllandone la registrazione:

```bash
whois dominio-sospetto.it
```

Questo è lo stesso approccio "guarda prima di aprire" che vale per qualunque link ricevuto via email, applicato a un QR code invece che a un URL testuale.

## Come proteggersi dal quishing

* **Controlla sempre l'anteprima del link** prima di aprirlo: la maggior parte delle fotocamere e app di scansione QR mostra l'URL di destinazione prima di seguirlo.
* **Diffida di adesivi su QR code pubblici**: controlla che non ci sia un adesivo sovrapposto a quello originale, specialmente su parchimetri e totem.
* **Non scansionare QR code ricevuti in email inattese**, specialmente se in allegati PDF o se accompagnati da urgenza.
* **Usa un'app di pagamento ufficiale** invece di scansionare un QR per i parcheggi, quando disponibile.
* **Nelle aziende**, estendi i controlli di sicurezza email anche alle immagini e ai PDF contenenti QR code, non solo al testo e ai link.
* **Attiva l'MFA** ovunque possibile: anche se le credenziali vengono rubate, un secondo fattore riduce il danno.

## Quishing e altri tipi di phishing: le differenze

|                                                       | Canale                  | Esempio tipico                                       |
| ----------------------------------------------------- | ----------------------- | ---------------------------------------------------- |
| **Phishing**                                          | Email con link testuale | Falsa fattura con link malevolo                      |
| **[Smishing](https://hackita.it/articoli/smishing/)** | SMS                     | Falso avviso di consegna con link                    |
| **[Vishing](https://hackita.it/articoli/vishing/)**   | Chiamata vocale         | Finto operatore bancario                             |
| **Quishing**                                          | Codice QR               | Falso pagamento di parcheggio o menu con QR malevolo |

Il quishing si distingue dagli altri per il meccanismo tecnico: non è il canale di consegna a cambiare radicalmente (può arrivare via email, SMS o essere fisicamente stampato), ma il fatto che il link sia **nascosto dentro un'immagine** fino al momento della scansione.

## Domande frequenti sul quishing

### Cos'è il quishing?

Una truffa in cui un codice QR malevolo porta a un sito falso per rubare credenziali, dati di pagamento o installare malware. Il nome unisce "QR" e "phishing".

### Perché il quishing è pericoloso?

Perché un QR code nasconde la destinazione finché non viene scansionato: non si può controllare il link in anticipo come si farebbe con un URL scritto per esteso, e spesso bypassa i filtri antispam aziendali pensati per il testo.

### Dove si trovano più spesso i QR code malevoli?

Parchimetri, menu di ristoranti, poster pubblici, email aziendali (spesso in allegati PDF) e messaggi SMS o WhatsApp.

### Come riconosco un QR code falso su un parchimetro?

Controlla se c'è un adesivo sovrapposto a quello originale: bordi visibili, colla o un posizionamento leggermente storto sono segnali da non ignorare.

### Come verifico un link prima di aprirlo dopo aver scansionato un QR?

La maggior parte delle fotocamere e app di scansione mostra un'anteprima dell'URL di destinazione prima di aprirlo: controllala sempre prima di procedere.

### Il quishing può colpire le aziende?

Sì, spesso tramite email con QR code al posto di link testuali per eludere i filtri antispam, con la vittima che scansiona dal proprio smartphone personale, fuori dal perimetro di sicurezza aziendale.

### Quanto è cresciuto il quishing di recente?

Secondo dati Microsoft, gli attacchi sono aumentati del 146% nel primo trimestre del 2026, con quasi 18,7 milioni di tentativi registrati nel solo marzo 2026.

### Un QR code con HTTPS è sempre sicuro?

No. HTTPS cifra la connessione, ma non dimostra che il sito appartenga all'organizzazione che dice di rappresentare: anche una pagina di phishing può avere un certificato valido.

### Un'app di pagamento ufficiale è più sicura di un QR code su un parchimetro?

Sì. Quando disponibile, usare l'app ufficiale del Comune o del gestore evita del tutto il rischio di un QR code manomesso fisicamente.
