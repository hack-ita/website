---
title: I Più Grandi Attacchi Hacker della Storia (Guida 2026)
slug: attacchi-hacker-piu-grandi-storia
description: 'I più grandi attacchi hacker della storia: Yahoo, Stuxnet, WannaCry, NotPetya, Equifax, SolarWinds, Colonial Pipeline e le lezioni imparate.'
image: /piu-grandi-attacchi-hacker-della-storia-cybersecurity.webp
draft: true
date: 2026-10-31T00:28:23.591Z
lastmod: 2026-10-31T00:30:59.403Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Attacchi Hacker
  - Cybersecurity
  - Ransomware
  - Cyberwarfare
  - Data Breach
---

# 7 Attacchi Informatici che Hanno Cambiato la Storia della Cybersecurity

Alcuni attacchi informatici hanno fatto molto più che compromettere un computer o rubare dei dati: hanno cambiato per sempre il modo in cui aziende, governi e professionisti pensano alla cybersecurity.

In questa lista trovi **i più grandi attacchi hacker della storia**, dai data breach che hanno esposto miliardi di account alle operazioni capaci di provocare danni fisici nel mondo reale. Ci sono ransomware che hanno paralizzato ospedali in decine di Paesi, attacchi supply chain che hanno trasformato un singolo fornitore in un punto d'accesso a migliaia di organizzazioni e semplici password deboli che hanno contribuito a bloccare infrastrutture critiche.

**Yahoo, Stuxnet, WannaCry, NotPetya, Equifax, SolarWinds e Colonial Pipeline** raccontano sette storie molto diverse, ma con una cosa in comune: dietro ogni grande incidente c'è una vulnerabilità, una scelta sbagliata o una debolezza che qualcuno è riuscito a sfruttare.

Vediamo cosa è successo, come sono stati condotti questi attacchi, quali danni hanno provocato e soprattutto **quali lezioni hanno lasciato alla cybersecurity moderna**.

## Yahoo (2013-2014): il data breach più grande della storia

Yahoo ha subito due violazioni distinte, entrambe rese pubbliche solo anni dopo i fatti. La prima, datata **agosto 2013**, fu inizialmente stimata in oltre un miliardo di account, ma nel 2017, in seguito ad analisi più approfondite, Yahoo l'ha rivalutata coinvolgendo **tutti i 3 miliardi** di account allora esistenti sul servizio, rendendola il più grande [data breach](/articoli/data-breach/) mai documentato. La seconda, un incidente distinto del **2014**, ha coinvolto circa **500 milioni di account**. In entrambi i casi sono finiti nelle mani degli attaccanti nomi, email, numeri di telefono, date di nascita e domande di sicurezza. Il caso resta un esempio di riferimento sulle conseguenze di una violazione scoperta e comunicata anni dopo la sua effettiva origine: il ritardo nella divulgazione ha fatto crollare di 350 milioni di dollari il prezzo dell'acquisizione di Yahoo da parte di Verizon, secondo quanto riportato nei documenti depositati presso la [SEC](https://www.sec.gov/Archives/edgar/data/1011006/000119312516793106/d305610dex991.htm).

## Stuxnet (2010): quando un attacco informatico distrugge macchinari reali

[Stuxnet](/articoli/stuxnet/) merita un posto a parte in questa lista: non ha rubato dati né chiesto un riscatto, ha sabotato fisicamente le centrifughe dell'impianto nucleare iraniano di Natanz, sfruttando quattro vulnerabilità zero-day di Windows e una nel software Siemens. È il caso che ha dimostrato, per primo e in modo documentato, che un attacco puramente digitale può avere conseguenze fisiche dirette. Ne abbiamo parlato nel dettaglio nel nostro [approfondimento su Stuxnet](/articoli/stuxnet/).

## WannaCry (2017): un worm, un weekend, 150 paesi

Il 12 maggio 2017, il [ransomware](/articoli/ransomware/) **WannaCry** ha iniziato a diffondersi come un worm, senza bisogno che nessuno cliccasse un link: sfruttava **EternalBlue**, un exploit per una vulnerabilità nel protocollo SMBv1 di Windows, sviluppato dalla NSA e trapelato pubblicamente poche settimane prima a opera del gruppo Shadow Brokers. In poche ore ha infettato **oltre 200.000 computer in almeno 150 paesi**, colpendo in modo particolarmente grave il servizio sanitario nazionale britannico (NHS), con ospedali costretti a rimandare operazioni e dirottare ambulanze. I danni totali sono stati stimati intorno ai **4 miliardi di dollari**, a fronte di riscatti effettivamente pagati per poche centinaia di migliaia di dollari: la sproporzione mostra quanto il costo reale di un attacco di questo tipo stia nell'interruzione operativa, non nel riscatto in sé. La diffusione fu rallentata quando il ricercatore Marcus Hutchins scoprì e registrò un dominio che fungeva da *kill switch* nel codice del malware.

## NotPetya (2017): il ransomware che non voleva soldi

Poche settimane dopo WannaCry, nel giugno 2017, è arrivato **NotPetya**: si presentava come ransomware, con tanto di richiesta di riscatto, ma il meccanismo di decifratura era rotto di proposito. Non era pensato per fare soldi, ma per **distruggere dati** su larga scala, mascherato da attacco finanziario. Il vettore iniziale è stato un aggiornamento compromesso del software di contabilità ucraino MeDoc. Una volta dentro una rete, NotPetya si muoveva lateralmente combinando **EternalBlue ed EternalRomance** (due exploit SMB della stessa famiglia trapelata dai Shadow Brokers) con il furto di credenziali tramite tecniche in stile [Mimikatz](/articoli/mimikatz/), poi riutilizzate con strumenti legittimi di amministrazione come **WMI e PsExec**: un dettaglio tecnico documentato nel dettaglio dall'analisi di [Mandiant/Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/petya-ransomware-spreading-via-eternalblue-exploit), e che mostra come l'exploit da solo non fosse l'unico motore della diffusione. Ha colpito aziende in oltre 60 paesi, con il caso più noto quello della società di spedizioni Maersk, costretta a reinstallare da zero migliaia di server e workstation. Il governo statunitense lo ha definito l'attacco informatico "più distruttivo e costoso" mai registrato fino ad allora; le stime indipendenti sui danni complessivi superano i 10 miliardi di dollari.

## Equifax (2017): una patch non applicata, 147 milioni di persone esposte

Nel 2017, l'agenzia di credito **Equifax** ha subito una violazione che ha esposto i dati personali e finanziari di circa **147 milioni di persone**: nomi, numeri di previdenza sociale, date di nascita, indirizzi e, in molti casi, numeri di patente. La causa è tra le più banali e istruttive di questa lista: una vulnerabilità nota del framework Apache Struts (**CVE-2017-5638**), per cui una patch era disponibile da mesi, non era mai stata applicata su un'applicazione esposta su Internet. Da lì, la catena è quella da manuale: applicazione esposta → RCE su Struts → movimento laterale interno → accesso ai database → esfiltrazione dei dati. Il caso Equifax è diventato lo standard con cui si spiega perché il *patch management* sia una delle misure di sicurezza più sottovalutate e più critiche in assoluto. Secondo l'accordo globale con [FTC, CFPB e 50 stati USA](https://www.ftc.gov/news-events/news/press-releases/2019/07/equifax-pay-575-million-part-settlement-ftc-cfpb-states-related-2017-data-breach), l'azienda ha accettato di pagare almeno 575 milioni di dollari, con un esborso potenziale fino a 700 milioni.

## SolarWinds (2020): quando il fornitore diventa il bersaglio

Nel dicembre 2020 è emerso che attaccanti (attribuiti a un gruppo legato all'intelligence russa) avevano compromesso il processo di build del software **Orion** di SolarWinds, una piattaforma di gestione IT usata da migliaia di aziende ed enti governativi statunitensi. Il codice malevolo, una backdoor nota come **SUNBURST**, è stato inserito direttamente nel processo di build del software, tramite un impianto preliminare (**SUNSPOT**) nell'ambiente di compilazione di SolarWinds, e distribuito poi **attraverso un aggiornamento ufficiale e firmato digitalmente**, raggiungendo circa 18.000 organizzazioni, comprese agenzie federali USA. Un dettaglio tecnico spesso trascurato: non tutte le organizzazioni che hanno ricevuto l'aggiornamento infetto sono state effettivamente sfruttate oltre la backdoor iniziale. Gli attaccanti avevano selezionato attivamente un sottoinsieme di bersagli su cui proseguire con movimento laterale e abuso di credenziali legittime, come documentato dalla [CISA](https://cisa.gov/supply-chain-compromise), che ha emesso una direttiva d'emergenza per le agenzie federali USA. Gli attaccanti erano rimasti nascosti nella rete di SolarWinds per oltre un anno prima della scoperta. È il caso di riferimento per il concetto di **supply chain attack**: compromettere un singolo fornitore di fiducia, con un aggiornamento regolarmente firmato, per raggiungere centinaia di bersagli finali.

## Colonial Pipeline (2021): una sola password senza MFA

Nel maggio 2021, il gruppo ransomware **DarkSide** ha colpito Colonial Pipeline, l'operatore del più grande oleodotto degli Stati Uniti, responsabile di circa il **45% del rifornimento di carburante della costa est**. L'azienda ha fermato precauzionalmente l'intero oleodotto per giorni, causando code ai distributori e rincari del carburante in diversi stati. La causa iniziale è stata disarmante nella sua semplicità: un **account VPN legacy** non più in uso ma ancora attivo, protetto da una **password riutilizzata** e privo di [autenticazione a più fattori](/articoli/mfa/). La password risultava presente in un set di credenziali trapelate online in precedenza, anche se non è mai stato stabilito con certezza che gli attaccanti l'abbiano ottenuta proprio da quella fonte. Colonial ha pagato un riscatto di circa 4,4 milioni di dollari in bitcoin; l'FBI è poi riuscita a recuperarne una parte rilevante tracciando i movimenti sulla blockchain. Il caso resta il riferimento principale per spiegare perché l'MFA su ogni accesso remoto non sia un dettaglio opzionale.

## Cosa hanno in comune questi attacchi

| Caso              | Causa principale                                                       | Lezione                                                 |
| ----------------- | ---------------------------------------------------------------------- | ------------------------------------------------------- |
| Yahoo             | Violazione non rilevata per anni, divulgazione tardiva                 | Rilevamento e trasparenza contano quanto la prevenzione |
| Stuxnet           | Zero-day multipli, air gap superato via USB                            | Nessun ambiente è isolato per definizione               |
| WannaCry          | Vulnerabilità SMB non patchata, exploit trapelato                      | Il patch management è una corsa contro il tempo         |
| NotPetya          | Supply chain software + furto di credenziali                           | Un attacco "a soldi" può essere un diversivo            |
| Equifax           | Vulnerabilità nota (CVE-2017-5638), patch disponibile ma non applicata | Conoscere il rischio non basta se non si agisce         |
| SolarWinds        | Compromissione del processo di build del fornitore                     | Fidarsi di un aggiornamento firmato non basta più       |
| Colonial Pipeline | Account VPN legacy, password riutilizzata, nessuna MFA                 | Un solo accesso debole può bloccare un intero settore   |

## Le tecniche dietro i più grandi attacchi

| Attacco           | Tipo                               | Tecniche chiave                                                                        |
| ----------------- | ---------------------------------- | -------------------------------------------------------------------------------------- |
| Yahoo             | Data breach                        | Compromissione di database, esfiltrazione di credenziali                               |
| Stuxnet           | Cyberweapon / ICS                  | Zero-day multipli, supporto rimovibile, movimento laterale, manipolazione PLC, rootkit |
| WannaCry          | Worm / Ransomware                  | Exploit SMB (EternalBlue), propagazione autonoma, RCE                                  |
| NotPetya          | Malware distruttivo / Supply chain | Compromissione del fornitore, furto di credenziali, WMI, PsExec                        |
| Equifax           | RCE / Data breach                  | Applicazione esposta, vulnerabilità nota non patchata, esfiltrazione                   |
| SolarWinds        | Supply chain / APT                 | Compromissione del build system, backdoor firmata, abuso di credenziali                |
| Colonial Pipeline | Ransomware / Initial access        | Account legacy, credenziali riutilizzate, assenza di MFA                               |

Il filo comune non è quasi mai la sofisticazione tecnica pura: è quasi sempre una combinazione di una debolezza nota, una procedura mancata e un tempo di reazione troppo lungo.

## Domande frequenti sui più grandi attacchi hacker della storia

### Qual è stato il più grande attacco hacker della storia?

Dipende dal criterio: Yahoo per numero di account coinvolti, NotPetya per impatto economico, Stuxnet per impatto fisico e strategico, WannaCry per velocità e diffusione globale, SolarWinds per profondità della compromissione della supply chain, Colonial Pipeline per impatto su un'infrastruttura critica.

### Qual è il data breach più grande della storia?

La violazione di Yahoo del 2013-2014, resa nota nel 2016, che ha coinvolto tutti i 3 miliardi di account allora esistenti sul servizio.

### Qual è stato l'attacco informatico più costoso in assoluto?

NotPetya (2017) è generalmente considerato il più costoso, con stime di danni complessivi superiori ai 10 miliardi di dollari a livello globale.

### Cos'è stato il primo attacco informatico a causare danni fisici documentati?

Stuxnet, scoperto nel 2010, che ha sabotato le centrifughe dell'impianto nucleare iraniano di Natanz.

### Perché WannaCry si è diffuso così rapidamente?

Perché sfruttava una vulnerabilità del protocollo SMB di Windows (EternalBlue) per diffondersi da solo come un worm, senza bisogno che nessuno cliccasse un link o un allegato.

### Cos'è un attacco alla supply chain?

Un attacco in cui i criminali compromettono un fornitore di fiducia (software, hardware o servizi) per raggiungere, tramite quel singolo punto, molte organizzazioni che lo usano: il caso SolarWinds ne è l'esempio di riferimento.

### Come è stato violato Colonial Pipeline?

Attraverso una password riutilizzata su un account VPN non più attivo, privo di autenticazione a più fattori: nessuna vulnerabilità tecnica sofisticata, solo un accesso debole non protetto.

### Questi attacchi si potevano prevenire?

Nella maggior parte dei casi di questa lista, sì, almeno in parte: Equifax con una patch già disponibile, Colonial Pipeline con l'MFA, Yahoo con un rilevamento e una divulgazione più tempestivi.

### Gli attacchi di questo tipo sono ancora comuni oggi?

Sì. Ransomware, supply chain attack e violazioni per credenziali deboli restano tra i vettori più diffusi ancora oggi, spesso con varianti più sofisticate ma la stessa logica di fondo.
