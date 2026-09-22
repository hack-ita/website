---
title: 'White Hat, Black Hat, Grey Hat: Chi Sono e Cosa Rischiano'
slug: white-hat-black-hat-grey-hat
description: 'Cosa distingue white hat, black hat e grey hat, l''origine del termine hacker/cracker, i rischi legali di ciascuno e cos''è la responsible disclosure.'
image: /white-hat-black-hat-grey-hat-differenze.webp
draft: true
date: 2026-09-25T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - white hat
  - black hat
  - grey hat
  - cracker
  - bug bounty
---

# White Hat, Black Hat e Grey Hat: le Differenze

White hat, black hat e grey hat sono le etichette che il settore della sicurezza informatica usa per classificare un hacker in base a due variabili: se ha l'autorizzazione per agire, e quale obiettivo persegue. Prendono in prestito l'immaginario dei western, dove il colore del cappello del protagonista diceva subito allo spettatore se fosse un "buono" o un "cattivo". Due persone possono trovare la stessa identica falla in un sito web — una la segnala e incassa un bonifico da un programma di bug bounty, l'altra la usa per rubare dati e rivenderli sul dark web — con un esito agli antipodi per chi la compie, a seconda di quale di questi tre cappelli indossa.

## Da Dove Nasce la Distinzione: Hacker vs Cracker

Prima che si diffondesse la terminologia "hat", la comunità tecnica usava una distinzione più netta: **hacker** per chi esplora e comprende i sistemi per curiosità o per migliorarli, **cracker** per chi usa le stesse competenze per violare sistemi altrui senza autorizzazione, causando danno o traendone profitto illecito. Il verbo "**craccare**" (dall'inglese *to crack*) descrive proprio questa attività: forzare una protezione — una password, una licenza software, un sistema di autenticazione — per aggirarla senza permesso. La distinzione si è persa nel linguaggio comune, dove "hacker" oggi copre entrambi i significati; la terminologia "hat" nasce in parte per recuperare quella distinzione con più sfumature. Per la storia completa del termine "hacker", vedi l'articolo [Hacker: Cos'è, Tipi di Hacker e Come Diventare Hacker Etico](https://hackita.it/articoli/hacker/). Si parte, inevitabilmente, dal cappello dei buoni.

## White Hat

Il white hat opera sempre con autorizzazione esplicita del proprietario del sistema. Tra gli esempi più comuni di attività white hat rientrano il penetration testing, il red teaming autorizzato e la ricerca di vulnerabilità nell'ambito di programmi di bug bounty come quelli coordinati da piattaforme come [HackerOne](https://www.hackerone.com/) — per la panoramica completa dei ruoli vedi [Ethical Hacker: Cos'è e Cosa Fa](https://hackita.it/articoli/ethical-hacker/). L'obiettivo è trovare le vulnerabilità prima che lo faccia qualcun altro, documentarle e aiutare a correggerle. Sul lato opposto dello spettro, senza permesso e senza le stesse intenzioni, c'è il black hat.

## Black Hat

Il black hat è quello che la parola "hacker" evoca nell'immaginario comune: opera nell'ombra, spesso appoggiandosi a marketplace del dark web per comprare e vendere exploit, credenziali rubate e accessi già compromessi pronti all'uso. I bersagli cambiano scala ma non logica: singole persone tramite [phishing](https://hackita.it/articoli/phishing/) o SIM swap per prendere il controllo di un telefono, siti web sfruttandone le vulnerabilità per rubare dati o piazzare pagine di pagamento false, aziende intere dove l'obiettivo è quasi sempre economico — un [virus o un ransomware](https://hackita.it/articoli/virus-informatico/) che cripta l'infrastruttura e blocca l'operatività finché non arriva un riscatto, tipicamente richiesto in criptovaluta per restare anonimi. In Italia l'accesso abusivo a un sistema informatico può integrare il reato previsto dall'art. 615-ter c.p.; a seconda di cosa viene fatto una volta dentro — sottrazione di dati, frode, danneggiamento, o la produzione e diffusione stessa del malware usato (art. 635-quater.1 c.p.) — possono aggiungersi altre fattispecie di reato, indipendentemente dalla motivazione dichiarata. Tra questi due estremi netti, però, esiste una zona grigia che la legge fatica a inquadrare con la stessa chiarezza.

## Grey Hat

Il grey hat è una via di mezzo ambigua: agisce senza permesso esplicito ma senza intento dannoso, ad esempio segnalando una vulnerabilità trovata "esplorando" un sistema non suo. L'assenza di intento malevolo non equivale però ad avere un'autorizzazione, e la legalità dipende dalla giurisdizione e dalle circostanze concrete — la buona fede non è una scriminante automatica.

Il modo corretto per gestire questa zona grigia ha un nome, **responsible disclosure**: trovare la vulnerabilità, non sfruttarla oltre il necessario per dimostrarla, contattare privatamente il proprietario, dargli il tempo di correggerla prima di qualsiasi divulgazione pubblica. Segue questo processo, senza autorizzazione preventiva, è ancora un grey hat; farlo dentro un programma di bug bounty che lo autorizza esplicitamente sposta l'attività nel campo white hat. Bianco, nero e grigio non esauriscono però la tavolozza.

## Le Altre Categorie: Non Solo Tre Colori

Queste categorie non condividono lo stesso criterio delle prime tre: script kiddie descrive un livello di competenza, hacktivist una motivazione, state-sponsored un'affiliazione — non una posizione sulla stessa scala di autorizzazione.

* **Blue Hat** — il termine non ha una definizione universale: la fonte più citata lo usa per un ricercatore esterno invitato da un'azienda (il nome nasce dagli eventi BlueHat di Microsoft) a testare un prodotto prima del rilascio, ma altre fonti lo usano diversamente
* **Script kiddie** — usa tool e exploit scritti da altri, senza comprenderne davvero il funzionamento interno
* **Hacktivist** — agisce per motivazioni politiche o ideologiche (es. Anonymous)
* **State-sponsored** — opera per conto di un governo, spesso in operazioni di spionaggio o sabotaggio (gruppi APT)

## Tabella Comparativa

| Tipo      | Autorizzazione | Obiettivo                        | Attività tipica                             |
| --------- | -------------- | -------------------------------- | ------------------------------------------- |
| White Hat | Sì             | Migliorare la sicurezza          | Penetration test, security assessment       |
| Black Hat | No             | Profitto o danno                 | Furto dati, ransomware, frode               |
| Grey Hat  | Ambigua        | Ricerca non richiesta            | Vulnerability research senza autorizzazione |
| Blue Hat  | Sì, su invito  | Testare un prodotto pre-rilascio | Security assessment per conto terzi         |

## FAQ

**Chi è un white hat? Cosa fa?** Un white hat è un hacker che opera sempre con autorizzazione esplicita: cerca vulnerabilità in sistemi e applicazioni per segnalarle e farle correggere, non per sfruttarle a proprio vantaggio.

**Chi è un black hat? Cosa fa?** Un black hat è un hacker che accede a sistemi senza autorizzazione per profitto o danno — ruba dati, installa ransomware o virus, vende accessi compromessi sul dark web.

**Chi è un grey hat? Cosa fa?** Un grey hat cerca vulnerabilità senza autorizzazione esplicita ma senza intento dannoso, spesso per segnalarle comunque — l'assenza di intento malevolo non equivale però ad avere un'autorizzazione, e la legalità dipende dalla giurisdizione e dalle circostanze concrete.

**Un grey hat può essere perseguito legalmente anche se segnala la vulnerabilità?** Sì. L'accesso non autorizzato resta di per sé un reato in molte giurisdizioni, a prescindere da cosa si fa dopo averlo scoperto o dalle intenzioni dichiarate.

**Il tool o la tecnica usata determinano se un hacker è white hat o black hat?** No. Nmap, Metasploit o qualsiasi altro strumento sono neutri: la stessa identica tecnica può essere usata in un penetration test autorizzato o in un attacco illecito. A determinare il cappello sono solo autorizzazione e finalità, mai lo strumento.

**White hat ed ethical hacker sono la stessa cosa?** Quasi: nel linguaggio comune sono usati come sinonimi, ma "ethical hacker" descrive più precisamente il professionista che usa competenze di hacking in modo autorizzato, mentre "white hat" è l'etichetta più ampia legata al comportamento e alle intenzioni. Il quadro completo è in [Ethical Hacker: Cos'è e Cosa Fa](https://hackita.it/articoli/ethical-hacker/).

**Qual è la differenza tra white hat e black hat?** Autorizzazione e finalità: il white hat opera col permesso del proprietario per migliorare la sicurezza, il black hat accede o agisce senza autorizzazione per profitto o danno.

**Quali sono i principali tipi di hacker?** White hat, black hat e grey hat sono le tre categorie principali, basate su autorizzazione e obiettivo. Blue hat, script kiddie, hacktivist e state-sponsored esistono come termini aggiuntivi, ma descrivono criteri diversi (invito, competenza, motivazione, affiliazione) e non appartengono alla stessa classificazione.

**Qual è la differenza pratica tra hacker e cracker oggi?** Nel linguaggio comune i due termini si sono fusi; nel gergo tecnico originale la distinzione resta: hacker esplora e comprende, cracker viola senza permesso per danneggiare o trarne profitto.

**Esistono altri "colori" oltre a white, black e grey?** Sì — blue hat è il più citato, ma la terminologia informale include anche varianti meno standardizzate, usate con significati diversi a seconda della fonte.

**Cosa significa script kiddie?** Descrive chi usa tool ed exploit scritti da altri senza comprenderne davvero il funzionamento — è una classificazione per livello di competenza, non per autorizzazione o intento.

**Cosa significa hacktivist?** Chi usa tecniche di hacking per motivazioni politiche o ideologiche piuttosto che per profitto personale — la legalità dell'azione dipende comunque dall'autorizzazione, non dalla causa che la motiva.

**Cosa significa state-sponsored hacker?** Un attaccante che opera per conto o su commissione di un governo, tipicamente in operazioni di spionaggio, sabotaggio o influenza — i gruppi tracciati come APT rientrano quasi sempre in questa categoria.
