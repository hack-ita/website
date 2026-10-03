---
title: 'Flipper Zero: Cos''è, A Cosa Serve ed È Legale in Italia?'
slug: flipper-zero
description: 'Flipper Zero: cos''è, come funziona e cosa può fare tra RFID, NFC, Sub-GHz e BadUSB. Scopri firmware custom e cosa è legale fare in Italia e cosa è illegale'
image: /flipper-zero-hacking-radio-rfid-nfc.webp
draft: true
date: 2026-10-11T23:38:24.913Z
lastmod: 2026-10-11T23:38:25.904Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Flipper Zero
  - NFC
  - RFID
  - Sub-GHz
  - BadUSB
---

# Flipper Zero: Come Funziona e Cosa Può Fare Davvero

Il **Flipper Zero** è un dispositivo portatile a forma di multitool, prodotto da **Flipper Devices**, pensato per studiare, leggere, salvare e in alcuni casi riprodurre segnali e protocolli wireless: **Sub-GHz**, **NFC**, **RFID a 125 kHz**, **infrarossi**, **Bluetooth Low Energy** e **GPIO**. È diventato virale sui social per la sua capacità di "clonare" telecomandi e tessere, ma gran parte di quello che si vede online è esagerato o frainteso.

È uno strumento legittimo per hobbisti, ricercatori di sicurezza e pentester, con un hardware aperto e un firmware open source. Il problema non è il dispositivo: è come e dove viene usato.

## Flipper Zero cos'è: hardware e specifiche

Il Flipper Zero nasce da una campagna Kickstarter del 2020 e sul negozio ufficiale (shop.flipper.net) è venduto a **169 dollari**, più spedizione; prezzo e disponibilità possono variare per mercato e periodo. Al suo interno:

| Componente                      | Funzione                                                                                                                                             |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **STM32WB55**                   | Microcontrollore principale, dual-core, con Bluetooth integrato                                                                                      |
| **CC1101**                      | Transceiver Sub-GHz: riceve nelle bande 300-348, 387-464 e 779-928 MHz; la trasmissione è limitata alle frequenze consentite nella regione impostata |
| **ST25R3916**                   | Chip NFC, per tag e carte a 13,56 MHz                                                                                                                |
| **Antenna RFID a 125 kHz**      | Per badge e chiavi più datate (EM4100, HID, T5577)                                                                                                   |
| **Ricevitore/trasmettitore IR** | Emula telecomandi                                                                                                                                    |
| **Pin GPIO**                    | Permette di collegare moduli esterni e interagire con hardware (UART, SPI, 1-Wire)                                                                   |
| **iButton / 1-Wire**            | Legge, salva ed emula chiavi a contatto supportate                                                                                                   |
| **Slot microSD**                | Richiesta per l'uso pieno del dispositivo: non è inclusa in confezione                                                                               |

La microSD non è inclusa in confezione ed è richiesta per l'uso pieno del dispositivo: molte applicazioni, tra cui NFC, RFID, Sub-GHz e BadUSB, la usano per salvare dati e database.

## A cosa serve davvero: i moduli uno per uno

### Sub-GHz: cancelli, telecomandi e sensori

Il Flipper ascolta le frequenze più comuni usate da telecomandi di cancelli, barriere, centraline auto e alcuni sensori wireless. Se il protocollo non usa un codice che cambia a ogni uso (*rolling code*), può registrare il segnale e ritrasmetterlo. Il firmware ufficiale riconosce decine di protocolli, ma **blocca volutamente** il replay dei rolling code noti usati da auto e molti cancelli moderni, proprio per limitare gli abusi più ovvi.

### NFC e RFID: carte e badge

Il modulo NFC legge tag e carte a 13,56 MHz: abbonamenti per i trasporti, chiavi hotel, badge aziendali e, parzialmente, carte di pagamento contactless (il Flipper legge i dati esposti dal protocollo, non clona una carta di credito funzionante). Il modulo RFID a 125 kHz lavora su tecnologie più vecchie come EM4100 e HID Prox, spesso scrivibili su una tessera vergine T5577.

### Infrarossi

Funziona come un telecomando universale: impara e riproduce i segnali IR di TV, condizionatori e altri dispositivi a infrarossi.

### Bluetooth Low Energy

Può interagire con dispositivi BLE nelle vicinanze. Alcune funzioni dimostrative (come lo spam di notifiche BLE verso smartphone) sono state in gran parte neutralizzate dagli aggiornamenti recenti di iOS e Android.

### GPIO e BadUSB

I pin GPIO permettono di collegare moduli esterni (schede Wi-Fi, lettori aggiuntivi) e di usare protocolli come UART e SPI per interagire con schede elettroniche. La modalità **BadUSB** emula una tastiera USB e digita comandi automaticamente non appena collegata a un computer: la stessa tecnica di dispositivi come il [Rubber Ducky](https://hackita.it/articoli/rubber-ducky/).

## Flipper Zero può clonare carte, badge e telecomandi?

Dipende dalla tecnologia. Non esiste una risposta unica valida per "tutto":

| Oggetto                                             | Può leggerlo?                            | Può emularlo o scriverlo?                   |
| --------------------------------------------------- | ---------------------------------------- | ------------------------------------------- |
| RFID a 125 kHz supportato (EM4100, HID Prox)        | Sì                                       | In molti casi, su tessera T5577             |
| NFC supportato (es. MIFARE Classic con chiave nota) | Sì                                       | In alcuni casi, dipende dal tipo di carta   |
| Telecomandi Sub-GHz senza rolling code              | Sì                                       | Sì, via replay                              |
| Telecomandi con rolling code moderni                | Limitato                                 | No, non come semplice replay                |
| Carte bancarie EMV                                  | Legge solo i dati esposti dal protocollo | No, non come carta di pagamento funzionante |

Anche per l'NFC la differenza è tecnica: per alcuni tipi di carta il Flipper può emulare l'intero contenuto, per altri solo l'UID (l'identificativo), che non basta a riprodurre un sistema di accesso più sofisticato.

## Cosa il Flipper Zero NON può fare

Molti video virali esagerano. Il Flipper Zero:

* **non clona carte di credito** per pagamenti reali: i chip EMV usano crittografia che il Flipper non sfrutta;
* **non apre la maggior parte delle auto moderne**: i rolling code non sono replicabili con un semplice replay;
* **non "hackera" uno smartphone** da solo: le funzioni BLE sono dimostrazioni di interferenza, non un'intrusione nel dispositivo;
* **non è una SDR** (*Software Defined Radio*): il chip CC1101 copre una banda stretta e non mostra lo spettro radio come fa un [HackRF One](https://hackita.it/articoli/hackrf-one/);
* **non bypassa la crittografia** dei sistemi moderni: funziona bene contro protocolli vecchi o non cifrati, molto meno contro quelli aggiornati.

## Flipper Zero vs HackRF One vs Proxmark3

|                | Flipper Zero                             | HackRF One                         | Proxmark3                                    |
| -------------- | ---------------------------------------- | ---------------------------------- | -------------------------------------------- |
| Tipo           | Multitool integrato                      | SDR vera e propria                 | Strumento specializzato RFID/NFC             |
| Portabilità    | Alta                                     | Media                              | Media                                        |
| Facilità d'uso | Alta                                     | Richiede più competenza            | Curva di apprendimento maggiore              |
| Punto di forza | Varietà di protocolli in un solo oggetto | Banda larga, analisi dello spettro | Profondità su RFID/NFC per security research |

In sintesi: il Flipper è il generalista tascabile, l'HackRF è lo strumento per chi deve vedere e analizzare lo spettro radio, il Proxmark3 è il riferimento per chi lavora seriamente su RFID e NFC.

## Firmware: ufficiale e community

Il firmware ufficiale è open source (licenza GPLv3) ed è deliberatamente conservativo: rilascia le funzionalità con prudenza e rispetta i limiti regionali sulle frequenze radio. Intorno al Flipper è nata una delle community di firmware più attive dell'hardware open:

| Firmware        | Impostazione                                                                                                                            |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Ufficiale**   | Stabile, limiti regionali rispettati, aggiornamenti prudenti                                                                            |
| **Unleashed**   | Base stabile, con i blocchi regionali rimossi                                                                                           |
| **Momentum**    | Firmware derivato dall'ecosistema Official/Unleashed e continuazione del progetto Xtreme, con personalizzazione spinta e plugin manager |
| **RogueMaster** | Il pacchetto più ricco di app e animazioni, combina Unleashed e Xtreme                                                                  |

*Situazione aggiornata a ottobre 2026: il firmware ufficiale resta sviluppato da Flipper Devices, Unleashed e Momentum sono progetti community attivi, Xtreme non riceve più sviluppo autonomo dalla fine del 2024.*

Un punto importante: **nessun firmware cambia cosa è legale fare**. Rimuovere un blocco regionale non significa che trasmettere su quella frequenza sia permesso nel tuo paese: la responsabilità resta di chi usa il dispositivo, non del firmware.

## È legale il Flipper Zero in Italia?

**Possedere e acquistare un Flipper Zero è legale in Italia.** Non esiste un divieto sul dispositivo in sé: è hardware di uso generale, come un computer o un saldatore.

Cambia tutto in base all'uso:

* **leggere o testare i tuoi dispositivi, badge e cancelli** è lecito;
* **testare sistemi di terzi con autorizzazione scritta** (penetration test, audit fisico) è lecito;
* **usare il dispositivo su sistemi, account o proprietà altrui senza autorizzazione** (clonare il badge di un collega, aprire un cancello non tuo) non è coperto da nessuna liceità e, a seconda del caso, può rilevare penalmente.

Il dispositivo non è di per sé vietato: la liceità dipende dall'attività svolta, dall'autorizzazione del proprietario del sistema e, per le trasmissioni radio, dalle regole applicabili a frequenze e potenze. In Italia l'uso delle frequenze è disciplinato dal **Codice delle comunicazioni elettroniche**, e lo stesso Flipper applica dei limiti regionali alla trasmissione Sub-GHz in base al paese impostato. All'estero, inoltre, alcune dogane hanno in passato trattenuto spedizioni del dispositivo per approfondimenti: se viaggi, informati sulle regole del paese di destinazione.

## Flipper Zero per chi fa sicurezza: usi legittimi

Nel lavoro di sicurezza fisica e offensiva, il Flipper è utile per:

* **audit di badge RFID/NFC aziendali**, per verificare se usano tecnologie deboli o facilmente clonabili;
* **test di cancelli e barriere** in un contesto di physical penetration test autorizzato;
* **simulazioni BadUSB** per valutare le policy USB di un'organizzazione (porte bloccate, allowlist dei dispositivi);
* **didattica**: è uno strumento pratico per capire come funzionano RFID, NFC e protocolli radio a basso livello, prima ancora di parlare di attacco o difesa.

Va sempre usato su sistemi propri o con un'autorizzazione scritta esplicita, come qualsiasi altro strumento da [red team](https://hackita.it/articoli/red-team/).

## Dove comprarlo e cosa sapere prima

In Europa si trova anche tramite rivenditori come Lab401 o, in modo discontinuo, su Amazon tramite venditori terzi: diffida dei prezzi troppo bassi, circolano cloni di qualità incerta. Serve una microSD (classe 10 consigliata), non inclusa in confezione.

## Flipper One: non è un semplice Flipper Zero più potente

Flipper Devices ha annunciato **Flipper One** il 21 maggio 2026: un mini computer Arm Linux tascabile con SoC Rockchip RK3576, 8 GB di RAM e un NPU da 6 TOPS. È un **progetto distinto dal Flipper Zero**, non un suo aggiornamento: l'azienda stessa lo presenta come una piattaforma diversa, pensata per un pubblico più avanzato, con un prezzo target dichiarato sotto i 350 dollari per la configurazione base. Il Flipper Zero resta il modello oggi disponibile e di riferimento per chi inizia.

## Domande frequenti sul Flipper Zero

### Cos'è il Flipper Zero?

Un dispositivo portatile per leggere, analizzare e in alcuni casi riprodurre segnali Sub-GHz, NFC, RFID, infrarossi e Bluetooth Low Energy, con firmware open source.

### Il Flipper Zero è legale in Italia?

Sì, possederlo e acquistarlo è legale. Diventa un problema solo l'uso contro sistemi di cui non sei proprietario e senza autorizzazione.

### Il Flipper Zero può clonare qualsiasi carta o badge?

No. Funziona bene su tecnologie vecchie o non cifrate (RFID a 125 kHz, alcuni NFC). Le carte di credito e i badge con crittografia moderna non sono clonabili con un semplice replay.

### Il Flipper Zero può aprire le auto?

Nella grande maggioranza dei casi no: i sistemi di apertura auto moderni usano rolling code che cambiano a ogni utilizzo e il firmware ufficiale ne blocca volutamente il replay.

### Serve una microSD per usare il Flipper Zero?

Sì, è richiesta per l'uso pieno del dispositivo e non è inclusa in confezione: molte funzioni, tra cui NFC, RFID, Sub-GHz e BadUSB, la usano per salvare dati.

### Qual è la differenza tra Flipper Zero e HackRF One?

Il Flipper è un multitool pratico e immediato, con ricezione Sub-GHz in bande specifiche e nessuna visualizzazione dello spettro. L'HackRF è una vera SDR, con banda molto più ampia e capacità di analisi dello spettro, ma richiede più competenza per essere usata.

### Installare un firmware custom è legale?

Il firmware in sé non cambia le leggi: rimuovere un blocco regionale non rende legale trasmettere su quella frequenza se non lo è già nel tuo paese.

### A cosa serve il Flipper Zero per chi lavora in sicurezza?

Ad audit di badge aziendali, test di controlli di accesso fisico, simulazioni BadUSB e didattica su protocolli RFID/NFC, sempre con autorizzazione.

### Quanto costa il Flipper Zero?

Sul negozio ufficiale è venduto a 169 dollari più spedizione; prezzo e disponibilità variano nel tempo e da mercato a mercato.
