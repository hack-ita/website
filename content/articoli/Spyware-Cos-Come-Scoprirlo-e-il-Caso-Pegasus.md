---
title: 'Spyware: Cos''è, Come Scoprirlo e il Caso Pegasus'
slug: spyware
description: >-
  Scopri come funziona uno spyware, i segnali per scoprirlo su telefono e PC, la
  differenza con lo stalkerware, come rimuoverlo e cosa riverò il caso Pegasus.
image: /spyware-come-funziona-segnali-stalkerware-pegasus.webp
draft: false
date: 2026-10-05T12:51:09.532Z
lastmod: 2026-10-05T12:54:59.616Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - spyware
  - spyware android
  - spyware iphone
  - pegasus spyware
  - stalkerware
---

# Spyware: Cos'è, Come Funziona e Come Scoprirlo

Uno spyware è un malware progettato per raccogliere informazioni su una persona senza che se ne accorga — cosa digita, cosa naviga, dove si trova, a volte persino cosa vede e sente attraverso webcam e microfono. Sul cellulare viene spesso chiamato anche **"app spia"**, dato che nella maggior parte dei casi arriva proprio come un'app apparentemente innocua. A differenza di un virus o di un worm, il suo obiettivo non è danneggiare o replicarsi: è restare invisibile il più a lungo possibile, perché ogni giorno in più di sorveglianza è dati in più raccolti.

> **In breve:** uno spyware è un malware che raccoglie informazioni sulla vittima all'insaputa — attività di navigazione, posizione, comunicazioni — senza necessariamente danneggiare il sistema. Il [keylogger](https://hackita.it/articoli/keylogger/) è una delle sue forme più comuni, ma non l'unica.

## Come Funziona uno Spyware

Il meccanismo segue quasi sempre lo stesso schema: **installazione** (spesso nascosta dentro un altro programma, un'app o un allegato), **esecuzione silenziosa** all'avvio del sistema o del dispositivo, **raccolta dati** in background secondo quello per cui è stato progettato, e infine **invio periodico** di quei dati a un server controllato da chi lo gestisce. La parte che lo rende difficile da notare non è la raccolta in sé, ma il fatto che ogni fase è pensata per non generare alcun sintomo visibile — a differenza di un virus con un payload distruttivo, lo spyware "funziona bene" proprio quando la vittima non si accorge di nulla.

Come arriva sul dispositivo dipende dal livello di sofisticazione: la maggior parte dello spyware comune si installa tramite un [trojan](https://hackita.it/articoli/trojan/), un'app scaricata fuori dagli store ufficiali, un link di phishing o, nel caso dello stalkerware, l'accesso fisico diretto al telefono di qualcun altro. Gli spyware più avanzati, come Pegasus di cui parliamo tra poco, possono invece sfruttare exploit zero-click che non richiedono alcuna azione della vittima.

## Cosa Raccoglie Davvero uno Spyware

Le categorie di dati variano molto in base a quanto è sofisticato:

| Tipo di raccolta              | Cosa comporta                                                        |
| ----------------------------- | -------------------------------------------------------------------- |
| Cronologia di navigazione     | Siti visitati, ricerche effettuate, abitudini online                 |
| Keylogging                    | Ogni tasto digitato — password, messaggi, numeri di carta            |
| Screen capture                | Screenshot periodici o continui dello schermo                        |
| Accesso a microfono/webcam    | Attivazione da remoto senza alcun indicatore visibile per la vittima |
| Localizzazione                | Posizione GPS in tempo reale, soprattutto su dispositivi mobili      |
| Accesso a messaggi e contatti | SMS, chat, rubrica, spesso su smartphone compromessi                 |

Uno spyware avanzato può combinare più di questi elementi contemporaneamente, come è emerso in modo eclatante con gli spyware commerciali di livello statale.

## Il Caso Pegasus: lo Spyware più Sofisticato Mai Documentato Pubblicamente

Pegasus, sviluppato dall'azienda israeliana NSO Group, è il caso che ha cambiato la percezione pubblica di cosa sia davvero possibile fare con questa categoria di malware. Reso pubblico per la prima volta nel 2016 dal [Citizen Lab](https://citizenlab.ca/spyware-litigation-tracker-legal-challenges-and-formal-complaints-related-to-mercenary-spyware/) dell'Università di Toronto — dopo un tentativo fallito di infettare il telefono dell'attivista per i diritti umani Ahmed Mansoor — alcune campagne Pegasus hanno sfruttato exploit **zero-click** come FORCEDENTRY contro iMessage: la vittima non deve cliccare né aprire nulla perché la compromissione inizi, una caratteristica del vettore di attacco più che della categoria spyware in sé. Una volta compromesso il dispositivo, le capacità effettive dipendono da variante, sistema operativo ed exploit usati; nei casi documentati da Citizen Lab, Pegasus ha permesso l'accesso a messaggi, contatti, calendario e cronologia, oltre all'attivazione di microfono e fotocamera in specifici campioni.

Nel luglio 2021 il "Pegasus Project" — un'indagine giornalistica internazionale coordinata su una lista trapelata di 50.000 numeri di telefono selezionati come possibili bersagli — portò alla luce l'uso dello spyware contro giornalisti, avvocati per i diritti umani e attivisti in decine di paesi. WhatsApp e Meta hanno citato in giudizio NSO Group nel 2019, sostenendo che Pegasus fosse stato usato contro circa 1.400 dispositivi sfruttando una vulnerabilità della piattaforma.

Il punto distintivo di Pegasus rispetto agli spyware "comuni" trattati nel resto dell'articolo è il modello di business: non è distribuito da criminali comuni per rubare credenziali bancarie, ma venduto come strumento a governi — con tutte le implicazioni sui diritti umani che questo comporta quando finisce nelle mani sbagliate. Apple stessa distingue oggi questa categoria, che chiama **mercenary spyware**, dalle minacce consumer: risorse enormi, bersagli numericamente limitati, costi elevatissimi per singola operazione.

## Spyware Commerciale vs Stalkerware

Non tutto lo spyware richiede le capacità di un'azienda con risorse statali. Esiste un intero mercato di app pubblicizzate per il "controllo genitori" o il "monitoraggio dipendenti" che, installate sul dispositivo di un partner o un familiare a sua insaputa, funzionano esattamente come uno spyware. Questa categoria è nota come **stalkerware**: secondo la definizione della Coalition Against Stalkerware, è software che permette il monitoraggio occulto di un dispositivo senza il consenso di chi lo usa — l'accesso fisico necessario per installarlo è spesso il metodo, ma non è di per sé ciò che la definisce, perché anche un consenso apparente non è automaticamente consenso informato. Il confine tra "monitoraggio autorizzato" (un genitore su un dispositivo di un minore, un'azienda su un dispositivo aziendale dichiarato) e sorveglianza illecita dipende quasi interamente da trasparenza e consenso — mai dalla tecnologia usata, che è spesso identica.

## Come Riconoscere uno Spyware

Un buon spyware, come un buon trojan, è progettato per non dare segnali. Alcuni indizi restano comunque frequenti: batteria che si scarica più in fretta del solito (specialmente su smartphone, dove la localizzazione continua consuma parecchio), consumo dati anomalo per un'app che dovrebbe essere leggera, surriscaldamento del dispositivo anche da inattivo, e — su computer — un antivirus che rileva processi sconosciuti in esecuzione in background. Su smartphone, app che richiedono permessi sproporzionati rispetto alla loro funzione dichiarata (una torcia che chiede accesso a microfono e contatti) sono un segnale da non ignorare mai.

Un controllo concreto e alla portata di chiunque: su Android, Impostazioni → App → \[nome app] → Autorizzazioni mostra esattamente cosa ogni app può vedere o usare; su iOS lo stesso percorso è Impostazioni → Privacy e sicurezza. Rivedere questa lista una volta ogni tanto, revocando ciò che non ha una ragione evidente, è più efficace di qualsiasi scansione contro le app di spyware commerciale meno sofisticate — quelle mercenarie come Pegasus sono un'altra storia, e lo vediamo tra poco.

## Come Rimuovere uno Spyware

1. **Scansiona con un antimalware aggiornato**, specifico per spyware se disponibile — molti antivirus generalisti hanno moduli dedicati.
2. **Rivedi i permessi delle app** su smartphone e rimuovi quelli concessi senza una ragione chiara.
3. **Disinstalla le app sospette**, in particolare quelle installate di recente o non riconosciute.
4. **Aggiorna il sistema operativo**: molti spyware commerciali sfruttano vulnerabilità già corrette nelle versioni più recenti.
5. **Nei casi di sospetto stalkerware**, valuta il reset completo del dispositivo alle impostazioni di fabbrica — spesso è il modo più affidabile per essere certi di aver rimosso tutto, e cambia le credenziali di ogni account da un dispositivo diverso subito dopo.

> ⚠️ Se sospetti stalkerware in un contesto di abuso o violenza domestica, non rimuoverlo d'impulso: chi lo ha installato può accorgersi della rimozione, e questo può creare un rischio concreto per la tua sicurezza. La Coalition Against Stalkerware raccomanda di valutare prima un piano di sicurezza personale, eventualmente con supporto specialistico, prima di agire sul dispositivo.

## Sospetti di Avere uno Spyware Adesso? Cosa Controllare

Se sei arrivato a questo articolo perché temi che qualcuno ti stia davvero sorvegliando, ecco da dove partire concretamente, senza panico.

1. **Controlla i permessi app** (Android: Impostazioni → App → \[app] → Autorizzazioni; iOS: Impostazioni → Privacy e sicurezza) e revoca tutto ciò che non ha una ragione evidente per esistere.
2. **Su Android, controlla le app con privilegi di amministratore del dispositivo** (Impostazioni → Sicurezza → App di amministrazione dispositivo): è un privilegio che uno spyware installato fisicamente usa spesso per resistere alla disinstallazione, e su un telefono "pulito" questa lista è di norma vuota o limitata ad app di sistema riconoscibili.
3. **Lancia una scansione con un antimalware aggiornato** — Play Protect su Android è già attivo di default, ma un secondo controllo con un prodotto dedicato non fa male.
4. **Se sospetti stalkerware in un contesto di abuso**, rileggi l'avviso più sopra prima di agire: la rimozione può essere visibile a chi ti sta sorvegliando.

Nessuno di questi controlli smaschera uno spyware mercenario avanzato come Pegasus — quello richiede analisi forense specialistica, non è alla portata di un controllo fai-da-te. Ma sono un buon punto di partenza per la stragrande maggioranza dei casi reali, che sono app commerciali o stalkerware, non operazioni di livello statale.

## FAQ

**Cos'è uno spyware?** È un malware che raccoglie informazioni sulla vittima — navigazione, posizione, comunicazioni — senza il suo consenso, restando il più possibile invisibile.

**Qual è la differenza tra spyware e virus?** Il virus è definito dalla replicazione tramite un file ospite; lo spyware è definito dallo scopo (sorveglianza), non dal meccanismo di diffusione, e spesso arriva tramite un [trojan](https://hackita.it/articoli/trojan/).

**Cos'è Pegasus?** È lo spyware sviluppato da NSO Group, reso famoso dal Pegasus Project del 2021: capace di infettare un telefono senza alcuna azione della vittima e di accedere a messaggi, microfono, webcam e posizione.

**Cos'è lo stalkerware?** App di monitoraggio, spesso vendute come "controllo genitori", che permettono di sorvegliare un dispositivo senza il consenso di chi lo usa — l'accesso fisico per installarle è spesso il metodo usato, ma non è ciò che le rende stalkerware: è l'assenza di consenso informato.

**Il mio telefono ha uno spyware?** I segnali più comuni sono batteria e dati che si consumano più del previsto, surriscaldamento anomalo e app con permessi ingiustificati — nessuno di questi da solo è una prova definitiva, ma insieme meritano un controllo.
