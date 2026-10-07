---
title: 'RAT (Remote Access Trojan): Cosa Fa E Come Riconoscerlo'
slug: rat
description: 'Cos''è un RAT, come funziona un trojan di controllo remoto, come capire se il tuo PC è infetto ,come rimuoverlo e la storia di Back Orifice e Blackshades.'
image: /rat-remote-access-trojan-malware.jpeg
draft: false
date: 2026-10-12T12:43:17.895Z
lastmod: 2026-10-12T12:43:15.592Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - RAT
  - Remote Access Trojan
  - RAT malware
  - trojan
  - remote access trojan
---

# RAT (Remote Access Trojan): Cos'è e Come Funziona

Un RAT, Remote Access Trojan, è un [trojan](/articoli/trojan/) progettato per dare a un operatore remoto la capacità di eseguire comandi e controllare determinate funzioni di un dispositivo compromesso — non solo rubare dati una volta e sparire, ma restare connesso e comandare quel dispositivo nel tempo. Le capacità effettive dipendono dal malware specifico e dai privilegi ottenuti: possono includere accesso ai file, esecuzione di comandi, keylogging, screenshot e, quando supportato da dispositivo e sistema operativo, attivazione di webcam o microfono.

> **In breve:** un RAT è un trojan che fornisce controllo remoto continuativo su un dispositivo infetto, con capacità che variano da malware a malware — dal semplice accesso ai file fino a webcam, microfono e tastiera nei casi più completi.

## Come Funziona un RAT

L'architettura è sempre la stessa a prescindere dal malware specifico: un componente **server** (o "agent") installato sul dispositivo della vittima, e un componente **client** (o "controller") usato dall'operatore per impartire comandi. Dopo l'infezione iniziale, il RAT cerca **persistenza** — sopravvivere a un riavvio — e apre una connessione verso un'infrastruttura di **comando e controllo (C2)**: da lì riceve istruzioni, le esegue sul dispositivo compromesso, e restituisce i risultati o i dati raccolti all'operatore. Molti RAT non mantengono una connessione costante ma fanno "beaconing": si ricollegano a intervalli regolari per chiedere se ci sono nuovi comandi, il che li rende più difficili da individuare rispetto a una connessione sempre aperta.

Come arriva un RAT sul dispositivo non è diverso dagli altri trojan: allegati di phishing, software piratato o crack, falsi aggiornamenti, link malevoli o, in un attacco strutturato, come secondo stadio scaricato da un malware già presente — spesso il RAT non è il primo punto di ingresso, ma quello che l'attaccante installa dopo aver già ottenuto un primo accesso.

## Cosa Può Fare Davvero un RAT

| Capacità                                                    | Cosa comporta                                                                                  |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Controllo file system                                       | Vedere, scaricare, modificare o cancellare qualsiasi file                                      |
| Keylogging                                                  | Registrare tutto ciò che viene digitato, incluse le password                                   |
| Accesso webcam/microfono                                    | Attivazione da remoto, quando supportata da hardware, driver e privilegi ottenuti              |
| Screen capture                                              | Screenshot o registrazione continua dello schermo                                              |
| Esecuzione comandi                                          | Lanciare programmi, aprire una shell, installare altro malware                                 |
| Uso come nodo [botnet](/articoli/botnet/) | Il dispositivo compromesso viene aggiunto a una rete più ampia, per attacchi DDoS o come proxy |

## Back Orifice: un Precursore dei RAT Moderni

Uno dei primi esempi divenuti pubblicamente famosi di software con caratteristiche poi associate ai RAT fu **Back Orifice**, rilasciato nel 1998 dal collettivo hacker Cult of the Dead Cow, che lo presentò come strumento di amministrazione e monitoraggio remoto per Windows — un'ambiguità voluta, dato che il dibattito dell'epoca riguardava esattamente dove finisse la ricerca sulla sicurezza e iniziasse la distribuzione di uno strumento offensivo. Il nome era un gioco di parole sul software di gestione remota Microsoft "BackOffice", e la sua presentazione a DEF CON scatenò polemiche enormi. Da lì il concetto si è evoluto, ma la struttura di base — un componente server nascosto sul dispositivo della vittima e un componente client usato dall'attaccante per controllarlo — resta la stessa di ogni RAT moderno.

## Il Caso Blackshades: un RAT Venduto come un Prodotto Software

Blackshades è il caso che meglio racconta come un RAT sia diventato, nel tempo, un vero e proprio prodotto commerciale criminale. Venduto a partire dal 2010 a un prezzo di appena 40 dollari, includeva keylogging, accesso a webcam e microfono, furto di credenziali e persino un modulo per usare i dispositivi infetti in attacchi DDoS — il tutto con un'interfaccia semplice da usare, senza richiedere alcuna competenza tecnica a chi lo comprava. Il suo creatore, Alex Yucel, gestiva l'operazione come un'azienda vera e propria, con un team dedicato a marketing e assistenza clienti.

Nel maggio 2014 l'[FBI](https://www.fbi.gov/news/stories/international-blackshades-malware-takedown-1), in coordinamento con le forze dell'ordine di altri 18 paesi, ha condotto una delle più grandi operazioni internazionali mai realizzate contro un singolo malware: oltre 90 arresti, più di 300 perquisizioni in tutto il mondo e il sequestro di quasi 1.900 domini usati per controllare i computer delle vittime. Le indagini rivelarono che erano stati venduti circa 6.000 profili cliente in oltre 100 paesi — un'indicazione di quanto fosse diffuso l'uso di questo tipo di strumento anche tra chi non aveva alcuna competenza da "hacker".

## RAT vs Backdoor vs Spyware

I termini si sovrappongono spesso nella pratica, ma indicano concetti diversi. **Backdoor** descrive in modo ampio qualsiasi meccanismo che consenta accesso o controllo non autorizzato attraverso un percorso nascosto — non è sinonimo di RAT: un RAT può implementare una backdoor come uno dei suoi meccanismi di accesso, ma "backdoor" da sola non implica le funzionalità interattive tipiche di un RAT (keylogging, webcam, controllo in tempo reale). Uno [spyware](/articoli/spyware/) è definito dallo scopo (raccogliere informazioni), mentre un RAT è definito dalla capacità (controllo remoto attivo) — un RAT è quasi sempre anche uno spyware, ma non tutti gli spyware permettono un controllo interattivo in tempo reale come fa un RAT.

## Come Riconoscere un RAT

I segnali più concreti riguardano proprio le capacità che un RAT sfrutta attivamente: la spia della webcam che si accende per un istante senza che nessuna app legittima sia in uso, il mouse o il cursore che si muove autonomamente, file che compaiono o scompaiono senza intervento dell'utente, e un consumo di banda anomalo anche a computer inattivo — segno che qualcuno dall'altra parte potrebbe star trasferendo dati o guardando lo schermo in tempo reale. Nessuno di questi segnali, da solo, è una prova: una spia webcam può attivarsi per un bug di un'app legittima, un cursore può muoversi per un problema di driver. È la combinazione di più segnali, non uno isolato, a giustificare un controllo più approfondito. Un RAT ben scritto, come qualsiasi trojan, cerca di restare silenzioso il più possibile, ma il controllo interattivo lascia più tracce comportamentali di un malware puramente automatizzato.

Un primo controllo pratico, su Windows, si fa con `netstat -ano` da prompt dei comandi: elenca le connessioni di rete attive insieme al PID del processo che le ha aperte, così puoi risalire da una connessione sospetta al programma che la genera tramite Gestione Attività. Attenzione però: una connessione "ESTABLISHED" verso un PID che non riconosci al volo non è di per sé prova di un RAT — può essere il browser, un aggiornamento di Windows, un client cloud o qualsiasi altro software legittimo. `netstat` serve a *correlare* una connessione a un processo, non a *diagnosticare* un'infezione da solo; il passo successivo è verificare cosa sia davvero quel processo prima di trarre conclusioni.

## Come Proteggersi

Le difese sono in gran parte le stesse valide contro ogni trojan — non installare software da fonti non ufficiali, diffidare di allegati inattesi, mantenere sistema e antivirus aggiornati. Un accorgimento in più specifico per i RAT: coprire fisicamente la webcam quando non in uso riduce il rischio legato a quella singola funzione, ma va inteso per quello che è — una misura fisica limitata, non una neutralizzazione del RAT. Non protegge da furto di file, keylogging, screenshot o accesso a una shell, che restano possibili anche a webcam coperta.

## Pensi che Qualcuno Ti Stia Controllando il PC Adesso? Verifica Così

1. **Controlla `netstat -ano`** da prompt dei comandi: guarda le connessioni con stato "ESTABLISHED" verso indirizzi che non riconosci, annota il PID nell'ultima colonna e cercalo in Gestione Attività per risalire al programma — ricorda che una connessione sconosciuta è un punto di partenza per indagare, non una diagnosi.
2. **Su Windows, controlla l'accesso recente a webcam e microfono**: Impostazioni → Privacy e sicurezza → Fotocamera (e Microfono) mostra quali app li hanno usati di recente — se compare un'app che non hai mai autorizzato consapevolmente, è un segnale concreto.
3. **Apri Gestione Attività, scheda Prestazioni → Rete**, e osserva se c'è traffico costante mentre non stai facendo nulla che lo giustifichi: un RAT attivo genera traffico anche a computer "inattivo" secondo te.
4. **Se trovi una conferma concreta**, isola il dispositivo dalla rete prima di fare qualsiasi altra cosa, poi procedi con una scansione completa e il cambio di tutte le credenziali sensibili da un dispositivo diverso.

## FAQ

**Cos'è un RAT?** È un trojan che dà a un operatore remoto la capacità di eseguire comandi e controllare determinate funzioni di un dispositivo compromesso nel tempo — non solo un furto di dati isolato. Le capacità esatte dipendono dal malware specifico.

**Qual è la differenza tra RAT e trojan generico?** Ogni RAT è un trojan, ma non ogni trojan è un RAT: un RAT si distingue per la capacità specifica di dare controllo remoto interattivo, mentre altri trojan possono avere scopi diversi (rubare credenziali una volta, scaricare altro malware, e così via).

**Come faccio a sapere se ho un RAT sul dispositivo?** I segnali più concreti sono la spia della webcam che si accende senza motivo, consumo di banda anomalo anche da inattivo e file che cambiano senza intervento — nessuno da solo è definitivo, ma insieme meritano un controllo con un antimalware aggiornato.

**Un RAT può essere usato legalmente?** Gli strumenti di amministrazione remota legittimi (usati ad esempio dal supporto IT) condividono principi tecnici simili, ma la differenza sta sempre nel consenso: installato all'insaputa della vittima, un RAT è malware indipendentemente da come viene chiamato commercialmente.

**Coprire la webcam serve davvero a qualcosa?** Riduce il rischio legato alla sola acquisizione video, ma non rimuove né neutralizza il RAT: furto di file, keylogging, screenshot e accesso a una shell restano possibili anche a webcam coperta.
