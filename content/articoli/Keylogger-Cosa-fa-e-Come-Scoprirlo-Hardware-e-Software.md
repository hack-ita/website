---
title: 'Keylogger: Cosa fa e Come Scoprirlo (Hardware e Software)'
slug: keylogger
description: |
  Come funziona un keylogger e cos'è, hardware e software, come riconoscerlo su Windows e cosa dice la legge, dal caso FTC contro l'app SpyFone.
image: /keylogger-hardware-software-windows-spyfone.webp
draft: false
date: 2026-10-12T12:57:21.444Z
lastmod: 2026-10-12T12:57:24.211Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - keylogger
  - keylogger hardware
  - keylogger software
  - keylogger windows
  - spyfone
---

# Keylogger: Cos'è, Come Funziona e Come Scoprirlo

Un keylogger è un software o un dispositivo hardware che registra gli input da tastiera, di nascosto rispetto a chi la sta usando. È probabilmente la forma di sorveglianza digitale più diretta che esista: a seconda dell'implementazione può catturare credenziali, messaggi e altri dati digitati — non serve necessariamente interpretare traffico di rete o decifrare comportamenti, spesso basta leggere quello che la vittima ha scritto.

> **In breve:** un keylogger registra ogni tasto digitato su un dispositivo, all'insaputa di chi lo usa. Può essere un software installato come componente di uno [spyware](https://hackita.it/articoli/spyware/) o un [trojan](https://hackita.it/articoli/trojan/), oppure un piccolo dispositivo hardware collegato fisicamente tra tastiera e computer.

## Come Funziona un Keylogger

Il principio è lo stesso per ogni variante: **intercettare** l'input prima o mentre viene elaborato dal sistema, **registrarlo** in un log locale, ed **esfiltrarlo** — inviarlo a un server remoto, subito o a intervalli. Dove cambia è il punto di intercettazione: un keylogger software si inserisce tra la tastiera e le applicazioni a livello di sistema operativo (a volte più in profondità, a livello kernel, per essere più difficile da individuare); un keylogger hardware intercetta il segnale elettrico ancora prima che raggiunga il computer, motivo per cui nessun software — antivirus incluso — può vederlo.

## Keylogger Software vs Hardware

|                              | Software                                         | Hardware                                                                                         |
| ---------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| Come si installa             | Eseguibile, spesso via trojan o download infetto | Adattatore fisico (USB, PS/2), periferica HID modificata, o firmware/componente interno alterato |
| Rilevabile con antivirus/EDR | Possibile, se la firma è nota                    | Generalmente no — non è codice sul sistema operativo                                             |
| Richiede accesso fisico      | Non necessariamente                              | Generalmente sì                                                                                  |
| Dove salva i dati            | File locale o invio remoto via rete              | Memoria interna del dispositivo, o invio via rete se dotato di Wi-Fi                             |

La differenza pratica più importante è che un keylogger hardware non è quasi mai rilevabile da un software di sicurezza, per quanto aggiornato: non è codice in esecuzione sul sistema, è elettronica indipendente. L'unico modo per scoprirlo è un controllo fisico dei cavi, delle porte e — nei casi più sofisticati — dei componenti interni, cosa che nella pratica quasi nessuno fa mai su un computer che usa ogni giorno.

## Dove si Nasconde Solitamente un Keylogger Software

Raramente un keylogger arriva da solo: è quasi sempre un componente integrato in un malware più ampio, o si maschera da **estensione del browser** apparentemente innocua — un vettore spesso sottovalutato perché le estensioni sembrano più "sicure" di un eseguibile scaricato, ma hanno comunque accesso a tutto ciò che digiti dentro il browser. I banking trojan lo usano per catturare le credenziali digitate durante l'accesso all'home banking; molti Remote Access Trojan (RAT) lo includono di serie insieme al controllo di webcam e microfono; e le app di **stalkerware** — pubblicizzate come strumenti di "controllo genitori" ma spesso usate per sorvegliare partner o familiari senza consenso — integrano il keylogging come una delle funzioni principali, installate con accesso fisico diretto al dispositivo della vittima invece che tramite un exploit.

## L'Uso Legittimo (e la Zona Grigia Legale)

Non ogni keylogger è malware nel senso stretto del termine. Software di monitoraggio dipendenti dichiarato e regolato contrattualmente, controlli parentali su dispositivi di minori di cui i genitori sono legalmente responsabili, e strumenti di audit IT aziendale su dispositivi di proprietà dell'azienda possono includere funzioni di keylogging in modo legale. La legittimità dipende da giurisdizione, consenso, contesto d'uso e modalità di raccolta e trattamento dei dati — non esiste una regola unica valida ovunque. Quello che resta costante è che installarlo di nascosto su un dispositivo personale altrui senza consenso può comportare conseguenze penali rilevanti, indipendentemente da chi lo installa o dal movente dichiarato.

Un caso reale mostra come le autorità trattano queste app quando superano il limite: nel 2021 la Federal Trade Commission statunitense ha bandito Support King, l'azienda dietro l'app di monitoraggio SpyFone, dal settore della sorveglianza — la prima messa al bando totale di un'azienda di stalkerware, dopo che l'app risultò raccogliere e condividere dati su spostamenti, messaggi e attività telefonica delle vittime a loro insaputa. Per chi sospetta di essere sorvegliato in questo modo, la [Coalition Against Stalkerware](https://stopstalkerware.org/) — fondata da EFF insieme a diverse aziende antivirus — offre risorse gratuite per il rilevamento e la rimozione.

## Come Riconoscere un Keylogger

Per un keylogger software, i segnali si sovrappongono a quelli di molti altri malware: rallentamenti nella digitazione percepibile (un keylogger che registra e invia dati in tempo reale può introdurre un minimo di latenza), processi sconosciuti in esecuzione, e un antivirus che segnala un rilevamento. Per un keylogger hardware, il controllo è fisico: ispezionare visivamente il cavo della tastiera nel punto in cui si collega al computer, cercando un piccolo adattatore che normalmente non dovrebbe essere lì — un controllo che richiede letteralmente pochi secondi ma che quasi nessuno effettua mai di routine.

Un controllo di base, su Windows, si fa aprendo **Gestione Attività** (Task Manager) e guardando i processi in esecuzione alla ricerca di nomi sconosciuti; **Autoruns** di Sysinternals fa un passo in più, mostrando anche cosa si avvia automaticamente col sistema — molti keylogger software puntano proprio a restare in memoria dall'avvio. Come per ogni controllo di questo tipo, un processo "strano" è un indizio da approfondire, non una diagnosi.

## Come Proteggersi (e Difendersi) da un Keylogger

Un antivirus aggiornato intercetta la maggior parte dei keylogger software noti, ma non quelli su misura o quelli hardware. L'**autenticazione a due fattori** riduce l'impatto del furto della sola password, ma non protegge da malware più completo capace di rubare session cookie o token — le passkey, resistenti al phishing per design, offrono una protezione più solida. Una **tastiera virtuale** (cliccata con il mouse invece che digitata) evita la cattura da parte di un keylogger che intercetta solo eventi di tastiera fisica, ma non protegge da malware che acquisisce screenshot, clipboard o dati direttamente dall'applicazione — una tecnica comunque usata non a caso da molti siti di home banking nei loro momenti più sensibili.

Vale anche la pena distinguere un keylogger da un **credential stealer**: non tutto il furto di credenziali passa dalla tastiera. Un malware può puntare direttamente a password salvate nel browser, cookie di sessione o token di autenticazione senza mai registrare un singolo tasto — "non ho trovato un keylogger" non equivale quindi a "le mie credenziali sono al sicuro".

## Pensi di Avere un Keylogger Adesso? Come Verificarlo

Se hai il sospetto concreto che qualcuno stia leggendo quello che scrivi — un partner, un datore di lavoro non trasparente, chiunque altro — ecco un controllo in tre passi, dal più semplice al più approfondito.

1. **Ispeziona fisicamente i cavi della tastiera**, in particolare dove si collegano al computer: un adattatore che non riconosci è un segnale da indagare seriamente, anche se da solo non è una prova assoluta — potrebbe in rari casi essere un accessorio legittimo dimenticato. Su laptop controlla anche eventuali porte USB inutilizzate.
2. **Su Windows**, apri **Gestione Dispositivi** (Device Manager) e guarda sotto "Tastiere" e "Dispositivi HID": un dispositivo sconosciuto elencato lì, oltre alla tua tastiera normale, è un segnale concreto da indagare.
3. **Esegui Autoruns di Sysinternals** e controlla ogni voce in avvio automatico che non riconosci — molti keylogger software puntano a restare attivi dal boot.
4. **Se il sospetto riguarda un contesto di controllo o abuso da parte di un'altra persona**, valuta la tua sicurezza personale prima di rimuovere qualcosa: la stessa cautela vista per lo stalkerware si applica qui.

## FAQ

**Cos'è un keylogger?** È un software o un dispositivo che registra ogni tasto digitato su una tastiera, all'insaputa di chi la sta usando.

**Un antivirus rileva sempre un keylogger?** No: rileva quelli software con firme già conosciute, ma un keylogger su misura può sfuggirgli. Un keylogger hardware è generalmente invisibile a qualsiasi software, perché non è codice in esecuzione sul sistema.

**I keylogger sono sempre illegali?** Dipende da giurisdizione, consenso e contesto: monitoraggio dipendenti dichiarato, controlli parentali su minori e audit aziendali su dispositivi di proprietà dell'azienda possono essere legali. Installarlo di nascosto su un dispositivo altrui senza consenso può avere conseguenze penali rilevanti.

**Come mi difendo da un keylogger anche se non lo scopro?** L'autenticazione a due fattori riduce l'impatto del furto della sola password (anche se non protegge da malware che ruba sessioni o token), e le tastiere virtuali usate da molti siti di home banking evitano la cattura dei keylogger che intercettano solo la tastiera fisica.

**Un keylogger può rubare le password anche se le copio e incollo invece di digitarle?** Un keylogger "puro" che intercetta solo la tastiera no — ma molte varianti moderne includono anche cattura degli appunti (clipboard) o screenshot periodici, che vanificano questo accorgimento.
