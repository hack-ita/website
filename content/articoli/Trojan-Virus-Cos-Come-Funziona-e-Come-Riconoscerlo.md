---
title: 'Trojan Virus: Cos''è, Come Funziona e Come Riconoscerlo'
slug: trojan
description: 'Trojan: come si diffonde, quali danni può causare e come riconoscerlo. Confronto con virus e worm, principali tipologie ed esempi come Zeus ed Emotet.'
image: /trojan-virus-malware-come-funziona.webp
draft: true
date: 2026-10-10T13:00:27.970Z
lastmod: 2026-10-10T13:00:31.647Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - trojan
  - trojan horse
  - trojan virus
  - trojan malware
  - banking trojan
---

# Trojan: Come Si Nasconde, Tipologie e Differenze dai Virus

Un trojan è un malware che si presenta come un programma legittimo o utile per convincere la vittima a installarlo di sua spontanea volontà. Il termine tecnicamente corretto è "trojan", ma nel linguaggio comune viene spesso chiamato anche **"trojan virus"** o "virus trojan" — un'imprecisione diffusa, perché come vedremo tra poco un trojan non è un virus in senso tecnico, ma è così che la maggior parte delle persone lo cerca e lo riconosce. A differenza di un virus o di un worm, non è definito dalla capacità di autoreplicarsi: la sua caratteristica distintiva è il mascheramento, non l'impossibilità tecnica di propagarsi in altri modi — un trojan può benissimo scaricare altro malware o aprire la strada a componenti che si diffondono da soli, restando comunque un trojan nella sua fase iniziale. Il nome viene esattamente da lì: come il cavallo di legno usato per introdursi a Troia, il pericolo non è nell'involucro ma in quello che nasconde dentro.

> **In breve:** un trojan (o trojan horse) è un malware che si maschera da software legittimo per farsi installare dalla vittima. A differenza di virus e worm non è caratterizzato dall'autoreplicazione: il meccanismo che lo definisce è l'inganno, non un limite assoluto su cosa può fare dopo.

## Trojan vs Virus vs Worm: la Differenza

I tre termini vengono confusi di continuo, ma descrivono meccanismi opposti:

|                           | Trojan                                  | Virus                         | Worm                         |
| ------------------------- | --------------------------------------- | ----------------------------- | ---------------------------- |
| Autoreplicazione          | Non è la sua caratteristica distintiva  | Sì, tramite un file ospite    | Sì, in autonomia             |
| Serve un file ospite      | No                                      | Sì                            | No                           |
| Come si diffonde          | Inganna l'utente perché lo installi     | Esecuzione di un file infetto | Sfrutta reti e vulnerabilità |
| Caratteristica principale | Mascheramento per ottenere l'esecuzione | Replicazione tramite ospite   | Propagazione autonoma        |

[Virus](https://hackita.it/articoli/virus-informatico/) e [worm](https://hackita.it/articoli/worm/) sono definiti soprattutto da *come si moltiplicano*; un trojan è definito da *come inganna* per farsi eseguire, non dalla propagazione. Le categorie, però, si sovrappongono spesso più di quanto i nomi suggeriscano: un trojan può scaricare un ransomware, aprire una backdoor persistente o installare le componenti che trasformano il dispositivo in parte di una [botnet](https://hackita.it/articoli/botnet/) — Emotet, che vedremo tra poco, è nato come trojan bancario ed è finito per distribuire ransomware per conto di altri gruppi criminali.

## Come Funziona un Trojan

Il meccanismo si regge su un solo elemento: convincere qualcuno a fare volontariamente ciò che un virus o un worm otterrebbero tecnicamente. I vettori più comuni sono allegati email che sembrano fatture o documenti urgenti, software piratato o crack per programmi a pagamento, download da siti non ufficiali spacciati per aggiornamenti o codec necessari per guardare un video, e finti antivirus che segnalano un'infezione inesistente per spingere all'installazione di quello che dovrebbe "risolverla". Una volta eseguito, il trojan installa silenziosamente il proprio payload — spesso senza alcun sintomo visibile, perché il suo scopo è proprio restare inosservato il più a lungo possibile, non farsi notare come farebbe un virus con un payload distruttivo immediato.

## Il "Trojan di Stato": Quando lo Usa la Magistratura

In Italia il termine "trojan" è associato anche a un uso specifico e legale: il **captatore informatico**, comunemente chiamato "trojan di Stato", è un software con le stesse capacità tecniche di un RAT (attivazione di webcam e microfono, lettura di messaggi anche cifrati, accesso ai file) che le procure possono installare su un dispositivo nell'ambito di un'indagine, previa autorizzazione del giudice. La Cassazione a Sezioni Unite, con la sentenza Scurato del 2016, ne aveva inizialmente limitato l'uso per le intercettazioni "tra presenti" (ambientali) ai soli reati di criminalità organizzata; riforme legislative successive (legge 103/2017 e i decreti che ne sono seguiti) hanno poi esteso la disciplina anche ad altri reati gravi, inclusi quelli contro la pubblica amministrazione. È un caso interessante proprio perché mostra che la tecnologia di un trojan è neutra: cambia tutto in base a chi la usa, con quale autorizzazione e per quale scopo.

## I Tipi di Trojan più Comuni

| Tipo                       | Cosa fa                                                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Backdoor                   | Apre un accesso remoto permanente al sistema per l'attaccante                                                                        |
| RAT (Remote Access Trojan) | Trojan progettato per dare all'attaccante il controllo remoto del dispositivo — comandi, file, spesso webcam, microfono e keylogging |
| Banking trojan             | Ruba credenziali bancarie intercettando le sessioni di home banking                                                                  |
| Downloader / Dropper       | Non ha un payload proprio: la sua unica funzione è scaricare e installare altro malware                                              |
| Fake antivirus (scareware) | Simula un'infezione per convincere la vittima a pagare per una "pulizia" inutile o dannosa                                           |
| SMS trojan                 | Colpisce dispositivi mobili, invia SMS a numeri a pagamento o intercetta messaggi                                                    |

## Trojan Famosi della Storia

| Trojan                  | Anno | Categoria                         | Impatto                                                  |
| ----------------------- | ---- | --------------------------------- | -------------------------------------------------------- |
| AIDS Trojan (PC Cyborg) | 1989 | Ransomware ante litteram          | Primo caso documentato di estorsione tramite cifratura   |
| Zeus (Zbot)             | 2007 | Banking trojan                    | Oltre 3,6 milioni di computer infettati solo negli USA   |
| Emotet                  | 2014 | Downloader / Malware-as-a-Service | Definito da Europol "il malware più pericoloso al mondo" |

**AIDS Trojan (1989).** Distribuito via floppy disk spedito per posta dal suo autore, Joseph Popp, contava i riavvii del computer e poi cifrava i nomi delle directory, chiedendo 189 dollari inviati a una casella postale a Panama per "rinnovare la licenza". È considerato il primo caso documentato di quello che oggi chiamiamo ransomware — con oltre trent'anni di anticipo sulle sue forme moderne.

**Zeus (2007).** Trojan bancario che rubava credenziali intercettando le sessioni di home banking e manipolando le pagine visualizzate dalla vittima. Nel suo periodo di massima diffusione infettò oltre 3,6 milioni di computer solo negli Stati Uniti. Il suo codice sorgente, trapelato nel 2011, diede origine a numerose varianti (GameOver Zeus, Citadel) ancora osservate in forma modificata anni dopo.

**Emotet (2014-2021).** Nato come trojan bancario, si evolse in quella che i ricercatori hanno soprannominato la "FedEx del cybercrime": non attaccava direttamente, ma vendeva l'accesso ai dispositivi infetti ad altri gruppi criminali, che lo usavano per distribuire ulteriore malware e ransomware (tra cui Ryuk e Conti). Nel gennaio 2021 la sua infrastruttura — centinaia di server in tutto il mondo — è stata presa sotto controllo e smantellata da un'operazione internazionale coordinata da [Europol ed Eurojust](https://www.europol.europa.eu/media-press/newsroom/news/world%E2%80%99s-most-dangerous-malware-emotet-disrupted-through-global-action), con la collaborazione di otto paesi. Emotet è poi riemerso in forma modificata mesi dopo, a dimostrazione di quanto sia difficile eliminare del tutto un'infrastruttura criminale di questo tipo.

## Come Riconoscere un Trojan

Un buon trojan è progettato per non dare segnali evidenti, ma alcuni indizi ricorrono: rallentamenti improvvisi senza causa apparente, programmi che si avviano da soli, un antivirus che segnala un rilevamento dopo l'installazione di software scaricato da fonti non ufficiali, traffico di rete verso destinazioni sconosciute, o account online che mostrano accessi non riconosciuti — segno che credenziali potrebbero essere già state sottratte. Su **Android**, dove i trojan bancari sono particolarmente diffusi, un segnale specifico da non ignorare è la richiesta di attivare i "Servizi di Accessibilità" da parte di un'app che non ne avrebbe alcun bisogno dichiarato: è il permesso che questi trojan sfruttano più spesso per leggere lo schermo e intercettare le credenziali digitate in altre app. Nessuno di questi segnali è definitivo da solo, ma un rilevamento dell'antivirus dopo aver installato qualcosa scaricato "da un sito non proprio ufficiale" andrebbe sempre preso sul serio, non ignorato.

## Come Rimuovere un Trojan

1. **Isola il dispositivo dalla rete** per impedire a un'eventuale backdoor di comunicare con l'esterno o di scaricare altro malware.
2. **Avvia una scansione completa** con un antimalware aggiornato — rileva la maggior parte delle minacce già note, ma non garantisce da sola la rimozione completa se il trojan ha già installato altri componenti.
3. **Verifica i programmi installati di recente** e rimuovi manualmente quelli non riconosciuti, specialmente se installati insieme a software piratato.
4. **Cambia le credenziali potenzialmente esposte** — soprattutto home banking ed email — da un dispositivo diverso e pulito.
5. **Se il trojan ha aperto una backdoor**, valuta il ripristino completo del sistema da un'immagine pulita: non c'è garanzia che una scansione da sola rimuova tutto ciò che è stato installato in seguito.

## Come Proteggersi dai Trojan

La difesa più efficace resta la più semplice da enunciare e la più difficile da rispettare sempre: non installare software da fonti non ufficiali — crack e keygen per programmi a pagamento restano tra i vettori più sfruttati per questo tipo di malware. A questo si aggiungono le stesse buone pratiche valide per ogni malware: diffidare di allegati email inattesi anche se sembrano provenire da mittenti noti, mantenere un antivirus aggiornato in grado di riconoscere le firme dei trojan più diffusi, e verificare i permessi richiesti da un'app prima di installarla, specialmente su dispositivi mobili.

## FAQ

**Cos'è un trojan?** È un malware che si maschera da software legittimo per convincere la vittima a installarlo volontariamente. A differenza di virus e worm, non è caratterizzato dall'autoreplicazione.

**Qual è la differenza tra trojan e virus?** Il virus si replica infettando altri file; il trojan non è definito dalla replicazione ma dal mascheramento usato per farsi installare dalla vittima.

**Un trojan può diffondersi da solo?** Non è la propagazione autonoma tipica di un worm a definirlo — un trojan da solo resta dov'è stato installato. Può però scaricare altro malware o componenti che si diffondono per conto suo, motivo per cui una singola infezione va sempre trattata come un potenziale punto di partenza, non un evento isolato.

**Cos'è un RAT?** È un Remote Access Trojan, un trojan che dà all'attaccante il controllo remoto completo del dispositivo infetto — spesso incluse webcam, microfono e tastiera.

**Un antivirus rileva sempre un trojan?** No sempre: i trojan più recenti o mirati possono eludere il rilevamento basato su firme note, motivo per cui comportamenti anomali del sistema restano un segnale importante quanto l'alert dell'antivirus stesso.

**Emotet esiste ancora?** L'infrastruttura originale è stata smantellata nel 2021 da un'operazione internazionale, ma è riapparsa in forma modificata mesi dopo — un esempio di quanto sia difficile eliminare del tutto un'infrastruttura malware distribuita su centinaia di server.
