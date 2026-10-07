---
title: 'Rootkit: Come Funziona, Tipi e Tecniche di Rilevamento'
slug: rootkit
description: 'Rootkit: scopri cos’è, come funziona e quali sono i tipi più comuni. Tecniche di rilevamento, esempi reali e metodi per rimuoverlo su Linux e Windows.'
image: /rootkit-cosa-e-come-funziona-rilevamento.webp
draft: true
date: 2026-10-15T12:24:38.164Z
lastmod: 2026-10-15T12:24:41.042Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - rootkit
  - rootkit detection
  - kernel rootkit
  - bootkit
  - firmware rootkit
---

# Rootkit: Cos'è, Come Funziona e Perché è Così Difficile da Trovare

Un rootkit è un software, o un insieme di componenti, progettato per nascondere la presenza di un attaccante, di altro malware o di determinate attività su un sistema — non necessariamente per mantenere accesso privilegiato di per sé, ma per far sì che quell'accesso, una volta ottenuto, resti invisibile il più a lungo possibile. Non è un malware con un obiettivo proprio come un [ransomware](/articoli/ransomware/) o uno [spyware](/articoli/spyware/): è l'infrastruttura di occultamento che permette ad altro malware — o a un intruso in carne e ossa — di restare invisibile.

Vale la pena chiarire subito una confusione comune: **rootkit non è sinonimo di persistenza**. La persistenza è la capacità di mantenere l'accesso a un sistema dopo un riavvio o altre modifiche; il rootkit riguarda l'occultamento di quell'accesso, non il fatto che sopravviva nel tempo. Un rootkit viene spesso usato per supportare la persistenza — nascondendo il meccanismo che la garantisce — ma le due funzioni restano concettualmente distinte, e un malware può avere l'una senza l'altra.

> **In breve:** un rootkit è software che nasconde processi, file o connessioni di rete a livello di sistema operativo, permettendo a un attaccante di mantenere accesso privilegiato senza essere scoperto dagli strumenti di sicurezza standard.

## Come Funziona un Rootkit

Il meccanismo distintivo è l'intercettazione: un rootkit si inserisce tra il sistema operativo e gli strumenti che dovrebbero monitorarlo, filtrando cosa questi strumenti "vedono". Se un antivirus chiede al sistema operativo l'elenco dei processi in esecuzione, un rootkit può intercettare quella richiesta e rimuovere se stesso dalla lista prima che venga mostrata — l'antivirus non sta guardando dati falsi, sta guardando dati veri da cui è stato tolto esattamente quello che cercava. Lo stesso vale per file, chiavi di registro e connessioni di rete. In generale, più il rootkit opera in profondità nel sistema (a livello di kernel invece che di semplice applicazione), più diventa difficile da rilevare con gli strumenti convenzionali — non è però una regola assoluta: molto dipende da quanto è ben scritta l'implementazione specifica, non solo dal livello a cui opera.

## Tipi di Rootkit, per Livello di Profondità

| Tipo        | Dove opera                                                            | Difficoltà di rilevamento |
| ----------- | --------------------------------------------------------------------- | ------------------------- |
| User-mode   | A livello di applicazioni, intercetta chiamate di programmi comuni    | Bassa-media               |
| Kernel-mode | Nel nucleo del sistema operativo, con privilegi massimi               | Alta                      |
| Bootkit     | Nel processo di avvio del sistema, prima ancora del sistema operativo | Molto alta                |
| Firmware    | In BIOS/UEFI, sopravvive alla reinstallazione del sistema operativo   | Estrema                   |

Da distinguere dal firmware rootkit c'è l'**hardware implant**: un componente fisico aggiunto o modificato sul dispositivo stesso, non semplicemente codice nel suo firmware. Condivide con il firmware rootkit la sopravvivenza a qualunque intervento software, ma richiede accesso fisico al dispositivo per essere installato — una barriera che lo rende molto più raro nella pratica.

## Come Viene Installato un Rootkit

Un rootkit quasi mai è il primo passo di un attacco: prima serve un livello di accesso sufficiente a installarlo, che tipicamente arriva da altrove. I vettori più comuni sono un [trojan](/articoli/trojan/) o altro malware già presente sul sistema che lo scarica come secondo stadio, lo sfruttamento di una vulnerabilità non corretta, credenziali amministrative compromesse, software piratato che lo nasconde al suo interno o, nei casi più rari, accesso fisico diretto al dispositivo. Una volta ottenuto l'accesso necessario, il livello a cui il rootkit si installa — user-mode, kernel-mode, boot o firmware — determina quanto sarà difficile trovarlo ed eliminarlo in seguito.

## Il Caso Sony BMG: un Rootkit Installato da un'Azienda Legittima

Il caso più istruttivo nella storia dei rootkit non riguarda criminali informatici, ma una delle più grandi etichette discografiche al mondo. Nel 2005 Sony BMG distribuì su circa 25 milioni di CD musicali un sistema di protezione anticopia chiamato XCP, sviluppato da First 4 Internet: quando un utente inseriva il CD su un computer Windows, XCP si installava silenziosamente usando esattamente le stesse tecniche di occultamento di un rootkit malevolo, per impedire che l'utente rimuovesse la protezione.

Il ricercatore Mark Russinovich lo scoprì per caso il 31 ottobre 2005 mentre testava un proprio tool di rilevamento rootkit su un computer dove aveva semplicemente ascoltato un CD comprato legalmente, e pubblicò [l'analisi completa](https://en.wikipedia.org/wiki/Sony_BMG_copy_protection_rootkit_scandal) sul suo blog Sysinternals. La scoperta si rivelò più grave del previsto: XCP non solo si nascondeva, ma "telefonava a casa" verso i server di Sony ogni volta che il CD veniva riprodotto, e la sua stessa presenza apriva una porta che altro malware poteva sfruttare per nascondersi a sua volta usando lo stesso meccanismo. Il tool di rimozione che Sony rilasciò in un primo momento peggiorò la situazione invece di risolverla. Secondo le stime successive, il software finì per essere installato su oltre 500.000 reti in più di 100 paesi, incluse reti militari e governative statunitensi. Ne seguirono cause legali e il ritiro forzato dei CD interessati.

Il caso resta rilevante ancora oggi per una ragione precisa: dimostra che un rootkit non richiede intenti criminali per essere pericoloso. Una volta che una tecnica di occultamento esiste su un sistema, chiunque altro — non solo chi l'ha installata — può potenzialmente sfruttarla.

## Il Caso ZeroAccess: quando il Rootkit è Criminale fin dall'Inizio

Se Sony BMG mostra come nasce un rootkit per errore, **ZeroAccess** mostra come viene costruito apposta. Scoperto nel 2011, questo trojan si diffondeva mascherato da crack o keygen per software piratato e, una volta eseguito, infettava il Master Boot Record del disco usando tecniche rootkit per restare invisibile agli antivirus. Il sistema compromesso diventava un nodo di un [botnet](/articoli/botnet/) peer-to-peer stimato in almeno 9 milioni di sistemi nel suo picco, usato principalmente per due attività redditizie: mining di Bitcoin e click fraud pubblicitario, quest'ultimo capace di generare fino a 100.000 dollari al giorno per chi lo controllava. A differenza di Sony BMG, qui il rootkit non era un effetto collaterale di una protezione anticopia: era l'infrastruttura pensata fin dal primo giorno per rendere il resto dell'operazione criminale sostenibile su scala milionaria.

## Come Rilevare un Rootkit

Proprio perché un rootkit inganna gli strumenti che girano *dentro* il sistema compromesso, il rilevamento più affidabile spesso richiede di guardare *da fuori*: avviare il sistema da un supporto esterno pulito (una chiavetta live) ed eseguire la scansione da lì, dove il rootkit non è mai stato caricato e non può nascondersi. Altri segnali indiretti includono comportamenti che un rootkit non riesce sempre a mascherare perfettamente: differenze tra la lista dei file riportata dal sistema operativo e quella osservata a basso livello (da cui il nome di molti "rootkit revealer"), un utilizzo di risorse che non corrisponde a nessun processo visibile, e — nei casi più gravi — un sistema che continua a comportarsi in modo anomalo anche dopo una scansione antivirus completa e apparentemente pulita.

Un primo controllo, senza pretesa di essere definitivo, si può fare con strumenti dedicati: su Linux, **rkhunter** (`sudo rkhunter --check`) e **chkrootkit** eseguono una serie di controlli alla ricerca di indicatori e configurazioni associate a rootkit e compromissioni note — un risultato "clean" non dimostra però che il sistema sia necessariamente libero da rootkit, specialmente quelli più recenti o su misura; su Windows, **Autoruns** di Sysinternals mostra tutto ciò che si avvia col sistema, comprese le voci che i pannelli standard di Windows non elencano. Nessuno di questi strumenti sostituisce un'analisi seria in caso di sospetto fondato, ma sono un punto di partenza migliore di "sembra tutto normale".

## Come Rimuoversi da un Rootkit

1. **Non fidarti di una scansione fatta dal sistema infetto**: se sospetti un rootkit a livello kernel, avvia da un supporto esterno pulito prima di scansionare.
2. **Usa strumenti specifici anti-rootkit**, non un antivirus generico: sono progettati per confrontare cosa il sistema operativo riporta con cosa esiste realmente a basso livello.
3. **Per un bootkit o un rootkit firmware**, la scansione da sistema esterno spesso non basta: valuta il ripristino completo del firmware/BIOS quando supportato, o la sostituzione del disco.
4. **Per un rootkit che opera esclusivamente a livello di sistema operativo**, la reinstallazione completa da un supporto affidabile rimuove tipicamente la compromissione. **Per bootkit e rootkit firmware questo non basta**: serve verificare anche i componenti sotto il sistema operativo, e quando la loro integrità non può essere garantita, l'unica strada resta il reflashing con firmware verificato o, nei casi più gravi, la sostituzione dell'hardware.

## Pensi di Avere un Rootkit Adesso? Come Verificarlo

Se il sistema si comporta in modo anomalo e i controlli normali continuano a risultare "puliti" nonostante tutto, è esattamente lo scenario in cui ha senso sospettare un rootkit invece di un malware più semplice.

1. **Linux**: esegui `sudo rkhunter --check` e leggi ogni riga segnalata come "Warning" — non tutte indicano un'infezione reale, ma vanno verificate una per una, non ignorate in blocco.
2. **Windows**: apri **Autoruns** di Sysinternals ed esamina ogni voce che si avvia col sistema, prestando attenzione a percorsi insoliti (una cartella temporanea invece di Program Files) o file senza firma digitale.
3. **Se puoi**, ripeti lo stesso controllo avviando da una chiavetta live pulita e confronta i risultati con quelli ottenuti dal sistema acceso normalmente: una discrepanza tra le due è il segnale più concreto ottenibile senza strumenti professionali.
4. **Se i controlli restano puliti ma il sistema continua a comportarsi in modo anomalo**, è il momento di considerare un'analisi forense professionale invece di insistere da soli — è esattamente il tipo di caso in cui un rootkit ben scritto elude gli strumenti generici.

## FAQ

**Cos'è un rootkit?** È un insieme di strumenti che nasconde processi, file o attività di rete a livello di sistema, permettendo a un attaccante di mantenere accesso privilegiato senza essere rilevato dagli strumenti di sicurezza standard.

**Un rootkit è un virus?** No: un virus è definito dalla replicazione tramite un file ospite, un rootkit dalla capacità di occultamento. Spesso lavorano insieme — un virus o un trojan installa il rootkit per nascondersi meglio.

**Perché i rootkit sono così difficili da rilevare?** Perché operano allo stesso livello, o più in profondità, degli strumenti che dovrebbero trovarli: possono intercettare e filtrare le informazioni che antivirus e sistema operativo si scambiano.

**Un'azienda legittima può installare un rootkit?** È successo davvero: nel 2005 Sony BMG distribuì un sistema anticopia sui propri CD musicali che usava tecniche di rootkit, finendo su oltre 500.000 reti nel mondo prima di essere scoperto e ritirato.

**Come mi accorgo di avere un rootkit?** I segnali sono indiretti — differenze tra ciò che il sistema riporta e ciò che sembra esistere realmente, risorse consumate da processi invisibili — motivo per cui la scansione più affidabile si fa spesso da un supporto esterno pulito, non dal sistema potenzialmente compromesso.

**Un rootkit sopravvive alla reinstallazione di Windows?** Dipende dal tipo: un rootkit che opera solo a livello di sistema operativo no, la reinstallazione lo rimuove. Un bootkit o un rootkit firmware sì, perché vivono in un livello che la reinstallazione del sistema operativo non tocca.

**Un rootkit può infettare il BIOS/UEFI?** Sì, è la categoria dei firmware rootkit — la più rara ma anche la più persistente, perché sopravvive non solo alla reinstallazione del sistema operativo ma anche alla sostituzione del disco.
