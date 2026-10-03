---
title: 'Adware: Pubblicità Indesiderata, Rischi E Come Rimuoverlo'
slug: adware
description: 'Adware: scopri cos''è e come riconoscere pubblicità indesiderate, bundling, raccolta dati, rischi per la sicurezza e come rimuoverlo da PC e smartphone.'
image: /adware-malware-pubblicita-indesiderata.webp
draft: true
date: 2026-10-19T12:46:49.165Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - adware
  - adware malware
  - adware virus
  - rimozione adware
---

# Adware: Cos'è, Come Funziona e Quando Diventa Pericoloso

Un adware è un software che mostra pubblicità non richiesta sul dispositivo su cui è installato, spesso raccogliendo dati sulla navigazione per scegliere quali annunci proporre. Nel linguaggio comune viene spesso chiamato anche **"adware virus"**, anche se tecnicamente non è un virus: non si replica né ha bisogno di un file ospite, è semplicemente il nome con cui la maggior parte delle persone lo cerca e lo riconosce. È il malware più "leggero" di questo cluster — la maggior parte delle volte è più fastidioso che pericoloso — ma la linea che lo separa dallo spyware è sottile, e in alcuni casi documentati un adware ha creato vulnerabilità di sicurezza reali, non solo pubblicità moleste.

> **In breve:** un adware mostra pubblicità non richiesta, spesso in cambio dell'uso "gratuito" di un software. Non tutti gli adware sono malevoli — alcuni sono un modello di business dichiarato — ma quando si installa di nascosto, raccoglie dati senza consenso o intercetta il traffico, smette di essere pubblicità e diventa malware a tutti gli effetti.

## Adware Legittimo vs Adware Malevolo

Non ogni software che mostra annunci è una minaccia. Molte app gratuite dichiarano apertamente di finanziarsi con la pubblicità, spesso offrendo una versione a pagamento senza annunci come alternativa — è un modello di business trasparente, non malware. La linea si supera quando l'adware viene installato senza consenso esplicito (spesso in bundle con altro software, nascosto tra le opzioni di un installer), continua a mostrare annunci anche fuori dall'app che lo ha portato sul dispositivo, raccoglie dati di navigazione senza dichiararlo, o — nei casi più gravi — manipola il traffico di rete per inserire pubblicità anche su siti che non gliel'hanno richiesto.

## Come Funziona un Adware

Il meccanismo più comune è l'iniezione di annunci nel browser: l'adware si installa come estensione, modifica le impostazioni del browser o si inserisce come proxy locale tra il dispositivo e internet, in modo da poter aggiungere o sostituire pubblicità nelle pagine visitate — comprese, nei casi peggiori, pagine che userebbero connessioni cifrate. Un'altra modalità comune sono i pop-up generati direttamente dal sistema operativo, indipendenti dal browser aperto. Ci sono infine adware che raccolgono dati di navigazione (siti visitati, ricerche, a volte posizione) per costruire un profilo pubblicitario, avvicinandosi molto a uno [spyware](https://hackita.it/articoli/spyware/) — a quel punto la distinzione è più terminologica che pratica.

## Come Arriva un Adware sul Dispositivo

Il vettore più comune, di gran lunga, è il **bundling**: un software gratuito legittimo (utility, convertitori di file, download manager) che durante l'installazione include, spesso preselezionata, l'opzione per installare anche una "barra degli strumenti" o un "assistente di navigazione" che è in realtà adware. Altri vettori includono estensioni del browser scaricate da store non ufficiali, siti di download "alternativi" per software popolare, e — nei casi più aggressivi — pre-installazione diretta da parte del produttore del dispositivo, come nel caso che segue.

## Il Caso Superfish: Quando l'Adware Diventa una Falla di Sicurezza

Tra il settembre 2014 e il febbraio 2015, Lenovo preinstallò su 28 modelli di laptop un software chiamato **Superfish VisualDiscovery**, pensato per inserire pubblicità comparativa nelle pagine di shopping online visitate dall'utente. Il problema è che gran parte del traffico web moderno è cifrato (HTTPS), e per poter inserire pubblicità anche lì, Superfish installava un proprio certificato root sul dispositivo e intercettava le connessioni cifrate con una tecnica da manuale del man-in-the-middle: terminava la connessione sicura dell'utente e ne apriva una propria, usando il certificato falso per decifrare e poi re-inserire il traffico.

Il problema più grave emerse quando i ricercatori di sicurezza scoprirono che **ogni laptop Lenovo con Superfish usava lo stesso identico certificato root**, protetto da una password facilmente individuabile ("komodia", il nome del fornitore della tecnologia MITM). Chiunque avesse scoperto quella password poteva potenzialmente intercettare il traffico HTTPS di qualsiasi utente Superfish — su una rete Wi-Fi pubblica, per esempio — vanificando completamente la protezione della connessione cifrata. La [FTC statunitense e i procuratori generali di 32 stati](https://www.securityweek.com/lenovo-settles-ftc-charges-over-superfish-adware/) citarono Lenovo in giudizio; la causa si chiuse con un accordo da 3,5 milioni di dollari con le autorità, a cui si aggiunsero oltre 8 milioni di dollari da una class action separata. Lenovo non ammise responsabilità legale, ma accettò di ottenere il consenso esplicito degli utenti prima di preinstallare software pubblicitario e di mantenere un programma di audit sulla sicurezza per vent'anni.

## Come Riconoscere un Adware

I segnali sono spesso più evidenti che per altri malware di questo cluster, proprio perché l'adware non è progettato per restare nascosto: pop-up pubblicitari che compaiono anche a browser chiuso, una nuova barra degli strumenti o estensione che non ricordi di aver installato, la homepage o il motore di ricerca predefinito del browser cambiati senza il tuo intervento, e un rallentamento generale della navigazione dovuto al traffico pubblicitario aggiuntivo. Su Windows, un controllo rapido in **Impostazioni → App** o nelle estensioni del browser mostra spesso il programma responsabile elencato apertamente, proprio perché molti adware non si preoccupano di nascondersi come farebbe un trojan.

## Come Rimuovere un Adware

1. **Controlla le estensioni del browser** e rimuovi quelle che non riconosci o non ricordi di aver installato.
2. **Controlla i programmi installati** (Impostazioni → App su Windows, Applicazioni su macOS) alla ricerca di barre degli strumenti, "assistenti" o utility che non hai installato consapevolmente.
3. **Ripristina le impostazioni del browser** (motore di ricerca, homepage, nuova scheda) se sono state modificate.
4. **Esegui una scansione con un antimalware aggiornato**: la maggior parte degli adware, non essendo progettata per l'occultamento, viene rilevata senza difficoltà. **AdwCleaner** (di Malwarebytes) è uno strumento gratuito pensato specificamente per questo tipo di minaccia e resta lo standard di riferimento per una pulizia mirata.
5. **Se il problema persiste** dopo questi passaggi, considera che potrebbe trattarsi di qualcosa di più della semplice pubblicità — a quel punto vale la pena trattarlo con la stessa attenzione riservata a uno spyware.

Su **Android**, i pop-up pubblicitari arrivano quasi sempre da un'app installata fuori dal Play Store o da una app apparentemente innocua (torce, wallpaper, "ottimizzatori di batteria") che nasconde adware al suo interno: disinstallare l'app responsabile, individuabile spesso testando quali app disinstallare finché i pop-up non si fermano, risolve la maggior parte dei casi senza bisogno di reset del dispositivo.

## Come Proteggersi

La difesa più efficace si gioca quasi interamente al momento dell'installazione di software gratuito: leggere ogni schermata dell'installer invece di cliccare "avanti" per abitudine, deselezionare esplicitamente le opzioni per barre degli strumenti o software aggiuntivo, e scaricare programmi solo dal sito ufficiale dello sviluppatore o da store verificati, evitando portali di download "aggregatori" che spesso impacchettano adware insieme al software richiesto. Un **ad blocker** (che blocca la pubblicità sui siti che visiti) riduce il fastidio quotidiano ma non impedisce l'installazione di un adware; un **adware blocker** vero e proprio — come AdwCleaner, già citato sopra — è invece pensato per individuare e rimuovere il software stesso, non solo nascondere i suoi effetti.

## FAQ

**Cos'è un adware?** È un software che mostra pubblicità non richiesta, spesso raccogliendo dati di navigazione per scegliere gli annunci — non sempre malevolo, ma lo diventa quando si installa senza consenso o raccoglie dati senza dichiararlo.

**L'adware è considerato malware?** Dipende dal comportamento: un adware trasparente, dichiarato e senza raccolta dati nascosta è un modello di business, non malware. Diventa malware quando si installa senza consenso, resta anche dopo la disinstallazione del programma che lo ha portato, o raccoglie dati senza dichiararlo — a quel punto rientra a tutti gli effetti nella categoria [malware](https://hackita.it/articoli/malware/).

**L'adware è pericoloso quanto un virus?** Di norma no: la maggior parte degli adware è fastidiosa più che dannosa. Il caso Superfish dimostra però che un adware mal progettato può creare vulnerabilità di sicurezza reali, non solo pubblicità moleste.

**Qual è la differenza tra adware e spyware?** L'adware mostra pubblicità, lo spyware raccoglie informazioni per sorvegliare la vittima — ma quando un adware raccoglie dati di navigazione dettagliati senza consenso, la distinzione diventa più terminologica che pratica.

**Come mi è finito un adware sul computer?** Quasi sempre tramite bundling: un software gratuito legittimo che durante l'installazione include, spesso preselezionata, l'opzione per installare anche l'adware insieme al programma richiesto.

**Un antivirus rileva sempre un adware?** Nella maggior parte dei casi sì, proprio perché l'adware non è progettato per nascondersi come farebbe un trojan o un rootkit — il suo modello di business richiede che l'utente veda la pubblicità, non che resti invisibile.
