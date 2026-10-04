---
title: 'Stuxnet: La Storia del Virus Usato come Cyber-Weapon'
slug: stuxnet
description: 'Stuxnet, il virus usato come cyber-weapon: cos''è, come sabotò le centrifughe di Natanz, i 4 zero-day sfruttati, i danni e l''impatto sulla cybersecurity.'
image: /stuxnet-malware-cyberwarfare-scada.webp
draft: true
date: 2026-10-23T00:17:00.316Z
lastmod: 2026-10-23T00:18:59.613Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Stuxnet
  - Malware
  - Cybersecurity
  - Cyberwarfare
  - SCADA
---

# Stuxnet: Come Funzionava il Malware che Colpì l'Iran

**Stuxnet** è un [worm](https://hackita.it/articoli/worm/) informatico scoperto nel giugno 2010, comunemente considerato il primo cyberweapon pubblicamente noto capace di causare danni fisici reali a un'infrastruttura industriale tramite la manipolazione di un sistema di controllo. Il suo bersaglio era l'impianto di arricchimento dell'uranio di **Natanz**, in Iran: non rubava dati, non chiedeva un riscatto, serviva a **distruggere fisicamente** le centrifughe usate per l'arricchimento nucleare, facendole girare a velocità pericolose mentre mostrava agli operatori dati del tutto normali sui monitor di controllo.

È il caso di scuola di come il mondo digitale possa colpire il mondo fisico, e ha definito lo standard per tutti gli attacchi successivi contro sistemi di controllo industriale (ICS/SCADA).

## Il bersaglio: le centrifughe di Natanz

L'impianto di Natanz usava cascate di migliaia di centrifughe **IR-1** per arricchire uranio, fatte ruotare ad altissima velocità da convertitori di frequenza (prodotti da Vacon e Fararo Paya). Se una centrifuga viene fermata o accelerata bruscamente mentre gira a quella velocità, si danneggia o si distrugge.

Stuxnet non attaccava genericamente "i computer": era progettato per riconoscere una configurazione molto precisa. Il codice conteneva logica relativa a due famiglie di PLC Siemens, **S7-315** e **S7-417**, ma secondo l'analisi dell'Institute for Science and International Security (ISIS) solo il payload per l'**S7-315** risultava effettivamente attivo nei campioni analizzati, mentre quello per l'S7-417 era presente ma non innescato: l'attacco reale alle centrifughe di Natanz passava dal primo. In entrambi i casi, se il worm non trovava la configurazione cercata — un numero preciso di convertitori di frequenza di marca Vacon o Fararo Paya, collegati tramite un modulo di comunicazione PROFIBUS CP 342-5 — restava inerte.

## Come funzionava: quattro zero-day in un solo attacco

Quello che ha reso Stuxnet eccezionale, anche oggi, è il numero di vulnerabilità sconosciute usate in un solo attacco: normalmente un gruppo che possiede uno [zero-day](https://hackita.it/articoli/zero-day/) lo usa con parsimonia, proprio per non "bruciarlo" e farlo scoprire. Microsoft ha identificato quattro vulnerabilità Windows sfruttate da Stuxnet, tutte sconosciute al momento dell'attacco:

| Vulnerabilità     | Cosa permetteva                                                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **CVE-2010-2568** | Esecuzione automatica tramite la gestione dei file `.LNK`/`.PIF` (collegamenti di Windows), il vettore iniziale via supporto rimovibile |
| **CVE-2010-2729** | Vulnerabilità nel servizio di spooling di stampa di Windows, usata per la propagazione in rete                                          |
| **CVE-2010-2743** | Elevazione di privilegi nel kernel di Windows                                                                                           |
| **CVE-2010-3338** | Elevazione di privilegi tramite il Task Scheduler di Windows                                                                            |

A questo si aggiungeva una **vulnerabilità applicativa zero-day** nel software Siemens (**CVE-2010-2772**), dovuta a una password hard-coded nel sistema WinCC/PCS 7, sfruttabile localmente per accedere al database di backend, oltre a una falla di rete già nota, usata in precedenza anche dal worm Conficker, per la diffusione su condivisioni di rete locale.

## Come ha bucato un impianto isolato da Internet

Natanz, per ragioni di sicurezza, non era connesso direttamente a Internet (un *air gap*). Stuxnet ha superato questo isolamento nel modo più semplice possibile: una **chiavetta USB infetta**, inserita da qualcuno (consapevolmente o meno) in un computer della rete interna. Da lì:

1. Il worm si diffondeva lateralmente tra le workstation della rete tramite le vulnerabilità Windows elencate sopra.
2. Cercava le **Field PG**, le workstation di ingegneria Siemens usate per programmare i PLC.
3. Quando una di queste si collegava a un PLC Siemens S7-315 per la programmazione, Stuxnet iniettava il proprio payload malevolo direttamente nella logica del controllore.
4. Una volta nel PLC, il worm monitorava le connessioni PROFIBUS (il protocollo industriale usato dai PLC) per circa **13 giorni**, osservando il normale funzionamento.
5. Dopo quella fase di osservazione, alterava la velocità di rotazione delle centrifughe per circa **27 giorni**, per poi tornare al funzionamento normale per altri 27 giorni, in un ciclo pensato per sembrare un guasto casuale piuttosto che un sabotaggio.

Secondo l'analisi di ISIS, la prima sequenza di attacco portava la frequenza di rotazione fino a circa **1.410 Hz per 15 minuti** (ben oltre i parametri di sicurezza), seguita circa 27 giorni dopo da una seconda sequenza che abbassava drasticamente la frequenza, con ulteriori cicli scanditi a intervalli di circa 27 giorni. Un comportamento così temporizzato, invece di un singolo guasto improvviso, era pensato per sembrare un deterioramento meccanico naturale piuttosto che un sabotaggio deliberato.

Nel frattempo, il worm **falsificava i dati mostrati agli operatori**: secondo la documentazione tecnica raccolta da MITRE ATT\&CK for ICS, Stuxnet intercettava le comunicazioni tra il software di supervisione (WinCC) e il PLC sostituendo la libreria di sistema `s7otbxdx.dll`, usata normalmente per quelle comunicazioni, con una propria versione modificata. In questo modo il worm poteva nascondere il proprio codice iniettato nei blocchi di programma del PLC (in particolare nei blocchi **OB1** e **OB35**, usati per l'esecuzione ciclica della logica di controllo) e mostrare agli operatori valori di processo del tutto normali, mentre le centrifughe venivano danneggiate dall'interno. MITRE classifica questo comportamento come una tecnica di [rootkit](https://hackita.it/articoli/rootkit/) a livello di PLC: non nascondeva solo file sul disco, ma l'intera rappresentazione dello stato reale del processo industriale.

## Il danno: circa 1.000 centrifughe compromesse

Secondo le stime dell'Institute for Science and International Security, tra la fine del 2009 e l'inizio del 2010 Stuxnet ha probabilmente danneggiato circa **1.000 centrifughe IR-1**, pari a circa il 10% di quelle operative nell'impianto in quel periodo. Gli ispettori dell'AIEA (Agenzia Internazionale per l'Energia Atomica) avevano osservato un anomalo aumento nella sostituzione di centrifughe a Natanz già a gennaio 2010, prima ancora che il worm venisse scoperto e analizzato pubblicamente.

## Chi ha scoperto Stuxnet e come

Stuxnet è stato identificato nel giugno 2010 da una società di sicurezza bielorussa, dopo che alcuni sistemi industriali in giro per il mondo (non solo in Iran) mostravano comportamenti anomali causati, senza volerlo, dalla diffusione del worm oltre il suo bersaglio originale. L'analisi tecnica approfondita è arrivata nei mesi successivi: **Symantec** ha pubblicato un dossier tecnico dettagliato (il celebre *W32.Stuxnet Dossier*), mentre l'esperto di sicurezza industriale **Ralph Langner** è stato tra i primi a decifrare pubblicamente lo scopo reale del payload, collegandolo in modo specifico alle centrifughe di Natanz.

## Chi c'è dietro Stuxnet

L'attribuzione non è mai stata ufficialmente confermata da nessun governo, ma l'analisi tecnica converge su un punto: un'operazione di questa complessità, con quattro zero-day Windows, certificati digitali rubati a due aziende taiwanesi (Realtek e JMicron, usati per far apparire i driver del worm come legittimi) e una conoscenza dettagliata e specifica dell'impianto di Natanz, richiede risorse e informazioni di intelligence tipiche di un attore statale. Il consenso diffuso tra ricercatori e giornalisti investigativi attribuisce l'operazione a una collaborazione tra Stati Uniti e Israele, ma si tratta appunto di un'attribuzione basata su analisi indipendenti, mai confermata ufficialmente dalle parti coinvolte.

## Perché Stuxnet ha cambiato tutto

Prima di Stuxnet, un attacco informatico "distruttivo" era più teoria che pratica documentata. Dopo Stuxnet, è diventato un precedente concreto e studiato:

* **Ha dimostrato che l'air gap non è una protezione assoluta**: un supporto rimovibile resta un vettore valido, a prescindere da quanto un impianto sia isolato dalla rete.
* **Ha stabilito un modello per gli attacchi ICS/SCADA successivi**: malware pensati specificamente per sistemi di controllo industriale, come Industroyer (2016, contro la rete elettrica ucraina), TRITON/TRISIS (2017, contro i sistemi di sicurezza di un impianto petrolchimico) e Industroyer2 (2022), condividono con Stuxnet l'obiettivo di manipolare direttamente un processo fisico attraverso i suoi sistemi di controllo.
* **Ha reso popolare il concetto di cyber-kinetic attack**: un'intrusione puramente digitale con conseguenze fisiche dirette, non solo furto di dati.
* **Ha normalizzato l'uso massiccio di zero-day in un singolo attacco** da parte di attori con risorse elevate, cambiando le aspettative su cosa un gruppo avanzato sia disposto a "bruciare" per un obiettivo di alto valore.

## Il lato difensivo: cosa impara chi lavora in sicurezza OT/ICS

Per chi si occupa di sicurezza di sistemi industriali (OT, *Operational Technology*), Stuxnet resta un caso di studio imprescindibile. Alcuni principi difensivi che ne derivano, e che vale la pena conoscere anche solo a livello teorico:

* **I supporti rimovibili restano un vettore reale**, anche in ambienti isolati: politiche di controllo sulle porte USB e scansione dei supporti prima dell'uso sono misure minime, non opzionali, in ambienti industriali critici.
* **Il monitoraggio deve includere l'integrità della logica PLC**, non solo i log di rete: Stuxnet ha aggirato il monitoraggio proprio falsificando i dati mostrati agli operatori, un principio che vale ancora oggi contro malware ICS moderni.
* **La segmentazione tra rete IT e rete OT** va progettata assumendo che un singolo punto di contatto (una workstation di ingegneria, un laptop di manutenzione) possa fare da ponte tra i due mondi.

Per chi vuole studiare pubblicamente la logica di programmazione dei PLC e il protocollo PROFIBUS/PROFINET a scopo didattico, esistono risorse aperte come la documentazione Siemens stessa e progetti di ricerca accademica su honeypot ICS (ambienti esca che simulano sistemi industriali per studiare gli attacchi in corso), un campo di studio nato in parte proprio dall'eredità di Stuxnet.

## Domande frequenti su Stuxnet

### Cos'è Stuxnet?

Un worm informatico scoperto nel 2010, considerato la prima arma informatica della storia capace di causare danni fisici reali: ha sabotato le centrifughe dell'impianto nucleare iraniano di Natanz.

### Come si è diffuso Stuxnet in un impianto isolato da Internet?

Tramite una chiavetta USB infetta, che ha permesso al worm di superare l'air gap e diffondersi poi lateralmente nella rete interna sfruttando diverse vulnerabilità Windows.

### Quante vulnerabilità zero-day usava Stuxnet?

Quattro vulnerabilità zero-day di Windows (tra cui CVE-2010-2568 per l'esecuzione via supporto rimovibile e CVE-2010-2743 per l'elevazione di privilegi), più una vulnerabilità applicativa zero-day nel software Siemens (CVE-2010-2772), un numero eccezionale per un singolo attacco.

### Quanti danni ha causato Stuxnet?

Si stima che abbia danneggiato circa 1.000 centrifughe IR-1 a Natanz, circa il 10% di quelle operative nel periodo dell'attacco.

### Chi ha creato Stuxnet?

L'attribuzione non è mai stata confermata ufficialmente da nessun governo. Il consenso tra ricercatori indipendenti attribuisce l'operazione a una collaborazione tra Stati Uniti e Israele.

### Perché Stuxnet è considerato così importante nella storia della cybersecurity?

Perché ha dimostrato concretamente che un attacco informatico può causare danni fisici diretti, ha stabilito un modello per gli attacchi successivi contro sistemi industriali e ha cambiato le aspettative su quante vulnerabilità un attore avanzato sia disposto a usare in una singola operazione.

### Stuxnet rubava dati come un malware tradizionale?

No. Il suo scopo non era il furto di informazioni ma il sabotaggio fisico: alterava la velocità delle centrifughe fino a danneggiarle, mentre falsificava i dati mostrati agli operatori per nascondere il sabotaggio in corso.

### Esistono malware simili a Stuxnet apparsi dopo il 2010?

Sì, il caso ha aperto un filone di ricerca e di attacchi reali contro sistemi di controllo industriale, da Shamoon contro Saudi Aramco nel 2012 a diverse famiglie di malware successive pensate specificamente per ambienti ICS/SCADA.
