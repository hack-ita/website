---
title: 'Data Center Basilicata: il caso Kraken e il giallo hacker'
slug: data-center-basilicata-kraken-attacco-hacker
description: 'Data Center Basilicata in tilt: guasto tecnico, pagine in russo e Kraken. Cosa è successo e cosa sappiamo sull’ipotesi di attacco hacker alla Regione.'
image: /data-center-basilicata-attacco-hacker-kraken.webp
draft: false
date: 2026-10-04T20:25:07.949Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - SEO Poisoning
  - Hacked Content
  - Data Center
  - Kraken
featured: true
---

# Sanità ed ospedali della Basilicata hackerati? Cosa sappiamo davvero sul caso Kraken

La sanità e gli ospedali** della Basilicata sono stati hackerati?** È la domanda che migliaia di cittadini lucani hanno digitato su Google in questi giorni, dopo giorni di CUP bloccato, visite impossibili da prenotare e un sito regionale sparito dalla rete. La risposta ufficiale è no: la Regione parla di un guasto tecnico. Ma nel frattempo, dentro il sito istituzionale, è comparsa una parola che un guasto hardware non può spiegare da solo: **Kraken**, scritta in russo, insieme a link verso un marketplace del dark web.

**In breve:** al momento non risultano prove pubbliche che il blocco del Data Center Unico Regionale sia stato causato da un attacco hacker. La Regione attribuisce il disservizio a un'anomalia dell'impianto di raffreddamento e al mancato avvio del backup, ed esclude accessi abusivi o sottrazione di dati personali. Separatamente, sono state documentate pagine del sito istituzionale con contenuti in russo e riferimenti a Kraken: il collegamento tra i due eventi non è stato dimostrato, ma le due cose sono successe nello stesso sito, nella stessa settimana.

Dal 27 settembre 2026 la Basilicata ha vissuto uno dei disservizi digitali più estesi degli ultimi anni, con un impatto diretto su CUP, prenotazioni sanitarie, portale dei pagamenti regionali e sito dell'Università.

## Cronologia dei fatti

* **23 settembre**: prime anomalie segnalate nella sezione "Amministrazione trasparente" del sito regione.basilicata.it.
* **27 settembre (domenica)**: il sito istituzionale diventa irraggiungibile.
* **28 settembre (lunedì)**: primo comunicato ufficiale via WhatsApp — "blocco tecnico al Data Center", la Regione esclude da subito l'ipotesi di attacco hacker esterno. Segnalati ritardi nelle attività ambulatoriali e negli esami di laboratorio.
* **29 settembre**: Basilicata24 documenta la stringa "Kraken" e contenuti in lingua russa nella sezione "Amministrazione trasparente" del sito.
* **30 settembre**: la Regione dichiara il ritorno operativo del CUP e afferma che non sono emerse evidenze di attacco informatico, accessi abusivi o esfiltrazione di dati personali.
* **1 ottobre**: la Regione aggiorna la ricostruzione tecnica del guasto — anomalia dell'impianto di raffreddamento del Data Center e mancato avvio del sistema di backup. ACN e Garante Privacy vengono comunque informati; il pagamento dei tributi regionali resta sospeso.

## Cosa è confermato, cosa è dichiarato, cosa è solo osservato

Nella ricostruzione di questo caso conviene tenere separati tre piani, perché nei resoconti si sono spesso sovrapposti:

**Confermato (fatto osservabile):** il Data Center Unico Regionale è stato fuori servizio per giorni, con impatto su CUP, prenotazioni sanitarie, pagamenti regionali e sito dell'Università.

**Dichiarato (fonte: Regione Basilicata):** la causa sarebbe un'anomalia dell'impianto di raffreddamento unita al mancato avvio del backup; non risulterebbero accessi abusivi né sottrazione di dati personali.

**Osservato da terzi (fonte: Basilicata24):** nella sezione "Amministrazione trasparente" del sito istituzionale sono comparsi contenuti in lingua russa e riferimenti al marketplace darknet Kraken.

Il guasto al raffreddamento spiega il blackout dei sistemi. Non spiega, da solo, la comparsa di contenuti in russo sul portale regionale: sono due osservazioni che riguardano livelli diversi dell'infrastruttura (hardware del Data Center da un lato, contenuto del sito web dall'altro) e che, allo stato attuale della documentazione pubblica, non risultano collegate da alcuna fonte ufficiale.

### Tabella riassuntiva

| Elemento                            | Stato                                       |
| ----------------------------------- | ------------------------------------------- |
| Data Center fuori servizio          | Confermato                                  |
| Anomalia impianto di raffreddamento | Dichiarazione ufficiale                     |
| Mancato avvio del backup            | Dichiarazione ufficiale                     |
| Contenuti in russo sul portale      | Documentato da fonti giornalistiche         |
| Riferimenti a Kraken                | Documentati                                 |
| Compromissione del CMS/sito         | Ipotesi tecnica compatibile con le evidenze |
| SEO poisoning                       | Ipotesi, non attribuita pubblicamente       |
| Attacco informatico al Data Center  | Non dimostrato                              |
| Furto di dati personali             | Non risultano evidenze pubbliche            |
| Collegamento Kraken ↔ blackout      | Non dimostrato                              |

## Cos'è Kraken, e perché potrebbe comparire su un sito PA

Kraken è un marketplace del dark web, tra i principali successori di Hydra (il colosso del commercio illegale russo chiuso dalle autorità nel 2022), diffuso nei paesi dell'area CSI per la vendita di beni e servizi illeciti. Per aggirare i blocchi e farsi trovare, questi mercati si affidano a reti di mirror e a tecniche di promozione aggressive sui motori di ricerca.

Google classifica esplicitamente questo tipo di fenomeno come **hacked content**: contenuto inserito senza autorizzazione sfruttando una vulnerabilità, che include categorie come la *page injection* e la *content injection* finalizzate a manipolare i risultati di ricerca. Una variante comune è il cosiddetto **SEO poisoning**: si compromette una pagina debole — spesso un CMS pubblico datato o mal protetto, come capita di frequente ai siti della Pubblica Amministrazione — e vi si inietta testo e link verso il sito da promuovere, nella lingua del pubblico target. Il dominio compromesso presta involontariamente la propria autorevolezza (in questo caso un .it governativo) per far scalare posizioni al sito di destinazione nei risultati di ricerca russi.

Il contenuto osservato sul portale della Regione Basilicata è compatibile con questo scenario. Non è però possibile, sulla base della documentazione pubblica attualmente disponibile, stabilire con certezza il vettore d'intrusione né attribuire la modifica a un autore specifico.

**Una precisazione necessaria:** esiste anche un malware chiamato "Kraken", scoperto nel 2020, che si nasconde nel processo legittimo di Windows `WerFault.exe` per eseguire codice eludendo gli antivirus. Il nome coincide per puro caso con quello del marketplace darknet: sono due minacce completamente distinte. Nulla, nella documentazione pubblica sul caso Basilicata, collega il disservizio a questo malware specifico.

## Come potrebbe essere stata compromessa la pagina della Regione

Una possibile catena di eventi, puramente ricostruttiva e compatibile con quanto osservato pubblicamente — non un'attribuzione, ma lo schema minimo che spiega i fatti documentati:

```
Initial Access → CMS Compromise → Content Injection → SEO Poisoning → Indexing
```

* **Initial Access**: una falla nel CMS che gestisce il sito — upload non validato, credenziali di amministrazione deboli o riusate, plugin/estensione non aggiornata. Le sezioni alimentate da upload automatici (come "Amministrazione trasparente", dove finiscono delibere e documenti pubblicati di continuo) sono bersagli tipici perché più permissive e meno monitorate.
* **CMS Compromise**: con un accesso valido o una falla sfruttabile, l'attaccante ottiene la possibilità di scrivere contenuto nella sezione colpita.
* **Content Injection**: non viene installato malware né eseguito codice sul server — viene semplicemente scritto testo statico in russo, con le keyword tipiche dei marketplace darknet, e link verso i mirror del sito da promuovere.
* **SEO Poisoning**: il dominio compromesso (.it governativo, alto trust score) presta involontariamente la propria autorevolezza per far scalare posizioni a quel contenuto nei risultati di ricerca russi.
* **Indexing**: Google indicizza la pagina compromessa, il marketplace guadagna visibilità organica gratuita, senza che un solo sistema del Data Center venga toccato.

Le evidenze tecniche che andrebbero verificate per confermare o escludere questo scenario sono:

* log di autenticazione amministrativa sul CMS, per identificare accessi anomali
* richieste HTTP POST/PUT fuori pattern verso gli endpoint della sezione colpita
* modifiche a template o database non riconducibili alla normale pipeline editoriale
* file creati o modificati fuori dal workflow standard di pubblicazione
* presenza di URL in lingua russa effettivamente indicizzate da Google
* eventuale **cloaking**, cioè contenuto diverso servito a Googlebot rispetto a quello mostrato agli utenti umani — tecnica che Google segnala esplicitamente come possibile veicolo di hacked content

Nessuno di questi elementi risulta confermato pubblicamente al momento della scrittura di questo articolo. Se emergesse una compromissione reale, si tratterebbe comunque di un incidente di sicurezza da notificare secondo gli schemi previsti dal [GDPR](https://hackita.it/articoli/gdpr/) (se coinvolge dati personali) e dalla [NIS2](https://hackita.it/articoli/nis2/) (se l'ente rientra tra i soggetti tenuti a notifica) — a prescindere dal fatto che configuri o meno un vero e proprio [data breach](https://hackita.it/articoli/data-breach/).

**Checklist operativa per un team che deve verificare un caso simile:**

```
CMS → account admin → log HTTP → DB/template → indicizzazione → persistence
```

In ordine: verificare versione e plugin del CMS contro CVE note; controllare i log di autenticazione admin per accessi fuori orario o da IP anomali; cercare richieste POST/PUT non riconducibili al workflow editoriale; confrontare hash e timestamp di database e template contro l'ultimo deploy legittimo noto; lanciare query `site:` su Google per individuare contenuto indicizzato non previsto; infine, verificare che non sia stata lasciata una backdoor o un account di servizio creato ad hoc per garantire un rientro futuro.

## Guasto tecnico o violazione di dati personali? La differenza conta

Un punto spesso frainteso nella copertura di questi casi: un'interruzione di servizio non equivale automaticamente a una violazione di dati personali ai sensi del GDPR. Il fermo dei sistemi costituisce certamente un incidente di disponibilità. Diventerebbe anche una violazione di dati personali solo qualora le verifiche in corso accertassero un impatto reale su disponibilità, integrità o riservatezza di dati personali — cosa che, allo stato attuale, la Regione esclude.

Questo è anche il motivo per cui Regione, ACN e Garante Privacy sono stati coinvolti in parallelo: la notifica è una misura prudenziale che non implica di per sé la conferma di una violazione.

Sul fronte della sicurezza delle infrastrutture digitali, il quadro normativo di riferimento è il D.Lgs. 138/2024 di recepimento della direttiva NIS2, che individua tra i soggetti potenzialmente rilevanti anche specifiche categorie di pubbliche amministrazioni regionali (Allegato III), fermo restando che la qualificazione concreta come soggetto "essenziale" o "importante" richiede una valutazione puntuale caso per caso. Per gli incidenti ritenuti significativi, il decreto prevede una pre-notifica a CSIRT Italia entro 24 ore e una notifica più dettagliata entro 72 ore.

## Se fosse stato un ransomware: cosa cambierebbe (e perché pagare non è la soluzione)

Va ribadito: non ci sono evidenze pubbliche che questo caso sia un attacco [ransomware](https://hackita.it/articoli/ransomware/). Ma visto che il sospetto è circolato, vale la pena chiarire in breve come funzionerebbe quello scenario, a scopo puramente informativo.

In un attacco ransomware "classico", i dati vengono cifrati e l'attaccante chiede un riscatto (spesso in criptovaluta) per fornire la chiave di decifratura; nelle varianti a doppia estorsione, minaccia anche di pubblicare i dati rubati sul dark web se non si paga. Le autorità italiane (Polizia Postale, ACN) e la prassi internazionale sconsigliano il pagamento del riscatto, per tre motivi concreti: non garantisce il recupero effettivo dei dati, finanzia direttamente le organizzazioni criminali permettendo nuovi attacchi, e non impedisce comunque un'eventuale pubblicazione dei dati già esfiltrati. La strategia difensiva raccomandata resta il ripristino da backup offline/immutabili, non la trattativa con l'attaccante.

Nel caso Basilicata, la Regione ha dichiarato pubblicamente di escludere questo scenario, attribuendo il blocco a una causa infrastrutturale.

## L'impatto reale sui cittadini

Al netto della ricostruzione tecnica, i disservizi sono stati concreti: sportelli e casse ferme, agende delle aziende sanitarie congelate, visite attese da mesi diventate impossibili da riprenotare, portale dei pagamenti regionali inaccessibile, seduta del Consiglio regionale rinviata. Il personale del Servizio Sanitario Regionale ha gestito urgenze ed emergenze con procedure manuali nelle strutture di Potenza e Matera, in attesa del ripristino completo.

Per una Pubblica Amministrazione che concentra la quasi totalità dei propri servizi digitali — tramite RUPAR e il Data Center Unico Regionale — in un'unica infrastruttura, un singolo punto di errore, tecnico o malevolo che sia, diventa un singolo punto di fallimento per un'intera regione. È lo stesso principio alla base dei piani di disaster recovery, di cui più volte si è discusso anche per l'infrastruttura regionale lucana.

## Analisi Hackita

Se la comparsa di contenuti in russo nella sezione "Amministrazione trasparente" fosse effettivamente riconducibile a un SEO poisoning, il pattern sarebbe compatibile con una compromissione mirata del solo layer applicativo/web del sito, distinta e indipendente dal guasto infrastrutturale dichiarato per il Data Center. In altre parole: due problemi paralleli, non necessariamente la stessa causa.

Quello che renderebbe questo caso interessante per chi si occupa di sicurezza delle PA non è tanto "è stato un attacco hacker sì o no", quanto il fatto che — guasto a parte — esisteva comunque una superficie di attacco non presidiata (una sezione del sito vulnerabile a content injection) che, se davvero sfruttata, meriterebbe interventi indipendenti dal ripristino del Data Center: audit del CMS, rotazione credenziali amministrative, controllo differenze tra contenuto servito a crawler e a utenti.

## Domande frequenti

**Il Data Center della Basilicata è stato hackerato?**
Non risulta dimostrato pubblicamente. La Regione attribuisce il blocco a un guasto tecnico (raffreddamento + backup non avviato) ed esclude accessi abusivi.

**Cosa è successo esattamente?**
Il Data Center Unico Regionale è rimasto fuori servizio da domenica 27 settembre, bloccando CUP, prenotazioni sanitarie, pagamenti regionali e il sito dell'Università.

**Cos'è Kraken e perché compare sul sito della Regione?**
Kraken è un marketplace del dark web molto diffuso in Russia. I contenuti in russo trovati sul sito regionale sono compatibili con una tecnica di SEO poisoning volta a sfruttare l'autorevolezza di un dominio governativo per promuovere quel marketplace.

**Sono stati rubati i dati dei cittadini?**
La Regione dichiara di non aver riscontrato evidenze di sottrazione o esfiltrazione di dati personali. Le verifiche tecniche erano ancora in corso al momento della stesura di questo articolo.

**Il guasto del Data Center e i contenuti in russo sono collegati?**
Non risulta dimostrato. Sono due osservazioni riferite a livelli diversi dell'infrastruttura (hardware vs contenuto del sito web) e, allo stato attuale, nessuna fonte ufficiale le collega.

**Cos'è un Data Center?**
È una struttura fisica che ospita server, sistemi di archiviazione e apparati di rete usati per far funzionare servizi digitali. Nel caso della Regione Basilicata, il Data Center Unico Regionale centralizza i sistemi informatici da cui dipendono CUP, pagamenti regionali, sito istituzionale e altri servizi di enti regionali, comunali e sanitari: se va fuori servizio, vanno giù con esso tutti i servizi che vi si appoggiano.

**Cos'è il SEO poisoning?**
Una tecnica che sfrutta vulnerabilità di un sito legittimo per iniettarvi contenuto (testo, link) finalizzato a far scalare posizioni nei motori di ricerca a un sito terzo, spesso illegale, parassitando l'autorevolezza del dominio compromesso.

## Fonti

* Regione Basilicata, comunicati ufficiali del 28 settembre e del 1° ottobre 2026
* Basilicata24, inchiesta del 29 settembre 2026 sulla scoperta dei contenuti in russo e del riferimento a Kraken
* ANSA Basilicata, 1 ottobre 2026
* Documentazione Google Search Central sulle categorie di hacked content (page injection, content injection, cloaking)

*Articolo aggiornato al 4 ottobre 2026. La vicenda è ancora in corso di accertamento da parte delle autorità competenti; questo articolo verrà aggiornato in caso di nuovi sviluppi ufficiali.*
