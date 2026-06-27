---
title: 'Ransomware 2026: guida completa .Cosa sono e come difendersi'
slug: ransomware
description: >-
  Guida completa al ransomware 2026: cos'è, come funziona, attacchi storici
  (WannaCry, LockBit), doppia estorsione, RaaS e best practice per difendersi
  con backup, MFA e Zero Trust.
image: /ransomware-2026-attacchi-difese.webp
draft: false
date: 2026-06-02T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - cyberattack
  - malware
  - double-extortion
  - raas
  - wannacry
  - lockbit
---

# Ransomware: Guida Completa 2026 — Cos'è, Come Funziona e Come Difendersi

> 📌 **Definizione**Il **ransomware** è un tipo di malware che cifra i file o blocca l'accesso ai sistemi della vittima, richiedendo un riscatto — solitamente in criptovalute come Bitcoin o Monero — per ripristinare l'accesso ai dati. È oggi la minaccia informatica economicamente più devastante al mondo.

***

## In Breve

|                         |                                                                  |
| ----------------------- | ---------------------------------------------------------------- |
| **Cos'è**               | Malware che cifra i dati e chiede un riscatto                    |
| **Come funziona**       | Accesso iniziale → movimento laterale → cifratura → estorsione   |
| **Chi colpisce**        | Aziende, ospedali, enti pubblici, PMI, infrastrutture critiche   |
| **Quanto costa**        | $2,73M di costo medio di recupero nel 2024 (escluso il riscatto) |
| **Come difendersi**     | Backup immutabili, MFA, patch management, EDR/XDR, Zero Trust    |
| **Pagare il riscatto?** | No — solo il 4% recupera tutti i dati dopo il pagamento          |

***

## Punti Chiave

* Nel 2024 sono state documentate **5.414 vittime pubblicate** a livello globale, +11% rispetto al 2023
* Il **94% degli attaccanti** tenta di compromettere i backup prima di attivare la cifratura
* Il **64% delle vittime** ha rifiutato di pagare nel 2024, riflettendo strategie di recovery migliorate
* Il pagamento più alto mai registrato è stato di **75 milioni di dollari** (Fortune 50, 2024)
* Sono oggi attivi **oltre 95 gruppi ransomware** tracciati a livello globale
* Il ransomware è responsabile di circa il **44% di tutti i data breach** (Verizon DBIR 2025)
* Il danno globale è proiettato a superare **265 miliardi di dollari annui entro il 2031** (Cybersecurity Ventures)

***

## Cos'è un Ransomware

Il ransomware è una categoria di software malevolo (malware) progettato con un obiettivo preciso: rendere inaccessibili i dati o i sistemi di una vittima e richiedere un riscatto — *ransom* in inglese — in cambio del ripristino dell'accesso.

Nella sua forma più comune, il ransomware cifra i file della vittima con algoritmi crittografici robusti (AES-256, RSA-2048), dopodiché i criminali richiedono un pagamento in criptovalute per fornire la chiave di decifratura.

Non si tratta di una minaccia recente: il primo caso documentato risale al **1989**, quando il ricercatore Joseph Popp distribuì fisicamente floppy disk contenenti il cosiddetto "AIDS Trojan", con un riscatto di 189 dollari. Tuttavia, è stato solo con la diffusione di internet, la maturazione delle criptovalute e l'avvento del modello **Ransomware-as-a-Service (RaaS)** che il ransomware è diventato la minaccia sistemica che conosciamo oggi.

**Perché il ransomware è così efficace?**

* Colpisce il bene più prezioso di un'organizzazione: i dati
* Genera effetti immediati e misurabili: impossibilità di operare, downtime, perdita di fatturato
* Sfrutta la pressione del tempo per forzare il pagamento (*deadline*, pubblicazione dati)
* Le criptovalute garantiscono pseudo-anonimato nei pagamenti
* Il modello RaaS ha abbassato la barriera d'ingresso: non serve più saper sviluppare malware
* L'uso crescente di **AI generativa** nella fase di phishing rende gli attacchi più convincenti e scalabili

***

## Come Funziona un Ransomware: La Kill Chain dell'Attacco

A livello concettuale, il ransomware segue un ciclo di vita strutturato che gli esperti di sicurezza descrivono attraverso il framework **MITRE ATT\&CK**, sviluppato dall'organizzazione MITRE Corporation come standard di riferimento globale per la categorizzazione delle tattiche, tecniche e procedure (TTP) degli attaccanti.

### Fase 1 — Initial Access (Accesso Iniziale)

L'attaccante guadagna un punto d'ingresso nella rete della vittima tramite phishing, credenziali rubate, vulnerabilità in sistemi esposti, o accessi acquistati da **Initial Access Broker (IAB)** nel dark web.

> 📌 **Definizione — Initial Access Broker (IAB)**Un Initial Access Broker è un operatore criminale specializzato nella compromissione di reti aziendali e nella rivendita di quell'accesso ad altri gruppi — tipicamente operatori RaaS. Acquistano accesso tramite phishing, credential stuffing o exploit, e lo rivendono nel dark web a prezzi che vanno da poche centinaia a decine di migliaia di dollari, a seconda del target.

Gli IAB alimentano direttamente l'ecosistema RaaS.

### Fase 2 — Persistence & Lateral Movement

Una volta all'interno, l'attaccante non agisce immediatamente. I gruppi ransomware professionali trascorrono in media **settimane o mesi** nella rete prima di attivare la cifratura. In questo intervallo mappano la rete, identificano i sistemi critici, escalano i privilegi (*privilege escalation*), si spostano lateralmente verso altri host — tecniche documentate da **CrowdStrike**, **Mandiant** e **Palo Alto Networks Unit42** nei loro threat report annuali.

Strumenti nativi di Windows come WMI, PsExec e PowerShell vengono spesso usati in modalità *Living off the Land (LotL)* per ridurre il rumore e sfuggire ai sistemi SIEM. La fase di [enumerazione della rete](https://hackita.it/articoli/enumeration/) è quella in cui vengono identificati i target ad alto valore prima dell'attivazione del payload.

### Fase 3 — Impact: Preparazione e Cifratura

Prima della cifratura vera e propria, il ransomware tenta di compromettere i sistemi di backup. Secondo il **Sophos State of Ransomware 2024**, nel **94%** degli attacchi gli attaccanti hanno tentato di sabotare i backup, riuscendoci nel **57%** dei casi. La cifratura viene poi attivata in modo coordinato — spesso in orari notturni o durante festività — per massimizzare il danno prima che qualcuno se ne accorga.

In molti casi viene usato il protocollo [NTLM](https://hackita.it/articoli/ntlm/) per il movimento laterale e la compromissione degli account privilegiati — un vettore ancora molto comune negli ambienti Active Directory aziendali.

### Fase 4 — Estorsione e Negoziazione

La vittima trova una *ransom note* che descrive la situazione, indica il metodo di pagamento e fissa una scadenza (*deadline*). Superata la scadenza, il riscatto aumenta o i dati esfiltrati vengono pubblicati su **leak site** nel dark web — nel modello a doppia estorsione, ormai standard.

***

## Come Avviene Normalmente un'Infezione

I principali vettori di infezione documentati dalle organizzazioni di threat intelligence globali sono:

| Vettore                               | % stimata (2024) | Note                                     |
| ------------------------------------- | ---------------- | ---------------------------------------- |
| Phishing via email                    | \~36%            | Vettore n°1; sfrutta il fattore umano    |
| Vulnerabilità software non patchate   | \~32%            | Zero-day e N-day in software enterprise  |
| Credenziali compromesse (RDP esposto) | \~29%            | Spesso acquistate da IAB                 |
| Supply chain e fornitori terzi        | \~11%            | Kaseya, MOVEit, Cleo — trend in crescita |
| Dispositivi rimovibili                | \<2%             | In forte calo nei contesti enterprise    |

*(Fonte: elaborazione da Sophos, Verizon DBIR, FBI IC3 2024)*

**Il phishing** rimane il vettore più comune perché sfrutta il fattore umano, il link più debole di qualsiasi catena di sicurezza. Un'email che simula una comunicazione aziendale legittima, un allegato apparentemente innocuo, un link verso una pagina di login clonata: basta un clic inconsapevole. Le tecniche di [phishing offensivo](https://hackita.it/articoli/phishing-techniques-red-team/) usate nei red team engagement sono oggi sofisticate quanto quelle dei criminali — il confine è sottile.

Le **vulnerabilità non patchate** rappresentano la seconda causa principale. Gruppi come Clop e BlackCat/ALPHV hanno costruito parte della loro fortuna sull'exploitation rapida di vulnerabilità **zero-day** in software enterprise ampiamente diffusi, come MOVEit Transfer e Cleo.

Il **Remote Desktop Protocol (RDP) esposto su internet** è storicamente uno dei vettori più sfruttati. Credenziali deboli o rubate permettono l'accesso diretto ai sistemi, spesso senza che nessun alert venga generato. Gli [attacchi NTLM Relay](https://hackita.it/articoli/ntlm-relay/) — che sfruttano il protocollo di autenticazione Windows — sono un'altra tecnica comune nella fase di lateral movement, spesso combinata con credenziali rubate via RDP.

***

## Le Tipologie di Ransomware

### Confronto tra le Tipologie Principali

| Caratteristica        | Crypto Ransomware | Locker Ransomware | Double Extortion             | Triple Extortion                        |
| --------------------- | ----------------- | ----------------- | ---------------------------- | --------------------------------------- |
| **Cosa fa**           | Cifra i file      | Blocca il sistema | Cifra + esfiltrazione        | Cifra + esfiltra + DDoS/pressione terzi |
| **Target principale** | Dati e file       | Interfaccia OS    | Dati aziendali critici       | Settori ad alta pressione (sanità, PA)  |
| **Diffusione**        | Molto alta        | Media (consumer)  | Altissima (standard attuale) | Crescente                               |
| **Esempi**            | WannaCry, LockBit | Police Locker     | Maze, Conti, REvil           | BlackCat, Akira                         |
| **Backup utile?**     | ✅ Sì              | ✅ Sì              | ❌ Parzialmente               | ❌ Quasi no                              |

### Crypto Ransomware

È la forma più diffusa. Il malware cifra i file della vittima — documenti, database, immagini, backup — rendendoli inaccessibili senza la chiave di decifratura. La struttura dei file rimane intatta, ma il contenuto diventa illeggibile. WannaCry e LockBit rientrano in questa categoria.

### Locker Ransomware

Blocca completamente l'accesso al sistema operativo o all'interfaccia utente. La vittima non può nemmeno avviare il computer normalmente. È meno diffuso nei contesti enterprise, ma colpisce ancora frequentemente utenti privati e dispositivi mobile.

### Double Extortion (Doppia Estorsione)

> 📌 **Definizione — Double Extortion**La doppia estorsione è un modello di attacco ransomware in cui i criminali esfiltrano i dati *prima* di cifrarli. La vittima viene minacciata su due fronti: pagare per recuperare i file E pagare per evitare la pubblicazione pubblica dei dati rubati.

Introdotto su larga scala dal gruppo **Maze** nel 2019-2020, combina la cifratura con la minaccia di pubblicazione dei dati esfiltrati. Anche con backup funzionanti, la vittima rimane sotto pressione: pagare o vedere pubblicati dati riservati, segreti industriali, dati personali dei clienti. Oggi è lo **standard de facto** tra i gruppi ransomware professionali.

### Triple Extortion (Tripla Estorsione)

L'evoluzione più aggressiva. Alle due estorsioni precedenti si aggiunge una terza: attacco DDoS (Distributed Denial of Service) contro i sistemi della vittima, oppure contatto diretto con clienti, partner o dipendenti per amplificare la pressione. Alcuni gruppi hanno minacciato di notificare direttamente le autorità di regolamentazione (GDPR, HIPAA) per forzare il pagamento.

***

## Ransomware-as-a-Service (RaaS): Il Crimine come Business

> 📌 **Definizione — Ransomware-as-a-Service (RaaS)**Il RaaS è un modello di business criminale in cui gli sviluppatori del ransomware affittano la propria piattaforma ad affiliati esterni. Gli affiliati conducono gli attacchi e trattengono il 70-80% del riscatto. Ha trasformato il ransomware in un'industria scalabile accessibile anche senza competenze tecniche avanzate.

Il **Ransomware-as-a-Service** è il modello di business che più di qualsiasi altro fattore ha contribuito alla proliferazione degli attacchi nell'ultimo decennio.

Il funzionamento è semplice: un gruppo di sviluppatori crea e mantiene la piattaforma ransomware — malware, infrastrutture di pagamento, pannelli di amministrazione, "assistenza alle vittime" — e la mette a disposizione di **affiliati** tramite accordi di partnership. Gli affiliati conducono gli attacchi e trattengono tipicamente il **70-80%** del riscatto.

Questo modello ha abbassato drasticamente la barriera d'ingresso: non serve più saper sviluppare malware. Basta avere accesso a una rete compromessa — spesso acquistato da un Initial Access Broker — e la capacità di gestire una negoziazione.

Il risultato è un ecosistema criminale altamente specializzato, con divisione del lavoro, support ticket, sistemi di reputazione, codici di condotta interni e persino "offerte di lavoro" pubblicate nel dark web.

> 📊 **Dati chiave:** Nel 2024 sono emersi **55 nuovi gruppi RaaS**, un incremento del 67% rispetto all'anno precedente. Sono oggi tracciati oltre **95 gruppi ransomware attivi** a livello globale (Halcyon, 2024). Per il panorama europeo aggiornato, il riferimento è il rapporto annuale [ENISA Threat Landscape](https://www.enisa.europa.eu/topics/cyber-threats/enisa-threat-landscape).

***

## Timeline Storica del Ransomware

| Anno        | Evento                       | Impatto                                              |
| ----------- | ---------------------------- | ---------------------------------------------------- |
| **1989**    | AIDS Trojan (Joseph Popp)    | Primo ransomware via floppy disk; riscatto $189      |
| **2013**    | CryptoLocker                 | Prima campagna ransomware moderna via Bitcoin        |
| **2016**    | Locky, Cerber                | Diffusione massiva via spam; milioni di vittime      |
| **2017**    | WannaCry                     | 200.000 sistemi in 150 paesi; danni $4-8 miliardi    |
| **2017**    | NotPetya                     | Wiper travestito da ransomware; danni >$10 miliardi  |
| **2018**    | Ryuk                         | Big game hunting; ospedali e grandi aziende          |
| **2019**    | REvil, Maze                  | RaaS e double extortion diventano standard           |
| **2020**    | Conti, DarkSide              | Struttura quasi aziendale; Colonial Pipeline         |
| **2021**    | REvil (Kaseya)               | Supply chain attack; 1.500 vittime indirette         |
| **2022**    | LockBit 2.0/3.0              | Gruppo più prolifico; 7.000+ attacchi in 2 anni      |
| **2023**    | Clop (MOVEit)                | 2.600+ organizzazioni colpite; zero-day supply chain |
| **2024**    | BlackCat (Change Healthcare) | $22M riscatto; impatto su sanità USA                 |
| **2024**    | Op. Cronos (LockBit)         | Europol/FBI smantellano l'infrastruttura             |
| **2025-26** | AI-driven ransomware         | Phishing AI-enhanced; 95+ gruppi attivi              |

***

## I Ransomware Più Famosi della Storia

### WannaCry (2017)

**Contesto storico:** Il 12 maggio 2017, WannaCry colpisce il mondo sfruttando **EternalBlue**, exploit sviluppato dalla NSA e trafugato dai Shadow Brokers. La vulnerabilità (MS17-010) era nel protocollo SMB di Windows: Microsoft aveva già rilasciato la patch mesi prima, ma milioni di sistemi erano ancora esposti.

**Impatto:** In meno di 24 ore, oltre **200.000 sistemi in 150 paesi**. Il National Health Service britannico cancella migliaia di appuntamenti medici. Telefónica, FedEx, Renault subiscono interruzioni massive. Danni stimati: **4-8 miliardi di dollari**. Attribuito al gruppo **Lazarus**, legato alla Corea del Nord.

**Lezione:** Un singolo exploit non patchato può avere conseguenze sistemiche globali. WannaCry ha accelerato l'adozione del patch management in migliaia di organizzazioni.

***

### NotPetya (2017)

**Contesto storico:** Il 27 giugno 2017, NotPetya si propaga tramite un aggiornamento compromesso del software di contabilità ucraino **MeDoc**. Si maschera da ransomware, ma è un *wiper* — progettato per distruggere, non per estorcere.

**Impatto:** L'attacco più costoso della storia. **Maersk** perde \~$300M ed è costretta a reinstallare 45.000 PC e 4.000 server in pochi giorni. **Merck** subisce danni per \~$870M. Danno globale: **oltre 10 miliardi di dollari**. Attribuito al gruppo russo **Sandworm** (GRU).

**Lezione:** NotPetya ridefinisce il concetto di *cyber warfare*: attacchi statali possono colpire aziende private globali come danno collaterale.

***

### Ryuk (2018–2021)

**Contesto storico:** Ryuk emerge nell'agosto 2018 come attacco altamente mirato. Non si propaga autonomamente: viene distribuito manualmente dopo aver già compromesso la rete tramite **Emotet** e **TrickBot** (modello *Big Game Hunting*).

**Impatto:** Colpisce ospedali, enti governativi e media. Durante la pandemia COVID-19, diversi attacchi a strutture sanitarie hanno avuto conseguenze potenzialmente letali. Il gruppo **Wizard Spider** avrebbe raccolto **oltre 150 milioni di dollari** tra 2018 e 2020.

***

### REvil / Sodinokibi (2019–2022)

**Contesto storico:** REvil introduce la double extortion con il proprio sito di leak *"Happy Blog"* nel dark web. Uno dei gruppi RaaS più sofisticati della storia.

* **JBS Foods (2021):** Il più grande produttore mondiale di carne paga **11 milioni di dollari** dopo la chiusura forzata di impianti in USA, Canada e Australia.
* **Kaseya VSA (luglio 2021):** Supply chain attack su 1.500 aziende; riscatto richiesto: **70 milioni di dollari**.

Smantellato da operazioni coordinate FBI/Europol; nel gennaio 2022, le autorità russe arrestano diversi membri.

***

### Conti (2020–2022)

Struttura quasi aziendale: dipartimenti separati, stipendi fissi, manuali operativi interni. Colpisce centinaia di organizzazioni globalmente, incluso il **governo della Costa Rica** (maggio 2022), costretto a dichiarare lo stato di emergenza nazionale.

Fine inattesa: dopo il supporto pubblico alla Russia in seguito all'invasione dell'Ucraina, un ricercatore pubblica online tutta la corrispondenza interna e il codice sorgente del ransomware. Il brand Conti si dissolve; i membri migrano in altri gruppi (Akira, Black Basta, Royal).

***

### LockBit (2019–2024)

Il gruppo ransomware più prolifico degli ultimi anni. Tra giugno 2022 e febbraio 2024, **oltre 7.000 attacchi globali** (National Crime Agency UK). Vittime: Boeing, Royal Mail, San Raffaele.

**Operazione Cronos (febbraio 2024):** Europol, FBI, NCA e altre 10 agenzie smantellano l'infrastruttura, recuperano circa 7.000 chiavi di decifratura, svelano l'identità del leader **Dmitry Khoroshev** (alias LockBitSupp), successivamente sanzionato da USA, UK e Australia.

***

### BlackCat / ALPHV (2021–2024)

Tecnicamente tra i ransomware più avanzati: scritto in **Rust**, portabile su Windows, Linux e VMware ESXi.

**Change Healthcare (febbraio 2024):** Colpisce una sussidiaria di **UnitedHealth Group** che gestisce un terzo di tutte le transazioni sanitarie USA. Il blocco dura settimane. Riscatto pagato: **\~22 milioni di dollari**. Considerato l'attacco ransomware con il maggior impatto sulla sanità pubblica della storia americana.

***

### Clop / Cl0p (2019–presente)

Specializzato nell'exploitation di **zero-day** in software enterprise di trasferimento file.

* **MOVEit Transfer (2023):** Zero-day colpisce **2.600+ organizzazioni** globalmente, tra cui agenzie governative USA, banche e università.
* **Cleo (dicembre 2024):** CVE-2024-50623 sfruttato su software usato da 4.000+ organizzazioni.

Dimostra come un singolo punto di ingresso (supply chain) possa generare impatto su scala industriale.

***

## Il Ransomware in Italia

L'Italia è stabilmente tra i paesi europei più colpiti da attacchi ransomware, con caratteristiche specifiche che rendono il contesto nazionale particolarmente vulnerabile.

Secondo le analisi di **ENISA** e del **CSIRT Italia** (Computer Security Incident Response Team della Presidenza del Consiglio), il tessuto produttivo italiano è esposto per diverse ragioni strutturali:

* **Frammentazione del tessuto imprenditoriale:** Le PMI — che rappresentano oltre il 99% delle imprese italiane — hanno in media budget di sicurezza informatica molto inferiori rispetto agli standard necessari.
* **Settore manifatturiero come target primario:** L'Italia, con il suo forte comparto industriale (automotive, moda, food & beverage, meccanica), è particolarmente appetibile: dati di produzione, brevetti, supply chain sono asset critici.
* **Sanità pubblica sotto pressione:** Ospedali italiani sono stati colpiti ripetutamente negli ultimi anni, incluso un grave attacco all'ULSS 6 Euganea nel 2021 e diversi incidenti agli IFO (Istituti Fisioterapici Ospitalieri) nel 2023.
* **Pagamenti sopra la media:** Secondo i dati di Actainfo, le aziende italiane pagano in media il **doppio** rispetto alla media globale dei riscatti.

Le vulnerabilità più sfruttate in Italia riguardano la **cybersecurity aziendale nel 35% dei casi**, il **phishing nel 23%** e la **compromissione delle credenziali nel 16%** degli incidenti documentati.

In caso di attacco, in Italia è obbligatorio notificare l'incidente al **CSIRT Italia** (csirt.gov.it) e al **CNAIPIC** della Polizia Postale per le infrastrutture critiche. Il GDPR impone inoltre notifica all'autorità di controllo (Garante Privacy) entro 72 ore dalla scoperta della violazione.

***

## I Settori Maggiormente Colpiti

| Settore                     | Esposizione | Costo medio breach | Note                                                           |
| --------------------------- | ----------- | ------------------ | -------------------------------------------------------------- |
| **Healthcare**              | Molto alta  | $11,2M (IBM 2025)  | 67% delle org. colpite (Sophos); massima urgenza di ripristino |
| **Manufacturing**           | Alta        | —                  | N°1 per volume (Group-IB); 21% delle vittime globali           |
| **Settore pubblico/Gov.**   | Alta        | $2,83M recovery    | 34% colpite; 98% tasso cifratura dati (Sophos)                 |
| **Financial Services**      | Alta        | —                  | 78% ha segnalato attacchi (Sophos)                             |
| **Education**               | Crescente   | $3,80M (IBM 2025)  | +58% attacchi nel 2025; 3.500 attacchi/settimana               |
| **Infrastrutture critiche** | Emergente   | —                  | 28% di tutti gli attacchi (Verizon 2025)                       |

La sanità è il settore con il costo medio più alto per il **quindicesimo anno consecutivo** (IBM). Le PMI rappresentano un target crescente: l'**88% di tutti i breach ransomware** ha colpito aziende di piccole dimensioni (Verizon DBIR 2025).

***

## Conseguenze Economiche e Operative

### Costi Diretti

* **Riscatto:** Mediana globale \~$115.000 nel 2024 (Verizon), ma il 63% delle richieste supera $1M (Sophos). Pagamento record: **$75 milioni** da un'azienda Fortune 50 anonima nel 2024.
* **Costo di recupero:** Media globale **$2,73M** nel 2024 (Sophos), escluso il riscatto.
* **Downtime:** Media **24 giorni** di interruzione operativa (Statista/Sophos 2024). Ogni ora può costare centinaia di migliaia di euro.

### Costi Indiretti

* **Danno reputazionale:** 53% delle organizzazioni colpite (Cybereason)
* **Perdita di revenue:** 60% registra perdita di fatturato post-attacco
* **Costi legali:** Notifiche GDPR, indagini forensi, sanzioni regolamentari, contenziosi
* **Cyber insurance:** I premi sono aumentati significativamente negli ultimi anni in risposta alla crescita degli attacchi

> ⚠️ **Il mito del "pago e recupero":** Secondo Fortinet, l'**80% delle organizzazioni che pagano** subisce un secondo attacco entro 12 mesi. Solo il **4%** recupera tutti i dati. Il **33%** non recupera i dati nemmeno dopo aver pagato (Coveware/Veeam). Coinvolgere le autorità permette di risparmiare in media **$990.000 per incidente** (IBM 2025).

***

## Come Proteggersi dal Ransomware: Le Best Practice Difensive

La buona notizia è che la grande maggioranza degli attacchi ransomware è prevenibile. Il ransomware non è magia: è un attacco che sfrutta configurazioni errate, software obsoleti e comportamenti umani prevedibili.

### 1. Backup — La Prima Linea di Difesa

* Regola **3-2-1**: 3 copie, 2 supporti diversi, 1 offsite
* Backup **air-gapped** (fisicamente disconnessi) o **immutabili** (non modificabili)
* Testare regolarmente il ripristino — un backup non testato non è un backup
* Il 94% degli attaccanti tenta di compromettere i backup: proteggerli è prioritario

> 💡 **Da ricordare**La regola 3-2-1 non basta più: serve aggiungere la "1" dell'**immutabilità**. Un backup che un attaccante può cifrare o cancellare vale zero.

### 2. Multi-Factor Authentication (MFA)

L'MFA è il controllo di sicurezza con il miglior rapporto costo/beneficio. Rende inutilizzabili le credenziali rubate da sole. Va implementata su tutti i sistemi critici: VPN, email, pannelli di admin, RDP. Vale la pena sapere però che non è infallibile: tecniche come l'[AiTM phishing con Evilginx 3](https://hackita.it/articoli/evilginx3-aitm-mfa-bypass/) dimostrano come sessioni autenticate possano essere intercettate — motivo in più per abbinarla a un monitoraggio comportamentale.

### 3. Patch Management

Le vulnerabilità non patchate causano \~32% degli attacchi ransomware. Un programma strutturato deve:

* Prioritizzare le CVE critiche entro 24-72 ore dalla pubblicazione
* Coprire server, endpoint, dispositivi di rete, applicazioni web e software terze parti
* Automatizzare il patching dove possibile per ridurre la finestra di esposizione

### 4. Segmentazione della Rete

La segmentazione limita la capacità di **lateral movement** degli attaccanti. Se un segmento è compromesso, l'attacco non si propaga automaticamente agli altri. Cruciale per proteggere i sistemi OT (Operational Technology) nelle infrastrutture critiche.

### 5. EDR/XDR — Rilevamento e Risposta Avanzata

Gli antivirus tradizionali basati su firma non bastano contro il ransomware moderno, che usa spesso tecniche *fileless* o si maschera da software legittimo. Le piattaforme **EDR/XDR** offrono:

* Monitoraggio comportamentale continuo degli endpoint
* Rilevamento anomalie anche senza signature note (analisi degli **Indicators of Attack, IoA**)
* Risposta automatizzata: isolamento endpoint, blocco processi
* Visibilità correlata su endpoint, rete, cloud e email

**MDR (Managed Detection & Response)** è l'opzione per le organizzazioni senza SOC interno, con copertura 24/7 esternalizzata.

### 6. Formazione del Personale (Security Awareness)

Il fattore umano rimane il punto d'ingresso più sfruttato. Un programma efficace deve essere:

* **Continuo** — non un corso annuale
* **Pratico** — simulazioni di phishing realistiche
* **Misurabile** — tracking dei tassi di clic nel tempo
* **Aggiornato** — le tecniche cambiano; il training deve riflettere le minacce attuali

### 7. Zero Trust Architecture

Il principio "never trust, always verify". Zero Trust richiede autenticazione e autorizzazione continue per ogni accesso, indipendentemente dalla posizione dell'utente. Elementi chiave:

* Verifica dell'identità continua (non solo al login)
* **Least Privilege**: accesso minimo necessario per ogni ruolo
* Micro-segmentazione della rete
* Monitoraggio continuo del comportamento (**UEBA**)

Il **NIST** (National Institute of Standards and Technology) ha pubblicato la guida di riferimento Zero Trust Architecture nel documento SP 800-207. In Italia, l'**ACN** (Agenzia per la Cybersicurezza Nazionale) e il **NCSC UK** (National Cyber Security Centre) hanno pubblicato linee guida specifiche sull'implementazione del modello Zero Trust per le organizzazioni.

> 💡 **Da ricordare**Zero Trust non è un prodotto da acquistare: è un **principio architetturale**. Si inizia con l'identità (MFA + PAM), poi si segmenta la rete, poi si applica il least privilege. È un percorso, non un interruttore.

### 8. Monitoraggio Continuo e Incident Response

* **SOC** interno o in outsourcing per il monitoraggio 24/7
* **SIEM** (Security Information and Event Management) per la correlazione degli eventi
* Piano di **Incident Response (IR)** specifico per scenari ransomware, testato almeno annualmente
* Procedure chiare per: isolamento sistemi, notifica autorità (CSIRT Italia, Garante Privacy entro 72h), comunicazione stakeholder
* Servizi di **Threat Intelligence** (CrowdStrike, Mandiant, IBM X-Force, Cisco Talos) per anticipare le TTP dei gruppi attivi

### 9. Gestione degli Accessi Privilegiati (PAM)

Gli account amministrativi sono il target primario. Una soluzione **PAM** gestisce, monitora e registra l'uso di questi account, limitando l'esposizione in caso di compromissione. Il principio di **least privilege** applicato ai servizi riduce drasticamente la blast radius di un attacco.

### 10. Business Continuity e Cyber Resilience

Oltre alla prevenzione, le organizzazioni devono pianificare la **business continuity** e il **disaster recovery** in scenari di compromissione totale. I piani devono essere documentati, aggiornati e — soprattutto — testati con esercitazioni pratiche (*tabletop exercises*).

### 11. Cyber Insurance

Una polizza cyber non sostituisce le misure preventive, ma offre una rete di sicurezza finanziaria. Leggere con attenzione le condizioni: molte polizze escludono attacchi classificati come "atti di guerra" (rilevante dopo NotPetya) e richiedono il rispetto di standard minimi di sicurezza.

***

## Domande Frequenti (FAQ)

### Cos'è il ransomware?

Il ransomware è un malware che cifra i file della vittima o blocca l'accesso ai sistemi, richiedendo un riscatto in criptovalute per ripristinare l'accesso. È oggi la minaccia informatica con il maggiore impatto economico globale.

### Come entra il ransomware in un sistema?

I vettori principali sono: email di phishing con allegati o link malevoli (36%), vulnerabilità software non patchate (32%), credenziali rubate su sistemi esposti come RDP (29%), e attacchi alla supply chain tramite software di terze parti (11%).

### Si possono recuperare i file senza pagare il riscatto?

A volte sì: è utile verificare su **No More Ransom** (nomoreransom.org), progetto congiunto di Europol, Interpol e vendor di sicurezza, che mette a disposizione gratuitamente chiavi di decifratura per molte varianti di ransomware note.

### Conviene pagare il riscatto?

No, in generale. Le autorità internazionali — tra cui [CISA](https://www.cisa.gov/ransomware), FBI ed Europol — sconsigliano il pagamento. L'80% delle organizzazioni che pagano subisce un secondo attacco entro 12 mesi, solo il 4% recupera tutti i dati, e il 33% non recupera nulla nemmeno dopo aver pagato.

### Qual è la differenza tra ransomware e wiper?

Il ransomware mira all'estorsione: i dati sono cifrati ma teoricamente recuperabili. Un wiper distrugge i dati in modo permanente. NotPetya (2017) è il caso più noto: si presentava come ransomware ma era un wiper progettato per la distruzione, senza vera infrastruttura di recupero.

### Cosa si intende per double extortion?

Nel modello a doppia estorsione, gli attaccanti esfiltrano i dati *prima* di cifrarli. La vittima è sotto due pressioni: pagare per la chiave di decifratura E pagare per evitare la pubblicazione dei dati rubati su siti di leak nel dark web.

### Cosa sono i gruppi RaaS?

RaaS (Ransomware-as-a-Service) è un modello criminale in cui gli sviluppatori del malware forniscono la piattaforma ad affiliati che conducono gli attacchi. Gli affiliati trattengono il 70-80% del riscatto. Questo ha democratizzato il cybercrime: non serve più saper sviluppare malware per lanciare un attacco ransomware.

### Quali settori sono più a rischio?

Healthcare, manifatturiero, settore pubblico, servizi finanziari e istruzione. La sanità è il settore più costoso per violazione ($11,2M secondo IBM 2025) perché la pressione di ripristinare servizi vitali accelera la decisione di pagare il riscatto.

### Quanto tempo ci vuole per riprendersi da un attacco ransomware?

In media **24 giorni** di downtime operativo (Sophos/Statista 2024). Il recupero completo — incluse indagini forensi, notifiche legali e rafforzamento delle difese — può richiedere mesi. In oltre un terzo dei casi il ripristino supera il mese.

### Cosa fare subito dopo aver scoperto un attacco ransomware?

1. **Isolare** i sistemi infetti dalla rete immediatamente
2. **Non spegnere** i sistemi (possono contenere prove forensi in memoria RAM)
3. **Notificare** il team IR interno o un provider specializzato
4. **Denunciare** al CSIRT Italia (csirt.gov.it) e al CNAIPIC (Polizia Postale)
5. **Non pagare** senza aver esplorato tutte le alternative
6. **Verificare** lo stato dei backup e avviare il recovery da sistemi puliti

***

## Takeaway

|                                  |                                                                                                        |
| -------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **Cos'è**                        | Malware che blocca l'accesso ai dati e chiede riscatto                                                 |
| **Perché è pericoloso**          | Impatto immediato, danno reputazionale, costi di recovery milionari                                    |
| **Come difendersi**              | Backup immutabili, MFA, patch management, EDR, Zero Trust, formazione                                  |
| **Cosa fare in caso di attacco** | Isolare, non spegnere, chiamare il team IR, denunciare alle autorità                                   |
| **Errori da evitare**            | Pagare senza alternative, non testare i backup, ignorare il patch management, non formare il personale |
| **Risorsa italiana**             | CSIRT Italia: csirt.gov.it — No More Ransom: nomoreransom.org                                          |

***

## Glossario

**AES (Advanced Encryption Standard)** — Algoritmo di cifratura simmetrica usato dalla maggior parte dei ransomware moderni. AES-256 è considerato inattaccabile con la forza bruta con le tecnologie attuali.

**Business Continuity** — Insieme di processi e procedure che permettono a un'organizzazione di continuare a operare durante e dopo un incidente grave, incluso un attacco ransomware.

**C2 / Command & Control** — Infrastruttura usata dagli attaccanti per comunicare con il malware installato sui sistemi della vittima e impartire comandi da remoto.

**Cyber Resilience** — Capacità di un'organizzazione di anticipare, resistere, recuperare e adattarsi agli effetti di un cyberattacco, mantenendo la continuità operativa.

**EDR (Endpoint Detection and Response)** — Soluzione di sicurezza che monitora continuamente il comportamento degli endpoint per rilevare, indagare e rispondere a minacce avanzate in tempo reale.

**IAB (Initial Access Broker)** — Operatore criminale specializzato nella compromissione di reti aziendali e nella rivendita dell'accesso ad altri gruppi nel dark web.

**IOC (Indicator of Compromise)** — Evidenza forense che indica che un sistema è stato compromesso. Esempi: hash di file malevoli, indirizzi IP, domini di C2.

**IoA (Indicator of Attack)** — A differenza degli IOC (tracce post-compromissione), gli IoA identificano comportamenti sospetti in corso, permettendo un rilevamento più precoce.

**Lateral Movement** — Fase di un attacco in cui l'attaccante si sposta da un sistema compromesso ad altri nella rete per espandere il controllo e raggiungere target ad alto valore.

**Least Privilege** — Principio di sicurezza secondo cui ogni utente, processo o sistema deve avere solo i permessi strettamente necessari per svolgere il proprio ruolo.

**LotL (Living off the Land)** — Tecnica offensiva in cui gli attaccanti usano strumenti legittimi già presenti nel sistema (PowerShell, WMI, PsExec) per eseguire attività malevole riducendo il rumore.

**MDR (Managed Detection & Response)** — Servizio di sicurezza gestito esternamente che fornisce monitoraggio 24/7, rilevamento delle minacce e risposta agli incidenti per organizzazioni senza SOC interno.

**MITRE ATT\&CK** — Framework sviluppato dalla MITRE Corporation che cataloga tattiche, tecniche e procedure (TTP) usate dagli attaccanti. Standard de facto nel settore per la classificazione degli attacchi.

**PAM (Privileged Access Management)** — Soluzione che gestisce, monitora e registra l'uso degli account con privilegi amministrativi, riducendo il rischio di abuso in caso di compromissione.

**RaaS (Ransomware-as-a-Service)** — Modello di business criminale in cui gli sviluppatori del ransomware affittano la piattaforma ad affiliati che conducono gli attacchi e trattengono il 70-80% del riscatto.

**RSA** — Algoritmo di cifratura asimmetrica usato dai ransomware per proteggere la chiave AES. Senza la chiave privata RSA in possesso degli attaccanti, la decifratura è computazionalmente impossibile.

**SIEM (Security Information and Event Management)** — Piattaforma che raccoglie, correla e analizza log da diversi sistemi per identificare anomalie e potenziali incidenti di sicurezza in tempo reale.

**SOC (Security Operations Center)** — Team dedicato al monitoraggio continuo (24/7) della sicurezza informatica di un'organizzazione, alla gestione degli alert e alla risposta agli incidenti.

**TTP (Tactics, Techniques and Procedures)** — Descrizione del comportamento di un threat actor: le tattiche (obiettivi), le tecniche (metodi) e le procedure (implementazioni specifiche) usate in un attacco.

**XDR (Extended Detection and Response)** — Evoluzione dell'EDR che correla dati di sicurezza da più fonti (endpoint, rete, cloud, email) per una visibilità e risposta integrate agli incidenti.

**Zero Trust** — Modello architetturale di sicurezza basato sul principio "never trust, always verify": nessun utente o sistema è considerato affidabile per default, anche se è già all'interno della rete aziendale.

**Zero-day** — Vulnerabilità software non ancora nota al vendor o per cui non esiste ancora una patch. Particolarmente pericolosa perché non può essere mitigata con aggiornamenti al momento dello sfruttamento.

***

## Fonti Utilizzate

Tutte le statistiche e i dati citati in questo articolo provengono da fonti primarie e rapporti pubblicamente verificabili:

| Fonte                      | Riferimento                                                                                               |
| -------------------------- | --------------------------------------------------------------------------------------------------------- |
| **IBM**                    | [Cost of a Data Breach Report 2024-2025](https://www.ibm.com/reports/data-breach)                         |
| **Sophos**                 | State of Ransomware 2024                                                                                  |
| **Verizon**                | [Data Breach Investigations Report (DBIR) 2025](https://www.verizon.com/business/resources/reports/dbir/) |
| **FBI**                    | IC3 Internet Crime Report 2024                                                                            |
| **ENISA**                  | [Threat Landscape 2024](https://www.enisa.europa.eu/topics/cyber-threats/enisa-threat-landscape)          |
| **Europol**                | IOCTA Report 2024                                                                                         |
| **CISA**                   | [Ransomware Guide](https://www.cisa.gov/ransomware)                                                       |
| **Chainalysis**            | Crypto Crime Report 2025                                                                                  |
| **CrowdStrike**            | Global Threat Report 2025                                                                                 |
| **MITRE**                  | [ATT\&CK Framework](https://attack.mitre.org/)                                                            |
| **NIST**                   | SP 800-207 Zero Trust Architecture                                                                        |
| **Cybersecurity Ventures** | Cybercrime Report 2024                                                                                    |
| **Halcyon**                | Ransomware Ecosystem Report 2024                                                                          |

***

***

## In 30 Secondi

|                            |                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------- |
| **Cos'è**                  | Malware che cifra i tuoi dati e chiede un riscatto in criptovalute              |
| **Come entra**             | Phishing (36%), vulnerabilità non patchate (32%), credenziali rubate (29%)      |
| **Come difendersi**        | Backup immutabili + MFA + patch management + EDR + formazione                   |
| **Cosa fare se colpito**   | Isola i sistemi → chiama il team IR → notifica CSIRT Italia → non pagare subito |
| **Chi chiamare in Italia** | CSIRT Italia: csirt.gov.it — Polizia Postale: CNAIPIC                           |
| **Risorse gratuite**       | No More Ransom: nomoreransom.org                                                |

***

## Conclusione

Il ransomware non è una minaccia destinata a scomparire. I dati del 2024-2026 mostrano un ecosistema criminale in piena espansione: nuovi gruppi, nuove tattiche, bersagli sempre più critici, riscatti sempre più alti e un'integrazione crescente con l'AI generativa che rende gli attacchi più scalabili ed efficaci.

Con danni globali proiettati oltre i **265 miliardi di dollari annui entro il 2031** (Cybersecurity Ventures), comprendere questa minaccia non è più un'opzione — è una necessità strategica.

La prevenzione funziona. La grande maggioranza degli attacchi riusciti sfrutta errori evitabili: patch non applicate, MFA assente, backup mai testati, personale non formato. Non esistono difese perfette, ma esistono difese sufficientemente robuste da rendere un'organizzazione un bersaglio troppo costoso.

**Il ransomware prospera sull'inerzia. La sicurezza prospera sull'azione.**

***

*Articolo aggiornato a giugno 2026. I dati citati derivano esclusivamente da fonti primarie pubblicamente verificabili.*
