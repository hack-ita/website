---
title: 'Penetration Test: Cos''è, Come Funziona e Quanto Costa'
slug: penetration-test
description: 'Penetration Test: tipologie di pentest, le fasi operative e cosa contiene il report. Ecco quando serve e le differenze con vulnerability assessment e red team.'
image: /penetration-test-guida-tipologie-fasi-metodologia.webp
draft: true
date: 2026-11-01T01:10:01.204Z
lastmod: 2026-11-01T01:10:03.912Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - penetration test
  - penetration testing
  - ethical hacking
  - vulnerability assessment
  - pentest
featured: false
---

# Penetration Test: guida a tipologie, fasi e metodologia

Il **penetration test** (o **penetration testing**, in italiano *test di penetrazione*; abbreviato **pentest**) è una simulazione controllata e autorizzata di un attacco informatico, condotta per trovare le vulnerabilità di un sistema prima che lo faccia qualcuno con intenzioni reali. A differenza di una scansione automatica, un pentest è condotto da una persona che ragiona come un attaccante: concatena più debolezze, prova percorsi che uno strumento automatico non considererebbe, e dimostra l'impatto concreto di ciò che trova.

È una delle attività principali dell'[ethical hacking](https://hackita.it/articoli/ethical-hacker/), e spesso è richiesto, direttamente o indirettamente, da normative e contratti: la [direttiva NIS 2](https://hackita.it/articoli/nis2/), per esempio, impone di valutare l'efficacia delle misure di sicurezza adottate senza indicare uno strumento specifico, e il pentest è uno dei modi più concreti per farlo.

## Penetration test in breve

| Domanda                     | Risposta                                                  |
| --------------------------- | --------------------------------------------------------- |
| **Cos'è**                   | Simulazione autorizzata di un attacco informatico         |
| **Obiettivo**               | Identificare e dimostrare vulnerabilità sfruttabili       |
| **Chi lo esegue**           | Penetration tester, team interno o società specializzata  |
| **Cosa testa**              | Network, web, API, cloud, Active Directory, mobile        |
| **Metodo**                  | Analisi manuale, supportata da strumenti automatici       |
| **Output**                  | Report con executive summary, finding, CVSS e remediation |
| **Differenza dal VA**       | Il pentest verifica lo sfruttamento e l'impatto           |
| **Differenza dal red team** | Il red team è più ampio e orientato a un obiettivo        |

## Penetration test cos'è: la differenza con un vulnerability assessment

Questi due termini vengono confusi spesso, ma descrivono attività diverse:

|                    | **Vulnerability Assessment**                              | **Penetration Test**                                           |
| ------------------ | --------------------------------------------------------- | -------------------------------------------------------------- |
| **Obiettivo**      | Trovare e classificare il maggior numero di vulnerabilità | Dimostrare se e come una vulnerabilità è realmente sfruttabile |
| **Metodo**         | Prevalentemente automatizzato (scanner)                   | Analisi manuale, concatenazione di più tecniche                |
| **Output**         | Lista di vulnerabilità con livello di gravità             | Percorso di attacco completo, con impatto dimostrato           |
| **Falsi positivi** | Più frequenti                                             | Ridotti, perché ogni finding è verificato manualmente          |

Un penetration test può includere attività di vulnerability assessment, ma il suo obiettivo va oltre l'identificazione delle vulnerabilità: lo scanner può dirti che una porta è aperta, il pentester ti dimostra cosa un attaccante potrebbe effettivamente fare con quell'accesso.

## I tipi di penetration test per livello di conoscenza

| Tipo          | Conoscenza del sistema                               | Quando si usa                                                          |
| ------------- | ---------------------------------------------------- | ---------------------------------------------------------------------- |
| **Black box** | Nessuna, come un attaccante esterno reale            | Simula un attacco dall'esterno senza informazioni privilegiate         |
| **White box** | Completa: codice sorgente, architettura, credenziali | Massima profondità, utile per sistemi critici o appena sviluppati      |
| **Grey box**  | Parziale, per esempio un account utente standard     | Un compromesso frequente: realistico ma efficiente in termini di tempo |

Il grey box è spesso un buon compromesso: rispecchia uno scenario plausibile (un dipendente malintenzionato, un account compromesso) senza il costo di tempo di un vero black box, che spesso consuma gran parte dell'ingaggio solo nella fase di ricognizione.

## I tipi di penetration test per ambito

| Ambito                              | Cosa si testa                                                                                                                                                        |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Network / infrastruttura**        | Server, firewall, servizi esposti, segmentazione di rete                                                                                                             |
| **Applicazioni web**                | Logica applicativa, autenticazione, input utente, secondo metodologie come la [OWASP Testing Guide](https://hackita.it/articoli/attacchi-applicazioni-web/)          |
| **Active Directory / rete interna** | Percorsi di privilege escalation interni, spesso mappati con strumenti come BloodHound                                                                               |
| **Cloud**                           | Configurazioni di IAM, storage esposto, servizi gestiti                                                                                                              |
| **Mobile**                          | App iOS/Android, comunicazione con i backend                                                                                                                         |
| **Wireless**                        | Reti Wi-Fi aziendali, autenticazione, segmentazione                                                                                                                  |
| **Fisico**                          | Controlli di accesso agli edifici, badge, tailgating                                                                                                                 |
| **Social engineering**              | Resistenza delle persone e dei processi, non solo della tecnologia: ne parliamo nella guida al [social engineering](https://hackita.it/articoli/social-engineering/) |
| **API**                             | Autenticazione, autorizzazione, esposizione eccessiva di dati                                                                                                        |

Un ingaggio reale spesso copre più ambiti insieme: un penetration test "infrastrutturale" che scopre credenziali deboli può facilmente estendersi a un test applicativo o ad Active Directory, se l'obiettivo concordato lo consente.

## Le fasi di un penetration test

La maggior parte dei pentest professionali segue una struttura simile a quella definita da framework come il [PTES](http://www.pentest-standard.org/) (*Penetration Testing Execution Standard*); framework paralleli come la guida tecnica [NIST SP 800-115](https://www.nist.gov/publications/technical-guide-information-security-testing-and-assessment) o la [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) per il web seguono una logica di fondo simile, solo con fasi organizzate sotto nomi diversi.

1. **Pre-engagement**: definizione di obiettivi, perimetro (*scope*), regole di ingaggio e, soprattutto, autorizzazione scritta. Senza questo passaggio, tutto il resto è illegale.
2. **Ricognizione (information gathering)**: raccolta di informazioni sul bersaglio, spesso con tecniche [OSINT](https://hackita.it/articoli/social-engineering/) e strumenti come [Nmap](https://hackita.it/articoli/nmap/) per mappare servizi e porte esposte.
3. **Threat modeling e vulnerability analysis**: identificazione delle debolezze potenziali e priorità in base all'impatto plausibile.
4. **Exploitation**: tentativo di sfruttare le vulnerabilità trovate — quello che il MITRE ATT\&CK classifica come fase di *Initial Access* — per dimostrarne concretamente l'impatto.
5. **Post-exploitation**: una volta ottenuto un accesso, si valuta fin dove un attaccante potrebbe arrivare: le stesse tattiche che ATT\&CK cataloga come *Privilege Escalation*, *Lateral Movement*, *Persistence* ed *Exfiltration* — altri sistemi raggiungibili, dati sensibili esposti, possibilità di persistenza.
6. **Reporting**: il risultato più importante dell'intero test. Un report utile non elenca solo le vulnerabilità, ma assegna a ciascuna un punteggio di gravità secondo uno standard riconosciuto come il [CVSS](https://www.first.org/cvss/) (*Common Vulnerability Scoring System*), spiega l'impatto concreto, il percorso seguito e le azioni di rimedio, con priorità chiare basate su quel punteggio.

Il report è spesso il punto debole dei pentest di bassa qualità: una lista di vulnerabilità senza contesto, CVSS o priorità serve a poco a chi deve decidere cosa correggere per primo.

## Cosa serve prima di iniziare: autorizzazione e regole di ingaggio

Nessun penetration test legittimo inizia senza un documento scritto che autorizzi esplicitamente l'attività, firmato da chi ha davvero l'autorità di farlo (non basta il permesso informale di un singolo dipendente). Questo documento, spesso chiamato *rules of engagement* o *get out of jail card*, definisce:

* quali sistemi sono in perimetro e quali esplicitamente esclusi;
* la finestra temporale dell'ingaggio;
* i contatti di emergenza, in caso qualcosa vada storto (per esempio un servizio di produzione che si blocca);
* cosa è permesso e cosa no (per esempio, se il social engineering sui dipendenti è incluso o escluso).

In Italia, testare un sistema senza questa autorizzazione, anche solo per "controllare se è sicuro", può rientrare nell'accesso abusivo a un sistema informatico (art. 615-ter del codice penale), a prescindere dalle intenzioni di chi lo fa.

## Cosa contiene il report di un penetration test

Il report è ciò che il cliente riceve davvero. Un buon report ha due livelli di lettura: uno per chi decide (rischio e priorità) e uno per chi corregge (dettagli tecnici).

| Sezione                 | Contenuto                                                                             |
| ----------------------- | ------------------------------------------------------------------------------------- |
| **Executive summary**   | Rischio complessivo e conclusioni, in linguaggio non tecnico                          |
| **Scope e metodologia** | Sistemi testati, periodo, approccio (black/grey/white box), framework seguito         |
| **Findings**            | Ogni vulnerabilità trovata, con descrizione e sistema coinvolto                       |
| **Severity**            | Gravità di ogni finding, di solito con punteggio CVSS                                 |
| **Proof of concept**    | Evidenze e passi di riproduzione                                                      |
| **Remediation**         | Come correggere, con priorità                                                         |
| **Retest**              | Verifica successiva che le correzioni abbiano funzionato (spesso un servizio a parte) |

## Quanto costa un penetration test

Non esiste un prezzo unico, e diffida di chi lo dà senza conoscere il perimetro. Il costo dipende soprattutto dal tempo di lavoro necessario (spesso quantificato in giornate/uomo) e quindi da:

* **scope**: numero di IP, applicazioni, endpoint, utenti e ruoli da testare;
* **tipo di test**: un black box richiede in genere più ricognizione di un grey o white box;
* **ambito**: web, rete interna, Active Directory, cloud e mobile hanno complessità diverse;
* **profondità**: solo ricerca delle vulnerabilità o anche exploitation e post-exploitation;
* **reporting**: livello di dettaglio, executive summary, presentazione dei risultati;
* **retest**: incluso o a parte.

## Quanto dura un penetration test

Dipende dalla stessa logica. Come ordine di grandezza, un'applicazione web piccola richiede meno tempo di una rete interna con Active Directory, e un test cloud o un ingaggio con più ambiti insieme richiede più tempo ancora. Alla durata del test vanno aggiunti la preparazione (scoping e autorizzazioni) e la stesura del report, che richiede una parte consistente dell'ingaggio.

## Quando fare un penetration test

* prima del rilascio di una nuova applicazione o di un nuovo servizio esposto su Internet;
* dopo cambiamenti importanti all'infrastruttura o all'architettura;
* dopo una migrazione al cloud o un'acquisizione;
* dopo un incidente di sicurezza, per verificare di aver chiuso davvero le porte usate;
* prima di un audit o di una certificazione;
* periodicamente, secondo il livello di rischio;
* quando lo richiedono norme o contratti.

### Il penetration test è obbligatorio?

Non esiste un obbligo generale per tutte le organizzazioni, ma alcuni contesti lo richiedono. Lo standard PCI DSS (pagamenti con carta) prevede pentest periodici, almeno una volta ogni 12 mesi e dopo modifiche significative. Il regolamento europeo DORA, per le entità finanziarie rientranti nel suo ambito, richiede almeno ogni 3 anni test avanzati basati su minacce reali (*TLPT*, Threat-Led Penetration Testing), salvo diversa indicazione dell'autorità competente. Per NIS 2 vale quanto detto sopra: serve dimostrare l'efficacia delle misure, e il pentest è uno degli strumenti.

## Chi esegue un penetration test

* **Penetration tester interni**: team di sicurezza dell'organizzazione, con il vantaggio di conoscere bene i sistemi.
* **Società specializzate o consulenti esterni**: danno una valutazione indipendente, spesso richiesta da clienti, auditor e normative.
* **Red team**: per gli ingaggi più ampi e orientati a un obiettivo.

La differenza con uno scanner automatico è la persona: lo scanner esegue controlli noti, il tester ragiona sul contesto, concatena le debolezze e valuta l'impatto reale.

## Penetration test, vulnerability assessment, red team: le differenze

|                                                       | Obiettivo                                                                                                                         | Durata tipica    | Approccio                                                              |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ---------------------------------------------------------------------- |
| **Vulnerability assessment**                          | Trovare quante più vulnerabilità possibile                                                                                        | Giorni           | Prevalentemente automatizzato                                          |
| **Penetration test**                                  | Dimostrare l'impatto reale di un percorso di attacco, su un perimetro concordato                                                  | Giorni-settimane | Manuale, focalizzato                                                   |
| **[Red team](https://hackita.it/articoli/red-team/)** | Simulare un attacco realistico completo; in base alle regole d'ingaggio, il team di difesa (*blue team*) può non essere informato | Settimane-mesi   | Obiettivo-centrico, copre più vettori insieme (tecnico, fisico, umano) |

Il penetration test risponde alla domanda "quali vulnerabilità esistono e sono sfruttabili?". Il red team risponde a una domanda diversa: "il mio team di sicurezza si accorgerebbe di un attacco reale, e come risponderebbe?".

## Come riconoscere un buon penetration test

* **Scope chiaro**: un perimetro vago porta a test incompleti o, peggio, a toccare sistemi fuori dall'autorizzazione.
* **Metodologia riconosciuta**: framework come PTES o la guida OWASP per le applicazioni web garantiscono copertura sistematica, non solo una scansione casuale.
* **Verifica manuale**: uno scanner produce falsi positivi; un pentester verifica se una vulnerabilità segnalata è davvero sfruttabile in quel contesto specifico.
* **Proof of concept, non solo teoria**: dimostrare concretamente l'impatto (per esempio un accesso ottenuto, non solo "ipotizzato") rende il report molto più convincente per chi deve stanziare budget per la correzione.
* **Report azionabile**: priorità chiare, passi di riproduzione, raccomandazioni specifiche per ogni finding, non un elenco generico di best practice.

## Come iniziare nel penetration testing

Chi vuole avvicinarsi professionalmente al penetration testing parte in genere da basi solide di reti e sistemi operativi (Linux e Windows), prosegue con la pratica su piattaforme legali come HackTheBox, TryHackMe o VulnLab, usando distribuzioni dedicate come [Kali Linux](https://hackita.it/articoli/kali-linux/), e converge poi verso certificazioni riconosciute dal settore. Una progressione tipica parte da certificazioni entry-level come l'eJPT, passa per l'OSCP (il riferimento più noto per il penetration testing generalista, perché richiede di dimostrare competenze pratiche su macchine reali e non solo teoriche) e, per chi si specializza su ambienti Active Directory, prosegue con certificazioni più verticali come CRTP o CRTO. La parte più sottovalutata da chi inizia è quasi sempre la **metodologia e il reporting**: sapere sfruttare una vulnerabilità conta meno se non si riesce a documentarla in modo chiaro e utile per chi deve poi correggerla.

## Domande frequenti sul penetration test

### Cos'è un penetration test?

Una simulazione controllata e autorizzata di un attacco informatico, condotta per trovare e dimostrare l'impatto reale delle vulnerabilità di un sistema prima che lo faccia un attaccante.

### Qual è la differenza tra penetration test e vulnerability assessment?

Il vulnerability assessment individua e classifica vulnerabilità, spesso in modo automatizzato. Il penetration test verifica manualmente se quelle vulnerabilità sono realmente sfruttabili e ne dimostra l'impatto concreto.

### Cos'è un penetration test black box?

Un test condotto senza nessuna informazione privilegiata sul sistema, simulando un attacco esterno reale.

### Qual è la differenza tra white box e grey box?

Il white box fornisce al tester accesso completo a codice e configurazioni per la massima profondità. Il grey box fornisce informazioni parziali, come un account utente standard, bilanciando realismo e tempo necessario.

### Un penetration test è legale?

Sì, se condotto con un'autorizzazione scritta esplicita da parte di chi ha l'autorità sul sistema. Senza questa autorizzazione, la stessa attività può costituire reato.

### Qual è la differenza tra penetration test e red team?

Il penetration test verifica le vulnerabilità su un perimetro concordato. Il red team simula un attacco realistico completo, orientato a un obiettivo, per testare anche la capacità di rilevamento e risposta; a seconda delle regole d'ingaggio, il team di difesa può non essere avvisato.

### Ogni quanto andrebbe fatto un penetration test?

Dipende dal rischio, ma una pratica diffusa è farlo almeno una volta l'anno e dopo modifiche significative all'infrastruttura o alle applicazioni, oltre che quando richiesto da norme o contratti (per esempio PCI DSS o DORA).

### Quanto costa un penetration test?

Dipende dallo scope, dal tipo di test (black, grey o white box), dall'ambito (web, rete, Active Directory, cloud), dalla profondità e dal reporting. Il costo riflette soprattutto le giornate di lavoro necessarie: nessun prezzo serio si dà senza aver definito il perimetro.

### Quanto dura un penetration test?

Da pochi giorni a diverse settimane, in base al perimetro e alla complessità, più il tempo di preparazione e di stesura del report.

### Il penetration test è obbligatorio?

Non in generale, ma può esserlo per contesto: PCI DSS lo prevede almeno ogni 12 mesi, DORA richiede test TLPT almeno ogni 3 anni per le entità finanziarie interessate, e NIS 2 richiede di valutare l'efficacia delle misure di sicurezza.

### Cosa contiene il report di un penetration test?

Executive summary, scope e metodologia, elenco dei finding con gravità (spesso CVSS), proof of concept, indicazioni di remediation e, se previsto, il retest.

### Come si diventa penetration tester?

Con basi solide di reti e sistemi operativi, pratica su piattaforme legali come HackTheBox o TryHackMe, e certificazioni riconosciute dal settore come l'OSCP, che testano competenze pratiche concrete.
