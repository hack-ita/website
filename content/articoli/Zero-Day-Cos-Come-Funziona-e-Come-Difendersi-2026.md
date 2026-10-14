---
title: 'Zero-Day: Cos''è, Come Funziona e Come Difendersi (2026)'
slug: zero-day
description: >-
  Cos'è un'attacco zero-day? Scopri cosa significa vulnerabilità zero-day,
  exploit , le differenze con n-day e CVE, esempi reali e come difenderti nel
  2026.
image: /zero-day-vulnerability-exploit-cybersecurity.webp
draft: false
date: 2026-10-09T23:26:17.707Z
lastmod: 2026-10-09T23:26:20.697Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Zero-Day
  - 0-Day
  - Vulnerabilità Zero-Day
  - Zero-Day Exploit
  - Ricerca di Vulnerabilità
---

# Zero-Day: Cos'è una Vulnerabilità 0-Day

Uno **zero day** (o **zero-day**, anche scritto **0day**) non è un semplice attacco, è particolare vulnerabilità di sicurezza sfruttata dagli attaccanti prima che il produttore del software abbia rilasciato una patch. Il nome viene dal fatto che chi deve difendersi ha avuto **zero giorni** per prepararsi: il problema è già in mano a qualcuno e non esiste ancora una correzione ufficiale.

Gli zero-day sono rari rispetto alle vulnerabilità note, ma sono tra gli strumenti più preziosi per spionaggio, ransomware e spyware. Nel 2025 il Google Threat Intelligence Group ne ha tracciati **90** sfruttati attivamente, quasi la metà contro tecnologie aziendali.

## Zero day significato: perché si chiama così

"Zero day" indica il tempo a disposizione dei difensori tra il momento in cui la vulnerabilità viene sfruttata o resa pubblica e il momento in cui esiste una patch: **zero giorni**.

Esempio semplice: immagina una serratura con un difetto che solo un ladro conosce. Il produttore non sa che esiste, quindi non c'è nessun aggiornamento. Il ladro entra in tutte le case con quella serratura finché qualcuno si accorge del problema. Quella è la finestra zero-day.

Le definizioni cambiano leggermente. Per Google, uno zero-day è una vulnerabilità sfruttata in modo malevolo **prima** che esista una patch pubblica. In altri contesti si usa il termine anche per vulnerabilità non ancora note al produttore. In pratica il concetto è lo stesso: **nessuna correzione disponibile**.

## Zero-Day, exploit e attacco zero-day: differenze

Questi tre termini vengono confusi di continuo:

| Termine                    | Cosa significa                                               |
| -------------------------- | ------------------------------------------------------------ |
| **Vulnerabilità zero-day** | Il difetto nel software o nell'hardware, non ancora corretto |
| **Exploit zero-day**       | Il codice o la tecnica che sfrutta quel difetto              |
| **Attacco zero-day**       | L'uso concreto dell'exploit contro un bersaglio reale        |

Una vulnerabilità può esistere per anni senza che nessuno la sfrutti. Diventa un problema vero quando qualcuno sviluppa un exploit e lo usa.

## Come funziona un attacco zero-day

Il ciclo di vita tipico è questo:

| Fase                         | Cosa succede                                                                    |
| ---------------------------- | ------------------------------------------------------------------------------- |
| **1. Il difetto nasce**      | Un bug entra nel codice, spesso anni prima di essere trovato                    |
| **2. Qualcuno lo scopre**    | Un ricercatore, un attaccante o un broker trova la vulnerabilità                |
| **3. Nasce l'exploit**       | Viene scritto il codice per sfruttarla in modo affidabile                       |
| **4. Sfruttamento**          | L'exploit viene usato contro bersagli reali, spesso in modo mirato e silenzioso |
| **5. Scoperta dell'attacco** | Un difensore, un vendor o un ricercatore nota l'attività anomala                |
| **6. Patch**                 | Il produttore rilascia la correzione                                            |
| **7. Diventa n-day**         | La vulnerabilità è nota e corretta, ma chi non aggiorna resta esposto           |

Il punto cruciale è la fase 4: l'attacco avviene **prima** che i sistemi di difesa tradizionali, che si basano su firme di minacce già note, abbiano qualcosa da riconoscere.

In una [Cyber Kill Chain](/articoli/cyber-kill-chain/) lo zero-day viene usato in genere nelle fasi di sfruttamento e installazione: è il modo per entrare, ottenere esecuzione di codice o scalare i privilegi senza essere notati.

## Zero-Day vs N-Day: qual è la differenza?

Un **n-day** è una vulnerabilità già nota e per cui esiste una patch, ma che non è stata ancora applicata. La differenza pratica è enorme:

* contro uno **zero-day** non puoi aggiornare, perché la patch non c'è;
* contro un **n-day** la difesa esiste, e si chiama aggiornamento.

Molti attacchi reali sfruttano proprio vulnerabilità note e non corrette. Per questo una buona gestione delle patch è spesso più efficace di qualsiasi strumento "anti zero-day".

## Chi scopre e usa gli zero-day

Intorno agli zero-day esiste un vero mercato, legale e illegale:

* **Ricercatori di sicurezza**: li trovano e li segnalano al produttore (*responsible disclosure*), spesso tramite programmi di bug bounty.
* **Produttori**: i team interni dei vendor cercano e correggono bug.
* **Broker e aziende di sorveglianza commerciale**: comprano o sviluppano exploit e li vendono a governi o clienti.
* **Gruppi statali di spionaggio**: li usano per operazioni mirate.
* **Gruppi criminali**: li usano per estorsioni e ransomware, anche se più raramente.

I dati del report Google 2025 mostrano come è cambiato il quadro:

| Dato 2025                                   | Valore                             |
| ------------------------------------------- | ---------------------------------- |
| Zero-day sfruttati in the wild              | **90** (78 nel 2024, 100 nel 2023) |
| Contro tecnologie enterprise                | **43**, il 48%: massimo storico    |
| Contro sistemi operativi                    | **39**, il 44%                     |
| Contro browser                              | meno del 10%                       |
| Zero-day su dispositivi mobili              | **15** (9 nel 2024)                |
| Zero-day usati da gruppi con fini economici | **9**                              |

Su 42 zero-day attribuiti a un attore specifico, **15** erano di aziende di sorveglianza commerciale e **12** di gruppi statali: per la prima volta le prime hanno superato i secondi. Tradotto: strumenti che una volta erano roba da intelligence ora si comprano.

Il trend più importante per chi difende è un altro: gli attaccanti si spostano verso **dispositivi di bordo e prodotti aziendali** (firewall, VPN, router, appliance di sicurezza), che spesso non hanno un EDR installato e dove un'intrusione può restare nascosta a lungo. Il report completo è sul [blog di Google Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/2025-zero-day-review).

## Zero-day famosi: esempi reali

| Caso                                         | Anno | Cosa è successo                                                                                                                                         |
| -------------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Stuxnet**                                  | 2010 | Malware contro impianti nucleari iraniani, che sfruttava più zero-day Windows (di solito si citano quattro)                                             |
| **FORCEDENTRY** (CVE-2021-30860)             | 2021 | Exploit *zero-click* su iMessage usato dallo spyware Pegasus di NSO Group, scoperto da Citizen Lab                                                      |
| **Log4Shell** (CVE-2021-44228)               | 2021 | Vulnerabilità RCE in Apache Log4j, sfruttata su larga scala a pochi giorni dalla divulgazione                                                           |
| **MOVEit Transfer** (CVE-2023-34362)         | 2023 | [SQL injection](/articoli/sql-injection/) sfruttata dal gruppo Cl0p per rubare dati da centinaia di organizzazioni, prima della patch |
| **Oracle E-Business Suite** (CVE-2025-61882) | 2025 | Zero-day sfruttato contro clienti Oracle in campagne di estorsione legate a Cl0p                                                                        |

Nota che gli esempi recenti sono quasi tutti **software aziendale esposto su Internet**, non il classico PC di casa.

## Zero-Day nel 2026: casi recenti

*Aggiornato al 3 ottobre 2026.* Due casi di settembre mostrano come funzionano oggi:

* **Chrome**: il 3 settembre 2026 Google ha rilasciato una patch d'emergenza per **CVE-2026-85046**, un type confusion nel motore V8 sfruttato attivamente. È il sesto zero-day di Chrome del 2026 e il giorno dopo la CISA l'ha aggiunto al catalogo KEV.
* **Windows**: il Patch Tuesday dell'8 settembre 2026 ha corretto due zero-day sfruttati in the wild, **CVE-2026-85880** (Windows ALPC) e **CVE-2026-81963** (Windows Update Stack), entrambi di *privilege escalation* locale fino a SYSTEM. Sono il tipo di bug che un attaccante usa **dopo** essere entrato, per prendere il controllo totale della macchina (vedi [privilege escalation su Windows](/articoli/privilege-escalation-windows/)).

Il filo comune: componenti molto diffusi, patch d'emergenza fuori ciclo e inserimento rapido nel catalogo KEV. I dettagli cambiano ogni settimana: controlla sempre le fonti ufficiali dei vendor.

## Zero-Day e CVE: qual è la differenza?

Una **CVE** (*Common Vulnerabilities and Exposures*) è un identificativo pubblico univoco assegnato a una vulnerabilità, nel formato CVE-ANNO-NUMERO. Una vulnerabilità può essere sfruttata come zero-day e ricevere una CVE **dopo**, quando viene analizzata e corretta. Ma avere una CVE **non significa** che sia stata uno zero-day: la grande maggioranza delle CVE riguarda vulnerabilità trovate e corrette senza essere mai sfruttate prima della patch.

Per sapere se una CVE è stata sfruttata attivamente, si controlla il catalogo KEV della CISA, che vedi più sotto.

## Come difendersi da un attacco zero-day: patch, mitigazione e rilevamento

Non puoi bloccare una vulnerabilità che nessuno conosce, ma puoi **ridurre la probabilità che venga sfruttata e limitare i danni** se succede. La sequenza è: **mitigazione** subito (se il vendor la indica), **patch** appena esce, **controlli compensativi** nel frattempo (segmentazione, WAF, privilegi minimi) e **rilevamento** continuo per accorgersi di un'intrusione.

| Misura                                  | Perché aiuta                                                                               |
| --------------------------------------- | ------------------------------------------------------------------------------------------ |
| **Ridurre la superficie d'attacco**     | Meno servizi esposti, meno bersagli. Se non serve su Internet, non va su Internet          |
| **Patch rapide**                        | Quando lo zero-day diventa n-day, la finestra di rischio si chiude solo se aggiorni subito |
| **Dare priorità al catalogo KEV**       | Le vulnerabilità già sfruttate vanno corrette prima delle altre                            |
| **Segmentazione di rete**               | Un'intrusione non deve poter raggiungere tutto                                             |
| **Privilegi minimi**                    | Meno privilegi ha un account compromesso, meno danni fa                                    |
| **EDR e monitoraggio**                  | Rilevano comportamenti anomali anche senza una firma nota                                  |
| **Protezione dei dispositivi di bordo** | Log, aggiornamenti e monitoraggio anche per firewall, VPN e appliance                      |
| **WAF e virtual patching**              | Mitigano un exploit a livello di rete mentre aspetti la patch                              |
| **Backup testati e isolati**            | Se arriva un ransomware, puoi ripartire                                                    |
| **Piano di incident response**          | Sapere chi fa cosa, e quando, riduce i tempi di reazione                                   |

Un antivirus tradizionale basato solo su firme non fermerà uno zero-day mai visto prima. Le soluzioni che osservano il comportamento di processi e file hanno più possibilità, ma non sono infallibili.

### Due controlli pratici

Il catalogo **KEV** della CISA elenca le vulnerabilità di cui è confermato lo sfruttamento attivo. Puoi scaricarlo e guardare le ultime aggiunte da terminale:

```bash
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
| jq -r '.vulnerabilities | sort_by(.dateAdded) | reverse | .[:10][] | "\(.dateAdded)  \(.cveID)  \(.vendorProject) \(.product)"'
```

Poi controlla se i tuoi sistemi sono aggiornati. Su Windows (PowerShell), ultime patch installate:

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
```

Su Debian/Ubuntu, aggiornamenti pendenti:

```bash
apt list --upgradable
```

Per vedere cosa hai esposto su Internet, come farebbe un attaccante, puoi partire da [Shodan](/articoli/shodan/). Se un servizio con una vulnerabilità nota è raggiungibile da fuori, qualcuno lo troverà.

## Zero-day e sicurezza offensiva

Chi fa red team o penetration test lavora in genere con vulnerabilità note: un pentest serve a trovare configurazioni sbagliate, patch mancanti e percorsi di attacco, non a scoprire zero-day. Strumenti come [Metasploit](/articoli/metasploit/) raccolgono exploit per vulnerabilità già pubbliche.

La ricerca di zero-day è un'attività diversa, chiamata *vulnerability research*: analisi del codice, reverse engineering, fuzzing. Quando qualcuno ne trova uno in modo legittimo, la prassi è la **divulgazione responsabile**: segnalare al produttore e concedere un tempo ragionevole per correggere prima di pubblicare i dettagli (molti team usano un termine di circa 90 giorni).

Dal punto di vista normativo, una buona gestione delle vulnerabilità e dei tempi di patching è un requisito concreto della [direttiva NIS 2](/articoli/nis2/) e rientra nelle misure di sicurezza dell'[articolo 32 del GDPR](/articoli/gdpr/).

## Domande frequenti sugli zero-day

### Cos'è uno zero-day?

Una vulnerabilità sfruttata dagli attaccanti prima che il produttore abbia rilasciato una patch. Il nome indica che i difensori hanno avuto zero giorni per prepararsi.

### Perché si chiama zero day?

Perché il tempo tra la scoperta dell'attacco o della falla e la disponibilità di una correzione è zero: non esiste ancora una patch.

### Cos'è un attacco zero-day?

È l'uso di un exploit contro una vulnerabilità non ancora corretta. Spesso è mirato e silenzioso, e può restare inosservato per molto tempo.

### Qual è la differenza tra zero-day e n-day?

Lo zero-day non ha ancora una patch. L'n-day è una vulnerabilità nota e già corretta, ma non ancora applicata sui sistemi vulnerabili.

### Si può prevenire uno zero-day?

Non puoi prevenire una vulnerabilità che nessuno conosce, ma puoi ridurre il rischio con meno superficie esposta, segmentazione, privilegi minimi, monitoraggio e patch rapide appena il fix esce.

### Un antivirus ferma gli zero-day?

Non quelli basati solo su firme, perché non ha nulla da riconoscere. Gli strumenti che analizzano il comportamento (EDR) hanno più possibilità, ma non garantiscono una protezione totale.

### Chi usa gli zero-day?

Gruppi statali di spionaggio, aziende di sorveglianza commerciale e, più raramente, gruppi criminali. Nel 2025 le aziende di sorveglianza hanno superato per la prima volta i gruppi statali tra gli zero-day attribuiti.

### Quanti zero-day vengono sfruttati ogni anno?

Secondo Google ne sono stati tracciati 90 nel 2025, 78 nel 2024 e 100 nel 2023.

### Cos'è una CVE?

Un identificativo pubblico univoco di una vulnerabilità nota, nel formato CVE-ANNO-NUMERO. Non tutte le CVE sono zero-day: lo sono solo quelle sfruttate prima che esistesse la patch.

### Cos'è il catalogo KEV della CISA?

L'elenco delle vulnerabilità di cui è confermato lo sfruttamento attivo. Si trova sul sito della [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) ed è un buon criterio per decidere cosa correggere per primo.
