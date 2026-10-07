---
title: 'Data Breach: Cos''è, Significato, Esempi e Cosa Fare (2026)'
slug: data-breach
description: 'Data breach, come funziona e cos''è una violazione dei dati, cause, esempi reali, regola delle 72 ore, costi 2026 e cosa fare se i tuoi dati vengono rubati.'
image: /data-breach-violazione-dati-personali.webp
draft: true
date: 2026-10-10T23:30:43.326Z
lastmod: 2026-10-10T23:30:54.768Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Data Breach
  - Violazione dei Dati
  - Data Leak
  - GDPR
  - Protezione dei Dati
---

# Data Breach: Cos'è una Violazione dei Dati e Cosa Fare

Un **data breach** è una violazione dei dati personali che compromette la riservatezza, l'integrità o la disponibilità dei dati, accidentalmente o in modo illecito. Può colpire un'azienda, un ente pubblico o una singola persona, per un attacco informatico oppure per un errore. In Europa può far scattare obblighi di notifica: quando c'è un rischio per i diritti e le libertà delle persone, il titolare deve avvisare il Garante Privacy senza ingiustificato ritardo e, ove possibile, **entro 72 ore** dalla conoscenza dell'evento; i soggetti NIS2 hanno anche una **pre-notifica entro 24 ore**.

Secondo l'IBM Cost of a Data Breach Report 2026, un data breach costa in media **4,99 milioni di dollari** a livello globale, il valore più alto mai registrato.

## Data breach significato: cosa vuol dire

*Data breach* si traduce letteralmente "violazione dei dati". Il GDPR lo definisce come una violazione di sicurezza che comporta, **accidentalmente o in modo illecito**, la distruzione, la perdita, la modifica, la divulgazione non autorizzata o l'accesso a dati personali.

La parola "accidentalmente" è importante: non serve un hacker. Un'email con dati dei clienti inviata al destinatario sbagliato, un laptop smarrito o un database lasciato aperto per errore sono tutti data breach.

### Data breach, data leak e attacco informatico: le differenze

| Termine                 | Cosa significa                                                                                                                                              |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Data breach**         | La violazione di sicurezza che compromette i dati, per errore o per attacco                                                                                 |
| **Data leak**           | Esposizione o divulgazione di dati senza autorizzazione. Può derivare da una configurazione errata, da una condivisione accidentale o da un'azione malevola |
| **Attacco informatico** | L'azione ostile, ad esempio un ransomware o un'intrusione. Può causare un data breach, ma non sempre lo fa                                                  |

In pratica: l'attacco è il mezzo, il data breach è la conseguenza sui dati.

## Tipi di data breach: riservatezza, integrità e disponibilità

La sicurezza dei dati si basa su tre proprietà (la cosiddetta *triade CIA*), e un singolo breach può violarne una o più:

| Tipo              | Cosa succede                                   | Esempio                                                     |
| ----------------- | ---------------------------------------------- | ----------------------------------------------------------- |
| **Riservatezza**  | Qualcuno vede o copia dati che non dovrebbe    | Furto di un database clienti                                |
| **Integrità**     | I dati vengono modificati senza autorizzazione | Un attaccante cambia gli IBAN di fornitori in un gestionale |
| **Disponibilità** | I dati diventano inaccessibili o vengono persi | Ransomware che cifra i server, backup distrutto             |

Molti incidenti reali toccano più tipi insieme: il ransomware moderno, per esempio, cifra i dati (disponibilità) **e** li copia prima (riservatezza) per minacciare la pubblicazione.

## Cause di un data breach: come avviene una violazione

| Causa                                                 | Come porta a un breach                                                                                                             |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **[Phishing](/articoli/phishing/)** | Un dipendente consegna le credenziali o installa un malware                                                                        |
| **Credenziali rubate o riutilizzate**                 | Attacchi come il [credential stuffing](/articoli/credential-stuffing/) provano le stesse password su più servizi |
| **Vulnerabilità non corrette**                        | Una falla nota (n-day) o uno [zero-day](/articoli/zero-day/) su un servizio esposto                              |
| **Applicazioni web vulnerabili**                      | Una [SQL injection](/articoli/sql-injection/) permette di leggere l'intero database                              |
| **Configurazioni errate**                             | Database, bucket cloud o [backup esposti sul web](/articoli/backup-exposure/) senza autenticazione               |
| **Insider**                                           | Un dipendente accede senza motivo a dati che non gli servono                                                                       |
| **Supply chain**                                      | Si compromette un fornitore per arrivare ai suoi clienti                                                                           |
| **Ransomware con doppia estorsione**                  | I dati vengono copiati e poi cifrati                                                                                               |
| **Perdita o furto di dispositivi**                    | Un portatile non cifrato finisce in mani sbagliate                                                                                 |

### Data breach e ransomware

Il ransomware moderno usa la **doppia estorsione**: prima l'attaccante copia i dati (esfiltrazione), poi cifra i sistemi. Anche se ripristini dai backup, i dati sono già fuori e possono essere pubblicati o venduti. Per questo un attacco ransomware è quasi sempre anche un data breach, con gli obblighi di notifica che ne derivano.

Nel report IBM 2026 la compromissione della supply chain risulta il secondo vettore iniziale più frequente e, insieme ad altri, tra quelli con il ciclo di vita più lungo: circa 258 giorni per identificarla e contenerla.

## Come avviene un data breach, passo per passo

Un'intrusione che porta a un breach segue spesso una sequenza simile a quella della [Cyber Kill Chain](/articoli/cyber-kill-chain/):

1. **Accesso iniziale**: phishing, credenziali rubate, vulnerabilità di un servizio esposto.
2. **Consolidamento e [privilege escalation](/articoli/privilege-escalation-windows/)**: l'attaccante ottiene privilegi più alti.
3. **[Movimento laterale](/articoli/lateral-movement/)**: si sposta verso i sistemi che contengono i dati interessanti.
4. **Raccolta ed esfiltrazione**: i dati vengono copiati verso l'esterno.
5. **Scoperta**: qualcuno nota qualcosa, oppure l'attaccante rivendica o vende i dati.

Il problema è il tempo: secondo IBM servono in media **247 giorni** per identificare e contenere un data breach. Quasi otto mesi in cui l'attaccante può restare dentro.

## Quali dati possono essere coinvolti in un data breach?

Qualsiasi dato personale o riservato può finire in un breach. I più colpiti:

* **email e password**, spesso rivendute o riusate per altri attacchi;
* **numeri di telefono e dati anagrafici**;
* **documenti d'identità**;
* **dati finanziari**: carte, IBAN, conti;
* **dati sanitari**, tra i più delicati e costosi;
* **dati aziendali riservati**: contratti, codice sorgente, listini;
* **token e credenziali tecniche**: chiavi API, cookie di sessione;
* **identificativi online**: indirizzi IP, ID dispositivo.

Un attaccante raramente vuole "un dato": vuole accessi e informazioni che può trasformare in denaro, estorsione o nuovi attacchi, come il phishing mirato con i dati rubati.

## Data breach famosi: esempi reali

| Caso                | Anno      | Cosa è successo                                                                                                                                                                        |
| ------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Yahoo**           | 2013      | Compromessi circa 3 miliardi di account, resi noti tra il 2016 e il 2017                                                                                                               |
| **Equifax**         | 2017      | Rubati i dati di circa 147 milioni di persone sfruttando una vulnerabilità di Apache Struts (CVE-2017-5638) per cui la patch esisteva già                                              |
| **Capital One**     | 2019      | Una [SSRF](/articoli/ssrf/) combinata con una configurazione errata ha permesso di accedere ai dati di circa 100 milioni di clienti negli Stati Uniti                |
| **MOVEit Transfer** | 2023      | Una SQL injection (CVE-2023-34362) sfruttata dal gruppo Cl0p ha colpito centinaia di organizzazioni                                                                                    |
| **Intesa Sanpaolo** | 2022-2024 | Un dipendente ha consultato senza giustificato motivo i dati di 3.573 clienti, con oltre 6.600 accessi. Il Garante ha sanzionato la banca con **31,8 milioni di euro** (30 marzo 2026) |

Il caso Intesa è istruttivo per due motivi: l'attacco non è venuto da fuori e, secondo il Garante, i sistemi di controllo interni **non hanno rilevato** gli accessi per oltre due anni. La sanzione ha riguardato sia le carenze di monitoraggio sia la gestione del data breach.

## Quanto costa un data breach

I dati dell'IBM Cost of a Data Breach Report 2026, pubblicato il 29 luglio 2026 su 602 organizzazioni, danno un'idea dell'impatto (puoi leggere una [sintesi su Infosecurity Magazine](https://www.infosecurity-magazine.com/news/cost-of-a-data-breach-5m-ibm/)):

| Dato                                           | Valore                                              |
| ---------------------------------------------- | --------------------------------------------------- |
| Costo medio globale                            | **4,99 milioni di dollari** (+12% rispetto al 2025) |
| Costo medio negli Stati Uniti                  | 11,5 milioni di dollari                             |
| Tempo medio per identificare e contenere       | 247 giorni                                          |
| Costo medio con ciclo di vita oltre 200 giorni | 5,65 milioni                                        |
| Costo medio con ciclo di vita sotto 200 giorni | 4,32 milioni                                        |

Il messaggio pratico: **ogni giorno in più** in cui un breach resta attivo costa di più. Rilevare presto vale denaro.

I costi non sono solo tecnici: ci sono perdita di clienti, indagini, consulenze legali, notifiche, sanzioni e danni di reputazione.

## Cosa fare se la tua azienda subisce un data breach

Una sequenza pratica, da adattare al caso:

| Passo                            | Cosa fare                                                                                                                            |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **1. Contenere**                 | Isola i sistemi coinvolti, blocca gli account compromessi, interrompi l'esfiltrazione                                                |
| **2. Preservare le evidenze**    | Salva log, immagini dei sistemi e tracce prima di "ripulire" tutto                                                                   |
| **3. Valutare**                  | Quali dati, quante persone, che rischio per loro, da quando                                                                          |
| **4. Notificare**                | Garante Privacy entro **72 ore** se c'è rischio per le persone. Se rientri nella NIS2, pre-notifica entro **24 ore** al CSIRT Italia |
| **5. Informare gli interessati** | Senza ingiustificato ritardo se il rischio per loro è elevato                                                                        |
| **6. Documentare**               | Registro delle violazioni: vanno annotate anche quelle non notificate                                                                |
| **7. Rimediare e imparare**      | Correggere la causa, aggiornare le procedure, fare un'analisi post-incidente                                                         |

**Non ogni data breach va notificato al Garante**: la notifica serve quando la violazione può comportare un rischio per i diritti e le libertà delle persone. Se il rischio è improbabile non c'è obbligo di notifica, ma la violazione va comunque documentata nel registro. Le regole complete sono nella guida al [GDPR](/articoli/gdpr/) e nella guida alla [direttiva NIS 2](/articoli/nis2/). Il punto più critico è il tempo: il conteggio parte da quando **vieni a conoscenza** della violazione, e per questo servono procedure scritte e ruoli chiari prima che succeda.

## Data breach: cosa fare se i tuoi dati sono stati violati

Se sei una persona e ricevi un avviso di breach (o lo scopri da notizie o da un servizio di controllo):

1. **Cambia la password** del servizio coinvolto e di tutti gli altri account dove la usavi. Usa password diverse per ogni servizio, con un password manager.
2. **Attiva l'autenticazione a più fattori** su email, banca e social.
3. **Controlla se i tuoi dati sono nei database violati noti**, ad esempio su [Have I Been Pwned](https://haveibeenpwned.com/).
4. **Stai attento al phishing**: dopo un breach arrivano email e SMS che sembrano legittimi e usano i dati rubati.
5. **Se sono finiti dati finanziari**, contatta la banca e blocca le carte; se documenti d'identità, valuta una denuncia alla Polizia Postale.
6. **Puoi fare reclamo al Garante Privacy** se ritieni che i tuoi dati non siano stati protetti o gestiti correttamente.

### Verifica una password senza inviarla a nessuno

Have I Been Pwned offre un'API che permette di controllare se una password è comparsa in un breach **senza trasmetterla**: si invia solo il prefisso di 5 caratteri del suo hash SHA-1 (principio di *k-anonymity*) e il confronto avviene in locale. Su Linux:

```bash
read -rs -p "Password: " P; echo
HASH=$(printf '%s' "$P" | sha1sum | awk '{print toupper($1)}')
curl -s "https://api.pwnedpasswords.com/range/${HASH:0:5}" | grep "${HASH:5}"
```

Se compare una riga, il numero dopo i due punti indica quante volte quella password è stata vista nei breach: **non usarla più**. Il `read -s` evita che la password finisca nella cronologia della shell.

## Come prevenire un data breach

Nessuna misura azzera il rischio, ma queste riducono molto probabilità e danni:

| Misura                                                  | Perché aiuta                                                                                |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| **MFA** su accessi remoti, email e account privilegiati | Una password rubata da sola non basta                                                       |
| **Patch rapide**                                        | Chiude le vulnerabilità note prima che vengano sfruttate                                    |
| **Minimizzazione dei dati**                             | Dati che non hai non possono essere rubati                                                  |
| **Cifratura** di dischi, database e backup              | Un furto non diventa automaticamente un breach leggibile                                    |
| **Privilegi minimi**                                    | Ognuno accede solo a ciò che gli serve davvero                                              |
| **Logging e monitoraggio**                              | Accessi anomali, come quelli del caso Intesa, vengono notati prima                          |
| **Segmentazione di rete**                               | Un'intrusione non raggiunge tutto                                                           |
| **Backup isolati e testati**                            | Il ransomware non diventa una perdita definitiva                                            |
| **Controllo dei fornitori**                             | La supply chain è un vettore reale                                                          |
| **Formazione contro phishing**                          | Il fattore umano è ancora tra i punti d'ingresso più comuni                                 |
| **Test di sicurezza periodici**                         | Trovi i problemi prima di un attaccante                                                     |
| **DLP** (*Data Loss Prevention*)                        | Strumenti che rilevano e bloccano l'uscita di dati sensibili, utili contro errori e insider |

## Data breach GDPR e NIS2: la regola delle 72 ore e cosa cambia

In Europa il data breach è regolato dal [GDPR](/articoli/gdpr/) (artt. 33 e 34) e, per i settori critici, dalla [NIS2](/articoli/nis2/):

|                     | **GDPR**                     | **NIS2**                             |
| ------------------- | ---------------------------- | ------------------------------------ |
| **Cosa si segnala** | Violazione di dati personali | Incidente significativo              |
| **A chi**           | Garante Privacy              | CSIRT Italia / ACN                   |
| **Tempi**           | 72 ore                       | Pre-notifica 24 ore, notifica 72 ore |

Dal punto di vista penale, in Italia il trattamento illecito di dati personali e l'accesso abusivo a un sistema informatico possono costituire reato, oltre alle sanzioni amministrative del Garante (fino a 10 o 20 milioni di euro, in base alla violazione).

## Domande frequenti sul data breach

### Cos'è un data breach in parole semplici?

È quando dei dati finiscono a persone che non dovrebbero vederli, o vengono persi o alterati, per un attacco o per un errore.

### Quali dati possono essere coinvolti in un data breach?

Email e password, dati anagrafici, documenti, dati finanziari e sanitari, dati aziendali riservati, credenziali tecniche e identificativi online.

### Un data breach va sempre notificato al Garante?

No. Va notificato quando presenta un rischio per i diritti e le libertà delle persone. Le violazioni che non raggiungono questa soglia non vanno notificate, ma devono comunque essere documentate.

### Cos'è un data breach?

Una violazione di sicurezza che porta alla perdita, alla modifica, alla divulgazione o all'accesso non autorizzato a dati, per attacco informatico o per errore. In italiano si dice violazione dei dati personali.

### Qual è la differenza tra data breach e data leak?

Il data breach è la violazione di sicurezza in senso ampio. Il data leak è la fuoriuscita di dati, spesso per un errore di configurazione, senza un'intrusione vera e propria.

### Quali sono le cause più comuni di un data breach?

Phishing, credenziali rubate o riutilizzate, vulnerabilità non corrette, configurazioni errate, accessi di insider, compromissione dei fornitori e ransomware.

### Entro quanto va notificato un data breach?

Senza ingiustificato ritardo e, ove possibile, entro 72 ore da quando se ne ha conoscenza, se la violazione può comportare un rischio per le persone. Per i soggetti NIS2 serve anche una pre-notifica entro 24 ore al CSIRT Italia.

### Quanto costa un data breach?

Secondo IBM 2026 il costo medio globale è di 4,99 milioni di dollari, con una media di 247 giorni per identificare e contenere la violazione.

### Cosa fare se i miei dati sono stati violati?

Cambia le password, attiva l'MFA, controlla i servizi di verifica dei breach, fai attenzione ai tentativi di phishing e, se necessario, contatta banca e autorità.

### Un'email inviata alla persona sbagliata è un data breach?

Sì, se contiene dati personali: il GDPR include anche le violazioni accidentali. Va valutato il rischio per gli interessati per decidere se notificare.

### Come faccio a sapere se i miei dati sono in un data breach?

Puoi usare servizi come Have I Been Pwned, che segnalano se la tua email compare in violazioni note. Non serve fornire la password.

### Un data breach è sempre colpa di un attacco hacker?

No. Può nascere da errori umani, configurazioni sbagliate o accessi interni illeciti. Il caso Intesa Sanpaolo, per esempio, riguardava un dipendente.

### Si può prevenire un data breach?

Non del tutto, ma si riducono molto rischio e impatto con MFA, patch rapide, cifratura, privilegi minimi, monitoraggio e formazione.
