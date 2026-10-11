---
title: 'SEO Poisoning: Cos''È, Come Funziona e Come Difendersi'
slug: seo-poisoning
description: 'SEO poisoning (avvelenamento SEO): malware, cloaking e Gootloader portano pagine false in cima a Google. Riconoscile e controlla se il tuo sito è compromesso.'
image: /seo-poisoning-risultati-google-malevoli.webp
draft: true
date: 2026-10-12T18:20:08.001Z
lastmod: 2026-10-12T18:20:05.283Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - SEO Poisoning
  - SEO poisoning malware
  - risultati Google malevoli
  - cloaking
---

# SEO Poisoning: come riconoscere i risultati Google malevoli e difendersi

La **SEO poisoning** (in italiano "avvelenamento SEO") è un attacco di sicurezza informatica (cybersecurity) in cui i criminali usano le tecniche di ottimizzazione per i motori di ricerca (SEO, *Search Engine Optimization*) per far comparire in alto su Google pagine malevole: siti che distribuiscono malware, finti portali di login, truffe e frodi. L'obiettivo è farsi trovare da chi sta cercando qualcosa di normale, per esempio un programma da scaricare o un modulo, e portarlo in una trappola.

A cliccare è la vittima stessa, ed è questo che rende la tecnica efficace: nessuna mail sospetta, nessun messaggio strano, solo un risultato in cima a Google di cui ci si fida.

In questa guida vediamo come funziona, quali varianti esistono, come riconoscere un risultato avvelenato, come difendersi e, se hai un sito, come capire se qualcuno lo sta usando contro i tuoi visitatori.

## Cosa significa SEO poisoning: significato, sigla e obiettivo

Il **significato** è semplice: SEO è la sigla di *Search Engine Optimization* (la sua forma estesa), cioè ottimizzazione per i motori di ricerca, e *poisoning* vuol dire avvelenamento. Nella sicurezza informatica indica quindi l'avvelenamento dei risultati di ricerca.

La SEO normale serve a far trovare un sito legittimo. Nella SEO poisoning le stesse tecniche (parole chiave, link, contenuti) vengono usate da un attaccante per posizionare una pagina pericolosa sulle ricerche che le persone fanno davvero: "scarica 7zip", "modello contratto di affitto", "login webmail", "driver stampante". "Poisoning" vuol dire proprio questo: avvelenare i risultati che ci si aspetta siano sicuri.

È una forma di **ingegneria sociale** indiretta. Nel [phishing](https://hackita.it/articoli/phishing/) l'attaccante scrive alla vittima; qui aspetta che sia la vittima a cercare qualcosa, quindi la guardia è più bassa.

**A cosa serve, cioè qual è l'obiettivo dell'attaccante:**

* **Distribuire malware:** finti installer, archivi e script che infettano il computer.
* **Rubare credenziali:** pagine di login clonate.
* **Frodi e truffe:** falsi supporti tecnici, falsi negozi, offerte fasulle.
* **Guadagnare con lo spam:** link di affiliazione, merce contraffatta, pubblicità.
* **Sfruttare la reputazione di altri siti:** un dominio hackerato dà credibilità alla pagina malevola.

## Come funziona, passo per passo

Una campagna di SEO poisoning segue quasi sempre queste fasi:

1. **Scelta delle parole chiave.** L'attaccante sceglie ricerche molto frequenti o con poca concorrenza: software popolari, documenti, aggiornamenti, ricerche legate a eventi del momento.
2. **Creazione o compromissione delle pagine.** Crea siti nuovi oppure compromette siti legittimi, una delle modalità più documentate, e ci inietta pagine nascoste.
3. **Posizionamento.** Usa keyword stuffing, link artificiali e contenuti pieni di parole chiave per far indicizzare le pagine. I siti compromessi hanno già fiducia agli occhi di Google, e questo aiuta.
4. **Attesa.** Qualcuno cerca quell'argomento e trova la pagina nei risultati.
5. **Trappola.** Il visitatore viene reindirizzato, oppure gli viene mostrato un finto download, una finta pagina di login o un falso "aggiornamento necessario".
6. **Payload.** Parte il malware, vengono rubate le credenziali o viene sottratto denaro.

![Schema di una campagna di SEO poisoning: sito compromesso, pagine nascoste, indicizzazione su Google, clic della vittima, malware o truffa]()

## Le principali varianti

Quando l'obiettivo è il malware si parla spesso di SEO poisoning e malware: la pagina finta serve solo a far scaricare il file che infetta il dispositivo. Le varianti principali sono quattro.

### 1. Siti legittimi compromessi

È la variante più pericolosa, perché il dominio è vero, magari vecchio e con una buona reputazione. L'attaccante entra nel sito (plugin vulnerabile, password debole, upload non protetto) e aggiunge pagine, link o codice nascosti.

Google le chiama "hacked content" e le divide in quattro tipi: **code injection** (codice dannoso aggiunto a pagine esistenti), **page injection** (nuove pagine spam o di phishing che il proprietario non ha mai creato), **content injection** (testo e link nascosti, a volte visibili solo ai crawler) e **redirect** (i visitatori che arrivano da Google vengono mandati altrove). Lo spiegano le [norme antispam di Google](https://developers.google.com/search/docs/essentials/spam-policies).

Per entrare in questi siti si usano di solito errori già noti: un [file upload mal protetto](https://hackita.it/articoli/file-upload-attack/), una [SQL injection](https://hackita.it/articoli/sql-injection/) o una [web shell](https://hackita.it/articoli/web-shell/) lasciata come porta di servizio.

### 2. Cloaking

Il cloaking significa mostrare contenuti diversi a Google e agli utenti. Googlebot vede una pagina piena di parole chiave e la posiziona; l'utente reale che arriva da Google vede altro, o viene rimbalzato su un sito truffa. E se invece apri tu direttamente l'indirizzo nel browser, non succede niente di strano, ed è per questo che il proprietario del sito spesso non si accorge di nulla.

### 3. Siti falsi con nomi e parole chiave costruiti ad arte

L'attaccante registra domini simili a un marchio noto, magari accompagnati da parole come "download", "gratis" o "ufficiale", e li fa salire nei risultati organici. Non va confusa con il malvertising, che usa annunci sponsorizzati a pagamento per le stesse ricerche: sono tecniche collegate e una campagna può usarle insieme, ma non sono la stessa cosa.

### 4. Spam di ricerca su siti vulnerabili

Qui l'obiettivo non è il malware ma il guadagno: pagine spam, link di affiliazione e prodotti contraffatti. Un caso classico è il *Japanese keyword hack*, in cui il sito si riempie di pagine in giapponese con link ad affiliazioni per merce contraffatta. Come descrive la [guida di web.dev](https://web.dev/articles/fix-the-japanese-keyword-hack), l'attaccante può perfino aggiungersi come proprietario in Search Console per modificare sitemap e impostazioni.

## Perché funziona così bene

* **Fiducia in Google.** I primi risultati sembrano affidabili, anche se non lo sono.
* **Intento alto.** Chi cerca "scarica X" vuole davvero installare qualcosa e clicca senza dubbi.
* **Siti veri come copertura.** Un dominio legittimo supera la prima occhiata.
* **Invisibilità per il proprietario.** Con il cloaking, chi gestisce il sito vede solo la versione pulita.
* **Costo basso.** Basta bucare un sito per averne la reputazione.

## Un caso reale: Gootloader

Gootloader è un esempio molto studiato. Secondo l'analisi dei ricercatori di [Sophos](https://www.sophos.com/blog/gootloader-inside-out), che descrive una campagna osservata e non un comportamento valido per ogni attacco, gli operatori usano siti WordPress compromessi: elementi nascosti con link e termini di ricerca fanno indicizzare la pagina per ricerche molto specifiche, come modelli e documenti.

Quando un utente arriva da Google, vede una finta pagina di forum con una domanda identica alla sua ricerca e una risposta che rimanda a un download. Il server mostra il contenuto solo a visitatori di certi Paesi, richiede che arrivino da una ricerca e blocca le visite ripetute dallo stesso IP nelle 24 ore successive. Chi scarica ottiene un archivio zip con un file JScript offuscato, il primo stadio dell'infezione.

Notare il dettaglio: il proprietario del sito, aprendo la pagina da solo, spesso non vede niente.

## Come riconoscere un risultato avvelenato

Non esiste un segnale unico, ma questi indizi, messi insieme, sono utili:

* **Dominio incoerente.** Un sito di giardinaggio che offre un programma di contabilità, o un indirizzo pieno di numeri e trattini.
* **Pagina strana rispetto alla ricerca.** Titolo che ripete esattamente quello che hai scritto, ma contenuto vuoto o generico.
* **Download diretto di un file eseguibile o archivio** (`.exe`, `.msi`, `.zip`, `.js`) da un sito che non è il produttore.
* **Pressione.** "Scarica ora", "il tuo browser è obsoleto", timer, popup.
* **Redirect.** Clicchi un risultato e finisci su un dominio diverso.
* **Permessi richiesti subito**, o una richiesta di login per vedere un documento qualunque.

## Come difendersi (da utente)

La prevenzione della SEO poisoning, per chi naviga, si basa soprattutto su abitudini semplici:

1. **Scarica software solo dal sito ufficiale**, scritto a mano o dai segnalibri, non da un risultato di ricerca.
2. **Controlla l'indirizzo completo**, non solo il titolo. Controlla il dominio nella barra degli indirizzi: in `https://example.com/pagina` il nome host è `example.com`. Attenzione a sottodomini ingannevoli, domini simili e caratteri sostituiti.
3. **Diffida dei risultati sponsorizzati** quando cerchi software: possono essere annunci malevoli.
4. **Usa un blocco annunci e la navigazione sicura del browser**, così i domini noti come pericolosi vengono segnalati.
5. **Mantieni aggiornati browser e sistema**, e non disattivare l'antivirus per "far funzionare" un file scaricato.
6. **Usa un password manager.** Compila le credenziali solo sul dominio salvato, quindi non funziona su un clone.
7. **Attiva l'autenticazione a più fattori**, meglio con chiavi hardware o passkey, che limitano i danni da pagine di login finte.

## Se hai un sito: come capire se sei stato usato

Se il tuo sito è stato hackerato, il pericolo è doppio: i tuoi visitatori finiscono nella trappola e Google può penalizzare il dominio. Ecco una routine da fare ogni mese, con pochi controlli concreti.

### 1. Cerca pagine che non hai creato

Su Google:

```text
site:tuosito.it casino OR viagra OR "scarica" OR crack
```

Guarda anche il numero totale di pagine indicizzate con `site:tuosito.it`. Un salto improvviso è un segnale forte. Ma `site:` è solo un controllo preliminare: non restituisce necessariamente tutte le pagine indicizzate e non prova da solo che il sito sia compromesso. Affiancalo a Search Console, ai log del server e alla verifica dei file.

### 2. Controlla cosa vede Googlebot

Con `curl` confronta la pagina come utente normale e come crawler, e provala anche arrivando "da Google":

```bash
curl -s https://tuosito.it/pagina | head -n 50
curl -s -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" https://tuosito.it/pagina | head -n 50
curl -s -L -e "https://www.google.com/" https://tuosito.it/pagina | head -n 50
```

Differenze anomale tra le risposte sono un indizio da approfondire, ma non dimostrano da sole il cloaking: possono dipendere anche da cache, JavaScript, cookie o personalizzazione. All'inverso, un risultato identico non lo esclude, perché attacchi più sofisticati controllano anche l'IP e il Paese del visitatore.

### 3. Usa Search Console

Guarda il report **Problemi di sicurezza**, l'elenco dei **proprietari e utenti** (un nome che non riconosci è un campanello d'allarme) e le sitemap inviate.

### 4. Controlla i file

Su un sito WordPress, verifica che i file di core e plugin siano originali:

```bash
wp core verify-checksums
wp plugin verify-checksums --all
```

Poi cerca file PHP modificati di recente, soprattutto dove non dovrebbero esserci:

```bash
find /var/www/html -name "*.php" -mtime -7 -ls
find /var/www/html/wp-content/uploads -name "*.php"
```

Nella cartella degli upload non dovrebbe esserci nessun `.php`. Se ne trovi uno, è un file sospetto da verificare, non una prova definitiva: controllalo, confrontalo con una copia pulita e disattiva l'esecuzione degli script in quella cartella.

Questi controlli hanno dei limiti: `verify-checksums` non copre allo stesso modo i plugin commerciali o personalizzati che non hanno checksum nel repository WordPress.org, e `find -mtime -7` trova le modifiche recenti, non per forza tutte quelle malevole. Integrali con il confronto con copie pulite, i log, il database e l'ambiente di hosting.

### 5. Guarda i log

Le visite che dichiarano di essere Googlebot ma arrivano da indirizzi sospetti sono un buon indizio:

```bash
grep -i "googlebot" access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head
host IP_DA_VERIFICARE
host NOME_OTTENUTO
```

Il primo `host` fa il reverse DNS: per un crawler vero di Google il nome finisce in `googlebot.com` o `google.com`. Poi il secondo `host` deve risolvere quel nome di nuovo allo stesso IP. Se uno dei due passaggi non torna, quella visita ha solo dichiarato di essere Googlebot. Il reverse DNS da solo non basta.

### Riepilogo: segnale, verifica, limite

| Segnale                         | Come verificarlo                     | Limite                                     |
| ------------------------------- | ------------------------------------ | ------------------------------------------ |
| Pagine strane su Google         | `site:` + Search Console             | Non mostra tutto, non è una prova          |
| Contenuto diverso per Googlebot | `curl` con User-Agent e Referer      | Differenze possibili anche per cache o JS  |
| File modificati                 | `wp core verify-checksums`, `find`   | Un file nuovo è un sospetto, non una prova |
| Visite finte di Googlebot       | Reverse DNS + verifica inversa       | Servono entrambi i passaggi                |
| Proprietario sconosciuto        | Search Console, utenti e proprietari | Va rimosso, poi cercato l'accesso iniziale |

## Come ripulire, nell'ordine giusto

Cancellare le pagine spam senza chiudere l'accesso dell'attaccante non serve: tornano.

1. **Fai un backup** completo, anche del sito infetto, per poterlo analizzare.
2. **Trova e chiudi l'ingresso.** Plugin vulnerabile, credenziale rubata, web shell. Se non capisci da dove è entrato, il problema si ripresenta.
3. **Rimuovi proprietari sconosciuti da Search Console** e i relativi token di verifica.
4. **Ripristina i file originali.** Reinstalla core, temi e plugin e ripristina un `.htaccess` pulito.
5. **Elimina pagine e sitemap spam**, controllando che rispondano 404 o 410.
6. **Cambia tutte le password** (hosting, FTP, CMS, database, chiavi API) e attiva la 2FA.
7. **Controlla anche i sottodomini.** Un record DNS dimenticato può essere sfruttato come nel [subdomain takeover](https://hackita.it/articoli/subdomain-takeover/).
8. **Chiedi il riesame a Google** se c'è una segnalazione di sicurezza.

Per evitare che succeda di nuovo: aggiornamenti regolari, niente plugin inutili, esecuzione degli script disattivata nelle cartelle di upload, e una scansione periodica che cerchi anche [backup e file dimenticati](https://hackita.it/articoli/backup-exposure/) esposti sul server.

## Sezione tecnica: TTP e indicatori

Per chi lavora in difesa o fa threat intelligence, nella sicurezza informatica la SEO poisoning è catalogata in MITRE ATT\&CK come sottotecnica **T1608.006** (SEO Poisoning, dentro Stage Capabilities), associata alla tattica Resource Development. Tra i metodi descritti figurano il keyword stuffing, i backlink comprati o piazzati e il cloaking. Una caratteristica importante: è difficile da mitigare con controlli preventivi, perché avviene fuori dal perimetro dell'azienda.

**Pattern tipici:**

* Pagine doorway o pagine "forum" fittizie che ripetono la query di ricerca.
* Contenuti serviti solo con `Referer` di un motore di ricerca, `User-Agent` coerente e geolocalizzazione selezionata.
* Rate limiting per IP (ad esempio, una sola visita ogni 24 ore).
* Payload scaricato come archivio con nome uguale alla query cercata.
* Iniezioni su CMS: script remoto con parametro numerico, tabelle di database con prefissi anomali, plugin legittimi modificati.

**Dove cercare in difesa:**

* Query di ricerca che portano a domini mai visti con download di `.zip`, `.js`, `.msi` nella telemetria proxy/DNS.
* Catena `Referer: google.com` → dominio sconosciuto → download di archivio → esecuzione di `wscript.exe` o `cscript.exe` da cartella temporanea.
* Per i siti propri: confronto del DOM servito a crawler e utenti, controllo dell'integrità dei file e allarmi su nuovi file PHP nelle cartelle di upload.

**Mitigazioni lato aziendale:** blocco degli script `.js` e `.vbs` aperti con Windows Script Host, filtro web con categorizzazione dei domini nuovi, formazione per scaricare software solo dai portali ufficiali, EDR con regole sull'esecuzione da archivi scaricati.

Se vuoi capire anche il lato offensivo della catena (come un attaccante ottiene l'accesso a un sito vittima), gli articoli su web shell e [XSS](https://hackita.it/articoli/xss/) coprono le tecniche in ambiente di test.

## Domande frequenti

### Cos'è la SEO poisoning?

La SEO poisoning o avvelenamento della Seo, è quando un criminale fa salire su Google una pagina pericolosa, usando le stesse tecniche della SEO, così che la vittima la trovi cercando qualcosa di normale e ci clicchi da sola.

### Cosa significa SEO poisoning e qual è il suo obiettivo?

SEO sta per *Search Engine Optimization*, cioè l'ottimizzazione per i motori di ricerca, e "poisoning" significa avvelenamento. L'obiettivo dell'attaccante è far arrivare utenti su pagine malevole, per distribuire malware, rubare credenziali, fare truffe o guadagnare con lo spam.

### La SEO poisoning è la stessa cosa del phishing?

No. Nel phishing è l'attaccante a contattare la vittima, per esempio con una mail. Nella SEO poisoning è la vittima a cercare qualcosa e a trovare la trappola. Spesso però la pagina finale è una pagina di phishing.

### Come faccio a sapere se il mio sito è stato usato per la SEO poisoning?

Controlla con `site:tuosito.it` se ci sono pagine che non hai creato, guarda il report Problemi di sicurezza e l'elenco dei proprietari in Search Console, e verifica l'integrità dei file. Ricorda che il cloaking può nascondere tutto al proprietario.

### Google può penalizzare il mio sito se viene hackerato?

Può avere conseguenze. Le norme antispam di Google considerano i contenuti hackerati una violazione, e un sito compromesso può perdere posizioni o mostrare avvisi di sicurezza, anche se la colpa non è del proprietario. Non ogni compromissione causa però automaticamente una penalità manuale: va distinto tra problemi di sicurezza, azioni manuali e normali variazioni degli algoritmi, controllando i report in Search Console.

### La SEO poisoning è la stessa cosa del malvertising?

Non esattamente. La SEO poisoning riguarda la manipolazione del posizionamento organico nei risultati di ricerca. Il malvertising usa la pubblicità online, per esempio gli annunci sponsorizzati, per distribuire malware o truffe. Una campagna può combinare entrambe le tecniche.

### Cosa faccio se ho già scaricato un file da un risultato sospetto?

Se non l'hai ancora aperto, cancellalo. Se l'hai eseguito, scollega il dispositivo dalla rete, avvisa il responsabile IT se è un dispositivo aziendale, fai una scansione con strumenti aggiornati e cambia le password da un dispositivo pulito, soprattutto quelle che usavi su quel computer. In ambito aziendale conviene analizzare anche l'endpoint e i log.

### Come si distingue un risultato di ricerca avvelenato?

Dominio incoerente con l'argomento, pagina generica che ripete la ricerca, download diretto di un file eseguibile o archivio, pressione a scaricare subito e redirect verso altri domini.

### Basta un antivirus per proteggersi?

Aiuta, ma non basta. La difesa migliore è scaricare i programmi solo dai siti ufficiali, tenere aggiornato il sistema e usare password manager e 2FA.

## Conclusione

La SEO poisoning funziona perché sfrutta qualcosa di molto umano: fidarsi del primo risultato. Per difenderti da utente, scarica solo da fonti ufficiali e guarda sempre l'indirizzo. Se gestisci un sito, controlla ogni mese cosa Google ha indicizzato e cosa vede davvero: un compromesso silenzioso può danneggiare sia i tuoi visitatori sia il tuo posizionamento.
