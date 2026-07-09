---
title: 'HTTP Port 80: guida operativa (porte/protocolli) nel pentest'
slug: porta-80-http
description: ' Porta 80 in pentest lab: scan, fingerprint HTTP, vhost enum, directory brute force, misconfig e detection. Workflow con Nmap/ffuf/curl.'
image: /http-porta-80-guida-operativa-pentest.webp
draft: true
date: 2026-07-09T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - http
  - port 80
---

# HTTP 80: porte, protocolli e payload nel pentest (guida offensiva cybersecurity)

Sei su un target HTB/PG e nmap ti restituisce **80/tcp open**. Da lì hai due strade: perdere tempo aprendo il browser a caso, o portare via in 10 minuti server, virtual host, directory e misconfig verificabili. Questo articolo copre il secondo caso: fingerprint HTTP, vhost/directory enumeration e le 5 misconfig su porta 80 che sbloccano più box di quanto sembri (solo lab/HTB/PG/VM autorizzate).

## Perché HTTP 80 è una porta "alta leva"

> **In breve:** 80/tcp raramente è "solo un sito": spesso è un gateway verso auth, pannelli, API e asset interni. Se è esposta male, è un moltiplicatore di rischio.

Un reverse proxy (Nginx/Apache) davanti a più app non si fingerprinta guardando "Server: nginx", ma osservando comportamenti:

* quali path esistono
* quali rispondono con 200/301/401/403
* cosa cambia al variare di Host/header/metodo

Quando l'obiettivo è solo liveness (host up/down), non fissarti sulla 80: fai prima discovery e poi scendi nel dettaglio applicativo.

## Stati della porta: cosa significa davvero "open"

> **In breve:** "open" indica che la porta accetta connessioni, non che il servizio sia vulnerabile. La vulnerabilità nasce da versione + config + esposizione + contesto.

```bash
nmap -sS -Pn -p80 --reason --open 10.10.10.10
```

```text
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack
```

Sai che la 80 risponde a livello TCP. Ora devi dimostrare che parla HTTP e con quali caratteristiche.

Errore comune: "80 open = web vulnerabile". Falso — passa a fingerprint prima di qualsiasi conclusione.

Da tenere a mente anche per UDP: "filtered" può nascondere un firewall/rate-limit (falsi negativi), e su UDP "open|filtered" è spesso solo silenzio, non conferma.

## Port scanning: SYN scan, connect scan, UDP scan

> **In breve:** SYN scan è veloce e semi-open, connect scan più compatibile ma rumoroso, UDP lento e ambiguo. La tecnica cambia il tipo di evidenza che ottieni.

**SYN scan** (mappa rapida delle porte TCP realmente raggiungibili):

```bash
nmap -sS -Pn -p- --min-rate 2000 --open 10.10.10.10
```

```text
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
445/tcp open  microsoft-ds
```

Errore comune + fix: scan aggressivo e risultati sporchi → abbassa `--min-rate`.

**Connect scan** (quando non hai privilegi raw, es. container):

```bash
nmap -sT -Pn -p80,443 --open 10.10.10.10
```

Errore comune + fix: risultati diversi tra `-sS` e `-sT` → possibile filtering; verifica con cattura traffico.

**UDP scan** (DNS, SNMP, DHCP, NTP vivono qui e spariscono se non li cerchi):

```bash
nmap -sU -Pn -p53,67,161 --open 10.10.10.10
```

```text
PORT    STATE         SERVICE
53/udp  open|filtered domain
161/udp open|filtered snmp
```

Errore comune + fix: "open|filtered = sicuramente aperto" è falso. Valida con probe dedicati.

## Fingerprint HTTP: oltre "Server: Apache"

> **In breve:** su 80 servono segnali ripetibili — server header, title, metodi permessi, redirect. Questo dà la mappa per test mirati.

```bash
nmap -sS -Pn -p80 -sV --script http-title,http-server-header,http-methods 10.10.10.10
```

```text
80/tcp open  http    nginx 1.18.0
| http-title: Lab Panel
| http-server-header: nginx/1.18.0
| http-methods:
|   Supported Methods: GET HEAD POST OPTIONS
|_  Potentially risky methods: TRACE
```

Title e metodi già dicono "ruolo" (pannello) e possibile misconfig (TRACE abilitato).

Se `TRACE` è tra i metodi supportati, verificalo — è la base del Cross-Site Tracing (XST), usato storicamente per bypassare `HttpOnly` sui cookie leggendo l'header di richiesta riflesso nella risposta:

```bash
curl -X TRACE http://10.10.10.10 -H "Cookie: session=test123" -i
```

Se la risposta (200 OK con `Content-Type: message/http`) riflette l'header `Cookie` che hai inviato, il metodo è realmente sfruttabile e non solo "elencato".

Errore comune + fix: `-sV` "sbaglia" versione dietro reverse proxy → passa a fingerprint per path e probe manuale.

Alternativa rapida con curl (più comodo di nc per un check veloce):

```bash
curl -I http://10.10.10.10
```

Con `-I` mandi una HEAD invece di una GET: stessi header di risposta, meno traffico generato — utile per banner grabbing ripetuto senza scaricare il body ogni volta.

Header da leggere sempre, non solo "Server":

* `Server` / `X-Powered-By` — stack tecnologico (spesso disattivabili, se ci sono è già un segnale di config non hardenata)
* `Set-Cookie` — nome cookie e flag (`HttpOnly`, `Secure`, `SameSite`): cookie senza `HttpOnly` sono leggibili da JS (rischio XSS→theft), senza `Secure` viaggiano anche in chiaro
* `Location` — dove ti reindirizza (spesso rivela path applicativi interni)
* `Cache-Control` — se manca su pagine con dati sensibili, possono restare in cache condivise

Per confermare in modo grezzo cosa risponde davvero (senza tool):

```bash
printf 'HEAD / HTTP/1.1\r\nHost: 10.10.10.10\r\nConnection: close\r\n\r\n' | nc -nv -w 3 10.10.10.10 80
```

```text
HTTP/1.1 302 Found
Server: nginx
Location: /login
Set-Cookie: session=...; HttpOnly
```

Redirect verso login + cookie di sessione: già una surface applicativa concreta. Qui il cookie ha `HttpOnly` ma non `Secure`: su un canale HTTP puro è comunque intercettabile in chiaro.

Errore comune + fix: risposta "400 Bad Request" → manca `Host:` o formattazione CRLF corretta.

## Virtual host e Host header: cosa nasconde il reverse proxy

> **In breve:** un solo IP su 80 spesso serve più applicazioni diverse in base all'header `Host`. Se non provi vhost diversi, ti perdi metà della superficie.

Su HTB è quasi la norma: `admin.target.htb`, `api.target.htb` rispondono in modo completamente diverso dall'IP nudo.

```bash
gobuster vhost -u http://10.10.10.10 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

O manualmente, cambiando solo l'header:

```bash
curl -H "Host: admin.target.htb" http://10.10.10.10
```

Cambiare `Host:` può far apparire un'applicazione completamente diversa dallo stesso IP/porta — è il comportamento normale di un reverse proxy con più vhost configurati.

Errore comune + fix: gobuster vhost dà falsi positivi su risposte quasi identiche → usa `-fs`/`--exclude-length` per filtrare la size di default.

## Enumerazione: directory, pannelli, leakage

> **In breve:** dopo il fingerprint, la domanda è quali endpoint esistono e cosa rivelano. Non serve bruteforce infinito, servono candidate ad alta leva (admin, api, backup, debug).

Check istantanei, zero rumore, prima di qualsiasi brute force:

```bash
curl http://10.10.10.10/robots.txt
curl http://10.10.10.10/sitemap.xml
```

`robots.txt` spesso elenca path che l'owner voleva "nascosti" ai crawler — non da un pentester.

```bash
nmap -Pn -p80 --script http-enum 10.10.10.10
```

```text
| http-enum:
|   /admin/: Possible admin folder
|   /api/:   Possible API endpoint
|_  /backup/: Directory listing may be enabled
```

Non è "pwn", è una lista di piste da verificare con richieste mirate.

Errore comune + fix: script muto → possibile WAF/redirect/vhost. Verifica prima `/` a mano e ripeti.

Per un'enumerazione più a fondo, `http-enum` è solo il punto di partenza — un brute force mirato con ffuf o feroxbuster copre molto più terreno:

```bash
ffuf -u http://10.10.10.10/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -fc 404
```

```bash
feroxbuster -u http://10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

Errore comune + fix: troppi falsi positivi → filtra per status code (`-fc`) o per size di risposta, non per singola parola trovata.

**WAF fingerprint**, se le risposte sembrano "strane" (block page generica, 403 su tutto):

```bash
wafw00f http://10.10.10.10
```

Sapere che c'è un WAF (e quale) ti dice se rallentare il rate o cambiare tecnica di evasione, prima di continuare a fuzzare a vuoto.

**Favicon hash**, tecnica moderna per identificare lo stack applicativo anche dietro un proxy generico:

```bash
curl -s http://10.10.10.10/favicon.ico | md5sum
```

L'hash (o il MurmurHash usato da Shodan) permesso di cercare su Shodan/Censys quale prodotto usa esattamente quella favicon — utile quando header e title non dicono nulla.

## Le 5 misconfig su 80 che diventano vettori d'attacco

> **In breve:** la maggior parte dei problemi su 80 sono config sbagliate, non CVE. Il test sano è: prova → evidenza → impatto → fix.

**1) HTTP in chiaro su rete interna** (credenziali/sessioni sniffabili):

```bash
sudo tcpdump -ni any host 10.10.10.10 and port 80 -A | head -n 40
```

```text
POST /login HTTP/1.1
Host: 10.10.10.10

user=lab&pass=lab123
```

Prova forte di impatto: credenziali in chiaro. Errore comune + fix: "non vedo nulla" → interfaccia sbagliata o traffico su 443, controlla routing.

Hardening: forza HTTPS, HSTS su 443, redirect 80→443.

**2) Directory listing / backup esposti:**

```bash
printf 'GET /backup/ HTTP/1.1\r\nHost: 10.10.10.10\r\nConnection: close\r\n\r\n' | nc -nv -w 3 10.10.10.10 80
```

```text
HTTP/1.1 200 OK
Index of /backup/
- db.sql
- site.zip
```

Errore comune + fix: "403 quindi niente" → falso, un 403 può comunque confermare esistenza; confronta path diversi.

Hardening: disabilita autoindex, ACL su directory, rimuovi backup dal docroot.

**3) Reverse proxy "aperto" verso servizi interni:**

```bash
printf 'GET /internal/ HTTP/1.1\r\nHost: 10.10.10.10\r\nConnection: close\r\n\r\n' | nc -nv -w 3 10.10.10.10 80
```

```text
HTTP/1.1 200 OK
X-Upstream: 127.0.0.1:8080
```

Un path che fa da ponte verso un backend rende la 80 un pivot applicativo.

Hardening: allowlist upstream, blocco path sensibili, segmentazione.

**4) Security header mancanti** (non exploit diretto, ma finding di hardening da riportare sempre):

```bash
curl -I http://10.10.10.10 | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer-policy"
```

Se il grep non restituisce nulla, mancano `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`. La loro assenza non è una vulnerabilità diretta, ma è un finding legittimo: apre la porta a clickjacking (senza X-Frame-Options) o downgrade attack (senza HSTS).

**5) `.git` esposto** (frequentissimo su HTB — sorgenti e history del repo scaricabili):

```bash
curl -s -o /dev/null -w "%{http_code}" http://10.10.10.10/.git/HEAD
```

Se risponde 200, il repo è raggiungibile. Scarica ed estrai con:

```bash
git-dumper http://10.10.10.10/.git/ ./dumped-repo
```

Interpretazione: history, commit e file di config finiscono spesso con credenziali hardcoded o segreti in vecchi commit anche se rimossi dall'ultima versione.

Hardening: rimuovi `.git` dal docroot in produzione, mai deploy diretto da working copy.

## Due attacchi HTTP che meritano un articolo a parte

> **In breve:** su 80, oltre alle misconfig viste sopra, esistono due classi di attacco che dipendono direttamente da come header e cache vengono gestiti — troppo ampie per un box qui, ma direttamente collegate a quanto hai appena enumerato.

Se durante il fingerprint noti header di cache (`Cache-Control`, `X-Cache`, `Age`) su un reverse proxy, il servizio è potenzialmente esposto a **web cache poisoning**: iniettando header non canonicalizzati (`X-Forwarded-Host`, parametri unkeyed) puoi far cachare una risposta malevola per tutti gli utenti successivi. Approfondimento operativo: [Cache Poisoning: guida completa](/articoli/cache-poisoning/).

Se il target è dietro un reverse proxy/load balancer (molto comune su 80) e noti incongruenze tra come front-end e back-end parsano `Content-Length`/`Transfer-Encoding`, sei nel territorio dell'**HTTP Request Smuggling** — bypass di controlli di accesso e cache poisoning "a monte". Approfondimento operativo: [HTTP Request Smuggling: guida completa](/articoli/http-request-smuggling/).

## Perché la mappa "porta → attacco" conta anche fuori da 80

> **In breve:** una porta aperta è un gancio: dice che protocollo parlare e quali errori cercare. Esempi rapidi su SMB/FTP/SSH/RDP.

* **SMB 445** — check non distruttivo per MS17-010: `nmap -Pn -p445 --script smb-vuln-ms17-010 10.10.10.10`. Un "VULNERABLE" è priorità di patching, non licenza per exploitation fuori scope.
* **FTP 21** — `nmap -Pn -p21 --script ftp-anon 10.10.10.10` verifica se l'anonymous login legge directory (data exposure classica).
* **SSH 22** — `nmap -Pn -p22 -sV --script ssh-hostkey,ssh2-enum-algos 10.10.10.10` valida config e crypto policy, non serve "sparare dizionari".
* **RDP 3389** — `nmap -Pn -p3389 -sV 10.10.10.10` conferma esposizione; RDP pubblico è già un finding di rischio.

## Strumenti: Nmap, Masscan, Netcat

> **In breve:** Nmap dà qualità e contesto, Masscan velocità su range, Netcat controllo manuale sul protocollo.

```bash
# Nmap: qualità e ripetibilità
nmap -sS -Pn -p80,443,22,445 --open -sV --reason 10.10.10.10

# Masscan: velocità su un range in lab
sudo masscan 10.10.10.0/24 -p80 --rate 1000

# Netcat: verità grezza sul protocollo
printf 'GET / HTTP/1.1\r\nHost: 10.10.10.10\r\nConnection: close\r\n\r\n' | nc -nv -w 3 10.10.10.10 80
```

Masscan ti dice velocemente "chi ha 80 aperta" su un range; Nmap fa il lavoro di qualità dopo.

**Scanner automatici** per una prima botta di segnali senza scrivere richieste a mano:

```bash
whatweb -a 4 10.10.10.10
nikto -h http://10.10.10.10
nuclei -u http://10.10.10.10 -t nuclei-templates/
```

`whatweb` identifica tech stack e CMS in un colpo; `nikto` trova file noti/misconfig comuni ma è rumoroso (non su target sensibili fuori scope); `nuclei` applica migliaia di template community — se rileva WordPress/Joomla, passa a `wpscan`/`joomscan` per un'enumerazione mirata al CMS.

## Scenario pratico: da "80 open" a evidenza in 4 mosse

Target `10.10.10.10`, obiettivo: identificare il servizio e trovare 1-2 endpoint ad alta leva.

```bash
sudo masscan 10.10.10.10 -p80 --rate 500
nmap -sS -Pn -p80 -sV --script http-title,http-server-header,http-methods 10.10.10.10
nmap -Pn -p80 --script http-enum 10.10.10.10
printf 'HEAD / HTTP/1.1\r\nHost: 10.10.10.10\r\nConnection: close\r\n\r\n' | nc -nv -w 3 10.10.10.10 80
```

Risultato atteso: status code, `Server:` header, title e almeno 1 path interessante (`/login`, `/admin`, `/api`, `/backup`).

## Checklist operativa

* Conferma `80/tcp open` con `--reason`.
* Separa discovery (porte) da enumeration (script/HTTP).
* Estrai almeno 3 segnali: status, Server/header, title.
* Verifica i metodi permessi (attenzione a TRACE).
* Controlla `robots.txt`/`sitemap.xml` e `.git/HEAD` prima di qualsiasi brute force.
* Prova almeno 1 vhost alternativo cambiando l'header `Host`.
* Esegui `whatweb`/`nikto`/`nuclei` per un primo giro di segnali automatici.
* Esegui `http-enum` + ffuf/feroxbuster per path ad alta probabilità.
* Verifica i security header mancanti (HSTS, CSP, X-Frame-Options).
* Valida manualmente `/` e 1-2 path con richiesta HTTP minimale.
* Se sospetti WAF/filtering, riduci rate, prova `wafw00f` e verifica con `tcpdump`.
* Non confondere versione del proxy con versione dell'app.

## Concetti controintuitivi

* **"80 open = sito normale"** — spesso è un proxy o pannello interno esposto. Trattalo come gateway, non come homepage.
* **"Server header = versione vera dell'app"** — dice poco sull'app dietro un proxy. Servono segnali applicativi (path, redirect, cookie).
* **"UDP open|filtered = aperto"** — su UDP il silenzio è normale, serve validazione con probe.
* **"403 = non c'è nulla"** — un 403 può confermare che l'endpoint esiste, solo protetto. Confronta path diversi.

## FAQ

**Se vedo 80 open, da dove parto?**
Conferma `open` con `--reason`, poi fingerprint (`http-title/http-server-header/http-methods`), poi `http-enum`, poi richiesta manuale con `nc`.

**Perché `-sV` a volte sbaglia versione?**
Perché su 80 spesso c'è un reverse proxy. Usa header, redirect e path per il fingerprint applicativo reale.

**Come distinguo proxy da app diretta?**
Confronta header e redirect tra path diversi; se puoi, verifica con cattura traffico.

**Quando ha senso Masscan invece di Nmap?**
Quando devi solo scoprire velocemente chi espone 80/443 su un range. Poi passi a Nmap per il dettaglio.

**Perché lo stesso IP su 80 mostra app diverse?**
Perché un reverse proxy instrada in base all'header `Host`, non solo su IP/porta. Cambiare `Host:` (manualmente o con gobuster vhost) rivela vhost nascosti.

## Link utili su HackIta.it

* [Nmap: la guida completa allo scanning](/articoli/nmap/)
* [Masscan: scanning veloce su larga scala](/articoli/masscan/)
* [Ffuf: fuzzing web veloce e flessibile](/articoli/ffuf/)
* [Gobuster: directory e vhost brute force](/articoli/gobuster/)
* [Netcat: il coltellino svizzero dell'hacking di rete](/articoli/netcat/)
* [Tcpdump: analizzare il traffico di rete da terminale](/articoli/tcpdump/)
* [TShark: analizzare il traffico di rete da terminale](/articoli/tshark/)
* [Wireshark in azione: analizza il traffico](/articoli/wireshark/)
* [Mitmproxy: analizza e manipola il traffico HTTPS](/articoli/mitmproxy/)
* [Bettercap: network hacking (MITM, sniffing e spoofing)](/articoli/bettercap/)

## Riferimenti autorevoli

* [https://www.rfc-editor.org/rfc/rfc9110.html](https://www.rfc-editor.org/rfc/rfc9110.html)
* [https://owasp.org/www-project-secure-headers/](https://owasp.org/www-project-secure-headers/)
