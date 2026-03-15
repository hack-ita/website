---
title: 'Porta 1025 MS RPC: endpoint dinamici Windows, porta 135 e lateral movement.'
slug: porta-1025-ms-rpc
description: 'Scopri cos’è la porta 1025 in ambito MS RPC, perché va correlata all’endpoint mapper sulla 135 e come le porte RPC dinamiche dipendano dalla versione di Windows: 1025-5000 nei sistemi legacy, 49152-65535 da Windows Vista/Server 2008 in poi.'
image: /porta-1025-ms-rpc.webp
draft: true
date: 2026-04-09T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - rpc-endpoint-mapper
  - rpc-dynamic-port
---

> **Executive Summary** — La porta **1025** non è un servizio ma un **endpoint RPC dinamico** assegnato da Windows a un servizio registrato sull’**Endpoint Mapper (135/TCP)**. Nel pentest il punto non è la 1025 in sé, ma capire **quale interfaccia RPC** si trovi dietro quella porta e **quale servizio la stia usando**. Nei sistemi legacy il range RPC dinamico era **1025–5000**, mentre nei Windows moderni il range predefinito è **49152–65535**. Per questo motivo, vedere la 1025 aperta oggi è solo **un indicatore da correlare**, non la prova di un servizio specifico.**TL;DR1025 non identifica un servizio specifico**: indica solo un **endpoint RPC dinamico** da correlare alla **135/TCP**.Nei sistemi moderni il range RPC dinamico predefinito è **49152–65535**, mentre **1025–5000** era tipico dei sistemi Windows più vecchi.**Task Scheduler, WMI, DCOM e Service Control Manager** possono usare RPC, ma non sempre con lo stesso trasporto: alcune interfacce usano **RPC su TCP**, altre **named pipe su SMB**.

Porta **1025 MS RPC** è quindi una dicitura utile lato SEO, ma tecnicamente va letta così: hai trovato **una porta alta assegnata dinamicamente da RPC**, e ora devi capire **quale UUID / protocollo / servizio** sia pubblicato lì dietro. Nel pentesting reale l’errore comune è trattare la 1025 come se fosse “Task Scheduler” o “WMI” per definizione. In realtà la porta viene assegnata dal runtime RPC e il servizio reale si identifica interrogando l’**Endpoint Mapper sulla porta 135**.

## 1. Anatomia tecnica della porta 1025

Storicamente la **1025** era la prima porta disponibile del vecchio range RPC dinamico Windows. Per questo sui sistemi legacy era comune trovarla come primo endpoint RPC. Nei sistemi moderni invece il range dinamico è stato spostato molto più in alto, quindi è più corretto parlare di **porte RPC dinamiche** piuttosto che della 1025 come caso specifico.

| Componente            | Porta                                      | Funzione                                              |
| --------------------- | ------------------------------------------ | ----------------------------------------------------- |
| Endpoint Mapper       | 135/TCP                                    | Directory che mappa UUID RPC verso una porta dinamica |
| Endpoint RPC dinamico | 1025–5000 (legacy) / 49152–65535 (moderni) | Porta effettiva su cui ascolta il servizio            |
| RPC over HTTP         | 593/TCP                                    | Trasporto RPC incapsulato su HTTP                     |

Il flusso RPC è sempre lo stesso:

1. Il client contatta **135/TCP**
2. Chiede dove si trovi una determinata interfaccia RPC
3. L’endpoint mapper restituisce una **porta dinamica**
4. Il client apre la connessione verso quella porta

In altre parole: **135 è la directory**, mentre la **porta alta è il vero endpoint del servizio**.

## 2. Enumerazione di base

Il primo passo è verificare la presenza dell’endpoint mapper e delle porte RPC dinamiche.

```bash
nmap -sV -p 135,1025,49152-49220 10.10.10.10
```

Output tipico:

```
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
1025/tcp  open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
```

Questo risultato indica solo che **l’host espone endpoint RPC**, ma non rivela ancora **quale servizio** sia dietro ogni porta.

## 3. Identificare il servizio reale

Per capire quale servizio usa quella porta bisogna interrogare l’endpoint mapper.

```bash
rpcdump.py 10.10.10.10
```

Oppure filtrare una porta specifica:

```bash
rpcdump.py 10.10.10.10 | grep -A3 -B1 "1025"
```

Output esempio:

```
Protocol: [MS-TSCH]
Provider: schedsvc.dll
UUID    : 86D35949-83C9-4044-B424-DB363231FD0C
Bindings: ncacn_ip_tcp:10.10.10.10[49154]
```

Questo output mostra che una specifica **interfaccia RPC** è stata pubblicata su una porta dinamica. È questa correlazione che permette di capire **quale servizio Windows stia usando quell’endpoint**.

Se vuoi approfondire RPC e servizi Windows correlati, vedi anche:

* [https://hackita.it/articoli/porta-135-msrpc](https://hackita.it/articoli/porta-135-msrpc)
* [https://hackita.it/articoli/wmi](https://hackita.it/articoli/wmi)
* [https://hackita.it/articoli/post-exploitation](https://hackita.it/articoli/post-exploitation)

## 4. Errori comuni nell’analisi RPC

Molte guide online associano direttamente alcune porte a determinati servizi, ma RPC non funziona così. I protocolli possono usare **trasporti diversi**:

* alcune interfacce usano **RPC over TCP**
* altre usano **named pipe su SMB**
* altre ancora usano **DCOM**

Ad esempio il **Task Scheduler Remoting Protocol** usa più interfacce: alcune passano tramite named pipe, altre tramite endpoint RPC dinamici. Dire quindi “porta 1025 = Task Scheduler” è tecnicamente scorretto.

## 5. Valore offensivo nel pentest

Una porta RPC dinamica aperta non significa automaticamente **remote code execution**, ma indica che il sistema espone **componenti di amministrazione remota**.

Se hai:

* credenziali valide
* accesso alla rete
* un’interfaccia RPC utile

quella porta può diventare un canale per:

* interrogazioni **WMI**
* operazioni **DCOM**
* gestione servizi
* enumerazione avanzata di sistema

Per questo durante un assessment la presenza di **135 + porte RPC dinamiche** indica spesso un host Windows con **superficie di amministrazione remota esposta**.

## 6. Scenario pratico

Situazione:

* **135 aperta**
* diverse porte RPC alte aperte

Errore tipico:

> “La 1025 è Task Scheduler, posso usarla direttamente.”

Approccio corretto:

1. scansiona le porte
2. interroga l’endpoint mapper
3. identifica l’interfaccia RPC
4. valuta se è utile nel contesto del pentest

Workflow:

```bash
nmap -sV -p 135,1025,49152-49220 10.10.10.10
rpcdump.py 10.10.10.10 | grep -E "Protocol|Provider|Bindings"
```

## 7. Cheat sheet

| Azione                 | Comando                                     |                   |          |             |
| ---------------------- | ------------------------------------------- | ----------------- | -------- | ----------- |
| Scan RPC               | `nmap -sV -p 135,1025,49152-49220 [target]` |                   |          |             |
| Dump endpoint mapper   | `rpcdump.py [target]`                       |                   |          |             |
| Filtra porta specifica | `rpcdump.py [target] \| grep [porta]`       |                   |          |             |
| Filtra servizi RPC     | \`rpcdump.py \[target]                      | grep -E "Protocol | Provider | Bindings"\` |

## 8. Perché la porta 1025 conta davvero

La 1025 non è importante perché rappresenta un servizio preciso, ma perché mostra come funziona realmente RPC: molti servizi Windows **non usano porte fisse**, ma endpoint pubblicati dinamicamente tramite l’endpoint mapper.

In un pentest la skill reale non è ricordare “porta = servizio”, ma saper fare la correlazione:

```
Endpoint Mapper → Porta dinamica → Interfaccia RPC → Servizio reale
```

## 9. Hardening

Per ridurre la superficie RPC in rete:

* restringere il **range RPC dinamico**
* filtrare **135/TCP tra VLAN**
* limitare RPC ai soli host autorizzati

Bloccare solo la 135 non basta: se il range RPC rimane aperto, molti servizi di amministrazione remota continueranno comunque a funzionare.

***

Se vuoi sostenere il progetto:
[https://hackita.it/supporto](https://hackita.it/supporto)

Se vuoi testare la sicurezza della tua azienda o ricevere supporto 1:1:
[https://hackita.it/servizi](https://hackita.it/servizi)
