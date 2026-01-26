---
title: >-
  Bettercap: Il Coltellino Svizzero del Network Hacking (MITM, Sniffing e
  Spoofing)
description: >-
  Bettercap è uno degli strumenti più potenti per attacchi man-in-the-middle,
  sniffing e spoofing. Scopri come usarlo da terminale per dominare le reti in
  modo rapido ed efficace.
image: /BETTERCAP.webp
draft: false
date: 2026-01-21T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - bettercap
  - mitm
  - spoofing
slug: "bettercap"
---

# Bettercap: guida pratica per network recon in lab

Bettercap è una vera “Swiss Army knife” per le reti: ti aiuta a fare ricognizione (IPv4/IPv6), lavorare con moduli Wi-Fi/BLE e, se serve, capire anche la parte **adversary-in-the-middle** (MITM).
In questa guida lo usiamo **solo in modo legale e da lab**: impari come funziona la discovery, come leggere i risultati senza confonderti e, soprattutto, cosa fare **per difenderti** da MITM/ARP poisoning.

Risorse ufficiali (senza link):

* Sito ufficiale Bettercap
* Repository ufficiale Bettercap (GitHub)
* Pagina tool Bettercap su Kali Linux

***

## Cos’è Bettercap (e cosa NON è)

Bettercap è un **framework modulare**: entri in una sessione interattiva e “accendi” i moduli che ti servono (discovery, proxy, spoofing, wireless…), impostando parametri e leggendo output in tempo reale.
Non è “il comando magico che fa tutto”: se non hai chiari **interfaccia**, **gateway** e **subnet**, ti perdi subito.

Nota etica (chiara): alcune funzioni sono intrusive (spoofing/deauth ecc.). Qui restiamo su **recon e difesa** e assumiamo sempre **reti/VM autorizzate**.

***

## Installazione su Kali e primo avvio “pulito”

Su Kali lo installi dai repo e poi impari la sessione interattiva (prima di toccare moduli a caso). Esiste anche una UI web, ma ha senso **solo dopo** che sei a tuo agio in CLI.

Install:

```bash
sudo apt update
sudo apt install bettercap
```

Avvio:

```bash
sudo bettercap
```

Dentro la sessione (help rapido):

```text
help
```

***

## Sessione interattiva: comandi base (skiddie-friendly)

Pensa alla sessione come a una console: scrivi comandi, abiliti moduli, setti parametri e leggi output.
Trucco utile: puoi concatenare comandi con `;` per velocizzare.

Esempio “pulito”:

```text
clear; help
```

Termini in 1 riga:

* **modulo** = “pezzo” che fa una cosa (es. discovery host)
* **parametro** = opzione del modulo (es. velocità, subnet)
* **caplet** = mini-script che esegue comandi in sequenza (utile per automazione)

***

## net.recon e net.probe: discovery host senza impazzire

* **net.recon** è “passivo”: scopre host leggendo periodicamente la tabella ARP del sistema (cioè quello che la tua macchina **sa già** della LAN).
* **net.probe** è “attivo”: manda pacchetti di probe nella subnet per far emergere host più “silenziosi”.

Dentro bettercap (sempre in LAN/VM autorizzata):

Avvia discovery passiva:

```text
net.recon on
```

Se vuoi spingere la scoperta (attivo):

```text
net.probe on
```

Stop:

```text
net.probe off
net.recon off
```

Differenza “da tavolo del lab”:

* net.recon = **osservo**
* net.probe = **stimolo la rete**

***

## Caplets: automazione senza scrivere 50 comandi a mano

Caplet = una ricetta. La lanci e Bettercap esegue una sequenza di comandi/moduli.
In lab è comodissimo per avere sempre lo stesso workflow (recon → verifica → stop) e confrontare risultati tra sessioni.

Regola pratica:

1. prima capisci il modulo “a mano”
2. poi lo metti in caplet (così automatizzi senza fare casino)

***

## Bettercap vs Wireshark/tcpdump vs mitmproxy (quando usarlo)

* **Wireshark/tcpdump**: vedono pacchetti (basso livello).
* **mitmproxy/Burp**: vedono HTTP(S) “alto livello” (request/response, cookie, header).
* **Bettercap**: sta più “operativo” in mezzo: recon + moduli + sessione interattiva.

Esempio mentale:

* “Voglio vedere `POST /login` con cookie” → mitmproxy/Burp
* “Voglio scoprire host in LAN e capire se c’è roba strana su ARP” → Bettercap (+ eventualmente tcpdump per confermare)
* “Voglio analisi forense di frame e conversazioni” → Wireshark

***

## Mini-playbook operativo: recon LAN in una VM (senza fare MITM)

Playbook safe:

1. avvia sessione
2. abilita discovery
3. verifica che gli host compaiono
4. salva appunti/evidenze
5. spegni i moduli

Questo lo fai su una rete di lab (Host-Only / NAT Network) senza toccare reti reali.

**Step 1 — Crea un lab semplice**
VM Kali + 1 VM “target” sulla stessa rete virtuale (Host-Only o NAT Network).

**Step 2 — Avvia Bettercap**

```bash
sudo bettercap
```

**Step 3 — Discovery passiva**

```text
net.recon on
```

**Step 4 — Se vedi poco, prova probe (attivo, ma sempre in lab)**

```text
net.probe on
```

**Step 5 — Verifica “reale” dal sistema (sanity check)**
Confronta con la tabella ARP del sistema:

```bash
ip neigh
```

**Step 6 — Stop e appunti**

```text
net.probe off; net.recon off
```

***

## Difesa: come chiudi davvero la superficie “MITM / ARP poisoning”

ARP cache poisoning è una tecnica AiTM: qualcuno prova a posizionarsi in mezzo tra due dispositivi e poi sniffa/manipola traffico.
La difesa migliore è **di rete**, non “bloccare il tool”:

* lato switch (aziendale/gestito): **Dynamic ARP Inspection + DHCP snooping**
* lato applicazione (web): **HTTPS fatto bene + HSTS** (riduce downgrade/HTTP)

Idea chiave: anche se qualcuno tenta AiTM, o lo blocchi a monte (rete) o rendi il traffico poco “utile” (cifratura e policy corrette).

***

## Checklist pratica (lab / esame / lavoro)

* Sto lavorando solo su rete di lab/consentita (Host-Only/NAT Network).
* Avvio sessione e so che interfaccia sto usando (se sbagli NIC, vedi zero).
* `net.recon on` per passivo.
* `net.probe on` solo se serve e solo in lab.
* Confermo “a mano” con `ip neigh` (non mi fido solo del tool).
* Se ragiono di difese AiTM: considero DAI/DHCP snooping (switch) + HTTPS/HSTS (web).

***

## Promemoria 80/20

| Obiettivo                   | Azione pratica                 | Comando/Strumento      |
| --------------------------- | ------------------------------ | ---------------------- |
| Entrare in console          | avvia sessione interattiva     | `sudo bettercap`       |
| Imparare la console         | lista comandi e moduli         | `help`                 |
| Scoprire host (passivo)     | leggi ARP periodicamente       | `net.recon on`         |
| Scoprire host (attivo)      | invia probe nella subnet       | `net.probe on`         |
| Verifica “reale”            | confronta con ARP del sistema  | `ip neigh`             |
| Ridurre rischio MITM (rete) | valida ARP con binding trusted | Dynamic ARP Inspection |
| Ridurre MITM (web)          | forza HTTPS sempre             | HSTS                   |

***

## Concetti controintuitivi (minimo 3)

Queste sono le cose che fanno dire “non funziona” a chi è agli inizi. Se le capisci, vai 10x più veloce.

1. **“Non vedo host → la rete è vuota” (spesso falso)**
   Se sei su NAT/bridge sbagliato o sull’interfaccia sbagliata, net.recon non vede nulla. Prima controlla NIC/subnet, poi il tool.
2. **“net.recon scopre tutto” (no)**
   net.recon legge l’ARP table: se un host non ha mai “parlato” o non è entrato in ARP, può non comparire. Per questo esiste net.probe (attivo).
3. **“MITM = solo roba web” (no)**
   AiTM è concetto di rete: ARP poisoning ti mette in mezzo e poi tutto ciò che non è protetto bene può diventare osservabile/manipolabile.
4. **“Basta HTTPS e sono invincibile” (non sempre)**
   HTTPS ti salva tantissimo, ma misconfig (HSTS assente, link HTTP, utenti che accettano certificati strani) possono riaprire problemi. HTTPS va “chiuso bene”, non solo acceso.

***

## FAQ su Bettercap

**Bettercap è solo per attaccare?**
No: è anche uno strumento di recon e monitoring. Il punto è che include moduli MITM, quindi va usato solo in ambienti autorizzati.

**Qual è il comando più semplice per iniziare?**

```bash
sudo bettercap
```

Poi dentro: `help` e `net.recon on`.

**Che differenza c’è tra net.recon e net.probe?**
net.recon è passivo (legge ARP), net.probe è attivo (manda probe).

**Bettercap sostituisce Wireshark?**
No: Wireshark è analisi pacchetti profonda. Bettercap è più “operativo” (moduli + sessione) e ti dà workflow rapidi.

**Come mi difendo da ARP spoofing/MITM in rete aziendale?**
Su switch gestiti: Dynamic ARP Inspection + DHCP snooping. Sul web: HTTPS + HSTS riducono molto gli scenari da downgrade/HTTP.

**Perché molti usano Bettercap invece di Ettercap?**
Perché Bettercap è più moderno, modulare e copre più superfici (recon, IPv6, Wi-Fi/BLE), con sessione interattiva e caplets.

***

## Supporta HackITA (e servizi)

Se questa guida ti è stata utile, puoi darci una mano dalla sezione **Supporta**: ci permette di pubblicare più contenuti tecnici e tenerli aggiornati.

Se sei bloccato o vuoi fare salto di livello più in fretta, facciamo **formazione 1:1** (percorsi pratici, debug insieme, metodo da lab).

E se hai un’azienda o un progetto, possiamo supportarti con lavori su misura: assessment, hardening, review e attività di sicurezza **solo in contesti autorizzati**.
