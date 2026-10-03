---
title: 'Kali Linux: Cos''è, A Cosa Serve, Tool e Installazione'
slug: kali-linux
description: 'Kali Linux: cos''è, a cosa serve, come installarlo, come imparare e quali sono i principali tool per penetration test, cybersecurity, forensics e red team.'
image: /kali-linux-distribuzione-pentest-ethical-hacking.webp
draft: true
date: 2026-10-11T23:35:47.973Z
lastmod: 2026-10-11T23:35:48.992Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Kali Linux
  - Penetration Testing
  - Ethical Hacking
  - Offensive Security
  - Security Tools
---

# Kali Linux: Cos'è, Come Funziona e Come Iniziare a Usarlo

**Kali Linux** è una distribuzione Linux basata su Debian, sviluppata da **Offensive Security**, pensata per penetration test, analisi forense digitale e ricerca sulla sicurezza. Arriva già con centinaia di strumenti preinstallati per ricognizione, scansione di vulnerabilità, exploitation, wireless security e reverse engineering: non serve installarli uno a uno, sono già pronti e organizzati per categoria.

È una delle distribuzioni più conosciute e utilizzate per penetration testing e security auditing, ed è il riferimento dell'ecosistema Offensive Security, ma **non è un sistema per navigare, giocare o studiare "da zero"**: è uno strumento professionale, e va trattato come tale.

## Kali Linux cos'è: la distinzione fondamentale

Kali è **un insieme di strumenti**, non una "scorciatoia per diventare hacker". Il sistema stesso non sa fare nulla di speciale: quello che conta è capire come funzionano le tecniche e i protocolli dietro ogni tool. Installare Kali senza studiare reti, Linux e sicurezza equivale a comprare una cassetta degli attrezzi senza sapere cosa sia un cacciavite.

Kali Linux è sviluppato e mantenuto da **Offensive Security**, la stessa organizzazione dietro certificazioni come OSCP, OSEP e OSWE, ed è il successore di **BackTrack Linux**, la distribuzione precedente da cui Kali è nato nel 2013.

## A cosa serve Kali Linux

Gli usi principali sono:

* **penetration test**: verificare la sicurezza di reti, applicazioni web e sistemi, con autorizzazione;
* **vulnerability assessment**: trovare e classificare le debolezze di un ambiente;
* **digital forensics**: analizzare dischi e immagini forensi senza alterarne il contenuto;
* **reverse engineering**: studiare binari e malware;
* **red teaming**: simulare un attacco realistico contro un'organizzazione;
* **sicurezza wireless**: audit di reti Wi-Fi;
* **CTF e studio**: allenarsi su piattaforme come HackTheBox o TryHackMe.

Kali è ottimizzato per il lavoro di sicurezza, non per essere un desktop general-purpose: molti strumenti e configurazioni sono pensati per attività di assessment e richiedono una conoscenza del sistema maggiore rispetto a una distribuzione desktop tradizionale.

## Kali Linux: strumenti e tool più importanti

Kali raggruppa gli strumenti in base alla fase del lavoro, seguendo più o meno le fasi di un penetration test e della [Cyber Kill Chain](https://hackita.it/articoli/cyber-kill-chain/):

| Categoria                    | Cosa serve a fare                        | Tool noti                                                                                                    |
| ---------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Information Gathering**    | Raccogliere informazioni su un bersaglio | [Nmap](https://hackita.it/articoli/nmap/), [Shodan](https://hackita.it/articoli/shodan/)                     |
| **Vulnerability Analysis**   | Trovare vulnerabilità note               | Nessus, OpenVAS                                                                                              |
| **Web Application Analysis** | Testare applicazioni web                 | [Burp Suite](https://hackita.it/articoli/burp-suite/), [SQLmap](https://hackita.it/articoli/sqlmap/)         |
| **Password Attacks**         | Attaccare credenziali                    | [Hashcat](https://hackita.it/articoli/hashcat/), John the Ripper, Hydra                                      |
| **Wireless Attacks**         | Audit di reti Wi-Fi                      | Aircrack-ng                                                                                                  |
| **Exploitation Tools**       | Sfruttare vulnerabilità                  | [Metasploit](https://hackita.it/articoli/metasploit/)                                                        |
| **Sniffing & Spoofing**      | Analizzare e manipolare il traffico      | Wireshark, [Responder](https://hackita.it/articoli/responder/)                                               |
| **Post Exploitation**        | Operare dopo l'accesso iniziale          | [Impacket](https://hackita.it/articoli/impacket/), [CrackMapExec](https://hackita.it/articoli/crackmapexec/) |
| **Forensics**                | Analisi forense                          | Autopsy, Volatility                                                                                          |
| **Reverse Engineering**      | Analisi di binari                        | Ghidra, GDB                                                                                                  |

Non servono tutti insieme: in un pentest reale ne usi una frazione, in base al contesto.

## Installazione: le opzioni disponibili

| Modalità                                   | Quando usarla                                                                                |
| ------------------------------------------ | -------------------------------------------------------------------------------------------- |
| **Macchina virtuale** (VMware, VirtualBox) | La scelta più comune per iniziare: isolata, con snapshot, facile da ripristinare             |
| **Bare metal** (installazione diretta)     | Quando serve tutta la potenza hardware, per esempio per il cracking di password con GPU      |
| **WSL** (Windows Subsystem for Linux)      | Comoda per strumenti a riga di comando su Windows, ma con limiti su wireless e alcuni driver |
| **Dual boot**                              | Avere Kali e un altro sistema sullo stesso disco                                             |
| **Kali NetHunter**                         | Versione per dispositivi Android, per penetration test mobile                                |
| **Container Docker**                       | Ambienti rapidi e usa e getta per singoli strumenti                                          |

Scarica Kali solo dal [sito ufficiale kali.org](https://www.kali.org/get-kali/) e verifica l'hash SHA256 dell'immagine prima di usarla, per essere sicuro di non eseguire una copia alterata.

Per iniziare, la macchina virtuale è quasi sempre la scelta giusta: puoi fare uno snapshot prima di ogni esperimento e tornare indietro senza danni.

## Primi comandi dopo l'installazione

Aggiornare il sistema è il primo passo, perché Kali è una **rolling release**: non ci sono versioni "maggiori" da installare da zero, il sistema si aggiorna continuamente.

```bash
sudo apt update && sudo apt full-upgrade -y
```

Verificare la versione installata:

```bash
cat /etc/os-release
```

Creare un utente non privilegiato per il lavoro quotidiano, invece di operare sempre come root:

```bash
sudo adduser nomeutente
sudo usermod -aG sudo nomeutente
```

Dalla versione 2020.1, Kali non usa più root come utente predefinito: si lavora con un utente normale e si eleva con `sudo` solo quando serve, proprio come su qualsiasi altra distribuzione Linux.

## Kali Linux: l'ultima versione e le novità recenti

Kali segue un ciclo di rilascio trimestrale. L'ultima versione, **Kali 2026.2**, è uscita il **29 giugno 2026** con:

* kernel aggiornato a **Linux 6.19** (il kernel 7.0 è disponibile in anteprima nel repository `kali-experimental`);
* passaggio a **GNOME 50** e **KDE Plasma 6.6** (Xfce resta l'ambiente desktop predefinito);
* **9 nuovi strumenti** nei repository, tra cui `arsenal-ng` (un lanciatore di comandi per pentest con oltre 200 set già pronti) e il ritorno di `hydra-gtk`, l'interfaccia grafica per Hydra;
* tempi di avvio delle macchine virtuali circa tre volte più veloci, grazie alla rimozione del firmware grafico non necessario dalle immagini VM;
* diversi aggiornamenti a **Kali NetHunter**, la piattaforma per penetration test su Android.

Per aggiornare un'installazione esistente basta il comando di aggiornamento visto sopra: non serve reinstallare nulla.

## Kali Linux e certificazioni

Kali è lo strumento standard per le certificazioni Offensive Security, prima fra tutte **OSCP** (Offensive Security Certified Professional), ma anche per OSEP, OSWE e OSED. È inoltre il sistema di riferimento su piattaforme di pratica come **HackTheBox**, **TryHackMe** e **VulnLab**, dove si allenano le tecniche prima di affrontare un esame o un lavoro reale.

## Kali Linux per principianti: è adatto?

Sì, ma non è la distribuzione Linux più semplice da cui partire. Kali è pensato per penetration testing e security auditing; conoscere almeno le basi di Linux, terminale e networking rende molto più facile usarlo. Molti iniziano proprio con Kali in una macchina virtuale, affiancandolo a piattaforme di pratica guidata come HackTheBox o TryHackMe.

## Kali Linux: limiti e cosa NON è

Qualche chiarimento che evita i fraintendimenti più comuni:

* **Non ti rende un hacker da solo**: i tool automatizzano azioni, ma scegliere cosa fare, interpretare i risultati e capire una rete richiede competenza.
* **Non è anonimo**: usare Kali non nasconde il tuo indirizzo IP né le tue attività di rete. È una distribuzione per sicurezza informatica, non uno strumento di anonimizzazione: per quello servono strumenti dedicati come VPN e Tor.
* **Non è una distribuzione desktop general-purpose**: è ottimizzata per penetration testing, security auditing e ricerca sulla sicurezza, non per sostituire Ubuntu o Fedora nel lavoro d'ufficio o nella navigazione quotidiana.
* **Alcuni tool sono rumorosi**: una scansione aggressiva o un bruteforce lasciano tracce evidenti nei log. In un contesto reale va sempre valutato cosa è autorizzato e cosa no.

## Attenzione: dove si può usare Kali

Gli strumenti di Kali vanno usati **solo** su sistemi di tua proprietà, in laboratori dedicati (HackTheBox, TryHackMe, VulnLab) o con autorizzazione scritta esplicita del proprietario del sistema. Scansionare o attaccare un sistema senza permesso è un reato, a prescindere dallo strumento usato: in Italia rientra nell'accesso abusivo a un sistema informatico (art. 615-ter del codice penale).

## Domande frequenti su Kali Linux

### Cos'è Kali Linux?

Una distribuzione Linux basata su Debian, sviluppata da Offensive Security, con strumenti preinstallati per penetration test, analisi forense e sicurezza offensiva.

### Kali Linux è gratis?

Sì, è open source e scaricabile gratuitamente dal sito ufficiale kali.org.

### Serve essere esperti di Linux per usare Kali?

No, ma aiuta molto. Kali è una distribuzione Linux a tutti gli effetti: conoscere terminale, permessi e rete di base rende tutto più semplice.

### Kali Linux è illegale da usare?

No. È il sistema operativo a essere legale: ciò che può essere illegale è usarlo contro sistemi senza autorizzazione.

### Qual è la differenza tra Kali Linux e Parrot OS?

Sono entrambe distribuzioni per sicurezza offensiva basate su Debian, con un set di tool molto simile. Kali è sviluppata specificamente per penetration testing e security auditing ed è il riferimento dell'ecosistema Offensive Security; Parrot ha un'impostazione più general-purpose, pur includendo strumenti per cybersecurity.

### Si può installare Kali Linux su Windows?

Sì, tramite WSL (Windows Subsystem for Linux), anche se alcuni strumenti, soprattutto wireless, funzionano meglio su una macchina virtuale o bare metal.

### Kali Linux rende anonimi su Internet?

No. Non nasconde l'indirizzo IP né le attività di rete. Per l'anonimato servono strumenti specifici come Tor, usati consapevolmente e con i loro limiti.

### Qual è l'ultima versione di Kali Linux?

Kali 2026.2, rilasciata il 30 giugno 2026, con kernel Linux 6.19, GNOME 50, KDE Plasma 6.6 e 9 nuovi strumenti.

### Devo reinstallare Kali a ogni nuova versione?

No. Kali è una rolling release: basta eseguire l'aggiornamento del sistema per restare sulla versione più recente.

### Quali sono i tool più importanti di Kali Linux?

Dipende dall'uso: Nmap per la ricognizione, Burp Suite e SQLmap per il web, Metasploit per l'exploitation, Hashcat per le password, Wireshark per l'analisi del traffico.
