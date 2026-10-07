---
title: 'Botnet: il Caso Mirai e Come Riconoscerne Uno Attivo'
slug: botnet
description: >-
  Cos'è un botnet, come un dispositivo diventa uno zombie controllato a
  distanza, come riconoscerlo e il caso Mirai che mise in crisi mezzo internet
  nel 2016.
image: /botnet-cose-come-funziona-attacchi-hackita.webp
draft: false
date: 2026-10-06T12:11:18.874Z
lastmod: 2026-10-06T12:11:38.117Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Botnet
  - Mirai
  - DDoS
  - IoT
  - Malware
---

# Botnet: Cos'è, Come Funziona e Come si Usa negli Attacchi

Un botnet è una rete di dispositivi infettati e controllati da remoto da uno o più operatori, all'insaputa dei rispettivi proprietari. Ogni dispositivo compromesso — un "bot", spesso chiamato anche **"computer zombie"** proprio per l'idea di un dispositivo che obbedisce a comandi esterni senza che il proprietario se ne accorga — esegue i comandi ricevuti da un'infrastruttura di comando e controllo (C2): anche un botnet relativamente piccolo può essere usato per attività coordinate, ma più dispositivi un operatore controlla, maggiore è la sua capacità di distribuire traffico o richieste — è quello che rende i botnet più grandi capaci di mettere in ginocchio anche i servizi online più grandi al mondo.

> **In breve:** un botnet è una rete di dispositivi compromessi (bot) controllati insieme da un attaccante tramite un'infrastruttura di comando e controllo, usata tipicamente per attacchi DDoS su larga scala, invio massivo di spam o mining di criptovalute.

## Come si Forma un Botnet

Un dispositivo diventa un bot quasi sempre attraverso lo stesso meccanismo visto per altri malware di questo cluster: un [worm](/articoli/worm/) che sfrutta una vulnerabilità di rete, un [trojan](/articoli/trojan/) che l'utente installa credendolo altro, o — nel caso più comune sui dispositivi IoT — semplicemente credenziali di default mai cambiate su router, telecamere di sicurezza e altri dispositivi connessi. Vale la pena distinguere i tre termini che si sovrappongono spesso nel linguaggio comune: il **malware** è il software usato per compromettere il dispositivo, il **bot** è il singolo dispositivo compromesso e sotto controllo, il **botnet** è l'insieme coordinato di bot — un malware non è di per sé un botnet, lo diventa solo quando più dispositivi infetti vengono collegati alla stessa infrastruttura di comando. Una volta compromesso, il dispositivo si registra presso un server di comando e controllo e resta in attesa di istruzioni — un ciclo che si ripete: il bot contatta periodicamente il C2 per chiedere se ci sono comandi, li esegue se presenti, e torna in attesa. È lo stesso identico meccanismo di beaconing usato dai [RAT](/articoli/rat/), solo distribuito su molti dispositivi invece che su uno solo. Spesso senza alcun sintomo visibile per il proprietario: una telecamera IP compromessa continua a funzionare normalmente come telecamera, mentre in background partecipa ad attacchi contro bersagli che il proprietario non ha mai sentito nominare.

## Il Caso Mirai: Quando un Esercito di Telecamere ha Rallentato Mezzo Internet

Il botnet [Mirai](https://www.cyber.nj.gov/threat-landscape/malware/botnets/mirai) resta il caso di studio più istruttivo mai documentato, perché mostra sia la scala del fenomeno sia quanto banale possa essere la causa. Creato nel 2016 da tre studenti universitari — inizialmente, secondo le indagini successive, per ottenere un vantaggio competitivo in un gioco online — Mirai infettava dispositivi IoT (telecamere, videoregistratori digitali, router) provando via Telnet una lista di appena 62 combinazioni di credenziali deboli o lasciate al valore di default: nessun exploit sofisticato, solo dispositivi esposti online senza che le credenziali fossero mai state cambiate.

Il 20 settembre 2016, Mirai colpì il sito del giornalista di sicurezza Brian Krebs con un attacco DDoS da 620 Gbps — il più grande che il suo fornitore di protezione, Akamai, avesse mai gestito fino a quel momento, al punto da costringerlo a interrompere la protezione gratuita che offriva al sito. Pochi giorni dopo l'hosting francese OVH fu colpito da un attacco che superò 1 Tbps, sfruttando circa 145.000 dispositivi compromessi. Il colpo più grave arrivò il 21 ottobre 2016, quando un botnet basato su Mirai attaccò Dyn, uno dei principali fornitori di infrastruttura DNS al mondo: per diverse ore, siti come Twitter, Netflix, Reddit, GitHub e PayPal risultarono irraggiungibili per gran parte della costa orientale degli Stati Uniti — non perché quei siti fossero stati colpiti direttamente, ma perché il servizio che traduceva i loro indirizzi in indirizzi IP era sommerso di traffico.

Poco prima dell'attacco a Dyn, il codice sorgente di Mirai era stato pubblicato online dal suo stesso creatore — una mossa che ha permesso a chiunque di creare varianti del botnet, ed è il motivo per cui derivati di Mirai continuano a comparire ancora oggi, quasi un decennio dopo. Gli autori originali, identificati grazie anche alla loro collaborazione con l'FBI, se la cavarono con una condanna relativamente lieve: libertà vigilata, ore di servizi sociali e un risarcimento — un esito che ha sorpreso non poco la comunità della sicurezza, viste le dimensioni del danno causato.

## Cosa Fa Davvero un Botnet, Oltre al DDoS

L'attacco DDoS è l'uso più noto ma non l'unico:

| Uso                      | Come funziona                                                                                                                                |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Attacco DDoS             | Migliaia di bot inviano traffico simultaneo verso un bersaglio, saturandone la capacità                                                      |
| Invio di spam/phishing   | I bot inviano email massive, spesso più difficili da bloccare perché provengono da migliaia di indirizzi IP diversi e apparentemente innocui |
| Cryptomining             | Sfrutta la potenza di calcolo dei dispositivi infetti per generare criptovalute a beneficio dell'attaccante                                  |
| Credential stuffing      | I bot testano in parallelo credenziali rubate su migliaia di siti diversi                                                                    |
| Proxy per altri attacchi | I dispositivi infetti nascondono la reale origine del traffico di chi li controlla                                                           |

## Come Riconoscere un Dispositivo che Fa Parte di un Botnet

Su un dispositivo IoT (router, telecamera, DVR) un rallentamento della connessione senza causa apparente può essere un primo campanello d'allarme, ma da solo è un segnale debole: dipende da troppi altri fattori (congestione, Wi-Fi, altri dispositivi in rete) per essere una prova. Un indicatore più solido è un traffico di rete costante e anomalo anche quando nessuno sta usando quel dispositivo attivamente, verificabile dal pannello di amministrazione del router — la maggior parte espone una pagina "dispositivi connessi" o "traffico" dove un dispositivo che comunica in continuazione con l'esterno senza motivo apparente salta all'occhio. Su un computer, gli indicatori si sovrappongono a quelli di altri malware di questo cluster: processi sconosciuti, connessioni verso indirizzi IP mai visti prima (visibili con `netstat -ano` su Windows) e, in ambito aziendale, alert da parte di sistemi di monitoraggio della rete su comunicazioni periodiche verso uno stesso server esterno — il classico pattern del "beaconing" verso un'infrastruttura di comando e controllo. Anche qui vale una regola generale: una singola connessione verso un indirizzo sconosciuto non dimostra da sola l'appartenenza a un botnet, serve correlarla con altri segnali.

## Come Proteggersi

La difesa più efficace ed economica contro il diventare parte di un botnet è anche la più trascurata: **cambiare le credenziali di default** su ogni dispositivo connesso a internet, dal router alla telecamera di sicurezza — è esattamente il vettore che ha reso possibile Mirai su centinaia di migliaia di dispositivi. A questo si aggiungono aggiornamenti firmware regolari (i produttori IoT correggono le vulnerabilità sfruttate dai botnet, ma solo chi aggiorna ne beneficia), la disattivazione dell'accesso remoto sui dispositivi che non ne hanno bisogno, e — per chi gestisce una rete aziendale — la segmentazione dei dispositivi IoT su una rete separata da quella con i dati sensibili.

## Pensi che un Tuo Dispositivo Faccia Parte di un Botnet? Verifica Così

1. **Sul router**, accedi al pannello di amministrazione (di solito 192.168.1.1 o 192.168.0.1 dal browser) e controlla la pagina "dispositivi connessi" o "traffico": cerca dispositivi che non riconosci o un consumo dati costante da un dispositivo che dovrebbe essere inattivo.
2. **Sul computer**, esegui `netstat -ano` e cerca connessioni "ESTABLISHED" ripetute verso lo stesso indirizzo IP a intervalli regolari — è il pattern tipico del beaconing verso un server di comando e controllo, anche se da solo non è una prova definitiva.
3. **Riavvia i dispositivi IoT sospetti**: alcune varianti di malware IoT, incluse diverse implementazioni della famiglia Mirai, vivono principalmente in memoria e un riavvio le elimina temporaneamente — ma non è una bonifica reale: se la vulnerabilità o le credenziali di default che hanno permesso l'infezione restano tali, il dispositivo si reinfetta nel giro di minuti.
4. **Se gestisci più dispositivi in un'azienda**, isola quello sospetto dalla rete prima di indagare oltre: un bot attivo che comunica ancora con il suo C2 può ricevere istruzioni per cancellare le proprie tracce.

## FAQ

**Cos'è un botnet?** È una rete di dispositivi infettati e controllati da remoto da uno o più operatori, usata tipicamente per attacchi coordinati su larga scala come DDoS, spam o cryptomining.

**Come diventa un dispositivo parte di un botnet?** Quasi sempre tramite malware come worm o trojan, oppure — specialmente su dispositivi IoT — sfruttando credenziali di default mai cambiate dal proprietario.

**Cos'è successo con l'attacco a Dyn nel 2016?** Il botnet Mirai, composto da centinaia di migliaia di dispositivi IoT compromessi, sommerse di traffico l'infrastruttura DNS di Dyn, rendendo temporaneamente irraggiungibili siti come Twitter, Netflix e Reddit per gran parte della costa orientale statunitense.

**Il mio dispositivo può far parte di un botnet senza che io me ne accorga?** Sì, ed è anzi il caso più comune: un dispositivo IoT compromesso continua a funzionare normalmente per il suo scopo dichiarato, mentre partecipa in background alle attività del botnet.

**Come proteggo i miei dispositivi IoT da un botnet?** Cambiando le credenziali di default appena installati, mantenendo il firmware aggiornato e disattivando l'accesso remoto quando non serve — sono tra le principali misure che avrebbero impedito molte delle compromissioni sfruttate da Mirai.
