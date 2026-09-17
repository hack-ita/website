---
title: 'Hacker: Significato, Tipi (White Hat, Black Hat) e Cracker'
slug: hacker
description: 'Cos''è un hacker, la differenza con cracker ed ethical hacker, i tipi (white, black, grey hat), quando hackerare è reato e come diventare hacker etico.'
image: /hacker.webp
draft: false
date: 2026-09-18T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - hacker
  - hacker etico
  - white hat
  - black hat
  - cracker
---

# Hacker: Cos'è, Tipi di Hacker e Come Diventare Hacker Etico

Nei film un hacker digita a raffica per trenta secondi e viola qualsiasi sistema al mondo. Nella realtà, un hacker è semplicemente una persona che studia a fondo il funzionamento di sistemi informatici, reti e software per trovarne i limiti — spesso oltre quello che i progettisti avevano previsto. Il termine di per sé non implica nulla di illegale: descrive una competenza tecnica, non un reato. È l'uso che se ne fa a determinare se dietro c'è un professionista della sicurezza o un criminale informatico, ed è proprio questa ambiguità a generare la maggior parte della confusione attorno alla parola — la stessa che si ritrova nei suoi sinonimi italiani, **pirata informatico** e **hacker informatico**.

## Hacker: Il Significato Originale

Il termine nasce negli anni '60 nei laboratori del MIT, dove indicava chi trovava soluzioni creative e non ovvie a problemi tecnici — un "hack" era un'idea ingegnosa, non un attacco. Il [Jargon File](https://www.catb.org/jargon/html/H/hacker.html), il dizionario storico dello slang hacker mantenuto dalla comunità tecnica fin dagli anni '70, registra ancora oggi questa accezione originale come la prima e più autentica, relegando il significato "criminale informatico" a un uso "deprecato" per cui il termine corretto resterebbe cracker. Solo più tardi, con la diffusione dei primi accessi non autorizzati a sistemi informatici negli anni '80, i media hanno iniziato a usare "hacker" come sinonimo di criminale informatico, un'accezione che nella comunità tecnica resta ancora oggi contestata.

Da qui la comunità stessa ha sentito il bisogno di distinguere ruoli diversi — a partire da una divisione più vecchia della stessa terminologia "hat" che vediamo oggi: quella tra hacker e cracker.

## Hacker vs Cracker: la Differenza che Conta

Nel gergo tecnico originale, l'hacker è chi esplora e comprende i sistemi per curiosità o per migliorarli; il **cracker** è chi usa le stesse competenze per violare sistemi altrui senza autorizzazione. È un termine storico, nato nella stessa comunità che ha coniato "hacker" per marcare la distinzione — oggi nella cybersecurity professionale è più comune parlare di **black hat**, o semplicemente di **cybercriminale** nel linguaggio giornalistico, anche se i tre termini non sono perfettamente intercambiabili. Per l'approfondimento completo: [White Hat, Black Hat e Grey Hat: le Differenze](https://hackita.it/articoli/white-hat-black-hat-grey-hat/).

Quella distinzione binaria, però, è troppo semplice per descrivere davvero chi opera nel settore oggi. Nel tempo si sono aggiunte sfumature, ognuna con un proprio "colore".

## I Tipi di Hacker

In sintesi, prima di guardarli uno per uno:

* **White Hat (hacker etico)** — opera sempre con autorizzazione esplicita, per migliorare la sicurezza
* **Black Hat** — accede senza autorizzazione per profitto o danno, spesso tramite [virus o ransomware](https://hackita.it/articoli/virus-informatico/); in Italia può integrare il reato di accesso abusivo a sistema informatico (art. 615-ter c.p.), a cui si possono aggiungere altre fattispecie a seconda di cosa viene fatto una volta dentro
* **Grey Hat** — via di mezzo ambigua, agisce senza permesso ma senza intento dannoso; l'assenza di intento malevolo non equivale però ad avere un'autorizzazione, e la legalità dipende comunque dalla giurisdizione
* **Blue Hat, script kiddie, hacktivist, state-sponsored** — categorie minori che usano criteri diversi tra loro (invito, competenza, motivazione, affiliazione) più che una scala comune di autorizzazione, e non sono terminologie standardizzate allo stesso livello di White/Black/Grey Hat

| Tipo      | Autorizzazione | Obiettivo               | Attività tipica                             |
| --------- | -------------- | ----------------------- | ------------------------------------------- |
| White Hat | Sì             | Migliorare la sicurezza | Penetration test, security assessment       |
| Black Hat | No             | Profitto o danno        | Furto dati, ransomware, frode               |
| Grey Hat  | Ambigua        | Ricerca non richiesta   | Vulnerability research senza autorizzazione |

Ruoli come red teamer e bug bounty hunter non sono altri "colori": sono professioni che si esercitano dentro la categoria white hat, con obiettivi diversi tra loro — se ne parla nel dettaglio più avanti.

Per l'approfondimento completo, con esempi e sfumature legali di ciascuna categoria: [White Hat, Black Hat e Grey Hat: le Differenze](https://hackita.it/articoli/white-hat-black-hat-grey-hat/).

Sapere a quale "colore" appartiene chi opera con permesso non basta, però, a capire cosa fa davvero sul lavoro: qui i titoli professionali si moltiplicano, e vale la pena distinguerli.

## Ethical Hacker, Penetration Tester, Red Teamer: Ruoli Diversi

I termini si sovrappongono nel linguaggio comune ma indicano ruoli distinti — un ethical hacker può lavorare come penetration tester, red teamer, bug bounty hunter o security researcher a seconda dell'obiettivo dell'incarico. Il quadro completo, con le differenze tra ciascun ruolo: [Ethical Hacker: Cos'è e Cosa Fa](https://hackita.it/articoli/ethical-hacker/).

Al di là dell'etichetta specifica, la giornata tipo di chi lavora in questo campo si somiglia parecchio.

## Cosa Fa Davvero un Hacker (Professionista)

Il lavoro quotidiano di un hacker etico è meno cinematografico di quanto suggerisca la parola. In pratica: enumerazione di sistemi e servizi esposti con strumenti come [Nmap](https://hackita.it/articoli/nmap/), ricerca di misconfigurazioni e vulnerabilità note, sviluppo o adattamento di exploit, [escalation dei privilegi](https://hackita.it/articoli/windows-privilege-escalation/), movimento laterale — spesso dentro un dominio [Active Directory](https://hackita.it/articoli/active-directory/) — e, alla fine, un report dettagliato con impatto e raccomandazioni per il cliente. La parte di scrittura e comunicazione occupa spesso più tempo di quella "offensiva" vera e propria.

Le competenze che servono davvero: reti (TCP/IP, protocolli), sistemi operativi (Windows e Linux a fondo), almeno un linguaggio di scripting (Python è lo standard), basi di programmazione per capire il codice che si sta attaccando, e — spesso sottovalutato — capacità di scrivere report chiari per un pubblico non tecnico.

Se tutto questo — trovare vulnerabilità, sfruttarle in modo controllato, documentarle — suona come qualcosa che vorresti fare per lavoro, la domanda naturale è da dove iniziare.

## Come Diventare un Hacker Etico

Il percorso più comune parte dalle fondamenta (reti, sistemi operativi, un linguaggio di scripting), passa per la pratica in ambienti legali come HackTheBox o TryHackMe, arriva a una certificazione pratica riconosciuta — OSCP, CRTO e CPTS su tutte — e si consolida con una specializzazione ([web application security](https://hackita.it/articoli/attacchi-applicazioni-web/), [Active Directory](https://hackita.it/articoli/active-directory/), mobile, cloud). Non serve una laurea specifica: contano competenze dimostrabili, e una certificazione pratica o una writeup di CTF pesano più di un titolo di studio generico.

La guida passo-passo completa, con la tabella delle certificazioni, i tempi realistici e gli errori più comuni da evitare: [Come Diventare Ethical Hacker: la Guida Pratica](https://hackita.it/articoli/come-diventare-ethical-hacker/).

C'è però un prerequisito che viene prima di qualsiasi competenza tecnica, ed è quello su cui si gioca davvero la differenza tra una carriera e una denuncia.

## Hacker Etico: è un Lavoro Legale?

Sì, ma non basta la buona fede: **autorizzazione scritta** e **scope definito** (cosa si può testare, cosa no, in che finestra temporale) sono gli elementi che distinguono un test autorizzato da un accesso abusivo — la valutazione giuridica esatta dipende comunque dalle circostanze concrete e dalla normativa applicabile. Senza questo documento, anche testare la sicurezza di un sito con le migliori intenzioni può configurare un accesso abusivo a sistema informatico: il rischio legale esiste a prescindere dalle intenzioni dichiarate.

Un caso concreto in cui questo confine viene superato più spesso di quanto si pensi — quasi sempre per semplice curiosità, non per reale intenzione criminale — riguarda proprio il wifi di casa.

## Hacker Wifi: Perché Craccare una Password Altrui è Reato

Una delle ricerche più comuni legate al termine è "hacker wifi" — nella maggior parte dei casi dietro c'è la curiosità di sapere quanto sia sicura la propria rete, non l'intenzione di violarne una altrui. Vale la pena essere diretti su questo: accedere alla rete WiFi di un vicino o di un'attività senza permesso rientra nello stesso reato di accesso abusivo a sistema informatico visto sopra, indipendentemente dalla tecnica usata o dal fatto che la password sia debole.

Il punto debole storico è stato il **WPS** (Wi-Fi Protected Setup): il suo PIN a 8 cifre, per un difetto di design, può essere ridotto a due metà attaccabili separatamente via brute-force, rendendolo violabile in poche ore anche con hardware modesto. Il protocollo **WPA2**, se usa una passphrase debole o riutilizzata, resta esposto ad attacchi a dizionario sull'handshake catturato al volo. **WPA3**, lo standard attuale, chiude gran parte di questi vettori grazie al protocollo SAE, che rende inutile catturare l'handshake per un attacco offline.

Per chi vuole solo proteggere la propria rete, le contromisure concrete sono poche e note: disattivare il WPS dal pannello del router, usare WPA3 se il dispositivo lo supporta (WPA2 con passphrase lunga e casuale altrimenti), e cambiare le credenziali di amministrazione del router dai valori di default — il vettore più sfruttato in assoluto non è mai la cifratura del WiFi, ma un pannello di gestione ancora protetto da "admin/admin".

## FAQ

**Cosa vuol dire hacker?** È chi possiede competenze tecniche avanzate per comprendere e manipolare sistemi informatici oltre il loro uso previsto. Il termine è neutro: diventa "buono" o "cattivo" solo in base a intento e autorizzazione.

**Che differenza c'è tra hacker e hacking?** Hacker è la persona; hacking è la pratica, l'insieme di tecniche che quella persona usa. Esattamente come "hacker", anche "hacking" è neutro finché non si specifica il contesto: può indicare un penetration test autorizzato o un attacco criminale.

**Cosa significa essere stato hackerato?** Vuol dire che un sistema, un account o un dispositivo di cui si è responsabili è stato compromesso tramite un accesso non autorizzato — la conseguenza pratica del lavoro di un black hat o di un cracker, vista dal lato di chi la subisce.

**Qual è la differenza tra hacker e cracker?** Nel gergo tecnico originale, l'hacker esplora e comprende, il cracker viola senza permesso per danneggiare o trarne profitto. Nel linguaggio comune i due termini si sono fusi.

**Cosa significa hackerare?** Accedere o manipolare un sistema informatico sfruttandone una vulnerabilità. Può essere legale (in un penetration test autorizzato) o illegale (accesso abusivo), a seconda esclusivamente dell'autorizzazione.

**Si può diventare hacker senza laurea?** Sì. Il settore valuta soprattutto competenze dimostrabili — certificazioni pratiche come l'OSCP, writeup di CTF, un profilo HackTheBox attivo — più della formazione accademica.

**Qual è la certificazione più richiesta per diventare hacker etico?** Dipende dal ruolo, dall'esperienza e dal mercato di riferimento più che da un unico standard universale: CEH è il punto di ingresso più conosciuto a livello generalista, mentre OSCP, CPTS e CRTO sono le certificazioni pratiche più citate per ruoli operativi — il confronto completo è nella guida dedicata.

**Cosa può fare un hacker con il mio numero di telefono o il mio indirizzo IP?** Da solo, un numero di telefono permette soprattutto attacchi di ingegneria sociale (SIM swap, phishing mirato via SMS); un indirizzo IP dà un'indicazione approssimativa di zona geografica e, se il dispositivo espone servizi vulnerabili verso l'esterno, un punto di partenza per la scansione — ma nessuno dei due dati da solo consente un accesso diretto a un dispositivo aggiornato e configurato correttamente.

**Quanto guadagna un hacker etico?** Varia molto in base a esperienza, ruolo, settore e paese — i dati salariali vanno letti considerando sempre mercato e seniority, più che una cifra unica valida ovunque.

**Un white hat può finire nei guai legali?** Sì, se esce dallo scope autorizzato o non rispetta le condizioni concordate — l'autorizzazione copre solo quello che è stato messo per iscritto, non ogni azione compiuta durante l'incarico.
