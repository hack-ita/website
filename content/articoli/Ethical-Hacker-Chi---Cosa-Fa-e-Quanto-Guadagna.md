---
title: 'Ethical Hacker: Chi è , Cosa Fa e Quanto Guadagna'
slug: ethical-hacker
description: 'Chi è un ethical hacker, cosa fa ogni giorno, quali competenze e strumenti usa, quanto guadagna in Italia e come diventarlo passo dopo passo.'
image: /ethical-hacker-cose-cosa-fa.webp
draft: true
date: 2026-09-23T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - ethical hacker
  - hacker etico
  - penetration tester
  - red team
  - certificazioni
---

# Ethical Hacker: Cos'è e Cosa Fa

Un ethical hacker usa esattamente le tecniche di un attaccante — enumerazione, exploitation, privilege escalation — ma sempre con autorizzazione esplicita e per un obiettivo dichiarato: migliorare la sicurezza di un sistema, non comprometterlo. È, in pratica, qualcuno pagato da un'azienda per entrare nei propri sistemi senza permesso — sulla carta un controsenso, nella pratica l'unica cosa che separa una carriera da una denuncia.

## Ethical Hacker vs Hacker: la Differenza in una Frase

"Hacker" è un termine ampio e neutro, riferito a chi ha competenze tecniche avanzate su sistemi e software, a prescindere da come le usa. "Ethical hacker" restringe il campo a chi le usa sempre con permesso, dentro uno scope concordato, con l'obiettivo di segnalare — non sfruttare a proprio vantaggio — le vulnerabilità trovate. Per la classificazione completa dei vari "colori" di hacker, vedi [White Hat, Black Hat e Grey Hat: le Differenze](https://hackita.it/articoli/white-hat-black-hat-grey-hat/).

Definito il confine, resta da capire come si traduce in pratica in una giornata di lavoro.

## Cosa Fa Concretamente un Ethical Hacker

Il lavoro si svolge quasi sempre dentro un incarico con scope, tempistiche e regole d'ingaggio definite per iscritto, spesso seguendo metodologie riconosciute come la [OWASP Web Security Testing Guide](https://owasp.org/projects/web-security-testing-guide) per la parte web. Le fasi tipiche:

1. **Ricognizione** — raccolta di informazioni pubbliche ed enumerazione dei sistemi in scope
2. **Scanning e vulnerability assessment** — identificazione di servizi, versioni e possibili vettori
3. **Exploitation** — sfruttamento controllato delle vulnerabilità trovate, per dimostrarne l'impatto reale
4. **Post-exploitation** — [escalation dei privilegi](https://hackita.it/articoli/windows-privilege-escalation/) e movimento laterale, per verificare fin dove un attaccante reale potrebbe arrivare da quel punto
5. **Reporting** — documentazione dettagliata di ogni finding, impatto stimato e raccomandazioni di rimedio

Il reporting non è un dettaglio amministrativo: è spesso la parte su cui viene giudicata la qualità del lavoro, perché è quello che il cliente userà davvero per correggere i problemi.

Tutto questo si muove dentro un perimetro preciso. Un ethical hacker può testare, sfruttare vulnerabilità in modo controllato e documentare tutto quello che trova — ma solo dentro i sistemi in scope. Non può uscire da quel perimetro, conservare o usare dati oltre quanto previsto dall'incarico, né continuare ad accedere ai sistemi una volta chiusa l'attività: sono esattamente le condizioni che separano il lavoro da un reato, viste dal lato di chi lo pratica ogni giorno. Ma "ethical hacker" è un ombrello che copre ruoli piuttosto diversi tra loro, a seconda di come queste fasi vengono applicate.

## Le Specializzazioni Principali

* **Penetration tester** — test strutturati a scope definito, generalmente su incarico diretto di un cliente
* **Red teamer** — simulazione di un attacco reale e prolungato, spesso senza avvisare il team di difesa (blue team)
* **Bug bounty hunter** — ricerca indipendente di vulnerabilità su programmi pubblici, pagato a risultato
* **Security researcher** — ricerca di tecniche e vulnerabilità nuove, spesso pubblicata per la comunità

Nella pratica i ruoli si sovrappongono spesso — un penetration tester lavora a volte anche in red team quando l'incarico lo richiede — ma la differenza di fondo è l'obiettivo dell'ingaggio: coprire quante più vulnerabilità possibile (pentest) contro testare la capacità di rilevamento e risposta di un'organizzazione (red team). Qualunque sia la specializzazione, però, sotto ci sono sempre le stesse competenze di base.

## Quali Competenze Servono

* **Fondamenta** — networking, i due sistemi operativi principali (Windows e Linux), autenticazione
* **Offensive security** — enumeration, vulnerability assessment, exploitation, privilege escalation, Active Directory, web security
* **Scripting** — Python su tutti, utile anche Bash e PowerShell per automatizzare e adattare exploit esistenti
* **Comunicazione** — reporting chiaro per un pubblico non tecnico, spesso sottovalutato rispetto alla parte "offensiva"

## Quali Strumenti Usa

Variano per specializzazione, ma un nucleo ricorre quasi ovunque: [Nmap](https://hackita.it/articoli/nmap/) per l'enumerazione di rete, [Burp Suite](https://hackita.it/articoli/burp-suite/) e ffuf per il web, [Metasploit](https://hackita.it/articoli/metasploit/) per l'exploitation, [BloodHound](https://hackita.it/articoli/bloodhound/) e Certipy per attacchi in ambienti Active Directory, Hashcat e John the Ripper per il cracking di hash e password.

## Ethical Hacker vs Cybersecurity

Non sono sinonimi: la cybersecurity è il campo ampio che comprende anche difesa (SOC, incident response, threat hunting), governance e vulnerability management. L'ethical hacking — e con esso il penetration testing, il red teaming, la ricerca di vulnerabilità — è una parte specifica di quel campo, quella orientata all'attacco simulato piuttosto che alla difesa. Resta però un requisito che clienti e datori di lavoro chiedono quasi sempre per crederci sulla parola.

## Ethical Hacker: Serve una Certificazione?

Non è obbligatoria per legge, ma nella pratica viene spesso richiesta da clienti e datori di lavoro come prova verificabile delle competenze. CEH (Certified Ethical Hacker) è tra le più conosciute a livello generalista, ma non l'unica strada: il confronto completo, con tabella delle certificazioni e tempi realistici, è in [Come Diventare Ethical Hacker: la Guida Pratica](https://hackita.it/articoli/come-diventare-ethical-hacker/).

## FAQ

**Cosa fa un ethical hacker nella pratica quotidiana?** Enumerazione di sistemi, ricerca di vulnerabilità, sfruttamento controllato per dimostrarne l'impatto, e un report finale con raccomandazioni — non "attacchi" isolati, ma un processo strutturato con uno scope definito.

**Qual è la differenza tra ethical hacker e penetration tester?** Ethical hacker è la categoria generale — chiunque operi con autorizzazione a scopo difensivo. Penetration tester è uno dei ruoli specifici dentro quella categoria, focalizzato su test strutturati a scope definito.

**Un ethical hacker deve saper programmare?** Non è obbligatorio per iniziare, ma diventa presto necessario: leggere codice per capire una vulnerabilità, adattare un exploit pubblico o scrivere uno script di automazione sono attività quotidiane del ruolo.

**Quanto guadagna un ethical hacker?** Varia molto in base a esperienza, ruolo, settore e paese — i dati salariali vanno letti considerando sempre mercato e seniority, più che una cifra unica valida ovunque.

**Serve una laurea per diventare ethical hacker?** Non è obbligatoria: competenze pratiche, laboratori, portfolio e certificazioni sono quello che il settore usa davvero per valutare le capacità di un candidato.

**Dove lavora un ethical hacker?** Aziende di cybersecurity, società di consulenza, team di sicurezza interni ad aziende più grandi (banche, fintech, software house), oppure da freelance su bug bounty e incarichi diretti.

**L'ethical hacking è legale?** Sì, ma solo con autorizzazione esplicita e dentro lo scope concordato — le buone intenzioni da sole non bastano, serve il permesso scritto del proprietario del sistema. Il quadro legale completo, comprese le conseguenze di uscire dallo scope, è nell'articolo [Hacker: Cos'è, Tipi di Hacker e Come Diventare Hacker Etico](https://hackita.it/articoli/hacker/).
