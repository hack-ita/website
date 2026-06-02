---
title: 'HTB ProLab Dante: Review Completa 2025 – Vale la Pena Farlo?'
slug: htb-proloab-dante
description: 'Review HTB ProLab Dante: struttura del lab, punti di forza sul pivoting, problemi reali con OS datati e CVE unintended. A chi serve davvero e quando saltarlo.'
image: /htb-prolab-dante.webp
draft: false
date: 2026-06-02T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - medium
tags:
  - prolabs
---

# HTB ProLab Dante – Review Completa: Vale Davvero la Pena?

Se stai cercando il tuo primo ProLab su Hack The Box, la risposta che trovi ovunque è sempre la stessa: *"Inizia da Dante."* Giusto, ma è tutto oro quello che luccica? In questa review ti dico esattamente cosa aspettarti — senza filtri e senza hype.

***

## Struttura del Lab

Dante è il ProLab entry-level di HTB, classificato come **Penetration Tester Level I**. Simula un'infrastruttura aziendale fittizia con macchine Windows e Linux distribuite su **più subnet segmentate**, raggiungibili solo tramite pivoting progressivo a partire da un unico punto d'ingresso.

I numeri:

* **14 macchine** (mix Windows/Linux, \~7 Linux e \~6 Windows)
* **27 flag** in formato `DANTE{...}`
* **Più subnet interne** non accessibili direttamente dalla VPN
* Accesso $49/mese (subscription flat che include tutti i ProLab attivi)

***

## Il Problema Principale: L'Aging dei Sistemi

Partiamo dalla nota dolente, perché è quella che cambia tutto il resto.

**I server Windows in Dante sono tutti Windows Server 2012 R2, non patchati.** Non è una stima — è la realtà confermata da chi ha fatto il lab. Il risultato è che CVE pubblicate negli anni successivi alla creazione del lab permettono di compromettere macchine bypassando completamente le challenge che i designer avevano in mente.

Esempio concreto: su almeno una macchina, l'intended path era fare privilege escalation attraverso un binary custom da reverserare o debuggare. In pratica? Basta lanciare `getsystem` da Meterpreter e sei SYSTEM in due secondi. L'OS vecchio regala i permessi senza che tu debba capire nulla.

**Sui Linux è peggio ancora.** Quasi tutte le macchine Linux del lab sono vulnerabili a **CVE-2021-3560** (polkit privilege escalation). Un tool come [Traitor](https://github.com/liamg/traitor) identifica e sfrutta automaticamente questa e altre vuln da OS aging. Il che significa che su molti target la vera sfida è solo l'initial foothold — il privesc è automatico.

Questo è il difetto strutturale di Dante: non è che sia diventato facile perché si è capito meglio, è che è diventato facile perché il tempo ha rotto le challenge dall'esterno.

***

## Come Si Approccia il Lab: Metodologia e Tool

Prima di entrare nei dettagli tecnici, vale la pena parlare di come si lavora concretamente in Dante — perché il metodo qui conta quanto le skill.

### Enumerazione iniziale

Il punto d'ingresso è una singola subnet esposta. Da lì devi scoprire tutto. I tool che funzionano meglio in questo contesto:

**RustScan** per la scansione iniziale delle porte: è molto più veloce di nmap su reti multi-host e ti dà subito una panoramica di cosa gira dove. Poi passi a nmap per i dettagli su porte specifiche.

**Nuclei** con template aggiornati: su macchine datate come quelle di Dante, una scansione Nuclei a volte restituisce hit diretti su CVE con exploit pubblici. Non è un caso — è proprio l'aging di cui parlavamo.

**Gobuster** con le wordlist raft di SecLists: la superficie web in Dante è ampia. Directory busting su ogni macchina che espone HTTP è obbligatorio, non optional. Molti foothold passano da lì.

### Gestione delle credenziali

Questo è uno dei meccanismi centrali di Dante che quasi nessuna review spiega bene: **il credential reuse è onnipresente**. Ogni coppia username/password che trovi su una macchina va testata su tutte le altre. Subito. Prima di andare avanti.

**NetExec (ex CrackMapExec)** è il tool per farlo in modo sistematico — spraying su SMB, WinRM, SSH su tutta la subnet raggiungibile. Con credenziali admin ottieni accesso a share SMB con loot ulteriore o movimento laterale diretto.

Un avvertimento concreto: **controlla sempre la lockout policy prima di fare spray**. In Dante ci sono ambienti AD con lockout configurato. Sbloccare account per sbaglio durante il lab è un modo efficace per bloccarsi da soli su percorsi critici.

### Note-taking: non è optional

A tre hop di profondità, con credenziali diverse per ogni macchina e subnet multiple aperte, **senza documentazione sei già perso**. Non è una questione di stile — è una questione di sopravvivenza nel lab.

Il minimo indispensabile per ogni macchina compromessa:

* IP e hostname
* Credenziali trovate (utente, password, hash)
* Servizi esposti e porte
* Subnet raggiungibili da quel pivot
* Tunnel attivi (tool, porta locale, porta remota)

Obsidian e CherryTree sono entrambi buoni. Anche un semplice file markdown funziona. L'importante è avere tutto in un unico posto aggiornato in tempo reale — quando un tunnel cade alle 2 di notte e devi ricostruire la catena, le note sono l'unica cosa che ti salva.

***

## Il Punto di Forza Reale: Il Pivoting

Qui Dante brilla e non ci sono discussioni.

Se arrivi da box singole HTB, qui hai il tuo primo contatto reale con reti segmentate multi-livello. Non stai imparando il pivoting in teoria — stai costruendo catene di tunnel reali su più hop, gestendo instabilità, ricostruendo connessioni quando cadono.

Gli strumenti che userai concretamente:

* **Chisel** — tunnel TCP/UDP over HTTP, utile quando SSH è bloccato ma HTTP passa. Diventa scomodo su pivot profondi perché introduce lag e instabilità, specialmente se lo passi dentro un Meterpreter.
* **SSH port forwarding** — quando SSH è disponibile, resta la scelta più stabile
* **sshuttle** — comodo per routing trasparente, ma vuole SSH sul pivot
* **Metasploit SOCKS proxy** — utile per integrare il routing con exploit MSF, ma aggiunge overhead
* **Ligolo-ng** — se non lo conosci ancora, è probabilmente il tool più comodo per Dante: crea una TUN interface vera invece di appoggiarsi a SOCKS, il che significa che puoi usare nmap direttamente senza proxychains

> Per una guida pratica su Chisel e su quando usarlo rispetto a Ligolo, leggi [Chisel: TCP Tunneling over HTTP per Pivoting e Post-Exploitation](https://hackita.it/articoli/chisel/) su HackIta.

Il punto critico che molti sottovalutano: **un Meterpreter che fa routing attraverso un tunnel Chisel è lento e instabile**. Se vuoi usare MSF su macchine interne, devi gestire bene la catena o ti ritrovi con sessioni che muoiono nel momento sbagliato.

Disegnare un diagramma di rete aggiornato in tempo reale — anche solo su carta o su Draw\.io — non è optional in Dante. A tre livelli di pivot senza una mappa visiva sei già perso.

***

## Active Directory: C'È, Ma Non È il Focus

Il componente AD di Dante è reale ma limitato. Trovi enumerazione con BloodHound, misconfigurazioni classiche da sfruttare, credential spraying su SMB e WinRM tramite NetExec. Il dominio è presente e funzionante, e arrivare a compromettere il Domain Controller richiede di passare attraverso più macchine intermedie — il che significa che l'AD si intreccia con il pivoting in modo organico.

BloodHound è utile ma non ti dà tutto su un piatto: devi comunque capire cosa stai guardando e come collegare i nodi. Se non hai mai usato BloodHound su un dominio reale, qui fai pratica concreta in un contesto abbastanza guidato.

Quello che non trovi: Kerberoasting avanzato, ACL abuse, RBCD, attacchi cross-domain, delegation chains. Quello è territorio di Zephyr e Offshore — livelli completamente diversi di complessità AD.

***

## Web Application Attacks e Exploit Development

Il lato web è la superficie d'attacco principale per l'initial foothold su molte macchine. I vettori che trovi sono classici ma variegati: SQLi, RCE tramite file upload, applicazioni con autenticazione debole, virtual host nascosti che non vengono fuori senza directory busting aggressivo. Burp Suite è utile ma non indispensabile su tutto — molti foothold si fanno anche a mano una volta capito il pattern.

Una cosa concreta: **alcune macchine espongono servizi su porte non standard**. Se la tua scansione iniziale è pigra e copre solo le porte top-1000, ti perdi roba. Scansione completa all ports su ogni target, sempre.

Sui **buffer overflow**: presenti sia su Windows che su Linux, ma a livello elementare — vanilla stack overflow senza stack canary, senza ASLR significativo, senza SEH. Il valore didattico c'è se non hai mai scritto uno shellcode da zero o non hai mai calcolato un offset a mano. Se invece hai già fatto il modulo BoF dell'OSCP vecchio stile, qui non impari nulla di nuovo. Se punti a OSED, questo non ti prepara minimamente.

***

## Stabilità, Tempo e Aspettative

Un problema reale che non trovi quasi mai menzionato nelle review positive: **la stabilità delle connessioni non è sempre affidabile**. Tunnel che cadono, macchine che rispondono male dopo un reset, pivot che smettono di funzionare senza una ragione ovvia.

Non è una costante, ma succede abbastanza da essere parte dell'esperienza. E quando sei a tre hop di profondità e la catena crolla, ricostruire tutto senza note dettagliate è un disastro.

Sul tempo: chi completa Dante in una settimana di solito lo fa con metodo solido già consolidato. Chi arriva da zero ci mette 3-4 settimane. Non è un indicatore di bravura — è semplicemente che il lab richiede esplorazione, e l'esplorazione richiede tempo. Non c'è una kill chain lineare da seguire: alcune macchine le trovi solo quando ne hai compromessa un'altra che le rivela. Questo è uno degli aspetti più realistici del lab.

***

## A Chi Serve Dante

**Lo fa per te se:**

* Hai già qualche box HTB o TryHackMe alle spalle e vuoi passare a una rete
* Stai preparando OSCP, eCPPT o eJPT e vuoi pratica concreta su pivoting e metodologia
* Non hai mai gestito una rete segmentata multi-host in autonomia
* Vuoi costruire l'abitudine a documentare e lavorare su più target in parallelo

**Non ti serve se:**

* Hai già esperienza solida su AD — Zephyr o Offshore ti danno un salto di qualità netto
* Cerchi exploit development serio
* Sei già OSCP e stai puntando a OSCE3
* Vuoi un ambiente con OPSEC, AV evasion e detection reale

***

## Il Verdetto

Dante è un buon primo ProLab. Ma la sua reputazione online è gonfiata rispetto a quello che offre effettivamente nel 2025.

Il vero valore è nel **pivoting**: esci con la capacità di gestire reti segmentate, catene di tunnel, e un metodo di lavoro ordinato. Se arrivi senza mai aver fatto pivoting su reti multi-subnet, quel salto da solo vale il prezzo del mese.

Il problema è che l'aging dei sistemi ha distrutto una parte del valore didattico originale. Le challenge di privesc che avrebbero dovuto insegnarti qualcosa si risolvono con CVE pubbliche e tool automatici. HTB non ha aggiornato le macchine, e si vede.

| Categoria                  | Voto  |
| -------------------------- | ----- |
| Pivoting e networking      | ★★★★★ |
| Active Directory           | ★★★☆☆ |
| Exploit development        | ★★☆☆☆ |
| Realismo dell'ambiente     | ★★★☆☆ |
| Valore prep certificazioni | ★★★★☆ |
| Rapporto qualità/prezzo    | ★★★★☆ |

**Voto complessivo: 7/10**

Fondamentale per chi parte dal basso. Optional per chi ha già le basi. Se sai già cosa fai, valuta direttamente Zephyr — il salto è netto e ti prepara su terreno molto più realistico.

***

*Hai già completato Dante e vuoi sapere qual è il passo successivo nel percorso OSCP → OSCE3? Leggi i nostri walktrough e scopri le migliori VM in ordine di difficoltà.*
