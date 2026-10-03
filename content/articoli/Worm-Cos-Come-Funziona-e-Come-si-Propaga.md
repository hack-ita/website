---
title: 'Worm: Cos''è, Come Funziona e Come si Propaga'
slug: worm
description: 'Scopri cos''è un worm informatico, come funziona e si propaga, le differenze con virus e ransomware, i casi famosi e come riconoscere un''infezione sulla rete.'
image: /worm-informatico-come-funziona-propagazione.webp
draft: true
date: 2026-10-11T12:13:36.016Z
lastmod: 2026-10-11T12:13:37.753Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - worm informatico
  - malware
  - virus informatico
  - ransomware
---

# Worm Informatico: Cos'è, Come si Diffonde e Differenze dal Virus

Un worm è un tipo di malware che si replica e si diffonde autonomamente attraverso una rete, senza bisogno di un file ospite. Questa capacità gli permette di diffondersi molto rapidamente, soprattutto quando sfrutta vulnerabilità presenti su numerosi sistemi contemporaneamente: mentre un virus resta fermo finché qualcuno non apre il file infetto, un worm può propagarsi da un sistema all'altro senza bisogno di alcuna azione umana. Un worm non è definito dal danno che provoca, ma dal modo in cui si propaga: il payload può essere distruttivo, rubare informazioni, installare altro malware o persino essere assente — quello che lo caratterizza è la capacità di diffondersi da solo.

> **In breve:** un worm è un malware capace di propagarsi autonomamente tra sistemi, spesso sfruttando vulnerabilità di rete o altri vettori di comunicazione. A differenza di un virus, non necessita di un file ospite per replicarsi.

## Come Funziona un Worm

Per capire il comportamento di un worm si può usare un modello concettuale in cinque fasi — non tutti i worm le seguono però nello stesso modo o nello stesso ordine:

1. **Discovery** — individua potenziali bersagli, scansionando una rete o leggendo la rubrica contatti del dispositivo infetto
2. **Exploitation** — sfrutta una vulnerabilità di rete o un altro vettore per ottenere accesso al bersaglio
3. **Replication** — copia il proprio codice sul nuovo sistema
4. **Propagation** — da lì riparte la ricerca di altri bersagli, spesso in parallelo su più sistemi contemporaneamente
5. **Payload** — esegue l'azione per cui è stato progettato, se ne ha una

## Worm vs Virus: la Differenza che Conta

È la confusione più comune sull'argomento, e la distinzione è netta. Un [virus](https://hackita.it/articoli/virus-informatico/) ha bisogno di un file ospite a cui agganciarsi e della sua esecuzione, di solito innescata da un utente che lo apre. Un worm non ha bisogno di un file ospite: è un programma completo e indipendente che si copia da solo da un sistema all'altro, tipicamente sfruttando una vulnerabilità di rete o i contatti trovati sul dispositivo infetto — anche se, a seconda del vettore, alcune modalità di diffusione (come l'apertura di un allegato email infetto) restano legate a un'azione su un sistema di destinazione.

|                         | Worm                                                                    | Virus                              |
| ----------------------- | ----------------------------------------------------------------------- | ---------------------------------- |
| Serve un file ospite    | No                                                                      | Sì                                 |
| Si diffonde da solo     | Sì, in autonomia sulla rete                                             | No                                 |
| Azione umana necessaria | Dipende dal vettore — spesso nessuna, a volte l'apertura di un allegato | Sì — deve eseguire il file infetto |
| Velocità di diffusione  | Molto alta                                                              | Legata all'azione umana            |

In pratica: un virus è un passeggero che aspetta un passaggio, un worm guida la propria macchina. Entrambi sono sottocategorie di [malware](https://hackita.it/articoli/malware/), ma il modo in cui si spostano è opposto.

## Come si Diffonde un Worm

I worm sfruttano essenzialmente tre vie di propagazione, spesso combinandole:

**Vulnerabilità di rete.** È il metodo più temibile: il worm scansiona internet o la rete locale in cerca di sistemi che espongono un servizio con una falla nota e non ancora corretta, poi si copia sul bersaglio sfruttando quella falla — senza che nessuno debba cliccare o aprire nulla. WannaCry, nel 2017, si diffuse esattamente così.

**Email e messaggistica.** ILOVEYOU (2000) è l'esempio da manuale: arrivava come allegato email e richiedeva che la vittima lo aprisse per attivarsi — quell'unica azione bastava perché il worm si inviasse da solo a tutta la rubrica Outlook, propagandosi da lì in poi senza bisogno di altro intervento umano.

**Supporti rimovibili e condivisioni.** Chiavette USB e cartelle condivise in rete sono un vettore classico: il worm si copia su ogni supporto o share raggiungibile, attivandosi sul sistema successivo che vi accede.

| Tipo                 | Vettore tipico                   | Esempio  |
| -------------------- | -------------------------------- | -------- |
| Network worm         | Vulnerabilità di servizi di rete | WannaCry |
| Email worm           | Allegati e rubrica contatti      | ILOVEYOU |
| Removable-media worm | USB e supporti rimovibili        | —        |
| File-sharing worm    | Cartelle condivise, reti P2P     | —        |

## Cosa Fa un Worm Dopo l'Infezione

La diffusione è solo il mezzo: il danno reale dipende dal **payload**, la parte del worm che esegue l'azione dannosa vera e propria. Alcuni worm hanno un payload distruttivo (cancellano o cifrano file), altri installano una backdoor che apre il sistema a ulteriori attacchi, altri ancora trasformano il dispositivo in parte di una **[botnet](https://hackita.it/articoli/botnet/)** — una rete di macchine compromesse controllate da remoto. In molti casi, però, il danno più grande non è nemmeno nel payload: è la diffusione stessa. Un worm che si replica senza controllo consuma banda e risorse, saturando reti aziendali intere fino a mandarle in tilt anche senza un payload esplicitamente distruttivo.

## Come si Propaga un Worm in una Rete Aziendale

Il modello concettuale è quasi sempre lo stesso, indipendentemente dal worm specifico: un host esposto verso internet viene compromesso per primo, poi il worm usa quella testa di ponte per scansionare la rete interna — a cui spesso ha accesso più ampio proprio in quanto host già dentro il perimetro — trovando altri sistemi vulnerabili e ripetendo il ciclo. È lo stesso principio del **movimento laterale** usato in un attacco mirato, solo automatizzato e senza un operatore umano a guidarlo: da un singolo punto di ingresso, in poche ore un worm può attraversare interi segmenti di rete che si fidavano implicitamente l'uno dell'altro.

## Come Riconoscere un'Infezione da Worm

Alcuni segnali valgono per un utente qualunque: rallentamenti improvvisi, consumo anomalo di banda o CPU, il computer che sembra "lavorare" anche da inattivo. In un contesto aziendale, chi monitora la rete guarda a indicatori più specifici: tentativi ripetuti di connessione verso lo stesso servizio su molti host in rapida successione (segno di una scansione automatizzata), traffico SMB anomalo quando il worm sfrutta quel protocollo, connessioni outbound verso un numero insolito di indirizzi diversi, e alert generati da EDR o IDS/IPS su processi che tentano di replicarsi o di contattare altri host della rete. Nessuno di questi segnali preso da solo è definitivo, ma la combinazione — soprattutto la velocità con cui si diffondono — è il tratto distintivo di un worm rispetto a un'infezione isolata.

## Worm vs Trojan vs Ransomware

Per collocare bene il worm nella famiglia malware, conviene chiarire due confini che spesso si sovrappongono:

* Un [trojan](https://hackita.it/articoli/trojan/) non si replica affatto: si finge software legittimo per farsi installare dall'utente. Il worm è l'opposto — non chiede permesso a nessuno.
* Il [ransomware](https://hackita.it/articoli/ransomware/) non è definito da come si diffonde ma da cosa fa (cifra i file e chiede un riscatto): può quindi *usare* un meccanismo da worm per propagarsi. WannaCry è proprio questo — un ransomware con capacità di worm, il che spiega perché fece così tanti danni così in fretta.

## I Worm più Famosi della Storia

| Worm             | Anno      | Vettore                                   | Impatto                                                             |
| ---------------- | --------- | ----------------------------------------- | ------------------------------------------------------------------- |
| Morris Worm      | 1988      | Vulnerabilità di servizi Unix             | \~6.000 dei \~60.000 host allora connessi a internet, circa il 10%  |
| ILOVEYOU         | 2000      | Email                                     | Decine di milioni di computer colpiti in pochi giorni               |
| Blaster / Sasser | 2003-2004 | Vulnerabilità di rete Windows (RPC/LSASS) | Propagazione automatica, riavvii in loop                            |
| WannaCry         | 2017      | SMB / EternalBlue                         | Centinaia di migliaia di sistemi in oltre 150 paesi in pochi giorni |

**Morris Worm (1988).** Uno dei primi worm a ottenere una diffusione significativa su internet, scritto da uno studente e rilasciato quasi per errore nelle sue conseguenze: secondo le stime di FBI e altre fonti dell'epoca, colpì circa 6.000 dei 60.000 host allora connessi alla rete, rallentandoli fino a bloccarli a causa di un difetto che lo faceva reinfettare più volte lo stesso sistema. Portò alla prima condanna negli Stati Uniti in base al Computer Fraud and Abuse Act.

**ILOVEYOU (2000).** Si diffuse via email con un allegato camuffato da lettera d'amore; una volta aperto, si reinviava a tutta la rubrica Outlook della vittima e sovrascriveva file sul sistema. In pochi giorni colpì decine di milioni di computer in tutto il mondo, causando danni stimati in miliardi di dollari.

**Blaster e Sasser (2003-2004).** Sfruttarono vulnerabilità di rete di Windows per propagarsi senza alcuna azione dell'utente, facendo riavviare in loop i sistemi infetti — un assaggio di quello che, oltre dieci anni dopo, avrebbe fatto WannaCry su scala ancora maggiore.

## Caso Studio: WannaCry, Quando Worm e Ransomware si Combinano

WannaCry sfruttò **EternalBlue**, un exploit sviluppato dalla NSA e reso pubblico nel 2017 dal gruppo Shadow Brokers, contro una vulnerabilità del protocollo SMBv1 di Windows. MS17-010 è il bollettino Microsoft che copre l'intero gruppo di vulnerabilità SMBv1 coinvolte (comprende diverse CVE, dalla 0143 alla 0148); quella specificamente sfruttata da EternalBlue è identificata come **CVE-2017-0144**. Microsoft aveva pubblicato la patch il 14 marzo 2017, quasi due mesi prima che WannaCry iniziasse a diffondersi il 12 maggio. Una volta dentro un host, il malware cifrava i file e chiedeva un riscatto come un normale ransomware — ma a differenza di un ransomware "classico", non aveva bisogno che qualcuno aprisse un allegato: scansionava da solo la rete locale e internet in cerca di altri host vulnerabili sulla stessa porta SMB, replicandosi automaticamente. È questa componente da worm, innestata su un payload da ransomware, ad aver permesso a WannaCry di raggiungere centinaia di migliaia di sistemi in oltre 150 paesi in pochi giorni, secondo [gli avvisi ufficiali della CISA](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware) pubblicati durante l'emergenza — inclusi ospedali del sistema sanitario britannico costretti a rinviare interventi.

## Come Rimuovere un Worm

1. **Isola il dispositivo dalla rete** — Wi-Fi e cavo — per fermare la propagazione verso altri sistemi.
2. **Identifica il processo o l'indicatore sospetto** che ha causato l'infezione, se possibile.
3. **Esegui una scansione completa** con un antimalware o EDR aggiornato.
4. **Applica la patch della vulnerabilità sfruttata**, se il worm si è propagato tramite un exploit di rete — altrimenti si reinfetterà appena riconnesso.
5. **Controlla gli altri host** che hanno comunicato con il dispositivo compromesso: un worm raramente resta isolato a una sola macchina.
6. **Reimposta le credenziali potenzialmente esposte**, da un dispositivo pulito.
7. **Ripristina i dati da un backup precedente all'infezione**, offline o immutabile, se il payload ha causato danni irreversibili.

## Come Proteggersi dai Worm

La difesa più efficace contro i worm è anche la più trascurata: **installare gli aggiornamenti di sicurezza appena disponibili**. Quasi tutti i grandi worm della storia hanno sfruttato vulnerabilità per cui una patch esisteva già — WannaCry compreso, che colpì mesi dopo che Microsoft aveva rilasciato la correzione. Oltre alle patch: disabilitare protocolli e servizi legacy non più necessari (SMBv1, nel caso di WannaCry, è tuttora presente su sistemi che nessuno ha mai aggiornato); un firewall che limiti i servizi esposti verso l'esterno riduce la superficie che un worm può scansionare; segmentare la rete impedisce a un'infezione di propagarsi liberamente da un reparto all'altro; e un antivirus aggiornato intercetta i worm già noti prima che si attivino. Come sempre, un backup offline o immutabile è l'ultima rete di sicurezza se il payload si rivela distruttivo.

I worm restano una minaccia attuale, non solo un capitolo di storia: la stessa logica di propagazione automatica continua a comparire in campagne di malware e ransomware moderne, spesso combinata con tecniche di movimento laterale più sofisticate di quelle viste in WannaCry.

Per chi vuole andare oltre la difesa e capire un worm dall'interno, il passo successivo è l'analisi malware — static e dynamic analysis, estrazione di indicatori di compromissione, analisi del traffico di rete generato durante la propagazione. È un terreno che tratteremo in articoli dedicati, insieme ai tool che lo rendono possibile.

## FAQ

**Cos'è un worm informatico?** È un malware che si replica e si diffonde da solo attraverso le reti, senza bisogno di un file ospite — a differenza di un virus, che ne richiede uno.

**Qual è la differenza tra worm e virus?** Il virus ha bisogno di un file ospite per diffondersi; il worm è autonomo e si propaga da sé sfruttando reti e vulnerabilità. È la ragione per cui i worm si diffondono molto più in fretta.

**Un worm è più pericoloso di un virus?** La capacità di propagarsi senza bisogno di un file ospite può permettere a un worm di diffondersi molto più rapidamente di un malware che dipende dall'azione manuale dell'utente. Il livello di pericolosità reale dipende però dal vettore, dalla vulnerabilità sfruttata e soprattutto dal payload che porta con sé.

**WannaCry era un virus o un worm?** Tecnicamente era un ransomware con capacità di worm: cifrava i file come un ransomware, ma si diffondeva da solo sfruttando una vulnerabilità di rete (MS17-010, tramite l'exploit EternalBlue) come un worm. È questa combinazione ad averlo reso così devastante.

**Un worm può infettare uno smartphone?** Sì, anche se è meno comune che sui PC: il sandboxing di iOS e Android limita la capacità di un worm di replicarsi automaticamente tra app, ma non lo esclude del tutto — sono esistiti worm mirati specificamente a dispositivi mobili, diffusi ad esempio via messaggistica o app compromesse.

**Un worm può diffondersi senza internet?** Sì. Una rete locale isolata da internet non è immune: chiavette USB, cartelle condivise e worm che scansionano solo la rete interna sono vettori sufficienti, come dimostrato da worm progettati proprio per ambienti air-gapped.

**Come ci si difende da un worm?** Soprattutto tenendo aggiornati sistema operativo e software, dato che i worm sfruttano vulnerabilità spesso già corrette da patch disponibili. Firewall, segmentazione della rete, antivirus aggiornato e backup scollegati completano la difesa.
