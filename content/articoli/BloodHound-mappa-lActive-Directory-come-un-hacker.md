---
title: 'BloodHound: Mappa l’Active Directory Come un Vero Hacker'
slug: bloodhound
description: >-
  Scopri come usare BloodHound per analizzare Active Directory e trovare
  escalation di privilegi. Tool essenziale per Red Team e attacchi interni
  simulati.
image: /BH.webp
draft: false
date: 2026-01-23T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - bloodhound
  - active directory
featured: false
---

# BloodHound: Mappa l’Active Directory Come un Vero Hacker

Se BloodHound “non mostra nulla” o le path sono vuote, in questa guida di hackita lo porti a regime in lab e arrivi a una path verificabile verso un obiettivo (senza improvvisare).

## Intro

BloodHound è uno strumento di auditing che **modella Active Directory come un grafo** per evidenziare relazioni e percorsi d’attacco che un attaccante potrebbe sfruttare.

In un workflow da pentest lab, ti serve per passare dal “ho enumerato” al “so esattamente quale catena di permessi/sessioni/ACL porta al target” e per comunicare rischio e remediation in modo visuale.

Cosa farai/imparerai:

* Setup rapido e sanity check
* Raccolta dati con SharpHound e ingest corretto
* Prime query utili (UI e Cypher) per trovare path
* Errori comuni (DNS/LDAP/permessi) e fix
* Detection e hardening quando simuli scenari offensivi

Nota etica: tutto ciò che segue è pensato **solo** per lab/CTF/HTB/PG o sistemi di tua proprietà con autorizzazione esplicita.

## Cos’è BloodHound e dove si incastra nel workflow

> **In breve:** BloodHound ti fa vedere “chi può arrivare a cosa” in AD, trasformando permessi e relazioni (ACL, gruppi, sessioni, admin locali) in percorsi d’attacco leggibili.

BloodHound non “buca” nulla da solo: è un moltiplicatore di chiarezza. Il flusso tipico in lab è:

1. enumerazione AD/SMB “grezza” per capire dominio, DC, utenti, share e policy
2. raccolta strutturata con SharpHound
3. import in BloodHound e ricerca di path verso un obiettivo (es. gruppo privilegiato)
4. validazione in lab (senza andare out-of-scope) + detection/hardening

Se vuoi arrivare a dati AD puliti prima di SharpHound, spesso conviene fare un check LDAP mirato con [enumerazione LDAP con ldapsearch](https://hackita.it/articoli/ldapsearch-enumerazione-ldap/). (\[HackIta]\[2])

Quando NON usarlo: se stai facendo solo un check veloce “host alive / porte / banner”, BloodHound è overkill e ti rallenta.

## Installazione rapida e sanity check (CE vs legacy)

> **In breve:** Oggi ha senso puntare su BloodHound Community Edition (CE) in container; la parte importante è portare su lo stack e verificare che UI e DB rispondano. (\[bloodhound.specterops.io]\[1])

BloodHound CE gira in architettura container (multi-tier). In lab ti interessa: “parte, si apre la UI, accetta ingest, querya bene”.

Perché: avviare BloodHound CE in modo ripetibile evita mezzi setup rotti e perdite di tempo. (\[bloodhound.specterops.io]\[1])
Cosa aspettarti: stack su, UI raggiungibile e pronta ad importare collector output. (\[bloodhound.specterops.io]\[1])
Comando:

```bash
docker compose up
```

Esempio di output (può variare):

```text
[+] Running 5/5
 ✔ Network bloodhound_default  Created
 ✔ Container bloodhound-db     Started
 ✔ Container bloodhound-app    Started
 ✔ Container bloodhound-ui     Started
 ✔ Container bloodhound-proxy  Started
```

Interpretazione: se i container restano “Started” e non crashano a loop, sei nella direzione giusta.
Errore comune + fix: `Cannot connect to the Docker daemon` → Docker non avviato o permessi; avvia Docker e/o aggiungi l’utente al gruppo `docker` (solo in lab).

Nota operativa: AV/EDR spesso flaggano BloodHound e componenti (collector inclusi). In lab isolato è normale; in ambienti reali devi coordinare con SOC e autorizzazioni. (\[bloodhound.specterops.io]\[1])

## Raccolta dati con SharpHound (cosa prende e cosa “manca”)

> **In breve:** SharpHound è il collector ufficiale per BloodHound CE: raccoglie membership, trust, ACL “abusabili”, policy/OU e anche segnali da host domain-joined (admin locali, sessioni). (\[bloodhound.specterops.io]\[3])

SharpHound è il punto in cui si rompe tutto se sottovaluti permessi, risoluzione DNS e reachability verso DC/host. Il “default” spesso basta per partire, poi iteri.

Perché: una prima raccolta “default” ti dà un grafo utile senza impazzire con 50 flag. (\[bloodhound.specterops.io]\[3])
Cosa aspettarti: al termine genera JSON e li impacchetta in uno zip pronto da importare in BloodHound. (\[bloodhound.specterops.io]\[3])
Comando:

```text
C:\> SharpHound.exe
```

Esempio di output (può variare):

```text
SharpHound  | Collecting default data
LDAP        | Using domain controller: DC01.example.com
Session     | Enumerating sessions on domain-joined computers
Output      | Writing output to C:\Users\lab\20260127_1200_BloodHound.zip
Finished    | Collection completed
```

Interpretazione: se arrivi a “Collection completed” e hai lo zip, sei pronto per l’ingest.
Errore comune + fix: “LDAP connection failed” → DNS/route verso DC o credenziali; verifica che la macchina risolva il dominio e raggiunga il controller (in lab, anche un semplice ping/risoluzione può già dirti dove guardare).

Quando NON usarlo: su host non domain-joined senza preparazione (o senza definire correttamente target/credenziali) rischi solo errori e rumore. (\[bloodhound.specterops.io]\[3])

## Import (ingest) e prime scorciatoie per trovare percorsi

> **In breve:** importi lo zip, poi usi ricerca + query predefinite per capire subito quali nodi “valgono” (utenti, gruppi, computer, sessioni) e dove c’è privilegio effettivo.

Perché: il valore di BloodHound è accorciare “ore di enumeration manuale” in “minuti di pathfinding”.
Cosa aspettarti: dopo ingest, puoi cercare un utente/gruppo e chiedere shortest path verso un target.

Comando:

```text
(Interfaccia) Drag & drop del file .zip nella UI di BloodHound
```

Esempio di output (può variare):

```text
Ingest started...
Parsed 6 JSON files
Created/updated nodes: 1250
Created/updated edges: 9800
Ingest completed
```

Interpretazione: se nodi/edge sono >0 e l’ingest completa, hai grafo popolato.
Errore comune + fix: ingest “completa” ma vedi pochi edge → raccolta incompleta (permessi insufficienti o metodo troppo leggero); rilancia SharpHound da host domain-joined con un account lab più adatto.

Per andare più veloce nella fase “prima mappa”, spesso aiuta avere un quadro SMB coerente con [enumerazione SMB con enum4linux-ng](https://hackita.it/articoli/enum4linux-ng-enumerazione-smb/). (\[HackIta]\[4])

## Cypher pratico: 3 query piccole che ti sbloccano il cervello

> **In breve:** anche se usi la UI, 3 query Cypher ti aiutano a controllare qualità dati e scoprire “hotspot” (gruppi privilegiati, admin locali diffusi, sessioni interessanti).

Perché: Cypher ti dà un controllo “chirurgico” quando la UI è troppo generica.
Cosa aspettarti: liste ordinate e pattern ricorrenti (es. un gruppo che è admin locale su troppi host).

Comando:

```cypher
MATCH (g:Group)
WHERE g.name CONTAINS "DOMAIN ADMINS"
RETURN g.name
```

Esempio di output (può variare):

```text
g.name
--------------------------------
EXAMPLE.COM\DOMAIN ADMINS
```

Interpretazione: confermi naming e presenza del gruppo target nel grafo.
Errore comune + fix: zero risultati → naming diverso o dominio diverso; cerca “ADMIN” e guarda la convenzione dei nomi nel dataset.

Perché: trovare computer dove un gruppo è admin locale è un classico pivot “da attaccante”.
Cosa aspettarti: elenco host su cui l’entità ha admin locale.

Comando:

```cypher
MATCH (g:Group)-[:AdminTo]->(c:Computer)
RETURN g.name, count(c) AS hosts
ORDER BY hosts DESC
LIMIT 10
```

Esempio di output (può variare):

```text
g.name                              hosts
-----------------------------------------
EXAMPLE.COM\IT-HELPDESK              42
EXAMPLE.COM\WORKSTATION-ADMINS       17
```

Interpretazione: gruppi “helpdesk” e simili sono spesso il punto debole del lab.
Errore comune + fix: conteggi bassissimi → raccolta host incompleta; rivedi reachability e metodo di raccolta.

Perché: le sessioni utente su host adminabili sono ponti reali verso credenziali e privilege.
Cosa aspettarti: coppie `utente -> host` dove la sessione esiste.

Comando:

```cypher
MATCH (u:User)-[:HasSession]->(c:Computer)
RETURN u.name, c.name
LIMIT 20
```

Esempio di output (può variare):

```text
u.name                      c.name
--------------------------------------------
EXAMPLE.COM\svc_backup       WS-02.EXAMPLE.COM
EXAMPLE.COM\j.doe            WS-05.EXAMPLE.COM
```

Interpretazione: se trovi account “svc\_\*” con sessioni su host interessanti, annota e valida in lab.
Errore comune + fix: nessuna sessione → spesso metodi di session collection bloccati da permessi/firewall; in lab abilita e ripeti.

## Casi d’uso offensivi “da lab” (con validazione, detection, hardening)

> **In breve:** BloodHound è perfetto per smascherare misconfig tipo “gruppo sbagliato admin locale ovunque”, ACL delegati male, sessioni privilegiate su workstation e percorsi che passano da SMB/LDAP.

Esempio 1: gruppo operativo che è admin locale su molte workstation.
Validazione in lab: verifica con enumerazione SMB mirata e membership, prima di simulare qualsiasi passo successivo. Un’ottima scorciatoia è [enumerazione SMB con CrackMapExec](https://hackita.it/articoli/crackmapexec-enumerazione-smb/). (\[HackIta]\[5])
Segnali di detection: spike di autenticazioni e enumerazioni verso tanti host, query LDAP intense, tentativi RPC/SMB ripetuti.
Hardening: riduci admin locali, usa LAPS/credential guard dove possibile, segmenta e limita chi può fare remote admin.

Esempio 2: path che passa da “NTLM relay/poisoning” (solo lab).
Validazione in lab: se stai simulando cattura hash in un dominio lab, fallo in un perimetro controllato e traccia bene cosa stai facendo; come materiale correlato vedi [Responder in lab](https://hackita.it/articoli/responder-lab/) (solo per capire segnali e contromisure). (\[HackIta]\[6])
Segnali di detection: traffico LLMNR/NBNS anomalo, richieste WPAD sospette, eventi di autenticazione inconsueti.
Hardening: disabilita LLMNR/NBNS dove possibile, firma SMB, proteggi WPAD, monitora broadcast e poisoning.

Quando NON usarlo: se stai già facendo remediation e vuoi “una sola prova”, BloodHound può essere troppo ampio; usa query puntuali LDAP/SMB.

## Errori comuni e troubleshooting (quelli che ti fanno perdere ore)

> **In breve:** i problemi veri sono sempre gli stessi: DNS/risoluzione dominio, permessi insufficienti, reachability verso DC/host, AV/EDR che blocca collector, dati ingest “vuoti”.

Perché: se li riconosci al volo, non resti impantanato.
Cosa aspettarti: sintomi chiari e fix semplici.

Caso: SharpHound parte ma produce dataset minuscolo.
Interpretazione: spesso non riesce a interrogare host domain-joined o a fare alcune collection.
Fix in lab: esegui da una macchina domain-joined con connettività completa e account lab con permessi adeguati.

Caso: UI su ma ingest fallisce o va in timeout.
Interpretazione: risorse docker insufficienti o DB sotto stress.
Fix in lab: aumenta RAM/CPU assegnate a Docker, riprova con dataset più piccolo, poi scala.

Caso: collector bloccato da protezioni.
Interpretazione: molti endpoint lo classificano come tool “risky”. (\[bloodhound.specterops.io]\[1])
Fix in lab: isolare VM e gestire eccezioni solo in ambiente controllato.

Suggerimento pratico: se il tuo problema è “non capisco il dominio/OU” prima di BloodHound, fatti un dump LDAP ragionato con [ldapsearch per enumerare AD](https://hackita.it/articoli/ldapsearch-enumerazione-ldap/). (\[HackIta]\[2])

## Alternative e tool correlati (quando preferirli)

> **In breve:** BloodHound è per grafi e path; per enumerazione “a colpi secchi” spesso conviene affiancare tool SMB/RPC/LDAP e poi tornare al grafo.

* Per SMB veloce e coerente: [smbclient offensivo](https://hackita.it/articoli/smbclient-uso-offensivo/) e [rpcclient per enumerazione SMB](https://hackita.it/articoli/rpcclient-enumerazione-smb/). (\[HackIta]\[7])
* Per discovery NetBIOS in lab: [NBTScan per enumerazione](https://hackita.it/articoli/nbtscan-enumerazione/). (\[HackIta]\[8])
* Per cattura credenziali in lab e capire segnali: [Inveigh in lab](https://hackita.it/articoli/inveigh-lab/). (\[HackIta]\[9])

Quando preferirli: se devi risolvere un blocco specifico (share access, RPC info, naming), usa tool puntuali; poi rientra in BloodHound per modellare l’impatto.

## Hardening & detection: cosa cambia quando “giochi” con BloodHound

> **In breve:** BloodHound rende visibili i percorsi, ma la difesa si fa riducendo privilegi, limitando sessioni privilegiate e monitorando enumerazioni anomale.

Detection (in lab, per capire cosa “suona”):

* picchi di traffico verso DC (LDAP) e verso molti host (SMB/RPC)
* pattern ripetuti di enumerazione (sessioni, gruppi locali, membership)
* esecuzione di collector su endpoint non standard

Hardening (azioni ad alto ROI):

* riduci gruppi con admin locale diffuso e applica principi di least privilege
* evita sessioni di account privilegiati su workstation
* segmenta rete e limita remote management dove non serve
* monitora policy che impattano NTLM/broadcast e riduci superficie di poisoning

Quando NON usarlo: se sei in fase “blue” e vuoi solo best practice generiche, non serve il grafo; ma se vuoi priorità di remediation, BloodHound è oro.

## Scenario pratico: BloodHound su una macchina HTB/PG

> **In breve:** raccogli dati con SharpHound su un host domain-joined, importi lo zip e trovi un percorso verso un gruppo privilegiato, poi annoti detection e hardening.

Ambiente (lab):

* DC: `10.10.10.10`
* WS domain-joined: `10.10.10.11`
* Dominio: `EXAMPLE.COM`

Obiettivo: identificare un percorso d’attacco “grafico” verso un gruppo privilegiato e capire dove la catena si spezza con remediation.

Perché: farlo su IP fittizi ti dà un pattern replicabile su qualsiasi lab AD.
Cosa aspettarti: zip di SharpHound → ingest ok → shortest path visibile.

Comando:

```text
C:\> SharpHound.exe
```

Esempio di output (può variare):

```text
Output | Writing output to C:\Users\lab\20260127_1300_BloodHound.zip
Finished | Collection completed
```

Interpretazione: importa lo zip nella UI e cerca un percorso verso “DOMAIN ADMINS” o un gruppo privilegiato del lab.
Errore comune + fix: zip generato ma ingest “vuoto” → ripeti da host con connettività migliore e controlla DNS verso DC.

Risultato atteso: una path che passa per un gruppo/ACL o una sessione (es. utente X ha sessione su host Y dove gruppo Z è admin locale).

Detection + hardening: in un SOC reale vedresti enumerazione LDAP e attività su molti host; la mitigazione tipica è tagliare admin locali diffusi e impedire sessioni privilegiate su workstation.

## Playbook 10 minuti: BloodHound in un lab

> **In breve:** 7 step asciutti per andare da “zero” a “path trovata” senza perderti in UI e feature.

### Step 1 – Prepara il lab (dominio e una workstation)

Assicurati di avere almeno DC + 1 host domain-joined, e che risolvano correttamente il dominio (DNS interno).

### Step 2 – Avvia BloodHound CE

Se hai già lo stack pronto, portalo su e verifica che resti stabile.

```bash
docker compose up
```

### Step 3 – Esegui SharpHound “default” sulla macchina domain-joined

Parti senza flag: prima vuoi un grafo “vivo”.

```text
C:\> SharpHound.exe
```

### Step 4 – Importa lo zip nella UI

Carica lo zip e aspetta ingest completato; se edge sono pochissimi, fermati e risolvi prima.

### Step 5 – Trova il tuo target (gruppo o utente)

Cerca “DOMAIN ADMINS” o il gruppo privilegiato equivalente del lab e osserva nodi/relazioni.

### Step 6 – Cerca una path corta e leggibile

Parti da un utente low-priv e chiedi shortest path verso il target; annota ogni hop e che tipo di edge è (admin locale, sessione, ACL).

### Step 7 – Valida e chiudi il loop con detection/hardening

Valida solo ciò che è sicuro in lab e scrivi remediation: “quale edge taglio per rompere la chain” + segnali che un blue team vedrebbe.

## Checklist operativa

* Ho un dominio lab funzionante e risoluzione DNS ok.
* BloodHound CE si avvia e resta stabile (container up, UI accessibile).
* Eseguo SharpHound da host domain-joined (non improvviso da host random).
* Ottengo uno zip e lo importo senza errori.
* Verifico che nodi ed edge siano in numero plausibile (non “quasi zero”).
* Identifico target (gruppo privilegiato) e confermo naming.
* Cerco una path corta e comprensibile (non 200 hop inutili).
* Ogni hop della path ha un senso operativo (admin, session, ACL) e lo posso spiegare.
* Se simulo un abuso in lab, scrivo subito detection e mitigazione.
* Segno quali privilegi/tagli rompono l’attack path con minor impatto.

## Riassunto 80/20

| Obiettivo          | Azione pratica                | Comando/Strumento   |
| ------------------ | ----------------------------- | ------------------- |
| Avviare BloodHound | Portare su lo stack           | `docker compose up` |
| Raccogliere dati   | Eseguire collector “default”  | `SharpHound.exe`    |
| Importare dataset  | Caricare lo zip nella UI      | `Drag & drop .zip`  |
| Validare target    | Cercare gruppo privilegiato   | `Search UI`         |
| Trovare path       | Shortest path verso target    | `Shortest Path`     |
| Controllo qualità  | Query base su nodi/edge       | `Cypher`            |
| Ridurre rischio    | Tagliare edge ad alto impatto | `Hardening`         |

## Concetti controintuitivi

* **“Se ho il grafo completo, ho già vinto”**
  No: il grafo ti mostra possibilità, non esecuzione. In lab devi validare ogni hop e scrivere come si rompe la chain con remediation.
* **“Più flag = più valore”**
  Spesso no: partire “default” e iterare è più veloce che fare una raccolta enorme che poi non ingestisce bene.
* **“Se non vedo sessioni, non esistono”**
  Non è detto: può essere un limite di permessi, firewall o metodo di raccolta. In lab controlla reachability e collection method.
* **“BloodHound è solo per red team”**
  È anche uno strumento di prioritizzazione remediation: tagliare 1 edge può rompere 10 path.

## FAQ

D: BloodHound CE o legacy con Neo4j?

R: In generale conviene CE per setup moderno e supporto attuale; legacy resta utile se hai workflow storici, ma in lab nuovo vai CE.

D: SharpHound mi crea lo zip ma ingest non mostra quasi nulla, perché?

R: Tipicamente raccolta incompleta (permessi/connessioni) o dataset troppo povero. Esegui da host domain-joined con DNS verso DC e riprova.

D: Posso usare BloodHound senza essere domain admin?

R: Sì: la raccolta base può funzionare con utenti di dominio standard, ma alcune info richiedono accessi/permessi maggiori o condizioni di rete.

D: È normale che AV/EDR blocchi SharpHound?

R: Sì, spesso viene segnalato come tool “risky”. In lab isolato lo gestisci; in ambienti reali serve coordinamento e autorizzazione. (\[bloodhound.specterops.io]\[1])

D: BloodHound “fa rumore” in rete?

R: Può generare traffico LDAP e interrogazioni su molti host. In lab va bene, ma in real devi pianificare finestre e monitoraggio.

## Link utili su HackIta.it

* [Enumerazione LDAP con ldapsearch](https://hackita.it/articoli/ldapsearch-enumerazione-ldap/)
* [Enumerazione SMB con CrackMapExec](https://hackita.it/articoli/crackmapexec-enumerazione-smb/)
* [Enumerazione SMB con enum4linux-ng](https://hackita.it/articoli/enum4linux-ng-enumerazione-smb/)
* [rpcclient per enumerazione SMB](https://hackita.it/articoli/rpcclient-enumerazione-smb/)
* [smbclient in ottica offensiva](https://hackita.it/articoli/smbclient-uso-offensivo/)
* [Responder in lab](https://hackita.it/articoli/responder-lab/)

Inoltre:

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/ (\[HackIta]\[10])

## Riferimenti autorevoli

* [https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) 
* [https://bloodhound.specterops.io/collect-data/ce-collection/sharphound](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound) 

## CTA finale HackITA

Se questa guida ti ha fatto risparmiare tempo in lab, puoi supportare il progetto qui: /supporto/

Se vuoi accelerare davvero (setup lab AD, workflow BloodHound, interpretazione path e remediation), trovi la formazione 1:1 qui: /servizi/

Per servizi alle aziende (assessment, hardening, percorsi d’attacco e priorità di remediation) trovi tutto qui: /servizi/

\[1]: [https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) "BloodHound Community Edition Quickstart - SpecterOps"
\[2]: [https://hackita.it/articoli/ldapsearch/](https://hackita.it/articoli/ldapsearch/) "Ldapsearch: enumerazione utenti e directory in attacco - HackIta"
\[3]: [https://bloodhound.specterops.io/collect-data/ce-collection/sharphound](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound) "SharpHound Community Edition - SpecterOps"
\[4]: [https://hackita.it/articoli/enum4linux-ng/](https://hackita.it/articoli/enum4linux-ng/) "Enum4linux-ng: enumerazione avanzata su reti Windows - HackIta"
\[5]: [https://hackita.it/articoli/crackmapexec/](https://hackita.it/articoli/crackmapexec/) "CrackMapExec: attacchi rapidi su Active Directory - HackIta"
\[6]: [https://hackita.it/articoli/responder/](https://hackita.it/articoli/responder/) "Responder: Attacco LLMNR, NBT-NS e WPAD in LAN per Rubare Hash NTLM come un Vero Red Teamer - HackIta"
\[7]: [https://hackita.it/articoli/smbclient/](https://hackita.it/articoli/smbclient/) "Smbclient: accesso e attacco alle condivisioni Windows - HackIta"
