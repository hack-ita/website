---
title: >-
  NBTScan: Scansione Silenziosa della Rete Windows via NetBIOS per Raccogliere
  Info Sensibili
slug: nbtscan
description: >-
  NBTScan è uno strumento essenziale per la fase di ricognizione su reti
  Windows. Permette di identificare host attivi, nomi NetBIOS, gruppi di lavoro
  e sessioni aperte in modo silenzioso e mirato. Ecco come sfruttarlo per
  mappare la rete come un vero red teamer.
image: /ntbscan.webp
draft: false
date: 2026-01-22T00:00:00.000Z
lastmod: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - nbtscan
  - netbios
---

# NBTScan: Scansione Silenziosa della Rete Windows via NetBIOS per Raccogliere Info Sensibili

Raccogli nomi host, dominio/workgroup e “ruoli” Windows via NetBIOS in pochi minuti, senza affidarti a DNS: tutto verificabile in un lab e pronto da usare per i passi SMB/AD.

## Intro

NBTScan è un tool CLI che scansiona una rete IP interrogando NetBIOS per ottenere informazioni come nome host, user loggato e tabella nomi/servizi associati.

In un pentest interno “da lab” è utile quando vuoi una fotografia rapida e leggibile dell’ecosistema Windows (workstation, file server, DC) anche in ambienti dove ICMP/DNS non aiutano.

Cosa farai in questa guida:

* Capire dove nbtscan entra nel workflow di recon interno.
* Usare 3 pattern di comandi che coprono il 90% dei casi.
* Interpretare suffix NetBIOS per identificare DC/file server/browser.
* Esportare output “script-friendly” per automatizzare follow-up.

Nota etica: usa questi passaggi solo su VM personali o ambienti autorizzati (CTF/HTB/PG/lab).

## Cos’è nbtscan e dove si incastra nel workflow

> **In breve:** nbtscan invia query NetBIOS (tipicamente su UDP 137) e stampa info utili (nomi, user, MAC, tabella servizi) per trasformare una subnet Windows in una lista di target prioritizzati.

nbtscan non è “uno scanner generico”: è un acceleratore di **NetBIOS intelligence**. Quando funziona bene, ti fa risparmiare tempo nel distinguere “host qualsiasi” da “host Windows interessante” (file server, DC, browser master). (\[Debian Manpages]\[1])

Quando usarlo (in lab):

* Hai subnet interna e vuoi nomi/ruoli senza dipendere da DNS.
* Vuoi identificare rapidamente host con **File Server Service** e **Domain Controllers** per guidare i passi SMB/AD.

Quando NON usarlo:

* Stai lavorando su segmenti non Windows (router/IoT): NetBIOS spesso non risponde o non ha senso.
* Ti serve enumerare condivisioni: nbtscan **non** fa share scanning (è volutamente fuori scope). (\[Debian Manpages]\[1])

## Installazione, versione e quick sanity check

> **In breve:** su Kali lo installi via `apt`, poi verifichi sintassi e opzioni con `--help` prima di fidarti di timeout/flag.

Perché: assicurarti di avere nbtscan e capire subito come interpreta le opzioni nel tuo sistema (timeout, verbose, parsing). (\[Kali Linux]\[2])

Cosa aspettarti: una schermata help con opzioni tipo `-v`, `-r`, `-s`, `-f`, versione installata.

Comando:

```bash
sudo apt update && sudo apt install -y nbtscan
nbtscan --help | head -40
```

Esempio di output (può variare):

```text
NBTscan version 1.7.2.
Usage:
nbtscan [-v] [-d] [-e] [-l] [-t timeout] [-b bandwidth] [-r] [-q] [-s separator] [-m retransmits] (-f filename)|(<scan_range>)
...
```

Interpretazione: se vedi `-r` e `-s`, sei già pronto per i due pattern più utili: affidabilità (porta 137) e parsing.

Errore comune + fix: `-r` può richiedere privilegi elevati (bind della porta 137). Se fallisce, rilancia con `sudo` o evita `-r` (sapendo che potresti perdere risposte). (\[Debian Manpages]\[1])

Nota anti-hallucination: l’unità di `-t` (timeout) può differire tra build/documentazione (secondi vs millisecondi). Regola pratica: fidati del tuo `nbtscan --help` e calibra con test su 1 host. (\[Debian Manpages]\[1])

## Sintassi base e 3 pattern che userai sempre

> **In breve:** (1) sweep subnet, (2) deep dive su host, (3) lista target da file/STDIN: con questi copri quasi tutto il recon NetBIOS.

### Pattern 1 — Sweep subnet (mappa veloce)

Perché: scoprire host Windows “parlanti” e ottenere subito nome + user + MAC.

Cosa aspettarti: righe con `IP`, `NetBIOS Name`, indicatore server, user e MAC.

Comando:

```bash
sudo nbtscan -r 10.10.10.0/24
```

Esempio di output (può variare):

```text
Doing NBT name scan for addresses from 10.10.10.0/24
IP address       NetBIOS Name     Server    User             MAC address
-----------------------------------------------------------------------
10.10.10.10      WS-DEV           <server>  DEV\devuser      00:0c:29:12:34:56
10.10.10.20      FILESRV          <server>  <unknown>        00:0c:29:aa:bb:cc
10.10.10.25      DC01             <server>  <unknown>        00:0c:29:11:22:33
```

Interpretazione: `DC01` e `FILESRV` entrano subito nella “shortlist” per follow-up SMB/AD.

Errore comune + fix: nessun risultato → prova senza `-r` (alcune reti/host rispondono comunque), oppure verifica che UDP 137 non sia filtrato nel lab.

### Pattern 2 — Deep dive su un host (tabella nomi/servizi)

Perché: confermare “ruolo” (DC, browser, file server) leggendo i suffix NetBIOS.

Cosa aspettarti: tabella `Name / <suffix> / UNIQUE|GROUP` e (se usi `-h`) descrizioni leggibili.

Comando:

```bash
nbtscan -v -h 10.10.10.25
```

Esempio di output (può variare):

```text
NetBIOS Name Table for Host 10.10.10.25:
Name             Service          Type
-----------------------------------------------
DC01             <00>             UNIQUE
LAB              <00>             GROUP
DC01             <20>             UNIQUE
LAB              <1B>             UNIQUE
LAB              <1C>             GROUP
..__MSBROWSE__.. <01>             GROUP
```

Interpretazione: `<1C>` (Domain Controllers) + `<1B>` (Domain Master Browser) = host altamente interessante in ottica AD.

Errore comune + fix: `-h` funziona solo con `-v`. Se ottieni errore o output strano, usa solo `-v` e interpreta i suffix manualmente. (\[Debian Manpages]\[1])

### Pattern 3 — Target list (file o STDIN)

Perché: lavorare “precisione chirurgica” su IP già selezionati (da ARP/DHCP/Nmap).

Cosa aspettarti: scansione solo degli IP in lista, meno rumore, più controllo.

Comando:

```bash
printf "10.10.10.10\n10.10.10.20\n10.10.10.25\n" > targets.txt
nbtscan -f targets.txt
```

Esempio di output (può variare):

```text
10.10.10.10      WS-DEV           <server>  DEV\devuser      00:0c:29:12:34:56
10.10.10.20      FILESRV          <server>  <unknown>        00:0c:29:aa:bb:cc
10.10.10.25      DC01             <server>  <unknown>        00:0c:29:11:22:33
```

Interpretazione: perfetto quando il discovery L2 l’hai già fatto (es. con ARP). In quel caso, nbtscan diventa “identificazione + priorità”, non discovery puro: vedi anche la guida su [ARP-Scan per host discovery in LAN](https://hackita.it/articoli/arp-scan/).

Errore comune + fix: se `-f` non legge come ti aspetti, assicurati che il file contenga un IP per riga e nessun trailing “strano” (spazi, CRLF).

## Interpretare output e suffix NetBIOS (la parte che conta davvero)

> **In breve:** i suffix NetBIOS ti dicono “che cosa è” un host: `<00>` workstation/domain, `<20>` file server, `<1B>/<1C>` indicatori forti di AD/DC.

Quello che ti interessa non è “un nome”: è il **significato operativo** dei suffix. In un lab Windows/AD, questi sono i più utili: (\[Debian Manpages]\[1])

* `<00>`: Workstation Service (nome macchina) o Domain Name (group).
* `<20>`: File Server Service (candidato naturale per follow-up SMB).
* `<1B>`: Domain Master Browser.
* `<1C>`: Domain Controllers (group).
* `<1D>/<1E>`: Master Browser / Browser elections.
* `__MSBROWSE__<01>`: segnali legati al browser service.

Perché: se vedi `<1C>`, la tua “kill chain da lab” cambia: stai guardando un nodo AD-centrico, quindi i passi dopo sono orientati a SMB/LDAP/cred hygiene.

Cosa aspettarti: su DC o server “ricchi” vedrai più righe (group + unique) rispetto a una workstation “pulita”.

Comando:

```bash
nbtscan -v 10.10.10.25
```

Esempio di output (può variare):

```text
LAB              <1C>             GROUP
LAB              <1B>             UNIQUE
DC01             <20>             UNIQUE
```

Interpretazione: `<1C>` = “qui ci sono Domain Controllers”, `<20>` = “qui parla SMB/file server service”. A quel punto il follow-up tipico (sempre in lab) è validare SMB e capire cosa è esposto: vedi [Smbclient per enumerare condivisioni Windows](https://hackita.it/articoli/smbclient/).

Errore comune + fix: MAC `00-00-00-00-00-00` su Samba/non-Windows può capitare: nbtscan stampa quello che riceve, non “inventa” MAC. (\[Debian Manpages]\[1])

## Casi d’uso offensivi “da lab” e validazione (con mitigazioni)

> **In breve:** nbtscan ti dà una lista di host Windows con ruoli; la parte “offensiva” è come usi quella lista per decisioni rapide, e come misuri rumore + detection.

### Caso 1 — Selezionare target SMB “sensati” senza perdere tempo

Perché: evitare di buttare minuti/ore su host irrilevanti e puntare ai candidati con `<20>`.

Cosa aspettarti: una lista IP “SMB-likely” da passare a tool SMB/AD.

Comando:

```bash
nbtscan -v 10.10.10.0/24 | grep "<20>" | awk '{print $1}' > smb_targets.txt
```

Esempio di output (può variare):

```text
10.10.10.20
10.10.10.25
```

Interpretazione: ora hai target “con motivo”, non una subnet a caso.

Errore comune + fix: output non standard tra versioni/locale → usa `-s` (separator) e fai parsing robusto (vedi sezione “Parsing e automazione”).

Mitigazione/detection (lab → blue-team):

* Logga e allerta raffiche di query NetBIOS (UDP 137) su subnet.
* Segmenta e filtra 137/139 dove non serve; disabilita NetBIOS over TCP/IP sui client quando possibile.

### Caso 2 — Collegare “identity” (NetBIOS) a attacchi di poisoning (solo lab)

Perché: i nomi NetBIOS sono benzina per scenari LLMNR/NBNS in LAN.

Cosa aspettarti: una lista di nomi macchina/dominio da usare per test controllati.

Comando:

```bash
nbtscan -r 10.10.10.0/24 | awk '{print $2}' | grep -E '^[A-Z0-9_-]+$' | sort -u > netbios_names.txt
```

Esempio di output (può variare):

```text
DC01
FILESRV
WS-DEV
```

Interpretazione: in un lab, puoi usare questa lista per costruire test mirati su risoluzione nomi debole e cattive pratiche in LAN; se vuoi la catena completa (sempre autorizzata) collega qui la guida su [Responder per LLMNR/NBT-NS/WPAD](https://hackita.it/articoli/responder/).

Validazione in lab:

* Genera una richiesta name-resolution controllata (es. share inesistente) da una VM client.
* Osserva se NBNS/LLMNR viene usato e se “cade” su risposte malevole (solo in ambiente isolato).

Mitigazione/detection:

* Disabilita LLMNR/NBNS quando non necessari.
* Abilita SMB signing e controlla WPAD/proxy auto-discovery in modo esplicito.

## Parsing e automazione (output “script-friendly”)

> **In breve:** `-s` ti permette di esportare risultati senza header e con separatore custom: perfetto per CSV e pipeline.

Perché: quando fai recon serio, vuoi trasformare output in oggetti (CSV/JSON/hostlist), non “leggere a occhio”.

Cosa aspettarti: righe senza intestazioni e campi separati dal carattere scelto.

Comando:

```bash
sudo nbtscan -r -s ',' 10.10.10.0/24 > nbtscan.csv
head -5 nbtscan.csv
```

Esempio di output (può variare):

```text
10.10.10.10,WS-DEV,<server>,DEV\devuser,00:0c:29:12:34:56
10.10.10.20,FILESRV,<server>,<unknown>,00:0c:29:aa:bb:cc
10.10.10.25,DC01,<server>,<unknown>,00:0c:29:11:22:33
```

Interpretazione: ora puoi filtrare/ordinare per `NetBIOS Name` o “server flag” in 2 secondi, e passare la lista ai tool successivi.

Errore comune + fix: `-s` non si combina con alcune modalità (es. dump). Se ti serve debug, usa `-v` o `-d`, non `-s`. (\[Debian Manpages]\[1])

Extra (follow-up da lab): se vuoi subito passare dalla lista a test SMB/AD, collega il flusso con [CrackMapExec/NetExec per mappare SMB e privilegi](https://hackita.it/articoli/crackmapexec/).

## Errori comuni e troubleshooting (quelli che ti bloccano davvero)

> **In breve:** la maggior parte dei “non funziona” è: UDP 137 filtrato, `-r` senza privilegi, o rumore di rete/host che rispondono male.

### “Nessun risultato” su una subnet che sai essere Windows

Perché succede: firewall locale o segmentazione blocca UDP 137, oppure NetBIOS disabilitato.

Fix in lab:

* Prova su un singolo host certo (IP noto).
* Se hai discovery L2, usa la lista target da file invece dello sweep.

Comando:

```bash
nbtscan 10.10.10.10
```

Esempio di output (può variare):

```text
10.10.10.10      WS-DEV           <server>  DEV\devuser      00:0c:29:12:34:56
```

### “Permission denied” o problemi con `-r`

Perché succede: `-r` usa la porta locale 137 e può richiedere privilegi elevati. (\[Debian Manpages]\[1])

Fix in lab:

* Rilancia con `sudo`.
* Se non puoi, prova senza `-r` (accettando possibile minor affidabilità).

Comando:

```bash
sudo nbtscan -r 10.10.10.0/24
```

### “Connection reset by peer” (o errori simili) su host Windows legacy

Perché succede: se la porta è chiusa, l’host può rispondere con ICMP “port unreachable” che alcuni OS riportano come errore applicativo.

Fix: spesso puoi ignorarlo se stai scansionando range e alcuni host non parlano NetBIOS. (\[Debian Manpages]\[1])

## Alternative e tool correlati (quando preferirli)

> **In breve:** nbtscan è perfetto per NetBIOS name intel; per share enum, SMB posture o traffico, serve altro.

* Se vuoi discovery L2 (LAN) più affidabile: usa ARP-based (vedi [Netdiscover per discovery in rete locale](https://hackita.it/articoli/netdiscover/)).
* Se vuoi enumerare share e permessi SMB: passa a [smbclient](https://hackita.it/articoli/smbclient/).
* Se vuoi posture SMB e triage AD rapido (lab): considera [CrackMapExec/NetExec](https://hackita.it/articoli/crackmapexec/).
* Se vuoi detection/triage del traffico (blue-team in lab): cattura e filtra (vedi [Wireshark per analisi traffico](https://hackita.it/articoli/wireshark/)).

Quando NON sostituirlo: nbtscan non è un sostituto di uno scanner di porte o di un framework SMB; è uno strumento “mirato” su NetBIOS.

## Hardening & detection (NetBIOS sotto controllo)

> **In breve:** se NetBIOS non serve, riducilo; se serve, monitoralo: UDP 137/139 sono segnali forti e spesso evitabili.

Hardening (ambienti enterprise / lab harden):

* Disabilita NetBIOS over TCP/IP dove non necessario (client moderni, segmenti non legacy).
* Filtra e segmenta UDP 137 e TCP 139 tra VLAN.
* Riduci l’impatto di poisoning: disabilita LLMNR/NBNS e configura WPAD in modo esplicito.
* Per SMB: abilita SMB signing e controlla l’esposizione share.

Detection (cosa cercare):

* Spike di query NetBIOS su subnet (pattern “sweep”).
* Host che interrogano molti IP su UDP 137 in finestra breve.
* Correlazione con eventi SMB successivi (tentativi login, enumerazioni, share listing).

## Scenario pratico: nbtscan su una macchina HTB/PG

> **In breve:** in 3 mosse identifichi host Windows, confermi il ruolo via suffix e avvii un follow-up SMB controllato, documentando anche segnali di detection.

Ambiente: attacker Kali (lab), target subnet `10.10.10.0/24`, host Windows “interessante” `10.10.10.10`.

Obiettivo: ottenere nome NetBIOS + ruolo e preparare un follow-up SMB “pulito”.

Azione 1 — Sweep rapido

Perché: trovare host che rispondono a NetBIOS.

Cosa aspettarti: lista di host con nome e possibile flag server.

Comando:

```bash
sudo nbtscan -r 10.10.10.0/24
```

Azione 2 — Conferma ruolo (verbose)

Perché: leggere suffix e capire se stai guardando un DC/file server/browser.

Cosa aspettarti: tabella nomi con `<20>`, `<1C>`, ecc.

Comando:

```bash
nbtscan -v -h 10.10.10.10
```

Azione 3 — Follow-up SMB controllato (solo lab)

Perché: se vedi `<20>`, ha senso verificare condivisioni esposte.

Cosa aspettarti: lista share o errore di accesso (che è comunque informazione).

Comando:

```bash
smbclient -L //10.10.10.10 -N
```

Risultato atteso concreto: un elenco share (anche vuoto) o un messaggio di accesso negato da includere nel report.

Detection + hardening: lo sweep NetBIOS genera traffico evidente su UDP 137; in un ambiente monitorato lo vedi facilmente. Se vuoi “hardenare” il lab, filtra 137/139 dove non serve e disabilita NetBIOS/LLMNR/NBNS sui client.

## Playbook 10 minuti: nbtscan in un lab

> **In breve:** sequenza corta, ripetibile e “report-ready” per passare da subnet a target list con motivazione tecnica.

### Step 1 – Verifica tool e opzioni “reali” sulla tua distro

Allinea aspettative su `-t`, `-r`, `-s` guardando l’help locale.

```bash
nbtscan --help | head -60
```

### Step 2 – Sweep subnet con focus affidabilità

Usa `-r` se puoi (con `sudo`) per aumentare la qualità delle risposte.

```bash
sudo nbtscan -r 10.10.10.0/24
```

### Step 3 – Seleziona 3 host “candidati” (DC/file server/workstation admin)

Non inseguire tutto: scegli per nome e segnali `server`.

```bash
sudo nbtscan -r 10.10.10.0/24 | head -20
```

### Step 4 – Deep dive su 1 host ad alto valore

Conferma suffix e ruoli (cerca `<20>`, `<1C>`, `<1B>`).

```bash
nbtscan -v -h 10.10.10.25
```

### Step 5 – Esporta output parsabile per report e automazione

Passa a `-s` per CSV e filtri.

```bash
sudo nbtscan -r -s ',' 10.10.10.0/24 > nbtscan.csv
```

### Step 6 – Costruisci una lista “SMB-likely” da seguire

Estrai i target con segnali compatibili con file server service.

```bash
nbtscan -v 10.10.10.0/24 | grep "<20>" | awk '{print $1}' > smb_targets.txt
```

### Step 7 – Follow-up controllato e documentato

Usa tool SMB/AD solo sui target filtrati e annota risultati + log/detection.

```bash
while read ip; do smbclient -L "//$ip" -N; done < smb_targets.txt
```

## Checklist operativa

> **In breve:** spunta questi punti e nbtscan diventa “metodo”, non un comando random.

* Sempre contesto autorizzato: lab/CTF/HTB/PG o VM personali.
* Verifica `nbtscan --help` prima di usare `-t` (unità timeout).
* Se usi `-r`, esegui con `sudo` (porta locale 137).
* Parti da subnet piccola, poi scala (evita rumore inutile).
* Usa `-v` su host selezionati per leggere suffix e ruolo.
* Ricorda: `<20>` = candidato SMB; `<1C>` = indicatori DC.
* Per output parsabile, preferisci `-s` e salva su file.
* Non confondere “nome NetBIOS trovato” con “accesso”: sono cose diverse.
* Se hai già discovery L2, usa `-f targets.txt` invece dello sweep.
* Logga sempre i comandi eseguiti e i risultati (report-ready).
* Se stai hardenando il lab, filtra UDP 137/139 dove non serve.
* Monitora spike UDP 137 come segnale di sweep.

## Riassunto 80/20

> **In breve:** tre comandi (sweep, verbose, export) ti danno quasi tutto quello che serve per decidere i passi successivi.

| Obiettivo                        | Azione pratica               | Comando/Strumento                                    |                |
| -------------------------------- | ---------------------------- | ---------------------------------------------------- | -------------- |
| Scoprire host Windows “parlanti” | Sweep NetBIOS su subnet      | `sudo nbtscan -r 10.10.10.0/24`                      |                |
| Capire ruolo di un host          | Verbose + suffix             | `nbtscan -v -h 10.10.10.10`                          |                |
| Esportare per parsing            | CSV con separatore           | `sudo nbtscan -r -s ',' 10.10.10.0/24 > nbtscan.csv` |                |
| Target SMB rapidi                | Filtra `<20>`                | \`nbtscan -v 10.10.10.0/24                           | grep '\<20>'\` |
| Follow-up share enum             | Lista share senza auth (lab) | `smbclient -L //10.10.10.10 -N`                      |                |
| Triage AD/SMB (opzionale)        | Postura SMB e mapping        | `nxc smb 10.10.10.0/24`                              |                |

## Concetti controintuitivi

> **In breve:** gli errori più comuni nascono da aspettative sbagliate, non dal comando.

* **“Se nbtscan vede un host allora posso entrare”**
  No: ti dà intelligence, non accesso. Usalo per priorità e follow-up, non per conclusioni.
* **“`-r` è stealth”**
  No: è più affidabile, non invisibile. In detection, UDP 137 a raffica è un faro.
* **“NetBIOS = sempre Windows”**
  Spesso sì, ma anche Samba può rispondere. Interpreta output e contesto, non solo il nome.
* **“MAC sempre affidabile”**
  Su alcuni sistemi (Samba) puoi ricevere MAC nullo: è un limite della risposta, non un bug “tuo”. (\[Debian Manpages]\[1])

## FAQ

> **In breve:** risposte rapide ai blocchi più frequenti usando nbtscan in lab.

D: nbtscan usa quali porte?

R: Tipicamente interroga NetBIOS su UDP 137 per ottenere la tabella nomi e servizi. Se 137 è filtrata o NetBIOS è disabilitato, vedrai pochi o zero risultati. (\[Debian Manpages]\[1])

D: Perché `-r` richiede `sudo`?

R: Perché tenta di usare la porta locale 137 come sorgente; su Unix il bind su porte “basse” richiede privilegi elevati. Se non puoi, prova senza `-r`. (\[Debian Manpages]\[1])

D: Perché vedo “Connection reset by peer”?

R: Può succedere quando l’host risponde con ICMP “port unreachable” e il sistema lo espone come errore applicativo. In scansioni di rete è spesso ignorabile se stai mappando range e alcuni host non parlano NetBIOS. (\[Debian Manpages]\[1])

D: nbtscan può enumerare le condivisioni SMB?

R: No: per design non fa share scanning (richiede TCP ed è un altro problema). Usa tool SMB dedicati per quel passo. (\[Debian Manpages]\[1])

D: `-t` è in secondi o millisecondi?

R: Dipende dalla build/documentazione: controlla `nbtscan --help` sul tuo sistema e calibra su 1 host prima di scansionare una subnet. (\[Debian Manpages]\[1])

## Link utili su HackIta.it

> **In breve:** questi link sono “spoke” naturali: discovery LAN, follow-up SMB/AD e analisi traffico.

* [ARP-Scan: host discovery e pivoting interno](https://hackita.it/articoli/arp-scan/)
* [Netdiscover: scopri dispositivi e IP in LAN](https://hackita.it/articoli/netdiscover/)
* [Responder: attacco LLMNR/NBT-NS/WPAD in LAN](https://hackita.it/articoli/responder/)
* [Smbclient: accesso e attacco alle condivisioni Windows](https://hackita.it/articoli/smbclient/)
* [CrackMapExec/NetExec: attacchi rapidi su Active Directory](https://hackita.it/articoli/crackmapexec/)
* [Wireshark: analizza traffico e credenziali in lab](https://hackita.it/articoli/wireshark/)
* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

> **In breve:** fonti primarie per opzioni, comportamento e limiti del tool.

* [https://manpages.debian.org/testing/nbtscan/nbtscan.1.en.html](https://manpages.debian.org/testing/nbtscan/nbtscan.1.en.html) (\[Debian Manpages]\[1])
* [https://www.kali.org/tools/nbtscan/](https://www.kali.org/tools/nbtscan/) (\[Kali Linux]\[2])

## CTA finale HackITA

Se questo articolo ti ha sbloccato il recon interno, puoi supportare il progetto qui: /supporto/

Se vuoi accelerare davvero (lab guidati, metodologia, report-ready), trovi la formazione 1:1 qui: /servizi/

Per aziende e team: assessment e simulazioni di attacco autorizzate con hardening e detection inclusi su /servizi/

(1): [https://manpages.debian.org/testing/nbtscan/nbtscan.1.en.html](https://manpages.debian.org/testing/nbtscan/nbtscan.1.en.html) "nbtscan(1) — nbtscan — Debian testing — Debian Manpages"
(2): [https://www.kali.org/tools/nbtscan/](https://www.kali.org/tools/nbtscan/) "nbtscan | Kali Linux Tools"
