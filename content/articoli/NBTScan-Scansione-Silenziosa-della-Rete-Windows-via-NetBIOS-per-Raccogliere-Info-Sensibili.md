---
title: 'NBTScan: Scansione NetBIOS su Linux per il Recon Windows'
slug: nbtscan
description: 'NBTScan su Linux: scopri come scansionare host Windows, identificare nomi NetBIOS, domini, workgroup e informazioni utili per il network reconnaissance.'
image: /ntbscan.webp
draft: false
date: 2026-01-22T00:00:00.000Z
lastmod: 2026-09-15T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - nbtscan
  - netbios
  - Windows
  - Active Directory
  - Network Reconnaissance
---

# NBTScan: Scansione NetBIOS per il Recon di Reti Windows

nbtscan è il tool da riga di comando per la scansione NetBIOS di una rete Windows: interroga UDP 137 e restituisce nomi host, dominio/workgroup e ruoli (DC, file server, browser) in pochi minuti, senza dipendere da DNS. In questa guida trovi i comandi nbtscan essenziali — sweep di subnet, deep dive su un host, export per parsing — e come leggere i suffix per capire cosa hai davanti prima del follow-up SMB/AD.

## Cos'è nbtscan e dove si incastra nel workflow

nbtscan invia query NetBIOS (tipicamente su UDP 137) e restituisce nomi, user loggato e tabella nomi/servizi. Non è uno scanner generico: è un acceleratore di **NetBIOS intelligence**, utile per distinguere "host qualsiasi" da "host Windows interessante" (file server, DC, browser master).

Quando usarlo (in lab):

* Hai una subnet interna e vuoi nomi/ruoli senza dipendere da DNS.
* Vuoi identificare rapidamente host con File Server Service o segnali di Domain Controller per guidare i passi SMB/AD successivi.

Quando NON usarlo:

* Su segmenti non Windows (router/IoT): NetBIOS spesso non risponde.
* Per enumerare condivisioni: nbtscan non fa share scanning, è volutamente fuori scope.

## Installazione e Quick Check

```bash
sudo apt update && sudo apt install -y nbtscan
nbtscan --help | head -40
```

Output atteso (può variare per versione):

```text
NBTscan version 1.7.2.
Usage:
nbtscan [-v] [-d] [-e] [-l] [-t timeout] [-b bandwidth] [-r] [-q] [-s separator] [-m retransmits] (-f filename)|(<scan_range>)
...
```

`-r` può richiedere privilegi elevati perché tenta il bind sulla porta locale 137: se fallisce, rilancia con `sudo` o accetta di perdere qualche risposta senza. L'unità del timeout (`-t`) varia tra build: verifica sempre con `--help` sul tuo sistema prima di affidarti al valore di default. Il sorgente e il changelog delle opzioni sono mantenuti sul [repo ufficiale del progetto](https://github.com/resurrecting-open-source-projects/nbtscan).

## Sintassi Base e 3 Pattern

### Pattern 1 — Sweep subnet

```bash
sudo nbtscan -r 10.10.10.0/24
```

```text
IP address       NetBIOS Name     Server    User             MAC address
-----------------------------------------------------------------------
10.10.10.10      WS-DEV           <server>  DEV\devuser      00:0c:29:12:34:56
10.10.10.20      FILESRV          <server>  <unknown>        00:0c:29:aa:bb:cc
10.10.10.25      DC01             <server>  <unknown>        00:0c:29:11:22:33
```

`DC01` e `FILESRV` entrano subito nella shortlist per il follow-up SMB/AD. Se non ottieni risultati, prova senza `-r` o verifica che UDP 137 non sia filtrato nel lab.

### Pattern 2 — Deep dive su un host

```bash
nbtscan -v -h 10.10.10.25
```

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

`-h` funziona solo insieme a `-v`; senza, usa solo `-v` e interpreta i suffix manualmente.

### Pattern 3 — Target list da file

```bash
printf "10.10.10.10\n10.10.10.20\n10.10.10.25\n" > targets.txt
nbtscan -f targets.txt
```

Utile quando il discovery L2 è già stato fatto (es. con [ARP-Scan](https://hackita.it/articoli/arp-scan/)): nbtscan diventa identificazione e priorità, non discovery puro. Assicurati che il file abbia un IP per riga senza spazi o CRLF residui.

## Interpretare i Suffix NetBIOS

I suffix più utili in un lab Windows/AD:

* `<00>`: Workstation Service (nome macchina) o Domain Name (group)
* `<20>`: File Server Service — candidato naturale per il follow-up SMB
* `<1B>`: Domain Master Browser
* `<1C>`: Domain Controllers (group)
* `<1D>/<1E>`: Master Browser / Browser elections
* `__MSBROWSE__<01>`: segnali legati al browser service

Attenzione: `<1C>` identifica il **gruppo** Domain Controllers, non certifica da solo che quell'host specifico sia un DC — è un indicatore forte, da correlare con altri dati (porte aperte, risposta LDAP/Kerberos) prima di trattarlo come conferma.

```bash
nbtscan -v 10.10.10.25
```

Il MAC `00-00-00-00-00-00` può comparire su Samba o sistemi non Windows: nbtscan stampa quello che riceve, non lo inventa.

## Casi d'Uso Offensivi da Lab

### Selezionare target SMB senza perdere tempo

```bash
nbtscan -v 10.10.10.0/24 | grep "<20>" | awk '{print $1}' > smb_targets.txt
```

Ottieni una lista di IP con motivo, non una subnet a caso, da passare a tool SMB come [smbclient](https://hackita.it/articoli/smbclient/). Se l'output non è nel formato atteso, usa `-s` per un separatore custom e fai parsing robusto (vedi sezione successiva).

### Nomi NetBIOS come base per test di poisoning (solo lab)

I nomi macchina raccolti sono utili anche per costruire scenari controllati legati a risoluzione nomi debole in LAN — lo step naturale successivo, sempre in ambiente autorizzato, è [Responder per LLMNR/NBT-NS/WPAD](https://hackita.it/articoli/responder/). In quel contesto conviene già pensare alle mitigazioni lato difesa: disabilitare LLMNR/NBNS dove non serve e abilitare SMB signing.

## Parsing e Automazione

```bash
sudo nbtscan -r -s ',' 10.10.10.0/24 > nbtscan.csv
head -5 nbtscan.csv
```

```text
10.10.10.10,WS-DEV,<server>,DEV\devuser,00:0c:29:12:34:56
10.10.10.20,FILESRV,<server>,<unknown>,00:0c:29:aa:bb:cc
10.10.10.25,DC01,<server>,<unknown>,00:0c:29:11:22:33
```

Output senza header e con separatore scelto, pronto per filtri o pipeline verso strumenti successivi come [CrackMapExec/NetExec](https://hackita.it/articoli/crackmapexec/). `-s` non si combina con la modalità dump: per debug usa `-v` o `-d`.

## Errori Comuni

**Nessun risultato su una subnet Windows nota:** firewall locale o segmentazione blocca UDP 137, oppure NetBIOS è disabilitato. Prova su un host singolo certo, oppure usa `-f` se hai già una lista da discovery L2.

**Permission denied con `-r`:** richiede il bind sulla porta locale 137, serve `sudo`. Se non puoi elevare i privilegi, ometti `-r` accettando minore affidabilità.

**"Connection reset by peer" o simili su host legacy:** spesso è solo un ICMP "port unreachable" riportato come errore applicativo — ignorabile se stai scansionando un range con host che non parlano NetBIOS.

## Alternative e Tool Correlati

nbtscan copre solo la NetBIOS name intelligence. Per il resto del workflow:

* Discovery L2 più affidabile: [ARP-Scan](https://hackita.it/articoli/arp-scan/) o [Netdiscover](https://hackita.it/articoli/netdiscover/)
* Enumerazione share e permessi SMB: [smbclient](https://hackita.it/articoli/smbclient/)
* Posture SMB/AD e triage rapido: [CrackMapExec/NetExec](https://hackita.it/articoli/crackmapexec/)
* Analisi del traffico generato: [Wireshark](https://hackita.it/articoli/wireshark/)

nbtscan non sostituisce uno scanner di porte né un framework SMB: resta uno strumento mirato su NetBIOS.

## Hardening e Detection

**Hardening:**

* Disabilita NetBIOS over TCP/IP dove non serve, soprattutto su client moderni.
* Filtra e segmenta UDP 137 / TCP 139 tra VLAN.
* Disabilita LLMNR/NBNS e configura WPAD in modo esplicito.
* Abilita SMB signing e controlla l'esposizione delle share.

**Detection:**

* Spike di query NetBIOS su una subnet (pattern sweep) — è un segnale evidente, non uno scan silenzioso.
* Un singolo host che interroga molti IP su UDP 137 in poco tempo.
* Correla con eventi SMB successivi: tentativi di login, enumerazioni, share listing.

## Scenario Pratico: NBTScan su una Macchina HTB/PG

Ambiente: attacker Kali (lab), subnet target `10.10.10.0/24`, host interessante `10.10.10.10`.

**1. Sweep rapido**

```bash
sudo nbtscan -r 10.10.10.0/24
```

**2. Conferma ruolo (verbose)**

```bash
nbtscan -v -h 10.10.10.10
```

Cerca `<20>` (file server) o `<1C>` (Domain Controllers) nella tabella.

**3. Follow-up SMB controllato**

```bash
smbclient -L //10.10.10.10 -N
```

Un elenco share (anche vuoto) o un accesso negato sono comunque informazione da riportare. Lo sweep NetBIOS genera traffico ben visibile su UDP 137: in un ambiente monitorato lo si nota facilmente, quindi in lab conviene documentare anche questo aspetto insieme al risultato tecnico.

## Checklist Operativa

* Contesto sempre autorizzato: lab/CTF/HTB/PG o VM personali.
* Verifica `nbtscan --help` prima di fidarti dell'unità di `-t`.
* Con `-r`, esegui con `sudo` (bind sulla porta 137).
* Parti da una subnet piccola, poi scala.
* Usa `-v` sugli host selezionati per leggere i suffix.
* `<20>` = candidato SMB; `<1C>` = indicatore di gruppo DC, da correlare.
* Per output parsabile, usa `-s` e salva su file.
* "Nome trovato" non è "accesso ottenuto": sono cose diverse.
* Se hai già discovery L2, usa `-f targets.txt` invece dello sweep completo.
* Logga comandi e risultati.

## Riassunto 80/20

| Obiettivo               | Comando                                              |
| ----------------------- | ---------------------------------------------------- |
| Scoprire host Windows   | `sudo nbtscan -r 10.10.10.0/24`                      |
| Capire ruolo di un host | `nbtscan -v -h 10.10.10.10`                          |
| Esportare per parsing   | `sudo nbtscan -r -s ',' 10.10.10.0/24 > nbtscan.csv` |
| Target SMB rapidi       | `nbtscan -v 10.10.10.0/24 \| grep '<20>'`            |
| Follow-up share enum    | `smbclient -L //10.10.10.10 -N`                      |

## Concetti Controintuitivi

* **"Se nbtscan vede un host, posso entrare"** — no, dà intelligence, non accesso. Usalo per priorità e follow-up.
* **"`-r` è stealth"** — no, è più affidabile, non invisibile: uno sweep UDP 137 a raffica è un segnale forte in detection.
* **"NetBIOS = sempre Windows"** — spesso sì, ma anche Samba risponde. Interpreta output e contesto, non solo il nome.
* **"Il MAC è sempre affidabile"** — su alcuni sistemi (Samba) può arrivare nullo: è un limite della risposta ricevuta, non un errore di comando.

## FAQ

**A cosa serve nbtscan?**
Interroga NetBIOS per ottenere nomi host, informazioni sui servizi e altri dati utili al recon di una rete Windows, senza dipendere da DNS.

**Quali porte usa nbtscan?**
Tipicamente UDP 137. Se è filtrata o NetBIOS è disabilitato, otterrai pochi o zero risultati.

**Perché `-r` richiede sudo?**
Tenta il bind sulla porta locale 137, e su Unix il bind su porte basse richiede privilegi elevati.

**Perché vedo "Connection reset by peer"?**
Può capitare quando l'host risponde con ICMP "port unreachable" esposto come errore applicativo — spesso ignorabile scansionando un range.

**nbtscan può enumerare le condivisioni SMB?**
No, per design non fa share scanning: usa un tool SMB dedicato per quel passo.

**`-t` è in secondi o millisecondi?**
Dipende dalla build: verifica sempre con `nbtscan --help` e calibra su un host singolo prima di scansionare una subnet intera.
