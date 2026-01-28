---
title: 'Netdiscover: Scopri Dispositivi e IP Nascosti Nella Rete LAN'
slug: netdiscover
description: Netdiscover è un tool essenziale per identificare dispositivi attivi nella rete locale. Ideale per il recon silenzioso tramite ARP su ambienti privi di DNS o DHCP.
image: /NETDISCOVER.webp
draft: false
date: 2026-01-26T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - Netdiscover
---

# Netdiscover: Scopri Dispositivi e IP Nascosti Nella Rete LAN

Se in lab il ping “non risponde” o vuoi scoprire subito **gateway + host vivi** nel tuo segmento L2, qui fai reconnaissance con netdiscover in modo controllato e verificabile.

## Intro

Netdiscover è un tool di **ricognizione ARP** che scopre host in rete **sniffando ARP** (passivo) o **inviando richieste ARP** (attivo).

In un pentest interno da lab ti serve per mappare rapidamente il broadcast domain: IP, MAC e spesso anche il vendor (OUI), senza dipendere da DNS/DHCP “comodi”.

Cosa farai/imparerai:

* scegliere tra modalità attiva vs passiva senza farti male
* scansionare una subnet in modo deterministico (`-r`) o rapido (`-f`)
* esportare output parsabile (`-P/-L`) per passare alla fase successiva
* riconoscere limiti reali (VLAN, Wi-Fi isolation, NAT, permessi)

Nota etica: usa queste tecniche solo su lab/CTF/HTB/PG/VM personali o sistemi di tua proprietà con autorizzazione esplicita.

## Cos’è netdiscover e dove si incastra nel workflow

> **In breve:** netdiscover è “host discovery da Layer 2”: usa ARP per trovare host vivi nel tuo segmento, anche quando l’ICMP è filtrato o rumoroso.

Netdiscover entra **subito dopo** l’accesso iniziale o quando sei “dentro” una LAN di lab e devi capire: chi c’è, qual è il gateway, quali device sembrano server/workstation.

Se stai ancora facendo discovery con ICMP (ping/fping/hping3), ricordati che in tanti lab l’ICMP viene filtrato: come base di confronto vedi anche la guida su **ping e tecniche ICMP per il recon** (/articoli/ping/).

Quando NON usarlo: se devi scoprire host **oltre un router** (ARP non attraversa L3) o se sei su Wi-Fi con **client isolation** attivo: vedrai poco o nulla.

## Installazione / verifica versione / quick sanity check

> **In breve:** installa il pacchetto, verifica l’help, e controlla subito interfaccia + subnet: il 90% dei “non trova nulla” nasce qui.

Perché: se l’interfaccia è sbagliata o non hai privilegi, netdiscover sembra “rotto” anche quando non lo è.
Cosa aspettarti: `netdiscover --help` mostra opzioni (attivo/passivo, range, output parsabile).
Comando:

```bash
sudo apt update
sudo apt install netdiscover
netdiscover --help
```

Interpretazione: se vedi usage e flag principali, il tool è ok.
Errore comune + fix: `Permission denied` / niente traffico → usa `sudo` (o capabilities), e scegli l’interfaccia corretta.

Perché: devi sapere su quale NIC stai sniffando/scansionando.
Cosa aspettarti: interfacce con IP (es. `eth0 10.10.10.50/24`).
Comando:

```bash
ip -br a
ip route
```

Interpretazione: l’interfaccia con IP nella subnet del target è quella giusta.
Errore comune + fix: sei su NAT (VM) e “non vedi la LAN” → passa a bridge/host-only nel lab.

## Attivo vs passivo: cosa cambia davvero (e quanto rumore fai)

> **In breve:** in passivo (`-p`) non invii nulla e aspetti ARP reali; in attivo mandi richieste ARP e “forzi” risposte dagli host vivi nel segmento.

### Modalità passiva (sniff ARP)

Perché: vuoi **low-noise** e vuoi capire se nel lab c’è traffico ARP utile.
Cosa aspettarti: host che compaiono col tempo mentre la rete “parla” (più lenta, ma silenziosa).
Comando:

```bash
sudo netdiscover -i eth0 -p
```

Esempio di output (può variare):

```text
IP              At MAC Address       Count  Len  MAC Vendor
10.10.10.1      00:11:22:33:44:55   12     60   (Gateway/Router)
10.10.10.25     08:00:27:aa:bb:cc   4      60   PCS Systemtechnik GmbH
```

Interpretazione: hai visibilità L2; se la rete è “viva” iniziano ad apparire IP/MAC.
Errore comune + fix: non compare nulla → spesso non c’è traffico ARP o sei su Wi-Fi isolata/segmento sbagliato.

Validation in lab: fai generare ARP da una VM (es. ping verso un IP della subnet) e verifica che compaia la risoluzione.
Segnali di detection: praticamente zero lato IDS “classico”, ma un SOC può notare sniffer/pcap su endpoint compromesso.
Hardening: segmentazione VLAN e client isolation su Wi-Fi riducono la visibilità L2.

### Modalità attiva (ARP scan su range)

Perché: vuoi risultati **veloci e completi** sul tuo /24 di lab.
Cosa aspettarti: host vivi rispondono con ARP reply; vedi IP/MAC/vendor.
Comando:

```bash
sudo netdiscover -i eth0 -r 10.10.10.0/24
```

Esempio di output (può variare):

```text
IP              At MAC Address       Count  Len  MAC Vendor
10.10.10.1      00:11:22:33:44:55   1      60   (Gateway/Router)
10.10.10.10     52:54:00:12:34:56   1      60   QEMU virtual NIC
10.10.10.20     3c:52:82:de:ad:be   1      60   Microsoft Corporation
```

Interpretazione: ora hai “mappa minima” del segmento: gateway, VM/host, possibili Windows.
Errore comune + fix: risultati incompleti su reti con perdita → aumenta `-c` e/o aggiungi delay con `-s`.

Validation in lab: confronta almeno 2 host con `ip neigh show` per vedere che l’ARP cache si popoli coerentemente.
Segnali di detection: picco di ARP request dallo stesso source (tu) in pochi secondi.
Hardening: Dynamic ARP Inspection (DAI), port security e monitor di storm/ARP anomaly su switch.

## Sintassi base + 3 pattern che userai sempre

> **In breve:** 1) auto scan rapido, 2) range deterministico, 3) output parsabile per automazione/report.

### Pattern 1 — Auto scan “plug & play” (quando non sai la subnet)

Perché: ti serve un “quick win” quando sei appena entrato e vuoi capire che LAN stai vedendo.
Cosa aspettarti: netdiscover prova reti comuni e mostra host trovati (meglio con fast mode).
Comando:

```bash
sudo netdiscover -i eth0 -f
```

Interpretazione: utile per orientarti, ma non è sempre deterministico come un `-r`.
Errore comune + fix: scansiona “troppo” e ci mette secoli → passa subito a `-r` appena identifichi la subnet corretta.

### Pattern 2 — Range deterministico (il più “pulito” per un lab)

Perché: vuoi coprire **tutti gli IP** di una subnet specifica e avere un risultato ripetibile.
Cosa aspettarti: output stabile; puoi rilanciare e confrontare.
Comando:

```bash
sudo netdiscover -i eth0 -r 10.10.10.0/24 -c 2 -s 10
```

Interpretazione: `-c 2` ripete l’ARP request (utile con loss), `-s 10` rallenta di poco e riduce burst.
Errore comune + fix: troppo lento → riduci `-c`/`-s` o usa `-f` solo per orientarti.

### Pattern 3 — Output parsabile (handoff alla fase successiva)

Perché: vuoi passare da “vedo host” a “ci faccio qualcosa” (liste, follow-up scan, report).
Cosa aspettarti: stampa in formato adatto a parsing e termina (`-P`) oppure continua a sniffare dopo lo scan (`-L`).
Comando:

```bash
sudo netdiscover -i eth0 -r 10.10.10.0/24 -P -N > hosts.txt
```

Esempio di output (può variare):

```text
10.10.10.1 00:11:22:33:44:55 1 60
10.10.10.20 3c:52:82:de:ad:be 1 60
10.10.10.25 08:00:27:aa:bb:cc 1 60
```

Interpretazione: `hosts.txt` diventa una base per priorità target e tool successivi.
Errore comune + fix: ti serve anche sniff dopo lo scan → usa `-L` al posto di `-P`.

## Leggere l’output e scegliere target “che valgono”

> **In breve:** IP+MAC non bastano: usa vendor/OUI e pattern di indirizzi per capire dove puntare prima.

Netdiscover spesso ti dà “segnali” rapidi:

* gateway quasi sempre `.1` o `.254` (ma non è una regola)
* MAC vendor che suggerisce Windows, VM, vendor networking
* host che appaiono spesso in passivo (talker = spesso infrastruttura)

Se vuoi un discovery più aggressivo e focalizzato (e spesso più veloce) sul segmento L2, la “spoke guide” naturale è **ARP-Scan per pivoting interno** (/articoli/arp-scan/).

Quando NON usarlo: non cadere nel bias “vendor = ruolo”. Un “Microsoft” può essere un client qualunque, non un server.

## Casi d’uso offensivi “da lab” + validazione (sempre con mitigazioni)

> **In breve:** netdiscover ti dà i pezzi per costruire una chain in lab: mappa host → scegli target → passi a enum/mitm/detection con evidenza.

### Caso 1 — Trova gateway + vittima per un MITM controllato (solo lab)

Perché: per un MITM in lab ti servono almeno **IP del gateway** e **IP del target** nello stesso segmento.
Cosa aspettarti: lista host dove identificare il gateway (es. 10.10.10.1) e il client (es. 10.10.10.25).
Comando:

```bash
sudo netdiscover -i eth0 -r 10.10.10.0/24
```

Interpretazione: seleziona 2 IP: gateway e un client “interessante” (talker/vendo).
Errore comune + fix: scegli IP fuori VLAN/segmento → netdiscover non li vedrà; resta nel tuo broadcast domain.

Validation in lab: conferma il gateway con `ip route | grep default` dalla tua VM e verifica che il MAC sia coerente.
Segnali di detection: burst ARP e (se fai MITM dopo) ARP spoofing evidente su switch/EDR.
Hardening: DAI + DHCP snooping, port security e NAC riducono spoof/scan; segmenta VLAN.

Se vuoi estendere questo scenario, considera **Bettercap** come “pillar” del cluster per MITM/sniffing/spoofing (/articoli/bettercap/).

### Caso 2 — Identifica host Windows “probabili” e prepara recon mirato

Perché: in lab AD/Windows, trovare subito le workstation ti fa risparmiare ore (enum NetBIOS/SMB, name resolution, ecc.).
Cosa aspettarti: entry con vendor che suggerisce NIC Microsoft/VM e IP “client-like”.
Comando:

```bash
sudo netdiscover -i eth0 -r 10.10.10.0/24 -P -N | grep -Ei "microsoft|msft" || true
```

Interpretazione: è un filtro grezzo: non è certezza, ma è una shortlist per follow-up.
Errore comune + fix: su `-P -N` potresti non avere vendor nel formato parsabile → usa output standard per la fase di triage e `-P` solo per liste IP/MAC.

Validation in lab: verifica 1–2 host con un tool Windows-specific; per esempio **NBTScan** per NetBIOS discovery (/articoli/nbtscan/).
Segnali di detection: ARP scan + successivo probing NetBIOS/SMB può far scattare alert.
Hardening: disabilita legacy name resolution dove possibile, limita broadcast, abilita logging e blocchi su endpoint.

### Caso 3 — Recon passivo “prima di muoverti” (quando vuoi capire il rumore)

Perché: spesso vuoi prima capire se ci sono host “chiacchieroni”, ARP storms, o pattern di rete, senza inviare nulla.
Cosa aspettarti: host che entrano/escono, device che refreshano ARP, gateway molto presente.
Comando:

```bash
sudo netdiscover -i eth0 -p -F "arp"
```

Interpretazione: stai solo sniffando ARP; se è piatto, non aspettarti miracoli.
Errore comune + fix: “silenzio” totale → genera tu traffico nel lab o passa all’attivo con `-r`.

Validation in lab: genera un cambio ARP (es. accendi una VM) e controlla che compaia la nuova entry.
Segnali di detection: minimi, ma un defender può cercare interfacce in promiscous mode e processi pcap.
Hardening: protezioni endpoint (EDR), least privilege, e controllo capabilities per libpcap.

## Errori comuni e troubleshooting (permessi, rete, VM)

> **In breve:** se netdiscover “non vede niente”, di solito è colpa di interfaccia, segmentazione, Wi-Fi isolation o virtualizzazione.

Perché: ARP non attraversa router: se stai provando a vedere una subnet “remota”, non funzionerà.
Cosa aspettarti: risultati solo nel tuo segmento L2.
Comando:

```bash
ip route
```

Interpretazione: se il target è dietro un gateway (L3), netdiscover non lo scopre via ARP.
Errore comune + fix: vuoi scoprire host su subnet remote → usa tool L3 (es. scan ICMP/TCP) oppure fai pivot nel lab.

Perché: in VM con NAT spesso non sniffi ARP della LAN reale.
Cosa aspettarti: con bridge/host-only in lab vedi ARP del segmento.
Comando:

```bash
ip -br a
```

Interpretazione: se sei su una subnet “strana” (es. 10.0.2.0/24 tipica NAT), sei nel mondo NAT.
Errore comune + fix: cambia modalità rete VM a bridge/host-only (solo lab isolati).

Perché: vuoi capire se ARP “passa” davvero sulla tua interfaccia.
Cosa aspettarti: pacchetti ARP in chiaro mentre netdiscover gira.
Comando:

```bash
sudo tcpdump -ni eth0 arp
```

Interpretazione: se tcpdump non vede ARP, netdiscover non può inventarselo.
Errore comune + fix: interfaccia sbagliata o client isolation; per analisi pacchetti vedi anche **tcpdump su HackIta** (/articoli/tcpdump/).

## Alternative e tool correlati (quando preferirli)

> **In breve:** netdiscover è ottimo per ARP discovery; ma a volte vuoi tool più veloci, più “L3”, o più analitici.

* ARP-scan: spesso più rapido e diretto per scansionare il localnet in L2 (segmento corrente).
* Nmap host discovery: utile quando devi andare oltre L2 o vuoi integrare subito script/port scan.
* Wireshark/TShark: se devi analizzare “perché” succede qualcosa in rete, non solo “chi c’è”.

Quando NON usarli: non sostituire netdiscover con tool L3 se sei in un lab dove ICMP è filtrato e ti basta mappare il segmento.

## Hardening & detection: cosa dovrebbe cercare un defender (e cosa evitare tu in lab)

> **In breve:** ARP scan e sniffing lasciano tracce: il defender può vedere burst ARP, promisc mode, e anomalie su switch/endpoint.

Detection pratica:

* burst di ARP request dallo stesso host in pochi secondi (soprattutto in attivo su /24)
* cambiamenti frequenti nelle tabelle ARP o conflitti (indicatori di scan/spoof)
* endpoint con processi che aprono libpcap o interfaccia in promiscous mode

Hardening pratico:

* Dynamic ARP Inspection (DAI) + DHCP snooping su switch
* segmentazione VLAN e riduzione broadcast domain
* port security e rate limiting su ARP/unknown unicast (dove supportato)
* EDR/monitoring che segnala sniffing e tool di rete “anomali” su endpoint

Quando NON “spingere”: se il tuo obiettivo è stealth in lab, evita scan aggressivi senza delay (`-s`) e senza contesto: prima passivo, poi range mirato.

## Scenario pratico: netdiscover su una macchina HTB/PG

Ambiente: Kali in lab, interfaccia `eth0`, target subnet `10.10.10.0/24`, host fittizio `10.10.10.10`.

Obiettivo: identificare gateway e 2 host vivi, esportare una lista IP per follow-up.

Perché: confermare subnet e gateway prima di scansionare.
Cosa aspettarti: una default route verso `10.10.10.1`.
Comando:

```bash
ip route
```

Perché: fare discovery veloce e ottenere una prima mappa host.
Cosa aspettarti: 3–20 entry (dipende dal lab) con IP/MAC e vendor.
Comando:

```bash
sudo netdiscover -i eth0 -r 10.10.10.0/24 -c 2 -s 10
```

Perché: esportare output parsabile per la fase successiva.
Cosa aspettarti: file `hosts.txt` con righe IP/MAC.
Comando:

```bash
sudo netdiscover -i eth0 -r 10.10.10.0/24 -P -N > hosts.txt
```

Risultato atteso: vedi `10.10.10.1` (gateway) e almeno 2 host vivi; `hosts.txt` è pronto per enum mirata.

Detection + hardening: un defender può notare burst ARP e spike in ARP table; mitigazioni tipiche sono VLAN più piccole, DAI/DHCP snooping e rate limiting su switch.

## Playbook 10 minuti: netdiscover in un lab

### Step 1 – Identifica interfaccia e subnet reale

Prima di lanciare tool “a caso”, fissa interfaccia e rete: evita 10 minuti buttati su NAT o NIC sbagliata.

```bash
ip -br a
ip route
```

### Step 2 – Parti in passivo per capire se la rete “parla”

Se vuoi low-noise o stai facendo troubleshooting, inizia passivo: se non vedi ARP qui, in attivo avrai comunque problemi.

```bash
sudo netdiscover -i eth0 -p
```

### Step 3 – Passa all’attivo su range deterministico

Appena hai la subnet, usa `-r`: è ripetibile e report-friendly.

```bash
sudo netdiscover -i eth0 -r 10.10.10.0/24
```

### Step 4 – Se hai fretta, usa fast mode (ma poi rifinisci)

Fast mode è un acceleratore, non una verità assoluta: usalo per orientarti, poi torna su `-r`.

```bash
sudo netdiscover -i eth0 -f
```

### Step 5 – Stabilizza risultati su reti “sporche” (loss/rumore)

Se perdi pacchetti o hai rumore, ripeti richieste e inserisci un minimo delay.

```bash
sudo netdiscover -i eth0 -r 10.10.10.0/24 -c 3 -s 10
```

### Step 6 – Esporta output parsabile e crea una shortlist

Porta fuori una lista per il follow-up (enum/scan mirato) senza reinventarti parsing a mano.

```bash
sudo netdiscover -i eth0 -r 10.10.10.0/24 -P -N > hosts.txt
```

### Step 7 – Verifica che ARP stia davvero passando (debug rapido)

Se hai dubbi, guarda i pacchetti: è il reality check più veloce.

```bash
sudo tcpdump -ni eth0 arp
```

## Checklist operativa

* Verifica di essere in un lab/CTF/VM autorizzata prima di iniziare.
* Identifica interfaccia corretta con `ip -br a`.
* Conferma subnet e gateway con `ip route`.
* Inizia con `-p` se vuoi low-noise o se stai debuggando visibilità.
* Usa `-r <subnet>` per scan deterministici (es. `10.10.10.0/24`).
* Su reti con perdita, aumenta `-c` (ripetizioni) e usa `-s` (delay).
* Se non sai la rete, usa `-f` solo per orientarti, poi passa a `-r`.
* Per automazione/report, esporta con `-P -N` in un file.
* Se vuoi continuare a sniffare dopo lo scan, preferisci `-L`.
* Ricorda: ARP vale solo nel broadcast domain (no subnet remote).
* Se non trovi host, controlla virtualizzazione (NAT vs bridge/host-only).
* Se sospetti Wi-Fi isolation, aspettati risultati poveri anche in `-r`.

## Riassunto 80/20

| Obiettivo                 | Azione pratica                   | Comando/Strumento              |
| ------------------------- | -------------------------------- | ------------------------------ |
| Capire la subnet          | Leggi route e IP locale          | `ip route`                     |
| Low-noise recon           | Sniff ARP senza inviare traffico | `netdiscover -p`               |
| Discovery completa L2     | Scansiona un range /24           | `netdiscover -r 10.10.10.0/24` |
| Accelerare l’orientamento | Auto scan rapido                 | `netdiscover -f`               |
| Esportare per follow-up   | Output parsabile su file         | `netdiscover -P -N`            |
| Reality check traffico    | Vedi ARP a livello pacchetto     | `tcpdump arp`                  |

## Concetti controintuitivi

* **“Se ping non risponde allora host down”**
  Spesso è falso: ICMP può essere filtrato. In lab usa ARP discovery e valida su L2, poi passa a probing mirato.
* **“Passivo = sempre veloce”**
  Passivo è silenzioso ma può essere lento se la rete non genera ARP. In lab, se ti serve certezza, passa a `-r`.
* **“Netdiscover vede tutta la rete”**
  No: vede il tuo broadcast domain. Se vuoi subnet remote, serve pivot o scan L3.
* **“Vendor = ruolo”**
  OUI aiuta, ma non è prova: una NIC “Microsoft” non significa “server AD”. Verifica con enum successiva e logica di lab.

## FAQ

D: Netdiscover funziona oltre il router (subnet remote)?

R: No: ARP è Layer 2 e non attraversa router. Per subnet remote serve un pivot nel lab o host discovery L3.

D: Qual è la differenza pratica tra `-P` e `-L`?

R: `-P` stampa in formato parsabile e **si ferma** dopo lo scan attivo. `-L` è simile ma **continua ad ascoltare** dopo lo scan.

D: Perché in modalità passiva non vedo nulla?

R: Perché non c’è traffico ARP sufficiente o sei nel segmento sbagliato (NAT, Wi-Fi isolation). Genera traffico in lab o usa `-r`.

D: Come riduco il “rumore” in attivo?

R: Aggiungi un minimo delay con `-s` e non esagerare con ripetizioni `-c`. Scansiona solo il range necessario.

D: Devo usare per forza `sudo`?

R: Nella pratica sì: sniff e invio ARP richiedono privilegi/capabilities. Se non li hai, vedrai output vuoto o errori.

## Link utili su HackIta.it

* ARP-Scan per host discovery e pivoting interno: /articoli/arp-scan/
* Ping e tecniche ICMP per il recon (pro/contro rispetto ad ARP): /articoli/ping/
* Tcpdump per verificare ARP e fare troubleshooting: /articoli/tcpdump/
* TShark per analisi rapida del traffico da terminale: /articoli/tshark/
* Bettercap per MITM/sniffing/spoofing in lab: /articoli/bettercap/
* NBTScan per discovery mirata in reti Windows: /articoli/nbtscan/

/supporto/
/contatto/
/articoli/
/servizi/
/about/
/categorie/

## Riferimenti autorevoli

* Kali Linux Tools – netdiscover: [https://www.kali.org/tools/netdiscover/](https://www.kali.org/tools/netdiscover/)
* Kali Package Tracker – netdiscover: [https://pkg.kali.org/pkg/netdiscover](https://pkg.kali.org/pkg/netdiscover)

## CTA finale HackIta

Se questo contenuto ti è stato utile e vuoi far crescere HackIta, puoi supportare il progetto qui: /supporto/.

Se vuoi una mano pratica (lab guidati, metodo OSCP-style, troubleshooting rapido), trovi la formazione 1:1 qui: /servizi/.

Se sei un’azienda e ti serve un assessment o un test autorizzato (con report e remediation), i servizi sono qui: /servizi/.

(1): [https://www.kali.org/tools/netdiscover/](https://www.kali.org/tools/netdiscover/) "netdiscover | Kali Linux Tools"
(2): [https://pkg.kali.org/pkg/netdiscover](https://pkg.kali.org/pkg/netdiscover?utm_source=chatgpt.com) "netdiscover"
