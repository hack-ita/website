---
title: Ping e Tecniche ICMP e Scansioni Attive Per Il Recon
slug: ping
description: 'Analizza il comportamento della rete con ping, fping e hping3. Tecniche di ricognizione ICMP, host discovery e test su firewall usati nei pentest.'
image: /ping.webp
draft: false
date: 2026-01-26T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - icmp
  - ping
---

# Ping e Tecniche ICMP e Scansioni Attive Per Il Recon

Se `ping` “non risponde”, in un lab vuoi capire subito se è **host down**, **ICMP filtrato**, **DNS rotto** o **MTU/route**: e farlo con 2–3 comandi verificabili.

## Intro

`ping` invia richieste ICMP Echo e misura risposta, latenza e perdita pacchetti: è la “sonda” più semplice per validare connettività.

In pentest interno (sempre autorizzato) ti serve per:

* fare pre-check low-noise prima di scansioni rumorose
* capire se un segmento/route è raggiungibile
* scovare filtri (ICMP bloccato, rate-limit) e problemi MTU

Cosa farai qui:

* impari 3 pattern che userai sempre
* usi TTL/MTU in modo realistico (senza magie)
* risolvi gli errori tipici e chiudi il vettore con hardening + detection

Nota etica: tutto quanto segue è **solo per lab/CTF/HTB/PG/VM personali o sistemi esplicitamente autorizzati**.

## Cos’è ping e dove si incastra nel workflow

> **In breve:** `ping` è un **pre-check**: ti dice se una destinazione risponde via ICMP e se la tratta è stabile, ma non garantisce che i servizi siano raggiungibili.

In un workflow “attacker-informed” usalo così:

1. Validazione reachability (low-noise).
2. Se ICMP è bloccato: cambia strategia (ARP in LAN o probe TCP/UDP).
3. Solo dopo passi a enumerazione (porte/servizi) e cattura traffico.

Quando NON usarlo: per “host discovery massivo” su reti grandi (anche in lab) è inefficiente e può triggerare rate-limit/alert. Per quello, meglio tool dedicati (vedi sezione alternative).

## Installazione, privilegi e quick sanity check

> **In breve:** su Kali di solito c’è già; se `ping` fallisce, spesso è un tema di privilegi/capabilities o di ambiente (container/minimal).

Perché: prima di interpretare “host down”, verifica che il tuo `ping` funzioni localmente.

Cosa aspettarti: un reply immediato su loopback; se no, il problema è locale.

Comando:

```bash
ping -c 1 127.0.0.1
```

Esempio di output (può variare):

```text
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.05 ms
```

Interpretazione: se `127.0.0.1` risponde, l’eseguibile funziona; i problemi verso la rete sono altrove.

Errore comune + fix: `ping: command not found` su immagini/minimal → installa il pacchetto (Debian/Kali: `sudo apt update && sudo apt install -y iputils-ping`).

## Sintassi base: 3 pattern che userai sempre

> **In breve:** (1) 1 pacchetto con timeout, (2) test senza DNS, (3) misura qualità (loss/jitter) con pochi colpi.

### Pattern 1 — “È vivo?” (1 pacchetto + timeout)

Perché: confermi reachability senza perdere tempo.

Cosa aspettarti: 1 risposta o timeout entro pochi secondi.

Comando:

```bash
ping -c 1 -W 1 10.10.10.10
```

Esempio di output (può variare):

```text
PING 10.10.10.10 (10.10.10.10) 56(84) bytes of data.
64 bytes from 10.10.10.10: icmp_seq=1 ttl=63 time=12.3 ms

--- 10.10.10.10 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
```

Interpretazione: se risponde, la tratta ICMP funziona; `ttl=` e `time=` sono indizi utili, non certezze assolute.

Errore comune + fix: `Destination Host Unreachable` → spesso route/gateway/segmento non raggiungibile: verifica IP/subnet e route (o passa a probe su gateway nel troubleshooting).

### Pattern 2 — “Non voglio dipendere dal DNS”

Perché: se DNS è rotto o manipolato, eviti falsi negativi.

Cosa aspettarti: output solo numerico, più “pulito” per parsing.

Comando:

```bash
ping -n -c 1 -W 1 example.com
```

Esempio di output (può variare):

```text
PING 93.184.216.34 (93.184.216.34) 56(84) bytes of data.
64 bytes from 93.184.216.34: icmp_seq=1 ttl=52 time=25.8 ms
```

Interpretazione: `-n` evita reverse DNS; utile in lab quando fai raccolta rapida di evidenze.

Errore comune + fix: se `example.com` non risolve, non è colpa di `-n`: prova direttamente IP o sistema DNS.

### Pattern 3 — “Qualità della tratta” (pochi pacchetti)

Perché: prima di exploit/enum vuoi sapere se la rete è instabile (packet loss) o lenta (RTT alto).

Cosa aspettarti: statistiche su loss e rtt.

Comando:

```bash
ping -c 5 -W 1 10.10.10.10
```

Esempio di output (può variare):

```text
--- 10.10.10.10 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4006ms
rtt min/avg/max/mdev = 11.9/12.6/13.4/0.5 ms
```

Interpretazione: loss >0% e `mdev` alto spesso significano tratta congestionata o rate-limit.

Errore comune + fix: `ping` “va a scatti” → riduci frequenza con `-i` (vedi troubleshooting) per evitare throttling.

## Casi d’uso offensivi da lab: ipotesi → verifica

> **In breve:** `ping` non “buca” nulla: ti aiuta a fare ipotesi (reachability, filtro, segmento) e a validarle prima di enumerazioni più rumorose.

### Pre-check prima di enumerazione porte

Perché: eviti di lanciare scan su target che non è raggiungibile (o su segmento sbagliato).

Cosa aspettarti: risposta ICMP o timeout; in entrambi i casi prendi decisioni.

Comando:

```bash
ping -c 1 -W 1 10.10.10.10 && echo "ICMP OK: passo a enum porte"
```

Esempio di output (può variare):

```text
64 bytes from 10.10.10.10: icmp_seq=1 ttl=63 time=12.1 ms
ICMP OK: passo a enum porte
```

Interpretazione: “ICMP OK” non significa “porte OK”, ma ti dà un segnale iniziale affidabile.

Errore comune + fix: ICMP bloccato ma host vivo → non fermarti: passa a tecniche L2 in LAN (vedi “host discovery con ARP-Scan” su [https://hackita.it/articoli/arp-scan/](https://hackita.it/articoli/arp-scan/)).

### Test rapido di reachability verso gateway/segmento

Perché: se hai pivot in lab, vuoi sapere se un nuovo segmento è raggiungibile.

Cosa aspettarti: reply dal gateway o timeout (route/ACL).

Comando:

```bash
ping -c 1 -W 1 10.10.10.1
```

Esempio di output (può variare):

```text
64 bytes from 10.10.10.1: icmp_seq=1 ttl=64 time=1.2 ms
```

Interpretazione: gateway raggiungibile → ha senso provare discovery nel segmento (con tool adatti).

Errore comune + fix: `100% packet loss` → può essere ACL ICMP; valida con probe su TCP (tool correlati) o discovery L2 se sei nella stessa LAN.

## ICMP “leakage” e cosa puoi inferire (senza inventare)

> **In breve:** da `ping` puoi ottenere indizi su **latenza**, **loss**, e talvolta **hop distance**; la “fingerprint OS via TTL” è solo una heuristic.

### Heuristic: TTL in risposta (fingerprinting leggero)

Perché: alcuni ambienti mostrano TTL “tipici” (Windows spesso più alto di Linux), ma tra hop e device intermedi il valore cambia.

Cosa aspettarti: una riga con `ttl=`.

Comando:

```bash
ping -c 1 -W 1 10.10.10.10 | grep -o 'ttl=[0-9]*'
```

Esempio di output (può variare):

```text
ttl=63
```

Interpretazione: `ttl` vicino a 64 spesso suggerisce host “tipo Linux” a \~1 hop, ma non è prova: NAT, firewall e routing possono alterare.

Errore comune + fix: “TTL dice Windows sicuro” → no: usa TTL solo per prioritizzare ipotesi, poi conferma con banner/SMB/LDAP ecc.

### Path MTU discovery (utile anche in attacco/defense)

Perché: se hai drop strani su exploit/transfer, può essere MTU; il test con DF ti dice se la tratta frammenta.

Cosa aspettarti: o reply (MTU ok) o “Frag needed”/nessuna risposta (dipende da rete/OS).

Comando:

```bash
ping -c 1 -W 1 -M do -s 1472 10.10.10.10
```

Esempio di output (può variare):

```text
PING 10.10.10.10 (10.10.10.10) 1472(1500) bytes of data.
1472 bytes from 10.10.10.10: icmp_seq=1 ttl=63 time=13.8 ms
```

Interpretazione: se passa a 1472 con DF, il path supporta MTU 1500 su IPv4 (indicazione pratica per troubleshooting).

Errore comune + fix: “non risponde” → prova size più bassa (es. 1200) o ricorda che alcuni device filtrano i messaggi ICMP necessari.

## Errori comuni e troubleshooting (firewall, permessi, DNS, MTU)

> **In breve:** i 4 colpevoli classici sono: ICMP filtrato, route errata, DNS, e permessi/capabilities.

### “100% packet loss” ma il servizio esiste

Perché: molte reti bloccano Echo Request; non è “host down”.

Cosa aspettarti: timeout su ping, ma altri segnali (ARP in LAN o TCP connect) positivi.

Comando:

```bash
ping -c 1 -W 1 10.10.10.10
```

Esempio di output (può variare):

```text
--- 10.10.10.10 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
```

Interpretazione: potrebbe essere filtro ICMP o rate-limit; non concludere “morto”.

Errore comune + fix: insistere con ping a raffica → se sei in LAN passa a enumerazione ARP (es. “discovery con Netdiscover” su [https://hackita.it/articoli/netdiscover/](https://hackita.it/articoli/netdiscover/)) oppure valida via TCP su porte note.

### “Operation not permitted” / permessi raw socket

Perché: alcuni ambienti non concedono raw socket a utenti non privilegiati.

Cosa aspettarti: errore immediato.

Comando:

```bash
ping -c 1 10.10.10.10
```

Esempio di output (può variare):

```text
ping: socket: Operation not permitted
```

Interpretazione: non è un problema di rete: è locale (privilegi/capabilities).

Errore comune + fix: in lab usa `sudo ping ...` e verifica che l’ambiente/container consenta ICMP.

### “Unknown host” / risoluzione DNS

Perché: stai pingando un nome che non risolve (o DNS non configurato).

Cosa aspettarti: errore di risoluzione.

Comando:

```bash
ping -c 1 -W 1 not-a-real-hostname
```

Esempio di output (può variare):

```text
ping: not-a-real-hostname: Name or service not known
```

Interpretazione: problema DNS/typo.

Errore comune + fix: passa a IP o correggi resolver; `-n` non risolve questo (serve a evitare reverse DNS, non a “fixare” il DNS).

### Rate-limit / IDS: “perché dopo un po’ smette?”

Perché: alcuni device limitano ICMP.

Cosa aspettarti: prime risposte ok, poi perdita.

Comando:

```bash
ping -c 10 -i 0.5 -W 1 10.10.10.10
```

Esempio di output (può variare):

```text
10 packets transmitted, 7 received, 30% packet loss, time 4509ms
```

Interpretazione: potrebbe essere congestione o rate-limit.

Errore comune + fix: riduci frequenza (`-i 1` o più) e usa tool più adatti al discovery invece di “martellare” ICMP.

## Alternative e tool correlati (quando preferirli)

> **In breve:** se `ping` non basta, scegli tool in base al livello: L2 per LAN, L3/L4 per discovery scalabile, e sniffing per capire cosa succede davvero.

* In LAN: ARP è spesso più affidabile di ICMP (host può bloccare Echo ma rispondere ad ARP). Vedi “host discovery con ARP-Scan” su [https://hackita.it/articoli/arp-scan/](https://hackita.it/articoli/arp-scan/).
* Per discovery più comodo: Netdiscover è utile quando vuoi “vedere” la LAN senza dipendere da ICMP. Vedi [https://hackita.it/articoli/netdiscover/](https://hackita.it/articoli/netdiscover/).
* Per capire se l’ICMP parte/torna: cattura traffico (sotto) invece di interpretare solo il sintomo.

Quando NON usarli: se non sei autorizzato sul segmento (vale anche in lab: rimani nel perimetro definito).

## Hardening & detection (ICMP control, logging, alert)

> **In breve:** non serve sempre “bloccare ping”; spesso è meglio **limitare**, **loggare** e **correlare** con altri segnali di recon.

### Detection veloce: osserva ICMP in chiaro

Perché: se un host fa sweep o stress test ICMP, lo vedi subito a pacchetto.

Cosa aspettarti: richieste Echo e risposte; utile per distinguere filtro vs assenza di traffico.

Comando:

```bash
sudo tcpdump -n icmp
```

Esempio di output (può variare):

```text
IP 10.10.10.50 > 10.10.10.10: ICMP echo request, id 1234, seq 1, length 64
IP 10.10.10.10 > 10.10.10.50: ICMP echo reply, id 1234, seq 1, length 64
```

Interpretazione: se vedi request senza reply, è filtro/host; se non vedi nulla, il problema è prima (routing/ACL locale).

Errore comune + fix: catturi sull’interfaccia sbagliata → specifica `-i eth0` e riprova.

Per andare oltre, usa analisi GUI o CLI: “analisi traffico con Wireshark” su [https://hackita.it/articoli/wireshark/](https://hackita.it/articoli/wireshark/) e “Wireshark CLI con TShark” su [https://hackita.it/articoli/tshark/](https://hackita.it/articoli/tshark/).

### Hardening pragmatico: rate-limit ICMP (non “blind blocking”)

Perché: bloccare ICMP rompe troubleshooting e a volte funzionalità; rate-limit riduce sweep e flood senza azzerare.

Cosa aspettarti: Echo Reply ancora possibile ma non a raffica.

Comando:

```bash
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second --limit-burst 5 -j ACCEPT
```

Esempio di output (può variare):

```text
(no output)
```

Interpretazione: stai accettando Echo Request con limite; il resto (oltre soglia) verrà gestito dalle regole successive (che in un hardening reale dovresti definire esplicitamente).

Errore comune + fix: mettere la regola dopo un DROP generale → l’ordine conta: posiziona correttamente la regola nella chain.

## Scenario pratico: ping su una macchina HTB/PG

> **In breve:** in lab, usi `ping` per validare raggiungibilità, stimare stabilità e capire se il “silenzio” è filtro o routing.

Ambiente: attacker box su Kali, target `10.10.10.10`.

Obiettivo: capire se il target è raggiungibile e se l’ICMP è filtrato/rate-limitato.

Perché: check immediato reachability.

Cosa aspettarti: reply o timeout rapido.

Comando:

```bash
ping -c 1 -W 1 10.10.10.10
```

Esempio di output (può variare):

```text
64 bytes from 10.10.10.10: icmp_seq=1 ttl=63 time=14.0 ms
```

Interpretazione: target risponde; ha senso procedere con enumerazione applicativa.

Errore comune + fix: risposta intermittente → fai test qualità breve.

Perché: misuri loss e RTT medio prima di lanciare enum/exploit.

Cosa aspettarti: statistiche con `packet loss` e `rtt`.

Comando:

```bash
ping -c 5 -W 1 10.10.10.10
```

Esempio di output (può variare):

```text
5 packets transmitted, 5 received, 0% packet loss, time 4007ms
rtt min/avg/max/mdev = 13.1/14.0/15.2/0.8 ms
```

Interpretazione: rete stabile → ok per step successivi.

Errore comune + fix: 20–40% loss → sospetta rate-limit o congestione; riduci frequenza e conferma con capture.

Perché: separi “filtro” da “non parte proprio traffico”.

Cosa aspettarti: vedi Echo request/reply in tempo reale.

Comando:

```bash
sudo tcpdump -n icmp
```

Esempio di output (può variare):

```text
IP 10.10.10.50 > 10.10.10.10: ICMP echo request, id 555, seq 1, length 64
```

Interpretazione: se vedi solo request, la reply non torna (filtro o host). Se non vedi nulla, problema locale/route.

Detection + hardening: sweep ICMP ripetuti sono facili da alertare (rate e pattern). In difesa, preferisci rate-limit + logging, e correla ICMP con scan L4 (TCP SYN) per riconoscere recon “a fasi”.

## Playbook 10 minuti: ping in un lab

> **In breve:** 7 step per passare da “non risponde” a diagnosi chiara (host/filtro/dns/mtu).

### Step 1 – Verifica che ping funzioni localmente

Perché: elimini problemi locali prima di accusare la rete.

```bash
ping -c 1 127.0.0.1
```

### Step 2 – Prova 1 pacchetto con timeout

Perché: test minimale, low-noise.

```bash
ping -c 1 -W 1 10.10.10.10
```

### Step 3 – Fai un test qualità (5 colpi)

Perché: vedi loss/jitter che impattano enum/exploit.

```bash
ping -c 5 -W 1 10.10.10.10
```

### Step 4 – Elimina DNS come variabile (se usi nomi)

Perché: distingui “DNS down” da “host down”.

```bash
ping -n -c 1 -W 1 example.com
```

### Step 5 – Se sospetti filtro/rate-limit, riduci il rate

Perché: eviti di triggerare throttling.

```bash
ping -c 10 -i 1 -W 1 10.10.10.10
```

### Step 6 – Se hai sintomi strani su transfer, testa MTU con DF

Perché: MTU mismatch crea failure “fantasma”.

```bash
ping -c 1 -W 1 -M do -s 1472 10.10.10.10
```

### Step 7 – Se ancora è ambiguo, cattura ICMP

Perché: vedi se le request escono e le reply tornano.

```bash
sudo tcpdump -n icmp
```

## Checklist operativa

* Uso sempre `-c` per non lasciare `ping` infinito.
* Imposto `-W 1` o `-W 2` per evitare attese inutili.
* Se ping fallisce, considero subito “ICMP filtrato”, non solo “host down”.
* In LAN, preferisco discovery L2 se ICMP è bloccato (ARP).
* Se uso nomi, valido DNS separatamente (o uso `-n` e IP).
* Se vedo loss, riduco il rate con `-i 1` per evitare rate-limit.
* Se i tool “cadono” su trasferimenti, provo MTU con `-M do` e `-s`.
* Per togliere dubbi, faccio capture (`tcpdump`) prima di teorie.
* Non uso flood/stress fuori da test espliciti di resilienza in lab.
* Loggo e documento output/statistiche (loss, rtt avg, deviazione).

## Riassunto 80/20

| Obiettivo            | Azione pratica            | Comando/Strumento          |
| -------------------- | ------------------------- | -------------------------- |
| Check “alive” rapido | 1 pacchetto + timeout     | `ping -c 1 -W 1 <IP>`      |
| Qualità della tratta | 5 colpi e leggi loss/rtt  | `ping -c 5 -W 1 <IP>`      |
| Togli DNS di mezzo   | disabilita reverse lookup | `ping -n -c 1 <host>`      |
| Evita rate-limit     | abbassa frequenza         | `ping -i 1 -c 10 <IP>`     |
| Debug MTU            | DF + payload controllato  | `ping -M do -s 1472 <IP>`  |
| Prova “a pacchetto”  | osserva request/reply     | `tcpdump -n icmp`          |
| Discovery in LAN     | ARP invece di ICMP        | `arp-scan` / `netdiscover` |

## Concetti controintuitivi

* **“Se ping non risponde, l’host è morto”**
  Falso: ICMP può essere filtrato o rate-limited. In lab, valida con capture e alternative L2/L4.
* **“TTL = OS fingerprint sicuro”**
  TTL è un indizio, non una prova: hop, NAT e firewall cambiano i valori. Usa TTL solo per prioritizzare ipotesi.
* **“Bloccare ICMP è sempre sicurezza”**
  Spesso peggiora troubleshooting e non ferma davvero un attacker: meglio rate-limit + logging + correlazione.
* **“Ping è innocuo quindi posso spammare”**
  Anche ICMP a raffica genera alert e degrada rete. In lab usa `-c` e `-i`, e documenta il perché.

## FAQ

D: `ping` usa una porta TCP/UDP?

R: No, ICMP non usa porte come TCP/UDP. Se ti serve verificare un servizio, devi testare a livello L4/L7 con tool dedicati.

D: Perché vedo `100% packet loss` ma il sito/app funziona?

R: Probabile ICMP Echo filtrato. Prova a validare con un probe TCP e/o cattura traffico (`tcpdump -n icmp`) per capire se le reply tornano.

D: `-W` e `-w` sono la stessa cosa?

R: No: `-W` è il timeout per singola risposta (varia per implementazione), `-w` è spesso una “deadline” totale. Controlla `man ping` sulla tua distro.

D: Posso usare `ping` per fare discovery di una /24?

R: Puoi in lab, ma è inefficiente e rumoroso. In LAN è più affidabile ARP; altrimenti usa strumenti nati per discovery con rate controllato.

D: Il test MTU con `-M do` non funziona, perché?

R: Alcuni device filtrano i messaggi ICMP necessari (es. “fragmentation needed”). Riduci la size e considera che i risultati possono essere incompleti in reti filtrate.

## Link utili su HackIta.it

* [ARP-Scan per host discovery e pivoting in LAN](https://hackita.it/articoli/arp-scan/)
* [Netdiscover per scoprire dispositivi e IP in LAN](https://hackita.it/articoli/netdiscover/)
* [Tcpdump per analizzare traffico di rete da terminale](https://hackita.it/articoli/tcpdump/)
* [Wireshark per analisi traffico e credenziali in lab](https://hackita.it/articoli/wireshark/)
* [TShark per analizzare traffico in CLI](https://hackita.it/articoli/tshark/)
* [Netcat: tool jolly per networking offensivo](https://hackita.it/articoli/netcat/)

Pagine:

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

* [ping(8) — iputils ping man page (Debian)](https://manpages.debian.org/testing/iputils-ping/ping.8.en.html)
* [RFC 792 — Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792.html)

## CTA finale HackITA

Se questo contenuto ti è utile e vuoi far crescere HackIta, puoi supportare il progetto qui: /supporto/.

Se vuoi accelerare davvero (lab guidati, roadmap, troubleshooting), trovi la formazione 1:1 qui: /servizi/.

Per aziende o team: assessment, hardening e test controllati su perimetri autorizzati li trovi qui: /servizi/.

(1): [https://manpages.debian.org/testing/iputils-ping/ping.8.en.html?utm\_source=chatgpt.com](https://manpages.debian.org/testing/iputils-ping/ping.8.en.html?utm_source=chatgpt.com) "ping(8) — iputils-ping — Debian testing — Debian Manpages"
