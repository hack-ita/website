---
title: 'SnmpCheck: enum dispositivi e servizi via SNMP v1/v2'
slug: snmp-check
description: >-
  Snmp-check permette di estrarre informazioni da dispositivi di rete usando
  SNMP. Perfetto per attacchi low-noise, enumeration silenziosa e footprinting.
image: /snmpcheck.webp
draft: false
date: 2026-01-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - snmp
  - ''
---

# Snmp-Check: Enumerazione SNMP rapida (v1/v2c) in lab

Se **snmp-check** ti dà solo `Timeout` o output “vuoto”, qui lo porti a risultato: validi SNMP, tiri fuori info utili in ottica offensiva e chiudi con **detection + hardening** (sempre in lab/CTF).

## Intro

**snmp-check** è uno script che automatizza query SNMP per raccogliere in pochi secondi informazioni esposte da un agente SNMP (tipicamente v1/v2c con community).
In un lab/pentest serve per scoprire leakage ad alto valore: OS, hostname, uptime, interfacce, routing, utenti, processi e talvolta software.
Cosa farai/imparerai:

* capire quando SNMP è “attaccabile” (community/ACL/versione)
* usare 3 pattern di comandi ripetibili
* interpretare output e trasformarlo in azioni (enum → pivot)
* risolvere timeout, auth e mismatch di versione

Nota etica: **solo** su sistemi autorizzati (HTB/PG/CTF/VM tue), mai su reti/asset reali senza permesso scritto.

## Dove si incastra snmp-check nel workflow offensivo

> **In breve:** usalo dopo discovery/port-scan quando sospetti UDP/161 e vuoi trasformare “SNMP presente” in “info utilizzabile” (leakage) rapidamente.

SNMP spesso è un “bonus service”: non ti dà una shell, ma ti regala contesto per attacchi successivi (credenziali deboli, share, utenti, processi, versioni).

Per arrivarci in modo pulito, io lo tratto così:

1. discovery host → 2) conferma reachability → 3) verifica SNMP → 4) snmp-check → 5) approfondisci con snmpwalk/snmpset (se e solo se ha senso).

Se sei in LAN lab, prima fai discovery L2 con **host discovery via arp-scan**: [arp-scan per scoprire host in rete locale](/articoli/arp-scan/).

Poi una reachability veloce evita “false assenze”: [ping operativo per validare connettività](/articoli/ping/).

## Installazione e quick sanity check (Kali/Ubuntu)

> **In breve:** installa il pacchetto, controlla che il binario sia presente e lancia `-h` per vedere opzioni/flag.

Perché: ti serve un setup ripetibile e veloce in lab.
Cosa aspettarti: `snmp-check` disponibile nel PATH e help stampato.

Comando:

```
sudo apt update && sudo apt install -y snmpcheck
```

Esempio di output (può variare):

```
Reading package lists... Done
Setting up snmpcheck ...
```

Interpretazione: pacchetto ok; ora verifica il comando.
Errore comune + fix: `Unable to locate package` → aggiorna repo o usa mirror corretti della distro.

Perché: confermare che stai usando **snmp-check** e non uno strumento “simile” con nome diverso.
Cosa aspettarti: help/usage con flag come `-c`, `-v`, `-p`, `-t`, `-r`.

Comando:

```
snmp-check -h
```

Esempio di output (può variare):

```
snmp-check <target> [options]
 -c <community>  SNMP community
 -v <version>    1 | 2c
 -p <port>       default 161
 -t <timeout>    seconds
 -r <retries>     number
 -w              check write access
 -d              disable TCP connections enumeration
```

Interpretazione: hai le opzioni chiave per v1/v2c.
Errore comune + fix: `command not found` → verifica installazione o PATH, oppure prova `which snmp-check`.

## Capire SNMP in 60 secondi (cosa ti serve davvero)

> **In breve:** con v1/v2c “autenticazione” = community string; se community e ACL sono deboli, SNMP diventa leakage massivo.

In molti lab, SNMP è configurato con community banali (`public`, `private`) e ACL permissive: è qui che **snmp-check** brilla.

SNMPv3 (auth/priv) è un altro mondo: se il target è solo v3, snmp-check potrebbe non bastare e devi passare a tool Net-SNMP con supporto v3 (valuta sempre versione e configurazione).

Quando NON usarlo: se devi fare walk su alberi enormi o hai bisogno di filtri OID precisi, passa direttamente a strumenti più granulari (vedi sezione alternative).

## Sintassi base + 3 pattern che userai sempre

> **In breve:** pattern base (community), forcing versione (v1/v2c) e tuning (timeout/retry/port) coprono il 90% dei casi.

### Pattern 1 — Run “base” con community (il più comune)

Perché: estrarre subito informazioni “alte” (system, network, users/process) quando community è nota o sospetta.
Cosa aspettarti: output strutturato per sezioni, spesso con sysDescr/hostname/interfaces.

Comando:

```
snmp-check 10.10.10.10 -c public
```

Esempio di output (può variare):

```
[+] System information:
  Hostname: lab-snmp
  Description: Linux lab-snmp 5.15.0 ...
  Uptime: 12 days, 04:11:22

[+] Network information:
  Interfaces: eth0(10.10.10.10), lo(127.0.0.1)
```

Interpretazione: hai già OS/hostname/interfacce → ottimo per pivot (scelte exploit/wordlist mirate).
Errore comune + fix: `Timeout: No Response` → community errata, UDP/161 filtrato o versione mismatch (vedi troubleshooting).

### Pattern 2 — Forza la versione (v1 vs v2c)

Perché: alcuni agent rispondono solo a v2c (o solo v1) e il default non sempre matcha.
Cosa aspettarti: con versione corretta, l’output “si accende” subito.

Comando:

```
snmp-check 10.10.10.10 -c public -v 2c
```

Esempio di output (può variare):

```
[+] Storage information:
  / (ext4)  12G used 4G free 8G
```

Interpretazione: se con `-v 2c` compare roba e senza no, era mismatch di protocollo.
Errore comune + fix: `Invalid SNMP version` → usa esattamente `1` o `2c` (come supportato dal tool).

### Pattern 3 — Tuning: port, timeout e retry (quando “sembra morto”)

Perché: SNMP su lab può essere lento, rate-limited o su porta non standard.
Cosa aspettarti: meno false negative e query più stabili.

Comando:

```
snmp-check 10.10.10.10 -c public -v 2c -p 161 -t 3 -r 2
```

Esempio di output (può variare):

```
[+] Processes:
  sshd
  apache2
  snmpd
```

Interpretazione: se con timeout/retry ottieni output, era solo latenza/perdita UDP.
Errore comune + fix: aumentare troppo `-t` in scan multipli → rallenti tutto; meglio poche retry e parallelismo controllato.

## Enumerazione e leakage tipici in lab (cosa cercare nell’output)

> **In breve:** il valore vero è trasformare “info SNMP” in prossime mosse: utenti, processi, software e rete.

Cerca sempre questi segnali:

* **sysDescr / kernel / distro** → scegli exploit, moduli e payload corretti
* **interfacce e subnet** → capisci segmentazione e possibili pivot
* **processi** → servizi reali in esecuzione (anche se non “scansionati” bene)
* **utenti** → nomi reali per bruteforce/lateral in lab
* **storage** → path interessanti e volumi montati

Quando vuoi scendere a livello OID e fare query mirate, passa a un walk controllato: [snmpwalk per enumerazione SNMP mirata](/articoli/snmpwalk/).

## Casi d’uso offensivi “da lab” + validazione (con mitigazioni)

> **In breve:** snmp-check ti aiuta a scoprire misconfig (community deboli, accesso troppo ampio, talvolta write) e a validarle senza “sparare nel buio”.

### Caso 1 — Community banali (public/private) e informazioni sensibili

Perché: è il caso più frequente nei lab e spesso basta per ottenere leakage utile.
Cosa aspettarti: output con system/network/processes/users se l’ACL lo consente.

Comando:

```
snmp-check 10.10.10.10 -c public -v 2c
```

Esempio di output (può variare):

```
[+] User accounts:
  devops
  svc-backup
[+] Listening ports:
  22/tcp  80/tcp
```

Interpretazione: utenti “reali” + servizi → ottimizza wordlist e next steps (web enum, SSH attempts in lab).
Errore comune + fix: scambiare “listening ports” per scan completo → verifica sempre con uno scan dedicato, SNMP può essere incompleto.

Validazione in lab: confronta ciò che SNMP dichiara con un check di rete e/o un accesso autenticato in VM (se previsto dallo scenario).
Segnali di detection: burst di richieste SNMP (GETNEXT/GETBULK), molte community tentate, molte sorgenti diverse verso UDP/161.
Hardening/mitigazione: SNMPv3, ACL per subnet di management, community random lunghe, view limitate sugli OID.

### Caso 2 — Verifica “write access” (solo lab) e rischio impatto

Perché: se esiste una community RW, potresti (in lab) dimostrare impatto controllato.
Cosa aspettarti: indicazione che l’accesso in scrittura è possibile o che è bloccato.

Comando:

```
snmp-check 10.10.10.10 -c private -v 2c -w
```

Esempio di output (può variare):

```
[+] Write access: enabled
```

Interpretazione: RW su SNMP è grave: può portare a modifiche di config/parametri (dipende dagli OID e dall’agente).
Errore comune + fix: “testare scrittura” in modo distruttivo → in lab usa sempre prove non impattanti o OID innocui, e documenta.

Validazione in lab: se devi dimostrare, fallo con un singolo cambiamento reversibile e tracciabile (mai su sistemi reali).
Segnali di detection: comparsa di SET request, modifiche di valori OID, eventi in syslog/snmptrap.
Hardening/mitigazione: disabilita scrittura, separa community RO/RW (meglio: niente v1/v2c), limita `snmpset` via ACL e auditing.

Quando NON usarlo: se il lab ha regole “no impact” o se non hai chiaro cosa modifichi (RW SNMP può rompere servizi).

## Troubleshooting: timeout, auth, version mismatch, firewall

> **In breve:** quasi tutti i problemi sono 1) UDP/161 filtrato 2) community sbagliata 3) versione errata 4) rate-limit.

### Timeout: No Response

Perché: capire se è rete o credenziali (community).
Cosa aspettarti: se SNMP è filtrato, snmp-check non riceve nulla; se community è sbagliata, spesso anche.

Comando:

```
snmp-check 10.10.10.10 -c public -v 2c -t 2 -r 1
```

Esempio di output (può variare):

```
Timeout: No Response from 10.10.10.10
```

Interpretazione: non conclude nulla: può essere filtro UDP, ACL SNMP o community errata.
Errore comune + fix: cambiare 10 parametri a caso → prima verifica reachability e porta UDP 161 con un controllo mirato.

### “Connection refused” o porta diversa

Perché: alcuni lab spostano SNMP su porta non standard.
Cosa aspettarti: con porta corretta l’output torna.

Comando:

```
snmp-check 10.10.10.10 -c public -v 2c -p 1161
```

Esempio di output (può variare):

```
[+] System information:
  Hostname: lab-snmp
```

Interpretazione: era solo porta custom.
Errore comune + fix: assumere sempre 161 → verifica sempre la porta dallo scan.

### Packet-level debug (quando vuoi “vedere” cosa succede)

Se vuoi capire se stai proprio parlando SNMP (richieste in uscita, risposte in arrivo), cattura traffico: [catturare pacchetti con tcpdump](/articoli/tcpdump/).
Per analisi più comoda a livello GUI, usa: [analizzare pacchetti e filtri con Wireshark](/articoli/wireshark/).

## Alternative e tool correlati (quando preferirli)

> **In breve:** snmp-check è “fast overview”; snmpwalk è “precisione”; altri tool servono per bruteforce community o efficienza.

Usa snmp-check quando:

* vuoi una fotografia rapida (system/network/users/process) senza costruire OID a mano

Preferisci snmpwalk/snmpbulkwalk quando:

* vuoi query mirate su un subtree specifico (meno rumore, più controllo)

Altri tool tipici in lab:

* onesixtyone: brute force community (attenzione: rumoroso → detection facile)
* nmap NSE SNMP: discovery/enum integrata nello scan
* snmpget/snmpset: query singola o scrittura (solo lab e con cautela)

## Hardening & detection (difesa: cosa rompe davvero questo vettore)

> **In breve:** blocchi snmp-check eliminando v1/v2c, restringendo ACL/view e osservando traffico/log SNMP in modo attivo.

Hardening minimo (pratico):

* disabilita SNMP v1/v2c se possibile; preferisci SNMPv3 con auth+priv
* limita UDP/161 a subnet di management (firewall + ACL su snmpd)
* community lunghe/random; niente `public/private`
* view SNMP ristrette (non esporre alberi “host resources” se non serve)
* niente write access in ambienti non-lab; auditing severo dove RW è inevitabile

Detection (pratica):

* allarmi su picchi di traffico verso UDP/161 (soprattutto da host non management)
* pattern di molte query sequenziali (walk) in poco tempo
* alert su tentativi ripetuti con community diverse (guess/bruteforce)
* log centralizzato di snmpd/snmptrapd (se disponibili) + correlazione con sorgenti

***

## Scenario pratico: snmp-check su una macchina HTB/PG

> **In breve:** in 3 comandi passi da “SNMP forse c’è” a “leakage concreto” e una lista di next-step offensivi (sempre lab).

Ambiente: attacker Kali, target `10.10.10.10`.
Obiettivo: ottenere OS/hostname/interfacce e 1 artefatto utile (utente o processo) per guidare l’enumerazione successiva.

Perché: confermare reachability prima di perdere tempo su UDP/161.
Cosa aspettarti: risposta ICMP o perdita (non conclusiva per SNMP, ma utile).

Comando:

```
ping -c 1 10.10.10.10
```

Esempio di output (può variare):

```
64 bytes from 10.10.10.10: icmp_seq=1 ttl=63 time=23.4 ms
```

Interpretazione: host raggiungibile; passa a SNMP.
Errore comune + fix: “ping fail = host down” → in lab ICMP può essere filtrato; verifica anche via scan UDP/TCP.

Perché: estrarre overview SNMP rapidamente.
Cosa aspettarti: sezioni con system/network/process/users se community/ACL ok.

Comando:

```
snmp-check 10.10.10.10 -c public -v 2c -t 3 -r 2
```

Esempio di output (può variare):

```
[+] System information:
  Hostname: lab-snmp
  Description: Linux lab-snmp 5.15.0 ...
[+] User accounts:
  devops
[+] Processes:
  sshd
  apache2
```

Interpretazione: hai almeno 1 username e 1 servizio reale → prepara enum mirata (SSH/web).
Errore comune + fix: output parziale → approfondisci con OID mirati via snmpwalk.

Perché: validare un’informazione specifica (es. processi) con una query più controllata.
Cosa aspettarti: righe OID → valore con nomi processi.

Comando:

```
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2
```

Esempio di output (può variare):

```
HOST-RESOURCES-MIB::hrSWRunName.1234 = STRING: "sshd"
HOST-RESOURCES-MIB::hrSWRunName.1251 = STRING: "apache2"
```

Interpretazione: conferma i processi; utile per capire stack e superfici.
Errore comune + fix: `No Such Object available` → il target non espone quel MIB o lo filtra.

Detection + hardening: una run così genera molte query sequenziali (walk-like) verso UDP/161, facilmente rilevabili in IDS/flow. Difendi con SNMPv3, ACL per subnet di management e view ristrette sugli OID.

## Playbook 10 minuti: snmp-check in un lab

> **In breve:** sequenza “pulita” da 0 a leakage, con fallback e controlli per evitare false assenze.

### Step 1 – Scopri l’host (LAN lab) e annota IP

In una rete lab locale, trova gli host e segna quelli plausibili per servizi di management.

```
sudo arp-scan --localnet
```

### Step 2 – Conferma che il target è vivo (o almeno raggiungibile)

ICMP non è definitivo, ma è un segnale rapido.

```
ping -c 1 10.10.10.10
```

### Step 3 – Verifica che SNMP sia plausibile (UDP/161)

Se hai nmap disponibile, fai un check mirato su UDP 161 prima di debugare community a caso.

```
nmap -sU -p 161 --open 10.10.10.10
```

### Step 4 – Prova snmp-check con community comune (lab)

Parti da `public` e forza v2c se sospetti mismatch.

```
snmp-check 10.10.10.10 -c public -v 2c -t 3 -r 2
```

### Step 5 – Se non risponde, cambia versione e ritocca timing

Prova v1 e un timeout leggermente diverso (senza esagerare).

```
snmp-check 10.10.10.10 -c public -v 1 -t 2 -r 1
```

### Step 6 – Se ottieni output, estrai 2 artefatti “azioni”

Esempi: `Hostname`, 1 `user`, 1 `process` → guida enum su SSH/web.

```
snmp-check 10.10.10.10 -c public -v 2c
```

### Step 7 – Approfondisci con query mirate (fallback “preciso”)

Quando serve controllo, passa a `snmpwalk` su subtree specifici.

```
snmpwalk -v2c -c public 10.10.10.10 system
```

## Checklist operativa

> **In breve:** check veloce per non sprecare tempo e non perdere segnali utili.

* Conferma contesto: solo lab/CTF/HTB/PG/VM personali.
* Segna IP target e subnet (`10.10.10.0/24`) e gateway se noto.
* Verifica reachability (ICMP o alternativa).
* Controlla UDP/161 aperta o plausibile.
* Prova `snmp-check` con `-c public` e `-v 2c`.
* Se timeout, prova `-v 1`, poi ritocca `-t` e `-r`.
* Se porta non standard sospetta, prova `-p <porta>`.
* Se ottieni output, estrai: hostname, OS, interfacce, utenti, processi.
* Valida 1 informazione con `snmpwalk` su subtree mirato.
* Se trovi indizi RW, usa `-w` solo in lab e con cautela.
* Documenta detection: volume query, tempi, sorgente.
* Chiudi con hardening: SNMPv3, ACL, view limitate, community robuste.

## Riassunto 80/20

> **In breve:** i comandi che coprono quasi tutti i casi d’uso reali in lab.

| Obiettivo         | Azione pratica            | Comando/Strumento                            |
| ----------------- | ------------------------- | -------------------------------------------- |
| Run base          | Prova community comune    | `snmp-check 10.10.10.10 -c public`           |
| Forza versione    | Evita mismatch v1/v2c     | `snmp-check 10.10.10.10 -c public -v 2c`     |
| Stabilizza        | Riduci false assenze      | `snmp-check ... -t 3 -r 2`                   |
| Porta custom      | Testa UDP non standard    | `snmp-check ... -p 1161`                     |
| Valida dettaglio  | Query OID mirato          | `snmpwalk -v2c -c public 10.10.10.10 system` |
| Write check (lab) | Verifica RW senza impatto | `snmp-check ... -w`                          |

## Concetti controintuitivi

> **In breve:** errori tipici che fanno perdere tempo o portano a conclusioni sbagliate.

* **“Se ping non risponde, SNMP non c’è”**
  ICMP può essere filtrato: valida con scan mirato su UDP/161 o prova SNMP direttamente con timing ragionevole.
* **“Timeout = community sbagliata”**
  Può essere anche ACL SNMP o firewall UDP: prova versioni e timing prima di cambiare 20 wordlist.
* **“Output SNMP = verità assoluta”**
  Alcuni agent espongono info parziali o vecchie: valida 1–2 punti con query mirate o osservazione di rete.
* **“Se c’è RW posso fare qualsiasi cosa”**
  Dipende dagli OID e dall’agente; in lab dimostra impatto solo con azioni reversibili e tracciabili.

## FAQ

> **In breve:** risposte secche ai blocchi più comuni.

D: `snmp-check` va bene per SNMPv3?

R: Dipende dalla build/strumento; spesso è pensato per v1/v2c. Se il target è v3-only, usa tool Net-SNMP che supportano `-v3` e credenziali.

D: Ho `Timeout: No Response`, cosa provo prima?

R: Forza `-v 2c` o `-v 1`, poi aggiusta `-t` e `-r`. Se continua, sospetta filtro UDP/ACL SNMP o porta non standard (`-p`).

D: Qual è il valore “offensivo” principale di SNMP in lab?

R: Leakage: OS, hostname, interfacce, utenti, processi e talvolta software. Ti serve per decidere dove colpire dopo (SSH/web/SMB, ecc.).

D: È meglio snmp-check o snmpwalk?

R: snmp-check per overview veloce; snmpwalk per query controllate e subtree mirati (meno rumore, più precisione).

D: Come riduco il rumore/detection in lab?

R: Evita walk enormi, limita tentativi di community, usa timing ragionevole e query mirate quando possibile.

## Link utili su HackIta.it

> **In breve:** articoli correlati per completare discovery, analisi traffico e SNMP enum mirata.

* [snmpwalk per enumerazione SNMP mirata](/articoli/snmpwalk/)
* [catturare pacchetti con tcpdump](/articoli/tcpdump/)
* [analizzare pacchetti e filtri con Wireshark](/articoli/wireshark/)
* [ping operativo per validare connettività](/articoli/ping/)
* [arp-scan per scoprire host in rete locale](/articoli/arp-scan/)
* [netdiscover per discovery layer 2](/articoli/netdiscover/)
* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

> **In breve:** fonti primarie per tool e comportamento SNMP (1–2 link esterni totali).

* [https://www.kali.org/tools/snmpcheck/](https://www.kali.org/tools/snmpcheck/) (\[Kali Linux]\[1])
* [https://www.nothink.org/codes/snmpcheck/index.php](https://www.nothink.org/codes/snmpcheck/index.php) (\[nothink.org]\[2])

## CTA finale HackITA

Se questa guida ti ha fatto risparmiare tempo in lab, puoi supportare il progetto qui: /supporto/.

Se vuoi accelerare davvero (OSCP/HTB/PG) con sessioni pratiche 1:1, trovi tutto qui: /servizi/.

Per aziende: assessment, hardening e test controllati (solo con autorizzazione) sono disponibili su: /servizi/.

(1): [https://www.kali.org/tools/snmpcheck/?utm\_source=chatgpt.com](https://www.kali.org/tools/snmpcheck/?utm_source=chatgpt.com) "snmpcheck | Kali Linux Tools"
(2): [https://www.nothink.org/codes/snmpcheck/?utm\_source=chatgpt.com](https://www.nothink.org/codes/snmpcheck/?utm_source=chatgpt.com) "Snmpcheck"
