---
title: 'Netdiscover: scopri dispositivi e IP nascosti nella rete LAN'
slug: netdiscover
description: >-
  Netdiscover è un tool essenziale per identificare dispositivi attivi nella
  rete locale. Ideale per il recon silenzioso tramite ARP su ambienti privi di
  DNS o DHCP.
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

# Netdiscover: scopri dispositivi e IP nascosti nella rete LAN

## Introduzione Tattica

Durante un internal assessment o CTF, trovi un segmento di rete interno con host che non rispondono agli scan ICMP. La rete è "silenziosa", senza DNS affidabile e con scope DHCP sconosciuti. Netdiscover diventa lo strumento principale per mappare il dominio broadcast quando sei all'interno dello stesso segmento Layer 2, basandosi sul protocollo ARP, fondamentale per il funzionamento di qualsiasi rete Ethernet.

## TL;DR Operativo (Flusso a Step)

1. Verifica interfaccia e subnet con `ip -br a` (escludi `tun0`)
2. Modalità fast `-f` per orientamento rapido su subnet comuni
3. Active scan completo con `-r CIDR` per enumerazione aggressiva
4. Passive sniff con `-p` per discovery low-noise
5. Export risultati con `-P -N > file.txt` per parsing automatico
6. Validazione con `tcpdump arp` se l'output è vuoto
7. Prioritarizzazione target basata su vendor OUI

## Fase 1 – Ricognizione & Enumeration

**Fingerprinting del dominio broadcast e selezione interfaccia:**
Il primo passo è identificare l'interfaccia corretta. Netdiscover opera a **Layer 2 (Data Link)** e funziona solo all'interno del **dominio broadcast locale** (es., stessa VLAN, stesso switch).

```bash
ip -br a | grep -E "(eth|enp|wlan)" | grep UP
```

Escludi le interfacce `tun0` o `tap0`: sono VPN a livello L3, dove l'ARP non può attraversare router.

**Perché usare ARP invece di ICMP (ping)?**
Il protocollo ARP è fondamentale per mappare gli indirizzi IP agli indirizzi MAC fisici in una LAN. A differenza degli ICMP echo request (ping), che possono essere bloccati da firewall locali, le richieste ARP sono **indispensabili** per la comunicazione di base in Ethernet. Se un host bloccasse l'ARP, non potrebbe comunicare sulla rete locale. Ciò rende il discovery via ARP estremamente affidabile nel segmento locale, bypassando le restrizioni ICMP.

## Fase 2 – Initial Exploitation del Layer 2

**Active ARP Sweep (`-r`): Meccanismo e impatto:**
La modalità `active` è quella predefinita di netdiscover.

```bash
sudo netdiscover -i eth0 -r 192.168.1.0/24
```

**Meccanismo:** Netdiscover invia una richiesta ARP **broadcast** ("who-has") per ogni singolo IP all'interno del range specificato (es., 256 IP per una `/24`). Gli host vivi rispondono con un pacchetto ARP di reply ("is-at") contenente il proprio indirizzo MAC.
**Considerazione Enterprise:** In grandi reti con subnet `/23` o `/22`, uno scan attivo completo genera migliaia di richieste ARP in pochi secondi, un pattern facilmente rilevabile da IDS/NDR.

**Passive Sniffing (`-p`): Meccanismo e limiti:**

```bash
sudo netdiscover -i eth0 -p
```

**Meccanismo:** In questa modalità, netdiscover **non invia alcun pacchetto**. Mette l'interfaccia di rete in **modalità promiscua** e si limita a "sniffare" (ascoltare) il traffico ARP già esistente sulla rete, registrando le richieste e le risposte che passano. È molto più difficile da rilevare per i sistemi di monitoraggio di rete.
**Limitazione:** La sua efficacia dipende interamente dal traffico ARP presente. In una rete silenziosa, potresti non vedere alcun host.

**Fast Mode (`-f`): Scansione esplorativa:**
Utile quando non si conosce la subnet esatta. Invece di scandire tutti gli IP, prova una selezione di indirizzi comuni (come `.1`, `.100`, `.254`) su un insieme di range di rete standard (10.x, 192.168.x).

## Fase 3 – Analisi Avanzata dell'Output netdiscover

**Interpretazione dei dati per la target prioritization:**
L'output di netdiscover fornisce diversi campi chiave:

* **IP Address & MAC Address:** Il mapping base.
* **Vendor (OUI):** Derivato dai primi 3 byte (Organizationally Unique Identifier) del MAC. Identifica il produttore della scheda di rete (es., `PCS Systemtechnik GmbH` per VirtualBox, `Cisco Systems` per dispositivi di rete). Questo aiuta a distinguere server, endpoint utente, dispositivi IoT o infrastruttura di rete.
* **Count:** Numero di pacchetti catturati per quell'host. Un conteggio alto può indicare un host molto attivo.
* **Len:** La lunghezza del pacchetto ARP catturato. Di solito è 60 byte per una richiesta o risposta ARP standard.

**Edge Cases Comuni nell'Interpretazione:**

* **Host Multi-Homed:** Un singolo MAC address (un server o una workstation con più schede) apparirà con più indirizzi IP.
* **Cache ARP Stale:** Un host che è andato offline potrebbe ancora apparire nelle risposte di altri dispositivi finché la loro cache ARP non scade (di solito pochi minuti).
* **MAC Randomization:** Su dispositivi moderni (specialmente smartphone), l'indirizzo MAC può cambiare periodicamente per preservare la privacy, rendendo difficile il tracking.

**Transizione a Service Scanning (L3/L4):**
Netdiscover fornisce **visibilità a livello L2**. Non fornisce informazioni su porte aperte, servizi o sistemi operativi. L'output deve essere utilizzato come input per strumenti di enumerazione successivi:

```bash
cat netdiscover_output.txt | awk '{print $1}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' > target_list.txt
nmap -iL target_list.txt -sS -p- --open
```

## Fase 4 – Implicazioni Operative della Discovery ARP

La mappatura completa del dominio broadcast tramite netdiscover è il prerequisito fondamentale per qualsiasi attività offensiva successiva nello stesso segmento di rete. La conoscenza precisa di tutti gli attori presenti (IP, MAC, tipo di dispositivo) permette di:

* Identificare il gateway predefinito (tipicamente `.1` o `.254`), obiettivo primario per attacchi man-in-the-middle.
* Rilevare potenziali victim per attacchi basati su protocolli di rete (come LLMNR/NBT-NS poisoning) scegliendo sistemi operativi specifici (tramite OUI).
* Comprendere l'architettura di rete locale, distinguendo segmenti server da segmenti utente.

**Limitazioni Critiche:**
Se netdiscover non rileva host, le cause possono essere:

1. Interfaccia di rete errata (es., in uso `tun0` invece di `eth0`).
2. Isolamento VLAN: sei su una VLAN diversa dai target.
3. Non sei nello stesso dominio broadcast (es., separato da un router).
4. Presenza di controlli di sicurezza avanzati come **Dynamic ARP Inspection (DAI)** che bloccano pacchetti ARP non validi.

## Fase 5 – Detection & Hardening

**Indicatori di Compromissione (IoCs) di una scansione netdiscover:**

* **Pattern di ARP Sweep:** Centinaia di richieste ARP "who-has" in sequenza da un singolo MAC sorgente in un breve lasso di tempo (secondi/minuti).
* **Picchi di Traffico Broadcast:** Un'improvvisa ondata di traffico broadcast ARP su una porta di switch.
* **Sorgente Incoerente:** Richieste ARP che utilizzano un IP sorgente fittizio o non appartenente alla subnet.

**Hardening Enterprise e Strategie di Rilevamento:**

1. **Dynamic ARP Inspection (DAI):** Implementato sugli switch gestiti (es., Cisco). Convalida i pacchetti ARP confrontandoli con una tabella di binding attendibile (creata via DHCP Snooping), scartando quelli non validi. È la difesa più efficace contro ARP spoofing e rileva immediatamente gli ARP sweep.
2. **Port Security:** Limita il numero di indirizzi MAC che possono essere appresi su una porta fisica dello switch, mitigando spoofing.
3. **Network Access Control (NAC):** Autentica i dispositivi prima di concedere l'accesso al livello L2, impedendo a dispositivi non autorizzati di inviare traffico ARP.
4. **Segmentazione VLAN:** Riduce la dimensione del dominio broadcast, limitando la superficie di scoperta e l'impatto potenziale di attacchi L2.
5. **Monitoraggio con Strumenti Dedicati:** Utilizzo di tool come `arpwatch` o `XArp` per monitorare le associazioni IP-MAC e allertare su cambiamenti sospetti.

**La differenza tra ARP Discovery e ARP Spoofing/Poisoning:**
È fondamentale distinguere concettualmente:

* **ARP Discovery (Netdiscover):** Tecnica **passiva** (ascolto) o **attiva** (invio di richieste legittime) per *mappare* le associazioni IP-MAC esistenti. È ricognizione.
* **ARP Spoofing/Poisoning:** Tecnica **attiva e malevola** che invia *risposte ARP fraudolente* per *corrompere* la cache ARP di altri host, dirottando il traffico (Man-in-the-Middle). Netdiscover può essere usato nella fase di ricognizione *preliminare* a un attacco di spoofing, ma non esegue lo spoofing stesso.

## Errori Comuni Che Vedo Negli Assessment Reali

* **Scansione sull'interfaccia sbagliata:** Usare `tun0` (VPN) e aspettarsi di vedere host nella LAN fisica.
* **Dimenticare i privilegi:** Netdiscover richiede `sudo` per accedere ai socket raw e inviare/ascoltare pacchetti ARP.
* **Fidarsi ciecamente del Vendor OUI:** Il MAC e il vendor possono essere falsificati (spoofati) via software. L'OUI è un indizio, non una prova certa.
* **Sovrastimare la Passive Mode:** In rete silenziosa, la modalità `-p` non trova host. Necessaria una valutazione realistica del traffico di rete.
* **Ignorare la Rilevabilità:** Lanciare uno scan attivo `-r` in un ambiente enterprise con DAI/NID senza considerare l'alto rischio di rilevamento.
* **Non validare i risultati negativi:** Se netdiscover non trova nulla, non verificare con `tcpdump -ni eth0 arp` per confermare l'assenza di traffico ARP.

## Mini Tabella 80/20 Finale

| Obiettivo                    | Azione                                | Comando                                                        |
| :--------------------------- | :------------------------------------ | :------------------------------------------------------------- |
| **Scansione Esplorativa**    | Fast mode su range comuni             | `sudo netdiscover -i eth0 -f`                                  |
| **Enum Completa Segmento**   | Active ARP sweep su /24               | `sudo netdiscover -i eth0 -r 192.168.1.0/24`                   |
| **Discovery Low-Noise**      | Passive ARP sniff                     | `sudo netdiscover -i eth0 -p`                                  |
| **Scan + Monitor Continuo**  | Active scan poi passive mode          | `sudo netdiscover -i eth0 -r 192.168.1.0/24 -L`                |
| **Esportazione per Parsing** | Output senza header, machine-readable | `sudo netdiscover -i eth0 -r 192.168.1.0/24 -P -N > hosts.txt` |
| **Troubleshooting**          | Validazione traffico ARP grezzo       | `sudo tcpdump -ni eth0 arp -c 10`                              |

## Decision Tree per la Scelta della Modalità

```
Sei in un lab controllato o subnet piccola?
        ├── SÌ → Usa **Active Scan (`-r`)** per risultati rapidi e completi.
        └── NO (Ambiente Enterprise monitorato)?
                ├── Priorità Stealth → Inizia con **Passive Mode (`-p`)** per valutare il traffico esistente senza lasciare traccia.
                ├── Necessità Copertura Completa → Valuta rischio e usa `-r` con tuning (`-s` per rallentare).
                └── Nessun Risultato in Passive?
                        → Verifica: 1) Interfaccia corretta? 2) Sei sulla VLAN giusta? 3) Esiste traffico ARP (`tcpdump`)?
```

**Pronto a Portare le Tue Skill di Network Discovery al Livello Successivo?**
La padronanza di netdiscover e delle tecniche di discovery L2 è un pilastro per qualsiasi attività di internal assessment. Per applicare queste competenze in scenari realistici, complessi e multi-step, dove la discovery è solo il primo movimento in una catena di esercizi di compromissione e lateral movement.

## 📌 Vuoi portare queste competenze al livello successivo?

Se vuoi testare la sicurezza della tua azienda o migliorare le tue capacità operative in scenari reali di internal assessment e Red Team, scopri i nostri servizi professionali:

👉 [https://hackita.it/servizi](https://hackita.it/servizi)

Se invece vuoi supportare il progetto e contribuire alla crescita dei contenuti tecnici di HackITA:

👉 [https://hackita.it/supporta](https://hackita.it/supporta)

Per approfondire il workflow completo dopo la fase di discovery ARP, consulta anche risorse ufficiali e documentazione tecnica su:

* ARP Protocol (RFC 826): [https://datatracker.ietf.org/doc/html/rfc826](https://datatracker.ietf.org/doc/html/rfc826)
* Nmap Reference Guide: [https://nmap.org/book/man.html](https://nmap.org/book/man.html)
* IEEE 802.1X e Network Access Control: [https://ieeexplore.ieee.org/document/742877](https://ieeexplore.ieee.org/document/742877)

La discovery è solo il primo passo: ciò che conta è come integri queste informazioni in un assessment strutturato e realistico.
