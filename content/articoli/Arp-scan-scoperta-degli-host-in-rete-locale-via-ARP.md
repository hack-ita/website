---
title: 'ARP-Scan Kali Linux: Scansione ARP e Host Discovery'
slug: arp-scan
description: 'Guida ad ARP-Scan su Kali Linux per scoprire host nella rete locale: scansione ARP, IP, MAC, vendor, subnet, output e workflow di network reconnaissance.'
image: /arpscan.webp
draft: false
date: 2026-01-26T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - arp-scan
  - ARP Discovery
  - Layer 2
  - Network Reconnaissance
---

# ARP-Scan: Host Discovery, Enumerazione e Network Recon

Hai un foothold su una workstation interna e l'ICMP è filtrato — `arp-scan` ti fa comunque mappare rapidamente chi c'è nel tuo stesso segmento Layer 2, prima di passare alla fase successiva di enumerazione dei servizi. Non è lo strumento che ti porta al Domain Admin: è quello che ti dice cosa c'è nel broadcast domain in cui ti trovi, appena entrato.

## Cos'è ARP-Scan

`arp-scan` invia richieste ARP a un range di indirizzi e registra chi risponde: IP, MAC e — tramite il database OUI — il vendor della scheda di rete. Funziona perché ARP è un protocollo non autenticato e necessario per qualsiasi comunicazione L2, quindi anche host che filtrano ICMP devono rispondere per poter comunicare sulla rete locale.

**Da non confondere con ARP spoofing:** `arp-scan` invia richieste per scoprire host — è discovery. L'ARP spoofing manipola le associazioni IP/MAC per intercettare traffico altrui — è un attacco attivo diverso, con rischi e regole d'ingaggio proprie, e non è l'argomento di questa guida.

## Preparare la Scansione

Prima di lanciare qualsiasi scan, identifica interfaccia e subnet effettiva:

```bash
ip addr show
ip route show
```

```bash
# Windows, se sei su una shell Windows
ipconfig /all
route print
```

`arp-scan` lavora solo sull'interfaccia e la subnet che gli indichi: se sbagli l'una o l'altra, torna zero risultati anche se la rete è piena di host attivi.

## Host Discovery

```bash
sudo arp-scan --interface eth0 --localnet
```

`--localnet` non scansiona "tutte le reti locali": usa la rete associata all'interfaccia indicata da `--interface`, calcolata da IP e subnet mask configurati su quell'interfaccia.

Subnet esplicite, anche multiple in un solo comando:

```bash
sudo arp-scan --interface eth0 192.168.1.0/24 10.10.10.0/24 172.16.0.0/24
```

Output grezzo per pipeline successive:

```bash
sudo arp-scan --interface eth0 --localnet -x | cut -f1 > live_hosts.txt
```

`arp-scan` non è silenzioso: genera traffico broadcast osservabile da qualsiasi sistema di monitoraggio di rete. È **rapido**, non stealth — se ti serve minimizzare il rumore, modula la velocità, ma non trattarlo come invisibile.

## Come Leggere l'Output

```text
192.168.1.10  aa:bb:cc:dd:ee:ff  VMware, Inc.
```

* **IP** — host raggiungibile nel tuo stesso segmento.
* **MAC** — identificatore Layer 2 effettivamente osservato.
* **Vendor (OUI)** — indicazione sul produttore della scheda di rete o sul contesto di virtualizzazione.

**Cosa NON ti dice:** sistema operativo, ruolo del dispositivo, versione software o presenza di vulnerabilità. Un MAC con vendor "VMware" indica una scheda di rete virtuale — non "questo è un server", non "questo host è prioritario". L'OUI è un indizio preliminare da confermare, non una classificazione.

```bash
sudo arp-scan --interface eth0 --localnet | tee full_scan.txt
grep -i "cisco" full_scan.txt
grep -i "vmware" full_scan.txt
```

Il passo dopo l'OUI è sempre lo stesso: verificare cosa gira davvero su quell'host.

```bash
nmap -sV -p 22,80,443,445,3389,5985 -iL live_hosts.txt --open
```

Da lì, in base ai servizi trovati, il workflow prosegue su [Nmap](https://hackita.it/articoli/nmap/), [SMB](https://hackita.it/articoli/smb/) o [LDAP](https://hackita.it/articoli/porta-389-ldap/) — non su `arp-scan`, il cui compito finisce con la lista di IP/MAC.

## Analisi della Cache ARP Locale

```bash
ip neigh show
```

```bash
# Windows
arp -a
```

Questo comando mostra le associazioni IP↔MAC che il tuo sistema ha già risolto localmente — nient'altro. Non rivela frequenza di comunicazione tra host, relazioni di trust o rapporti AD: quelli richiedono altre fonti (log, LDAP, BloodHound), non la cache ARP.

## Limiti di ARP-Scan

* **Non attraversa router.** ARP resta nel dominio broadcast locale: per una subnet remota serve discovery a Layer 3 o accesso diretto a quel segmento.
* **Non fa VLAN hopping.** Se sei nella VLAN A, vedi solo la VLAN A. Passare a un'altra VLAN è una tecnica completamente diversa, non una funzione di `arp-scan`.
* **Client isolation Wi-Fi lo blocca.** Se la rete Wi-Fi isola i client tra loro, non vedrai nulla anche essendo connesso.
* **È rilevabile.** Un IDS/IPS moderno riconosce facilmente un volume anomalo di richieste ARP da una singola sorgente.

## ARP-Scan vs Altre Tecniche di Discovery

| Metodo            | Layer | Dove funziona        | Uso principale                                     |
| ----------------- | ----- | -------------------- | -------------------------------------------------- |
| ARP-scan          | L2    | Solo segmento locale | Host discovery quando ICMP è filtrato              |
| Nmap `-PR`        | L2    | Solo segmento locale | ARP discovery integrato in una scansione più ampia |
| ICMP (`nmap -sn`) | L3    | Reti instradate      | Host discovery generico, spesso filtrato           |
| TCP/UDP discovery | L3/L4 | Reti instradate      | Discovery quando ICMP e ARP non sono utilizzabili  |

`arp-scan` e `nmap -PR` fanno concettualmente la stessa cosa; `arp-scan` è spesso preferito quando vuoi solo il discovery L2 puro senza il resto della suite Nmap in mezzo.

## Troubleshooting

**Nessun host trovato** — verifica di aver indicato l'interfaccia giusta (`ip addr show` per controllare) e che la subnet passata corrisponda davvero a quella configurata.

**Permission denied** — `arp-scan` richiede privilegi elevati per creare i pacchetti raw: usa `sudo`.

**Zero risultati su Wi-Fi** — probabile client isolation attiva sull'access point: non è un problema di sintassi.

**Host noti mancanti nell'output** — potrebbero essere su una VLAN diversa dalla tua: `arp-scan` non li vedrà comunque, serve un altro punto di accesso a quel segmento.

## Detection & Hardening

**Detection:** volume anomalo di richieste ARP da una singola sorgente in poco tempo, scansioni sequenziali di interi range in una finestra breve — segnali facilmente distinguibili con Dynamic ARP Inspection o un IDS con soglia sul traffico ARP.

**Hardening:** segmentazione L2 più stretta, DHCP Snooping e Dynamic ARP Inspection sugli switch gestiti, client isolation sulle reti Wi-Fi dove non serve comunicazione diretta tra host, port security per limitare i MAC per porta.

## Workflow: da Foothold a Target Prioritizzati

```bash
# 1. Contesto di rete
ip addr show
ip route show

# 2. Discovery del segmento locale
sudo arp-scan --interface eth0 --localnet | tee full_scan.txt

# 3. Salva la lista IP per la fase successiva
sudo arp-scan --interface eth0 --localnet -x | cut -f1 > live_hosts.txt

# 4. Passa alla service enumeration
nmap -sV -iL live_hosts.txt --open -p 22,80,443,445,3389,5985
```

Da qui il lavoro prosegue con gli strumenti giusti per ciascun servizio trovato — [smbclient](https://hackita.it/articoli/smbclient/) per SMB, [ldapsearch](https://hackita.it/articoli/ldapsearch/) per LDAP, e così via. `arp-scan` ha già fatto il suo lavoro: darti la lista di chi c'è.

## FAQ

**ARP-scan funziona tra VLAN diverse?**
No. ARP opera al Layer 2 e non attraversa i confini di VLAN senza routing o accesso diretto al segmento di destinazione.

**ARP-scan è stealth?**
No, genera traffico broadcast rilevabile da qualsiasi monitoraggio di rete. È rapido, non silenzioso.

**Qual è la differenza tra arp-scan e nmap -PR?**
Fanno discovery L2 nello stesso modo; `arp-scan` è uno strumento dedicato e spesso più rapido quando ti serve solo quello, senza il resto della suite Nmap.

**La cache ARP mostra le relazioni di trust tra host?**
No, mostra solo le associazioni IP↔MAC già risolte localmente dal tuo sistema — niente di più.

***

Uso esclusivo in ambienti autorizzati (lab, CTF, HTB, PG o assessment con consenso scritto).
