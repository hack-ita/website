---
title: >-
  Wi-Fi 802.11: Frame, WPA2/WPA3, Deauth ed Evil Twin — Guida Completa agli
  Attacchi Wireless
slug: wifi-802-11
description: >-
  Guida completa al Wi-Fi 802.11: frame wireless, monitor mode, WPA2/WPA3,
  four-way handshake, PMKID, deauthentication, Evil Twin e rischi reali nel
  pentest.
image: /wifi-802-11.webp
draft: false
date: 2026-03-26T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - deauth-attack
  - evil-twin
featured: true
---

Wi-Fi è la superficie di attacco wireless che ogni pentester incontra. Capire cos'è 802.11 e come funziona il protocollo a livello profondo è la differenza tra chi esegue tool a memoria e chi capisce cosa sta facendo e perché funziona. Wardriving, deauthentication, WPA2 handshake cracking, Evil Twin: tutte tecniche radicate nella struttura stessa del protocollo.

***

## Cos'è Wi-Fi 802.11

Wi-Fi è il nome commerciale della famiglia di standard wireless definiti dall'IEEE con la specifica **802.11**. Opera al **livello 1 (Physical Layer)** e **livello 2 (Data Link Layer)** del modello OSI, esattamente come Ethernet — ma su mezzo radio invece che su cavo.

Lo standard nasce nel 1997. Da allora si è evoluto in numerose revisioni:

| Standard | Anno | Frequenza   | Velocità massima teorica | Nome commerciale |
| -------- | ---- | ----------- | ------------------------ | ---------------- |
| 802.11b  | 1999 | 2.4 GHz     | 11 Mbps                  | Wi-Fi 1          |
| 802.11g  | 2003 | 2.4 GHz     | 54 Mbps                  | Wi-Fi 3          |
| 802.11n  | 2009 | 2.4/5 GHz   | 600 Mbps                 | Wi-Fi 4          |
| 802.11ac | 2013 | 5 GHz       | 6.9 Gbps                 | Wi-Fi 5          |
| 802.11ax | 2019 | 2.4/5/6 GHz | 9.6 Gbps                 | Wi-Fi 6/6E       |
| 802.11be | 2024 | 2.4/5/6 GHz | 46 Gbps                  | Wi-Fi 7          |

La differenza fondamentale rispetto a Ethernet è il mezzo trasmissivo: l'aria è condivisa, non ci sono porte fisiche, e chiunque nel raggio di ricezione può ascoltare il traffico — con l'hardware giusto.

***

## Come funziona Wi-Fi 802.11

### Il frame 802.11

Il frame 802.11 è significativamente più complesso di un frame Ethernet. Ha tre possibili indirizzi MAC (invece di due) per gestire le diverse modalità di trasmissione, e include campi per la gestione del mezzo radio.

Struttura base:

| Campo            | Descrizione                                   |
| ---------------- | --------------------------------------------- |
| Frame Control    | Tipo e sottotipo del frame, flags             |
| Duration/ID      | Tempo di occupazione del canale               |
| Address 1        | Destinatario immediato                        |
| Address 2        | Mittente immediato                            |
| Address 3        | Indirizzo aggiuntivo (dipende dalla modalità) |
| Sequence Control | Numero di sequenza e fragment                 |
| Address 4        | Solo in modalità WDS (opzionale)              |
| Payload          | Dati trasportati                              |
| FCS              | Checksum                                      |

### I tre tipi di frame 802.11

**Management frames:** gestiscono la connessione tra client e access point.

* **Beacon:** inviato dall'AP ogni \~100ms per annunciare la rete (SSID, capabilities, canale)
* **Probe Request/Response:** il client cerca reti, l'AP risponde
* **Authentication:** processo di autenticazione 802.11
* **Association Request/Response:** il client si associa all'AP
* **Deauthentication/Disassociation:** disconnessione (forzata o volontaria)

**Control frames:** gestiscono l'accesso al mezzo radio.

* **ACK:** conferma ricezione
* **RTS/CTS:** Request to Send / Clear to Send per gestire collisioni
* **Block ACK**

**Data frames:** trasportano i dati effettivi.

### CSMA/CA: l'accesso al mezzo condiviso

Wi-Fi usa **CSMA/CA (Carrier Sense Multiple Access with Collision Avoidance)** per gestire l'accesso al mezzo radio condiviso. Prima di trasmettere, ogni dispositivo ascolta il canale. Se è libero, attende un backoff casuale e poi trasmette. Se è occupato, aspetta.

Questo meccanismo è fondamentale per capire gli attacchi DoS: non servono grandi risorse per saturare un canale Wi-Fi.

### Modalità operative

**Infrastructure mode:** client si connettono a un Access Point (AP). È la modalità standard nelle reti domestiche e aziendali.

**Ad-hoc (IBSS):** comunicazione diretta tra client senza AP. Raro in produzione.

**Monitor mode:** l'interfaccia cattura tutti i frame nell'aria senza associarsi a nessuna rete. Fondamentale per il pentesting wireless.

**Master mode (AP mode):** l'interfaccia funziona come Access Point.

***

## I protocolli di sicurezza Wi-Fi

### WEP (Wired Equivalent Privacy)

WEP è il primo protocollo di sicurezza 802.11, introdotto nel 1997. Usa RC4 con chiavi a 40 o 104 bit. È completamente compromesso dal 2001: con strumenti moderni una chiave WEP si recupera in pochi minuti raccogliendo abbastanza IV (Initialization Vector). Non va considerato sicuro in nessuno scenario.

### WPA (Wi-Fi Protected Access)

WPA nasce nel 2003 come soluzione rapida alle vulnerabilità di WEP. Usa TKIP (Temporal Key Integrity Protocol) e il four-way handshake per la derivazione delle chiavi. Meglio di WEP, ma TKIP ha vulnerabilità proprie. Anch'esso considerato obsoleto.

### WPA2 (802.11i)

WPA2 è lo standard dominante. Usa **AES-CCMP** al posto di RC4/TKIP. Ha due modalità:

**WPA2-Personal (PSK):** autenticazione tramite Pre-Shared Key. La stessa password per tutti i client. Il four-way handshake usa la PSK per derivare la chiave di sessione. Se si cattura il handshake, si può attaccare offline.

**WPA2-Enterprise (802.1X/EAP):** autenticazione tramite server RADIUS con credenziali individuali. Significativamente più sicuro: ogni utente ha le proprie credenziali e la compromissione di una non compromette le altre.

### WPA3

WPA3 introduce **SAE (Simultaneous Authentication of Equals)**, che sostituisce il four-way handshake PSK con un protocollo Diffie-Hellman. Resistente agli attacchi dizionario offline sui handshake. Adottato gradualmente, non ancora universale.

### Management Frame Protection (802.11w)

I frame di management (beacon, deauth, disassoc) storicamente non erano autenticati né cifrati. 802.11w introduce la loro protezione crittografica. Senza 802.11w, i deauthentication attack funzionano sempre. Con 802.11w obbligatorio, sono molto più difficili.

***

## Dove viene usato Wi-Fi nelle reti

Wi-Fi è presente in ogni contesto:

* **Reti aziendali enterprise:** SSID multipli (corporate, guest, IoT), WPA2-Enterprise con RADIUS, segmentazione tramite VLAN per SSID
* **Reti domestiche e SOHO:** WPA2-PSK, spesso con configurazione di default
* **Reti pubbliche (hotspot):** autenticazione captive portal, spesso senza cifratura end-to-end
* **Reti industriali OT:** access point industriali per dispositivi embedded, spesso con sicurezza minima
* **IoT e smart building:** dispositivi connessi in Wi-Fi con firmware raramente aggiornato

In un engagement che include wireless assessment, la superficie è enorme: dipendenti con laptop aziendali, dispositivi IoT, reti guest, access point non autorizzati (rogue AP).

***

## Perché Wi-Fi è importante in cybersecurity

Il mezzo radio è intrinsecamente accessibile a chiunque si trovi nel raggio dell'access point. Non c'è un cavo fisico da collegare, non c'è una porta su cui applicare port security. Questo cambia radicalmente la superficie di attacco rispetto alle reti cablate.

Un pentester che conosce 802.11 a fondo può:

* **Intercettare handshake WPA2** per attacchi offline a dizionario
* **Forzare la disconnessione** di client tramite deauthentication
* **Impersonare access point legittimi** (Evil Twin) per intercettare credenziali
* **Mappare l'infrastruttura wireless** senza essere fisicamente nella rete
* **Identificare rogue AP** e SSID non autorizzati
* **Attaccare WPA2-Enterprise** con certificati falsi e credential harvesting

***

## Wi-Fi in un engagement di pentesting

### Reconnaissance wireless: wardriving e scanning passivo

La fase iniziale è sempre passiva: mettere l'interfaccia in monitor mode e ascoltare.

```bash
airmon-ng start wlan0
airodump-ng wlan0mon
```

`airodump-ng` mostra in tempo reale:

* Tutti gli SSID nell'area con BSSID (MAC dell'AP), canale, potenza del segnale, tipo di cifratura, numero di client connessi
* I client e a quali reti sono associati (o cercano attivamente tramite Probe Request)

Informazioni raccolte senza inviare un singolo byte.

Per registrare su un canale specifico e salvare per analisi:

```bash
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
```

### Cattura del four-way handshake WPA2

Il four-way handshake WPA2 avviene quando un client si connette all'AP. Contiene informazioni sufficienti per attaccare la PSK offline. Per catturarlo:

**Metodo 1 — Attesa passiva:**
Rimani su `airodump-ng` sul canale target finché un client non si connette. Il handshake appare nell'angolo in alto a destra dell'output.

**Metodo 2 — Deauthentication forzata:**
Forza la disconnessione di un client per provocare una riconnessione e catturare il handshake:

```bash
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c CC:DD:EE:FF:00:11 wlan0mon
# -0 = deauth attack, 5 = numero di pacchetti
# -a = BSSID dell'AP, -c = MAC del client
```

Poi attacca il handshake catturato con dizionario:

```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
```

O con hashcat per performance migliori:

```bash
hcxtools cap2hccapx capture-01.cap capture.hccapx
hashcat -m 2500 capture.hccapx wordlist.txt
```

### PMKID Attack (senza client)

WPA2 con PMKID Attack non richiede di catturare un client che si connette. Il PMKID è derivabile direttamente dall'AP:

```bash
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
hcxpcaptool -z pmkid.hash pmkid.pcapng
hashcat -m 22000 pmkid.hash wordlist.txt
```

Più veloce, più silenzioso, non richiede client attivi.

### Evil Twin Attack

L'Evil Twin è un AP malevolo che imita un SSID legittimo. I client si connettono pensando di essere sulla rete autentica.

Setup base con **hostapd-wpe** per WPA2-Enterprise (harvesting credenziali EAP):

```bash
hostapd-wpe hostapd-wpe.conf
```

hostapd-wpe cattura le credenziali EAP (MS-CHAPv2) inviate dai client che si connettono. Combinato con una deauthentication sull'AP legittimo, si forza la connessione verso l'Evil Twin.

Per reti WPA2-PSK, un Evil Twin open (senza password) con captive portal è sufficiente per ingannare utenti non attenti.

### Enumeration della rete dopo l'accesso

Una volta connesso alla rete wireless, l'engagement prosegue come una qualsiasi rete interna: [ARP scan](https://hackita.it/articoli/arp), [Nmap](https://hackita.it/articoli/nmap), analisi delle VLAN, ricerca di servizi esposti.

***

## Attacchi e abusi possibili su Wi-Fi

### WPA2-PSK Handshake Cracking

Come descritto: cattura del four-way handshake e attacco dizionario/brute force offline. La robustezza della PSK è l'unica difesa una volta catturato il handshake.

### Deauthentication Attack (DoS)

Frame di deauthentication non autenticati (senza 802.11w) permettono di disconnettere forzatamente qualsiasi client da qualsiasi AP. Bastano pochi frame per tenere un client disconnesso indefinitamente.

```bash
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon
# 0 = loop continuo
```

Usato sia come DoS che come step preparatorio per altri attacchi (handshake capture, Evil Twin).

### PMKID Attack

Come descritto: derivazione del PMKID direttamente dall'AP senza client. Più efficiente del classico handshake capture in molti scenari.

### Rogue AP / Evil Twin

Impersonare un AP legittimo per intercettare le connessioni dei client. Particolarmente efficace contro reti WPA2-Enterprise dove è possibile fare credential harvesting EAP.

### Wardriving e SSID Harvesting

Mappatura sistematica degli access point in un'area geografica. Utile in fase di reconnaissance esterna per identificare reti aziendali, rogue AP, reti con cifratura debole o assente, e punti di accesso fisici potenziali.

### Probe Request Tracking

I dispositivi Wi-Fi inviano Probe Request anche quando non sono connessi a nessuna rete, cercando reti conosciute. Questi frame contengono i SSID delle reti cercate: rivela quali reti ha frequentato il dispositivo, potenzialmente includendo reti aziendali, VPN, e ambienti sensibili.

***

## Esempi pratici con Wi-Fi 802.11 in laboratorio

### Setup completo per wireless pentesting su Linux

```bash
# Mettere l'interfaccia in monitor mode
airmon-ng check kill
airmon-ng start wlan0

# Verificare
iwconfig wlan0mon
```

### Identificare tutti gli AP nell'area

```bash
airodump-ng wlan0mon
```

### Cambiare il canale manualmente

```bash
iwconfig wlan0mon channel 6
```

### Analisi del traffico wireless con Wireshark

In Wireshark su interfaccia in monitor mode, decodifica automatica dei frame 802.11. Filtri utili:

```
wlan.fc.type == 0        # Solo management frames
wlan.fc.type_subtype == 8  # Solo beacon
wlan.fc.type_subtype == 12 # Solo deauthentication
eapol                    # Four-way handshake WPA2
```

### Identificare client che cercano reti specifiche (Probe Request)

```bash
airodump-ng wlan0mon | grep -v "^BSSID"
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 4" -T fields -e wlan.sa -e wlan_mgt.ssid
```

***

## Detection e difesa Wi-Fi 802.11

Un difensore che monitora l'infrastruttura wireless può rilevare:

* **Deauthentication frame anomali:** burst di deauth non correlati a eventi legittimi indicano un attacco in corso
* **SSID duplicati con BSSID diverso:** possibile Evil Twin nella zona
* **Client che si connettono a SSID non autorizzati:** indicatore di rogue AP o credential harvesting
* **Probe Request verso SSID aziendali da MAC non in inventario:** dispositivi non autorizzati
* **Traffico EAPOL anomalo:** handshake WPA2 in eccesso, possibile tentativo di cattura massiva

Tool: **Wireless Intrusion Detection System (WIDS)** integrato in Cisco WLC, Aruba, Ruckus. **Kismet** come WIDS open source. **Zeek** con plugin wireless per analisi del traffico 802.11.

***

## Hardening e mitigazioni Wi-Fi

### Usare WPA3 o WPA2-Enterprise

WPA2-PSK è vulnerabile al dizionario se la password è debole. WPA3 risolve strutturalmente il problema. In alternativa, WPA2-Enterprise con 802.1X garantisce autenticazione individuale e non è vulnerabile all'handshake cracking classico.

### Abilitare 802.11w (Management Frame Protection)

MFP rende i frame di deauthentication autenticati e firmati, rendendo il deauth attack molto più difficile. Abilita PMF (Protected Management Frames) su tutti gli SSID:

```
# Cisco WLC
Management Frame Protection: Required
```

### Password WPA2-PSK lunghe e casuali

Se WPA3 non è disponibile, usa PSK di almeno 20 caratteri casuali. Una password casuale di 20+ caratteri rende il dizionario praticamente inutile — ma rimane vulnerabile a brute force con GPU potenti se la password ha pattern.

### Segmentare le VLAN per SSID

Ogni SSID dovrebbe mappare a una VLAN separata con accesso controllato da ACL. La rete guest non deve vedere la rete corporate. Vedi [VLAN e 802.1Q](https://hackita.it/articoli/vlan).

### WIDS (Wireless Intrusion Detection System)

Monitora continuamente l'ambiente RF per rilevare rogue AP, deauth attack, Evil Twin, e altri comportamenti anomali. Essenziale in ambienti enterprise.

### Disabilitare protocolli legacy

Se non hai dispositivi che richiedono WEP o WPA/TKIP, disabilitali esplicitamente sul controller wireless. Lasciare compatibilità con protocolli obsoleti abbassa il livello di sicurezza dell'intera rete.

### Client isolation

Abilita la client isolation sulle VLAN guest e IoT: impedisce la comunicazione diretta tra client connessi allo stesso SSID, limitando la propagazione di attacchi laterali.

***

## Errori comuni su Wi-Fi

**"WPA2 con password lunga è completamente sicuro"**
WPA2-PSK con password lunga è molto più resistente, ma il four-way handshake rimane catturabile e attaccabile offline. La sicurezza reale richiede WPA3 o WPA2-Enterprise.

**"Nascondere l'SSID protegge la rete"**
No. Un SSID nascosto non viene incluso nei beacon, ma appare comunque nelle Probe Request dei client che cercano quella rete. airodump-ng lo rivela in pochi secondi.

**"Il MAC filtering blocca gli intrusi"**
Come per le reti cablate: il MAC spoofing è triviale. Basta osservare un MAC autorizzato con airodump-ng e replicarlo.

**"La distanza fisica protegge dalle intercettazioni"**
Dipende dall'hardware dell'attaccante. Antenne direzionali ad alto guadagno permettono di ricevere segnali Wi-Fi da distanze di centinaia di metri o oltre. La "bolla" Wi-Fi non ha confini precisi e controllabili.

**"WPA3 è immune a tutti gli attacchi"**
WPA3 risolve il problema del handshake cracking PSK, ma ha avuto vulnerabilità proprie (Dragonblood) nella sua implementazione iniziale. Nessun protocollo è immune: l'implementazione conta quanto il design.

***

## FAQ su Wi-Fi 802.11

**Cos'è Wi-Fi 802.11 e come funziona?**
Wi-Fi è la tecnologia di comunicazione wireless basata sullo standard IEEE 802.11. Opera ai livelli fisico e data link del modello OSI, trasmettendo dati su frequenze radio (2.4, 5, 6 GHz) invece che su cavo. I dispositivi comunicano tramite access point in modalità infrastruttura, o direttamente in modalità ad-hoc.

**Cos'è un deauthentication attack Wi-Fi?**
È un attacco che sfrutta i frame di management 802.11 non autenticati (in assenza di 802.11w) per forzare la disconnessione di un client da un AP. Basta inviare pochi frame deauth con il MAC dell'AP come sorgente per disconnettere qualsiasi client.

**WPA2 è ancora sicuro?**
WPA2-Personal è vulnerabile al dizionario se la password è debole, poiché il four-way handshake può essere catturato e attaccato offline. WPA2-Enterprise con 802.1X è significativamente più robusto. Per nuove installazioni, WPA3 è la scelta corretta.

**Cos'è un Evil Twin attack?**
Un Evil Twin è un access point malevolo che imita il SSID di una rete legittima. I client si connettono pensando di essere sulla rete originale. L'attaccante può intercettare il traffico, raccogliere credenziali, e servire contenuti modificati.

**Quali tool si usano per il pentesting wireless?**
La suite **aircrack-ng** (airodump-ng, aireplay-ng, aircrack-ng) è lo standard per WPA2. **hcxdumptool** e **hcxtools** per il PMKID attack. **hostapd-wpe** per Evil Twin con EAP harvesting. **Kismet** per passive reconnaissance avanzata. **Wireshark** e **tshark** per analisi dei frame 802.11.

***

## Conclusione su Wi-Fi 802.11

Wi-Fi è una delle superfici di attacco più accessibili in un engagement: non richiede accesso fisico, i segnali attraversano le pareti, e i protocolli legacy sono ancora ovunque. Capire 802.11 a livello profondo — struttura dei frame, meccanismi di autenticazione, vulnerabilità specifiche di WEP/WPA/WPA2/WPA3 — permette di costruire attacchi precisi invece di eseguire tool alla cieca.

Wardriving, deauth, handshake cracking, Evil Twin, PMKID attack: non sono tecniche esotiche. Sono nel toolkit standard di qualsiasi wireless assessment e funzionano nella maggior parte degli ambienti enterprise reali.

E spesso, l'access point più vulnerabile è quello che nessuno sapeva esistesse.

Approfondisci i protocolli e le tecniche correlate:

* [Ethernet IEEE 802.3: il livello cablato a confronto](https://hackita.it/articoli/ethernet-ieee-802-3)
* [VLAN e 802.1Q: segmentazione degli SSID](https://hackita.it/articoli/vlan)
* [ARP: spoofing e discovery post-connessione](https://hackita.it/articoli/arp)
* [Sniffing su reti locali e wireless](https://hackita.it/articoli/sniffing)
* [Man in the Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle)
* [Nmap: scanning post-accesso wireless](https://hackita.it/articoli/nmap)
* [Password cracking: dizionari e hashcat](https://hackita.it/articoli/password-cracking)

Riferimento ufficiale: [IEEE 802.11 — Wireless LAN Medium Access Control and Physical Layer Specifications](https://standards.ieee.org/ieee/802.11/7028/)

***

Vuoi un wireless assessment professionale della tua infrastruttura o un percorso di formazione dedicato al pentesting wireless?
Tutto su [hackita.it/servizi](https://hackita.it/servizi).

HackITA cresce grazie a chi lo usa. Se vuoi fare la tua parte:
[hackita.it/supporto](https://hackita.it/supporto)
